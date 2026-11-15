// Package l2gw is the exit's Layer 2 gateway, built on gVisor's userspace network stack. Ethernet
// frames carried over the bond go straight into the stack: it answers ARP, serves DHCP, and
// forwards every TCP and UDP flow the devices open by dialling ordinary sockets from this process.
// There is no TAP, bridge, dnsmasq or NAT rule, so it needs no capability beyond a normal
// unprivileged socket and works inside the hardened, read-only container.
//
// Flows are terminated here, so the gateway knows exactly which flows are alive; that count is
// what lets an exit drain before it updates.
package l2gw

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const nicID = 1

// Host pins an address to a MAC.
type Host struct {
	MAC  net.HardwareAddr
	IP   netip.Addr
	Name string
}

// Config describes the gateway. Out receives every frame the gateway sends toward the devices.
type Config struct {
	Address           netip.Prefix     // gateway address and subnet, for example 10.78.0.1/24
	IPv6Address       netip.Prefix     // optional IPv6 gateway address and prefix; clients need a configured IPv6 address
	MAC               net.HardwareAddr // gateway MAC; default 02:47:42:00:00:01
	MTU               int              // Ethernet payload size; default 1380
	DHCPStart         netip.Addr
	DHCPEnd           netip.Addr
	DHCPRelay4        netip.AddrPort // optional upstream DHCPv4 server; mutually exclusive with the local pool
	DHCPRelayGateway4 netip.Addr     // optional on-link next hop for an off-subnet relay server
	DHCPRelay6        netip.AddrPort // optional upstream DHCPv6 server; mutually exclusive with the local DHCPv6 server
	DHCPRelayLink6    netip.Addr     // IPv6 relay link-address; defaults to IPv6Address.Addr()
	DHCPv6PDPool      netip.Prefix   // optional delegated-prefix pool for local IA_PD service
	DHCPv6PDBits      uint8          // delegated prefix size, for example 60 from a /48 pool
	Lease             time.Duration  // default 12 h
	DNS               []netip.Addr   // handed to clients; default 1.1.1.1 and 9.9.9.9
	DNS6              []netip.Addr   // advertised to SLAAC clients in Router Advertisements
	Hosts             []Host
	Hosts6            []DHCPv6Host
	Out               func(frame []byte)

	// AllowPrivate lets devices reach private, loopback and link-local destinations. Off in
	// production: devices get the internet, not the networks behind the exit.
	AllowPrivate bool
	// DialTimeout bounds an outbound TCP connect (default 8 s); IdleTCP and IdleUDP close quiet flows.
	DialTimeout time.Duration
	IdleTCP     time.Duration // default 30 min
	IdleUDP     time.Duration // default 60 s
	// Dial opens the outbound socket for a flow; nil uses the operating system. Tests replace it.
	Dial func(network, address string, timeout time.Duration) (net.Conn, error)
	// ECMPPaths selects a stable host egress member per TCP flow and UDP device endpoint.
	// Linux requires usable routes on each interface or policy routes for each fwmark.
	ECMPPaths []ECMPPath
	// Listen opens the public UDP socket of a device mapping; nil uses the operating system.
	Listen func() (net.PacketConn, error)
	// RestrictedUDP drops datagrams from addresses the device has not sent to first. Off by default:
	// full-cone mapping is what gives consoles NAT type 2 and lets PSN sign-in succeed.
	RestrictedUDP bool
	// Tap, when set, sees every IPv4 or IPv6 packet that crosses the gateway: fromDevice is the leg a device sent,
	// false the leg the stack sent back. It runs on the frame path, so it must only parse and count, and
	// must not keep the slice.
	Tap func(fromDevice bool, ipPacket []byte)
	// DNSFilter, when set and On reports true, answers every DNS query a device sends to port 53 (UDP or TCP)
	// itself, whatever resolver the device chose, so the DNS filter and its logs cover bridged devices.
	DNSFilter *DNSHook
	// LLDPMEDPolicy advertises this network policy only when it belongs to the
	// gateway's VLAN. A nil policy still permits LLDP-MED capability replies.
	LLDPMEDPolicy   *LLDPMEDNetworkPolicy
	LLDPMEDInterval time.Duration // default 30 s when a network policy is configured
}

// DNSHook is the filtering resolver the gateway hands device DNS to.
type DNSHook struct {
	On     func() bool
	Handle func(client netip.Addr, req []byte, tcp bool) []byte
}

// Stats are the counters shown in the panel.
type Stats struct {
	TCPFlows, UDPFlows        int // alive now
	TCPTotal, UDPTotal        uint64
	Blocked, DialFailed       uint64
	DHCPDiscover, DHCPRequest uint64
	DHCPAck, DHCPNak          uint64
	Leases                    int
	FramesIn, FramesOut       uint64
	// Stack is the gVisor stack's own receive-side counters, nonzero entries only.
	Stack map[string]uint64
}

// Gateway is one gVisor stack serving one bridged segment.
type Gateway struct {
	cfg    Config
	stack  *stack.Stack
	link   *channel.Endpoint
	cancel context.CancelFunc
	done   sync.WaitGroup

	tcpFlows, udpFlows  atomic.Int64
	tcpTotal, udpTotal  atomic.Uint64
	blocked, dialFailed atomic.Uint64
	framesIn, framesOut atomic.Uint64
	dhcp                dhcpServer
	dhcpv6              *dhcpv6Server
	dhcpv6Relay         *dhcpv6Relay
	closed              atomic.Bool
	raAdvertised        atomic.Bool
	draining            atomic.Bool
	policy              atomic.Pointer[compiledPolicy]
	devs                devices
	nbMu                sync.Mutex
	raMu                sync.Mutex
	raSendMu            sync.Mutex
	raLast              map[[6]byte]time.Time
	dnsClosers          []io.Closer
	udpMu               sync.Mutex
	udpMaps             map[netip.AddrPort]*udpMapping
	neighbours          map[netip.Addr][6]byte
	pdRouteMu           sync.Mutex
	pdBaseRoutes        []tcpip.Route
	pdRoutes            map[netip.Prefix]dhcpv6PDLease
}

// DHCPBinding is a DHCP lease learned from a complete request whose BOOTP
// hardware address matched the Ethernet source. SessionPort is supplied by
// the authenticated segment attachment, never derived from the packet.
type DHCPBinding struct {
	MAC         string     `json:"mac"`
	IP          netip.Addr `json:"ip"`
	SessionPort string     `json:"session_port,omitempty"`
	Expires     time.Time  `json:"expires"`
}

// New builds and starts the gateway.
func New(cfg Config) (*Gateway, error) {
	if !cfg.Address.IsValid() || !cfg.Address.Addr().Is4() {
		return nil, errors.New("l2gw: address must be an IPv4 prefix")
	}
	if cfg.IPv6Address.IsValid() && (!cfg.IPv6Address.Addr().Is6() || cfg.IPv6Address.Addr().Is4In6() || cfg.IPv6Address.Bits() < 48 || cfg.IPv6Address.Bits() > 120) {
		return nil, errors.New("l2gw: IPv6 address must be a native IPv6 prefix between /48 and /120")
	}
	if cfg.Out == nil {
		return nil, errors.New("l2gw: Out is required")
	}
	if err := ValidateECMPPaths(cfg.ECMPPaths); err != nil {
		return nil, err
	}
	if cfg.DHCPRelay4.IsValid() && (!cfg.DHCPRelay4.Addr().Is4() || cfg.DHCPRelay4.Addr().IsUnspecified() || cfg.DHCPRelay4.Addr().IsMulticast() || cfg.DHCPRelay4.Port() == 0) {
		return nil, errors.New("l2gw: DHCPv4 relay must be a unicast IPv4 address and nonzero UDP port")
	}
	if cfg.DHCPRelayGateway4.IsValid() && (!cfg.DHCPRelay4.IsValid() || !validDHCPRelayGateway(cfg.Address, cfg.DHCPRelayGateway4)) {
		return nil, errors.New("l2gw: DHCPv4 relay gateway must be a distinct on-link IPv4 next hop and requires a relay server")
	}
	if cfg.DHCPRelay4.IsValid() && !cfg.Address.Contains(cfg.DHCPRelay4.Addr()) && !cfg.DHCPRelayGateway4.IsValid() {
		return nil, errors.New("l2gw: off-subnet DHCPv4 relay server requires an on-link relay gateway")
	}
	if cfg.DHCPRelay6.IsValid() && (!cfg.DHCPRelay6.Addr().Is6() || cfg.DHCPRelay6.Addr().Is4In6() || cfg.DHCPRelay6.Addr().IsUnspecified() || cfg.DHCPRelay6.Addr().IsMulticast() || cfg.DHCPRelay6.Port() == 0) {
		return nil, errors.New("l2gw: DHCPv6 relay server must be a native IPv6 unicast endpoint with a nonzero UDP port")
	}
	if cfg.DHCPRelay6.IsValid() && (!cfg.IPv6Address.IsValid() || len(cfg.Hosts6) != 0 || cfg.DHCPv6PDPool.IsValid()) {
		return nil, errors.New("l2gw: DHCPv6 relay requires an IPv6 gateway and cannot use local DHCPv6 reservations or a PD pool")
	}
	if cfg.DHCPRelayLink6.IsValid() && (!cfg.DHCPRelay6.IsValid() || !cfg.IPv6Address.Contains(cfg.DHCPRelayLink6) || cfg.DHCPRelayLink6.IsUnspecified() || cfg.DHCPRelayLink6.IsMulticast()) {
		return nil, errors.New("l2gw: DHCPv6 relay link address must be a unicast address in the configured IPv6 gateway prefix and requires a relay server")
	}
	if cfg.DHCPv6PDPool.IsValid() && (!cfg.IPv6Address.IsValid() || cfg.DHCPRelay6.IsValid()) {
		return nil, errors.New("l2gw: DHCPv6 PD pool requires a local IPv6 gateway and cannot be combined with relay mode")
	}
	if cfg.DHCPv6PDPool.IsValid() && cfg.DHCPv6PDPool.Overlaps(cfg.IPv6Address) {
		return nil, errors.New("l2gw: DHCPv6 PD pool must not overlap the gateway's client prefix")
	}
	if cfg.MAC == nil {
		cfg.MAC = net.HardwareAddr{0x02, 0x47, 0x42, 0x00, 0x00, 0x01}
	}
	if len(cfg.MAC) != 6 || cfg.MAC[0]&1 != 0 || bytes.Equal(cfg.MAC, []byte{0, 0, 0, 0, 0, 0}) {
		return nil, errors.New("l2gw: gateway MAC must be a six-byte unicast address")
	}
	if cfg.MTU == 0 {
		cfg.MTU = 1380
	}
	if cfg.Lease == 0 {
		cfg.Lease = 12 * time.Hour
	}
	if len(cfg.DNS) == 0 {
		cfg.DNS = []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("9.9.9.9")}
	}
	if cfg.IPv6Address.IsValid() && len(cfg.DNS6) == 0 {
		cfg.DNS6 = []netip.Addr{netip.MustParseAddr("2606:4700:4700::1111"), netip.MustParseAddr("2620:fe::fe")}
	}
	if len(cfg.DNS6) > 3 {
		return nil, errors.New("l2gw: at most three IPv6 DNS servers")
	}
	for _, dns := range cfg.DNS6 {
		if !dns.Is6() || dns.Is4In6() || dns.IsUnspecified() || dns.IsMulticast() {
			return nil, errors.New("l2gw: invalid IPv6 DNS server")
		}
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 8 * time.Second
	}
	if cfg.LLDPMEDPolicy != nil {
		p := *cfg.LLDPMEDPolicy
		if p.VLANID == 0 || p.VLANID > 4094 || p.ApplicationType < 1 || p.ApplicationType > 8 || p.L2Priority > 7 || p.DSCP > 63 {
			return nil, errors.New("l2gw: invalid LLDP-MED network policy")
		}
		cfg.LLDPMEDPolicy = &p
		if cfg.LLDPMEDInterval == 0 {
			cfg.LLDPMEDInterval = 30 * time.Second
		}
		if cfg.LLDPMEDInterval < time.Second || cfg.LLDPMEDInterval > time.Hour {
			return nil, errors.New("l2gw: LLDP-MED advertisement interval must be 1s..1h")
		}
	}
	if cfg.IdleTCP == 0 {
		cfg.IdleTCP = 30 * time.Minute
	}
	if cfg.IdleUDP == 0 {
		cfg.IdleUDP = 60 * time.Second
	}
	if cfg.Dial == nil {
		cfg.Dial = func(network, address string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout(network, address, timeout)
		}
	}
	g := &Gateway{cfg: cfg}
	if cfg.DHCPRelay4.IsValid() {
		if cfg.DHCPStart.IsValid() || cfg.DHCPEnd.IsValid() || len(cfg.Hosts) != 0 {
			return nil, errors.New("l2gw: DHCPv4 relay cannot be combined with a local DHCPv4 pool or fixed hosts")
		}
		g.dhcp.cfg = &g.cfg
		g.dhcp.ingress = make(map[[6]byte]string)
	} else {
		if err := g.dhcp.init(&g.cfg); err != nil {
			return nil, err
		}
	}
	if cfg.IPv6Address.IsValid() && !cfg.DHCPRelay6.IsValid() {
		server, err := newDHCPv6Server(cfg.IPv6Address, cfg.MAC, cfg.DNS6, cfg.Lease, cfg.Hosts6...)
		if err != nil {
			return nil, err
		}
		g.dhcpv6 = server
		if cfg.DHCPv6PDPool.IsValid() {
			if err := server.ConfigurePrefixDelegation(cfg.DHCPv6PDPool, cfg.DHCPv6PDBits); err != nil {
				return nil, err
			}
		}
	}

	g.link = channel.New(512, uint32(cfg.MTU), tcpip.LinkAddress(cfg.MAC))
	networkProtocols := []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol}
	transportProtocols := []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4}
	if cfg.IPv6Address.IsValid() {
		networkProtocols = append(networkProtocols, ipv6.NewProtocol)
		transportProtocols = append(transportProtocols, icmp.NewProtocol6)
	}
	s := stack.New(stack.Options{NetworkProtocols: networkProtocols, TransportProtocols: transportProtocols})
	g.stack = s
	if err := s.CreateNIC(nicID, ethernet.New(g.link)); err != nil {
		return nil, fmt.Errorf("l2gw: create NIC: %v", err)
	}
	addr := tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{
		Address: tcpip.AddrFrom4(cfg.Address.Addr().As4()), PrefixLen: cfg.Address.Bits()}}
	if err := s.AddProtocolAddress(nicID, addr, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("l2gw: add address: %v", err)
	}
	// Promiscuous and spoofing let the stack accept a flow for any destination, which is what
	// turns it into a forwarder; the route sends replies back out the one NIC.
	s.SetPromiscuousMode(nicID, true)
	s.SetSpoofing(nicID, true)
	routes := make([]tcpip.Route, 0, 3)
	if cfg.DHCPRelay4.IsValid() && cfg.DHCPRelayGateway4.IsValid() {
		hostMask := tcpip.MaskFromBytes([]byte{255, 255, 255, 255})
		destination, err := tcpip.NewSubnet(tcpip.AddrFrom4(cfg.DHCPRelay4.Addr().As4()), hostMask)
		if err != nil {
			return nil, fmt.Errorf("l2gw: relay server route: %v", err)
		}
		routes = append(routes, tcpip.Route{Destination: destination, Gateway: tcpip.AddrFrom4(cfg.DHCPRelayGateway4.As4()), NIC: nicID})
	}
	routes = append(routes, tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: nicID})
	if cfg.IPv6Address.IsValid() {
		v6 := tcpip.ProtocolAddress{Protocol: ipv6.ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{
			Address: tcpip.AddrFrom16(cfg.IPv6Address.Addr().As16()), PrefixLen: cfg.IPv6Address.Bits()}}
		if err := s.AddProtocolAddress(nicID, v6, stack.AddressProperties{}); err != nil {
			return nil, fmt.Errorf("l2gw: add IPv6 address: %v", err)
		}
		routes = append(routes, tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: nicID})
	}
	s.SetRouteTable(routes)
	if g.dhcpv6 != nil && cfg.DHCPv6PDPool.IsValid() {
		g.pdBaseRoutes = append([]tcpip.Route(nil), routes...)
		g.pdRoutes = make(map[netip.Prefix]dhcpv6PDLease)
	}
	sack := tcpip.TCPSACKEnabled(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)

	g.installFirewall()
	g.installForwarders()
	ctx, cancel := context.WithCancel(context.Background())
	g.cancel = cancel
	if cfg.DHCPRelay6.IsValid() {
		linkAddress := cfg.DHCPRelayLink6
		if !linkAddress.IsValid() {
			linkAddress = cfg.IPv6Address.Addr()
		}
		relay, err := newDHCPv6Relay(cfg.DHCPRelay6, linkAddress, cfg.MAC, netip.AddrFrom16(g.routerLinkLocal()), cfg.Out)
		if err != nil {
			cancel()
			g.stack.Close()
			g.link.Close()
			return nil, err
		}
		g.dhcpv6Relay = relay
		g.done.Add(1)
		go func() { defer g.done.Done(); relay.readLoop(ctx.Done()) }()
	}
	g.done.Add(1)
	go g.pumpOut(ctx)
	if cfg.IPv6Address.IsValid() {
		g.done.Add(1)
		go g.periodicRouterAdvertisements(ctx.Done())
	}
	if g.dhcpv6 != nil && cfg.DHCPv6PDPool.IsValid() {
		g.done.Add(1)
		go g.periodicPDRouteSync(ctx.Done())
	}
	if err := g.startDNSFilter(); err != nil {
		g.Close()
		return nil, err
	}
	if err := g.startDHCP(ctx); err != nil {
		g.Close()
		return nil, err
	}
	if cfg.LLDPMEDPolicy != nil {
		g.done.Add(1)
		go g.periodicLLDPMED(ctx.Done())
		g.sendLLDPMED(120, nil)
	}
	return g, nil
}

// pumpOut hands every frame the stack produces to cfg.Out.
func (g *Gateway) pumpOut(ctx context.Context) {
	defer g.done.Done()
	for {
		pkt := g.link.ReadContext(ctx)
		if pkt == nil {
			return
		}
		view := pkt.ToView()
		frame := append([]byte(nil), view.AsSlice()...)
		view.Release()
		pkt.DecRef()
		g.framesOut.Add(1)
		g.tap(false, frame)
		g.cfg.Out(frame)
	}
}

// Inbound feeds a frame that arrived from the bond into the stack.
func (g *Gateway) Inbound(frame []byte) {
	g.InboundFrom(frame, "")
}

// InboundFrom feeds a frame into the stack while preserving the authenticated
// segment attachment that supplied it for DHCP snooping.
func (g *Gateway) InboundFrom(frame []byte, ingressIdentity string) {
	if g.closed.Load() || len(frame) < header.EthernetMinimumSize {
		return
	}
	g.framesIn.Add(1)
	g.tap(true, frame)
	now := time.Now()
	message, dhcp, valid := parseDHCPEthernet(frame)
	if dhcp && !valid {
		return
	}
	if dhcp && ingressIdentity != "" {
		g.dhcp.setIngress(message.chaddr, ingressIdentity)
	}
	if g.dhcpv6 != nil {
		if reply, isDHCPv6 := g.dhcpv6.handleFrame(frame, g.cfg.MAC, netip.AddrFrom16(g.routerLinkLocal()), ingressIdentity, now); isDHCPv6 {
			g.syncPDRoutes(now)
			if len(reply) > 0 {
				g.framesOut.Add(1)
				g.tap(false, reply)
				g.cfg.Out(reply)
			}
			return
		}
	}
	if g.dhcpv6Relay != nil && g.dhcpv6Relay.HandleFrame(frame, ingressIdentity) {
		return
	}
	if lldp := g.BuildLLDPMEDResponse(frame); lldp != nil {
		g.framesOut.Add(1)
		g.tap(false, lldp)
		g.cfg.Out(lldp)
		return
	}
	if ra := g.routerAdvertisement(frame, now); ra != nil {
		g.sendRouterAdvertisement(ra)
	}
	if g.foreignARPRequest(frame) {
		return
	}
	g.learnNeighbour(frame)
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(frame)})
	g.link.InjectInbound(0, pkt)
	pkt.DecRef()
}

// periodicPDRouteSync removes routes for leases that expire without another
// DHCPv6 exchange. The tick bounds stale forwarding state to one second.
func (g *Gateway) periodicPDRouteSync(done <-chan struct{}) {
	defer g.done.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case now := <-ticker.C:
			g.syncPDRoutes(now)
		}
	}
}

// syncPDRoutes installs a route for each committed delegated prefix through
// the requesting router's link-local address and pins that next hop to its
// authenticated Ethernet source. A delegated prefix is routed to the client
// router; the client router remains responsible for advertising it on its LAN.
func (g *Gateway) syncPDRoutes(now time.Time) {
	if g.dhcpv6 == nil || g.pdRoutes == nil || g.closed.Load() {
		return
	}
	leases := g.dhcpv6.activePDLeases(now)
	wanted := make(map[netip.Prefix]dhcpv6PDLease, len(leases))
	wantedNeighbours := make(map[netip.Addr][6]byte, len(leases))
	for _, lease := range leases {
		wanted[lease.prefix] = lease
		wantedNeighbours[lease.nextHop] = lease.mac
	}

	g.pdRouteMu.Lock()
	defer g.pdRouteMu.Unlock()
	if g.closed.Load() {
		return
	}
	for prefix, previous := range g.pdRoutes {
		if _, stillPresent := wanted[prefix]; !stillPresent {
			delete(g.pdRoutes, prefix)
			if _, nextHopStillUsed := wantedNeighbours[previous.nextHop]; !nextHopStillUsed && previous.nextHop.IsValid() {
				_ = g.stack.RemoveNeighbor(nicID, ipv6.ProtocolNumber, tcpip.AddrFrom16(previous.nextHop.As16()))
			}
		}
	}
	for prefix, previous := range g.pdRoutes {
		if current, stillPresent := wanted[prefix]; stillPresent && (current.nextHop != previous.nextHop || current.mac != previous.mac) {
			if _, nextHopStillUsed := wantedNeighbours[previous.nextHop]; !nextHopStillUsed && previous.nextHop.IsValid() {
				_ = g.stack.RemoveNeighbor(nicID, ipv6.ProtocolNumber, tcpip.AddrFrom16(previous.nextHop.As16()))
			}
		}
	}
	routes := append([]tcpip.Route(nil), g.pdBaseRoutes...)
	for prefix, lease := range wanted {
		mask := net.CIDRMask(prefix.Bits(), 128)
		destination, err := tcpip.NewSubnet(tcpip.AddrFrom16(prefix.Addr().As16()), tcpip.MaskFromBytes(mask))
		if err != nil {
			continue
		}
		routes = append(routes, tcpip.Route{Destination: destination, Gateway: tcpip.AddrFrom16(lease.nextHop.As16()), NIC: nicID})
		g.pdRoutes[prefix] = lease
	}
	g.stack.SetRouteTable(routes)
	for addr, mac := range wantedNeighbours {
		g.stack.AddStaticNeighbor(nicID, ipv6.ProtocolNumber, tcpip.AddrFrom16(addr.As16()), tcpip.LinkAddress(mac[:]))
	}
}

// DHCPBindings snapshots active IPv4 and IPv6 leases with their authenticated ingress identity.
func (g *Gateway) DHCPBindings() []DHCPBinding {
	bindings := g.dhcp.bindings()
	if g.dhcpv6 != nil {
		bindings = append(bindings, g.dhcpv6.bindings()...)
	}
	return bindings
}

// dhcpEthernetSourceValid checks complete, unfragmented DHCPv4 requests before
// gVisor delivers the UDP payload to the DHCP socket. The BOOTP chaddr is
// client-controlled, so trusting it without matching the Ethernet source lets
// a device claim another device's static reservation. Non-DHCP and fragmented
// IPv4 frames are left to the stack; DHCP fragments cannot be parsed as a
// complete request by this ingress guard.
func dhcpEthernetSourceValid(frame []byte) (isDHCP, valid bool) {
	_, isDHCP, valid = parseDHCPEthernet(frame)
	return
}

func parseDHCPEthernet(frame []byte) (dhcpMessage, bool, bool) {
	var empty dhcpMessage
	if len(frame) < header.EthernetMinimumSize {
		return empty, false, true
	}
	offset := 14
	etherType := binary.BigEndian.Uint16(frame[12:14])
	for tags := 0; tags < 2 && (etherType == 0x8100 || etherType == 0x88a8 || etherType == 0x9100); tags++ {
		if len(frame) < offset+4 {
			return empty, false, true
		}
		etherType = binary.BigEndian.Uint16(frame[offset+2 : offset+4])
		offset += 4
	}
	if etherType != uint16(header.IPv4ProtocolNumber) || len(frame) < offset+20 {
		return empty, false, true
	}
	ip := frame[offset:]
	if ip[0]>>4 != 4 {
		return empty, false, true
	}
	ipHeaderLen := int(ip[0]&0x0f) * 4
	if ipHeaderLen < 20 || len(ip) < ipHeaderLen+8 {
		return empty, false, true
	}
	totalLen := int(binary.BigEndian.Uint16(ip[2:4]))
	if totalLen < ipHeaderLen+8 || totalLen > len(ip) || ip[9] != byte(udp.ProtocolNumber) {
		return empty, false, true
	}
	fragment := binary.BigEndian.Uint16(ip[6:8])
	if fragment&0x3fff != 0 {
		return empty, false, true
	}
	udpHeader := ip[ipHeaderLen : ipHeaderLen+8]
	if binary.BigEndian.Uint16(udpHeader[0:2]) != 68 || binary.BigEndian.Uint16(udpHeader[2:4]) != 67 {
		return empty, false, true
	}
	udpLen := int(binary.BigEndian.Uint16(udpHeader[4:6]))
	if udpLen < 8 || udpLen > totalLen-ipHeaderLen {
		return empty, true, false
	}
	payload := ip[ipHeaderLen+8 : ipHeaderLen+udpLen]
	message, ok := parseDHCP(payload)
	if !ok {
		return empty, true, false
	}
	return message, true, bytes.Equal(frame[6:12], message.chaddr[:])
}

// learnNeighbour pins the sender of an IPv4 frame as a static neighbour. Without it the stack must
// ARP for the device every time it answers from a new (spoofed) remote address, with that remote
// address as the ARP sender, which costs a round trip per flow and confuses some devices.
func (g *Gateway) learnNeighbour(f []byte) {
	if len(f) < header.EthernetMinimumSize || f[6]&1 == 1 {
		return
	}
	var ip netip.Addr
	var proto tcpip.NetworkProtocolNumber
	switch header.Ethernet(f).Type() {
	case header.IPv4ProtocolNumber:
		if len(f) < 34 {
			return
		}
		ip = netip.AddrFrom4([4]byte{f[26], f[27], f[28], f[29]})
		proto = ipv4.ProtocolNumber
		if ip == g.cfg.Address.Addr() || !g.cfg.Address.Contains(ip) {
			return
		}
	case header.IPv6ProtocolNumber:
		if len(f) < 54 || !g.cfg.IPv6Address.IsValid() {
			return
		}
		ip = netip.AddrFrom16([16]byte(f[22:38]))
		proto = ipv6.ProtocolNumber
		if ip == g.cfg.IPv6Address.Addr() || !g.cfg.IPv6Address.Contains(ip) {
			return
		}
	default:
		return
	}
	if ip.IsUnspecified() || ip.IsMulticast() {
		return
	}
	var mac [6]byte
	copy(mac[:], f[6:12])
	g.nbMu.Lock()
	if g.neighbours == nil {
		g.neighbours = map[netip.Addr][6]byte{}
	}
	if g.neighbours[ip] == mac {
		g.nbMu.Unlock()
		return
	}
	g.neighbours[ip] = mac
	g.nbMu.Unlock()
	addr := tcpip.AddrFrom16(ip.As16())
	if ip.Is4() {
		addr = tcpip.AddrFrom4(ip.As4())
	}
	g.stack.AddStaticNeighbor(nicID, proto, addr, tcpip.LinkAddress(mac[:]))
}

func (g *Gateway) macForIP(ip netip.Addr) ([6]byte, bool) {
	if ip.Is4() {
		return g.dhcp.macFor(ip)
	}
	g.nbMu.Lock()
	defer g.nbMu.Unlock()
	mac, ok := g.neighbours[ip]
	return mac, ok
}

// foreignARPRequest reports an ARP request for an address other than the gateway's. A promiscuous
// stack would answer it, and then every device's duplicate-address probe after DHCP finds a
// "conflict", declines its lease and starts over, so only the gateway's own address may answer.
func (g *Gateway) foreignARPRequest(f []byte) bool {
	if len(f) < 42 || f[12] != 0x08 || f[13] != 0x06 || f[20] != 0 || f[21] != 1 {
		return false
	}
	gw := g.cfg.Address.Addr().As4()
	return !(f[38] == gw[0] && f[39] == gw[1] && f[40] == gw[2] && f[41] == gw[3])
}

// ActiveFlows is the number of TCP and UDP flows alive now: an exit may update when it is zero.
func (g *Gateway) ActiveFlows() int { return int(g.tcpFlows.Load() + g.udpFlows.Load()) }

// SetDraining makes the gateway refuse new flows (TCP gets a reset, UDP is dropped) while existing
// ones continue, so devices move their next connections to the other exit.
func (g *Gateway) SetDraining(on bool) { g.draining.Store(on) }

// Draining says whether new flows are being refused.
func (g *Gateway) Draining() bool { return g.draining.Load() }

// Stats snapshots the counters.
func (g *Gateway) Stats() Stats {
	d := g.dhcp.stats()
	return Stats{
		TCPFlows: int(g.tcpFlows.Load()), UDPFlows: int(g.udpFlows.Load()),
		TCPTotal: g.tcpTotal.Load(), UDPTotal: g.udpTotal.Load(),
		Blocked: g.blocked.Load(), DialFailed: g.dialFailed.Load(),
		DHCPDiscover: d.discover, DHCPRequest: d.request, DHCPAck: d.ack, DHCPNak: d.nak, Leases: d.leases,
		FramesIn: g.framesIn.Load(), FramesOut: g.framesOut.Load(),
		Stack: g.stackCounters(),
	}
}

// Close stops the gateway and every flow.
func (g *Gateway) Close() {
	if !g.closed.CompareAndSwap(false, true) {
		return
	}
	if g.cfg.LLDPMEDPolicy != nil {
		g.sendLLDPMED(0, nil) // withdraw the advertised policy before the port detaches
	}
	g.raSendMu.Lock()
	if g.raAdvertised.Load() && g.cfg.IPv6Address.IsValid() {
		if ra := g.withdrawRouterAdvertisement(); ra != nil {
			g.framesOut.Add(1)
			g.tap(false, ra)
			g.cfg.Out(ra)
		}
	}
	g.raSendMu.Unlock()
	if g.dhcpv6Relay != nil {
		g.dhcpv6Relay.Close()
	}
	g.cancel()
	for _, c := range g.dnsClosers {
		c.Close()
	}
	g.pdRouteMu.Lock()
	g.stack.Close()
	g.pdRouteMu.Unlock()
	g.link.Close()
	g.done.Wait()
}
