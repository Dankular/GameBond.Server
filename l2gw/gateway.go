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
	"context"
	"errors"
	"fmt"
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
	Address   netip.Prefix     // gateway address and subnet, for example 10.78.0.1/24
	MAC       net.HardwareAddr // gateway MAC; default 02:47:42:00:00:01
	MTU       int              // Ethernet payload size; default 1380
	DHCPStart netip.Addr
	DHCPEnd   netip.Addr
	Lease     time.Duration // default 12 h
	DNS       []netip.Addr  // handed to clients; default 1.1.1.1 and 9.9.9.9
	Hosts     []Host
	Out       func(frame []byte)

	// AllowPrivate lets devices reach private, loopback and link-local destinations. Off in
	// production: devices get the internet, not the networks behind the exit.
	AllowPrivate bool
	// DialTimeout bounds an outbound TCP connect (default 8 s); IdleTCP and IdleUDP close quiet flows.
	DialTimeout time.Duration
	IdleTCP     time.Duration // default 30 min
	IdleUDP     time.Duration // default 60 s
	// Dial opens the outbound socket for a flow; nil uses the operating system. Tests replace it.
	Dial func(network, address string, timeout time.Duration) (net.Conn, error)
	// Listen opens the public UDP socket of a device mapping; nil uses the operating system.
	Listen func() (net.PacketConn, error)
	// RestrictedUDP drops datagrams from addresses the device has not sent to first. Off by default:
	// full-cone mapping is what gives consoles NAT type 2 and lets PSN sign-in succeed.
	RestrictedUDP bool
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
	closed              atomic.Bool
	draining            atomic.Bool
	policy              atomic.Pointer[compiledPolicy]
	devs                devices
	nbMu                sync.Mutex
	udpMu               sync.Mutex
	udpMaps             map[netip.AddrPort]*udpMapping
	neighbours          map[netip.Addr][6]byte
}

// New builds and starts the gateway.
func New(cfg Config) (*Gateway, error) {
	if !cfg.Address.IsValid() || !cfg.Address.Addr().Is4() {
		return nil, errors.New("l2gw: address must be an IPv4 prefix")
	}
	if cfg.Out == nil {
		return nil, errors.New("l2gw: Out is required")
	}
	if cfg.MAC == nil {
		cfg.MAC = net.HardwareAddr{0x02, 0x47, 0x42, 0x00, 0x00, 0x01}
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
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 8 * time.Second
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
	if err := g.dhcp.init(&g.cfg); err != nil {
		return nil, err
	}

	g.link = channel.New(512, uint32(cfg.MTU), tcpip.LinkAddress(cfg.MAC))
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
	})
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
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}})
	sack := tcpip.TCPSACKEnabled(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)

	g.installForwarders()
	ctx, cancel := context.WithCancel(context.Background())
	g.cancel = cancel
	g.done.Add(1)
	go g.pumpOut(ctx)
	if err := g.startDHCP(ctx); err != nil {
		g.Close()
		return nil, err
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
		g.cfg.Out(frame)
	}
}

// Inbound feeds a frame that arrived from the bond into the stack.
func (g *Gateway) Inbound(frame []byte) {
	if g.closed.Load() || len(frame) < header.EthernetMinimumSize {
		return
	}
	g.framesIn.Add(1)
	if g.foreignARPRequest(frame) {
		return
	}
	g.learnNeighbour(frame)
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(frame)})
	g.link.InjectInbound(0, pkt)
	pkt.DecRef()
}

// learnNeighbour pins the sender of an IPv4 frame as a static neighbour. Without it the stack must
// ARP for the device every time it answers from a new (spoofed) remote address, with that remote
// address as the ARP sender, which costs a round trip per flow and confuses some devices.
func (g *Gateway) learnNeighbour(f []byte) {
	if len(f) < 34 || f[12] != 0x08 || f[13] != 0x00 || f[6]&1 == 1 {
		return
	}
	ip := netip.AddrFrom4([4]byte{f[26], f[27], f[28], f[29]})
	if ip.IsUnspecified() || ip == g.cfg.Address.Addr() || !g.cfg.Address.Contains(ip) {
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
	g.stack.AddStaticNeighbor(nicID, ipv4.ProtocolNumber, tcpip.AddrFrom4(ip.As4()), tcpip.LinkAddress(mac[:]))
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
	g.cancel()
	g.stack.Close()
	g.link.Close()
	g.done.Wait()
}
