//go:build linux

package edge

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Dankular/GameBond.Core/bond"
	"github.com/Dankular/GameBond.Server/l2gw"
	"golang.org/x/sys/unix"
)

// Switch ports of the exit: the bond (every frame the client sent) and the TAP (the exit side
// of the bridged domain).
const (
	l2PortTunnel  bond.PortID = 1
	l2PortTap     bond.PortID = 2
	l2PortMonitor bond.PortID = 3
)

// l2Edge owns the exit side of the carried segment and the transport's switch core. With a bridge
// section the exit side is the userspace gateway (l2gw): no TAP, bridge, DHCP daemon or NAT rule,
// and every flow is visible. Without one it is a TAP for the host to wire. Frames from the bond pass the switch
// before they reach the TAP and the other way round, so MAC cap, loop guard and storm control
// protect the bridged domain from either side.
type l2Edge struct {
	fd                      int // the TAP, or in gateway mode an eventfd that wakes the loop when the gateway has frames
	notifyFD                int // eventfd for fabric deliveries; gateway mode reuses fd
	monitorFD               int // output-only capture TAP; -1 when mirroring is disabled
	name                    string
	sw                      *bond.L2Switch
	gw                      *l2gw.Gateway
	bridge                  *L2Bridge // the section the gateway was started with
	config                  *L2Config
	fabric                  *SegmentFabric
	tunnelPort, servicePort *SegmentPort
	qmu                     sync.Mutex
	q                       [][]byte // frames the gateway produced, drained by the packet loop
	fabricQ                 []fabricDelivery
	fabricCancel            context.CancelFunc
	fabricWG                sync.WaitGroup
	// counters touched only by the packet loop, read through Stats
	toTap, fromTap, tapFull, switchDrops              atomic.Uint64
	mirrored, mirrorFull                              atomic.Uint64
	fabricToTunnel, fabricToService, fabricQueueDrops atomic.Uint64
}

type fabricDelivery struct {
	port            *SegmentPort
	frame           []byte
	ingressPort     bond.PortID
	ingressIdentity string
}

func openL2(c *L2Config) (*l2Edge, error) {
	return openL2WithFabric(c, nil)
}

func openL2WithFabric(c *L2Config, fabric *SegmentFabric, sessionName ...string) (*l2Edge, error) {
	if fabric != nil && c.Bridge != nil {
		return nil, errors.New("shared in-process segment mode does not support a per-session gVisor gateway; attach one shared gateway service port separately")
	}
	if c.Bridge != nil {
		return openGateway(c, fabric)
	}
	if fabric != nil {
		name := "session"
		if len(sessionName) > 0 && sessionName[0] != "" {
			name += "-" + sessionName[0]
		}
		e := &l2Edge{fd: -1, notifyFD: -1, monitorFD: -1, name: name, config: c, fabric: fabric}
		if err := e.attachFabricPorts(c, name); err != nil {
			e.close()
			return nil, err
		}
		return e, nil
	}
	fd, err := openTap(c.TapName, c.FrameMTU-bond.EthHeaderLen)
	if err != nil {
		return nil, err
	}
	monitorFD, err := openMonitorTap(c)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	var sw *bond.L2Switch
	if fabric == nil {
		sw = l2Switch(c, c.TapName)
	}
	e := &l2Edge{fd: fd, notifyFD: -1, monitorFD: monitorFD, name: c.TapName, sw: sw, config: c, fabric: fabric}
	if err := e.attachFabricPorts(c, c.TapName); err != nil {
		e.close()
		return nil, err
	}
	return e, nil
}

func l2Switch(c *L2Config, second string) *bond.L2Switch {
	exitPort := bond.L2PortConfig{ID: l2PortTap, Name: second, BPDUGuard: c.BPDUGuardExit, RAGuard: c.RAGuardExit, ControlPlanePPS: c.ControlPlanePPS, ControlPlaneRates: c.ControlPlaneRates, VLAN: c.ExitVLAN}
	_ = c.ExitPrivateVLAN.apply(&exitPort) // validated before opening the edge
	if c.Bridge != nil {
		if address, err := netip.ParsePrefix(c.Bridge.Address); err == nil {
			exitPort = gatewayQuerierPort(exitPort, c.Bridge, address.Addr().As4())
		}
	}
	tunnelPort := bond.L2PortConfig{ID: l2PortTunnel, Name: "bond", MACLimit: c.MACLimit, BroadcastPPS: c.BroadcastPPS, MulticastPPS: c.MulticastPPS, UnknownUnicastPPS: c.UnknownUnicastPPS, BPDUGuard: c.BPDUGuardTunnel, RAGuard: c.RAGuardTunnel, IPv4SourceGuard: c.IPv4SourceGuardTunnel, IPv6SourceGuard: c.IPv6SourceGuardTunnel, VLAN: c.TunnelVLAN, MulticastRouter: c.MulticastRouterTunnel}
	_ = c.TunnelPrivateVLAN.apply(&tunnelPort) // validated before opening the edge
	ports := []bond.L2PortConfig{
		tunnelPort,
		exitPort,
	}
	if c.RSTP != nil {
		ports[0].RSTPParticipant = true
		if c.Bridge == nil {
			ports[1].RSTPParticipant = true
		}
	}
	var mirrors []bond.L2Mirror
	if c.Monitor != nil {
		ports = append(ports, bond.L2PortConfig{ID: l2PortMonitor, Name: c.Monitor.TapName, Monitor: true})
		mirrors = []bond.L2Mirror{
			{Source: l2PortTunnel, Monitor: l2PortMonitor, Ingress: c.Monitor.TunnelIngress, Egress: c.Monitor.TunnelEgress},
			{Source: l2PortTap, Monitor: l2PortMonitor, Ingress: c.Monitor.ExitIngress, Egress: c.Monitor.ExitEgress},
		}
	}
	settings, _ := RSTPSwitchConfig(c.RSTP) // L2Config validation runs before the edge is opened.
	settings.Ports, settings.Mirrors, settings.MVR = ports, mirrors, c.MVR
	return bond.NewL2Switch(settings)
}

var defaultGatewayMAC = [6]byte{0x02, 0x47, 0x42, 0, 0, 1}

func gatewayQuerierPort(port bond.L2PortConfig, bridge *L2Bridge, ipv4 [4]byte) bond.L2PortConfig {
	port.ControlPlane = true
	port.MulticastRouter = true
	port.MulticastQuerier = true
	port.QuerierMAC = defaultGatewayMAC
	port.QuerierIPv4 = ipv4
	if bridge != nil && bridge.IPv6Address != "" {
		port.QuerierIPv6 = linkLocalFromMAC(defaultGatewayMAC)
	}
	if bridge != nil && bridge.PrivateVLAN != 0 {
		port.PrivateVLAN = bridge.PrivateVLAN
		port.PrivateVLANRole = bond.L2PVLANPromiscuous
		port.PVLANPrimaryVLAN = port.VLAN.AccessVLAN
	}
	return port
}

func linkLocalFromMAC(mac [6]byte) [16]byte {
	return [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, mac[0] ^ 0x02, mac[1], mac[2], 0xff, 0xfe, mac[3], mac[4], mac[5]}
}

func openTap(name string, mtu int) (int, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	request, err := unix.NewIfreq(name)
	if err != nil {
		unix.Close(fd)
		return -1, err
	}
	request.SetUint16(unix.IFF_TAP | unix.IFF_NO_PI)
	if err = unix.IoctlIfreq(fd, unix.TUNSETIFF, request); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("open TAP %s: %w", name, err)
	}
	if err = configureTap(name, mtu); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func openMonitorTap(c *L2Config) (int, error) {
	if c.Monitor == nil {
		return -1, nil
	}
	return openTap(c.Monitor.TapName, c.FrameMTU-bond.EthHeaderLen)
}

// openGateway starts the userspace gateway for the bridge section.
func openGateway(c *L2Config, fabric *SegmentFabric) (*l2Edge, error) {
	b := c.Bridge
	pfx, err := netip.ParsePrefix(b.Address)
	if err != nil {
		return nil, err
	}
	// FrameMTU reserves enough room for the largest configured egress tag
	// stack. Strip that overhead before setting the gateway's IP MTU.
	cfg := l2gw.Config{Address: pfx, MTU: gatewayStackMTU(c)}
	cfg.ECMPPaths = append([]l2gw.ECMPPath(nil), b.EgressPaths...)
	if b.LLDPMEDPolicy != nil {
		cfg.LLDPMEDPolicy = &l2gw.LLDPMEDNetworkPolicy{
			ApplicationType: b.LLDPMEDPolicy.ApplicationType, VLANID: b.LLDPMEDPolicy.VLANID,
			Tagged: b.LLDPMEDPolicy.Tagged, L2Priority: b.LLDPMEDPolicy.L2Priority, DSCP: b.LLDPMEDPolicy.DSCP,
		}
	}
	if b.IPv6Address != "" {
		cfg.IPv6Address, err = netip.ParsePrefix(b.IPv6Address)
		if err != nil {
			return nil, err
		}
	}
	if b.DHCPRelay6 != "" {
		cfg.DHCPRelay6, err = netip.ParseAddrPort(b.DHCPRelay6)
		if err != nil {
			return nil, err
		}
	}
	if b.DHCPRelayLink6 != "" {
		cfg.DHCPRelayLink6, err = netip.ParseAddr(b.DHCPRelayLink6)
		if err != nil {
			return nil, err
		}
	}
	if b.DHCPv6PDPool != "" {
		cfg.DHCPv6PDPool, err = netip.ParsePrefix(b.DHCPv6PDPool)
		if err != nil {
			return nil, err
		}
		cfg.DHCPv6PDBits = b.DHCPv6PDBits
	}
	// Bridged devices get the same observers as tunnel traffic: the IDS and traffic classifier see every packet,
	// and the DNS filter answers every query. Both are resolved per call, so a settings change applies at once.
	cfg.Tap = func(fromDevice bool, p []byte) {
		if f := tap.Load(); f != nil {
			(*f)(fromDevice, p)
		}
	}
	cfg.DNSFilter = &l2gw.DNSHook{
		On: func() bool {
			h := dnsFilter.Load()
			return h != nil && (h.On == nil || h.On())
		},
		Handle: func(client netip.Addr, req []byte, tcp bool) []byte {
			if h := dnsFilter.Load(); h != nil {
				return h.Handle(client, req, tcp)
			}
			return nil
		},
	}
	cfg.DHCPStart, _ = netip.ParseAddr(b.DHCPStart)
	cfg.DHCPEnd, _ = netip.ParseAddr(b.DHCPEnd)
	if b.DHCPRelay4 != "" {
		cfg.DHCPRelay4, _ = netip.ParseAddrPort(b.DHCPRelay4)
	}
	if b.DHCPRelayGateway4 != "" {
		cfg.DHCPRelayGateway4, _ = netip.ParseAddr(b.DHCPRelayGateway4)
	}
	if cfg.Lease, err = time.ParseDuration(b.Lease); err != nil {
		return nil, err
	}
	for _, d := range b.DNS {
		a, _ := netip.ParseAddr(d)
		cfg.DNS = append(cfg.DNS, a)
	}
	for _, d := range b.DNS6 {
		a, _ := netip.ParseAddr(d)
		cfg.DNS6 = append(cfg.DNS6, a)
	}
	for _, h := range b.Hosts {
		mac, _ := net.ParseMAC(h.MAC)
		ip, _ := netip.ParseAddr(h.IP)
		cfg.Hosts = append(cfg.Hosts, l2gw.Host{MAC: mac, IP: ip, Name: h.Name})
	}
	for _, h := range b.Hosts6 {
		clientID, _ := hex.DecodeString(h.ClientIDHex)
		mac, _ := net.ParseMAC(h.MAC)
		ip, _ := netip.ParseAddr(h.IP)
		cfg.Hosts6 = append(cfg.Hosts6, l2gw.DHCPv6Host{ClientID: clientID, IAID: h.IAID, MAC: mac, IP: ip})
	}
	fd, monitorFD := -1, -1
	if fabric == nil {
		fd, err = unix.Eventfd(0, unix.EFD_NONBLOCK|unix.EFD_CLOEXEC)
		if err != nil {
			return nil, err
		}
		monitorFD, err = openMonitorTap(c)
		if err != nil {
			unix.Close(fd)
			return nil, err
		}
	}
	var sw *bond.L2Switch
	if fabric == nil {
		sw = l2Switch(c, "gateway")
	}
	e := &l2Edge{fd: fd, notifyFD: -1, monitorFD: monitorFD, name: "gateway", sw: sw, bridge: b, config: c, fabric: fabric}
	if fabric != nil {
		name := "gateway-" + c.SegmentID
		if c.ExitVLAN.AccessVLAN != 0 {
			name += fmt.Sprintf("-vlan-%d", c.ExitVLAN.AccessVLAN)
		}
		mirrorIngress, mirrorEgress := false, false
		if c.Monitor != nil {
			mirrorIngress, mirrorEgress = c.Monitor.ExitIngress, c.Monitor.ExitEgress
		}
		servicePort := gatewayQuerierPort(bond.L2PortConfig{Name: name, VLAN: c.ExitVLAN, ControlPlanePPS: c.ControlPlanePPS, ControlPlaneRates: c.ControlPlaneRates}, b, pfx.Addr().As4())
		e.servicePort, err = fabric.AttachService(servicePort, 0, mirrorIngress, mirrorEgress)
	} else {
		err = e.attachFabricPorts(c, "gateway")
	}
	if err != nil {
		e.close()
		return nil, err
	}
	if fabric != nil {
		cfg.Out = func(frame []byte) {
			if e.servicePort.Send(frame, time.Now()).Drop != bond.L2Forward {
				e.switchDrops.Add(1)
			}
		}
	} else {
		cfg.Out = e.enqueue
	}
	if e.gw, err = l2gw.New(cfg); err != nil {
		e.close()
		return nil, err
	}
	if b.Policy != nil {
		if err := e.applyPolicy(b); err != nil {
			e.close()
			return nil, err
		}
	}
	if fabric == nil {
		activeL2.Store(e)
	}
	return e, nil
}

func (e *l2Edge) attachFabricPorts(c *L2Config, sessionName string) error {
	if e.fabric == nil {
		return nil
	}
	var err error
	mirrorIngress, mirrorEgress := false, false
	if c.Monitor != nil {
		mirrorIngress, mirrorEgress = c.Monitor.TunnelIngress, c.Monitor.TunnelEgress
	}
	e.tunnelPort, err = e.fabric.AttachSession(bond.L2PortConfig{
		Name: sessionName, MACLimit: c.MACLimit, BroadcastPPS: c.BroadcastPPS,
		MulticastPPS: c.MulticastPPS, UnknownUnicastPPS: c.UnknownUnicastPPS,
		BPDUGuard: c.BPDUGuardTunnel, RAGuard: c.RAGuardTunnel, IPv4SourceGuard: c.IPv4SourceGuardTunnel, IPv6SourceGuard: c.IPv6SourceGuardTunnel,
		VLAN: c.TunnelVLAN, MulticastRouter: c.MulticastRouterTunnel,
	}, 0, mirrorIngress, mirrorEgress)
	if err != nil {
		return fmt.Errorf("attach tunnel to Layer 2 segment: %w", err)
	}
	return nil
}

// startFabric starts bounded, nonblocking delivery pumps from the fabric's tunnel
// and service ports into the packet-loop queue. The packet loop remains the only
// caller of Session.TUN and Gateway.Inbound.
func (e *l2Edge) startFabric(parent context.Context) error {
	if e.fabric == nil {
		return nil
	}
	if e.gw != nil {
		e.notifyFD = e.fd
	} else {
		fd, err := unix.Eventfd(0, unix.EFD_NONBLOCK|unix.EFD_CLOEXEC)
		if err != nil {
			return fmt.Errorf("create Layer 2 fabric eventfd: %w", err)
		}
		e.notifyFD = fd
	}
	ctx, cancel := context.WithCancel(parent)
	e.fabricCancel = cancel
	for _, port := range []*SegmentPort{e.tunnelPort} {
		if port == nil {
			continue
		}
		e.fabricWG.Add(1)
		go func(port *SegmentPort) {
			defer e.fabricWG.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case frame, ok := <-port.Receive():
					if !ok {
						return
					}
					e.enqueueFabric(port, frame)
				}
			}
		}(port)
	}
	return nil
}

func (e *l2Edge) enqueueFabric(port *SegmentPort, frame SegmentFrame) {
	e.qmu.Lock()
	if len(e.fabricQ) < 4096 {
		e.fabricQ = append(e.fabricQ, fabricDelivery{port: port, frame: frame.Frame, ingressPort: frame.IngressPort, ingressIdentity: frame.IngressIdentity})
	} else {
		e.fabricQueueDrops.Add(1)
		e.qmu.Unlock()
		return
	}
	e.qmu.Unlock()
	if e.notifyFD >= 0 {
		_, _ = unix.Write(e.notifyFD, []byte{1, 0, 0, 0, 0, 0, 0, 0})
	}
}

// activeL2 is the running gateway edge, so a config reload can reach it.
var activeL2 atomic.Pointer[l2Edge]
var activeSegmentL2 atomic.Pointer[[]*l2Edge]

// policyFor turns the config section into the gateway's rule set.
func policyFor(b *L2Bridge) (l2gw.Policy, error) {
	var p l2gw.Policy
	for _, h := range b.Hosts {
		mac, err := net.ParseMAC(h.MAC)
		if err != nil {
			return p, err
		}
		ip, err := netip.ParseAddr(h.IP)
		if err != nil {
			return p, err
		}
		p.Hosts = append(p.Hosts, l2gw.Host{MAC: mac, IP: ip, Name: h.Name})
	}
	rule := func(r L2DeviceRule) (l2gw.DeviceRule, error) {
		out := l2gw.DeviceRule{Deny: r.Deny, AllowPrivate: r.AllowPrivate, MaxFlows: r.MaxFlows}
		for _, port := range r.BlockPorts {
			out.BlockPorts = append(out.BlockPorts, uint16(port))
		}
		for _, n := range r.BlockNets {
			pfx, err := netip.ParsePrefix(n)
			if err != nil {
				return out, err
			}
			out.BlockNets = append(out.BlockNets, pfx)
		}
		return out, nil
	}
	if b.Policy == nil {
		return p, nil
	}
	p.Version = b.Policy.Version
	var err error
	if p.Default, err = rule(b.Policy.Default); err != nil {
		return p, err
	}
	for _, d := range b.Policy.Devices {
		mac, err := net.ParseMAC(d.MAC)
		if err != nil {
			return p, err
		}
		r, err := rule(d.L2DeviceRule)
		if err != nil {
			return p, err
		}
		p.Devices = append(p.Devices, l2gw.DevicePolicy{MAC: mac, Name: d.Name, Rule: r})
	}
	return p, nil
}

func (e *l2Edge) applyPolicy(b *L2Bridge) error {
	p, err := policyFor(b)
	if err != nil {
		return err
	}
	return e.gw.SetPolicy(p)
}

// ReloadL2 applies the l2.bridge hosts and policy of a freshly read config to the running gateway,
// without a restart. The address, pool and lease time still need one: changing them under live
// leases would strand devices, so a change there is refused.
func ReloadL2(data []byte) error {
	if segment := activeSegmentL2.Load(); segment != nil {
		return reloadSegmentL2(data, *segment)
	}
	e := activeL2.Load()
	if e == nil || e.gw == nil {
		return errors.New("no Layer 2 gateway is running")
	}
	c, _, _, _, err := DecodeConfig(data)
	if err != nil {
		return err
	}
	if c.L2 == nil || !c.L2.Enabled || c.L2.Bridge == nil {
		return errors.New("the new config has no l2.bridge section")
	}
	if e.config == nil || !reflect.DeepEqual(l2RestartSettings(c.L2), l2RestartSettings(e.config)) {
		return errors.New("Layer 2 interface, monitor, addressing, pool, resolver and gateway setting changes need a restart")
	}
	if err := e.applyPolicy(c.L2.Bridge); err != nil {
		return err
	}
	e.config = c.L2
	e.bridge = c.L2.Bridge
	return nil
}

func reloadSegmentL2(data []byte, gateways []*l2Edge) error {
	c, _, _, _, err := DecodeConfig(data)
	if err != nil {
		return err
	}
	if c.L2 == nil || !c.L2.Enabled || c.L2.Bridge == nil {
		return errors.New("the new config has no l2.bridge section")
	}
	configs := make([]*L2Config, 0, len(gateways))
	if len(c.L2.Bridge.VLANs) == 0 {
		if len(gateways) != 1 {
			return errors.New("changing the gateway VLAN set needs a restart")
		}
		configs = append(configs, c.L2)
	} else {
		for _, entry := range c.L2.Bridge.VLANs {
			l2 := *c.L2
			gateway := *entry.Gateway
			gateway.LLDPMEDPolicy = entry.LLDPMEDPolicy
			l2.Bridge = &gateway
			l2.ExitVLAN = bond.L2VLANPolicy{AccessVLAN: entry.VLANID}
			configs = append(configs, &l2)
		}
	}
	if len(configs) != len(gateways) {
		return errors.New("changing the gateway VLAN set needs a restart")
	}
	byVLAN := make(map[uint16]*L2Config, len(configs))
	for _, cfg := range configs {
		byVLAN[cfg.ExitVLAN.AccessVLAN] = cfg
	}
	policies := make(map[*l2Edge]l2gw.Policy, len(gateways))
	for _, e := range gateways {
		cfg := byVLAN[e.config.ExitVLAN.AccessVLAN]
		if cfg == nil || !reflect.DeepEqual(l2RestartSettings(cfg), l2RestartSettings(e.config)) {
			return errors.New("Layer 2 interface, monitor, VLAN, addressing, pool, resolver and gateway setting changes need a restart")
		}
		p, err := policyFor(cfg.Bridge)
		if err != nil {
			return err
		}
		if err := p.Validate(); err != nil {
			return err
		}
		policies[e] = p
	}
	for _, e := range gateways {
		cfg := byVLAN[e.config.ExitVLAN.AccessVLAN]
		if err := e.gw.SetPolicy(policies[e]); err != nil {
			return err
		}
		e.config = cfg
		e.bridge = cfg.Bridge
	}
	return nil
}

// l2RestartSettings removes the live-reloadable host bindings and device policy.
// Every other setting changes the active interface or gateway and must be applied
// by restarting the edge, rather than accepted while the running datapath ignores it.
func l2RestartSettings(c *L2Config) L2Config {
	settings := *c
	if c.Bridge != nil {
		bridge := *c.Bridge
		bridge.Hosts = nil
		bridge.Policy = nil
		settings.Bridge = &bridge
	}
	return settings
}

// enqueue is called from the gateway's goroutines; the packet loop does the sending.
func (e *l2Edge) enqueue(frame []byte) {
	e.qmu.Lock()
	if len(e.q) < 4096 {
		e.q = append(e.q, frame)
	} else {
		e.tapFull.Add(1)
	}
	e.qmu.Unlock()
	unix.Write(e.fd, []byte{1, 0, 0, 0, 0, 0, 0, 0})
}

// drainGateway runs on the packet loop when the eventfd fires.
func (e *l2Edge) drainGateway(engine *bond.Session, now time.Time) {
	var scratch [8]byte
	unix.Read(e.fd, scratch[:])
	e.qmu.Lock()
	frames := e.q
	e.q = nil
	e.qmu.Unlock()
	for _, f := range frames {
		e.fromTapFrame(f, engine, now)
	}
	e.drainFabricQueue(engine, now)
}

// drainFabric handles frames queued by the shared segment on the packet-loop actor.
func (e *l2Edge) drainFabric(engine *bond.Session, now time.Time) {
	if e.notifyFD >= 0 && e.notifyFD != e.fd {
		var scratch [8]byte
		_, _ = unix.Read(e.notifyFD, scratch[:])
	}
	e.drainFabricQueue(engine, now)
}

func (e *l2Edge) drainFabricQueue(engine *bond.Session, now time.Time) {
	e.qmu.Lock()
	frames := e.fabricQ
	e.fabricQ = nil
	e.qmu.Unlock()
	for _, delivery := range frames {
		if delivery.port == e.tunnelPort {
			if engine.TUN(bond.WrapFrame(delivery.frame), now) {
				e.fabricToTunnel.Add(1)
				e.fromTap.Add(1)
			}
			continue
		}
		if delivery.port != e.servicePort {
			continue
		}
		if e.gw != nil {
			e.gw.InboundFrom(delivery.frame, delivery.ingressIdentity)
			e.fabricToService.Add(1)
			e.toTap.Add(1)
			continue
		}
		if n, err := unix.Write(e.fd, delivery.frame); err != nil || n != len(delivery.frame) {
			e.tapFull.Add(1)
			continue
		}
		e.fabricToService.Add(1)
		e.toTap.Add(1)
	}
}

// configureTap sets the interface MTU and brings it up, so the bridge can take it as it is.
func configureTap(name string, mtu int) error {
	s, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(s)
	r, err := unix.NewIfreq(name)
	if err != nil {
		return err
	}
	r.SetUint32(uint32(mtu))
	if err = unix.IoctlIfreq(s, unix.SIOCSIFMTU, r); err != nil {
		return fmt.Errorf("set %s MTU %d: %w", name, mtu, err)
	}
	r, _ = unix.NewIfreq(name)
	if err = unix.IoctlIfreq(s, unix.SIOCGIFFLAGS, r); err != nil {
		return err
	}
	r.SetUint16(r.Uint16() | unix.IFF_UP)
	if err = unix.IoctlIfreq(s, unix.SIOCSIFFLAGS, r); err != nil {
		return fmt.Errorf("bring up %s: %w", name, err)
	}
	return nil
}

func (e *l2Edge) close() {
	if e.gw != nil {
		e.gw.Close()
	}
	if e.fabricCancel != nil {
		e.fabricCancel()
	}
	if e.tunnelPort != nil {
		e.tunnelPort.Close()
	}
	if e.servicePort != nil {
		e.servicePort.Close()
	}
	e.fabricWG.Wait()
	if e.fd >= 0 {
		unix.Close(e.fd)
	}
	if e.notifyFD >= 0 && e.notifyFD != e.fd {
		unix.Close(e.notifyFD)
	}
	if e.monitorFD >= 0 {
		unix.Close(e.monitorFD)
	}
}

// deliver handles an L2 payload that arrived over the bond. Frames are best effort: a refused,
// filtered or backed-up frame is counted and consumed, never retried, so Ethernet traffic can
// not stall the IP packets behind it.
func (e *l2Edge) deliver(payload []byte, now time.Time) error {
	frame, ok := bond.UnwrapFrame(payload)
	if !ok {
		return bond.ErrPacketRejected
	}
	if e.fabric != nil {
		v := e.tunnelPort.Send(frame, now)
		if v.Drop != bond.L2Forward {
			e.switchDrops.Add(1)
		}
		return nil
	}
	v := e.sw.Forward(l2PortTunnel, frame, now)
	e.writeMirror(v.Mirror, frame, v.MirrorFrames)
	if v.Drop != bond.L2Forward {
		e.switchDrops.Add(1)
		return nil
	}
	for _, out := range v.Out {
		if out != l2PortTap {
			continue
		}
		outFrame := v.FrameFor(out, frame)
		if e.gw != nil {
			e.gw.Inbound(outFrame)
			e.toTap.Add(1)
			continue
		}
		if _, err := unix.Write(e.fd, outFrame); err != nil {
			if err == unix.EAGAIN || err == unix.ENOBUFS || err == unix.ENETDOWN || err == unix.EIO {
				e.tapFull.Add(1)
				return nil
			}
			if err == unix.EINVAL || err == unix.EMSGSIZE {
				e.switchDrops.Add(1)
				return nil
			}
			return err
		}
		e.toTap.Add(1)
	}
	return nil
}

func (e *l2Edge) emitMulticastQueries(engine *bond.Session, now time.Time) {
	if e == nil || e.sw == nil || engine == nil {
		return // shared fabrics emit from their single gateway runtime
	}
	for _, query := range e.sw.DueMulticastQueries(now) {
		verdict := e.sw.Forward(query.IngressPort, query.Frame, now)
		e.writeMirror(verdict.Mirror, query.Frame, verdict.MirrorFrames)
		if verdict.Drop != bond.L2Forward {
			e.switchDrops.Add(1)
			continue
		}
		for _, out := range verdict.Out {
			if out == l2PortTunnel && engine.TUN(bond.WrapFrame(verdict.FrameFor(out, query.Frame)), now) {
				e.fromTap.Add(1)
			}
		}
	}
}

func (e *l2Edge) emitRSTPBPDUs(engine *bond.Session, now time.Time) {
	if e == nil || engine == nil {
		return
	}
	if e.fabric != nil {
		e.fabric.EmitRSTPBPDUs(now) // a shared switch owns one protocol state for all attached sessions
		return
	}
	if e.sw == nil {
		return
	}
	for port, frame := range e.sw.DueRSTPBPDUs(now) {
		switch port {
		case l2PortTunnel:
			if !engine.TUN(bond.WrapFrame(frame), now) {
				e.switchDrops.Add(1)
			}
		case l2PortTap:
			if e.gw != nil {
				continue // gVisor gateway service ports are not RSTP participants
			}
			n, err := unix.Write(e.fd, frame)
			if err != nil || n != len(frame) {
				e.tapFull.Add(1)
			}
		}
	}
}

// fromTapFrame sends a frame the bridge produced into the bond.
func (e *l2Edge) fromTapFrame(frame []byte, engine *bond.Session, now time.Time) {
	if e.fabric != nil {
		v := e.servicePort.Send(frame, now)
		if v.Drop != bond.L2Forward {
			e.switchDrops.Add(1)
		}
		return
	}
	v := e.sw.Forward(l2PortTap, frame, now)
	e.writeMirror(v.Mirror, frame, v.MirrorFrames)
	if v.Drop != bond.L2Forward {
		e.switchDrops.Add(1)
		return
	}
	for _, out := range v.Out {
		if out == l2PortTunnel && engine.TUN(bond.WrapFrame(v.FrameFor(out, frame)), now) {
			e.fromTap.Add(1)
		}
	}
}

func (e *l2Edge) writeMirror(ports []bond.PortID, frame []byte, rewrites map[bond.PortID][]byte) {
	if e.monitorFD < 0 || len(ports) == 0 {
		return
	}
	for _, port := range ports {
		if port != l2PortMonitor {
			continue
		}
		copyFrame := frame
		if rewritten := rewrites[port]; rewritten != nil {
			copyFrame = rewritten
		}
		if n, err := unix.Write(e.monitorFD, copyFrame); err != nil || n != len(copyFrame) {
			e.mirrorFull.Add(1)
			continue
		}
		e.mirrored.Add(1)
	}
}

// Stats is the panel view: carriage counters plus the switch core's table and drop reasons.
func (e *l2Edge) Stats(now time.Time) map[string]any {
	var st bond.L2SwitchStats
	if e.fabric != nil {
		e.fabric.Sweep(now)
		st = e.fabric.SwitchStats()
	} else {
		e.sw.Sweep(now)
		st = e.sw.Stats()
	}
	extra := map[string]any{}
	if e.gw != nil {
		g := e.gw.Stats()
		extra = map[string]any{"gateway": map[string]any{
			"tcp_flows": g.TCPFlows, "udp_flows": g.UDPFlows, "tcp_total": g.TCPTotal, "udp_total": g.UDPTotal,
			"blocked": g.Blocked, "dial_failed": g.DialFailed, "leases": g.Leases,
			"dhcp_discover": g.DHCPDiscover, "dhcp_request": g.DHCPRequest, "dhcp_ack": g.DHCPAck, "dhcp_nak": g.DHCPNak,
			"dhcp_bindings": e.gw.DHCPBindings(),
			"frames_in":     g.FramesIn, "frames_out": g.FramesOut,
			"stack": g.Stack, "policy_version": e.gw.PolicyVersion(), "draining": e.gw.Draining(), "devices": e.gw.DeviceStats(), "udp_mappings": e.gw.UDPMappings(),
		}, "active_flows": e.gw.ActiveFlows()}
	}
	st2 := map[string]any{
		"tap": e.name, "to_tap": e.toTap.Load(), "from_tap": e.fromTap.Load(),
		"tap_backpressure": e.tapFull.Load(), "switch_drops": e.switchDrops.Load(),
		"mirrored": e.mirrored.Load(), "mirror_backpressure": e.mirrorFull.Load(), "bpdu_guard_trips": st.BPDUGuards, "bpdu_guard_drops": st.DropBPDUGuard,
		"fdb_size": st.FDBSize, "learned": st.Learned, "moves": st.Moves, "aged": st.Aged,
		"forwarded": st.Forwarded, "flooded": st.Flooded,
		"drop_storm": st.DropStorm, "drop_mac_limit": st.DropMACLimit, "drop_blocked": st.DropBlocked, "drop_ip_source_guard": st.DropSourceGuard, "drop_copp": st.DropCoPP,
		"drop_rstp":  st.DropRSTP,
		"loop_holds": st.LoopHolds, "multicast_groups": st.MulticastGroups, "multicast_members": st.MulticastMembers,
		"fabric_to_tunnel": e.fabricToTunnel.Load(), "fabric_to_service": e.fabricToService.Load(), "fabric_queue_drops": e.fabricQueueDrops.Load(),
	}
	if e.sw != nil {
		st2["rstp"] = e.sw.RSTPStatus()
	} else if e.fabric != nil {
		st2["rstp"] = e.fabric.RSTPStatus()
	}
	if e.fabric != nil {
		segment := map[string]any{"shared_in_process": true, "segment_id": e.fabric.Identity(), "stats": e.fabric.Stats()}
		if e.tunnelPort != nil {
			segment["session_port"] = e.tunnelPort.ID()
		}
		if e.servicePort != nil {
			segment["service_port"] = e.servicePort.ID()
		}
		if e.config != nil && e.config.ExitVLAN.AccessVLAN != 0 {
			segment["vlan_id"] = e.config.ExitVLAN.AccessVLAN
		}
		st2["segment_fabric"] = segment
	}
	for k, v := range extra {
		st2[k] = v
	}
	return st2
}

// SetL2Draining makes the gateway refuse new flows while existing ones carry on; it is how an exit
// empties itself before an update. It reports whether a gateway is running.
func SetL2Draining(on bool) bool {
	if segment := activeSegmentL2.Load(); segment != nil {
		for _, e := range *segment {
			e.gw.SetDraining(on)
		}
		return len(*segment) > 0
	}
	e := activeL2.Load()
	if e == nil || e.gw == nil {
		return false
	}
	e.gw.SetDraining(on)
	return true
}

// l2Draining reports whether the gateway is draining and how many flows it still carries.
func l2Draining() (int, bool) {
	if segment := activeSegmentL2.Load(); segment != nil {
		total, draining := 0, false
		for _, e := range *segment {
			total += e.gw.ActiveFlows()
			draining = draining || e.gw.Draining()
		}
		return total, draining
	}
	e := activeL2.Load()
	if e == nil || e.gw == nil || !e.gw.Draining() {
		return 0, false
	}
	return e.gw.ActiveFlows(), true
}

// L2Flows is the number of flows the gateway carries now, for the update probe; -1 without a gateway.
func L2Flows() int {
	if segment := activeSegmentL2.Load(); segment != nil {
		total := 0
		for _, e := range *segment {
			total += e.gw.ActiveFlows()
		}
		return total
	}
	e := activeL2.Load()
	if e == nil || e.gw == nil {
		return -1
	}
	return e.gw.ActiveFlows()
}
