//go:build linux

package edge

import (
	"fmt"
	"net"
	"net/netip"
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
	l2PortTunnel bond.PortID = 1
	l2PortTap    bond.PortID = 2
)

// l2Edge owns the exit side of the carried segment and the transport's switch core. With a bridge
// section the exit side is the userspace gateway (l2gw): no TAP, bridge, DHCP daemon or NAT rule,
// and every flow is visible. Without one it is a TAP for the host to wire. Frames from the bond pass the switch
// before they reach the TAP and the other way round, so MAC cap, loop guard and storm control
// protect the bridged domain from either side.
type l2Edge struct {
	fd   int // the TAP, or in gateway mode an eventfd that wakes the loop when the gateway has frames
	name string
	sw   *bond.L2Switch
	gw   *l2gw.Gateway
	qmu  sync.Mutex
	q    [][]byte // frames the gateway produced, drained by the packet loop
	// counters touched only by the packet loop, read through Stats
	toTap, fromTap, tapFull, switchDrops atomic.Uint64
}

func openL2(c *L2Config) (*l2Edge, error) {
	if c.Bridge != nil {
		return openGateway(c)
	}
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	request, err := unix.NewIfreq(c.TapName)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	request.SetUint16(unix.IFF_TAP | unix.IFF_NO_PI)
	if err = unix.IoctlIfreq(fd, unix.TUNSETIFF, request); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("open TAP %s: %w", c.TapName, err)
	}
	if err = configureTap(c.TapName, c.FrameMTU-bond.EthHeaderLen); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return &l2Edge{fd: fd, name: c.TapName, sw: l2Switch(c, c.TapName)}, nil
}

func l2Switch(c *L2Config, second string) *bond.L2Switch {
	return bond.NewL2Switch(bond.L2SwitchConfig{Ports: []bond.L2PortConfig{
		{ID: l2PortTunnel, Name: "bond", MACLimit: c.MACLimit, BroadcastPPS: c.BroadcastPPS, MulticastPPS: c.MulticastPPS, UnknownUnicastPPS: c.UnknownUnicastPPS},
		{ID: l2PortTap, Name: second},
	}})
}

// openGateway starts the userspace gateway for the bridge section.
func openGateway(c *L2Config) (*l2Edge, error) {
	b := c.Bridge
	pfx, err := netip.ParsePrefix(b.Address)
	if err != nil {
		return nil, err
	}
	cfg := l2gw.Config{Address: pfx, MTU: c.FrameMTU - bond.EthHeaderLen}
	cfg.DHCPStart, _ = netip.ParseAddr(b.DHCPStart)
	cfg.DHCPEnd, _ = netip.ParseAddr(b.DHCPEnd)
	if cfg.Lease, err = time.ParseDuration(b.Lease); err != nil {
		return nil, err
	}
	for _, d := range b.DNS {
		a, _ := netip.ParseAddr(d)
		cfg.DNS = append(cfg.DNS, a)
	}
	for _, h := range b.Hosts {
		mac, _ := net.ParseMAC(h.MAC)
		ip, _ := netip.ParseAddr(h.IP)
		cfg.Hosts = append(cfg.Hosts, l2gw.Host{MAC: mac, IP: ip, Name: h.Name})
	}
	fd, err := unix.Eventfd(0, unix.EFD_NONBLOCK|unix.EFD_CLOEXEC)
	if err != nil {
		return nil, err
	}
	e := &l2Edge{fd: fd, name: "gateway", sw: l2Switch(c, "gateway")}
	cfg.Out = e.enqueue
	if e.gw, err = l2gw.New(cfg); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return e, nil
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
	unix.Close(e.fd)
}

// deliver handles an L2 payload that arrived over the bond. Frames are best effort: a refused,
// filtered or backed-up frame is counted and consumed, never retried, so Ethernet traffic can
// not stall the IP packets behind it.
func (e *l2Edge) deliver(payload []byte, now time.Time) error {
	frame, ok := bond.UnwrapFrame(payload)
	if !ok {
		return bond.ErrPacketRejected
	}
	v := e.sw.Forward(l2PortTunnel, frame, now)
	if v.Drop != bond.L2Forward {
		e.switchDrops.Add(1)
		return nil
	}
	for _, out := range v.Out {
		if out != l2PortTap {
			continue
		}
		if e.gw != nil {
			e.gw.Inbound(frame)
			e.toTap.Add(1)
			continue
		}
		if _, err := unix.Write(e.fd, frame); err != nil {
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

// fromTapFrame sends a frame the bridge produced into the bond.
func (e *l2Edge) fromTapFrame(frame []byte, engine *bond.Session, now time.Time) {
	v := e.sw.Forward(l2PortTap, frame, now)
	if v.Drop != bond.L2Forward {
		e.switchDrops.Add(1)
		return
	}
	for _, out := range v.Out {
		if out == l2PortTunnel && engine.TUN(bond.WrapFrame(frame), now) {
			e.fromTap.Add(1)
		}
	}
}

// Stats is the panel view: carriage counters plus the switch core's table and drop reasons.
func (e *l2Edge) Stats(now time.Time) map[string]any {
	e.sw.Sweep(now)
	st := e.sw.Stats()
	extra := map[string]any{}
	if e.gw != nil {
		g := e.gw.Stats()
		extra = map[string]any{"gateway": map[string]any{
			"tcp_flows": g.TCPFlows, "udp_flows": g.UDPFlows, "tcp_total": g.TCPTotal, "udp_total": g.UDPTotal,
			"blocked": g.Blocked, "dial_failed": g.DialFailed, "leases": g.Leases,
			"dhcp_discover": g.DHCPDiscover, "dhcp_request": g.DHCPRequest, "dhcp_ack": g.DHCPAck, "dhcp_nak": g.DHCPNak,
			"frames_in": g.FramesIn, "frames_out": g.FramesOut,
		}, "active_flows": e.gw.ActiveFlows()}
	}
	st2 := map[string]any{
		"tap": e.name, "to_tap": e.toTap.Load(), "from_tap": e.fromTap.Load(),
		"tap_backpressure": e.tapFull.Load(), "switch_drops": e.switchDrops.Load(),
		"fdb_size": st.FDBSize, "learned": st.Learned, "moves": st.Moves, "aged": st.Aged,
		"forwarded": st.Forwarded, "flooded": st.Flooded,
		"drop_storm": st.DropStorm, "drop_mac_limit": st.DropMACLimit, "drop_blocked": st.DropBlocked,
		"loop_holds": st.LoopHolds,
	}
	for k, v := range extra {
		st2[k] = v
	}
	return st2
}
