//go:build linux

package edge

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/Dankular/GameBond.Core/bond"
	"golang.org/x/sys/unix"
)

// Switch ports of the exit: the bond (every frame the client sent) and the TAP (the exit side
// of the bridged domain).
const (
	l2PortTunnel bond.PortID = 1
	l2PortTap    bond.PortID = 2
)

// l2Edge owns the TAP and the transport's switch core. Frames from the bond pass the switch
// before they reach the TAP and the other way round, so MAC cap, loop guard and storm control
// protect the bridged domain from either side.
type l2Edge struct {
	fd   int
	name string
	sw   *bond.L2Switch
	// counters touched only by the packet loop, read through Stats
	toTap, fromTap, tapFull, switchDrops atomic.Uint64
}

func openL2(c *L2Config) (*l2Edge, error) {
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
	return &l2Edge{fd: fd, name: c.TapName, sw: bond.NewL2Switch(bond.L2SwitchConfig{Ports: []bond.L2PortConfig{
		{ID: l2PortTunnel, Name: "bond", MACLimit: c.MACLimit, BroadcastPPS: c.BroadcastPPS, MulticastPPS: c.MulticastPPS, UnknownUnicastPPS: c.UnknownUnicastPPS},
		{ID: l2PortTap, Name: c.TapName},
	}})}, nil
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

func (e *l2Edge) close() { unix.Close(e.fd) }

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
	return map[string]any{
		"tap": e.name, "to_tap": e.toTap.Load(), "from_tap": e.fromTap.Load(),
		"tap_backpressure": e.tapFull.Load(), "switch_drops": e.switchDrops.Load(),
		"fdb_size": st.FDBSize, "learned": st.Learned, "moves": st.Moves, "aged": st.Aged,
		"forwarded": st.Forwarded, "flooded": st.Flooded,
		"drop_storm": st.DropStorm, "drop_mac_limit": st.DropMACLimit, "drop_blocked": st.DropBlocked,
		"loop_holds": st.LoopHolds,
	}
}
