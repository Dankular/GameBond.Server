package l2gw

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// A UDP mapping is one outbound socket per device source endpoint (ip:port), the endpoint-independent
// mapping that game consoles and STUN-style NAT tests call "open" or type 2. Everything the device
// sends from that port leaves through the same public port whatever the destination, and datagrams
// arriving at that port from any address are delivered to the device with their real source
// address. The connected per-destination sockets this replaces drop every reply that comes from a
// different address or port than the one the device sent to, which is exactly what makes a console
// report NAT type 3 and fail to sign in.
type udpMapping struct {
	g   *Gateway
	src netip.AddrPort
	pc  net.PacketConn

	mu     sync.Mutex
	eps    map[netip.AddrPort]*gonet.UDPConn // remote address -> device-facing endpoint
	last   time.Time
	closed bool
}

func (g *Gateway) listenUDP() (net.PacketConn, error) {
	if g.cfg.Listen != nil {
		return g.cfg.Listen()
	}
	return net.ListenPacket("udp4", "0.0.0.0:0")
}

// mappingFor returns the live mapping for a device endpoint, creating it on the first datagram.
func (g *Gateway) mappingFor(src netip.AddrPort) (*udpMapping, error) {
	g.udpMu.Lock()
	defer g.udpMu.Unlock()
	if m := g.udpMaps[src]; m != nil {
		return m, nil
	}
	pc, err := g.listenUDP()
	if err != nil {
		return nil, err
	}
	m := &udpMapping{g: g, src: src, pc: pc, eps: map[netip.AddrPort]*gonet.UDPConn{}, last: time.Now()}
	if g.udpMaps == nil {
		g.udpMaps = map[netip.AddrPort]*udpMapping{}
	}
	g.udpMaps[src] = m
	go m.readLoop()
	return m, nil
}

// UDPMapping is one live mapping as the control plane sees it.
type UDPMapping struct {
	Device string // the device endpoint
	Public string // the exit's socket that stands for it
	Peers  int    // remote addresses it is talking to
}

// UDPMappings lists the live mappings.
func (g *Gateway) UDPMappings() []UDPMapping {
	g.udpMu.Lock()
	defer g.udpMu.Unlock()
	var out []UDPMapping
	for src, m := range g.udpMaps {
		m.mu.Lock()
		out = append(out, UDPMapping{Device: src.String(), Public: m.pc.LocalAddr().String(), Peers: len(m.eps)})
		m.mu.Unlock()
	}
	return out
}

func (m *udpMapping) touch() { m.mu.Lock(); m.last = time.Now(); m.mu.Unlock() }

func (m *udpMapping) quiet() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return time.Since(m.last) >= m.g.cfg.IdleUDP
}

func (m *udpMapping) close() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	eps := make([]*gonet.UDPConn, 0, len(m.eps))
	for _, c := range m.eps {
		eps = append(eps, c)
	}
	m.mu.Unlock()
	m.pc.Close()
	for _, c := range eps {
		c.Close()
	}
	m.g.udpMu.Lock()
	if m.g.udpMaps[m.src] == m {
		delete(m.g.udpMaps, m.src)
	}
	m.g.udpMu.Unlock()
}

// attach registers a device-facing endpoint for one remote and starts relaying what the device
// sends to it out through the mapping's public socket.
func (m *udpMapping) attach(remote netip.AddrPort, c *gonet.UDPConn, release func()) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		c.Close()
		if release != nil {
			release()
		}
		return
	}
	if old := m.eps[remote]; old != nil {
		old.Close()
	}
	m.eps[remote] = c
	m.mu.Unlock()
	m.g.udpFlows.Add(1)
	go func() {
		defer m.g.udpFlows.Add(-1)
		if release != nil {
			defer release()
		}
		to := net.UDPAddrFromAddrPort(remote)
		buf := make([]byte, 64*1024)
		for {
			c.SetReadDeadline(time.Now().Add(time.Second))
			n, err := c.Read(buf)
			if err == nil {
				m.touch()
				m.pc.WriteTo(buf[:n], to)
				continue
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() && !m.quiet() {
				m.mu.Lock()
				stale := m.closed || m.eps[remote] != c
				m.mu.Unlock()
				if stale {
					return
				}
				continue
			}
			m.mu.Lock()
			if m.eps[remote] == c {
				delete(m.eps, remote)
			}
			m.mu.Unlock()
			c.Close()
			return
		}
	}()
}

// readLoop delivers datagrams that reach the public socket to the device, from any source.
func (m *udpMapping) readLoop() {
	defer m.close()
	buf := make([]byte, 64*1024)
	for {
		m.pc.SetReadDeadline(time.Now().Add(time.Second))
		n, from, err := m.pc.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if m.quiet() {
					return
				}
				continue
			}
			return
		}
		ua, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}
		ap := ua.AddrPort()
		remote := netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
		if !remote.Addr().Is4() {
			continue
		}
		m.mu.Lock()
		c := m.eps[remote]
		m.mu.Unlock()
		if c == nil {
			if m.g.cfg.RestrictedUDP || m.g.draining.Load() {
				m.g.blocked.Add(1)
				continue
			}
			// A new peer talking to a port the device opened: the full-cone case. Hard-blocked
			// sources (loopback, multicast, the exit's own networks) are never let in.
			if blockedHard(remote.Addr()) && !m.g.cfg.AllowPrivate {
				m.g.blocked.Add(1)
				continue
			}
			nc, err := m.g.deviceEndpoint(remote, m.src)
			if err != nil {
				continue
			}
			m.attach(remote, nc, nil)
			c = nc
		}
		m.touch()
		c.Write(buf[:n])
	}
}

// deviceEndpoint makes a stack endpoint that speaks to the device as remote: bound to the remote's
// address (the NIC accepts any address in spoofing mode) and connected to the device endpoint.
func (g *Gateway) deviceEndpoint(remote, dev netip.AddrPort) (*gonet.UDPConn, error) {
	var wq waiter.Queue
	ep, terr := g.stack.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if terr != nil {
		return nil, &net.OpError{Op: "endpoint", Err: net.UnknownNetworkError(terr.String())}
	}
	if terr := ep.Bind(tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFrom4(remote.Addr().As4()), Port: remote.Port()}); terr != nil {
		ep.Close()
		return nil, &net.OpError{Op: "bind", Err: net.UnknownNetworkError(terr.String())}
	}
	if terr := ep.Connect(tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFrom4(dev.Addr().As4()), Port: dev.Port()}); terr != nil {
		ep.Close()
		return nil, &net.OpError{Op: "connect", Err: net.UnknownNetworkError(terr.String())}
	}
	return gonet.NewUDPConn(&wq, ep), nil
}

// udpFlow is the device-initiated path: the forwarder hands over the first datagram for a new
// (device, destination) pair and the endpoint joins the device's mapping.
func (g *Gateway) udpFlow(r *udp.ForwarderRequest, dst netip.AddrPort, release func()) {
	id := r.ID()
	src := netip.AddrPortFrom(addrOf(id.RemoteAddress), id.RemotePort)
	m, err := g.mappingFor(src)
	if err != nil {
		g.dialFailed.Add(1)
		release()
		return
	}
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		release()
		return
	}
	m.attach(dst, gonet.NewUDPConn(&wq, ep), release)
}
