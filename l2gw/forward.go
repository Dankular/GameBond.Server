package l2gw

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

var blockedPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, p := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/3"} {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}()

// allowed says whether devices may open a flow to dst.
func (g *Gateway) allowed(dst netip.Addr) bool {
	if g.cfg.AllowPrivate {
		return true
	}
	for _, p := range blockedPrefixes {
		if p.Contains(dst) {
			return false
		}
	}
	return true
}

func addrOf(a tcpip.Address) netip.Addr { return netip.AddrFrom4(a.As4()) }

func (g *Gateway) installForwarders() {
	tcpFwd := tcp.NewForwarder(g.stack, 0, 4096, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		dst := netip.AddrPortFrom(addrOf(id.LocalAddress), id.LocalPort)
		if g.draining.Load() || !g.allowed(dst.Addr()) {
			g.blocked.Add(1)
			r.Complete(true)
			return
		}
		g.tcpFlows.Add(1)
		g.tcpTotal.Add(1)
		go g.tcpFlow(r, dst)
	})
	g.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	udpFwd := udp.NewForwarder(g.stack, func(r *udp.ForwarderRequest) {
		id := r.ID()
		dst := netip.AddrPortFrom(addrOf(id.LocalAddress), id.LocalPort)
		if g.draining.Load() || !g.allowed(dst.Addr()) {
			g.blocked.Add(1)
			return
		}
		g.udpFlows.Add(1)
		g.udpTotal.Add(1)
		go g.udpFlow(r, dst)
	})
	g.stack.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)
}

// tcpFlow dials the real destination first, so an unreachable host answers the device with a reset
// instead of a connection that then dies, and only then accepts the device's connection.
func (g *Gateway) tcpFlow(r *tcp.ForwarderRequest, dst netip.AddrPort) {
	defer g.tcpFlows.Add(-1)
	out, err := g.cfg.Dial("tcp", dst.String(), g.cfg.DialTimeout)
	if err != nil {
		g.dialFailed.Add(1)
		r.Complete(true)
		return
	}
	defer out.Close()
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		r.Complete(true)
		return
	}
	r.Complete(false)
	in := gonet.NewTCPConn(&wq, ep)
	defer in.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); relay(in, out, g.cfg.IdleTCP); in.CloseWrite() }()
	go func() { defer wg.Done(); relay(out, in, g.cfg.IdleTCP); closeWrite(out) }()
	wg.Wait()
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
}

// relay copies src to dst until EOF, an error or idle time with no data.
func relay(dst, src net.Conn, idle time.Duration) {
	buf := make([]byte, 32*1024)
	for {
		src.SetReadDeadline(time.Now().Add(idle))
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// udpFlow relays one device<->destination datagram flow until it has been quiet for IdleUDP.
func (g *Gateway) udpFlow(r *udp.ForwarderRequest, dst netip.AddrPort) {
	defer g.udpFlows.Add(-1)
	out, err := g.cfg.Dial("udp", dst.String(), g.cfg.DialTimeout)
	if err != nil {
		g.dialFailed.Add(1)
		return
	}
	defer out.Close()
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		return
	}
	in := gonet.NewUDPConn(&wq, ep)
	defer in.Close()
	var mu sync.Mutex
	last := time.Now()
	touch := func() { mu.Lock(); last = time.Now(); mu.Unlock() }
	quiet := func() bool { mu.Lock(); defer mu.Unlock(); return time.Since(last) >= g.cfg.IdleUDP }
	done := make(chan struct{})
	go func() { // internet -> device
		defer close(done)
		buf := make([]byte, 64*1024)
		for {
			out.SetReadDeadline(time.Now().Add(time.Second))
			n, err := out.Read(buf)
			if err == nil {
				touch()
				in.Write(buf[:n])
				continue
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() && !quiet() {
				continue
			}
			return
		}
	}()
	buf := make([]byte, 64*1024) // device -> internet
	for {
		in.SetReadDeadline(time.Now().Add(time.Second))
		n, err := in.Read(buf)
		if err == nil {
			touch()
			out.Write(buf[:n])
			continue
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() && !quiet() {
			select {
			case <-done:
				return
			default:
				continue
			}
		}
		return
	}
}
