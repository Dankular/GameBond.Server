package l2gw

import (
	"encoding/binary"
	"net/netip"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// tap hands an IPv4 frame's packet to the observer, the same view the tunnel path gives the IDS and the
// traffic classifier.
func (g *Gateway) tap(fromDevice bool, frame []byte) {
	if g.cfg.Tap == nil || len(frame) < header.EthernetMinimumSize+header.IPv4MinimumSize || binary.BigEndian.Uint16(frame[12:]) != 0x0800 {
		return
	}
	g.cfg.Tap(fromDevice, frame[header.EthernetMinimumSize:])
}

func (g *Gateway) dnsOn() bool {
	h := g.cfg.DNSFilter
	return h != nil && h.Handle != nil && (h.On == nil || h.On())
}

// dnsUDP answers a device's DNS datagrams through the filtering resolver. The reply leaves from the
// resolver address the device asked, so a device with its own resolver configured is none the wiser.
func (g *Gateway) dnsUDP(r *udp.ForwarderRequest, release func()) {
	defer release()
	id := r.ID()
	client := addrOf(id.RemoteAddress)
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		return
	}
	c := gonet.NewUDPConn(&wq, ep)
	defer c.Close()
	g.udpFlows.Add(1)
	defer g.udpFlows.Add(-1)
	buf := make([]byte, 4096)
	for {
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		if resp := g.cfg.DNSFilter.Handle(client, append([]byte(nil), buf[:n]...), false); resp != nil {
			c.Write(resp)
		}
	}
}

// dnsTCP is the stream form: two-byte length, then the message.
func (g *Gateway) dnsTCP(r *tcp.ForwarderRequest) {
	defer g.tcpFlows.Add(-1)
	id := r.ID()
	client := addrOf(id.RemoteAddress)
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		r.Complete(true)
		return
	}
	r.Complete(false)
	c := gonet.NewTCPConn(&wq, ep)
	defer c.Close()
	var hdr [2]byte
	for {
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		if _, err := readFull(c, hdr[:]); err != nil {
			return
		}
		msg := make([]byte, binary.BigEndian.Uint16(hdr[:]))
		if _, err := readFull(c, msg); err != nil {
			return
		}
		resp := g.cfg.DNSFilter.Handle(client, msg, true)
		if resp == nil {
			return
		}
		out := make([]byte, 2+len(resp))
		binary.BigEndian.PutUint16(out, uint16(len(resp)))
		copy(out[2:], resp)
		if _, err := c.Write(out); err != nil {
			return
		}
	}
}

func readFull(c *gonet.TCPConn, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		k, err := c.Read(b[n:])
		n += k
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

var _ = netip.Addr{}
