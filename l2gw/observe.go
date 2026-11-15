package l2gw

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
)

// tap hands an IP frame's packet to the observer, the same view the tunnel path gives the IDS and the
// traffic classifier.
func (g *Gateway) tap(fromDevice bool, frame []byte) {
	if g.cfg.Tap == nil || len(frame) < header.EthernetMinimumSize {
		return
	}
	switch header.Ethernet(frame).Type() {
	case header.IPv4ProtocolNumber:
		if len(frame) >= header.EthernetMinimumSize+header.IPv4MinimumSize {
			g.cfg.Tap(fromDevice, frame[header.EthernetMinimumSize:])
		}
	case header.IPv6ProtocolNumber:
		if len(frame) >= header.EthernetMinimumSize+header.IPv6MinimumSize {
			g.cfg.Tap(fromDevice, frame[header.EthernetMinimumSize:])
		}
	}
}

func (g *Gateway) dnsOn() bool {
	h := g.cfg.DNSFilter
	return h != nil && h.Handle != nil && (h.On == nil || h.On())
}

// startDNSFilter listens on the gateway's own address, port 53, for the DNS the NAT table redirects here.
// Queries are answered by the filtering resolver; when it is off nothing is redirected, and a device that asks
// the gateway directly gets no answer rather than an unfiltered one.
func (g *Gateway) startDNSFilter() error {
	if g.cfg.DNSFilter == nil || g.cfg.DNSFilter.Handle == nil {
		return nil
	}
	servers := []struct {
		address tcpip.Address
		proto   tcpip.NetworkProtocolNumber
	}{{tcpip.AddrFrom4(g.cfg.Address.Addr().As4()), ipv4.ProtocolNumber}}
	if g.cfg.IPv6Address.IsValid() {
		servers = append(servers, struct {
			address tcpip.Address
			proto   tcpip.NetworkProtocolNumber
		}{tcpip.AddrFrom16(g.cfg.IPv6Address.Addr().As16()), ipv6.ProtocolNumber})
	}
	for _, server := range servers {
		la := tcpip.FullAddress{NIC: nicID, Addr: server.address, Port: 53}
		pc, err := gonet.DialUDP(g.stack, &la, nil, server.proto)
		if err != nil {
			return err
		}
		ln, err := gonet.ListenTCP(g.stack, la, server.proto)
		if err != nil {
			pc.Close()
			return err
		}
		g.dnsClosers = append(g.dnsClosers, pc, ln)
		go g.dnsUDPLoop(pc)
		go g.dnsAccept(ln)
	}
	return nil
}

func clientOf(a net.Addr) (netip.Addr, bool) {
	switch v := a.(type) {
	case *net.UDPAddr:
		ap := v.AddrPort()
		return ap.Addr().Unmap(), ap.Addr().IsValid()
	case *net.TCPAddr:
		ap := v.AddrPort()
		return ap.Addr().Unmap(), ap.Addr().IsValid()
	}
	return netip.Addr{}, false
}

func (g *Gateway) dnsUDPLoop(pc *gonet.UDPConn) {
	buf := make([]byte, 4096)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		client, ok := clientOf(from)
		if !ok || !g.dnsOn() {
			continue
		}
		g.udpTotal.Add(1)
		if resp := g.cfg.DNSFilter.Handle(client, append([]byte(nil), buf[:n]...), false); resp != nil {
			pc.WriteTo(resp, from)
		}
	}
}

func (g *Gateway) dnsAccept(ln *gonet.TCPListener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go g.dnsTCP(c)
	}
}

// dnsTCP is the stream form: two-byte length, then the message.
func (g *Gateway) dnsTCP(c net.Conn) {
	defer c.Close()
	client, ok := clientOf(c.RemoteAddr())
	if !ok || !g.dnsOn() {
		return
	}
	g.tcpTotal.Add(1)
	var hdr [2]byte
	for {
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			return
		}
		msg := make([]byte, binary.BigEndian.Uint16(hdr[:]))
		if _, err := io.ReadFull(c, msg); err != nil {
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
