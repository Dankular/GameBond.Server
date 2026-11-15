package l2gw

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

var deviceMAC = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x99}

func newTestGateway(t *testing.T, mutate func(*Config)) (*Gateway, chan []byte) {
	t.Helper()
	out := make(chan []byte, 1024)
	cfg := Config{
		Address:      netip.MustParsePrefix("10.78.0.1/24"),
		DHCPStart:    netip.MustParseAddr("10.78.0.100"),
		DHCPEnd:      netip.MustParseAddr("10.78.0.102"),
		Hosts:        []Host{{MAC: deviceMAC, IP: netip.MustParseAddr("10.78.0.20"), Name: "ps5"}},
		Out:          func(f []byte) { out <- f },
		AllowPrivate: true,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.Close)
	return g, out
}

func TestUnsolicitedRouterAdvertisementCarriesAutonomousPrefixLifetime(t *testing.T) {
	g := &Gateway{cfg: Config{
		IPv6Address: netip.MustParsePrefix("2001:db8:78::1/64"),
		MAC:         net.HardwareAddr{0x02, 0x47, 0x42, 0, 0, 1},
	}}
	frame := g.unsolicitedRouterAdvertisement()
	if len(frame) < 14+40+48 || frame[12] != 0x86 || frame[13] != 0xdd || frame[0] != 0x33 || frame[1] != 0x33 || frame[2] != 0 || frame[3] != 0 || frame[4] != 0 || frame[5] != 1 {
		t.Fatalf("unsolicited RA Ethernet framing is invalid: %x", frame)
	}
	ip := frame[14:]
	if ip[6] != 58 || ip[7] != 255 || netip.AddrFrom16([16]byte(ip[8:24])) != netip.MustParseAddr("fe80::47:42ff:fe00:1") || netip.AddrFrom16([16]byte(ip[24:40])) != netip.MustParseAddr("ff02::1") {
		t.Fatalf("unsolicited RA IPv6 header is invalid: %x", ip[:40])
	}
	ra := ip[40:]
	if ra[0] != 134 || ra[1] != 0 || icmpv6Checksum(ip[8:24], ip[24:40], ra) != 0 {
		t.Fatalf("unsolicited RA ICMPv6 message is invalid: %x", ra)
	}
	pio := ra[16:48]
	if pio[0] != 3 || pio[1] != 4 || pio[2] != 64 || pio[3]&0x40 == 0 || binary.BigEndian.Uint32(pio[4:8]) != 86400 || binary.BigEndian.Uint32(pio[8:12]) != 14400 || netip.AddrFrom16([16]byte(pio[16:32])) != netip.MustParseAddr("2001:db8:78::") {
		t.Fatalf("unsolicited RA Prefix Information is invalid: %x", pio)
	}
}

func TestPeriodicRouterAdvertisementSendsAndStops(t *testing.T) {
	out := make(chan []byte, 1)
	g := &Gateway{cfg: Config{
		IPv6Address: netip.MustParsePrefix("2001:db8:78::1/64"),
		MAC:         net.HardwareAddr{0x02, 0x47, 0x42, 0, 0, 1},
		Out:         func(frame []byte) { out <- append([]byte(nil), frame...) },
	}}
	stop := make(chan struct{})
	g.done.Add(1)
	go g.periodicRouterAdvertisements(stop)
	select {
	case frame := <-out:
		if len(frame) < 14+40+48 || frame[14+40] != 134 {
			t.Fatalf("periodic output was not a Router Advertisement: %x", frame)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("periodic Router Advertisement was not sent")
	}
	close(stop)
	done := make(chan struct{})
	go func() { g.done.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("periodic Router Advertisement did not stop")
	}
}

func TestGatewayCloseWithdrawsRouterAndSLAACLifetimes(t *testing.T) {
	g, out := newTestGateway(t, func(cfg *Config) {
		cfg.IPv6Address = netip.MustParsePrefix("2001:db8:78::1/64")
		cfg.DNS6 = []netip.Addr{netip.MustParseAddr("2001:db8:78::53")}
	})
	g.Inbound(routerSolicitationFrame())
	select {
	case frame := <-out:
		if frame[14+40] != 134 || binary.BigEndian.Uint16(frame[14+40+6:14+40+8]) == 0 {
			t.Fatalf("Router Solicitation did not receive a live RA: %x", frame)
		}
	case <-time.After(time.Second):
		t.Fatal("Router Solicitation did not receive a live RA")
	}
	g.Close()
	select {
	case frame := <-out:
		ip, ra := frame[14:], frame[14+40:]
		if ra[0] != 134 || binary.BigEndian.Uint16(ra[6:8]) != 0 || binary.BigEndian.Uint32(ra[20:24]) != 0 || binary.BigEndian.Uint32(ra[24:28]) != 0 || binary.BigEndian.Uint32(ra[48+4:48+8]) != 0 || icmpv6Checksum(ip[8:24], ip[24:40], ra) != 0 {
			t.Fatalf("gateway shutdown did not withdraw router, PIO, and RDNSS lifetimes: %x", frame)
		}
	case <-time.After(time.Second):
		t.Fatal("gateway shutdown did not send an RA withdrawal")
	}
}

func routerSolicitationFrame() []byte {
	source := netip.MustParseAddr("fe80::99").As16()
	destination := netip.MustParseAddr("ff02::2").As16()
	frame := make([]byte, header.EthernetMinimumSize+40+8)
	header.Ethernet(frame).Encode(&header.EthernetFields{
		SrcAddr: tcpip.LinkAddress(deviceMAC), DstAddr: tcpip.LinkAddress([]byte{0x33, 0x33, 0, 0, 0, 2}), Type: header.IPv6ProtocolNumber,
	})
	ip := frame[header.EthernetMinimumSize:]
	ip[0], ip[6], ip[7] = 0x60, 58, 255
	binary.BigEndian.PutUint16(ip[4:6], 8)
	copy(ip[8:24], source[:])
	copy(ip[24:40], destination[:])
	rs := ip[40:]
	rs[0] = 133
	binary.BigEndian.PutUint16(rs[2:4], icmpv6Checksum(ip[8:24], ip[24:40], rs))
	return frame
}

// dhcpFrame builds a client DHCP packet inside Ethernet, IPv4 and UDP, as a device puts it on the wire.
func dhcpFrame(mac net.HardwareAddr, typ byte, xid uint32, reqIP, serverID netip.Addr) []byte {
	b := make([]byte, dhcpFixedSize+4)
	b[0], b[1], b[2] = 1, 1, 6
	binary.BigEndian.PutUint32(b[4:], xid)
	binary.BigEndian.PutUint16(b[10:], 0x8000)
	copy(b[28:], mac)
	binary.BigEndian.PutUint32(b[dhcpFixedSize:], dhcpMagic)
	b = append(b, 53, 1, typ)
	if reqIP.IsValid() {
		b = append(b, 50, 4)
		b = append(b, reqIP.AsSlice()...)
	}
	if serverID.IsValid() {
		b = append(b, 54, 4)
		b = append(b, serverID.AsSlice()...)
	}
	b = append(b, 255)
	total := header.EthernetMinimumSize + header.IPv4MinimumSize + header.UDPMinimumSize + len(b)
	f := make([]byte, total)
	header.Ethernet(f).Encode(&header.EthernetFields{SrcAddr: tcpip.LinkAddress(mac), DstAddr: header.EthernetBroadcastAddress, Type: header.IPv4ProtocolNumber})
	ip := header.IPv4(f[header.EthernetMinimumSize:])
	ip.Encode(&header.IPv4Fields{TotalLength: uint16(total - header.EthernetMinimumSize), TTL: 64, Protocol: uint8(udp.ProtocolNumber),
		SrcAddr: tcpip.AddrFrom4([4]byte{}), DstAddr: tcpip.AddrFrom4([4]byte{255, 255, 255, 255})})
	ip.SetChecksum(^ip.CalculateChecksum())
	u := header.UDP(ip.Payload())
	u.Encode(&header.UDPFields{SrcPort: 68, DstPort: 67, Length: uint16(header.UDPMinimumSize + len(b))})
	copy(u.Payload(), b)
	return f
}

// awaitDHCP waits for a DHCP reply frame and returns its message type, offered address and options.
func awaitDHCP(t *testing.T, out chan []byte) (byte, netip.Addr, map[byte][]byte) {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case f := <-out:
			if len(f) < 14 || header.Ethernet(f).Type() != header.IPv4ProtocolNumber {
				continue
			}
			ip := header.IPv4(f[14:])
			if ip.TransportProtocol() != udp.ProtocolNumber {
				continue
			}
			u := header.UDP(ip.Payload())
			if u.SourcePort() != 67 {
				continue
			}
			p := u.Payload()
			if len(p) < dhcpFixedSize+4 {
				continue
			}
			opts := map[byte][]byte{}
			for o := p[dhcpFixedSize+4:]; len(o) > 1 && o[0] != 255; o = o[2+int(o[1]):] {
				opts[o[0]] = o[2 : 2+int(o[1])]
			}
			return opts[53][0], netip.AddrFrom4([4]byte(p[16:20])), opts
		case <-deadline:
			t.Fatal("no DHCP reply")
		}
	}
}

func TestDHCPOfferAckAndFixedHost(t *testing.T) {
	g, out := newTestGateway(t, nil)
	other := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x55}

	g.Inbound(dhcpFrame(other, dhcpDiscover, 1, netip.Addr{}, netip.Addr{}))
	typ, ip, opts := awaitDHCP(t, out)
	if typ != dhcpOffer || ip != netip.MustParseAddr("10.78.0.100") {
		t.Fatalf("offer: type %d ip %v", typ, ip)
	}
	if !bytes.Equal(opts[3], []byte{10, 78, 0, 1}) || !bytes.Equal(opts[1], []byte{255, 255, 255, 0}) || binary.BigEndian.Uint16(opts[26]) != 1380 {
		t.Fatalf("options wrong: %v", opts)
	}
	g.Inbound(dhcpFrame(other, dhcpRequest, 1, ip, netip.MustParseAddr("10.78.0.1")))
	if typ, _, _ = awaitDHCP(t, out); typ != dhcpAck {
		t.Fatalf("want ack, got %d", typ)
	}
	if g.Stats().Leases != 1 {
		t.Fatalf("lease not recorded: %+v", g.Stats())
	}

	// A second device cannot take the held address and gets the next one.
	third := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x66}
	g.Inbound(dhcpFrame(third, dhcpDiscover, 2, netip.Addr{}, netip.Addr{}))
	if _, ip, _ = awaitDHCP(t, out); ip != netip.MustParseAddr("10.78.0.101") {
		t.Fatalf("second offer %v", ip)
	}
	// Asking for the first device's address is refused (authoritative NAK).
	g.Inbound(dhcpFrame(third, dhcpRequest, 3, netip.MustParseAddr("10.78.0.100"), netip.Addr{}))
	if typ, _, _ = awaitDHCP(t, out); typ != dhcpNak {
		t.Fatalf("want nak, got %d", typ)
	}
	// An address outside the pool, as held after failing over from the other exit, is refused too.
	g.Inbound(dhcpFrame(third, dhcpRequest, 4, netip.MustParseAddr("10.78.0.177"), netip.Addr{}))
	if typ, _, _ = awaitDHCP(t, out); typ != dhcpNak {
		t.Fatalf("want nak for out-of-pool address, got %d", typ)
	}
	// The fixed host always gets its own address.
	g.Inbound(dhcpFrame(deviceMAC, dhcpDiscover, 5, netip.Addr{}, netip.Addr{}))
	if _, ip, _ = awaitDHCP(t, out); ip != netip.MustParseAddr("10.78.0.20") {
		t.Fatalf("fixed host got %v", ip)
	}
	// A request naming another server is ignored.
	g.Inbound(dhcpFrame(third, dhcpRequest, 6, netip.MustParseAddr("10.78.0.101"), netip.MustParseAddr("10.78.0.254")))
	select {
	case <-out:
		t.Fatal("answered a request meant for another server")
	case <-time.After(300 * time.Millisecond):
	}
}

func TestDHCPBindingRetainsAuthenticatedIngressSession(t *testing.T) {
	g, out := newTestGateway(t, nil)
	client := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x73}
	identity := "session-00010203"
	g.InboundFrom(dhcpFrame(client, dhcpDiscover, 91, netip.Addr{}, netip.Addr{}), identity)
	_, offered, _ := awaitDHCP(t, out)
	g.InboundFrom(dhcpFrame(client, dhcpRequest, 91, offered, netip.MustParseAddr("10.78.0.1")), identity)
	if typ, _, _ := awaitDHCP(t, out); typ != dhcpAck {
		t.Fatalf("expected ACK, got %d", typ)
	}
	bindings := g.DHCPBindings()
	if len(bindings) != 1 || bindings[0].IP != offered || bindings[0].SessionPort != identity || bindings[0].MAC != client.String() {
		t.Fatalf("DHCP binding did not retain authenticated ingress identity: %+v", bindings)
	}
}

func TestDHCPv4RelayAddsCircuitIdentityAndRestoresClientReply(t *testing.T) {
	client := net.HardwareAddr{2, 9, 8, 7, 6, 5}
	requestFrame := dhcpFrame(client, dhcpDiscover, 0x10203040, netip.Addr{}, netip.Addr{})
	request := requestFrame[14+20+8:]
	giaddr := netip.MustParseAddr("10.78.0.1")
	forward, ok := makeDHCPv4RelayForward(request, giaddr, "session-a")
	if !ok || forward[3] != 1 || !bytes.Equal(forward[24:28], giaddr.AsSlice()) {
		t.Fatalf("relay-forward did not set hop count/giaddr: ok=%v packet=%x", ok, forward)
	}
	if !dhcpRelayOptionPresent(forward, "session-a") {
		t.Fatalf("relay-forward did not include authenticated circuit ID: %x", forward)
	}

	reply := append([]byte(nil), forward...)
	reply[0] = 2
	for off := dhcpFixedSize + 4; off < len(reply); {
		if reply[off] == 255 {
			break
		}
		if reply[off] == 53 {
			reply[off+2] = dhcpOffer
			break
		}
		off += 1
		if reply[off-1] != 0 {
			off += 1 + int(reply[off])
		}
	}
	out, ok := parseDHCPv4RelayReply(reply, giaddr, "session-a")
	if !ok || out[3] != 0 || !bytes.Equal(out[24:28], []byte{0, 0, 0, 0}) || dhcpRelayOptionPresent(out, "session-a") {
		t.Fatalf("relay-reply was not restored for the client: ok=%v packet=%x", ok, out)
	}
	if _, ok := parseDHCPv4RelayReply(reply, giaddr, "session-b"); ok {
		t.Fatal("relay-reply circuit ID from another session was accepted")
	}
	if _, ok := makeDHCPv4RelayForward(request, giaddr, ""); ok {
		t.Fatal("empty circuit ID accepted")
	}
	clientWithOption82 := append([]byte(nil), request...)
	clientWithOption82 = append(clientWithOption82[:len(clientWithOption82)-1], 82, 1, 1, 0, 255)
	if _, ok := makeDHCPv4RelayForward(clientWithOption82, giaddr, "session-a"); ok {
		t.Fatal("client-supplied relay-agent option accepted")
	}
}

func TestDHCPv4RelayExchangesFramesWithOnLinkServer(t *testing.T) {
	clientOut := make(chan []byte, 16)
	toUpstream := make(chan []byte, 64)
	var upstreamLink *channel.Endpoint
	g, err := New(Config{
		Address:    netip.MustParsePrefix("10.78.0.1/24"),
		DHCPRelay4: netip.MustParseAddrPort("10.78.0.2:67"),
		Out: func(frame []byte) {
			copyFrame := append([]byte(nil), frame...)
			if isDHCPv4ClientReplyFrame(copyFrame) {
				clientOut <- copyFrame
				return
			}
			toUpstream <- copyFrame
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.Close)

	upstreamLink = channel.New(512, 1380, tcpip.LinkAddress([]byte{2, 0, 0, 0, 0, 2}))
	serverStack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
	})
	if err := serverStack.CreateNIC(1, ethernet.New(upstreamLink)); err != nil {
		t.Fatal(err)
	}
	if err := serverStack.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{
		Address: tcpip.AddrFrom4([4]byte{10, 78, 0, 2}), PrefixLen: 24,
	}}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	serverStack.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	var wq waiter.Queue
	ep, terr := serverStack.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if terr != nil {
		t.Fatal(terr)
	}
	ep.SocketOptions().SetReuseAddress(true)
	if terr := ep.Bind(tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{10, 78, 0, 2}), Port: 67}); terr != nil {
		t.Fatal(terr)
	}
	serverConn := gonet.NewUDPConn(&wq, ep)
	serverCtx, stopServer := context.WithCancel(context.Background())
	t.Cleanup(func() { stopServer(); serverConn.Close(); serverStack.Close(); upstreamLink.Close() })
	go func() {
		for {
			pkt := upstreamLink.ReadContext(serverCtx)
			if pkt == nil {
				return
			}
			view := pkt.ToView()
			g.Inbound(append([]byte(nil), view.AsSlice()...))
			view.Release()
			pkt.DecRef()
		}
	}()
	go func() {
		for {
			select {
			case frame := <-toUpstream:
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(frame)})
				upstreamLink.InjectInbound(0, pkt)
				pkt.DecRef()
			case <-serverCtx.Done():
				return
			}
		}
	}()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, _, err := serverConn.ReadFrom(buf)
			if err != nil {
				return
			}
			relayRequest := append([]byte(nil), buf[:n]...)
			if !dhcpRelayOptionPresent(relayRequest, "session-relay") || !bytes.Equal(relayRequest[24:28], []byte{10, 78, 0, 1}) {
				continue
			}
			reply := append([]byte(nil), relayRequest...)
			reply[0] = 2
			copy(reply[16:20], []byte{10, 78, 0, 100})
			for off := dhcpFixedSize + 4; off < len(reply); {
				if reply[off] == 255 {
					break
				}
				if reply[off] == 53 {
					reply[off+2] = dhcpOffer
					break
				}
				if reply[off] == 0 {
					off++
					continue
				}
				off += 2 + int(reply[off+1])
			}
			_, _ = serverConn.WriteTo(reply, &net.UDPAddr{IP: net.IPv4(10, 78, 0, 1), Port: 67})
			return
		}
	}()

	clientMAC := net.HardwareAddr{2, 9, 8, 7, 6, 5}
	g.InboundFrom(dhcpFrame(clientMAC, dhcpDiscover, 0x10203040, netip.Addr{}, netip.Addr{}), "session-relay")
	typ, offered, _ := awaitDHCP(t, clientOut)
	if typ != dhcpOffer || offered != netip.MustParseAddr("10.78.0.100") {
		t.Fatalf("relay response = type %d, address %s", typ, offered)
	}
}

func TestDHCPv4RelayConfigRejectsAmbiguousPoolAndUnroutableServer(t *testing.T) {
	base := Config{Address: netip.MustParsePrefix("10.78.0.1/24"), DHCPRelay4: netip.MustParseAddrPort("192.0.2.53:67"), Out: func([]byte) {}}
	if _, err := New(base); err == nil {
		t.Fatal("off-subnet DHCP relay without a next hop was accepted")
	}
	base.DHCPRelayGateway4 = netip.MustParseAddr("10.78.0.254")
	base.DHCPStart, base.DHCPEnd = netip.MustParseAddr("10.78.0.100"), netip.MustParseAddr("10.78.0.110")
	if _, err := New(base); err == nil {
		t.Fatal("DHCP relay and local pool were both accepted")
	}
	base.DHCPRelay4 = netip.AddrPort{}
	base.DHCPStart, base.DHCPEnd = netip.Addr{}, netip.Addr{}
	if _, err := New(base); err == nil {
		t.Fatal("relay next hop without a DHCP relay target was accepted")
	}
	for _, nextHop := range []string{"10.78.0.0", "10.78.0.255", "10.79.0.254", "10.78.0.1"} {
		bad := Config{Address: netip.MustParsePrefix("10.78.0.1/24"), DHCPRelay4: netip.MustParseAddrPort("192.0.2.53:67"), DHCPRelayGateway4: netip.MustParseAddr(nextHop), Out: func([]byte) {}}
		if _, err := New(bad); err == nil {
			t.Errorf("invalid relay next hop %s was accepted", nextHop)
		}
	}
}

func isDHCPv4ClientReplyFrame(frame []byte) bool {
	if len(frame) < 14+20+8 || binary.BigEndian.Uint16(frame[12:14]) != 0x0800 {
		return false
	}
	ip := frame[14:]
	ihl := int(ip[0]&0x0f) * 4
	if ip[0]>>4 != 4 || ip[9] != byte(udp.ProtocolNumber) || ihl < 20 || len(ip) < ihl+8 {
		return false
	}
	return binary.BigEndian.Uint16(ip[ihl:ihl+2]) == 67 && binary.BigEndian.Uint16(ip[ihl+2:ihl+4]) == 68
}

func dhcpRelayOptionPresent(payload []byte, circuitID string) bool {
	end, ok := dhcpOptionEnd(payload)
	if !ok {
		return false
	}
	for off := dhcpFixedSize + 4; off < end; {
		if payload[off] == 0 {
			off++
			continue
		}
		if payload[off] == 82 && dhcpRelayCircuitIDMatches(payload[off+2:off+2+int(payload[off+1])], circuitID) {
			return true
		}
		off += 2 + int(payload[off+1])
	}
	return false
}

// device is a second gVisor stack on the far side of the bond: what a PS5 would be.
type device struct{ s *stack.Stack }

func newDevice(t *testing.T, g *Gateway, out chan []byte, ip string) *device {
	t.Helper()
	link := channel.New(512, 1380, tcpip.LinkAddress(deviceMAC))
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	if err := s.CreateNIC(1, ethernet.New(link)); err != nil {
		t.Fatal(err)
	}
	pa := tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{
		Address: tcpip.AddrFromSlice(net.ParseIP(ip).To4()), PrefixLen: 24}}
	if err := s.AddProtocolAddress(1, pa, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, Gateway: tcpip.AddrFrom4([4]byte{10, 78, 0, 1}), NIC: 1}})
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	t.Cleanup(func() { cancel(); s.Close(); link.Close(); wg.Wait() })
	wg.Add(2)
	go func() { // device -> gateway
		defer wg.Done()
		for {
			pkt := link.ReadContext(ctx)
			if pkt == nil {
				return
			}
			v := pkt.ToView()
			g.Inbound(append([]byte(nil), v.AsSlice()...))
			v.Release()
			pkt.DecRef()
		}
	}()
	go func() { // gateway -> device
		defer wg.Done()
		for {
			select {
			case f := <-out:
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(f)})
				link.InjectInbound(0, pkt)
				pkt.DecRef()
			case <-ctx.Done():
				return
			}
		}
	}()
	return &device{s: s}
}

// fakeInternet answers any destination on port 7 from local echo servers and refuses everything else.
func fakeInternet(t *testing.T) func(string, string, time.Duration) (net.Conn, error) {
	t.Helper()
	tl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tl.Close() })
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	ul, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ul.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, a, err := ul.ReadFrom(buf)
			if err != nil {
				return
			}
			ul.WriteTo(buf[:n], a)
		}
	}()
	return func(network, addr string, timeout time.Duration) (net.Conn, error) {
		_, port, _ := net.SplitHostPort(addr)
		switch {
		case network == "tcp" && port == "7":
			return net.DialTimeout("tcp", tl.Addr().String(), timeout)
		case network == "udp" && port == "7":
			return net.Dial("udp", ul.LocalAddr().String())
		}
		return nil, io.ErrClosedPipe
	}
}

var internet = tcpip.FullAddress{Addr: tcpip.AddrFrom4([4]byte{203, 0, 113, 9}), Port: 7}

func TestDeviceTCPAndUDPThroughGateway(t *testing.T) {
	listen, _ := fakeUDPInternet(t)
	g, out := newTestGateway(t, func(c *Config) { c.Dial = fakeInternet(t); c.Listen = listen })
	dev := newDevice(t, g, out, "10.78.0.50")

	// TCP: 100 KB echoes back intact through the gateway.
	conn, err := gonet.DialContextTCP(context.Background(), dev.s, internet, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal("tcp dial through gateway:", err)
	}
	payload := bytes.Repeat([]byte("0123456789abcdef"), 6400)
	go conn.Write(payload)
	got := make([]byte, len(payload))
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatal("tcp echo mismatch", err)
	}
	if g.ActiveFlows() != 1 {
		t.Fatalf("flow count while open: %d", g.ActiveFlows())
	}
	conn.Close()
	for i := 0; i < 50 && g.ActiveFlows() != 0; i++ {
		time.Sleep(100 * time.Millisecond)
	}
	if g.ActiveFlows() != 0 {
		t.Fatalf("flow not released: %+v", g.Stats())
	}

	uc, err := gonet.DialUDP(dev.s, nil, &internet, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	uc.Write([]byte("ping"))
	buf := make([]byte, 64)
	uc.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := uc.Read(buf)
	if err != nil || string(buf[:n]) != "ping" {
		t.Fatalf("udp echo: %q %v", buf[:n], err)
	}
}

func TestPrivateDestinationsAreBlockedAndDrainRefusesNewFlows(t *testing.T) {
	g, out := newTestGateway(t, func(c *Config) { c.Dial = fakeInternet(t); c.AllowPrivate = false })
	dev := newDevice(t, g, out, "10.78.0.50")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	private := tcpip.FullAddress{Addr: tcpip.AddrFrom4([4]byte{192, 168, 1, 1}), Port: 7}
	if _, err := gonet.DialContextTCP(ctx, dev.s, private, ipv4.ProtocolNumber); err == nil {
		t.Fatal("private destination reachable")
	}
	if g.Stats().Blocked == 0 {
		t.Fatal("block not counted")
	}
	// An allowed flow, then drain: the existing flow keeps working, a new one is refused.
	open, err := gonet.DialContextTCP(context.Background(), dev.s, internet, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer open.Close()
	g.SetDraining(true)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel2()
	if c, err := gonet.DialContextTCP(ctx2, dev.s, internet, ipv4.ProtocolNumber); err == nil {
		c.Close()
		t.Fatal("new flow accepted while draining")
	}
	open.Write([]byte("still alive"))
	b := make([]byte, 32)
	open.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := open.Read(b); err != nil || string(b[:n]) != "still alive" {
		t.Fatal("existing flow broken by drain", err)
	}
}

// A device probes its new address with an ARP request; only the gateway's own address may answer,
// or the device sees a duplicate and declines the lease.
func TestARPAnswersOnlyForTheGateway(t *testing.T) {
	g, out := newTestGateway(t, nil)
	arpReq := func(target [4]byte) []byte {
		f := append([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, deviceMAC...)
		f = append(f, 0x08, 0x06, 0, 1, 8, 0, 6, 4, 0, 1)
		f = append(f, deviceMAC...)
		f = append(f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
		return append(f, target[:]...)
	}
	g.Inbound(arpReq([4]byte{10, 78, 0, 100}))
	select {
	case f := <-out:
		t.Fatalf("the gateway answered an ARP probe for another address: % x", f[:42])
	case <-time.After(300 * time.Millisecond):
	}
	g.Inbound(arpReq([4]byte{10, 78, 0, 1}))
	select {
	case f := <-out:
		if f[21] != 2 {
			t.Fatalf("not an ARP reply padded to the Ethernet minimum: len %d", len(f))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no ARP reply for the gateway address")
	}
}

// A pushed policy applies to the next flow without a restart, per device, and never cuts a flow
// that is already open.
func TestPolicyIsLiveAndPerDevice(t *testing.T) {
	g, out := newTestGateway(t, func(c *Config) { c.Dial = fakeInternet(t) })
	dev := newDevice(t, g, out, "10.78.0.20") // deviceMAC holds the fixed host 10.78.0.20
	dial := func() (net.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return gonet.DialContextTCP(ctx, dev.s, internet, ipv4.ProtocolNumber)
	}
	hosts := []Host{{MAC: deviceMAC, IP: netip.MustParseAddr("10.78.0.20"), Name: "ps5"}}

	open, err := dial()
	if err != nil {
		t.Fatal("no policy should allow:", err)
	}
	defer open.Close()

	if err := g.SetPolicy(Policy{Version: 2, Hosts: hosts, Devices: []DevicePolicy{{MAC: deviceMAC, Rule: DeviceRule{Deny: true}}}}); err != nil {
		t.Fatal(err)
	}
	if g.PolicyVersion() != 2 {
		t.Fatal("version not reported")
	}
	if c, err := dial(); err == nil {
		c.Close()
		t.Fatal("denied device opened a flow")
	}
	open.Write([]byte("x"))
	b := make([]byte, 8)
	open.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := open.Read(b); err != nil || n != 1 {
		t.Fatal("the open flow was cut by the policy change", err)
	}

	if err := g.SetPolicy(Policy{Version: 3, Hosts: hosts, Devices: []DevicePolicy{{MAC: deviceMAC, Rule: DeviceRule{MaxFlows: 1}}}}); err != nil {
		t.Fatal(err)
	}
	if c, err := dial(); err == nil {
		c.Close()
		t.Fatal("max_flows not enforced")
	}
	var seen bool
	for _, d := range g.DeviceStats() {
		if d.IP == "10.78.0.20" && d.Denied >= 2 && d.Flows == 1 {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("device stats wrong: %+v", g.DeviceStats())
	}
	if err := g.SetPolicy(Policy{Devices: []DevicePolicy{{MAC: net.HardwareAddr{1, 2, 3, 4, 5, 6}}}}); err == nil {
		t.Fatal("a multicast MAC rule was accepted")
	}
}

// natPC stands in for the internet: it maps the documentation addresses a device talks to onto two
// local sockets, an echo server and a second socket that answers from a different address and port.
type natPC struct {
	net.PacketConn
	toReal   map[string]net.Addr // fake destination -> local socket
	fromReal map[string]net.Addr // local socket -> fake source
}

func (n *natPC) WriteTo(b []byte, a net.Addr) (int, error) {
	if r, ok := n.toReal[a.String()]; ok {
		return n.PacketConn.WriteTo(b, r)
	}
	return len(b), nil
}

func (n *natPC) ReadFrom(b []byte) (int, net.Addr, error) {
	k, a, err := n.PacketConn.ReadFrom(b)
	if err != nil {
		return k, a, err
	}
	if f, ok := n.fromReal[a.String()]; ok {
		a = f
	}
	return k, a, err
}

// fakeUDPInternet returns a Listen hook and the second socket, "other", which a test uses to send to a
// mapping's public port from an address the device never contacted.
func fakeUDPInternet(t *testing.T) (func() (net.PacketConn, error), *net.UDPConn) {
	t.Helper()
	echo, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	other, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close(); other.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, a, err := echo.ReadFrom(buf)
			if err != nil {
				return
			}
			echo.WriteTo(buf[:n], a)
		}
	}()
	fakeEcho, _ := net.ResolveUDPAddr("udp4", "203.0.113.9:7")
	fakeOther, _ := net.ResolveUDPAddr("udp4", "198.51.100.7:4000")
	return func() (net.PacketConn, error) {
		pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		return &natPC{PacketConn: pc,
			toReal:   map[string]net.Addr{fakeEcho.String(): echo.LocalAddr()},
			fromReal: map[string]net.Addr{echo.LocalAddr().String(): fakeEcho, other.LocalAddr().String(): fakeOther}}, nil
	}, other
}

func TestUDPMappingIsFullCone(t *testing.T) {
	listen, other := fakeUDPInternet(t)
	g, out := newTestGateway(t, func(c *Config) { c.Listen = listen })
	dev := newDevice(t, g, out, "10.78.0.50")

	// The device opens a port by sending to one server (the echo) and gets its answer.
	local := tcpip.FullAddress{Addr: tcpip.AddrFrom4([4]byte{10, 78, 0, 50}), Port: 40000}
	uc, err := gonet.DialUDP(dev.s, &local, nil, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	to := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 7}
	if _, err := uc.WriteTo([]byte("hello"), to); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	uc.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, from, err := uc.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "hello" || from.(*net.UDPAddr) == nil {
		t.Fatalf("echo through the mapping: %q %v", buf[:n], err)
	}

	// A server the device never contacted, at another address and port, sends to the public port.
	maps := g.UDPMappings()
	if len(maps) != 1 || maps[0].Device != "10.78.0.50:40000" {
		t.Fatalf("mappings: %+v", maps)
	}
	pub, err := net.ResolveUDPAddr("udp4", maps[0].Public)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.WriteToUDP([]byte("cone"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: pub.Port}); err != nil {
		t.Fatal(err)
	}
	uc.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, from, err = uc.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "cone" {
		t.Fatalf("full-cone delivery failed: %q %v (%+v)", buf[:n], err, g.Stats())
	}
	if ua := from.(*net.UDPAddr); ua.IP.String() != "198.51.100.7" || ua.Port != 4000 {
		t.Fatalf("the device must see the real source, got %v", from)
	}

	// With the restriction on, the same datagram is dropped.
	listen2, other2 := fakeUDPInternet(t)
	g2, out2 := newTestGateway(t, func(c *Config) { c.Listen = listen2; c.RestrictedUDP = true })
	dev2 := newDevice(t, g2, out2, "10.78.0.51")
	uc2, err := gonet.DialUDP(dev2.s, &tcpip.FullAddress{Addr: tcpip.AddrFrom4([4]byte{10, 78, 0, 51}), Port: 40001}, nil, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer uc2.Close()
	uc2.WriteTo([]byte("hello"), to)
	uc2.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := uc2.ReadFrom(buf); err != nil {
		t.Fatal(err)
	}
	pub2, _ := net.ResolveUDPAddr("udp4", g2.UDPMappings()[0].Public)
	other2.WriteToUDP([]byte("cone"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: pub2.Port})
	uc2.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
	if n, _, err := uc2.ReadFrom(buf); err == nil {
		t.Fatalf("restricted mapping delivered %q", buf[:n])
	}
}

func TestDNSAndTapHooksCoverBridgedDevices(t *testing.T) {
	var up, down atomic.Int64
	g, out := newTestGateway(t, func(c *Config) {
		c.Tap = func(fromDevice bool, p []byte) {
			if fromDevice {
				up.Add(1)
			} else {
				down.Add(1)
			}
		}
		c.DNSFilter = &DNSHook{Handle: func(client netip.Addr, req []byte, tcp bool) []byte {
			return append([]byte("filtered:"), req...)
		}}
	})
	dev := newDevice(t, g, out, "10.78.0.60")

	// A device that talks to a resolver of its own choosing still gets the filtering resolver's answer.
	dns := tcpip.FullAddress{Addr: tcpip.AddrFrom4([4]byte{203, 0, 113, 53}), Port: 53}
	uc, err := gonet.DialUDP(dev.s, &tcpip.FullAddress{Addr: tcpip.AddrFrom4([4]byte{10, 78, 0, 60}), Port: 41000}, &dns, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	uc.Write([]byte("q"))
	buf := make([]byte, 64)
	uc.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := uc.Read(buf)
	if err != nil || string(buf[:n]) != "filtered:q" {
		t.Fatalf("udp dns: %q %v", buf[:n], err)
	}

	// The stream form: length-prefixed.
	tc, err := gonet.DialTCP(dev.s, dns, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	tc.Write([]byte{0, 1, 'q'})
	tc.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp := make([]byte, 2+len("filtered:q"))
	if _, err := io.ReadFull(tc, resp); err != nil || string(resp[2:]) != "filtered:q" {
		t.Fatalf("tcp dns: %q %v", resp, err)
	}
	if up.Load() == 0 || down.Load() == 0 {
		t.Fatalf("tap saw up=%d down=%d", up.Load(), down.Load())
	}
}

// The firewall is the netstack's filter table: port and network rules refuse a new connection, and the device
// is told at once (ICMP) instead of being left to time out.
func TestNetstackFirewallRulesRefuseFast(t *testing.T) {
	g, out := newTestGateway(t, func(c *Config) { c.Dial = fakeInternet(t) })
	dev := newDevice(t, g, out, "10.78.0.20")
	hosts := []Host{{MAC: deviceMAC, IP: netip.MustParseAddr("10.78.0.20"), Name: "ps5"}}
	try := func() (time.Duration, error) {
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		c, err := gonet.DialContextTCP(ctx, dev.s, internet, ipv4.ProtocolNumber)
		if err == nil {
			c.Close()
		}
		return time.Since(start), err
	}
	cases := []struct {
		name string
		rule DeviceRule
		deny bool
	}{
		{"no rule", DeviceRule{}, false},
		{"other port blocked", DeviceRule{BlockPorts: []uint16{8}}, false},
		{"port blocked", DeviceRule{BlockPorts: []uint16{7}}, true},
		{"network blocked", DeviceRule{BlockNets: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}}, true},
		{"other network blocked", DeviceRule{BlockNets: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}}, false},
	}
	for i, tc := range cases {
		if err := g.SetPolicy(Policy{Version: int64(i + 1), Hosts: hosts, Devices: []DevicePolicy{{MAC: deviceMAC, Rule: tc.rule}}}); err != nil {
			t.Fatal(err)
		}
		took, err := try()
		if tc.deny && err == nil {
			t.Fatalf("%s: connection was allowed", tc.name)
		}
		if !tc.deny && err != nil {
			t.Fatalf("%s: connection refused: %v", tc.name, err)
		}
		if tc.deny && took > 1500*time.Millisecond {
			t.Fatalf("%s: refusal took %v, the device should be told at once", tc.name, took)
		}
	}
	if g.Stats().Blocked == 0 {
		t.Fatal("refusals were not counted")
	}
}

// The firewall tables turn on connection tracking for every packet; this measures what that costs a bulk
// transfer against the stack's default accept-all tables, so a regression in single-flow speed shows up here.
func TestFirewallThroughputOverhead(t *testing.T) {
	run := func(withFirewall bool) float64 {
		g, out := newTestGateway(t, func(c *Config) {
			c.Dial = fakeInternet(t)
			c.DNSFilter = &DNSHook{Handle: func(netip.Addr, []byte, bool) []byte { return nil }}
		})
		dev := newDevice(t, g, out, "10.78.0.20")
		if !withFirewall {
			dt := stack.DefaultTables(g.stack.Clock(), rand.New(rand.NewSource(1)))
			g.stack.IPTables().ForceReplaceTable(stack.FilterID, dt.GetTable(stack.FilterID, false), false)
			g.stack.IPTables().ForceReplaceTable(stack.NATID, dt.GetTable(stack.NATID, false), false)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		c, err := gonet.DialContextTCP(ctx, dev.s, internet, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		const total = 24 << 20
		start := time.Now()
		go func() {
			buf := make([]byte, 64<<10)
			for sent := 0; sent < total; sent += len(buf) {
				if _, err := c.Write(buf); err != nil {
					return
				}
			}
		}()
		n, _ := io.CopyN(io.Discard, c, total)
		return float64(n) / (1 << 20) / time.Since(start).Seconds()
	}
	base, fw := run(false), run(true)
	base2, fw2 := run(false), run(true)
	base, fw = (base+base2)/2, (fw+fw2)/2
	t.Logf("accept-all tables %.0f MB/s, firewall tables %.0f MB/s (%.0f%%)", base, fw, 100*fw/base)
	if fw < base*0.5 {
		t.Fatalf("firewall tables cost more than half the throughput: %.0f vs %.0f MB/s", fw, base)
	}
}
