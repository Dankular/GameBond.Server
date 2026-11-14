package l2gw

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
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
	g, out := newTestGateway(t, func(c *Config) { c.Dial = fakeInternet(t) })
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
		if len(f) < 60 || f[21] != 2 {
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
