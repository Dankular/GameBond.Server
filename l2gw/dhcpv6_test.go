package l2gw

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
)

func TestDHCPv6SolicitAdvertiseRequestAndSessionBinding(t *testing.T) {
	server, err := newDHCPv6Server(netip.MustParsePrefix("fd78:78::1/64"), net.HardwareAddr{2, 1, 2, 3, 4, 5}, []netip.Addr{netip.MustParseAddr("2606:4700:4700::1111")}, 12*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	client := []byte{0, 3, 0, 1, 2, 9, 8, 7, 6, 5}
	var mac [6]byte
	copy(mac[:], []byte{2, 9, 8, 7, 6, 5})
	now := time.Now()
	solicit := makeDHCPv6Message(dhcpv6Solicit, 0x010203, client, nil, 0x11223344, nil, false)
	advertise := server.handle(solicit, mac, "session-abc", now)
	req, ok := parseDHCPv6(advertise)
	if !ok || req.typ != dhcpv6Advertise || !req.requestedIP.IsValid() || !server.prefix.Contains(req.requestedIP) || req.requestedIP == server.gateway {
		t.Fatalf("bad Advertise response: parsed=%+v ok=%v payload=%x", req, ok, advertise)
	}
	leaseIP := req.requestedIP
	request := makeDHCPv6Message(dhcpv6Request, 0x010204, client, server.serverID, 0x11223344, &leaseIP, false)
	reply := server.handle(request, mac, "session-abc", now.Add(time.Second))
	parsed, ok := parseDHCPv6(reply)
	if !ok || parsed.typ != dhcpv6Reply || parsed.requestedIP != leaseIP {
		t.Fatalf("bad Reply: parsed=%+v ok=%v payload=%x", parsed, ok, reply)
	}
	bindings := server.bindings()
	if len(bindings) != 1 || bindings[0].IP != leaseIP || bindings[0].MAC != net.HardwareAddr(mac[:]).String() || bindings[0].SessionPort != "session-abc" {
		t.Fatalf("DHCPv6 lease lost authenticated ingress identity: %+v", bindings)
	}
}

func TestDHCPv6EthernetInterceptPreservesVLANAndIngressIdentity(t *testing.T) {
	server, err := newDHCPv6Server(netip.MustParsePrefix("fd78:78::1/64"), net.HardwareAddr{2, 1, 2, 3, 4, 5}, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	client := []byte{0, 3, 0, 1, 2, 9, 8, 7, 6, 5}
	request := makeDHCPv6Message(dhcpv6Solicit, 0x050607, client, nil, 1, nil, false)
	frame := makeDHCPv6EthernetFrame(request, true)
	serverMAC := net.HardwareAddr{2, 1, 2, 3, 4, 5}
	reply, intercepted := server.handleFrame(frame, serverMAC, netip.MustParseAddr("fe80::1"), "session-v6", time.Now())
	if !intercepted || len(reply) == 0 {
		t.Fatalf("valid DHCPv6 frame not answered: intercepted=%v reply=%x", intercepted, reply)
	}
	if binary.BigEndian.Uint16(reply[12:14]) != 0x8100 || binary.BigEndian.Uint16(reply[16:18]) != 0x86dd {
		t.Fatalf("VLAN encapsulation was not preserved: %x", reply[:18])
	}
	udp := reply[18+40:]
	if binary.BigEndian.Uint16(udp[:2]) != 547 || binary.BigEndian.Uint16(udp[2:4]) != 546 || dhcpv6UDPChecksum(reply[18+8:18+24], reply[18+24:18+40], udp) != 0 {
		t.Fatalf("invalid DHCPv6 response UDP tuple/checksum: %x", udp)
	}
	parsed, ok := parseDHCPv6(udp[8:])
	if !ok || parsed.typ != dhcpv6Advertise {
		t.Fatalf("invalid DHCPv6 Advertise payload: %+v ok=%v", parsed, ok)
	}
	if bindings := server.bindings(); len(bindings) != 0 {
		t.Fatalf("Offer must not appear as an active lease: %+v", bindings)
	}
	leaseIP := parsed.requestedIP
	ack := server.handle(makeDHCPv6Message(dhcpv6Request, 0x050608, client, server.serverID, 1, &leaseIP, false), [6]byte{2, 9, 8, 7, 6, 5}, "session-v6", time.Now())
	ackReq, ok := parseDHCPv6(ack)
	if !ok || ackReq.typ != dhcpv6Reply || len(server.bindings()) != 1 || server.bindings()[0].SessionPort != "session-v6" {
		t.Fatalf("DHCPv6 ACK did not retain authenticated ingress identity: %+v bindings=%+v", ackReq, server.bindings())
	}

	bad := append([]byte(nil), frame...)
	bad[len(bad)-1] ^= 1
	if _, intercepted := server.handleFrame(bad, serverMAC, netip.MustParseAddr("fe80::1"), "session-v6", time.Now()); intercepted {
		t.Fatal("invalid DHCPv6 UDP checksum was intercepted")
	}
}

func TestDHCPv6PDInstallsAndExpiresDelegatedRoute(t *testing.T) {
	out := make(chan []byte, 8)
	g, err := New(Config{
		Address:      netip.MustParsePrefix("10.78.0.1/24"),
		DHCPStart:    netip.MustParseAddr("10.78.0.100"),
		DHCPEnd:      netip.MustParseAddr("10.78.0.110"),
		IPv6Address:  netip.MustParsePrefix("fd78:78::1/64"),
		DHCPv6PDPool: netip.MustParsePrefix("2001:db8:100::/48"),
		DHCPv6PDBits: 56,
		Out:          func(frame []byte) { out <- append([]byte(nil), frame...) },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()

	clientID := []byte{0, 3, 0, 1, 2, 9, 8, 7, 6, 5}
	clientMAC := [6]byte{2, 9, 8, 7, 6, 5}
	clientLinkLocal := netip.MustParseAddr("fe80::2908:7ff:fe06:5")
	now := time.Now()
	frameFor := func(payload []byte) []byte {
		frame := makeDHCPv6EthernetFrame(payload, false)
		setDHCPv6FrameSource(frame, clientLinkLocal)
		return frame
	}
	solicit := makeDHCPv6PDMessage(dhcpv6Solicit, 0x010203, clientID, nil, 0x11223344, netip.Prefix{}, false)
	g.InboundFrom(frameFor(solicit), "session-pd")
	var advertiseFrame []byte
	select {
	case advertiseFrame = <-out:
	case <-time.After(time.Second):
		t.Fatal("gateway did not answer DHCPv6 PD Solicit")
	}
	advertisePayload := advertiseFrame[14+40+8:]
	advertise, ok := parseDHCPv6(advertisePayload)
	if !ok || advertise.typ != dhcpv6Advertise || !advertise.requestedPD.IsValid() {
		t.Fatalf("invalid PD Advertise: %+v, ok=%v", advertise, ok)
	}

	request := makeDHCPv6PDMessage(dhcpv6Request, 0x010204, clientID, g.dhcpv6.serverID, 0x11223344, advertise.requestedPD, false)
	g.InboundFrom(frameFor(request), "session-pd")
	select {
	case <-out:
	case <-time.After(time.Second):
		t.Fatal("gateway did not answer DHCPv6 PD Request")
	}

	delegated := advertise.requestedPD
	nextHop := tcpip.AddrFrom16(clientLinkLocal.As16())
	routeFound := false
	for _, route := range g.stack.GetRouteTable() {
		if route.Destination.Contains(tcpip.AddrFrom16(delegated.Addr().As16())) && route.Destination.Prefix() == delegated.Bits() {
			routeFound = route.Gateway == nextHop && route.NIC == nicID
			break
		}
	}
	if !routeFound {
		t.Fatalf("delegated route %s via %s missing from route table: %+v", delegated, clientLinkLocal, g.stack.GetRouteTable())
	}
	selected, tcpErr := g.stack.FindRoute(nicID, tcpip.AddrFrom16(g.cfg.IPv6Address.Addr().As16()), tcpip.AddrFrom16(delegated.Addr().As16()), ipv6.ProtocolNumber, false)
	if tcpErr != nil {
		t.Fatalf("gVisor could not select a route to delegated prefix %s: %v", delegated, tcpErr)
	}
	selectedNextHop := selected.NextHop()
	if selectedNextHop != nextHop {
		selected.Release()
		t.Fatalf("gVisor selected next hop %s for delegated prefix %s, want %s", selectedNextHop, delegated, clientLinkLocal)
	}
	selected.Release()
	neighbors, tcpErr := g.stack.Neighbors(nicID, ipv6.ProtocolNumber)
	if tcpErr != nil {
		t.Fatal(tcpErr)
	}
	neighborFound := false
	for _, neighbor := range neighbors {
		if neighbor.Addr == nextHop && neighbor.LinkAddr == tcpip.LinkAddress(clientMAC[:]) {
			neighborFound = true
		}
	}
	if !neighborFound {
		t.Fatalf("missing static neighbor for delegated-prefix router %s: %+v", clientLinkLocal, neighbors)
	}

	g.dhcpv6.mu.Lock()
	for _, lease := range g.dhcpv6.pdByClient {
		lease.expires = now.Add(time.Second)
	}
	g.dhcpv6.mu.Unlock()
	g.syncPDRoutes(now.Add(2 * time.Second))
	for _, route := range g.stack.GetRouteTable() {
		if route.Destination.Contains(tcpip.AddrFrom16(delegated.Addr().As16())) && route.Destination.Prefix() == delegated.Bits() {
			t.Fatalf("expired delegated route %s remains installed", delegated)
		}
	}
	neighbors, tcpErr = g.stack.Neighbors(nicID, ipv6.ProtocolNumber)
	if tcpErr != nil {
		t.Fatal(tcpErr)
	}
	for _, neighbor := range neighbors {
		if neighbor.Addr == nextHop {
			t.Fatalf("expired delegated-prefix next hop %s remains installed: %+v", clientLinkLocal, neighbor)
		}
	}
}

func setDHCPv6FrameSource(frame []byte, source netip.Addr) {
	l2Len := 14
	if binary.BigEndian.Uint16(frame[12:14]) == 0x8100 {
		l2Len += 4
	}
	ip := frame[l2Len:]
	addr := source.As16()
	copy(ip[8:24], addr[:])
	udp := ip[40:]
	udp[6], udp[7] = 0, 0
	checksum := dhcpv6UDPChecksum(ip[8:24], ip[24:40], udp)
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], checksum)
}

func TestDHCPv6RejectsOtherServerAndMalformedOptions(t *testing.T) {
	server, err := newDHCPv6Server(netip.MustParsePrefix("fd78:78::1/64"), net.HardwareAddr{2, 1, 2, 3, 4, 5}, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	client := []byte{0, 3, 0, 1, 2, 9, 8, 7, 6, 5}
	var mac [6]byte
	copy(mac[:], client[4:])
	solicit := makeDHCPv6Message(dhcpv6Solicit, 1, client, nil, 1, nil, false)
	if _, ok := parseDHCPv6(append(solicit, 0, 1)); ok {
		t.Fatal("truncated option header accepted")
	}
	if got := server.handle(solicit, mac, "session-a", time.Now()); len(got) == 0 {
		t.Fatal("valid Solicit received no Advertise")
	}
	request := makeDHCPv6Message(dhcpv6Request, 2, client, []byte{0, 2, 9, 9}, 1, nil, false)
	if got := server.handle(request, mac, "session-a", time.Now()); got != nil {
		t.Fatalf("request for another server got a response: %x", got)
	}
}

func TestDHCPv6ReleaseRemovesLease(t *testing.T) {
	server, _ := newDHCPv6Server(netip.MustParsePrefix("fd78:78::1/64"), net.HardwareAddr{2, 1, 2, 3, 4, 5}, nil, time.Hour)
	client := []byte{0, 3, 0, 1, 2, 9, 8, 7, 6, 5}
	var mac [6]byte
	copy(mac[:], client[4:])
	now := time.Now()
	server.handle(makeDHCPv6Message(dhcpv6Solicit, 1, client, nil, 1, nil, true), mac, "session-a", now)
	leaseIP := server.byClient[string(client)+"/00000001"].ip
	server.handle(makeDHCPv6Message(dhcpv6Request, 2, client, server.serverID, 1, &leaseIP, false), mac, "session-a", now.Add(time.Second))
	server.handle(makeDHCPv6Message(dhcpv6Release, 3, client, server.serverID, 1, &leaseIP, false), mac, "session-a", now.Add(2*time.Second))
	if len(server.bindings()) != 0 {
		t.Fatalf("released lease still appears: %+v", server.bindings())
	}
}

func TestDHCPv6StaticReservationAndAuthenticatedOwner(t *testing.T) {
	client := []byte{0, 3, 0, 1, 2, 9, 8, 7, 6, 5}
	mac := net.HardwareAddr{2, 9, 8, 7, 6, 5}
	reservedIP := netip.MustParseAddr("fd78:78::20")
	server, err := newDHCPv6Server(netip.MustParsePrefix("fd78:78::1/64"), net.HardwareAddr{2, 1, 2, 3, 4, 5}, nil, time.Hour,
		DHCPv6Host{ClientID: client, IAID: 7, MAC: mac, IP: reservedIP})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	wrongMAC := [6]byte{2, 9, 8, 7, 6, 4}
	solicit := makeDHCPv6Message(dhcpv6Solicit, 1, client, nil, 7, nil, false)
	if got, ok := parseDHCPv6(server.handle(solicit, wrongMAC, "session-a", now)); !ok || got.requestedIP.IsValid() {
		t.Fatalf("reservation was offered to a different MAC: parsed=%+v ok=%v", got, ok)
	}
	var rightMAC [6]byte
	copy(rightMAC[:], mac)
	advertise, ok := parseDHCPv6(server.handle(solicit, rightMAC, "session-a", now))
	if !ok || advertise.requestedIP != reservedIP {
		t.Fatalf("static address was not advertised: %+v ok=%v", advertise, ok)
	}
	request := makeDHCPv6Message(dhcpv6Request, 2, client, server.serverID, 7, &reservedIP, false)
	reply, ok := parseDHCPv6(server.handle(request, rightMAC, "session-a", now.Add(time.Second)))
	if !ok || reply.typ != dhcpv6Reply || reply.requestedIP != reservedIP {
		t.Fatalf("static address was not leased: %+v ok=%v", reply, ok)
	}
	spoofed := server.handle(makeDHCPv6Message(dhcpv6Renew, 3, client, server.serverID, 7, &reservedIP, false), rightMAC, "session-b", now.Add(2*time.Second))
	if parsed, ok := parseDHCPv6(spoofed); !ok || parsed.requestedIP.IsValid() {
		t.Fatalf("lease renewal moved across authenticated session ports: %+v ok=%v", parsed, ok)
	}
	bindings := server.bindings()
	if len(bindings) != 1 || bindings[0].IP != reservedIP || bindings[0].SessionPort != "session-a" {
		t.Fatalf("static lease binding lost its session identity: %+v", bindings)
	}
}

func TestDHCPv6PrefixDelegationAndSessionBinding(t *testing.T) {
	server, err := newDHCPv6Server(netip.MustParsePrefix("fd78:78::1/64"), net.HardwareAddr{2, 1, 2, 3, 4, 5}, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.ConfigurePrefixDelegation(netip.MustParsePrefix("2001:db8:100::/48"), 56); err != nil {
		t.Fatal(err)
	}
	client := []byte{0, 3, 0, 1, 2, 9, 8, 7, 6, 5}
	mac := [6]byte{2, 9, 8, 7, 6, 5}
	now := time.Now()
	solicit := makeDHCPv6PDMessage(dhcpv6Solicit, 0x010203, client, nil, 0x11223344, netip.Prefix{}, false)
	advertise := server.handle(solicit, mac, "session-pd", now)
	parsed, ok := parseDHCPv6(advertise)
	if !ok || parsed.typ != dhcpv6Advertise || !parsed.requestedPD.IsValid() || parsed.requestedPD.Bits() != 56 || !netip.MustParsePrefix("2001:db8:100::/48").Contains(parsed.requestedPD.Addr()) {
		t.Fatalf("invalid IA_PD Advertise: parsed=%+v ok=%v payload=%x", parsed, ok, advertise)
	}
	want := parsed.requestedPD
	request := makeDHCPv6PDMessage(dhcpv6Request, 0x010204, client, server.serverID, 0x11223344, want, false)
	reply := server.handle(request, mac, "session-pd", now.Add(time.Second))
	parsed, ok = parseDHCPv6(reply)
	if !ok || parsed.typ != dhcpv6Reply || parsed.requestedPD != want {
		t.Fatalf("invalid IA_PD Reply: %+v ok=%v payload=%x", parsed, ok, reply)
	}
	if lease := server.pdByClient[string(client)+"/pd/11223344"]; lease == nil || lease.ingress != "session-pd" || lease.prefix != want {
		t.Fatalf("delegated prefix lost authenticated owner: %+v", lease)
	}
	spoof := server.handle(makeDHCPv6PDMessage(dhcpv6Renew, 3, client, server.serverID, 0x11223344, want, false), mac, "session-other", now.Add(2*time.Second))
	if got, ok := parseDHCPv6(spoof); !ok || got.requestedPD.IsValid() {
		t.Fatalf("delegated prefix moved across session ports: %+v ok=%v", got, ok)
	}
}

func TestDHCPv6CombinedAddressAndPrefixDelegation(t *testing.T) {
	server, err := newDHCPv6Server(netip.MustParsePrefix("fd78:78::1/64"), net.HardwareAddr{2, 1, 2, 3, 4, 5}, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.ConfigurePrefixDelegation(netip.MustParsePrefix("2001:db8:200::/48"), 56); err != nil {
		t.Fatal(err)
	}
	client := []byte{0, 3, 0, 1, 2, 9, 8, 7, 6, 5}
	mac := [6]byte{2, 9, 8, 7, 6, 5}
	request := makeDHCPv6Message(dhcpv6Solicit, 0x010203, client, nil, 0x55667788, nil, false)
	option := makeDHCPv6PDMessage(dhcpv6Solicit, 0x010203, client, nil, 0x99aabbcc, netip.Prefix{}, false)
	appendDHCPv6Option(&request, dhcpv6OptIAPD, dhcpv6OptionValue(option, dhcpv6OptIAPD))
	reply := server.handle(request, mac, "combined-session", time.Now())
	parsed, ok := parseDHCPv6(reply)
	if !ok || parsed.typ != dhcpv6Advertise || !parsed.requestedIP.IsValid() || !parsed.requestedPD.IsValid() {
		t.Fatalf("combined IA_NA+IA_PD request did not receive both offers: parsed=%+v ok=%v reply=%x", parsed, ok, reply)
	}
}

func TestDHCPv6RelayForwardReplyBinding(t *testing.T) {
	client := makeDHCPv6Message(dhcpv6Solicit, 0x123456, []byte{0, 3, 0, 1, 2, 3}, nil, 1, nil, false)
	link, peer := netip.MustParseAddr("fe80::1"), netip.MustParseAddr("fe80::1234")
	forward, err := makeDHCPv6RelayForward(client, link, peer, "segment/port-7")
	if err != nil {
		t.Fatal(err)
	}
	if forward[0] != dhcpv6RelayForward || binary.BigEndian.Uint16(forward[34:36]) != dhcpv6OptRelayMsg {
		t.Fatalf("not a relay-forward: %x", forward)
	}
	response := makeDHCPv6Message(dhcpv6Advertise, 0x123456, []byte{0, 3, 0, 1, 2, 3}, nil, 1, nil, false)
	relayReply := make([]byte, 34)
	relayReply[0] = dhcpv6RelayReply
	l, p := link.As16(), peer.As16()
	copy(relayReply[2:18], l[:])
	copy(relayReply[18:34], p[:])
	appendOpt := func(code uint16, value []byte) {
		var h [4]byte
		binary.BigEndian.PutUint16(h[:2], code)
		binary.BigEndian.PutUint16(h[2:], uint16(len(value)))
		relayReply = append(relayReply, h[:]...)
		relayReply = append(relayReply, value...)
	}
	appendOpt(dhcpv6OptRelayMsg, response)
	appendOpt(18, []byte("segment/port-7"))
	inner, err := parseDHCPv6RelayReply(relayReply, link, peer, "segment/port-7")
	if err != nil || !bytes.Equal(inner, response) {
		t.Fatalf("relay reply rejected: err=%v inner=%x", err, inner)
	}
	if _, err := parseDHCPv6RelayReply(relayReply, link, peer, "segment/port-8"); err == nil {
		t.Fatal("reply with wrong circuit identity accepted")
	}
}

func makeDHCPv6PDMessage(typ byte, xid uint32, client, server []byte, iaid uint32, prefix netip.Prefix, rapid bool) []byte {
	out := []byte{typ, byte(xid >> 16), byte(xid >> 8), byte(xid)}
	option := func(code uint16, value []byte) {
		var h [4]byte
		binary.BigEndian.PutUint16(h[:2], code)
		binary.BigEndian.PutUint16(h[2:], uint16(len(value)))
		out = append(out, h[:]...)
		out = append(out, value...)
	}
	option(dhcpv6OptClientID, client)
	if server != nil {
		option(dhcpv6OptServerID, server)
	}
	ia := make([]byte, 12)
	binary.BigEndian.PutUint32(ia[:4], iaid)
	if prefix.IsValid() {
		value := make([]byte, 25)
		binary.BigEndian.PutUint32(value[:4], 3600)
		binary.BigEndian.PutUint32(value[4:8], 7200)
		value[8] = byte(prefix.Bits())
		addr := prefix.Addr().As16()
		copy(value[9:], addr[:])
		var h [4]byte
		binary.BigEndian.PutUint16(h[:2], dhcpv6OptIAPrefix)
		binary.BigEndian.PutUint16(h[2:], uint16(len(value)))
		ia = append(ia, h[:]...)
		ia = append(ia, value...)
	}
	option(dhcpv6OptIAPD, ia)
	if rapid {
		option(dhcpv6OptRapid, nil)
	}
	return out
}

func makeDHCPv6Message(typ byte, xid uint32, client, server []byte, iaid uint32, address *netip.Addr, rapid bool) []byte {
	out := []byte{typ, byte(xid >> 16), byte(xid >> 8), byte(xid)}
	option := func(code uint16, value []byte) {
		var header [4]byte
		binary.BigEndian.PutUint16(header[:2], code)
		binary.BigEndian.PutUint16(header[2:], uint16(len(value)))
		out = append(out, header[:]...)
		out = append(out, value...)
	}
	option(dhcpv6OptClientID, client)
	if server != nil {
		option(dhcpv6OptServerID, server)
	}
	ia := make([]byte, 12)
	binary.BigEndian.PutUint32(ia[:4], iaid)
	if address != nil {
		value := make([]byte, 24)
		a := address.As16()
		copy(value, a[:])
		var header [4]byte
		binary.BigEndian.PutUint16(header[:2], dhcpv6OptIAAddr)
		binary.BigEndian.PutUint16(header[2:], uint16(len(value)))
		ia = append(ia, header[:]...)
		ia = append(ia, value...)
	}
	option(dhcpv6OptIANA, ia)
	if rapid {
		option(dhcpv6OptRapid, nil)
	}
	return out
}

func makeDHCPv6EthernetFrame(payload []byte, tagged bool) []byte {
	l2Len := 14
	if tagged {
		l2Len += 4
	}
	udpLen := 8 + len(payload)
	frame := make([]byte, l2Len+40+udpLen)
	copy(frame[:6], []byte{0x33, 0x33, 0x00, 0x01, 0x00, 0x02})
	copy(frame[6:12], []byte{2, 9, 8, 7, 6, 5})
	if tagged {
		binary.BigEndian.PutUint16(frame[12:14], 0x8100)
		binary.BigEndian.PutUint16(frame[14:16], 10)
		binary.BigEndian.PutUint16(frame[16:18], 0x86dd)
	} else {
		binary.BigEndian.PutUint16(frame[12:14], 0x86dd)
	}
	ip := frame[l2Len:]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(udpLen))
	ip[6], ip[7] = 17, 1
	destination := dhcpv6AllServersAndRelays.As16()
	copy(ip[24:40], destination[:])
	udp := ip[40:]
	binary.BigEndian.PutUint16(udp[:2], 546)
	binary.BigEndian.PutUint16(udp[2:4], 547)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(udp[8:], payload)
	checksum := dhcpv6UDPChecksum(ip[8:24], ip[24:40], udp)
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], checksum)
	return frame
}
