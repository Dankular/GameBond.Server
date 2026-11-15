package l2gw

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestDHCPv6RelayForwardsAndReturnsToAuthenticatedIngress(t *testing.T) {
	server, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer server.Close()
	serverAddr := server.LocalAddr().(*net.UDPAddr).AddrPort()
	out := make(chan []byte, 1)
	mac := net.HardwareAddr{2, 1, 2, 3, 4, 5}
	link, peer := netip.MustParseAddr("fd78:78::1"), netip.IPv6Unspecified()
	relay, err := newDHCPv6Relay(serverAddr, link, mac, netip.MustParseAddr("fe80::1"), func(frame []byte) { out <- frame })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { relay.readLoop(ctx.Done()); close(done) }()
	defer func() { relay.Close(); <-done }()

	clientID := []byte{0, 3, 0, 1, 2, 9, 8, 7, 6, 5}
	request := makeDHCPv6Message(dhcpv6Solicit, 0x010203, clientID, nil, 7, nil, false)
	frame := makeDHCPv6EthernetFrame(request, true)
	if !relay.HandleFrame(frame, "authenticated-session-7") {
		t.Fatal("DHCPv6 request was not consumed")
	}
	buf := make([]byte, 2048)
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	n, client, err := server.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read relay-forward: %v", err)
	}
	forward := buf[:n]
	if forward[0] != dhcpv6RelayForward {
		t.Fatalf("upstream got message type %d, want Relay-Forward", forward[0])
	}
	gotPeer, gotCircuit, ok := parseRelayForwardForTest(forward)
	if !ok || gotPeer != peer || gotCircuit != "authenticated-session-7" {
		t.Fatalf("relay-forward identity/address mismatch: peer=%s circuit=%q valid=%v", gotPeer, gotCircuit, ok)
	}

	response := makeDHCPv6Message(dhcpv6Advertise, 0x010203, clientID, nil, 7, nil, false)
	reply := make([]byte, 34)
	reply[0] = dhcpv6RelayReply
	l, p := link.As16(), peer.As16()
	copy(reply[2:18], l[:])
	copy(reply[18:34], p[:])
	appendRelayOption := func(code uint16, value []byte) {
		var h [4]byte
		binary.BigEndian.PutUint16(h[:2], code)
		binary.BigEndian.PutUint16(h[2:], uint16(len(value)))
		reply = append(reply, h[:]...)
		reply = append(reply, value...)
	}
	appendRelayOption(dhcpv6OptRelayMsg, response)
	appendRelayOption(18, []byte("authenticated-session-7"))
	if _, err := server.WriteToUDP(reply, client); err != nil {
		t.Fatal(err)
	}
	select {
	case delivered := <-out:
		clientMulticastMAC := []byte{0x33, 0x33, 0, 1, 0, 2}
		if string(delivered[:6]) != string(clientMulticastMAC) {
			t.Fatalf("reply did not target the original DHCPv6 all-servers group: %x", delivered[:12])
		}
		payload := delivered[18+48:]
		parsed, valid := parseDHCPv6(payload)
		if !valid || parsed.typ != dhcpv6Advertise {
			t.Fatalf("bad relayed client response: %+v valid=%v", parsed, valid)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not return matching reply to the original client ingress")
	}
}

func TestGatewayConfigStartsDHCPv6RelayInsteadOfLocalServer(t *testing.T) {
	server, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer server.Close()
	g, err := New(Config{
		Address: netip.MustParsePrefix("10.78.0.1/24"), DHCPStart: netip.MustParseAddr("10.78.0.100"), DHCPEnd: netip.MustParseAddr("10.78.0.120"),
		IPv6Address: netip.MustParsePrefix("fd78:78::1/64"), DHCPRelay6: server.LocalAddr().(*net.UDPAddr).AddrPort(),
		Out: func([]byte) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	if g.dhcpv6 != nil || g.dhcpv6Relay == nil {
		t.Fatalf("relay mode did not replace local DHCPv6 server: local=%v relay=%v", g.dhcpv6, g.dhcpv6Relay)
	}
}

func parseRelayForwardForTest(payload []byte) (netip.Addr, string, bool) {
	if len(payload) < 34 || payload[0] != dhcpv6RelayForward {
		return netip.Addr{}, "", false
	}
	peer := netip.AddrFrom16([16]byte(payload[18:34]))
	circuit := ""
	for off := 34; off+4 <= len(payload); {
		code, n := binary.BigEndian.Uint16(payload[off:off+2]), int(binary.BigEndian.Uint16(payload[off+2:off+4]))
		off += 4
		if n > len(payload)-off {
			return netip.Addr{}, "", false
		}
		if code == 18 {
			circuit = string(payload[off : off+n])
		}
		off += n
	}
	return peer, circuit, peer.Is6() && circuit != ""
}
