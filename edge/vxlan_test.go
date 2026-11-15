package edge

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/Dankular/GameBond.Core/bond"
)

func TestVXLANCodecValidatesVNIAndReservedFields(t *testing.T) {
	frame := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2, 0, 0, 0, 0, 1, 0x88, 0xb5}
	packet, ok := encodeVXLAN(42, frame, 1500)
	if !ok || len(packet) != vxlanHeaderLen+len(frame) {
		t.Fatalf("VXLAN encode failed: ok=%v packet=%x", ok, packet)
	}
	got, ok := decodeVXLAN(packet, 42, 1500)
	if !ok || string(got) != string(frame) {
		t.Fatalf("VXLAN decode mismatch: ok=%v frame=%x", ok, got)
	}
	if _, ok := decodeVXLAN(packet, 43, 1500); ok {
		t.Fatal("packet with a different VNI was accepted")
	}
	for _, offset := range []int{0, 1, 2, 3, 7} {
		bad := append([]byte(nil), packet...)
		bad[offset] ^= 1
		if _, ok := decodeVXLAN(bad, 42, 1500); ok {
			t.Fatalf("reserved/flag mutation at byte %d was accepted", offset)
		}
	}
}

func TestVXLANOverlaySwitchesFramesBetweenNamedSegments(t *testing.T) {
	addrA := reserveVXLANAddr(t)
	addrB := reserveVXLANAddr(t)
	fabricA := NewNamedSegmentFabric("venue-crosshost", bond.L2SwitchConfig{})
	fabricB := NewNamedSegmentFabric("venue-crosshost", bond.L2SwitchConfig{})
	sessionA, err := fabricA.AttachSession(bond.L2PortConfig{Name: "session-a", VLAN: bond.L2VLANPolicy{AccessVLAN: 10}}, 8, false, false)
	if err != nil {
		t.Fatal(err)
	}
	sessionB, err := fabricB.AttachSession(bond.L2PortConfig{Name: "session-b", VLAN: bond.L2VLANPolicy{AccessVLAN: 10}}, 8, false, false)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	portPolicy := bond.L2PortConfig{VLAN: bond.L2VLANPolicy{AllowedVLANs: []uint16{10}}}
	overlayA, err := AttachVXLAN(ctx, fabricA, VXLANConfig{VNI: 1042, Listen: addrA, Peers: []VXLANPeer{{Remote: addrB}}, Port: portPolicy})
	if err != nil {
		t.Fatal(err)
	}
	defer overlayA.Close()
	overlayB, err := AttachVXLAN(ctx, fabricB, VXLANConfig{VNI: 1042, Listen: addrB, Peers: []VXLANPeer{{Remote: addrA}}, Port: portPolicy})
	if err != nil {
		t.Fatal(err)
	}
	defer overlayB.Close()

	frameA := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2, 0, 0, 0, 0, 0x11, 0x88, 0xb5}
	if verdict := sessionA.Send(frameA, time.Now()); verdict.Drop != bond.L2Forward {
		t.Fatalf("local frame did not enter the fabric: %+v", verdict)
	}
	forwarded := awaitVXLANFrame(t, sessionB)
	if string(forwarded.Frame) != string(frameA) || forwarded.IngressIdentity == "session-b" {
		t.Fatalf("remote frame changed or lost ingress metadata: %+v", forwarded)
	}

	frameB := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2, 0, 0, 0, 0, 0x22, 0x88, 0xb5}
	if verdict := sessionB.Send(frameB, time.Now()); verdict.Drop != bond.L2Forward {
		t.Fatalf("reverse local frame did not enter the fabric: %+v", verdict)
	}
	forwarded = awaitVXLANFrame(t, sessionA)
	if string(forwarded.Frame) != string(frameB) {
		t.Fatalf("reverse remote frame changed: %+v", forwarded)
	}
	listener, err := fabricB.AttachSession(bond.L2PortConfig{Name: "listener", VLAN: bond.L2VLANPolicy{AccessVLAN: 10}}, 8, false, false)
	if err != nil {
		t.Fatal(err)
	}
	nonmember, err := fabricB.AttachSession(bond.L2PortConfig{Name: "nonmember", VLAN: bond.L2VLANPolicy{AccessVLAN: 10}}, 8, false, false)
	if err != nil {
		t.Fatal(err)
	}
	querier, err := fabricB.AttachService(bond.L2PortConfig{Name: "querier", VLAN: bond.L2VLANPolicy{AccessVLAN: 10},
		MulticastRouter: true, MulticastQuerier: true, QuerierMAC: [6]byte{2, 0, 0, 0, 0, 9}, QuerierIPv4: [4]byte{10, 0, 0, 9},
		QuerierIPv6: [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9}}, 8, false, false)
	if err != nil {
		t.Fatal(err)
	}
	queries := fabricB.sw.DueMulticastQueries(time.Now())
	if len(queries) != 2 {
		t.Fatalf("dual-stack querier generated %d queries, want IGMP and MLD", len(queries))
	}
	for _, query := range queries {
		if verdict := querier.Send(query.Frame, time.Now()); verdict.Drop != bond.L2Forward {
			t.Fatalf("multicast query did not enter the fabric: %+v", verdict)
		}
	}
	for _, port := range []*SegmentPort{sessionB, listener, nonmember} {
		gotIGMP, gotMLD := false, false
		for range queries {
			delivery := awaitVXLANFrame(t, port)
			info, parseErr := bond.ParseFrame(delivery.Frame)
			if parseErr != nil {
				t.Fatalf("could not parse multicast query: %v", parseErr)
			}
			gotIGMP = gotIGMP || info.IGMPQuery
			gotMLD = gotMLD || info.MLDQuery
		}
		if !gotIGMP || !gotMLD {
			t.Fatalf("port did not receive both IGMP and MLD queries: IGMP=%v MLD=%v", gotIGMP, gotMLD)
		}
	}
	group := [4]byte{239, 1, 2, 3}
	if verdict := listener.Send(vxlanIGMPReport(0x43, group), time.Now()); verdict.Drop != bond.L2Forward {
		t.Fatalf("remote listener join did not enter the fabric: %+v", verdict)
	}
	multicast := vxlanIPv4MulticastFrame(0x44, group)
	if verdict := sessionA.Send(multicast, time.Now()); verdict.Drop != bond.L2Forward {
		t.Fatalf("source multicast did not enter the local fabric: %+v", verdict)
	}
	forwarded = awaitVXLANFrame(t, listener)
	if string(forwarded.Frame) != string(multicast) {
		t.Fatalf("joined multicast changed across VXLAN: %+v", forwarded)
	}
	select {
	case delivery := <-nonmember.Receive():
		t.Fatalf("nonmember received snooped VXLAN multicast: %+v", delivery)
	case <-time.After(50 * time.Millisecond):
	}
	group6 := [16]byte{0xff, 0x3e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34}
	if verdict := listener.Send(vxlanMLDv1Report(0x45, group6), time.Now()); verdict.Drop != bond.L2Forward {
		t.Fatalf("remote MLD listener join did not enter the fabric: %+v", verdict)
	}
	multicast6 := vxlanIPv6MulticastFrame(0x46, group6)
	if verdict := sessionA.Send(multicast6, time.Now()); verdict.Drop != bond.L2Forward {
		t.Fatalf("source IPv6 multicast did not enter the local fabric: %+v", verdict)
	}
	forwarded = awaitVXLANFrame(t, listener)
	if string(forwarded.Frame) != string(multicast6) {
		t.Fatalf("joined IPv6 multicast changed across VXLAN: %+v", forwarded)
	}
	select {
	case delivery := <-nonmember.Receive():
		t.Fatalf("nonmember received snooped VXLAN IPv6 multicast: %+v", delivery)
	case <-time.After(50 * time.Millisecond):
	}
	if overlayA.Stats().Encapsulated == 0 || overlayB.Stats().Decapsulated == 0 {
		t.Fatalf("VXLAN counters did not record transport: A=%+v B=%+v", overlayA.Stats(), overlayB.Stats())
	}

	rogue, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(overlayB.Addr()))
	if err != nil {
		t.Fatal(err)
	}
	defer rogue.Close()
	packet, _ := encodeVXLAN(1042, frameA, 1400)
	if _, err := rogue.Write(packet); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for overlayB.Stats().Invalid == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if overlayB.Stats().Invalid == 0 {
		t.Fatal("datagram from a non-peer VTEP was not rejected")
	}
	select {
	case leaked := <-sessionB.Receive():
		t.Fatalf("unlisted VTEP injected a frame: %+v", leaked)
	case <-time.After(50 * time.Millisecond):
	}
}

func vxlanIGMPReport(source byte, group [4]byte) []byte {
	dst := [6]byte{0x01, 0x00, 0x5e, group[1] & 0x7f, group[2], group[3]}
	ip := make([]byte, 28)
	ip[0], ip[8], ip[9] = 0x45, 1, 2
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	ip[12], ip[15] = 10, source
	copy(ip[16:20], group[:])
	ip[20] = 0x16
	copy(ip[24:28], group[:])
	return vxlanEthernetFrame(dst, [6]byte{2, 0, 0, 0, 0, source}, 0x0800, ip)
}

func vxlanIPv4MulticastFrame(source byte, group [4]byte) []byte {
	dst := [6]byte{0x01, 0x00, 0x5e, group[1] & 0x7f, group[2], group[3]}
	ip := make([]byte, 20)
	ip[0], ip[8], ip[9] = 0x45, 1, 1
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	ip[12], ip[15] = 10, source
	copy(ip[16:20], group[:])
	return vxlanEthernetFrame(dst, [6]byte{2, 0, 0, 0, 0, source}, 0x0800, ip)
}

func vxlanMLDv1Report(source byte, group [16]byte) []byte {
	dst := [6]byte{0x33, 0x33, group[12], group[13], group[14], group[15]}
	ip := make([]byte, 40+8+24)
	ip[0], ip[6], ip[7] = 0x60, 0, 1
	binary.BigEndian.PutUint16(ip[4:6], 8+24)
	ip[8], ip[9] = 0xfe, 2
	ip[23] = source
	copy(ip[24:40], group[:])
	copy(ip[40:48], []byte{58, 0, 5, 2, 0, 0, 1, 0})
	ip[48] = 131
	copy(ip[56:72], group[:])
	return vxlanEthernetFrame(dst, [6]byte{2, 0, 0, 0, 0, source}, 0x86dd, ip)
}

func vxlanIPv6MulticastFrame(source byte, group [16]byte) []byte {
	dst := [6]byte{0x33, 0x33, group[12], group[13], group[14], group[15]}
	ip := make([]byte, 40)
	ip[0], ip[6], ip[7] = 0x60, 59, 1
	ip[8], ip[9] = 0xfe, 2
	ip[23] = source
	copy(ip[24:40], group[:])
	return vxlanEthernetFrame(dst, [6]byte{2, 0, 0, 0, 0, source}, 0x86dd, ip)
}

func vxlanEthernetFrame(dst, src [6]byte, etherType uint16, payload []byte) []byte {
	frame := append([]byte{}, dst[:]...)
	frame = append(frame, src[:]...)
	frame = append(frame, byte(etherType>>8), byte(etherType))
	return append(frame, payload...)
}

func reserveVXLANAddr(t *testing.T) netip.AddrPort {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	addr := conn.LocalAddr().(*net.UDPAddr).AddrPort()
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func awaitVXLANFrame(t *testing.T, port *SegmentPort) SegmentFrame {
	t.Helper()
	select {
	case frame, ok := <-port.Receive():
		if !ok {
			t.Fatal("segment port closed before VXLAN delivery")
		}
		return frame
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for VXLAN frame")
		return SegmentFrame{}
	}
}
