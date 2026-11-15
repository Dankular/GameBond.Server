package edge

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/Dankular/GameBond.Core/bond"
)

func TestPrepareMDNSRelayFrameChecksAndMarksIPv4Multicast(t *testing.T) {
	frame := mdnsIPv4QueryFrame(false)
	got, ok := prepareMDNSRelayFrame(frame)
	if !ok {
		t.Fatal("valid mDNS query rejected")
	}
	if !isMDNSRelayFrame(got) || got[14+8] != 255 || internetChecksum(got[14:34]) != 0 {
		t.Fatal("relay marker, hop limit, or IPv4 checksum is invalid")
	}
	if isMDNSRelayFrame(frame) {
		t.Fatal("ordinary client frame was marked as a relay")
	}
	quFrame := mdnsIPv4QueryFrame(true)
	quRelay, ok := prepareMDNSRelayFrame(quFrame)
	if !ok || !isMDNSRelayFrame(quRelay) {
		t.Fatal("valid QU query was not converted to a multicast relay query")
	}
	quDNS := quRelay[42:]
	if binary.BigEndian.Uint16(quDNS[len(quDNS)-2:])&0x8000 != 0 || !validIPv4UDPChecksum(quRelay[26:34], quRelay[34:]) {
		t.Fatal("relayed IPv4 query retained QU or has an invalid UDP checksum")
	}
	badTTL := mdnsIPv4QueryFrame(false)
	badTTL[22] = 254
	badTTL[24], badTTL[25] = 0, 0
	binary.BigEndian.PutUint16(badTTL[24:26], internetChecksumValue(badTTL[14:34]))
	if _, ok := prepareMDNSRelayFrame(badTTL); ok {
		t.Fatal("non-link-local IPv4 TTL was relayed")
	}
	badChecksum := append([]byte(nil), frame...)
	badChecksum[24] ^= 1
	if _, ok := prepareMDNSRelayFrame(badChecksum); ok {
		t.Fatal("invalid IPv4 header checksum was relayed")
	}
}

func TestPrepareMDNSRelayConvertsIPv6QUQuestionAndRecomputesChecksum(t *testing.T) {
	frame := mdnsIPv6QueryFrame(true)
	got, ok := prepareMDNSRelayFrame(frame)
	if !ok || !isMDNSRelayFrame(got) {
		t.Fatal("valid IPv6 QU query was not relayed")
	}
	dns := got[14+40+8:]
	if binary.BigEndian.Uint16(dns[len(dns)-2:])&0x8000 != 0 {
		t.Fatal("relayed IPv6 query retained QU")
	}
	if !validIPv6UDPChecksum(got[22:54], got[54:]) {
		t.Fatal("relayed IPv6 query has an invalid UDP checksum")
	}
}

func TestPrepareMDNSRelayFrameValidatesIPv6HopLimitAndUDPChecksum(t *testing.T) {
	frame := mdnsIPv6ResponseFrame()
	got, ok := prepareMDNSRelayFrame(frame)
	if !ok || !isMDNSRelayFrame(got) || got[14+7] != 255 {
		t.Fatalf("valid IPv6 mDNS response rejected or rewritten incorrectly: ok=%v checksum=%v", ok, validIPv6UDPChecksum(frame[22:54], frame[54:]))
	}
	bad := append([]byte(nil), frame...)
	bad[14+7] = 64
	if _, ok := prepareMDNSRelayFrame(bad); ok {
		t.Fatal("IPv6 mDNS with non-255 hop limit was relayed")
	}
	bad = append([]byte(nil), frame...)
	bad[len(bad)-1] ^= 1
	if _, ok := prepareMDNSRelayFrame(bad); ok {
		t.Fatal("IPv6 mDNS with invalid UDP checksum was relayed")
	}
}

func TestMDNSUnicastTrackerReturnsAnswersOnlyToAuthorizedQueryOrigins(t *testing.T) {
	now := time.Unix(100, 0)
	tracker := newMDNSUnicastTracker()
	query := mdnsIPv4QueryFrame(false)
	binary.BigEndian.PutUint16(query[34:36], 5354) // legacy query source port requests a unicast answer.
	binary.BigEndian.PutUint16(query[42:44], 0x1234)
	binary.BigEndian.PutUint16(query[40:42], 0)
	binary.BigEndian.PutUint16(query[40:42], internetChecksumValue(ipv4UDPPseudoHeader(query[26:34], query[34:])))
	if _, ok := prepareMDNSRelayFrame(query); !ok {
		t.Fatal("valid legacy mDNS query rejected")
	}
	if !tracker.rememberQuery(query, 10, 20, now) {
		t.Fatal("legacy query return path was not recorded")
	}
	secondOrigin := append([]byte(nil), query...)
	copy(secondOrigin[6:12], []byte{2, 0xaa, 0xbb, 0xcc, 0xdd, 9})
	if !tracker.rememberQuery(secondOrigin, 11, 20, now) {
		t.Fatal("overlapping-address query origin was not recorded")
	}
	response := mdnsIPv4UnicastResponseFrame([6]byte{2, 0xaa, 0xbb, 0xcc, 0xdd, 2}, netip.MustParseAddr("169.254.1.2"), 5354, 0x1234)
	if deliveries, consumed := tracker.reflectResponse(response, 10, now.Add(time.Second)); !consumed || len(deliveries) != 0 {
		t.Fatal("wrong-VLAN answer was not consumed without being reflected")
	}
	wrongID := append([]byte(nil), response...)
	binary.BigEndian.PutUint16(wrongID[42:44], 0x4321)
	binary.BigEndian.PutUint16(wrongID[40:42], 0)
	binary.BigEndian.PutUint16(wrongID[40:42], internetChecksumValue(ipv4UDPPseudoHeader(wrongID[26:34], wrongID[34:])))
	if deliveries, consumed := tracker.reflectResponse(wrongID, 20, now.Add(time.Second)); !consumed || len(deliveries) != 0 {
		t.Fatal("answer with a different DNS transaction ID was not consumed without reflection")
	}
	deliveries, matched := tracker.reflectResponse(response, 20, now.Add(time.Second))
	if !matched || len(deliveries) != 2 {
		t.Fatalf("matching unicast answer deliveries = %d, matched=%v", len(deliveries), matched)
	}
	want := map[uint16][6]byte{10: {2, 0xaa, 0xbb, 0xcc, 0xdd, 1}, 11: {2, 0xaa, 0xbb, 0xcc, 0xdd, 9}}
	for _, delivery := range deliveries {
		mac, exists := want[delivery.vlan]
		if !exists || !bytes.Equal(delivery.frame[:6], mac[:]) || !bytes.Equal(delivery.frame[6:12], mdnsRelayMAC[:]) {
			t.Fatalf("unicast answer delivered to unauthorized origin VLAN/MAC %d/%x", delivery.vlan, delivery.frame[:6])
		}
		delete(want, delivery.vlan)
	}
	if len(want) != 0 {
		t.Fatalf("unicast answer missed authorized origin VLANs: %v", want)
	}
	if deliveries, consumed := tracker.reflectResponse(response, 20, now.Add(6*time.Second)); !consumed || len(deliveries) != 0 {
		t.Fatal("expired unicast answer was not consumed without reflection")
	}
}

func mdnsIPv4UnicastResponseFrame(destinationMAC [6]byte, destinationIP netip.Addr, destinationPort, transactionID uint16) []byte {
	dns := []byte{0, 0, 0x84, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(dns[:2], transactionID)
	frame := make([]byte, 14+20+8+len(dns))
	copy(frame[:6], mdnsRelayMAC[:])
	copy(frame[6:12], []byte{2, 0xaa, 0xbb, 0xcc, 0xdd, 2})
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	ip := frame[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+8+len(dns)))
	ip[8], ip[9] = 255, 17
	copy(ip[12:16], netip.MustParseAddr("169.254.2.3").AsSlice())
	copy(ip[16:20], destinationIP.AsSlice())
	binary.BigEndian.PutUint16(ip[10:12], internetChecksumValue(ip))
	udp := frame[34:42]
	binary.BigEndian.PutUint16(udp[0:2], 5353)
	binary.BigEndian.PutUint16(udp[2:4], destinationPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(dns)))
	copy(frame[42:], dns)
	binary.BigEndian.PutUint16(udp[6:8], internetChecksumValue(ipv4UDPPseudoHeader(ip[12:20], frame[34:])))
	return frame
}

func TestMDNSUnicastTrackerHandlesIPv6LegacyResponses(t *testing.T) {
	now := time.Unix(200, 0)
	tracker := newMDNSUnicastTracker()
	query := mdnsIPv6QueryFrame(false)
	binary.BigEndian.PutUint16(query[54:56], 5354)
	binary.BigEndian.PutUint16(query[62:64], 0x4321)
	binary.BigEndian.PutUint16(query[60:62], 0)
	binary.BigEndian.PutUint16(query[60:62], ipv6UDPChecksum(query[22:54], query[54:]))
	if _, ok := prepareMDNSRelayFrame(query); !ok || !tracker.rememberQuery(query, 30, 40, now) {
		t.Fatal("valid IPv6 legacy mDNS query or return-path recording failed")
	}
	response := mdnsIPv6UnicastResponseFrame(netip.MustParseAddr("fe80::2"), 5354, 0x4321)
	deliveries, matched := tracker.reflectResponse(response, 40, now.Add(time.Second))
	if !matched || len(deliveries) != 1 || deliveries[0].vlan != 30 || !bytes.Equal(deliveries[0].frame[:6], query[6:12]) {
		t.Fatalf("IPv6 unicast response target mismatch: matched=%v deliveries=%+v", matched, deliveries)
	}
	if !validIPv6UDPChecksum(deliveries[0].frame[22:54], deliveries[0].frame[54:]) {
		t.Fatal("IPv6 unicast response checksum changed during L2 rewrite")
	}
}

func TestMDNSUnicastReflectionCrossesOnlyTheAuthorizedFabricVLANPair(t *testing.T) {
	fabric := NewNamedSegmentFabric("mdns-pair", bond.L2SwitchConfig{})
	sourceGateway, err := fabric.AttachService(bond.L2PortConfig{Name: "gateway-10", VLAN: bond.L2VLANPolicy{AccessVLAN: 10}}, 8, false, false)
	if err != nil {
		t.Fatal(err)
	}
	targetGateway, err := fabric.AttachService(bond.L2PortConfig{Name: "gateway-20", VLAN: bond.L2VLANPolicy{AccessVLAN: 20}}, 8, false, false)
	if err != nil {
		t.Fatal(err)
	}
	client, err := fabric.AttachSession(bond.L2PortConfig{Name: "client", VLAN: bond.L2VLANPolicy{AccessVLAN: 10}}, 8, false, false)
	if err != nil {
		t.Fatal(err)
	}
	responder, err := fabric.AttachSession(bond.L2PortConfig{Name: "responder", VLAN: bond.L2VLANPolicy{AccessVLAN: 20}}, 8, false, false)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(300, 0)
	query := mdnsIPv4QueryFrame(false)
	binary.BigEndian.PutUint16(query[34:36], 5354)
	binary.BigEndian.PutUint16(query[42:44], 0x2345)
	binary.BigEndian.PutUint16(query[40:42], 0)
	binary.BigEndian.PutUint16(query[40:42], internetChecksumValue(ipv4UDPPseudoHeader(query[26:34], query[34:])))
	if verdict := client.Send(query, now); verdict.Drop != bond.L2Forward {
		t.Fatalf("source client query rejected: %+v", verdict)
	}
	select {
	case ingress := <-sourceGateway.Receive():
		if ingress.IngressIdentity != "client" {
			t.Fatalf("query ingress identity = %q, want client", ingress.IngressIdentity)
		}
	case <-time.After(time.Second):
		t.Fatal("mDNS query did not reach the source VLAN gateway")
	}
	relayQuery, ok := prepareMDNSRelayFrame(query)
	if !ok {
		t.Fatal("valid mDNS query could not be prepared for reflection")
	}
	tracker := newMDNSUnicastTracker()
	if !tracker.rememberQuery(query, 10, 20, now) {
		t.Fatal("query return path was not recorded")
	}
	if verdict := targetGateway.Send(relayQuery, now); verdict.Drop != bond.L2Forward {
		t.Fatalf("reflected query rejected by target VLAN: %+v", verdict)
	}
	select {
	case delivery := <-responder.Receive():
		if delivery.IngressIdentity != "gateway-20" || !isMDNSRelayFrame(delivery.Frame) {
			t.Fatalf("reflected query lost its target gateway identity: %+v", delivery)
		}
	case <-time.After(time.Second):
		t.Fatal("reflected query did not reach the target VLAN responder")
	}
	response := mdnsIPv4UnicastResponseFrame([6]byte{2, 0xaa, 0xbb, 0xcc, 0xdd, 2}, netip.MustParseAddr("169.254.1.2"), 5354, 0x2345)
	if verdict := responder.Send(response, now.Add(time.Second)); verdict.Drop != bond.L2Forward {
		t.Fatalf("target responder's unicast answer rejected: %+v", verdict)
	}
	select {
	case incoming := <-targetGateway.Receive():
		if incoming.IngressIdentity != "responder" {
			t.Fatalf("unicast answer ingress identity = %q, want responder", incoming.IngressIdentity)
		}
		deliveries, matched := tracker.reflectResponse(incoming.Frame, 20, now.Add(time.Second))
		if !matched || len(deliveries) != 1 || deliveries[0].vlan != 10 {
			t.Fatalf("target response did not map back to VLAN 10: matched=%v deliveries=%+v", matched, deliveries)
		}
		if verdict := sourceGateway.Send(deliveries[0].frame, now.Add(time.Second)); verdict.Drop != bond.L2Forward {
			t.Fatalf("returned answer rejected by source VLAN: %+v", verdict)
		}
	case <-time.After(time.Second):
		t.Fatal("target VLAN responder's unicast answer did not reach its gateway")
	}
	select {
	case delivery := <-client.Receive():
		if delivery.IngressIdentity != "gateway-10" || !bytes.Equal(delivery.Frame[:6], query[6:12]) || !bytes.Equal(delivery.Frame[6:12], mdnsRelayMAC[:]) || binary.BigEndian.Uint16(delivery.Frame[14+20+2:14+20+4]) != 5354 {
			t.Fatalf("unicast answer did not return intact to its client: %+v", delivery)
		}
	case <-time.After(time.Second):
		t.Fatal("unicast mDNS answer did not return to the query origin")
	}
}

func mdnsIPv6UnicastResponseFrame(destinationIP netip.Addr, destinationPort, transactionID uint16) []byte {
	dns := []byte{0, 0, 0x84, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(dns[:2], transactionID)
	frame := make([]byte, 14+40+8+len(dns))
	copy(frame[:6], mdnsRelayMAC[:])
	copy(frame[6:12], []byte{2, 0xaa, 0xbb, 0xcc, 0xdd, 3})
	binary.BigEndian.PutUint16(frame[12:14], 0x86dd)
	ip := frame[14:54]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(8+len(dns)))
	ip[6], ip[7] = 17, 255
	copy(ip[8:24], netip.MustParseAddr("fe80::3").AsSlice())
	copy(ip[24:40], destinationIP.AsSlice())
	udp := frame[54:62]
	binary.BigEndian.PutUint16(udp[0:2], 5353)
	binary.BigEndian.PutUint16(udp[2:4], destinationPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(dns)))
	copy(frame[62:], dns)
	binary.BigEndian.PutUint16(udp[6:8], ipv6UDPChecksum(ip[8:40], frame[54:]))
	return frame
}

func mdnsIPv4QueryFrame(unicastResponse bool) []byte {
	dns := []byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
		5, '_', 'h', 't', 't', 'p', 4, '_', 't', 'c', 'p', 5, 'l', 'o', 'c', 'a', 'l', 0,
		0, 12, 0, 1}
	if unicastResponse {
		dns[len(dns)-2] = 0x80
	}
	frame := make([]byte, 14+20+8+len(dns))
	copy(frame[:6], []byte{1, 0, 0x5e, 0, 0, 0xfb})
	copy(frame[6:12], []byte{2, 0xaa, 0xbb, 0xcc, 0xdd, 1})
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	ip := frame[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+8+len(dns)))
	ip[8], ip[9] = 255, 17
	copy(ip[12:16], netip.MustParseAddr("169.254.1.2").AsSlice())
	copy(ip[16:20], mdnsIPv4Group[:])
	binary.BigEndian.PutUint16(ip[10:12], internetChecksumValue(ip))
	udp := frame[34:42]
	binary.BigEndian.PutUint16(udp[0:2], 5353)
	binary.BigEndian.PutUint16(udp[2:4], 5353)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(dns)))
	copy(frame[42:], dns)
	pseudo := ipv4UDPPseudoHeader(ip[12:20], frame[34:])
	binary.BigEndian.PutUint16(udp[6:8], internetChecksumValue(pseudo))
	return frame
}

func mdnsIPv6QueryFrame(unicastResponse bool) []byte {
	dns := []byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
		5, '_', 'h', 't', 't', 'p', 4, '_', 't', 'c', 'p', 5, 'l', 'o', 'c', 'a', 'l', 0,
		0, 12, 0, 1}
	if unicastResponse {
		dns[len(dns)-2] = 0x80
	}
	frame := make([]byte, 14+40+8+len(dns))
	copy(frame[:6], []byte{0x33, 0x33, 0, 0, 0, 0xfb})
	copy(frame[6:12], []byte{2, 0xaa, 0xbb, 0xcc, 0xdd, 1})
	binary.BigEndian.PutUint16(frame[12:14], 0x86dd)
	ip := frame[14:54]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(8+len(dns)))
	ip[6], ip[7] = 17, 255
	copy(ip[8:24], netip.MustParseAddr("fe80::2").AsSlice())
	copy(ip[24:40], mdnsIPv6Group[:])
	udp := frame[54:62]
	binary.BigEndian.PutUint16(udp[0:2], 5353)
	binary.BigEndian.PutUint16(udp[2:4], 5353)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(dns)))
	copy(frame[62:], dns)
	binary.BigEndian.PutUint16(udp[6:8], ipv6UDPChecksum(ip[8:40], frame[54:]))
	return frame
}

func mdnsIPv6ResponseFrame() []byte {
	dns := []byte{0, 0, 0x84, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	frame := make([]byte, 14+40+8+len(dns))
	copy(frame[:6], []byte{0x33, 0x33, 0, 0, 0, 0xfb})
	copy(frame[6:12], []byte{2, 0xaa, 0xbb, 0xcc, 0xdd, 1})
	binary.BigEndian.PutUint16(frame[12:14], 0x86dd)
	ip := frame[14:54]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(8+len(dns)))
	ip[6], ip[7] = 17, 255
	copy(ip[8:24], netip.MustParseAddr("fe80::1").AsSlice())
	copy(ip[24:40], mdnsIPv6Group[:])
	udp := frame[54:62]
	binary.BigEndian.PutUint16(udp[0:2], 5353)
	binary.BigEndian.PutUint16(udp[2:4], 5353)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(dns)))
	copy(frame[62:], dns)
	pseudo := make([]byte, 40+8+len(dns))
	copy(pseudo[:32], ip[8:40])
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(8+len(dns)))
	pseudo[39] = 17
	copy(pseudo[40:], frame[54:])
	binary.BigEndian.PutUint16(udp[6:8], internetChecksumValue(pseudo))
	return frame
}
