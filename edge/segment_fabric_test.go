package edge

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/Dankular/GameBond.Core/bond"
	"github.com/Dankular/GameBond.Server/l2gw"
)

func TestLLDPMEDGatewayAdvertisementReachesVLANSession(t *testing.T) {
	fabric := NewNamedSegmentFabric("venue-lldp", bond.L2SwitchConfig{})
	service, err := fabric.AttachService(bond.L2PortConfig{
		Name: "gateway-vlan-23", VLAN: bond.L2VLANPolicy{AccessVLAN: 23},
	}, 4, false, false)
	if err != nil {
		t.Fatal(err)
	}
	session, err := fabric.AttachSession(bond.L2PortConfig{
		Name: "phone", VLAN: bond.L2VLANPolicy{AccessVLAN: 23},
	}, 4, false, false)
	if err != nil {
		t.Fatal(err)
	}
	const now = 1_800_000_000
	gateway, err := l2gw.New(l2gw.Config{
		Address:         netip.MustParsePrefix("10.23.0.1/24"),
		DHCPStart:       netip.MustParseAddr("10.23.0.100"),
		DHCPEnd:         netip.MustParseAddr("10.23.0.110"),
		LLDPMEDPolicy:   &l2gw.LLDPMEDNetworkPolicy{ApplicationType: 1, VLANID: 23, Tagged: true, L2Priority: 5, DSCP: 46},
		LLDPMEDInterval: time.Hour,
		Out: func(frame []byte) {
			if verdict := service.Send(frame, time.Unix(now, 0)); verdict.Drop != bond.L2Forward {
				t.Errorf("gateway LLDP-MED frame rejected by fabric: %+v", verdict)
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer gateway.Close()
	select {
	case received := <-session.Receive():
		if received.IngressPort != service.ID() || received.IngressIdentity != "gateway-vlan-23" {
			t.Fatalf("LLDP-MED ingress identity = port %d / %q, want service port %d / gateway-vlan-23", received.IngressPort, received.IngressIdentity, service.ID())
		}
		if len(received.Frame) < 14 || binary.BigEndian.Uint16(received.Frame[12:14]) != 0x88cc {
			t.Fatalf("received frame is not untagged LLDP: %x", received.Frame)
		}
		assertSegmentLLDPMEDPolicy(t, received.Frame, 0x01402f6e)
	case <-time.After(time.Second):
		t.Fatal("gateway LLDP-MED advertisement did not reach the session on VLAN 23")
	}
}

func assertSegmentLLDPMEDPolicy(t *testing.T, frame []byte, want uint32) {
	t.Helper()
	for offset := 14; offset+2 <= len(frame); {
		header := binary.BigEndian.Uint16(frame[offset : offset+2])
		typ, size := header>>9, int(header&0x1ff)
		offset += 2
		if size > len(frame)-offset {
			t.Fatalf("malformed LLDP TLV in frame %x", frame)
		}
		value := frame[offset : offset+size]
		offset += size
		if typ == 127 && len(value) == 8 && bytes.Equal(value[:4], []byte{0x00, 0x12, 0xbb, 2}) {
			if got := binary.BigEndian.Uint32(value[4:]); got != want {
				t.Fatalf("LLDP-MED network policy = %08x, want %08x", got, want)
			}
			return
		}
		if typ == 0 {
			break
		}
	}
	t.Fatalf("LLDP-MED network policy TLV not received: %x", frame)
}

func TestNamedSegmentFabricForwardsBetweenSessionPorts(t *testing.T) {
	fabric := NewNamedSegmentFabric("venue-a", bond.L2SwitchConfig{})
	left, err := fabric.Attach(bond.L2PortConfig{Name: "session-a"}, 4)
	if err != nil {
		t.Fatal(err)
	}
	right, err := fabric.Attach(bond.L2PortConfig{Name: "session-b"}, 4)
	if err != nil {
		t.Fatal(err)
	}
	frame := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2, 0, 0, 0, 0, 1, 0x88, 0xb5}
	verdict := left.Send(frame, time.Unix(1, 0))
	if verdict.Drop != bond.L2Forward {
		t.Fatalf("frame was not accepted: %+v", verdict)
	}
	select {
	case received := <-right.Receive():
		if string(received.Frame) != string(frame) {
			t.Fatalf("frame changed in fabric: got %x want %x", received.Frame, frame)
		}
		if received.IngressPort != left.ID() {
			t.Fatalf("ingress identity = %d, want %d", received.IngressPort, left.ID())
		}
		if received.IngressIdentity != "session-a" {
			t.Fatalf("ingress session identity = %q, want session-a", received.IngressIdentity)
		}
	case <-time.After(time.Second):
		t.Fatal("frame did not reach the other session port")
	}
	if got := fabric.Identity(); got != "venue-a" {
		t.Fatalf("segment identity = %q", got)
	}
	left.Close()
	right.Close()
}

func TestSegmentFabricRefreshesDHCPSourceBindingsByAuthenticatedPortAndVLAN(t *testing.T) {
	fabric := NewNamedSegmentFabric("guarded", bond.L2SwitchConfig{})
	guarded, err := fabric.AttachSession(bond.L2PortConfig{Name: "session-a", IPv4SourceGuard: true, IPv6SourceGuard: true, VLAN: bond.L2VLANPolicy{AllowedVLANs: []uint16{10, 20}}}, 8, false, false)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := fabric.AttachSession(bond.L2PortConfig{Name: "session-b", VLAN: bond.L2VLANPolicy{AllowedVLANs: []uint16{10, 20}}}, 8, false, false)
	if err != nil {
		t.Fatal(err)
	}
	clientMAC := [6]byte{2, 0, 0, 0, 0, 1}
	if err := fabric.ReplaceDHCPSourceBindings(map[string][]bond.L2SourceBinding{
		"session-a": {
			{VLAN: 10, IP: netip.MustParseAddr("10.0.0.10"), MAC: clientMAC},
			{VLAN: 10, IP: netip.MustParseAddr("2001:db8:10::10"), MAC: clientMAC},
		},
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if verdict := guarded.Send(segmentIPv4Frame(clientMAC, 10, "10.0.0.10"), now); verdict.Drop != bond.L2Forward {
		t.Fatalf("matching lease binding rejected: %+v", verdict)
	}
	<-peer.Receive()
	if verdict := guarded.Send(segmentIPv4Frame(clientMAC, 20, "10.0.0.10"), now); verdict.Drop != bond.L2DropSourceGuard {
		t.Fatalf("lease binding leaked across VLANs: %+v", verdict)
	}
	if verdict := guarded.Send(segmentIPv6Frame(clientMAC, 10, "2001:db8:10::10"), now); verdict.Drop != bond.L2Forward {
		t.Fatalf("matching DHCPv6 binding rejected: %+v", verdict)
	}
	<-peer.Receive()
	if verdict := guarded.Send(segmentIPv6Frame(clientMAC, 20, "2001:db8:10::10"), now); verdict.Drop != bond.L2DropSourceGuard {
		t.Fatalf("DHCPv6 binding leaked across VLANs: %+v", verdict)
	}
	spoof := [6]byte{2, 0, 0, 0, 0, 2}
	if verdict := guarded.Send(segmentIPv4Frame(spoof, 10, "10.0.0.10"), now); verdict.Drop != bond.L2DropSourceGuard {
		t.Fatalf("binding leaked across authenticated session ports: %+v", verdict)
	}
	if verdict := guarded.Send(segmentIPv6Frame(spoof, 10, "2001:db8:10::10"), now); verdict.Drop != bond.L2DropSourceGuard {
		t.Fatalf("DHCPv6 binding leaked across authenticated session ports: %+v", verdict)
	}
	if err := fabric.ReplaceDHCPSourceBindings(map[string][]bond.L2SourceBinding{}); err != nil {
		t.Fatal(err)
	}
	if verdict := guarded.Send(segmentIPv4Frame(clientMAC, 10, "10.0.0.10"), now); verdict.Drop != bond.L2DropSourceGuard {
		t.Fatalf("expired/removed DHCP binding remained authorized: %+v", verdict)
	}
	stats := fabric.Stats()
	guardDrops, ok := stats["source_guard_drops"].(map[string]uint64)
	if !ok || guardDrops["session-a"] != 5 {
		t.Fatalf("per-session source-guard drops = %#v, want session-a=5: %#v", stats["source_guard_drops"], stats)
	}
}

func segmentIPv6Frame(sourceMAC [6]byte, vlan uint16, sourceIP string) []byte {
	frame := make([]byte, 18+40)
	copy(frame[:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(frame[6:12], sourceMAC[:])
	binary.BigEndian.PutUint16(frame[12:14], 0x8100)
	binary.BigEndian.PutUint16(frame[14:16], vlan)
	binary.BigEndian.PutUint16(frame[16:18], 0x86dd)
	ip := frame[18:]
	ip[0], ip[6], ip[7] = 0x60, 59, 64
	parsed := netip.MustParseAddr(sourceIP).As16()
	copy(ip[8:24], parsed[:])
	copy(ip[24:40], netip.MustParseAddr("2001:db8:10::1").AsSlice())
	return frame
}

func TestDHCPv4LeaseFrameDetectionRequiresClientRequestPorts(t *testing.T) {
	clientMAC := [6]byte{2, 0, 0, 0, 0, 1}
	zero, broadcast := [4]byte{}, [4]byte{255, 255, 255, 255}
	if !isDHCPv4LeaseFrame(segmentIPv4UDPFrame(clientMAC, zero, broadcast, 68, 67)) {
		t.Fatal("DHCP client request was not recognized")
	}
	if isDHCPv4LeaseFrame(segmentIPv4UDPFrame(clientMAC, [4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1}, 1234, 80)) {
		t.Fatal("ordinary IPv4 traffic was classified as DHCP")
	}
}

func segmentIPv4Frame(sourceMAC [6]byte, vlan uint16, sourceIP string) []byte {
	frame := make([]byte, 18+28)
	copy(frame[:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(frame[6:12], sourceMAC[:])
	binary.BigEndian.PutUint16(frame[12:14], 0x8100)
	binary.BigEndian.PutUint16(frame[14:16], vlan)
	binary.BigEndian.PutUint16(frame[16:18], 0x0800)
	ip := frame[18:]
	ip[0], ip[8], ip[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	parsed := netip.MustParseAddr(sourceIP).As4()
	copy(ip[12:16], parsed[:])
	copy(ip[16:20], []byte{10, 0, 0, 1})
	binary.BigEndian.PutUint16(ip[20:22], 12345)
	binary.BigEndian.PutUint16(ip[22:24], 80)
	binary.BigEndian.PutUint16(ip[24:26], 8)
	return frame
}

func segmentIPv4UDPFrame(sourceMAC [6]byte, source, destination [4]byte, sourcePort, destinationPort uint16) []byte {
	frame := make([]byte, 14+28)
	copy(frame[:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(frame[6:12], sourceMAC[:])
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	ip := frame[14:]
	ip[0], ip[8], ip[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	copy(ip[12:16], source[:])
	copy(ip[16:20], destination[:])
	binary.BigEndian.PutUint16(ip[20:22], sourcePort)
	binary.BigEndian.PutUint16(ip[22:24], destinationPort)
	binary.BigEndian.PutUint16(ip[24:26], 8)
	return frame
}

func TestSegmentFabricMirrorsDynamicSessionAndServicePorts(t *testing.T) {
	fabric := NewNamedSegmentFabric("venue-mirror", bond.L2SwitchConfig{})
	sessionA, err := fabric.AttachSession(bond.L2PortConfig{Name: "session-a", VLAN: bond.L2VLANPolicy{AccessVLAN: 10}}, 8, true, true)
	if err != nil {
		t.Fatal(err)
	}
	sessionB, err := fabric.AttachSession(bond.L2PortConfig{Name: "session-b", VLAN: bond.L2VLANPolicy{AccessVLAN: 10}}, 8, false, false)
	if err != nil {
		t.Fatal(err)
	}
	service, err := fabric.AttachService(bond.L2PortConfig{Name: "gateway-vlan-10", VLAN: bond.L2VLANPolicy{AccessVLAN: 10}}, 8, false, false)
	if err != nil {
		t.Fatal(err)
	}
	monitor, err := fabric.AttachMonitor("monitor0", 8)
	if err != nil {
		t.Fatal(err)
	}

	broadcast := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0, 0, 0, 0, 0x31, 0x88, 0xb5}
	if verdict := sessionA.Send(broadcast, time.Unix(10, 0)); verdict.Drop != bond.L2Forward {
		t.Fatalf("session broadcast forwarding = %+v", verdict)
	}
	mirrored := waitSegmentFrame(t, monitor)
	if !bytes.Equal(mirrored.Frame, broadcast) || mirrored.IngressIdentity != "session-a" || mirrored.IngressPort != sessionA.ID() {
		t.Fatalf("ingress mirror lost frame or source identity: %+v", mirrored)
	}
	if delivery := waitSegmentFrame(t, sessionB); !bytes.Equal(delivery.Frame, broadcast) {
		t.Fatalf("broadcast changed for peer: %+v", delivery)
	}

	knownUnicast := []byte{0x02, 0, 0, 0, 0, 0x31, 0x02, 0, 0, 0, 0, 0x42, 0x88, 0xb5}
	if verdict := sessionB.Send(knownUnicast, time.Unix(10, 0)); verdict.Drop != bond.L2Forward {
		t.Fatalf("known unicast forwarding = %+v", verdict)
	}
	if delivery := waitSegmentFrame(t, sessionA); !bytes.Equal(delivery.Frame, knownUnicast) {
		t.Fatalf("known unicast changed for session: %+v", delivery)
	}
	if delivery := waitSegmentFrame(t, monitor); !bytes.Equal(delivery.Frame, knownUnicast) || delivery.IngressIdentity != "session-b" {
		t.Fatalf("egress mirror incorrect: %+v", delivery)
	}

	stats := fabric.Stats()
	if stats["mirrored_frames"] != uint64(2) || stats["mirror_queue_drops"] != uint64(0) {
		t.Fatalf("unexpected mirror counters: %#v", stats)
	}
	monitor.Close()
	service.Close()
	sessionA.Close()
	sessionB.Close()
}

func TestSegmentFabricForwardsJoinedMulticastOnlyToListenersAndRouter(t *testing.T) {
	fabric := NewNamedSegmentFabric("venue-multicast", bond.L2SwitchConfig{})
	listenerA, err := fabric.AttachSession(bond.L2PortConfig{Name: "listener-a", VLAN: bond.L2VLANPolicy{AccessVLAN: 10}}, 8, false, false)
	if err != nil {
		t.Fatal(err)
	}
	listenerB, err := fabric.AttachSession(bond.L2PortConfig{Name: "listener-b", VLAN: bond.L2VLANPolicy{AccessVLAN: 10}}, 8, false, false)
	if err != nil {
		t.Fatal(err)
	}
	nonmember, err := fabric.AttachSession(bond.L2PortConfig{Name: "nonmember", VLAN: bond.L2VLANPolicy{AccessVLAN: 10}}, 8, false, false)
	if err != nil {
		t.Fatal(err)
	}
	router, err := fabric.AttachService(bond.L2PortConfig{
		Name: "gateway", VLAN: bond.L2VLANPolicy{AccessVLAN: 10}, MulticastRouter: true, MulticastQuerier: true,
		QuerierMAC: [6]byte{0x02, 0x47, 0x42, 0, 0, 1}, QuerierIPv4: [4]byte{10, 0, 0, 1},
	}, 8, false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer listenerA.Close()
	defer listenerB.Close()
	defer nonmember.Close()
	defer router.Close()

	now := time.Unix(100, 0)
	if dropped := fabric.EmitMulticastQueries(now); dropped != 0 {
		t.Fatalf("initial querier query was dropped: %d", dropped)
	}
	for _, port := range []*SegmentPort{listenerA, listenerB, nonmember} {
		if delivery := waitSegmentFrame(t, port); !isIGMPQueryFrame(delivery.Frame) {
			t.Fatalf("expected initial IGMP query on %s, got %x", port.cfgName, delivery.Frame)
		}
	}
	group := [4]byte{239, 1, 2, 3}
	if verdict := listenerA.Send(testIGMPv2Report(0x41, group), now.Add(time.Millisecond)); verdict.Drop != bond.L2Forward {
		t.Fatalf("listener A membership report failed: %+v", verdict)
	}
	if verdict := listenerB.Send(testIGMPv2Report(0x42, group), now.Add(2*time.Millisecond)); verdict.Drop != bond.L2Forward {
		t.Fatalf("listener B membership report failed: %+v", verdict)
	}
	if got := fabric.SwitchStats().MulticastMembers; got != 2 {
		t.Fatalf("fabric learned %d listeners, want 2", got)
	}
	for i := 0; i < 2; i++ {
		if delivery := waitSegmentFrame(t, router); !isIGMPReportFrame(delivery.Frame) {
			t.Fatalf("router port did not receive a membership report: %x", delivery.Frame)
		}
	}
	frame := testIPv4MulticastFrame(0x41, group)
	if verdict := listenerA.Send(frame, now.Add(3*time.Millisecond)); verdict.Drop != bond.L2Forward {
		t.Fatalf("listener multicast send failed: %+v", verdict)
	}
	if got := waitSegmentFrame(t, listenerB); !bytes.Equal(got.Frame, frame) || got.IngressIdentity != "listener-a" {
		t.Fatalf("multicast did not cross between listeners: %+v", got)
	}
	if got := waitSegmentFrame(t, router); !bytes.Equal(got.Frame, frame) {
		t.Fatalf("multicast was not delivered to router port: %+v", got)
	}
	select {
	case got := <-nonmember.Receive():
		t.Fatalf("nonmember received snooped multicast: %+v", got)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestSegmentFabricMVRRetagsMulticastAcrossTrunkVLANs(t *testing.T) {
	mvr := bond.L2MVRConfig{MulticastVLAN: 100, Groups: []bond.L2MVRGroup{{Group: netip.MustParseAddr("239.3.3.3"), ReceiverVLAN: 10}}}
	fabric := NewNamedSegmentFabric("venue-mvr", bond.L2SwitchConfig{MVR: &mvr})
	source, err := fabric.AttachService(bond.L2PortConfig{
		Name: "multicast-uplink", VLAN: bond.L2VLANPolicy{AllowedVLANs: []uint16{100}}, MulticastRouter: true,
	}, 8, false, false)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := fabric.AttachSession(bond.L2PortConfig{
		Name: "listener-trunk", VLAN: bond.L2VLANPolicy{AllowedVLANs: []uint16{10}},
	}, 8, false, false)
	if err != nil {
		t.Fatal(err)
	}
	nonmember, err := fabric.AttachSession(bond.L2PortConfig{Name: "same-vlan-nonmember", VLAN: bond.L2VLANPolicy{AccessVLAN: 10}}, 8, false, false)
	if err != nil {
		t.Fatal(err)
	}
	otherVLAN, err := fabric.AttachSession(bond.L2PortConfig{Name: "other-vlan", VLAN: bond.L2VLANPolicy{AccessVLAN: 20}}, 8, false, false)
	if err != nil {
		t.Fatal(err)
	}
	querier, err := fabric.AttachService(bond.L2PortConfig{
		Name: "receiver-vlan-router", VLAN: bond.L2VLANPolicy{AccessVLAN: 10}, MulticastRouter: true, MulticastQuerier: true,
		QuerierMAC: [6]byte{0x02, 0x47, 0x42, 0, 0, 2}, QuerierIPv4: [4]byte{10, 0, 0, 2},
	}, 8, false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	defer receiver.Close()
	defer nonmember.Close()
	defer otherVLAN.Close()
	defer querier.Close()

	now := time.Unix(200, 0)
	group := [4]byte{239, 3, 3, 3}
	if dropped := fabric.EmitMulticastQueries(now); dropped != 0 {
		t.Fatalf("receiver-VLAN querier query dropped: %d", dropped)
	}
	if delivery := waitSegmentFrame(t, receiver); !isIGMPQueryFrame(delivery.Frame) {
		t.Fatalf("receiver trunk did not receive the VLAN 10 query: %x", delivery.Frame)
	}
	if delivery := waitSegmentFrame(t, nonmember); !isIGMPQueryFrame(delivery.Frame) {
		t.Fatalf("same-VLAN nonmember did not receive the VLAN 10 query: %x", delivery.Frame)
	}
	report := withSingleVLANTag(testIGMPv2Report(0x51, group), 10)
	if verdict := receiver.Send(report, now); verdict.Drop != bond.L2Forward {
		t.Fatalf("receiver membership report rejected: %+v", verdict)
	}
	routerReport := waitSegmentFrame(t, source)
	info, err := bond.ParseFrame(routerReport.Frame)
	if err != nil || info.VLAN != 100 {
		t.Fatalf("receiver report was not retagged for source VLAN 100: info=%+v err=%v frame=%x", info, err, routerReport.Frame)
	}

	multicast := withSingleVLANTag(testIPv4MulticastFrame(0x52, group), 100)
	if verdict := source.Send(multicast, now.Add(time.Second)); verdict.Drop != bond.L2Forward {
		t.Fatalf("source multicast rejected: %+v", verdict)
	}
	forwarded := waitSegmentFrame(t, receiver)
	info, err = bond.ParseFrame(forwarded.Frame)
	if err != nil || info.VLAN != 10 {
		t.Fatalf("multicast trunk egress was not rewritten to receiver VLAN 10: info=%+v err=%v frame=%x", info, err, forwarded.Frame)
	}
	select {
	case got := <-nonmember.Receive():
		t.Fatalf("MVR multicast reached a nonmember on receiver VLAN: %+v", got)
	case got := <-otherVLAN.Receive():
		t.Fatalf("MVR multicast escaped to another VLAN: %+v", got)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestSegmentFabricQinQIsolatesCompositeVLANsAcrossSessions(t *testing.T) {
	fabric := NewNamedSegmentFabric("venue-qinq", bond.L2SwitchConfig{})
	customerA, err := fabric.AttachSession(bond.L2PortConfig{
		Name: "service-10-customer-20", VLAN: bond.L2VLANPolicy{ServiceVLAN: 10, CustomerVLAN: 20},
	}, 8, false, false)
	if err != nil {
		t.Fatal(err)
	}
	trunk, err := fabric.AttachSession(bond.L2PortConfig{
		Name: "service-trunk", VLAN: bond.L2VLANPolicy{ServiceVLAN: 10, AllowedCustomerVLANs: []uint16{20, 30}},
	}, 8, false, false)
	if err != nil {
		t.Fatal(err)
	}
	customerB, err := fabric.AttachSession(bond.L2PortConfig{
		Name: "service-10-customer-30", VLAN: bond.L2VLANPolicy{ServiceVLAN: 10, CustomerVLAN: 30},
	}, 8, false, false)
	if err != nil {
		t.Fatal(err)
	}
	otherService, err := fabric.AttachSession(bond.L2PortConfig{
		Name: "service-11-customer-20", VLAN: bond.L2VLANPolicy{ServiceVLAN: 11, CustomerVLAN: 20},
	}, 8, false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer customerA.Close()
	defer trunk.Close()
	defer customerB.Close()
	defer otherService.Close()

	now := time.Unix(300, 0)
	broadcast := [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	frame := appendEthernetFrame(broadcast, [6]byte{0x02, 0, 0, 0, 0, 0x21}, 0x88b5, []byte{1, 2, 3})
	if verdict := customerA.Send(frame, now); verdict.Drop != bond.L2Forward {
		t.Fatalf("customer access ingress rejected: %+v", verdict)
	}
	trunkFrame := waitSegmentFrame(t, trunk).Frame
	info, err := bond.ParseFrame(trunkFrame)
	if err != nil || info.VLANDepth != 2 || info.VLAN != 10 || info.InnerVLAN != 20 || binary.BigEndian.Uint16(trunkFrame[12:14]) != 0x88a8 {
		t.Fatalf("access-to-trunk Q-in-Q tags incorrect: info=%+v err=%v frame=%x", info, err, trunkFrame)
	}
	for _, port := range []*SegmentPort{customerB, otherService} {
		select {
		case got := <-port.Receive():
			t.Fatalf("composite VLAN broadcast leaked to %s: %+v", port.cfgName, got)
		case <-time.After(20 * time.Millisecond):
		}
	}

	trunkInput := appendEthernetFrame(broadcast, [6]byte{0x02, 0, 0, 0, 0, 0x23}, 0x88b5, []byte{7, 8, 9})
	stacked := withQinQTags(trunkInput, 10, 20)
	if verdict := trunk.Send(stacked, now.Add(time.Second)); verdict.Drop != bond.L2Forward {
		t.Fatalf("stacked-tag trunk ingress rejected: %+v", verdict)
	}
	accessFrame := waitSegmentFrame(t, customerA).Frame
	if len(accessFrame) < 14 || binary.BigEndian.Uint16(accessFrame[12:14]) != 0x88b5 {
		t.Fatalf("trunk-to-access egress retained a VLAN tag: %x", accessFrame)
	}
	if !bytes.Equal(accessFrame[14:], trunkInput[14:]) {
		t.Fatalf("trunk-to-access payload changed: got=%x want=%x", accessFrame, trunkInput)
	}

	otherFrame := appendEthernetFrame(broadcast, [6]byte{0x02, 0, 0, 0, 0, 0x22}, 0x88b5, []byte{4, 5, 6})
	if verdict := otherService.Send(otherFrame, now.Add(2*time.Second)); verdict.Drop != bond.L2DropVLAN || len(verdict.Out) != 0 {
		t.Fatalf("same customer VID on a different service VLAN crossed the fabric: %+v", verdict)
	}
}

func withSingleVLANTag(frame []byte, vlan uint16) []byte {
	tagged := make([]byte, len(frame)+4)
	copy(tagged[:12], frame[:12])
	binary.BigEndian.PutUint16(tagged[12:14], 0x8100)
	binary.BigEndian.PutUint16(tagged[14:16], vlan)
	copy(tagged[16:18], frame[12:14])
	copy(tagged[18:], frame[14:])
	return tagged
}

func withQinQTags(frame []byte, serviceVLAN, customerVLAN uint16) []byte {
	tagged := make([]byte, len(frame)+8)
	copy(tagged[:12], frame[:12])
	binary.BigEndian.PutUint16(tagged[12:14], 0x88a8)
	binary.BigEndian.PutUint16(tagged[14:16], serviceVLAN)
	binary.BigEndian.PutUint16(tagged[16:18], 0x8100)
	binary.BigEndian.PutUint16(tagged[18:20], customerVLAN)
	copy(tagged[20:22], frame[12:14])
	copy(tagged[22:], frame[14:])
	return tagged
}

func waitSegmentFrame(t *testing.T, port *SegmentPort) SegmentFrame {
	t.Helper()
	select {
	case delivery := <-port.Receive():
		return delivery
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for segment frame")
		return SegmentFrame{}
	}
}

func testIGMPv2Report(source byte, group [4]byte) []byte {
	dstMAC := [6]byte{0x01, 0x00, 0x5e, group[1] & 0x7f, group[2], group[3]}
	ip := make([]byte, 28)
	ip[0], ip[8], ip[9] = 0x45, 1, 2
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	ip[12], ip[15] = 10, source
	copy(ip[16:20], group[:])
	ip[20] = 0x16
	copy(ip[24:28], group[:])
	return appendEthernetFrame(dstMAC, [6]byte{0x02, 0, 0, 0, 0, source}, 0x0800, ip)
}

func testIPv4MulticastFrame(source byte, group [4]byte) []byte {
	dstMAC := [6]byte{0x01, 0x00, 0x5e, group[1] & 0x7f, group[2], group[3]}
	ip := make([]byte, 20)
	ip[0], ip[8], ip[9] = 0x45, 1, 1
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	ip[12], ip[15] = 10, source
	copy(ip[16:20], group[:])
	return appendEthernetFrame(dstMAC, [6]byte{0x02, 0, 0, 0, 0, source}, 0x0800, ip)
}

func appendEthernetFrame(dst, src [6]byte, etherType uint16, payload []byte) []byte {
	frame := append([]byte{}, dst[:]...)
	frame = append(frame, src[:]...)
	frame = append(frame, byte(etherType>>8), byte(etherType))
	return append(frame, payload...)
}

func isIGMPQueryFrame(frame []byte) bool {
	info, err := bond.ParseFrame(frame)
	return err == nil && info.IGMPQuery
}

func isIGMPReportFrame(frame []byte) bool {
	info, err := bond.ParseFrame(frame)
	return err == nil && info.IGMPType == 0x16
}

func testMLDv1Report(source byte, group [16]byte) []byte {
	mac := [6]byte{0x33, 0x33, group[12], group[13], group[14], group[15]}
	ip := make([]byte, 40+8+24)
	ip[0], ip[6], ip[7] = 0x60, 0, 1
	binary.BigEndian.PutUint16(ip[4:6], 8+24)
	ip[8], ip[9] = 0xfe, 2
	ip[23] = source
	copy(ip[24:40], group[:])
	copy(ip[40:48], []byte{58, 0, 5, 2, 0, 0, 1, 0})
	ip[48] = 131
	copy(ip[56:72], group[:])
	return appendEthernetFrame(mac, [6]byte{0x02, 0, 0, 0, 0, source}, 0x86dd, ip)
}

func testIPv6MulticastFrame(source byte, group [16]byte) []byte {
	dst := [6]byte{0x33, 0x33, group[12], group[13], group[14], group[15]}
	ip := make([]byte, 40)
	ip[0], ip[6], ip[7] = 0x60, 59, 1
	ip[8], ip[9] = 0xfe, 2
	ip[23] = source
	copy(ip[24:40], group[:])
	return appendEthernetFrame(dst, [6]byte{0x02, 0, 0, 0, 0, source}, 0x86dd, ip)
}

func isMLDReportFrame(frame []byte) bool {
	info, err := bond.ParseFrame(frame)
	return err == nil && len(info.MLDJoins) > 0
}

func isMLDQueryFrame(frame []byte) bool {
	info, err := bond.ParseFrame(frame)
	return err == nil && info.MLDQuery
}
