//go:build linux

package edge

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Dankular/GameBond.Core/bond"
	"github.com/Dankular/GameBond.Server/l2gw"
)

func TestSegmentSocketCarriesLLDPMEDAdvertisementOnlyWithinItsVLAN(t *testing.T) {
	fabric := NewNamedSegmentFabric("venue-lldp", bond.L2SwitchConfig{})
	authorizations := map[string]SegmentSocketAuthorization{
		"session-a": {Token: bytesOf(0x71, 32), Port: bond.L2PortConfig{VLAN: bond.L2VLANPolicy{AccessVLAN: 23}}},
		"session-b": {Token: bytesOf(0x72, 32), Port: bond.L2PortConfig{VLAN: bond.L2VLANPolicy{AccessVLAN: 23}}},
		"session-c": {Token: bytesOf(0x73, 32), Port: bond.L2PortConfig{VLAN: bond.L2VLANPolicy{AccessVLAN: 24}}},
	}
	socketPath := filepath.Join(os.TempDir(), fmt.Sprintf("gb-lldp-%d-%d.sock", os.Getpid(), time.Now().UnixNano()))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServeSegmentSocket(ctx, socketPath, fabric, authorizations) }()
	waitForSocket(t, socketPath)
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("segment socket server: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("segment socket server did not stop")
		}
	}()

	ports := make(map[string]*SegmentSocketPort, len(authorizations))
	for name, authorization := range authorizations {
		port, err := DialSegmentSocket(context.Background(), socketPath, "venue-lldp", name, authorization.Token, 4)
		if err != nil {
			for _, opened := range ports {
				opened.Close()
			}
			t.Fatal(err)
		}
		ports[name] = port
		defer port.Close()
	}
	service, err := fabric.AttachService(bond.L2PortConfig{
		Name: "gateway-vlan-23", VLAN: bond.L2VLANPolicy{AccessVLAN: 23},
	}, 4, false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	var initialDrop bond.L2Drop
	gateway, err := l2gw.New(l2gw.Config{
		Address:         netip.MustParsePrefix("10.23.0.1/24"),
		DHCPStart:       netip.MustParseAddr("10.23.0.100"),
		DHCPEnd:         netip.MustParseAddr("10.23.0.110"),
		LLDPMEDPolicy:   &l2gw.LLDPMEDNetworkPolicy{ApplicationType: 1, VLANID: 23, Tagged: true, L2Priority: 5, DSCP: 46},
		LLDPMEDInterval: time.Hour,
		Out: func(frame []byte) {
			initialDrop = service.Send(frame, time.Now()).Drop
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer gateway.Close()
	if initialDrop != bond.L2Forward {
		t.Fatalf("gateway LLDP-MED advertisement rejected by broker: %s", initialDrop)
	}
	for _, name := range []string{"session-a", "session-b"} {
		select {
		case delivery := <-ports[name].Receive():
			if delivery.IngressIdentity != "gateway-vlan-23" || delivery.IngressPort != service.ID() {
				t.Fatalf("LLDP-MED broker ingress identity = %q/%d, want gateway-vlan-23/%d", delivery.IngressIdentity, delivery.IngressPort, service.ID())
			}
			assertSegmentLLDPMEDPolicy(t, delivery.Frame, 0x01402f6e)
		case <-time.After(time.Second):
			t.Fatalf("LLDP-MED advertisement did not reach %s over the socket", name)
		}
	}
	select {
	case delivery := <-ports["session-c"].Receive():
		t.Fatalf("VLAN 24 received VLAN 23 LLDP-MED advertisement: %+v", delivery)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestSegmentSocketReturnsTrackedMDNSUnicastAnswerToOrigin(t *testing.T) {
	fabric := NewNamedSegmentFabric("mdns-unicast", bond.L2SwitchConfig{})
	const (
		clientName    = "client-vlan-10"
		responderName = "responder-vlan-20"
	)
	authorizations := map[string]SegmentSocketAuthorization{
		clientName:    {Token: bytesOf(0x81, 32), Port: bond.L2PortConfig{VLAN: bond.L2VLANPolicy{AccessVLAN: 10}}},
		responderName: {Token: bytesOf(0x82, 32), Port: bond.L2PortConfig{VLAN: bond.L2VLANPolicy{AccessVLAN: 20}}},
	}
	socketPath := filepath.Join(os.TempDir(), fmt.Sprintf("gb-mdns-%d-%d.sock", os.Getpid(), time.Now().UnixNano()))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServeSegmentSocket(ctx, socketPath, fabric, authorizations) }()
	waitForSocket(t, socketPath)
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("segment socket server: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("segment socket server did not stop")
		}
	}()
	client, err := DialSegmentSocket(context.Background(), socketPath, "mdns-unicast", clientName, authorizations[clientName].Token, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	responder, err := DialSegmentSocket(context.Background(), socketPath, "mdns-unicast", responderName, authorizations[responderName].Token, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer responder.Close()
	sourceGateway, err := fabric.AttachService(bond.L2PortConfig{Name: "gateway-10", VLAN: bond.L2VLANPolicy{AccessVLAN: 10}}, 8, false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer sourceGateway.Close()
	targetGateway, err := fabric.AttachService(bond.L2PortConfig{Name: "gateway-20", VLAN: bond.L2VLANPolicy{AccessVLAN: 20}}, 8, false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer targetGateway.Close()
	now := time.Now()
	query := mdnsIPv4QueryFrame(false)
	binary.BigEndian.PutUint16(query[34:36], 5354)
	binary.BigEndian.PutUint16(query[42:44], 0x3456)
	binary.BigEndian.PutUint16(query[40:42], 0)
	binary.BigEndian.PutUint16(query[40:42], internetChecksumValue(ipv4UDPPseudoHeader(query[26:34], query[34:])))
	if verdict := client.Send(query, now); verdict.Drop != bond.L2Forward {
		t.Fatalf("origin query rejected by broker: %+v", verdict)
	}
	select {
	case delivery := <-sourceGateway.Receive():
		if delivery.IngressIdentity != clientName {
			t.Fatalf("source gateway saw query identity %q, want %q", delivery.IngressIdentity, clientName)
		}
	case <-time.After(time.Second):
		t.Fatal("origin query did not reach the source gateway")
	}
	relayQuery, ok := prepareMDNSRelayFrame(query)
	if !ok {
		t.Fatal("origin query could not be prepared for reflection")
	}
	tracker := newMDNSUnicastTracker()
	if !tracker.rememberQuery(query, 10, 20, now) {
		t.Fatal("origin query return path was not recorded")
	}
	if verdict := targetGateway.Send(relayQuery, now); verdict.Drop != bond.L2Forward {
		t.Fatalf("reflected query rejected by target gateway: %+v", verdict)
	}
	select {
	case delivery := <-responder.Receive():
		if delivery.IngressIdentity != "gateway-20" || !isMDNSRelayFrame(delivery.Frame) {
			t.Fatalf("target responder got an unexpected reflected query: %+v", delivery)
		}
	case <-time.After(time.Second):
		t.Fatal("reflected query did not reach target responder over the socket")
	}
	response := mdnsIPv4UnicastResponseFrame([6]byte{2, 0xaa, 0xbb, 0xcc, 0xdd, 2}, netip.MustParseAddr("169.254.1.2"), 5354, 0x3456)
	if verdict := responder.Send(response, now.Add(time.Second)); verdict.Drop != bond.L2Forward {
		t.Fatalf("target response rejected by broker: %+v", verdict)
	}
	select {
	case incoming := <-targetGateway.Receive():
		if incoming.IngressIdentity != responderName {
			t.Fatalf("target gateway saw response identity %q, want %q", incoming.IngressIdentity, responderName)
		}
		deliveries, matched := tracker.reflectResponse(incoming.Frame, 20, now.Add(time.Second))
		if !matched || len(deliveries) != 1 || deliveries[0].vlan != 10 {
			t.Fatalf("target response did not map to the authorized source VLAN: matched=%v deliveries=%+v", matched, deliveries)
		}
		if verdict := sourceGateway.Send(deliveries[0].frame, now.Add(time.Second)); verdict.Drop != bond.L2Forward {
			t.Fatalf("returned answer rejected by source gateway: %+v", verdict)
		}
	case <-time.After(time.Second):
		t.Fatal("target response did not reach its gateway through the broker")
	}
	select {
	case delivery := <-client.Receive():
		if delivery.IngressIdentity != "gateway-10" || delivery.IngressPort != sourceGateway.ID() || !bytes.Equal(delivery.Frame[:6], query[6:12]) || !bytes.Equal(delivery.Frame[6:12], mdnsRelayMAC[:]) {
			t.Fatalf("unicast response lost its origin or gateway identity: %+v", delivery)
		}
	case <-time.After(time.Second):
		t.Fatal("unicast answer did not return to the querying session over the socket")
	}
}

func TestSegmentSocketAuthenticatesPortsAndPreservesIngressIdentity(t *testing.T) {
	fabric := NewNamedSegmentFabric("venue-a", bond.L2SwitchConfig{})
	auth := map[string]SegmentSocketAuthorization{
		"session-a":  {Token: bytesOf(0x11, 32), Port: bond.L2PortConfig{VLAN: bond.L2VLANPolicy{AccessVLAN: 10}}},
		"session-b":  {Token: bytesOf(0x22, 32), Port: bond.L2PortConfig{VLAN: bond.L2VLANPolicy{AccessVLAN: 10}}},
		"session-c":  {Token: bytesOf(0x33, 32), Port: bond.L2PortConfig{VLAN: bond.L2VLANPolicy{AccessVLAN: 20}}},
		"session-d":  {Token: bytesOf(0x44, 32), Port: bond.L2PortConfig{VLAN: bond.L2VLANPolicy{AccessVLAN: 10}}},
		"qinq-a":     {Token: bytesOf(0x55, 32), Port: bond.L2PortConfig{VLAN: bond.L2VLANPolicy{ServiceVLAN: 100, CustomerVLAN: 10}}},
		"qinq-trunk": {Token: bytesOf(0x66, 32), Port: bond.L2PortConfig{VLAN: bond.L2VLANPolicy{ServiceVLAN: 100, AllowedCustomerVLANs: []uint16{10, 20}}}},
		"qinq-b":     {Token: bytesOf(0x77, 32), Port: bond.L2PortConfig{VLAN: bond.L2VLANPolicy{ServiceVLAN: 100, CustomerVLAN: 20}}},
	}
	socketPath := filepath.Join(os.TempDir(), fmt.Sprintf("gb-%d-%d.sock", os.Getpid(), time.Now().UnixNano()))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServeSegmentSocket(ctx, socketPath, fabric, auth) }()
	waitForSocket(t, socketPath)
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("segment socket server: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("segment socket server did not stop")
		}
	}()

	if info, err := os.Stat(socketPath); err != nil || runtime.GOOS == "linux" && info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode = %v, err=%v; want 0600", info, err)
	}
	a, err := DialSegmentSocket(context.Background(), socketPath, "venue-a", "session-a", auth["session-a"].Token, 8)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DialSegmentSocket(context.Background(), socketPath, "venue-a", "session-b", auth["session-b"].Token, 8)
	if err != nil {
		a.Close()
		t.Fatal(err)
	}
	c, err := DialSegmentSocket(context.Background(), socketPath, "venue-a", "session-c", auth["session-c"].Token, 8)
	if err != nil {
		a.Close()
		b.Close()
		t.Fatal(err)
	}
	defer b.Close()
	defer c.Close()
	if cap(a.out) != 8 || cap(a.in) != 8 {
		t.Fatalf("remote queues are not bounded to authorization depth: out=%d in=%d", cap(a.out), cap(a.in))
	}

	frame := testBroadcastFrame(0x41)
	if verdict := a.Send(frame, time.Now()); verdict.Drop != bond.L2Forward {
		t.Fatalf("authorized send rejected: %+v", verdict)
	}
	select {
	case delivery := <-b.Receive():
		if delivery.IngressIdentity != "session-a" || delivery.IngressPort != a.ID() {
			t.Fatalf("broker did not derive ingress identity: %+v want port %d", delivery, a.ID())
		}
		if string(delivery.Frame) != string(frame) {
			t.Fatalf("frame changed: got %x want %x", delivery.Frame, frame)
		}
	case <-time.After(time.Second):
		t.Fatal("same-VLAN peer did not receive frame")
	}
	select {
	case delivery := <-c.Receive():
		t.Fatalf("VLAN 20 port received VLAN 10 broadcast: %+v", delivery)
	case <-time.After(50 * time.Millisecond):
	}

	d, err := DialSegmentSocket(context.Background(), socketPath, "venue-a", "session-d", auth["session-d"].Token, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	querierMAC := [6]byte{0x02, 0x47, 0x42, 0, 0, 1}
	querierIPv6 := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	router, err := fabric.AttachService(bond.L2PortConfig{
		Name: "gateway-vlan-10", VLAN: bond.L2VLANPolicy{AccessVLAN: 10}, MulticastRouter: true, MulticastQuerier: true,
		QuerierMAC: querierMAC, QuerierIPv4: [4]byte{10, 0, 0, 1}, QuerierIPv6: querierIPv6,
	}, 8, false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	if dropped := fabric.EmitMulticastQueries(time.Now()); dropped != 0 {
		t.Fatalf("querier could not emit the initial group query: %d", dropped)
	}
	for _, port := range []*SegmentSocketPort{a, b, d} {
		gotIGMP, gotMLD := false, false
		for i := 0; i < 2; i++ {
			select {
			case delivery := <-port.Receive():
				if delivery.IngressIdentity != "gateway-vlan-10" {
					t.Fatalf("querier frame lost its router ingress identity: %+v", delivery)
				}
				gotIGMP = gotIGMP || isIGMPQueryFrame(delivery.Frame)
				gotMLD = gotMLD || isMLDQueryFrame(delivery.Frame)
			case <-time.After(time.Second):
				t.Fatal("session did not receive both IGMP and MLD queries over the socket")
			}
		}
		if !gotIGMP || !gotMLD {
			t.Fatalf("session query families: IGMP=%v MLD=%v", gotIGMP, gotMLD)
		}
	}
	group := [4]byte{239, 1, 2, 3}
	if verdict := a.Send(testIGMPv2Report(0x41, group), time.Now()); verdict.Drop != bond.L2Forward {
		t.Fatalf("session A membership report failed: %+v", verdict)
	}
	if verdict := b.Send(testIGMPv2Report(0x42, group), time.Now()); verdict.Drop != bond.L2Forward {
		t.Fatalf("session B membership report failed: %+v", verdict)
	}
	waitFor(t, time.Second, func() bool { return fabric.SwitchStats().MulticastMembers == 2 })
	for i := 0; i < 2; i++ {
		select {
		case delivery := <-router.Receive():
			if !isIGMPReportFrame(delivery.Frame) || (delivery.IngressIdentity != "session-a" && delivery.IngressIdentity != "session-b") {
				t.Fatalf("gateway did not receive the authenticated session report: %+v", delivery)
			}
		case <-time.After(time.Second):
			t.Fatal("gateway did not receive both session membership reports")
		}
	}
	multicast := testIPv4MulticastFrame(0x41, group)
	if verdict := a.Send(multicast, time.Now()); verdict.Drop != bond.L2Forward {
		t.Fatalf("session multicast send failed: %+v", verdict)
	}
	select {
	case delivery := <-b.Receive():
		if !bytes.Equal(delivery.Frame, multicast) || delivery.IngressIdentity != "session-a" || delivery.IngressPort != a.ID() {
			t.Fatalf("listener-to-listener multicast lost its frame or ingress identity: %+v", delivery)
		}
	case <-time.After(time.Second):
		t.Fatal("joined session B did not receive session A multicast over the socket")
	}
	select {
	case delivery := <-router.Receive():
		if !bytes.Equal(delivery.Frame, multicast) || delivery.IngressIdentity != "session-a" {
			t.Fatalf("router port received unexpected multicast delivery: %+v", delivery)
		}
	case <-time.After(time.Second):
		t.Fatal("multicast did not reach the VLAN router port")
	}
	for _, port := range []*SegmentSocketPort{a, d, c} {
		select {
		case delivery := <-port.Receive():
			t.Fatalf("nonlistener or ingress port received snooped multicast: %+v", delivery)
		case <-time.After(30 * time.Millisecond):
		}
	}

	group6 := [16]byte{0xff, 0x3e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78}
	for _, item := range []struct {
		port   *SegmentSocketPort
		source byte
	}{{a, 0x41}, {b, 0x42}} {
		if verdict := item.port.Send(testMLDv1Report(item.source, group6), time.Now()); verdict.Drop != bond.L2Forward {
			t.Fatalf("session MLD membership report failed: %+v", verdict)
		}
	}
	waitFor(t, time.Second, func() bool { return fabric.SwitchStats().MulticastMembers == 4 })
	for i := 0; i < 2; i++ {
		select {
		case delivery := <-router.Receive():
			if !isMLDReportFrame(delivery.Frame) || (delivery.IngressIdentity != "session-a" && delivery.IngressIdentity != "session-b") {
				t.Fatalf("gateway did not receive the authenticated MLD report: %+v", delivery)
			}
		case <-time.After(time.Second):
			t.Fatal("gateway did not receive both session MLD membership reports")
		}
	}
	// Reports may themselves be forwarded while the fabric processes membership
	// changes. Drain those control frames so the following assertions cover data.
	for _, port := range []*SegmentSocketPort{a, b, c, d} {
		drainSegmentSocketFrames(port)
	}
	multicast6 := testIPv6MulticastFrame(0x41, group6)
	if verdict := a.Send(multicast6, time.Now()); verdict.Drop != bond.L2Forward {
		t.Fatalf("session IPv6 multicast send failed: %+v", verdict)
	}
	select {
	case delivery := <-b.Receive():
		if !bytes.Equal(delivery.Frame, multicast6) || delivery.IngressIdentity != "session-a" || delivery.IngressPort != a.ID() {
			t.Fatalf("listener-to-listener IPv6 multicast lost frame or ingress identity: %+v", delivery)
		}
	case <-time.After(time.Second):
		t.Fatal("joined session B did not receive IPv6 multicast over the socket")
	}
	select {
	case delivery := <-router.Receive():
		if !bytes.Equal(delivery.Frame, multicast6) || delivery.IngressIdentity != "session-a" {
			t.Fatalf("router port received unexpected IPv6 multicast delivery: %+v", delivery)
		}
	case <-time.After(time.Second):
		t.Fatal("IPv6 multicast did not reach the VLAN router port")
	}
	for _, port := range []*SegmentSocketPort{a, d, c} {
		select {
		case delivery := <-port.Receive():
			t.Fatalf("nonlistener or ingress port received snooped IPv6 multicast: %+v", delivery)
		case <-time.After(30 * time.Millisecond):
		}
	}

	qinqA, err := DialSegmentSocket(context.Background(), socketPath, "venue-a", "qinq-a", auth["qinq-a"].Token, 8)
	if err != nil {
		t.Fatal(err)
	}
	qinqTrunk, err := DialSegmentSocket(context.Background(), socketPath, "venue-a", "qinq-trunk", auth["qinq-trunk"].Token, 8)
	if err != nil {
		qinqA.Close()
		t.Fatal(err)
	}
	qinqB, err := DialSegmentSocket(context.Background(), socketPath, "venue-a", "qinq-b", auth["qinq-b"].Token, 8)
	if err != nil {
		qinqA.Close()
		qinqTrunk.Close()
		t.Fatal(err)
	}
	defer qinqA.Close()
	defer qinqTrunk.Close()
	defer qinqB.Close()

	qinqFrameA := testBroadcastFrame(0x61)
	if verdict := qinqA.Send(qinqFrameA, time.Now()); verdict.Drop != bond.L2Forward {
		t.Fatalf("Q-in-Q customer access send failed: %+v", verdict)
	}
	qinqDelivery := receiveSegmentSocketFrame(t, qinqTrunk)
	qinqInfo, err := bond.ParseFrame(qinqDelivery.Frame)
	if err != nil || qinqInfo.VLANDepth != 2 || qinqInfo.VLAN != 100 || qinqInfo.InnerVLAN != 10 || qinqDelivery.IngressIdentity != "qinq-a" {
		t.Fatalf("Q-in-Q socket egress tags or ingress identity incorrect: delivery=%+v info=%+v err=%v", qinqDelivery, qinqInfo, err)
	}
	assertNoSegmentSocketFrame(t, qinqB, "customer VLAN 20 received service 100/customer 10 traffic")

	qinqFrameTrunk := withQinQTags(testBroadcastFrame(0x62), 100, 10)
	if verdict := qinqTrunk.Send(qinqFrameTrunk, time.Now()); verdict.Drop != bond.L2Forward {
		t.Fatalf("stacked-tag socket ingress failed: %+v", verdict)
	}
	accessDelivery := receiveSegmentSocketFrame(t, qinqA)
	accessInfo, err := bond.ParseFrame(accessDelivery.Frame)
	if err != nil || accessInfo.VLANDepth != 0 || accessDelivery.IngressIdentity != "qinq-trunk" || !bytes.Equal(accessDelivery.Frame, testBroadcastFrame(0x62)) {
		t.Fatalf("Q-in-Q socket access egress did not strip tags or preserve identity: delivery=%+v info=%+v err=%v", accessDelivery, accessInfo, err)
	}
	assertNoSegmentSocketFrame(t, qinqB, "customer VLAN 20 received service 100/customer 10 trunk traffic")

	qinqFrameCustomer20 := withQinQTags(testBroadcastFrame(0x63), 100, 20)
	if verdict := qinqTrunk.Send(qinqFrameCustomer20, time.Now()); verdict.Drop != bond.L2Forward {
		t.Fatalf("second customer VLAN socket ingress failed: %+v", verdict)
	}
	customer20Delivery := receiveSegmentSocketFrame(t, qinqB)
	customer20Info, err := bond.ParseFrame(customer20Delivery.Frame)
	if err != nil || customer20Info.VLANDepth != 0 || customer20Delivery.IngressIdentity != "qinq-trunk" {
		t.Fatalf("service 100/customer 20 did not reach its customer access port: delivery=%+v info=%+v err=%v", customer20Delivery, customer20Info, err)
	}
	assertNoSegmentSocketFrame(t, qinqA, "customer VLAN 10 received service 100/customer 20 traffic")

	if verdict := a.Send(make([]byte, maxSegmentEthernetFrame+1), time.Now()); verdict.Drop != bond.L2DropMalform {
		t.Fatalf("oversized Ethernet frame was not rejected: %+v", verdict)
	}
	fdbBeforeClose := fabric.SwitchStats().FDBSize
	a.Close()
	waitFor(t, time.Second, func() bool { return fabric.SwitchStats().FDBSize < fdbBeforeClose })
}

func receiveSegmentSocketFrame(t *testing.T, port *SegmentSocketPort) SegmentFrame {
	t.Helper()
	select {
	case frame := <-port.Receive():
		return frame
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for segment socket frame")
		return SegmentFrame{}
	}
}

func assertNoSegmentSocketFrame(t *testing.T, port *SegmentSocketPort, message string) {
	t.Helper()
	select {
	case frame := <-port.Receive():
		t.Fatalf("%s: %+v", message, frame)
	case <-time.After(30 * time.Millisecond):
	}
}

func TestSegmentSocketMACAuthorizationControlGatesSessionTraffic(t *testing.T) {
	fabric := NewNamedSegmentFabric("venue-auth", bond.L2SwitchConfig{})
	token := bytesOf(0x71, 32)
	adminToken := bytesOf(0x73, 32)
	auth := map[string]SegmentSocketAuthorization{
		"session-auth": {Token: token, EAPOLTapName: "gb-auth-a", Port: bond.L2PortConfig{MACAuth: true, VLAN: bond.L2VLANPolicy{AccessVLAN: 10}}},
		"session-peer": {Token: bytesOf(0x72, 32), Port: bond.L2PortConfig{VLAN: bond.L2VLANPolicy{AccessVLAN: 10}}},
	}
	socketPath := filepath.Join(os.TempDir(), fmt.Sprintf("gb-auth-%d-%d.sock", os.Getpid(), time.Now().UnixNano()))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServeSegmentSocketWithAdminToken(ctx, socketPath, fabric, auth, adminToken) }()
	waitForSocket(t, socketPath)
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("segment socket server: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("segment socket server did not stop")
		}
	}()
	a, err := DialSegmentSocket(ctx, socketPath, "venue-auth", "session-auth", token, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := DialSegmentSocket(ctx, socketPath, "venue-auth", "session-peer", auth["session-peer"].Token, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	frame := testBroadcastFrame(0x77)
	if got := a.Send(frame, time.Now()); got.Drop != bond.L2Forward {
		t.Fatalf("send before auth: %+v", got)
	}
	select {
	case delivery := <-b.Receive():
		t.Fatalf("unauthorized frame crossed fabric: %+v", delivery)
	case <-time.After(50 * time.Millisecond):
	}
	mac := [6]byte{0x02, 0, 0, 0, 0, 0x77}
	if err := SetRemoteSegmentMACAuthorization(ctx, socketPath, "venue-auth", "session-auth", "gb-auth-a", token, mac, true); err == nil {
		t.Fatal("session attachment token improperly authorized a MAC")
	}
	select {
	case delivery := <-b.Receive():
		t.Fatalf("member credential authorized traffic: %+v", delivery)
	case <-time.After(50 * time.Millisecond):
	}
	if err := SetRemoteSegmentMACAuthorization(ctx, socketPath, "venue-auth", "session-auth", "wrong-tap", adminToken, mac, true); err == nil {
		t.Fatal("event from a mismatched TAP authorized a MAC")
	}
	if err := SetRemoteSegmentMACAuthorization(ctx, socketPath, "venue-auth", "session-auth", "gb-auth-a", adminToken, mac, true); err != nil {
		t.Fatal(err)
	}
	if got := a.Send(frame, time.Now()); got.Drop != bond.L2Forward {
		t.Fatalf("send after auth: %+v", got)
	}
	select {
	case delivery := <-b.Receive():
		if !bytes.Equal(delivery.Frame, frame) || delivery.IngressIdentity != "session-auth" {
			t.Fatalf("authorized delivery: %+v", delivery)
		}
	case <-time.After(time.Second):
		t.Fatal("authorized frame did not cross fabric")
	}
	if err := SetRemoteSegmentMACAuthorization(ctx, socketPath, "venue-auth", "session-auth", "gb-auth-a", adminToken, mac, false); err != nil {
		t.Fatal(err)
	}
	if got := a.Send(frame, time.Now()); got.Drop != bond.L2Forward {
		t.Fatalf("send after revoke: %+v", got)
	}
	select {
	case delivery := <-b.Receive():
		t.Fatalf("revoked frame crossed fabric: %+v", delivery)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestSegmentSocketEAPOLAndAuthorizationStayWithPairedSession(t *testing.T) {
	fabric := NewNamedSegmentFabric("venue-paired-auth", bond.L2SwitchConfig{})
	adminToken := bytesOf(0x84, 32)
	macA := [6]byte{0x02, 0, 0, 0, 0, 0xa1}
	macB := [6]byte{0x02, 0, 0, 0, 0xb1}
	auth := map[string]SegmentSocketAuthorization{
		"session-a": {Token: bytesOf(0x81, 32), EAPOLTapName: "gb-auth-a", Port: bond.L2PortConfig{MACAuth: true, VLAN: bond.L2VLANPolicy{AccessVLAN: 10}}},
		"session-b": {Token: bytesOf(0x82, 32), EAPOLTapName: "gb-auth-b", Port: bond.L2PortConfig{MACAuth: true, VLAN: bond.L2VLANPolicy{AccessVLAN: 10}}},
	}
	socketPath := filepath.Join(os.TempDir(), fmt.Sprintf("gb-pair-%d-%d.sock", os.Getpid(), time.Now().UnixNano()))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServeSegmentSocketWithAdminToken(ctx, socketPath, fabric, auth, adminToken) }()
	waitForSocket(t, socketPath)
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("segment socket server: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("segment socket server did not stop")
		}
	}()
	a, err := DialSegmentSocket(ctx, socketPath, "venue-paired-auth", "session-a", auth["session-a"].Token, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := DialSegmentSocket(ctx, socketPath, "venue-paired-auth", "session-b", auth["session-b"].Token, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	tapA, err := fabric.AttachService(bond.L2PortConfig{Name: "auth-a", VLAN: bond.L2VLANPolicy{AccessVLAN: 10}, EAPOLAuthenticator: true, EAPOLAuthenticatorFor: "session-a"}, 8, false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer tapA.Close()
	tapB, err := fabric.AttachService(bond.L2PortConfig{Name: "auth-b", VLAN: bond.L2VLANPolicy{AccessVLAN: 10}, EAPOLAuthenticator: true, EAPOLAuthenticatorFor: "session-b"}, 8, false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer tapB.Close()
	requestA := testEAPOLRequest(macA)
	if got := a.Send(requestA, time.Now()); got.Drop != bond.L2Forward {
		t.Fatalf("session A EAPOL send: %+v", got)
	}
	select {
	case delivery := <-tapA.Receive():
		if !bytes.Equal(delivery.Frame, requestA) || delivery.IngressIdentity != "session-a" {
			t.Fatalf("session A request reached wrong TAP: %+v", delivery)
		}
	case <-time.After(time.Second):
		t.Fatal("session A EAPOL did not reach its TAP")
	}
	select {
	case delivery := <-tapB.Receive():
		t.Fatalf("session A EAPOL reached session B TAP: %+v", delivery)
	case <-time.After(50 * time.Millisecond):
	}
	requestB := testEAPOLRequest(macB)
	if got := b.Send(requestB, time.Now()); got.Drop != bond.L2Forward {
		t.Fatalf("session B EAPOL send: %+v", got)
	}
	select {
	case delivery := <-tapB.Receive():
		if !bytes.Equal(delivery.Frame, requestB) || delivery.IngressIdentity != "session-b" {
			t.Fatalf("session B request reached wrong TAP: %+v", delivery)
		}
	case <-time.After(time.Second):
		t.Fatal("session B EAPOL did not reach its TAP")
	}
	select {
	case delivery := <-tapA.Receive():
		t.Fatalf("session B EAPOL reached session A TAP: %+v", delivery)
	case <-time.After(50 * time.Millisecond):
	}
	if err := SetRemoteSegmentMACAuthorization(ctx, socketPath, "venue-paired-auth", "session-a", "gb-auth-b", adminToken, macA, true); err == nil {
		t.Fatal("session B TAP event authorized a session A MAC")
	}
	if err := SetRemoteSegmentMACAuthorization(ctx, socketPath, "venue-paired-auth", "session-a", "gb-auth-a", adminToken, macA, true); err != nil {
		t.Fatal(err)
	}
	if err := SetRemoteSegmentMACAuthorization(ctx, socketPath, "venue-paired-auth", "session-b", "gb-auth-b", adminToken, macB, false); err != nil {
		t.Fatal(err)
	}
	dataA := testBroadcastFrame(0xa1)
	if got := a.Send(dataA, time.Now()); got.Drop != bond.L2Forward {
		t.Fatalf("authorized session A data: %+v", got)
	}
	dataB := testBroadcastFrame(0xb1)
	if got := b.Send(dataB, time.Now()); got.Drop != bond.L2Forward {
		t.Fatalf("session B data enqueue: %+v", got)
	}
	waitFor(t, time.Second, func() bool { return fabric.SwitchStats().DropUnauthorized > 0 })
}

func testEAPOLRequest(source [6]byte) []byte {
	frame := make([]byte, 18)
	copy(frame[:6], []byte{1, 0x80, 0xc2, 0, 0, 3})
	copy(frame[6:12], source[:])
	frame[12], frame[13] = 0x88, 0x8e
	frame[14], frame[15], frame[16], frame[17] = 2, 1, 0, 0
	return frame
}

func drainSegmentSocketFrames(port *SegmentSocketPort) {
	timer := time.NewTimer(50 * time.Millisecond)
	defer timer.Stop()
	for {
		select {
		case <-port.Receive():
		case <-timer.C:
			return
		}
	}
}

func TestSegmentSocketRejectsWrongSegmentIdentityAndToken(t *testing.T) {
	fabric := NewNamedSegmentFabric("venue-a", bond.L2SwitchConfig{})
	token := bytesOf(0x51, 32)
	auth := map[string]SegmentSocketAuthorization{"session-a": {Token: token, Port: bond.L2PortConfig{VLAN: bond.L2VLANPolicy{AccessVLAN: 10}}}}
	socketPath := filepath.Join(t.TempDir(), "fabric.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServeSegmentSocket(ctx, socketPath, fabric, auth) }()
	waitForSocket(t, socketPath)
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("segment socket server did not stop")
		}
	}()
	for _, attempt := range []struct {
		segment, identity string
		token             []byte
	}{
		{"venue-b", "session-a", token},
		{"venue-a", "session-a", bytesOf(0x52, 32)},
		{"venue-a", "session-unknown", token},
	} {
		if port, err := DialSegmentSocket(context.Background(), socketPath, attempt.segment, attempt.identity, attempt.token, 4); err == nil {
			port.Close()
			t.Fatalf("unauthorized attachment accepted: %+v", attempt)
		}
	}
	if got := fabric.Stats()["attached_ports"].(int); got != 0 {
		t.Fatalf("rejected handshakes attached %d ports", got)
	}
}

func TestRemoteSegmentFabricAdapterUsesBrokerIdentityAndClosesAttachment(t *testing.T) {
	fabric := NewNamedSegmentFabric("venue-a", bond.L2SwitchConfig{})
	token := bytesOf(0x71, 32)
	auth := map[string]SegmentSocketAuthorization{
		"session-authoritative": {Token: token, Port: bond.L2PortConfig{VLAN: bond.L2VLANPolicy{AccessVLAN: 10}}},
	}
	socketPath := filepath.Join(t.TempDir(), "fabric.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServeSegmentSocket(ctx, socketPath, fabric, auth) }()
	waitForSocket(t, socketPath)
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("segment socket server: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("segment socket server did not stop")
		}
	}()

	remoteFabric, err := NewRemoteSegmentFabric("venue-a", socketPath, "session-authoritative", token)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := remoteFabric.Attach(bond.L2PortConfig{Name: "peer-controlled-name", VLAN: bond.L2VLANPolicy{AccessVLAN: 20}}, 4)
	if err != nil {
		t.Fatal(err)
	}
	if remote.ID() <= 0 || remote.cfgName != "session-authoritative" {
		t.Fatalf("remote port identity was not broker-derived: id=%d name=%q", remote.ID(), remote.cfgName)
	}
	if _, err := remoteFabric.Attach(bond.L2PortConfig{}, 4); err == nil {
		t.Fatal("remote fabric allowed multiple attachments on one credential")
	}
	local, err := fabric.Attach(bond.L2PortConfig{Name: "local", VLAN: bond.L2VLANPolicy{AccessVLAN: 10}}, 4)
	if err != nil {
		remote.Close()
		t.Fatal(err)
	}
	if verdict := remote.Send(testBroadcastFrame(0x72), time.Now()); verdict.Drop != bond.L2Forward {
		t.Fatalf("remote send failed: %+v", verdict)
	}
	select {
	case delivery := <-local.Receive():
		if delivery.IngressIdentity != "session-authoritative" {
			t.Fatalf("broker did not author ingress identity: %+v", delivery)
		}
	case <-time.After(time.Second):
		t.Fatal("remote frame did not reach local fabric attachment")
	}
	stats, ok := remoteFabric.Stats()["remote"].(bool)
	if !ok || !stats {
		t.Fatalf("remote fabric stats do not identify the adapter: %#v", remoteFabric.Stats())
	}
	remote.Close()
	waitFor(t, time.Second, func() bool { return fabric.SwitchStats().FDBSize == 0 })
	local.Close()
}

func TestSegmentSocketRequiresUniqueStrongTokensAndSafePath(t *testing.T) {
	fabric := NewNamedSegmentFabric("venue-a", bond.L2SwitchConfig{})
	short := map[string]SegmentSocketAuthorization{"session-a": {Token: []byte("short"), Port: bond.L2PortConfig{VLAN: bond.L2VLANPolicy{AccessVLAN: 10}}}}
	if err := ServeSegmentSocket(context.Background(), filepath.Join(t.TempDir(), "short.sock"), fabric, short); err == nil {
		t.Fatal("short token accepted")
	}
	duplicate := map[string]SegmentSocketAuthorization{
		"session-a": {Token: bytesOf(0x61, 32), Port: bond.L2PortConfig{VLAN: bond.L2VLANPolicy{AccessVLAN: 10}}},
		"session-b": {Token: bytesOf(0x61, 32), Port: bond.L2PortConfig{VLAN: bond.L2VLANPolicy{AccessVLAN: 10}}},
	}
	if err := ServeSegmentSocket(context.Background(), filepath.Join(t.TempDir(), "duplicate.sock"), fabric, duplicate); err == nil {
		t.Fatal("shared bearer token accepted for two identities")
	}
	if err := ServeSegmentSocket(context.Background(), "relative.sock", fabric, map[string]SegmentSocketAuthorization{"session-a": {Token: bytesOf(0x61, 32)}}); err == nil {
		t.Fatal("relative socket path accepted")
	}
	if _, err := DialSegmentSocket(context.Background(), "relative.sock", "venue-a", "session-a", bytesOf(0x61, 32), 4); err == nil {
		t.Fatal("relative dial path accepted")
	}
}

func TestSegmentSocketReplacesOnlyStaleSocketPath(t *testing.T) {
	fabric := NewNamedSegmentFabric("venue-a", bond.L2SwitchConfig{})
	socketPath := filepath.Join(t.TempDir(), "fabric.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- ServeSegmentSocket(ctx, socketPath, fabric, map[string]SegmentSocketAuthorization{
			"session-a": {Token: bytesOf(0x81, 32), Port: bond.L2PortConfig{VLAN: bond.L2VLANPolicy{AccessVLAN: 10}}},
		})
	}()
	waitFor(t, time.Second, func() bool {
		info, err := os.Stat(socketPath)
		return err == nil && info.Mode()&os.ModeSocket != 0 && info.Mode().Perm() == 0o600
	})
	if info, err := os.Stat(socketPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("stale path was not replaced with a private listener: %v, %v", info, err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("broker did not stop")
	}
}

func bytesOf(value byte, count int) []byte {
	b := make([]byte, count)
	for i := range b {
		b[i] = value
	}
	return b
}

func testBroadcastFrame(source byte) []byte {
	return []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0, 0, 0, 0, source, 0x88, 0xb5}
}

func waitForSocket(t *testing.T, path string) {
	t.Helper()
	waitFor(t, time.Second, func() bool {
		info, err := os.Stat(path)
		return err == nil && info.Mode()&os.ModeSocket != 0
	})
}

func waitFor(t *testing.T, timeout time.Duration, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition did not become true before timeout")
}
