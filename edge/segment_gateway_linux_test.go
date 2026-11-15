//go:build linux

package edge

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/Dankular/GameBond.Core/bond"
)

func TestSharedSegmentSwitchesToSingleGatewayAndReturnsToSession(t *testing.T) {
	fabric := NewNamedSegmentFabric("venue-a", bond.L2SwitchConfig{})
	session, err := fabric.Attach(bond.L2PortConfig{Name: "session-client-a", VLAN: bond.L2VLANPolicy{AccessVLAN: 10}}, 8)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &L2Config{Enabled: true, SegmentID: "venue-a", FrameMTU: 1394, ExitVLAN: bond.L2VLANPolicy{AccessVLAN: 10}, Bridge: &L2Bridge{
		Address: "10.78.0.1/24", DHCPStart: "10.78.0.100", DHCPEnd: "10.78.0.110", Lease: "12h",
	}}
	e, err := openGateway(cfg, fabric)
	if err != nil {
		t.Fatal(err)
	}
	defer e.close()

	clientMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x42}
	clientIP := []byte{10, 78, 0, 42}
	frame := make([]byte, 14+28)
	copy(frame[:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(frame[6:12], clientMAC)
	binary.BigEndian.PutUint16(frame[12:14], 0x0806)
	arp := frame[14:]
	binary.BigEndian.PutUint16(arp[0:2], 1)
	binary.BigEndian.PutUint16(arp[2:4], 0x0800)
	arp[4], arp[5] = 6, 4
	binary.BigEndian.PutUint16(arp[6:8], 1)
	copy(arp[8:14], clientMAC)
	copy(arp[14:18], clientIP)
	copy(arp[24:28], []byte{10, 78, 0, 1})

	if verdict := session.Send(frame, time.Now()); verdict.Drop != bond.L2Forward {
		t.Fatalf("session frame was not switched to gateway VLAN: %+v", verdict)
	}
	select {
	case delivery := <-e.servicePort.Receive():
		if delivery.IngressIdentity != "session-client-a" || delivery.IngressPort != session.ID() {
			t.Fatalf("gateway lost ingress identity: %+v", delivery)
		}
		e.gw.InboundFrom(delivery.Frame, delivery.IngressIdentity)
	case <-time.After(time.Second):
		t.Fatal("frame did not reach shared gateway service port")
	}
	select {
	case reply := <-session.Receive():
		if len(reply.Frame) < 14+28 || binary.BigEndian.Uint16(reply.Frame[12:14]) != 0x0806 || binary.BigEndian.Uint16(reply.Frame[20:22]) != 2 {
			t.Fatalf("gateway did not return an ARP reply through the segment: %x", reply.Frame)
		}
	case <-time.After(time.Second):
		t.Fatal("gateway response did not return to the session port")
	}
}
