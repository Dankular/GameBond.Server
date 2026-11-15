package l2gw

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestLLDPMEDNetworkPolicyPeriodicAdvertisementAndWithdrawal(t *testing.T) {
	out := make(chan []byte, 8)
	g, err := New(Config{
		Address:   netip.MustParsePrefix("10.78.0.1/24"),
		DHCPStart: netip.MustParseAddr("10.78.0.100"), DHCPEnd: netip.MustParseAddr("10.78.0.110"),
		Out:             func(frame []byte) { out <- append([]byte(nil), frame...) },
		LLDPMEDPolicy:   &LLDPMEDNetworkPolicy{ApplicationType: 1, VLANID: 23, Tagged: true, L2Priority: 5, DSCP: 46},
		LLDPMEDInterval: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	first := awaitLLDPFrame(t, out)
	assertLLDPMEDFields(t, first, 120, 0x01402f6e)

	periodic := awaitLLDPFrame(t, out)
	assertLLDPMEDFields(t, periodic, 120, 0x01402f6e)

	g.Close()
	withdrawal := awaitLLDPFrame(t, out)
	assertLLDPMEDFields(t, withdrawal, 0, 0x01402f6e)
}

func TestLLDPMEDNetworkPolicyRejectsInvalidConfiguration(t *testing.T) {
	for name, policy := range map[string]LLDPMEDNetworkPolicy{
		"vlan zero":     {ApplicationType: 1, VLANID: 0},
		"reserved vlan": {ApplicationType: 1, VLANID: 4095},
		"application":   {ApplicationType: 9, VLANID: 1},
		"priority":      {ApplicationType: 1, VLANID: 1, L2Priority: 8},
		"dscp":          {ApplicationType: 1, VLANID: 1, DSCP: 64},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := New(Config{
				Address:   netip.MustParsePrefix("10.78.0.1/24"),
				DHCPStart: netip.MustParseAddr("10.78.0.100"), DHCPEnd: netip.MustParseAddr("10.78.0.110"),
				Out: func([]byte) {}, LLDPMEDPolicy: &policy,
			})
			if err == nil {
				t.Fatal("accepted invalid LLDP-MED network policy")
			}
		})
	}
}

func awaitLLDPFrame(t *testing.T, out <-chan []byte) []byte {
	t.Helper()
	select {
	case frame := <-out:
		return frame
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for LLDP-MED frame")
		return nil
	}
}

func assertLLDPMEDFields(t *testing.T, frame []byte, wantTTL uint16, wantPolicy uint32) {
	t.Helper()
	if len(frame) < 14 || binary.BigEndian.Uint16(frame[12:14]) != lldpEtherType {
		t.Fatalf("not an untagged LLDP frame: %x", frame)
	}
	var gotTTL uint16
	var gotPolicy uint32
	for offset := 14; offset+2 <= len(frame); {
		header := binary.BigEndian.Uint16(frame[offset : offset+2])
		typ, size := header>>9, int(header&0x1ff)
		offset += 2
		if size > len(frame)-offset {
			t.Fatalf("invalid LLDP TLV length in %x", frame)
		}
		value := frame[offset : offset+size]
		offset += size
		switch typ {
		case 3:
			gotTTL = binary.BigEndian.Uint16(value)
		case 127:
			if len(value) == 8 && value[0] == lldpMEDOUI0 && value[1] == lldpMEDOUI1 && value[2] == lldpMEDOUI2 && value[3] == lldpMEDNetworkPolicy {
				gotPolicy = binary.BigEndian.Uint32(value[4:])
			}
		case 0:
			if gotTTL != wantTTL || gotPolicy != wantPolicy {
				t.Fatalf("LLDP TTL/policy = %d/%08x, want %d/%08x (frame %x)", gotTTL, gotPolicy, wantTTL, wantPolicy, frame)
			}
			return
		}
	}
	t.Fatalf("LLDP frame missing end TLV: %x", frame)
}

func TestLLDPMEDPolicyFrameUsesGatewayMAC(t *testing.T) {
	custom := net.HardwareAddr{0x02, 0x47, 0x42, 0, 0, 7}
	g, err := New(Config{
		Address:   netip.MustParsePrefix("10.78.0.1/24"),
		DHCPStart: netip.MustParseAddr("10.78.0.100"), DHCPEnd: netip.MustParseAddr("10.78.0.110"),
		Out: func([]byte) {}, MAC: custom,
		LLDPMEDPolicy: &LLDPMEDNetworkPolicy{ApplicationType: 1, VLANID: 77},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	frame := g.buildLLDPMEDFrame(120, nil)
	if string(frame[6:12]) != string(custom) {
		t.Fatalf("source MAC = %x, want %x", frame[6:12], custom)
	}
}
