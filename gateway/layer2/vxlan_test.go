package layer2

import (
	"reflect"
	"strings"
	"testing"
)

func validVXLANConfig(t *testing.T) Config {
	t.Helper()
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Overrides = nil
	cfg.Interfaces = append(cfg.Interfaces, Interface{ID: "evpn-tap", Name: "gb-evpn0"}, Interface{ID: "evpn-vxlan", Name: "vxlan10010"}, Interface{ID: "underlay", Name: "wan-vtep"})
	cfg.Bridges[0].Ports = append(cfg.Bridges[0].Ports,
		BridgePort{Interface: "evpn-tap", UntaggedNetwork: "default"},
		BridgePort{Interface: "evpn-vxlan", UntaggedNetwork: "default"})
	cfg.VXLANDevices = []VXLANDevice{{ID: "venue-a", VNI: 10010, TapInterface: "evpn-tap", VxlanInterface: "evpn-vxlan", UnderlayInterface: "underlay", Network: "default", LocalAddress: "192.0.2.10"}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestBuildTopologyPlanCreatesKernelVXLANAndPersistentBrokerTAP(t *testing.T) {
	cfg := validVXLANConfig(t)
	host := Capabilities{Features: map[string]FeatureCapability{
		FeatureBridgeVLAN: {State: CapabilityConditional}, FeatureVXLAN: {State: CapabilityConditional},
	}, Interfaces: []HostInterface{{Name: "enp2s0", MTU: 1500}, {Name: "enp3s0", MTU: 1500}, {Name: "wan-vtep", MTU: 1600, AdminUp: true}}}
	plan, err := BuildTopologyPlan(Config{}, cfg, host)
	if err != nil {
		t.Fatal(err)
	}
	find := func(tool string, args ...string) int {
		for i, change := range plan.Changes {
			if change.Apply.Tool == tool && reflect.DeepEqual(change.Apply.Args, args) {
				return i
			}
		}
		return -1
	}
	tap := find("ip", "tuntap", "add", "dev", "gb-evpn0", "mode", "tap")
	vxlan := find("ip", "link", "add", "name", "vxlan10010", "mtu", "1500", "type", "vxlan", "id", "10010", "local", "192.0.2.10", "dev", "wan-vtep", "dstport", "4789", "nolearning")
	bridge := find("ip", "link", "add", "name", "br-main", "type", "bridge", "vlan_filtering", "1")
	vlan := find("bridge", "vlan", "add", "dev", "vxlan10010", "vid", "10", "pvid", "untagged")
	if tap < 0 || vxlan < 0 || bridge < 0 || vlan < 0 || !(tap < vxlan && vxlan < bridge && bridge < vlan) {
		t.Fatalf("TAP/VXLAN/bridge/VLAN dependencies are not ordered: tap=%d vxlan=%d bridge=%d vlan=%d changes=%+v", tap, vxlan, bridge, vlan, plan.Changes)
	}
	if !reflect.DeepEqual(plan.Changes[tap].Rollback.Args, []string{"link", "del", "dev", "gb-evpn0"}) || !reflect.DeepEqual(plan.Changes[vxlan].Rollback.Args, []string{"link", "del", "dev", "vxlan10010"}) {
		t.Fatalf("created kernel devices have no rollback delete: tap=%+v vxlan=%+v", plan.Changes[tap], plan.Changes[vxlan])
	}
}

func TestBuildTopologyPlanRefusesUnmanagedKernelVXLAN(t *testing.T) {
	cfg := validVXLANConfig(t)
	host := Capabilities{Features: map[string]FeatureCapability{FeatureBridgeVLAN: {State: CapabilityConditional}, FeatureVXLAN: {State: CapabilityConditional}},
		Interfaces: []HostInterface{{Name: "enp2s0", MTU: 1500}, {Name: "enp3s0", MTU: 1500}, {Name: "wan-vtep", MTU: 1600, AdminUp: true}, {Name: "gb-evpn0", Kind: "tun"},
			{Name: "vxlan10010", Kind: "vxlan", VXLANKnown: true, VXLANID: 10010, VXLANLocal: "192.0.2.10", VXLANDstPort: 4789}}}
	if _, err := BuildTopologyPlan(Config{}, cfg, host); err == nil || !strings.Contains(err.Error(), "not owned by a previous") {
		t.Fatalf("planner adopted an unmanaged VXLAN/TAP pair: %v", err)
	}
}

func TestVXLANConfigRequiresUniqueVNIAndBothBridgeAttachments(t *testing.T) {
	cfg := validVXLANConfig(t)
	cfg.VXLANDevices = append(cfg.VXLANDevices, VXLANDevice{ID: "venue-b", VNI: 10010, TapInterface: "evpn-tap", VxlanInterface: "evpn-vxlan", UnderlayInterface: "underlay", Network: "default", LocalAddress: "192.0.2.11"})
	if err := cfg.Validate(); err == nil {
		t.Fatal("duplicate VNI and interface ownership accepted")
	}
	cfg = validVXLANConfig(t)
	cfg.Bridges[0].Ports = cfg.Bridges[0].Ports[:len(cfg.Bridges[0].Ports)-1]
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "bridge ports carrying network") {
		t.Fatalf("VXLAN device without bridge attachment accepted: %v", err)
	}
}
