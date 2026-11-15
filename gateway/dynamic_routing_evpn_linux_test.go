//go:build linux

package gateway

import (
	"context"
	"strings"
	"testing"

	"github.com/Dankular/GameBond.Server/gateway/layer2"
)

func TestEVPNDataPlaneSnapshotReflectsManagedVXLANConfigurationWithoutClaimingReadiness(t *testing.T) {
	cfg := DynamicRoutingConfig{BGP: BGPConfig{EVPN: BGPFlowEVPNConfig{Enabled: true}}}
	withoutManagedVXLAN := snapshotDynamicRouting(context.Background(), nil, cfg, false)
	if !withoutManagedVXLAN.EVPNEnabled || withoutManagedVXLAN.EVPNDataPlaneReady || withoutManagedVXLAN.EVPNDataPlaneState != "unmanaged" {
		t.Fatalf("EVPN without managed VXLAN should remain unmanaged and not ready: %+v", withoutManagedVXLAN)
	}
	withManagedVXLAN := snapshotDynamicRouting(context.Background(), nil, cfg, true)
	if !withManagedVXLAN.EVPNEnabled || withManagedVXLAN.EVPNDataPlaneReady || withManagedVXLAN.EVPNDataPlaneState != "configured" {
		t.Fatalf("managed VXLAN should report configured but not ready absent live evidence: %+v", withManagedVXLAN)
	}
	disabled := snapshotDynamicRouting(context.Background(), nil, DynamicRoutingConfig{}, true)
	if disabled.EVPNEnabled || disabled.EVPNDataPlaneReady || disabled.EVPNDataPlaneState != "disabled" {
		t.Fatalf("disabled EVPN state should remain disabled: %+v", disabled)
	}
}

func TestEVPNMHRequiresManagedLACPIdentityAndVXLANNetwork(t *testing.T) {
	segment := []BGPFlowEVPNEthernetSegment{{BondID: "lag-a", ESID: 101}}
	l2 := evpnMHL2Config()
	if err := validateEVPNMHEthernetSegments(segment, &l2); err != nil {
		t.Fatalf("valid Ethernet Segment rejected: %v", err)
	}
	if err := validateEVPNMHEthernetSegments([]BGPFlowEVPNEthernetSegment{{BondID: "missing", ESID: 101}}, &l2); err == nil {
		t.Fatal("unknown/non-managed bond accepted")
	}
	l2.Bonds[0].SystemMAC = ""
	if err := validateEVPNMHEthernetSegments(segment, &l2); err == nil {
		t.Fatal("Ethernet Segment accepted without stable bond system MAC")
	}
	l2 = evpnMHL2Config()
	l2.Bridges[0].Ports[0].UntaggedNetwork = ""
	if err := validateEVPNMHEthernetSegments(segment, &l2); err == nil {
		t.Fatal("bond not attached to the VXLAN network accepted")
	}
}

func TestEVPNMHZebraConfigUsesManagedBondAndDFPreference(t *testing.T) {
	cfg := DynamicRoutingConfig{Enabled: true, RouterID: "192.0.2.1", BGP: BGPConfig{
		Enabled: true, LocalAS: 64512,
		Neighbors: []BGPNeighbor{{ID: "peer-a", Address: "198.51.100.1", RemoteAS: 64513}},
		EVPN:      BGPFlowEVPNConfig{Enabled: true, Neighbors: []string{"peer-a"}, EthernetSegments: []BGPFlowEVPNEthernetSegment{{BondID: "lag-a", ESID: 101, DFPreference: 200}}},
	}}
	l2 := evpnMHL2Config()
	configs, err := renderFRRConfigs(cfg, nil, &l2)
	if err != nil {
		t.Fatal(err)
	}
	zebra := string(configs["zebra"])
	for _, required := range []string{"interface bond0", "evpn mh es-id 101", "evpn mh es-sys-mac 02:00:00:00:00:01", "evpn mh es-df-pref 200"} {
		if !strings.Contains(zebra, required) {
			t.Fatalf("generated zebra config missing %q:\n%s", required, zebra)
		}
	}
	if strings.Contains(string(configs["bgpd"]), "evpn mh es-") {
		t.Fatalf("Ethernet Segment commands belong in zebra, not bgpd:\n%s", configs["bgpd"])
	}
}

func TestEVPNMHDynamicRoutingValidatesSegmentIdentityBounds(t *testing.T) {
	cfg := DynamicRoutingConfig{Enabled: true, RouterID: "192.0.2.1", BGP: BGPConfig{Enabled: true, LocalAS: 64512,
		Neighbors: []BGPNeighbor{{ID: "peer-a", Address: "198.51.100.1", RemoteAS: 64513}},
		EVPN:      BGPFlowEVPNConfig{Enabled: true, Neighbors: []string{"peer-a"}, EthernetSegments: []BGPFlowEVPNEthernetSegment{{BondID: "lag-a", ESID: 101}}},
	}}
	if err := cfg.Validate(nil); err != nil {
		t.Fatalf("valid EVPN-MH configuration rejected: %v", err)
	}
	cfg.BGP.EVPN.EthernetSegments[0].ESID = 0
	if err := cfg.Validate(nil); err == nil {
		t.Fatal("zero ESID accepted")
	}
	cfg.BGP.EVPN.EthernetSegments[0] = BGPFlowEVPNEthernetSegment{BondID: "lag-a", ESID: 101, DFPreference: 16777216}
	if err := cfg.Validate(nil); err == nil {
		t.Fatal("out-of-range DF preference accepted")
	}
}

func evpnMHL2Config() layer2.Config {
	return layer2.Config{
		Interfaces:   []layer2.Interface{{ID: "lag-if", Name: "bond0"}},
		Bonds:        []layer2.Bond{{ID: "lag-a", Interface: "lag-if", SystemMAC: "02:00:00:00:00:01"}},
		Bridges:      []layer2.Bridge{{ID: "br0", Name: "br0", Ports: []layer2.BridgePort{{Interface: "lag-if", UntaggedNetwork: "net0"}}}},
		Networks:     []layer2.Network{{ID: "net0", Bridge: "br0", VLAN: 100, MTU: 1500}},
		VXLANDevices: []layer2.VXLANDevice{{ID: "vx0", VNI: 1000, Network: "net0"}},
	}
}

func TestRenderFRREVPNUsesExistingBGPDInstance(t *testing.T) {
	cfg := DynamicRoutingConfig{
		Enabled:  true,
		RouterID: "192.0.2.1",
		BGP: BGPConfig{Enabled: true, LocalAS: 64512,
			Neighbors: []BGPNeighbor{
				{ID: "peer-a", Address: "198.51.100.1", RemoteAS: 64513, Import: []string{"0.0.0.0/0"}, Export: []string{"203.0.113.0/24"}},
				{ID: "peer-b", Address: "198.51.100.2", RemoteAS: 64514},
			},
			EVPN: BGPFlowEVPNConfig{Enabled: true, Neighbors: []string{"peer-a"}},
		},
	}
	configs, err := renderFRRConfigs(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	bgp := string(configs["bgpd"])
	for _, required := range []string{"router bgp 64512", "address-family l2vpn evpn", "neighbor 198.51.100.1 activate", "advertise-all-vni"} {
		if !strings.Contains(bgp, required) {
			t.Fatalf("generated bgpd config missing %q:\n%s", required, bgp)
		}
	}
	if strings.Count(bgp, "router bgp ") != 1 {
		t.Fatalf("EVPN must share the configured bgpd control plane:\n%s", bgp)
	}
	evpn := strings.SplitN(bgp, " address-family l2vpn evpn\n", 2)
	if len(evpn) != 2 {
		t.Fatalf("EVPN address family was not generated:\n%s", bgp)
	}
	evpn = strings.SplitN(evpn[1], " exit-address-family\n", 2)
	if !strings.Contains(evpn[0], "neighbor 198.51.100.1 activate") || strings.Contains(evpn[0], "neighbor 198.51.100.2 activate") {
		t.Fatalf("EVPN activation did not match the selected peer list:\n%s", evpn[0])
	}
	if strings.Contains(bgp, "systemctl") || strings.Contains(bgp, "gamebond-evpn") {
		t.Fatalf("EVPN generated an unexpected second daemon/config:\n%s", bgp)
	}
}

func TestValidateFRREVPNRequiresSelectedBGPNeighbors(t *testing.T) {
	base := DynamicRoutingConfig{Enabled: true, RouterID: "192.0.2.1", BGP: BGPConfig{Enabled: true, LocalAS: 64512,
		Neighbors: []BGPNeighbor{{ID: "peer-a", Address: "198.51.100.1", RemoteAS: 64513}},
		EVPN:      BGPFlowEVPNConfig{Enabled: true, Neighbors: []string{"missing"}},
	}}
	if err := base.Validate(nil); err == nil {
		t.Fatal("EVPN accepted an unknown BGP peer")
	}
	base.BGP.EVPN.Neighbors = []string{"peer-a"}
	if err := base.Validate(nil); err != nil {
		t.Fatalf("valid EVPN peer selection rejected: %v", err)
	}
	base.BGP.Enabled = false
	if err := base.Validate(nil); err == nil {
		t.Fatal("EVPN accepted without BGP")
	}
}
