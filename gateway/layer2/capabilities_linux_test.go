//go:build linux

package layer2

import (
	"context"
	"strings"
	"testing"
)

func TestEvaluateCapabilitiesReportsMissingTools(t *testing.T) {
	c := EvaluateCapabilities(Detection{KernelRelease: "6.12.0", Tools: map[string]bool{"ip": true}})
	if got := c.Features[FeatureBridgeVLAN]; got.State != CapabilityUnavailable || got.Reason == "" {
		t.Fatalf("bridge VLAN without bridge tool must be unavailable, got %#v", got)
	}
	if got := c.Features[FeatureFlowControl]; got.State != CapabilityUnavailable {
		t.Fatalf("flow control without ethtool must be unavailable, got %#v", got)
	}
}

func TestEvaluateCapabilitiesDoesNotClaimGenericMCLAG(t *testing.T) {
	c := EvaluateCapabilities(Detection{Tools: map[string]bool{
		"ip": true, "bridge": true, "tc": true, "nft": true, "ethtool": true,
	}})
	if got := c.Features[FeatureMCLAG]; got.State != CapabilityUnsupported {
		t.Fatalf("generic Linux provider must not claim MC-LAG support, got %#v", got)
	}
}

func TestEvaluateCapabilitiesGatesLACPOnKernelBondingAndTools(t *testing.T) {
	withoutModule := EvaluateCapabilities(Detection{Tools: map[string]bool{"ip": true, "ethtool": true}})
	if got := withoutModule.Features[FeatureLACP]; got.State != CapabilityUnavailable {
		t.Fatalf("LACP without bonding support = %#v", got)
	}
	withModule := EvaluateCapabilities(Detection{Bonding: true, Tools: map[string]bool{"ip": true, "ethtool": true}})
	if got := withModule.Features[FeatureLACP]; got.State != CapabilityConditional {
		t.Fatalf("LACP with required host support = %#v", got)
	}
}

func TestEvaluateCapabilitiesRequiresProvidersForProtocolFeatures(t *testing.T) {
	c := EvaluateCapabilities(Detection{Tools: map[string]bool{"ip": true, "bridge": true}})
	if got := c.Features[FeatureVRRP]; got.State != CapabilityUnavailable {
		t.Fatalf("VRRP without provider must be unavailable, got %#v", got)
	}
	if got := c.Features[FeatureRSTP]; got.State != CapabilityUnavailable {
		t.Fatalf("RSTP without provider must be unavailable, got %#v", got)
	}
	if got := c.Features[FeatureLLDPMED]; got.State != CapabilityUnavailable {
		t.Fatalf("LLDP-MED without provider must be unavailable, got %#v", got)
	}
}

func TestEvaluateCapabilitiesMarksProfilesUnsupportedUntilIntegrated(t *testing.T) {
	c := EvaluateCapabilities(Detection{Tools: map[string]bool{"ip": true, "bridge": true, "tc": true, "nft": true}})
	for _, profile := range avProfiles {
		if got := c.Features[profile.feature]; got.State != CapabilityUnsupported {
			t.Errorf("profile %s must stay unsupported before integration, got %#v", profile.name, got)
		}
	}
}

type capabilityRunner struct{}

func (capabilityRunner) Available(tool string) bool {
	return tool == "ip" || tool == "bridge" || tool == "tc"
}
func (capabilityRunner) Run(_ context.Context, tool string, _ ...string) ([]byte, error) {
	if tool == "ip" {
		return []byte(`[{"ifname":"enp2s0","mtu":1500,"max_mtu":9000,"flags":["UP"]}]`), nil
	}
	return []byte(`[]`), nil
}

func TestSnapshotCapabilitiesReportsInterfaceMaximumMTU(t *testing.T) {
	caps, err := SnapshotCapabilities(context.Background(), Config{Version: 1, Interfaces: []Interface{{ID: "lan", Name: "enp2s0"}}}, capabilityRunner{})
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range caps.Interfaces {
		if iface.Name == "enp2s0" {
			if iface.MaxMTU != 9000 {
				t.Fatalf("max_mtu = %d, want 9000", iface.MaxMTU)
			}
			if iface.TCClsact || len(iface.TCFilters) != 0 {
				t.Fatalf("unexpected traffic-control state: %#v", iface)
			}
			if caps.Features[FeatureVirtualNet].State != CapabilityConditional {
				t.Fatalf("tc-capable host should conditionally expose virtual network overrides: %#v", caps.Features[FeatureVirtualNet])
			}
			return
		}
	}
	t.Fatalf("expected interface in snapshot, got %d interfaces", len(caps.Interfaces))
}

type isolationSnapshotRunner struct{ capabilityRunner }

func (isolationSnapshotRunner) Run(_ context.Context, tool string, args ...string) ([]byte, error) {
	if tool == "ip" {
		return []byte(`[{"ifname":"enp2s0","mtu":1500,"max_mtu":9000,"flags":["UP"]}]`), nil
	}
	if tool == "bridge" && len(args) >= 4 && args[2] == "link" {
		return []byte(`[{"ifname":"enp2s0","isolated":true}]`), nil
	}
	return []byte(`[]`), nil
}

func TestSnapshotCapabilitiesReportsBridgePortIsolation(t *testing.T) {
	caps, err := SnapshotCapabilities(context.Background(), Config{Version: 1}, isolationSnapshotRunner{})
	if err != nil {
		t.Fatal(err)
	}
	if len(caps.Interfaces) != 1 || !caps.Interfaces[0].IsolationKnown || !caps.Interfaces[0].Isolated {
		t.Fatalf("expected observed isolated bridge port, got %#v", caps.Interfaces)
	}
}

func TestMACPortRestrictionStatusRequiresLockedPortLimitAndAllowedFDB(t *testing.T) {
	input := strings.Replace(validConfig, `{"interface":"lan-a","untagged_network":"default","tagged_networks":["voice"]},`, ``, 1)
	input = strings.TrimSuffix(input, `}`) + `,"mac_port_restrictions":[{"interface":"lan-b","network":"default","allowed_macs":["02:00:00:00:00:02"],"max_devices":4,"violation_action":"drop"}]}`
	cfg, err := DecodeConfig([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	caps := Capabilities{Interfaces: []HostInterface{
		{Name: "br-main", Kind: "bridge", FDBLimitKnown: true, FDBMaxLearned: 4},
		{Name: "enp3s0", Master: "br-main", BridgePortKnown: true, Locked: true},
	}, BridgeFDB: []BridgeFDBEntry{
		{MAC: "02:00:00:00:00:02", Device: "enp3s0", VLAN: 10, Static: true},
		{MAC: "02:00:00:00:00:03", Device: "enp3s0", VLAN: 10, Locked: true},
	}}
	applyMACPortRestrictionStatus(&caps, cfg)
	if len(caps.MACPortRestrictions) != 1 || !caps.MACPortRestrictions[0].Applied || caps.MACPortRestrictions[0].LearnedDevices != 1 || caps.MACPortRestrictions[0].LockedEntries != 1 {
		t.Fatalf("effective MAC restriction status = %#v", caps.MACPortRestrictions)
	}
}

func TestMACBlockStatusRequiresAllOwnedRulesAndReportsCounters(t *testing.T) {
	input := strings.Replace(validConfig, `{"interface":"lan-a","untagged_network":"default","tagged_networks":["voice"]},`, ``, 1)
	input = strings.TrimSuffix(input, `}`) + `,"mac_address_blocks":[{"interface":"lan-b","network":"default","mac":"02:00:00:00:00:03"}]}`
	cfg, err := DecodeConfig([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	comments := macBlockRuleComments(cfg)
	counters := make(map[string][2]uint64, len(comments))
	for _, comment := range comments {
		counters[comment] = [2]uint64{2, 100}
	}
	caps := Capabilities{MACBlockTablePresent: true, MACBlockTableManaged: true, MACBlockRuleCounters: counters}
	applyMACBlockStatus(&caps, cfg)
	if len(caps.MACBlocks) != 1 || !caps.MACBlocks[0].Applied || caps.MACBlocks[0].Packets != 8 || caps.MACBlocks[0].Bytes != 400 {
		t.Fatalf("MAC block status = %#v", caps.MACBlocks)
	}
}

func TestMACACLStatusReportsOrderAndCountersOnlyForCompleteRuleset(t *testing.T) {
	input := strings.Replace(validConfig, `{"interface":"lan-a","untagged_network":"default","tagged_networks":["voice"]},`, ``, 1)
	input = strings.TrimSuffix(input, `}`) + `,"mac_acls":[{"id":"allow-device","interface":"lan-b","network":"default","direction":"both","destination_mac":"02:00:00:00:00:06","action":"allow"}]}`
	cfg, err := DecodeConfig([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	comments := macACLRuleComments(cfg)
	counters := make(map[string][2]uint64, len(comments))
	for _, comment := range comments {
		counters[comment] = [2]uint64{3, 120}
	}
	caps := Capabilities{MACACLTablePresent: true, MACACLTableManaged: true, MACACLRuleCounters: counters}
	applyMACACLStatus(&caps, cfg)
	if len(caps.MACACL) != 1 || !caps.MACACL[0].Applied || caps.MACACL[0].RuleOrder != 1 || caps.MACACL[0].Packets != 12 || caps.MACACL[0].Bytes != 480 {
		t.Fatalf("MAC ACL status = %#v", caps.MACACL)
	}
}

func TestEgressRateStatusRequiresExactEffectiveTBF(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Overrides = nil
	cfg.EgressRates = []EgressRateLimit{{Interface: "lan-b", RateBPS: 10_000_000, BurstBytes: 16_384}}
	caps := Capabilities{Interfaces: []HostInterface{{Name: "enp3s0", RootQdisc: "tbf", RootQdiscRateBPS: 10_000_000, RootQdiscBurstBytes: 16_384}}}
	applyEgressRateStatus(&caps, cfg)
	if len(caps.EgressRates) != 1 || !caps.EgressRates[0].Applied || caps.EgressRates[0].EffectiveRateBPS != 10_000_000 {
		t.Fatalf("egress status = %#v", caps.EgressRates)
	}
	caps = Capabilities{Interfaces: []HostInterface{{Name: "enp3s0", RootQdisc: "tbf", RootQdiscRateBPS: 20_000_000, RootQdiscBurstBytes: 16_384}}}
	applyEgressRateStatus(&caps, cfg)
	if caps.EgressRates[0].Applied || caps.EgressRates[0].Reason == "" {
		t.Fatalf("mismatched rate reported active: %#v", caps.EgressRates[0])
	}
}

func TestParseTCFiltersReportsVLANPoliceEffectiveRate(t *testing.T) {
	got, err := parseTCFilters([]byte(`[{"pref":45020,"kind":"flower","options":{"vlan_id":20,"actions":[{"kind":"police","rate":500000000,"burst":65536,"control_action":{"type":"drop"}}]}}]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].VLANID != 20 || got[0].PoliceRateBPS != 500_000_000 || got[0].PoliceBurstBytes != 65_536 {
		t.Fatalf("parsed policer = %#v", got)
	}
}

func TestParseTCPoliceDetailsReadsEffectiveRateAndBurst(t *testing.T) {
	got, err := parseTCPoliceDetails([]byte("filter protocol 802.1Q pref 45020 flower chain 0\n vlan_id 20\n action order 1: police 0x1 rate 500Mbit burst 64Kb mtu 2Kb\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got[45020] != [2]uint64{500_000_000, 65_536} {
		t.Fatalf("policer details = %#v", got)
	}
}

func TestNetworkEgressStatusUsesObservedClsactPolice(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Overrides = nil
	cfg.EgressRates = []EgressRateLimit{{Interface: "lan-a", Network: "voice", RateBPS: 500_000_000, BurstBytes: 65_536}}
	caps := Capabilities{Interfaces: []HostInterface{{Name: "enp2s0", TCClsact: true, TCEgressFilters: []TCFilterState{{Priority: 45020, Kind: "flower", VLANID: 20, PoliceRateBPS: 500_000_000, PoliceBurstBytes: 65_536}}}}}
	applyEgressRateStatus(&caps, cfg)
	if len(caps.EgressRates) != 1 || !caps.EgressRates[0].Applied || caps.EgressRates[0].EffectiveQdisc != "clsact/police" {
		t.Fatalf("network rate status = %#v", caps.EgressRates)
	}
}

func TestParsePauseStateRequiresAllThreeFields(t *testing.T) {
	state, err := parsePauseState([]byte("Pause parameters for enp2s0:\nAutonegotiate: on\nRX: on\nTX: off\n"))
	if err != nil || state != (pauseState{Autoneg: "on", RX: true, TX: false}) {
		t.Fatalf("pause state = %#v, err=%v", state, err)
	}
	if _, err := parsePauseState([]byte("RX: on\nTX: off\n")); err == nil {
		t.Fatal("incomplete pause state accepted")
	}
}

func TestFlowControlStatusReportsUnsupportedAndApplied(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Overrides = nil
	cfg.FlowControl = []FlowControlPolicy{{Interface: "lan-b", Autoneg: "on", RX: true, TX: false}}
	caps := Capabilities{Interfaces: []HostInterface{{Name: "enp3s0", PauseKnown: true, PauseAutoneg: "on", PauseRX: true, PauseTX: false}}}
	applyFlowControlStatus(&caps, cfg)
	if len(caps.FlowControl) != 1 || !caps.FlowControl[0].Supported || !caps.FlowControl[0].Applied {
		t.Fatalf("flow-control status = %#v", caps.FlowControl)
	}
	caps = Capabilities{Interfaces: []HostInterface{{Name: "enp3s0", PauseError: "pause parameters unsupported"}}}
	applyFlowControlStatus(&caps, cfg)
	if caps.FlowControl[0].Supported || caps.FlowControl[0].Applied || caps.FlowControl[0].Reason != "pause parameters unsupported" {
		t.Fatalf("unsupported status = %#v", caps.FlowControl[0])
	}
}

func TestParseTCFiltersFindsTaggedDropAndMACVLANPush(t *testing.T) {
	got, err := parseTCFilters([]byte(`[
		{"pref":1,"kind":"flower","options":{"num_of_vlans":1,"actions":[{"kind":"gact","control_action":{"type":"drop"}}]}},
		{"pref":2,"kind":"flower","options":{"num_of_vlans":0,"src_mac":"02:00:00:00:00:01","actions":[{"kind":"vlan","vlan_action":"push","id":20,"protocol":"802.1Q","control_action":{"type":"pass"}}]}}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !got[0].DropTagged || got[1].SourceMAC != "02:00:00:00:00:01" || got[1].VLANAction != "push" || got[1].VLANID != 20 {
		t.Fatalf("parsed TC filters = %#v", got)
	}
}

func TestApplyOverrideStatusRequiresEffectiveFilterAndVLANMembership(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	filters := expectedOverrideFilters(cfg)
	caps := Capabilities{Interfaces: []HostInterface{{Name: "enp3s0", TCClsact: true, TCFilters: filters["enp3s0"]}},
		BridgeVLANs: []BridgeVLANState{{Device: "enp3s0", VLAN: 20}}}
	applyOverrideStatus(&caps, cfg)
	if len(caps.Overrides) != 1 || !caps.Overrides[0].Applied || caps.Overrides[0].VLAN != 20 {
		t.Fatalf("effective override status = %#v", caps.Overrides)
	}
	caps.BridgeVLANs = nil
	caps.Overrides = nil
	applyOverrideStatus(&caps, cfg)
	if caps.Overrides[0].Applied || caps.Overrides[0].Reason == "" {
		t.Fatalf("override without bridge VLAN membership must not be reported applied: %#v", caps.Overrides[0])
	}
}
