//go:build linux

package layer2

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func TestParseBridgeMDBReportsListenerAndRouterPortsInStableOrder(t *testing.T) {
	input := []byte(`{"mdb":[{"dev":"br0","port":"swp2","grp":"239.1.1.2","state":"temp","vid":20},{"dev":"br0","port":"swp1","grp":"239.1.1.1","state":"temp","vid":10}],"router":{"br0":[{"port":"swp4","type":"permanent"},{"port":"swp3","type":"temp"}]}}`)
	groups, routers, err := parseBridgeMDB(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 2 || groups[0].Group != "239.1.1.1" || groups[0].VLAN != 10 || groups[0].Port != "swp1" || groups[1].Group != "239.1.1.2" {
		t.Fatalf("multicast database = %#v", groups)
	}
	if len(routers) != 2 || routers[0].Bridge != "br0" || routers[0].Port != "swp3" || routers[1].Port != "swp4" {
		t.Fatalf("router ports = %#v", routers)
	}
}

type mdbSnapshotRunner struct{ capabilityRunner }

func (mdbSnapshotRunner) Run(ctx context.Context, tool string, args ...string) ([]byte, error) {
	if tool == "bridge" && len(args) >= 3 && args[1] == "mdb" {
		return []byte(`{"mdb":[{"dev":"br-main","port":"enp2s0","grp":"239.10.0.1","state":"temp","vid":10}],"router":{"br-main":[{"port":"enp3s0","type":"permanent"}]}}`), nil
	}
	return capabilityRunner{}.Run(ctx, tool, args...)
}

func TestSnapshotCapabilitiesIncludesEffectiveMDBAndRouterPorts(t *testing.T) {
	caps, err := SnapshotCapabilities(context.Background(), Config{Version: 1}, mdbSnapshotRunner{})
	if err != nil {
		t.Fatal(err)
	}
	if len(caps.MulticastDatabase) != 1 || caps.MulticastDatabase[0].Bridge != "br-main" || caps.MulticastDatabase[0].VLAN != 10 {
		t.Fatalf("multicast database not surfaced from effective state: %#v", caps.MulticastDatabase)
	}
	if len(caps.MulticastRouterPorts) != 1 || caps.MulticastRouterPorts[0].Port != "enp3s0" {
		t.Fatalf("multicast router ports not surfaced from effective state: %#v", caps.MulticastRouterPorts)
	}
}

func TestParsePortAuthStaticStateIgnoresDynamicAuthorizationElements(t *testing.T) {
	raw := []byte(`{"nftables":[
		{"table":{"family":"bridge","name":"gamebond_8021x","comment":"gamebond-8021x:v1"}},
		{"set":{"family":"bridge","table":"gamebond_8021x","name":"protected_ports","type":"ifname","elem":["enp2s0"]}},
		{"set":{"family":"bridge","table":"gamebond_8021x","name":"authorized_ports","type":"ifname","elem":["enp2s0"]}},
		{"set":{"family":"bridge","table":"gamebond_8021x","name":"authenticated_clients","type":["ifname","ether_addr"],"elem":[{"concat":["enp2s0","02:00:00:00:00:10"]}]}},
		{"chain":{"family":"bridge","table":"gamebond_8021x","name":"input","type":"filter","hook":"input","prio":-300,"policy":"accept"}},
		{"chain":{"family":"bridge","table":"gamebond_8021x","name":"forward","type":"filter","hook":"forward","prio":-300,"policy":"accept"}},
		{"chain":{"family":"bridge","table":"gamebond_8021x","name":"egress","type":"filter","hook":"postrouting","prio":-300,"policy":"accept"}},
		{"rule":{"family":"bridge","table":"gamebond_8021x","chain":"input","comment":"gamebond-8021x:eapol-host"}},
		{"rule":{"family":"bridge","table":"gamebond_8021x","chain":"input","comment":"gamebond-8021x:authorized-host"}},
		{"rule":{"family":"bridge","table":"gamebond_8021x","chain":"input","comment":"gamebond-8021x:unauthorized-host"}},
		{"rule":{"family":"bridge","table":"gamebond_8021x","chain":"forward","comment":"gamebond-8021x:eapol-in"}},
		{"rule":{"family":"bridge","table":"gamebond_8021x","chain":"forward","comment":"gamebond-8021x:authorized-in"}},
		{"rule":{"family":"bridge","table":"gamebond_8021x","chain":"forward","comment":"gamebond-8021x:unauthorized-in"}},
		{"rule":{"family":"bridge","table":"gamebond_8021x","chain":"egress","comment":"gamebond-8021x:eapol-out"}},
		{"rule":{"family":"bridge","table":"gamebond_8021x","chain":"egress","comment":"gamebond-8021x:authorized-out"}},
		{"rule":{"family":"bridge","table":"gamebond_8021x","chain":"egress","comment":"gamebond-8021x:authorized-group-out"}},
		{"rule":{"family":"bridge","table":"gamebond_8021x","chain":"egress","comment":"gamebond-8021x:unauthorized-out"}}
	]}`)
	managed, valid, ports, comments := parsePortAuthStaticState(raw)
	if !managed || !valid || !reflect.DeepEqual(ports, []string{"enp2s0"}) || !reflect.DeepEqual(comments, portAuthRuleComments()) {
		t.Fatalf("static port-auth state = managed=%v valid=%v ports=%v comments=%v", managed, valid, ports, comments)
	}
}

type vlanIGMPSnapshotRunner struct{ capabilityRunner }

func (vlanIGMPSnapshotRunner) Run(ctx context.Context, tool string, args ...string) ([]byte, error) {
	if tool == "ip" {
		return []byte(`[{"ifname":"br-main","mtu":1500,"flags":["UP"],"linkinfo":{"info_kind":"bridge","info_data":{"mcast_snooping":1,"mcast_querier":0,"mcast_vlan_snooping":1}}}]`), nil
	}
	if tool == "bridge" && len(args) >= 4 && args[1] == "vlan" && args[2] == "global" {
		return []byte(`[{"ifname":"br-main","vlans":[{"vlan":10,"mcast_snooping":0}]}]`), nil
	}
	return capabilityRunner{}.Run(ctx, tool, args...)
}

func TestSnapshotCapabilitiesReportsPerVLANIGMPState(t *testing.T) {
	disabled := false
	cfg := Config{Version: 1, Networks: []Network{{ID: "default", Bridge: "main", VLAN: 10, IGMPSnooping: &disabled}}}
	caps, err := SnapshotCapabilities(context.Background(), cfg, vlanIGMPSnapshotRunner{})
	if err != nil {
		t.Fatal(err)
	}
	if caps.Features[FeatureIGMPVLAN].State != CapabilityConditional {
		t.Fatalf("feature capability = %#v", caps.Features[FeatureIGMPVLAN])
	}
	if len(caps.BridgeVLANGLOBALs) != 1 || caps.BridgeVLANGLOBALs[0].Bridge != "br-main" || caps.BridgeVLANGLOBALs[0].VLAN != 10 || caps.BridgeVLANGLOBALs[0].Snooping {
		t.Fatalf("per-VLAN state = %#v", caps.BridgeVLANGLOBALs)
	}
	found := false
	for _, iface := range caps.Interfaces {
		if iface.Name == "br-main" {
			found = iface.IGMPVLANKnown && iface.IGMPVLANMode
		}
	}
	if !found {
		t.Fatal("bridge per-VLAN mode was not reported")
	}
}

func TestApplyDHCPGuardStatusReportsExactActiveRulesAndCounters(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.DHCPGuard = []DHCPGuardPort{{Interface: "lan-a", RateLimitPPS: 20}}
	counters := map[string][2]uint64{}
	for _, comment := range dhcpGuardRuleComments(cfg) {
		counters[comment] = [2]uint64{3, 150}
	}
	caps := Capabilities{DHCPGuardTablePresent: true, DHCPGuardTableManaged: true, DHCPGuardRuleCounters: counters}
	applyDHCPGuardStatus(&caps, cfg)
	if len(caps.DHCPGuard) != 1 || !caps.DHCPGuard[0].Applied || caps.DHCPGuard[0].Packets != 6 || caps.DHCPGuard[0].Bytes != 300 {
		t.Fatalf("DHCP guard status = %#v", caps.DHCPGuard)
	}
	caps.DHCPGuardRuleCounters["unowned-rule"] = [2]uint64{}
	caps.DHCPGuard = nil
	applyDHCPGuardStatus(&caps, cfg)
	if caps.DHCPGuard[0].Applied {
		t.Fatalf("unowned rule did not invalidate managed status: %#v", caps.DHCPGuard[0])
	}
}

type dhcpGuardSnapshotRunner struct{}

func (dhcpGuardSnapshotRunner) Available(tool string) bool { return tool == "nft" }
func (dhcpGuardSnapshotRunner) Run(_ context.Context, tool string, args ...string) ([]byte, error) {
	if tool != "nft" {
		return nil, errors.New("unexpected tool")
	}
	if len(args) == 3 && args[2] == "tables" {
		return []byte(`{"nftables":[{"table":{"family":"bridge","name":"gamebond_dhcp_guard"}}]}`), nil
	}
	if len(args) == 5 && args[2] == "table" {
		return []byte(`{"nftables":[{"table":{"comment":"gamebond-dhcp-guard:v1"}},{"rule":{"comment":"gamebond-dhcp-guard:lan-a:server","expr":[{"counter":{"packets":2,"bytes":120}}]}},{"rule":{"comment":"gamebond-dhcp-guard:lan-a:rate:20","expr":[{"counter":{"packets":3,"bytes":180}}]}}]}`), nil
	}
	return nil, errors.New("unexpected nft command")
}
func (dhcpGuardSnapshotRunner) RunInput(_ context.Context, tool string, _ []byte, args ...string) ([]byte, error) {
	if tool != "nft" || !reflect.DeepEqual(args, []string{"-c", "-f", "-"}) {
		return nil, errors.New("unexpected nft check-mode command")
	}
	return nil, nil
}

func TestSnapshotDHCPGuardReportsManagedLiveCounters(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.DHCPGuard = []DHCPGuardPort{{Interface: "lan-a", RateLimitPPS: 20}}
	caps := Capabilities{Features: map[string]FeatureCapability{FeatureDHCPSnoop: {State: CapabilityConditional}}}
	snapshotDHCPGuardState(context.Background(), dhcpGuardSnapshotRunner{}, &caps, cfg)
	if !caps.DHCPGuardTablePresent || !caps.DHCPGuardTableManaged || len(caps.DHCPGuard) != 1 {
		t.Fatalf("guard state not loaded: %#v", caps)
	}
	if !caps.DHCPGuard[0].Applied || caps.DHCPGuard[0].Packets != 5 || caps.DHCPGuard[0].Bytes != 300 {
		t.Fatalf("unexpected DHCP guard status: %#v", caps.DHCPGuard[0])
	}
}

func TestJSONBoolAcceptsIPRoute2NumericSwitches(t *testing.T) {
	var state struct {
		Snooping jsonBool `json:"mcast_snooping"`
		Querier  jsonBool `json:"mcast_querier"`
	}
	if err := json.Unmarshal([]byte(`{"mcast_snooping":1,"mcast_querier":0}`), &state); err != nil {
		t.Fatal(err)
	}
	if !bool(state.Snooping) || bool(state.Querier) {
		t.Fatalf("numeric bridge state decoded incorrectly: %#v", state)
	}
}

func TestEvaluateCapabilitiesSeparatesDHCPPortGuardFromLeaseBindingGuard(t *testing.T) {
	caps := EvaluateCapabilities(Detection{Tools: map[string]bool{"nft": true, "bridge": true}})
	if caps.Features[FeatureDHCPSnoop].State != CapabilityConditional {
		t.Fatalf("port guard capability = %#v", caps.Features[FeatureDHCPSnoop])
	}
	if caps.Features[FeatureDHCPBinding].State != CapabilityUnsupported || !strings.Contains(caps.Features[FeatureDHCPBinding].Reason, "FDB state is not trusted") {
		t.Fatalf("lease binding capability = %#v", caps.Features[FeatureDHCPBinding])
	}
}

func TestDHCPBridgeProbeFailureMarksBindingGuardUnavailable(t *testing.T) {
	caps := Capabilities{Features: map[string]FeatureCapability{
		FeatureDHCPSnoop:   {State: CapabilityConditional},
		FeatureDHCPBinding: {State: CapabilityUnsupported, Reason: "authoritative DHCP ingress binding metadata is unavailable; learned bridge FDB state is not trusted for port authorization"},
	}}
	snapshotDHCPGuardState(context.Background(), dhcpGuardUnsupportedRunner{}, &caps, Config{Version: 1})
	if caps.Features[FeatureDHCPSnoop].State != CapabilityUnavailable {
		t.Errorf("%s state = %#v", FeatureDHCPSnoop, caps.Features[FeatureDHCPSnoop])
	}
	if caps.Features[FeatureDHCPBinding].State != CapabilityUnsupported {
		t.Errorf("%s state = %#v", FeatureDHCPBinding, caps.Features[FeatureDHCPBinding])
	}
}

type dhcpGuardUnsupportedRunner struct{}

func (dhcpGuardUnsupportedRunner) Available(string) bool { return true }
func (dhcpGuardUnsupportedRunner) Run(context.Context, string, ...string) ([]byte, error) {
	return nil, errors.New("bridge nft family unsupported")
}
func (dhcpGuardUnsupportedRunner) RunInput(context.Context, string, []byte, ...string) ([]byte, error) {
	return nil, errors.New("Operation not supported")
}

func TestParseMSTPModeReadsShowBridgeForceVersion(t *testing.T) {
	mode, err := parseMSTPMode([]byte("br0 CIST info\n  enabled yes\n  force protocol version     rstp\n"))
	if err != nil || mode != "rstp" {
		t.Fatalf("parseMSTPMode() = %q, %v", mode, err)
	}
	if _, err := parseMSTPMode([]byte("br0 CIST info\n  enabled yes\n")); err == nil {
		t.Fatal("showbridge output without the protocol version was accepted")
	}
}

func TestParseMSTPPortSettingsReadsConfiguredAndDefaultValues(t *testing.T) {
	state, err := parseMSTPPortSettings([]byte("bridge:swp1 CIST info\n  admin edge port    yes                      auto edge port       yes\n  point-to-point      yes                     admin point-to-point auto\n  bpdu guard port     no                      bpdu guard error     no\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !state.Edge || state.PointToPoint != "auto" || state.BPDUGuard {
		t.Fatalf("parsed mstpd settings = %#v", state)
	}
	if _, err := parseMSTPPortSettings([]byte("bridge:swp1 CIST info\n  enabled yes\n")); err == nil {
		t.Fatal("incomplete mstpd state accepted")
	}
}

func TestParseTCFiltersCapturesMirredMonitorTarget(t *testing.T) {
	filters, err := parseTCFilters([]byte(`[{"pref":49100,"kind":"matchall","options":{"actions":[{"kind":"mirred","mirred_action":"mirror","direction":"egress","to_dev":"mon0"}]}}]`))
	if err != nil {
		t.Fatal(err)
	}
	want := TCFilterState{Priority: 49100, Kind: "matchall", NumVLANs: -1, MirrorDevice: "mon0", MirrorAction: "mirror", MirrorDirection: "egress"}
	if len(filters) != 1 || filters[0] != want {
		t.Fatalf("mirred filter state = %#v, want %#v", filters, want)
	}
}

func TestParseTCFiltersCapturesStormControlFlowerAndPolice(t *testing.T) {
	filters, err := parseTCFilters([]byte(`[{"pref":48020,"kind":"flower","stats":{"bytes":4096,"packets":32,"drops":7},"options":{"dst_mac":"01:00:00:00:00:00","dst_mac_mask":"01:00:00:00:00:00","actions":[{"kind":"police","rate":2000000,"burst":16384,"control_action":{"type":"drop"}}]}}]`))
	if err != nil {
		t.Fatal(err)
	}
	want := stormFilter(2_000_000, 16_384, true)
	want.Bytes, want.Packets, want.Drops = 4096, 32, 7
	if len(filters) != 1 {
		t.Fatalf("got %d filters", len(filters))
	}
	if filters[0] != want {
		t.Fatalf("storm filter = %#v, want %#v", filters[0], want)
	}
	if filters[0].Bytes != 4096 || filters[0].Packets != 32 || filters[0].Drops != 7 {
		t.Fatalf("policer counters were not parsed: %#v", filters[0])
	}
}

func withTCStats(filter TCFilterState, packets, bytes, drops uint64) TCFilterState {
	filter.Packets, filter.Bytes, filter.Drops = packets, bytes, drops
	return filter
}

func TestApplyStormControlStatusRequiresBothConfiguredClasses(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.StormControl = []StormControl{{Interface: "lan-b", BroadcastRateBPS: 1_000_000, MulticastRateBPS: 2_000_000, BurstBytes: 16_384}}
	broadcast, multicast := stormFilter(1_000_000, 16_384, false), stormFilter(2_000_000, 16_384, true)
	broadcast.Drops, multicast.Drops = 3, 7
	live := Capabilities{Interfaces: []HostInterface{{Name: "enp3s0", TCClsact: true, TCFilters: []TCFilterState{
		broadcast, multicast,
	}}}}
	applyStormControlStatus(&live, cfg)
	if len(live.StormControl) != 1 || !live.StormControl[0].Applied {
		t.Fatalf("matching filters not reported applied: %#v", live.StormControl)
	}
	if live.StormControl[0].BroadcastDrops != 3 || live.StormControl[0].MulticastDrops != 7 {
		t.Fatalf("policer drop counters not reported: %#v", live.StormControl[0])
	}
	live.Interfaces[0].TCFilters = live.Interfaces[0].TCFilters[:1]
	applyStormControlStatus(&live, cfg)
	if live.StormControl[1].Applied || live.StormControl[1].Reason == "" {
		t.Fatalf("missing multicast filter reported applied: %#v", live.StormControl[1])
	}
}

func TestApplyNetworkIsolationStatusRequiresExactOwnedRuleSet(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Networks[0].RouteInterface = "br-main.10"
	cfg.Networks[1].RouteInterface = "br-main.20"
	cfg.NetworkACL = []NetworkACLRule{{ID: "av-control", SourceNetwork: "default", DestinationNetwork: "voice", Protocol: "tcp", Port: 443}}
	counters := map[string][2]uint64{}
	for _, comment := range networkIsolationRuleComments(cfg) {
		counters[comment] = [2]uint64{}
	}
	caps := Capabilities{NetworkIsolationTablePresent: true, NetworkIsolationTableManaged: true, NetworkIsolationRuleCounters: counters}
	applyNetworkIsolationStatus(&caps, cfg)
	if len(caps.NetworkIsolation) != 1 || !caps.NetworkIsolation[0].Applied {
		t.Fatalf("matching isolation rules not reported active: %#v", caps.NetworkIsolation)
	}
	delete(counters, networkIsolationDenyComment(Network{ID: "voice", RouteInterface: "br-main.20"}, Network{ID: "default", RouteInterface: "br-main.10"}))
	caps.NetworkIsolation = nil
	applyNetworkIsolationStatus(&caps, cfg)
	if caps.NetworkIsolation[0].Applied || caps.NetworkIsolation[0].Reason == "" {
		t.Fatalf("missing default-deny rule reported active: %#v", caps.NetworkIsolation[0])
	}
}

func TestRenderNetworkIsolationTablePassesNftCheck(t *testing.T) {
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft is not installed")
	}
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Networks[0].RouteInterface, cfg.Networks[1].RouteInterface = "br-main.10", "br-main.20"
	cfg.NetworkACL = []NetworkACLRule{{ID: "allow-control", SourceNetwork: "default", DestinationNetwork: "voice", Protocol: "tcp", Port: 443}}
	script := renderNetworkIsolationTable(cfg, false)
	cmd := exec.Command("nft", "-c", "-f", "-")
	cmd.Stdin = bytes.NewReader(script)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft rejected generated isolation rules: %v\n%s\n%s", err, output, script)
	}
}

type routedIsolationSnapshotRunner struct{ capabilityRunner }

func (routedIsolationSnapshotRunner) Available(tool string) bool {
	return tool == "nft" || capabilityRunner{}.Available(tool)
}

func (routedIsolationSnapshotRunner) Run(_ context.Context, tool string, args ...string) ([]byte, error) {
	if tool != "nft" {
		return nil, nil
	}
	if len(args) >= 3 && args[0] == "-j" && args[1] == "list" && args[2] == "tables" {
		return []byte(`{"nftables":[{"table":{"family":"inet","name":"gamebond_l2_isolation"}}]}`), nil
	}
	if len(args) >= 5 && args[0] == "-j" && args[1] == "list" && args[2] == "table" {
		return []byte(`{"nftables":[{"table":{"family":"inet","name":"gamebond_l2_isolation","comment":"gamebond-l2-isolation:v1"}},{"chain":{"family":"inet","table":"gamebond_l2_isolation","name":"forward"}},{"rule":{"family":"inet","table":"gamebond_l2_isolation","chain":"forward","comment":"gamebond-l2-isolation:configured","expr":[{"counter":{"packets":4,"bytes":256}}]}}]}`), nil
	}
	return nil, nil
}

func (routedIsolationSnapshotRunner) RunInput(context.Context, string, []byte, ...string) ([]byte, error) {
	return nil, nil
}

func TestSnapshotNetworkIsolationStateRequiresOwnedTableAndRules(t *testing.T) {
	cfg := Config{Version: 1, Networks: []Network{
		{ID: "trusted", RouteInterface: "br-main.10"}, {ID: "media", RouteInterface: "br-main.20"},
	}, NetworkACL: []NetworkACLRule{{ID: "allow-api", SourceNetwork: "trusted", DestinationNetwork: "media", Protocol: "tcp", Port: 443}}}
	caps := Capabilities{Features: map[string]FeatureCapability{}}
	snapshotNetworkIsolationState(context.Background(), routedIsolationSnapshotRunner{}, &caps, cfg)
	if !caps.NetworkIsolationTablePresent || !caps.NetworkIsolationTableManaged {
		t.Fatalf("owned routed isolation table not recognized: %#v", caps)
	}
	if len(caps.NetworkIsolation) != 1 || caps.NetworkIsolation[0].Applied {
		t.Fatalf("partial rule set was reported applied: %#v", caps.NetworkIsolation)
	}
}

func TestEvaluateCapabilitiesReportsMissingTools(t *testing.T) {
	c := EvaluateCapabilities(Detection{KernelRelease: "6.12.0", Tools: map[string]bool{"ip": true}})
	if got := c.Features[FeatureBridgeVLAN]; got.State != CapabilityUnavailable || got.Reason == "" {
		t.Fatalf("bridge VLAN without bridge tool must be unavailable, got %#v", got)
	}
	if got := c.Features[FeatureFlowControl]; got.State != CapabilityUnavailable {
		t.Fatalf("flow control without ethtool must be unavailable, got %#v", got)
	}
	if got := c.Features[FeatureQoSDSCP]; got.State != CapabilityUnavailable {
		t.Fatalf("DSCP QoS without tc/ethtool must be unavailable, got %#v", got)
	}
	withTools := EvaluateCapabilities(Detection{Tools: map[string]bool{"tc": true, "ethtool": true}})
	if got := withTools.Features[FeatureQoSDSCP]; got.State != CapabilityConditional {
		t.Fatalf("DSCP QoS with tc/ethtool must be conditionally available, got %#v", got)
	}
}

func TestEvaluateCapabilitiesReportsRedundancyCoordinator(t *testing.T) {
	got := EvaluateCapabilities(Detection{}).Features[FeatureRedundancy]
	if got.State != CapabilityConditional || !strings.Contains(got.Reason, "coordinates") {
		t.Fatalf("redundancy capability = %#v, want conditional coordinator support", got)
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

func TestEvaluateCapabilitiesDoesNotClaimBPDUNodeGuardAsLoopProtection(t *testing.T) {
	c := EvaluateCapabilities(Detection{Tools: map[string]bool{"bridge": true}})
	got := c.Features[FeatureLoopProtect]
	if got.State != CapabilityUnsupported {
		t.Fatalf("Linux bridge BPDU guard must not be advertised as generic loop protection, got %#v", got)
	}
	for _, required := range []string{"loopback detection", "recovery timer"} {
		if !strings.Contains(got.Reason, required) {
			t.Fatalf("loop-protection reason %q does not explain missing %s", got.Reason, required)
		}
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
	withRSTP := EvaluateCapabilities(Detection{Tools: map[string]bool{"ip": true, "bridge": true, "mstpd": true, "mstpctl": true}})
	if got := withRSTP.Features[FeatureRSTP]; got.State != CapabilityConditional {
		t.Fatalf("RSTP with mstpd provider must be conditionally available, got %#v", got)
	}
	if got := c.Features[FeatureLLDPMED]; got.State != CapabilityUnavailable {
		t.Fatalf("LLDP-MED without provider must be unavailable, got %#v", got)
	}
	withLLDP := EvaluateCapabilities(Detection{Tools: map[string]bool{"bridge": true, "lldpd": true, "lldpcli": true, "systemctl": true}})
	if got := withLLDP.Features[FeatureLLDPMED]; got.State != CapabilityConditional {
		t.Fatalf("LLDP-MED with lldpd provider must be conditional, got %#v", got)
	}
	if got := withLLDP.Features[FeatureVoiceVLAN]; got.State != CapabilityConditional {
		t.Fatalf("Voice VLAN with lldpd and bridge providers must be conditional, got %#v", got)
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
func (capabilityRunner) Run(_ context.Context, tool string, args ...string) ([]byte, error) {
	if tool == "ip" {
		return []byte(`[{"ifname":"enp2s0","mtu":1500,"max_mtu":9000,"flags":["UP"]}]`), nil
	}
	if tool == "bridge" && len(args) >= 3 && args[1] == "mdb" {
		return []byte(`{"mdb":[],"router":{}}`), nil
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

type stpTuningSnapshotRunner struct{ capabilityRunner }

func (stpTuningSnapshotRunner) Run(_ context.Context, tool string, args ...string) ([]byte, error) {
	if tool == "ip" {
		return []byte(`[{"ifname":"br-main","mtu":1500,"flags":["UP"],"linkinfo":{"info_kind":"bridge","info_data":{"stp_state":1,"priority":8192}}},{"ifname":"enp2s0","mtu":1500,"master":"br-main"}]`), nil
	}
	if tool == "bridge" && len(args) >= 4 && args[2] == "link" {
		return []byte(`[{"ifname":"enp2s0","priority":24,"cost":300,"root_block":true}]`), nil
	}
	if tool == "bridge" && len(args) >= 3 && args[1] == "mdb" {
		return []byte(`{"mdb":[],"router":{}}`), nil
	}
	return []byte(`[]`), nil
}

type mstpStatusSnapshotRunner struct{ capabilityRunner }

func (mstpStatusSnapshotRunner) Available(tool string) bool {
	return tool == "mstpctl" || tool == "mstpd" || capabilityRunner{}.Available(tool)
}

func (mstpStatusSnapshotRunner) Run(_ context.Context, tool string, args ...string) ([]byte, error) {
	if tool == "ip" {
		return []byte(`[{"ifname":"br-main","mtu":1500,"flags":["UP"],"linkinfo":{"info_kind":"bridge","info_data":{"stp_state":1,"priority":8192}}},{"ifname":"enp2s0","mtu":1500,"master":"br-main"}]`), nil
	}
	if tool == "mstpctl" {
		if len(args) == 2 && args[0] == "showbridge" {
			return []byte("bridge CIST info\n force protocol version rstp\n"), nil
		}
		if len(args) == 3 && args[0] == "showbridge" {
			values := map[string]string{"designated-root": "8.000.00:11:22:33:44:55", "root-port": "enp2s0", "topology-change": "no", "topology-change-count": "7"}
			return []byte(values[args[2]]), nil
		}
		if len(args) == 3 && args[0] == "showportdetail" {
			return []byte("bridge:enp2s0 CIST info\n  admin edge port yes auto edge port yes\n  point-to-point yes admin point-to-point auto\n  bpdu guard port no bpdu guard error no\n"), nil
		}
		if len(args) == 4 && args[0] == "showport" {
			return []byte(map[string]string{"role": "Root", "state": "forwarding"}[args[3]]), nil
		}
	}
	return capabilityRunner{}.Run(context.Background(), tool, args...)
}

func TestSnapshotCapabilitiesReportsMSTPControllerAndPortState(t *testing.T) {
	edge := true
	cfg := Config{Version: 1, Interfaces: []Interface{{ID: "uplink", Name: "enp2s0"}}, Bridges: []Bridge{{ID: "main", Name: "br-main", STPMode: "rstp", Ports: []BridgePort{{Interface: "uplink", STPEdge: &edge}}}}}
	caps, err := SnapshotCapabilities(context.Background(), cfg, mstpStatusSnapshotRunner{})
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]HostInterface{}
	for _, iface := range caps.Interfaces {
		byName[iface.Name] = iface
	}
	bridge, port := byName["br-main"], byName["enp2s0"]
	if !bridge.STPControllerKnown || bridge.STPRootID != "8.000.00:11:22:33:44:55" || bridge.STPRootPort != "enp2s0" || bridge.STPTopologyChange || bridge.STPTopologyChanges != 7 {
		t.Fatalf("bridge MSTP state = %#v", bridge)
	}
	if !port.STPAdvancedKnown || !port.STPEdge || port.STPRole != "Root" || port.STPPortState != "forwarding" {
		t.Fatalf("port MSTP state = %#v", port)
	}
}

type competingSTPControllerSnapshotRunner struct{ mstpStatusSnapshotRunner }

func (competingSTPControllerSnapshotRunner) Available(tool string) bool {
	return tool == "systemctl" || mstpStatusSnapshotRunner{}.Available(tool)
}

func (competingSTPControllerSnapshotRunner) Run(ctx context.Context, tool string, args ...string) ([]byte, error) {
	if tool == "systemctl" {
		if len(args) == 4 && args[0] == "show" && args[3] == "rstpd.service" {
			return []byte("active\n"), nil
		}
		return []byte("inactive\n"), nil
	}
	return mstpStatusSnapshotRunner{}.Run(ctx, tool, args...)
}

func TestSnapshotCapabilitiesReportsActiveCompetingSTPController(t *testing.T) {
	cfg := Config{Version: 1, Interfaces: []Interface{{ID: "uplink", Name: "enp2s0"}}, Bridges: []Bridge{{ID: "main", Name: "br-main", STPMode: "rstp", Ports: []BridgePort{{Interface: "uplink"}}}}}
	caps, err := SnapshotCapabilities(context.Background(), cfg, competingSTPControllerSnapshotRunner{})
	if err != nil {
		t.Fatal(err)
	}
	if got := caps.Features[FeatureRSTP]; got.State != CapabilityUnavailable || !strings.Contains(got.Reason, "rstpd.service") {
		t.Fatalf("RSTP capability with competing controller = %#v", got)
	}
	raw, err := json.Marshal(caps)
	if err != nil {
		t.Fatal(err)
	}
	var status map[string]any
	if err := json.Unmarshal(raw, &status); err != nil {
		t.Fatal(err)
	}
	discovery, ok := status["stp_controller_discovery"].(map[string]any)
	if !ok || discovery["known"] != true || discovery["conflict"] != true || discovery["controller"] != "rstpd.service" {
		t.Fatalf("controller discovery status = %#v", discovery)
	}
}

type externalBridgeManagerSnapshotRunner struct {
	mstpStatusSnapshotRunner
	managed          string
	managedInterface string
}

func (externalBridgeManagerSnapshotRunner) Available(tool string) bool {
	return tool == "systemctl" || tool == "nmcli" || mstpStatusSnapshotRunner{}.Available(tool)
}

func (r externalBridgeManagerSnapshotRunner) Run(ctx context.Context, tool string, args ...string) ([]byte, error) {
	if tool == "systemctl" {
		if len(args) == 4 && args[0] == "show" && args[3] == "NetworkManager.service" {
			return []byte("active\n"), nil
		}
		return []byte("inactive\n"), nil
	}
	if tool == "nmcli" {
		if r.managedInterface != "" && len(args) == 5 {
			if args[4] == r.managedInterface {
				return []byte("yes\n"), nil
			}
			return []byte("no\n"), nil
		}
		return []byte(r.managed + "\n"), nil
	}
	return mstpStatusSnapshotRunner{}.Run(ctx, tool, args...)
}

func TestSnapshotCapabilitiesFailsClosedWithExternalBridgeManager(t *testing.T) {
	enabled := true
	cfg := Config{Version: 1, Interfaces: []Interface{{ID: "uplink", Name: "enp2s0"}}, Bridges: []Bridge{{ID: "main", Name: "br-main", STPEnabled: &enabled, Ports: []BridgePort{{Interface: "uplink"}}}}}
	caps, err := SnapshotCapabilities(context.Background(), cfg, externalBridgeManagerSnapshotRunner{managed: "yes"})
	if err != nil {
		t.Fatal(err)
	}
	if got := caps.Features[FeatureSTP]; got.State != CapabilityUnavailable || !strings.Contains(got.Reason, "NetworkManager.service") {
		t.Fatalf("STP capability with external bridge manager = %#v", got)
	}
	if discovery := caps.STPControllerDiscovery; discovery == nil || discovery.Known || !strings.Contains(discovery.Reason, "exclusive bridge STP ownership") {
		t.Fatalf("STP ownership discovery = %#v, want unknown/exclusive ownership refusal", discovery)
	}
}

func TestSnapshotCapabilitiesIgnoresActiveManagerOnUnmanagedTargets(t *testing.T) {
	enabled := true
	cfg := Config{Version: 1, Interfaces: []Interface{{ID: "uplink", Name: "enp2s0"}}, Bridges: []Bridge{
		{ID: "main", Name: "br-main", STPEnabled: &enabled, Ports: []BridgePort{{Interface: "uplink"}}},
		{ID: "other", Name: "br-other", Ports: []BridgePort{}},
	}}
	caps, err := SnapshotCapabilities(context.Background(), cfg, externalBridgeManagerSnapshotRunner{managedInterface: "br-other"})
	if err != nil {
		t.Fatal(err)
	}
	if discovery := caps.STPControllerDiscovery; discovery == nil || !discovery.Known || discovery.Conflict {
		t.Fatalf("unrelated active manager blocked GameBond bridge: %#v", discovery)
	}
}

func TestSnapshotCapabilitiesReportsSTPBridgeAndPortTuning(t *testing.T) {
	caps, err := SnapshotCapabilities(context.Background(), Config{Version: 1}, stpTuningSnapshotRunner{})
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]HostInterface{}
	for _, iface := range caps.Interfaces {
		byName[iface.Name] = iface
	}
	bridge, port := byName["br-main"], byName["enp2s0"]
	if !bridge.STPPriorityKnown || bridge.STPPriority != 8192 {
		t.Fatalf("bridge STP priority = %#v", bridge)
	}
	if !port.STPPortKnown || port.STPPortPriority != 24 || port.STPPathCost != 300 || !port.STPRootBlock {
		t.Fatalf("port STP state = %#v", port)
	}
}

func (isolationSnapshotRunner) Run(_ context.Context, tool string, args ...string) ([]byte, error) {
	if tool == "ip" {
		return []byte(`[{"ifname":"enp2s0","mtu":1500,"max_mtu":9000,"flags":["UP"]}]`), nil
	}
	if tool == "bridge" && len(args) >= 4 && args[2] == "link" {
		return []byte(`[{"ifname":"enp2s0","isolated":true}]`), nil
	}
	if tool == "bridge" && len(args) >= 3 && args[1] == "mdb" {
		return []byte(`{"mdb":[],"router":{}}`), nil
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

func TestParseEthtoolLinkSpeedRejectsUnknownAndParsesUnits(t *testing.T) {
	speed, err := parseEthtoolLinkSpeed([]byte("Settings for enp3s0:\n\tSpeed: 2.5Gb/s\n"))
	if err != nil || speed != 2_500_000_000 {
		t.Fatalf("parsed speed = %d, error = %v", speed, err)
	}
	if _, err := parseEthtoolLinkSpeed([]byte("Settings for enp3s0:\n\tSpeed: Unknown!\n")); err == nil {
		t.Fatal("unknown speed reported as usable")
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
