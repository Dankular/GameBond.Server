package layer2

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestBuildTopologyPlanCreatesVLANBridgeInDependencyOrder(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Overrides = nil
	host := Capabilities{Features: map[string]FeatureCapability{
		FeatureBridgeVLAN: {State: CapabilityConditional},
	}, Interfaces: []HostInterface{
		{Name: "enp2s0", MTU: 1500, AdminUp: true},
		{Name: "enp3s0", MTU: 1500, AdminUp: true},
	}}
	previous := cfg
	previous.MACPortRestrictions = nil
	plan, err := BuildTopologyPlan(previous, cfg, host)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Changes) < 8 {
		t.Fatalf("expected bridge, port, and VLAN operations, got %d", len(plan.Changes))
	}
	if got := strings.Join(plan.Changes[0].Apply.Args, " "); got != "link add name br-main type bridge vlan_filtering 1" {
		t.Fatalf("first operation must create a VLAN-filtering bridge, got %q", got)
	}
	wantPortVLAN := []string{"vlan", "add", "dev", "enp2s0", "vid", "10", "pvid", "untagged"}
	found := false
	for _, change := range plan.Changes {
		if change.Apply.Tool == "bridge" && reflect.DeepEqual(change.Apply.Args, wantPortVLAN) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("missing access VLAN operation %q", strings.Join(wantPortVLAN, " "))
	}
}

func TestBuildTopologyPlanRejectsUnmanagedBridge(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Overrides = nil
	host := Capabilities{Features: map[string]FeatureCapability{FeatureBridgeVLAN: {State: CapabilityConditional}},
		Interfaces: []HostInterface{{Name: "br-main", Kind: "bridge", MTU: 1500}}}
	if _, err := BuildTopologyPlan(Config{}, cfg, host); err == nil || !strings.Contains(err.Error(), "unmanaged") {
		t.Fatalf("expected refusal to adopt an unmanaged bridge, got %v", err)
	}
}

func TestBuildTopologyPlanRejectsUnmanagedPortMaster(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Overrides = nil
	host := Capabilities{Features: map[string]FeatureCapability{FeatureBridgeVLAN: {State: CapabilityConditional}},
		Interfaces: []HostInterface{{Name: "enp2s0", Master: "br-external", MTU: 1500}, {Name: "enp3s0", MTU: 1500}}}
	if _, err := BuildTopologyPlan(Config{}, cfg, host); err == nil || !strings.Contains(err.Error(), "unmanaged master") {
		t.Fatalf("expected refusal to steal an unmanaged port, got %v", err)
	}
}

const lacpConfig = `{"version":1,"interfaces":[{"id":"bond0","name":"bond0"},{"id":"member-a","name":"enp2s0"},{"id":"member-b","name":"enp3s0"}],"bonds":[{"id":"uplink","interface":"bond0","members":["member-a","member-b"],"min_links":1,"lacp_rate":"fast","hash_policy":"layer2+3"}]}`

func TestBuildTopologyPlanCreatesLACPBeforeAttachingMembers(t *testing.T) {
	cfg, err := DecodeConfig([]byte(lacpConfig))
	if err != nil {
		t.Fatal(err)
	}
	host := Capabilities{Features: map[string]FeatureCapability{FeatureLACP: {State: CapabilityConditional}}, Interfaces: []HostInterface{
		{Name: "enp2s0", MTU: 1500, AdminUp: true}, {Name: "enp3s0", MTU: 1500, AdminUp: true},
	}}
	plan, err := BuildTopologyPlan(Config{}, cfg, host)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Changes) < 8 {
		t.Fatalf("expected bond creation and member lifecycle operations, got %d", len(plan.Changes))
	}
	if got := plan.Changes[0].Apply.Tool + " " + strings.Join(plan.Changes[0].Apply.Args, " "); got != "ip link add name bond0 type bond mode 802.3ad miimon 100 lacp_rate fast xmit_hash_policy layer2+3 min_links 1" {
		t.Fatalf("first operation must create a configured 802.3ad bond, got %q", got)
	}
	attach, bringUp := -1, -1
	for i, change := range plan.Changes {
		args := strings.Join(change.Apply.Args, " ")
		if strings.Contains(args, "dev enp2s0 master bond0") {
			attach = i
		}
		if strings.Contains(args, "dev bond0 up") {
			bringUp = i
		}
	}
	if attach < 0 || bringUp < attach {
		t.Fatalf("bond must attach members before bringing bond up: attach=%d up=%d", attach, bringUp)
	}
}

func TestBuildTopologyPlanRejectsLACPMemberOwnedByAnotherMaster(t *testing.T) {
	cfg, err := DecodeConfig([]byte(lacpConfig))
	if err != nil {
		t.Fatal(err)
	}
	host := Capabilities{Features: map[string]FeatureCapability{FeatureLACP: {State: CapabilityConditional}}, Interfaces: []HostInterface{
		{Name: "enp2s0", Master: "br-existing", MTU: 1500}, {Name: "enp3s0", MTU: 1500},
	}}
	if _, err := BuildTopologyPlan(Config{}, cfg, host); err == nil || !strings.Contains(err.Error(), "already attached to master") {
		t.Fatalf("expected rejection of conflicting LACP member, got %v", err)
	}
}

func TestVerifyBondsRequiresNegotiatedPartnerAndActiveLinks(t *testing.T) {
	cfg, err := DecodeConfig([]byte(lacpConfig))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBonds(cfg, Capabilities{Bonds: []BondStatus{{ID: "uplink", Reason: "no active LACP partner is negotiated"}}}); err == nil || !strings.Contains(err.Error(), "not active") {
		t.Fatalf("bond without peer negotiation must fail verification, got %v", err)
	}
	if err := VerifyBonds(cfg, Capabilities{Bonds: []BondStatus{{ID: "uplink", Applied: true, PartnerSystem: "02:00:00:00:00:10", ActiveMembers: 2}}}); err != nil {
		t.Fatalf("negotiated active bond should verify: %v", err)
	}
}

func TestBuildTopologyPlanAppliesPortIsolationWithRollback(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Overrides = nil
	cfg.Bridges[0].Ports[0].Isolated = true
	host := Capabilities{Features: map[string]FeatureCapability{
		FeatureBridgeVLAN: {State: CapabilityConditional}, FeaturePortIsolation: {State: CapabilityConditional},
	}, Interfaces: []HostInterface{{Name: "enp2s0", MTU: 1500, IsolationKnown: true}, {Name: "enp3s0", MTU: 1500, IsolationKnown: true}}}
	plan, err := BuildTopologyPlan(Config{}, cfg, host)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, change := range plan.Changes {
		if change.Apply.Tool == "bridge" && strings.Join(change.Apply.Args, " ") == "link set dev enp2s0 isolated on" {
			found = true
			if got := strings.Join(change.Rollback.Args, " "); got != "link set dev enp2s0 isolated off" {
				t.Fatalf("rollback = %q", got)
			}
		}
	}
	if !found {
		t.Fatal("expected bridge port isolation operation")
	}
}

func TestBuildTopologyPlanEnforcesMACPortRestriction(t *testing.T) {
	input := strings.Replace(validConfig, `{"interface":"lan-a","untagged_network":"default","tagged_networks":["voice"]},`, ``, 1)
	input = strings.TrimSuffix(input, `}`) + `,"mac_port_restrictions":[{"interface":"lan-b","network":"default","allowed_macs":["02:00:00:00:00:02"],"max_devices":4,"violation_action":"drop"}]}`
	cfg, err := DecodeConfig([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Overrides = nil
	host := Capabilities{Features: map[string]FeatureCapability{FeatureBridgeVLAN: {State: CapabilityConditional}, FeatureMACPort: {State: CapabilityConditional}},
		Interfaces: []HostInterface{{Name: "br-main", Kind: "bridge", MTU: 1500, FDBLimitKnown: true}, {Name: "enp3s0", Master: "br-main", MTU: 1500, BridgePortKnown: true}}}
	previous := cfg
	previous.MACPortRestrictions = nil
	plan, err := BuildTopologyPlan(previous, cfg, host)
	if err != nil {
		t.Fatal(err)
	}
	var fdb, locked, limit bool
	for _, change := range plan.Changes {
		cmd := change.Apply.Tool + " " + strings.Join(change.Apply.Args, " ")
		fdb = fdb || cmd == "bridge fdb replace 02:00:00:00:00:02 dev enp3s0 master static vlan 10"
		locked = locked || cmd == "bridge link set dev enp3s0 locked on"
		limit = limit || cmd == "ip link set dev br-main type bridge fdb_max_learned 4"
	}
	if !fdb || !locked || !limit {
		t.Fatalf("restriction plan lacks enforcement (fdb=%t locked=%t limit=%t)", fdb, locked, limit)
	}
}

func TestBuildTopologyPlanCompilesScopedMACBlockIntoAtomicNFTScript(t *testing.T) {
	input := strings.Replace(validConfig, `{"interface":"lan-a","untagged_network":"default","tagged_networks":["voice"]},`, ``, 1)
	input = strings.TrimSuffix(input, `}`) + `,"mac_address_blocks":[{"interface":"lan-b","network":"default","mac":"02:00:00:00:00:03"}]}`
	cfg, err := DecodeConfig([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Overrides = nil
	previous := cfg
	previous.MACBlocks = nil
	host := Capabilities{Features: map[string]FeatureCapability{FeatureBridgeVLAN: {State: CapabilityConditional}, FeatureMACBlock: {State: CapabilityConditional}},
		Interfaces: []HostInterface{{Name: "br-main", Kind: "bridge", MTU: 1500}, {Name: "enp3s0", Master: "br-main", MTU: 1500}}}
	plan, err := BuildTopologyPlan(previous, cfg, host)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, change := range plan.Changes {
		if change.Apply.Tool != "nft" || change.Apply.Input == nil {
			continue
		}
		found = true
		script := string(change.Apply.Input)
		for _, want := range []string{"add table bridge gamebond_mac_block", "hook forward", "hook input", "hook output", "iifname \"enp3s0\" ether saddr 02:00:00:00:00:03", "oifname \"enp3s0\" ether daddr 02:00:00:00:00:03", "counter drop"} {
			if !strings.Contains(script, want) {
				t.Errorf("nft transaction missing %q: %s", want, script)
			}
		}
		if change.Rollback.Input == nil || !strings.Contains(string(change.Rollback.Input), "delete table bridge gamebond_mac_block") {
			t.Fatal("rollback must remove the newly-owned table")
		}
	}
	if !found {
		t.Fatal("expected atomic nft script change")
	}
}

func TestBuildTopologyPlanPreservesOrderedScopedMACACL(t *testing.T) {
	input := strings.Replace(validConfig, `{"interface":"lan-a","untagged_network":"default","tagged_networks":["voice"]},`, ``, 1)
	input = strings.TrimSuffix(input, `}`) + `,"mac_acls":[{"id":"deny-first","interface":"lan-b","network":"default","direction":"ingress","source_mac":"02:00:00:00:00:04","action":"deny"},{"id":"allow-second","interface":"lan-b","network":"default","direction":"egress","destination_mac":"02:00:00:00:00:05","action":"allow"}]}`
	cfg, err := DecodeConfig([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Overrides = nil
	previous := cfg
	previous.MACACL = nil
	host := Capabilities{Features: map[string]FeatureCapability{FeatureBridgeVLAN: {State: CapabilityConditional}, FeatureMACACL: {State: CapabilityConditional}}, Interfaces: []HostInterface{{Name: "br-main", Kind: "bridge", MTU: 1500}, {Name: "enp3s0", Master: "br-main", MTU: 1500}}}
	plan, err := BuildTopologyPlan(previous, cfg, host)
	if err != nil {
		t.Fatal(err)
	}
	var script string
	for _, change := range plan.Changes {
		if change.Apply.Tool == "nft" && change.Apply.Input != nil {
			script = string(change.Apply.Input)
		}
	}
	first := strings.Index(script, "gamebond-mac-acl:deny-first:forward-in")
	second := strings.Index(script, "gamebond-mac-acl:allow-second:forward-out")
	if first < 0 || second < 0 || first >= second {
		t.Fatalf("ACL order was not preserved: %s", script)
	}
	for _, want := range []string{"iifname \"enp3s0\" ether saddr 02:00:00:00:00:04 counter drop", "oifname \"enp3s0\" ether daddr 02:00:00:00:00:05 counter accept", "priority -190"} {
		if !strings.Contains(script, want) {
			t.Errorf("MAC ACL script missing %q: %s", want, script)
		}
	}
}

func TestBuildTopologyPlanCompilesIPACLAtomically(t *testing.T) {
	previous, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	desired := previous
	desired.Overrides = nil
	desired.IPACL = []IPACLRule{{ID: "web", Interface: "lan-b", Network: "default", Direction: "ingress", Family: "ipv4", Source: "192.0.2.0/24", Protocol: "tcp", Port: 443, Action: "allow"}}
	previous.IPACL = nil
	host := Capabilities{Features: map[string]FeatureCapability{FeatureBridgeVLAN: {State: CapabilityConditional}, FeatureIPACL: {State: CapabilityConditional}}, Interfaces: []HostInterface{{Name: "br-main", Kind: "bridge", MTU: 1500}, {Name: "enp2s0", Master: "br-main", MTU: 1500}, {Name: "enp3s0", Master: "br-main", MTU: 1500}}}
	plan, err := BuildTopologyPlan(previous, desired, host)
	if err != nil {
		t.Fatal(err)
	}
	var input string
	for _, change := range plan.Changes {
		if change.Description == "apply ordered GameBond IP ACL" {
			input = string(change.Apply.Input)
		}
	}
	for _, want := range []string{"add table bridge gamebond_ip_acl", "ip saddr 192.0.2.0/24", "meta l4proto tcp", "th dport 443", "counter accept", "gamebond-ip-acl:web:in"} {
		if !strings.Contains(input, want) {
			t.Fatalf("IP ACL script missing %q: %s", want, input)
		}
	}
}

func TestBuildTopologyPlanRequiresUnmanagedFreeRootForEgressTBF(t *testing.T) {
	previous, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	desired := previous
	desired.Overrides = nil
	desired.EgressRates = []EgressRateLimit{{Interface: "lan-b", RateBPS: 10_000_000, BurstBytes: 16_384}}
	previous.EgressRates = nil
	host := Capabilities{Features: map[string]FeatureCapability{FeatureBridgeVLAN: {State: CapabilityConditional}, FeatureEgressRate: {State: CapabilityConditional}}, Interfaces: []HostInterface{{Name: "br-main", Kind: "bridge", MTU: 1500}, {Name: "enp2s0", Master: "br-main", MTU: 1500, RootQdisc: "noqueue"}, {Name: "enp3s0", Master: "br-main", MTU: 1500, RootQdisc: "noqueue"}}}
	plan, err := BuildTopologyPlan(previous, desired, host)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range plan.Changes {
		if c.Description == "apply egress TBF rate on lan-b" {
			found = true
			if !reflect.DeepEqual(c.Apply.Args, []string{"qdisc", "replace", "dev", "enp3s0", "root", "handle", "7fff:", "tbf", "rate", "10000000bit", "burst", "16384b", "latency", "50ms"}) {
				t.Fatalf("TBF command = %#v", c.Apply.Args)
			}
		}
	}
	if !found {
		t.Fatal("missing egress TBF change")
	}
	host.Interfaces[2].RootQdisc = "mq"
	if _, err := BuildTopologyPlan(previous, desired, host); err == nil || !strings.Contains(err.Error(), "unmanaged-free noqueue") {
		t.Fatalf("expected unmanaged qdisc rejection, got %v", err)
	}
}

func TestEgressRatePlanIsIdempotentAfterApplyAndRemoval(t *testing.T) {
	previous, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	desired := previous
	desired.Overrides = nil
	desired.EgressRates = []EgressRateLimit{{Interface: "lan-b", RateBPS: 20_000_000, BurstBytes: 32_768}}
	previous.EgressRates = nil
	host := Capabilities{Features: map[string]FeatureCapability{FeatureBridgeVLAN: {State: CapabilityConditional}, FeatureEgressRate: {State: CapabilityConditional}}, Interfaces: []HostInterface{{Name: "br-main", Kind: "bridge", MTU: 1500}, {Name: "enp2s0", Master: "br-main", MTU: 1500, RootQdisc: "noqueue"}, {Name: "enp3s0", Master: "br-main", MTU: 1500, RootQdisc: "noqueue"}}}
	if _, err := BuildTopologyPlan(previous, desired, host); err != nil {
		t.Fatal(err)
	}
	host.Interfaces[2].RootQdisc = "tbf"
	host.Interfaces[2].RootQdiscRateBPS = desired.EgressRates[0].RateBPS
	host.Interfaces[2].RootQdiscBurstBytes = desired.EgressRates[0].BurstBytes
	plan, err := BuildTopologyPlan(previous, desired, host)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range plan.Changes {
		if strings.Contains(change.Description, "egress TBF") {
			t.Fatalf("already-applied TBF remained in plan: %#v", change)
		}
	}
	removed := desired
	removed.EgressRates = nil
	plan, err = BuildTopologyPlan(desired, removed, host)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, change := range plan.Changes {
		if strings.Contains(change.Description, "egress TBF") {
			found = true
		}
	}
	if !found {
		t.Fatal("missing TBF removal")
	}
	host.Interfaces[2].RootQdisc = "noqueue"
	host.Interfaces[2].RootQdiscRateBPS = 0
	host.Interfaces[2].RootQdiscBurstBytes = 0
	plan, err = BuildTopologyPlan(desired, removed, host)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range plan.Changes {
		if strings.Contains(change.Description, "egress TBF") {
			t.Fatalf("removed TBF remained in plan: %#v", change)
		}
	}
}

func TestBuildTopologyPlanInstallsTaggedNetworkEgressPolicerOnClsact(t *testing.T) {
	previous, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	desired := previous
	desired.Overrides = nil
	desired.EgressRates = []EgressRateLimit{{Interface: "lan-a", Network: "voice", RateBPS: 500_000_000, BurstBytes: 65_536}}
	previous.EgressRates = nil
	host := Capabilities{Features: map[string]FeatureCapability{FeatureBridgeVLAN: {State: CapabilityConditional}, FeatureEgressRate: {State: CapabilityConditional}}, Interfaces: []HostInterface{{Name: "br-main", Kind: "bridge", MTU: 1500}, {Name: "enp2s0", Master: "br-main", MTU: 1500, RootQdisc: "noqueue"}, {Name: "enp3s0", Master: "br-main", MTU: 1500, RootQdisc: "noqueue"}}}
	plan, err := BuildTopologyPlan(previous, desired, host)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"filter", "replace", "dev", "enp2s0", "egress", "pref", "45020", "protocol", "802.1Q", "flower", "skip_hw", "vlan_id", "20", "action", "police", "rate", "500000000bit", "burst", "65536b", "drop"}
	found := false
	for _, change := range plan.Changes {
		if change.Description == "apply network egress rate on lan-a/voice" {
			found = true
			if !reflect.DeepEqual(change.Apply.Args, want) {
				t.Fatalf("network policer args = %#v", change.Apply.Args)
			}
		}
	}
	if !found {
		t.Fatal("network egress policer missing")
	}
	host.Interfaces[1].TCClsact = true
	host.Interfaces[1].TCEgressFilters = []TCFilterState{{Priority: 45020, Kind: "flower", VLANID: 20, PoliceRateBPS: 500_000_000, PoliceBurstBytes: 65_536}}
	plan, err = BuildTopologyPlan(previous, desired, host)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range plan.Changes {
		if change.Description == "apply network egress rate on lan-a/voice" {
			t.Fatalf("active network policer remained in plan: %#v", change)
		}
	}
}

func TestFlowControlPlanAppliesAndRestoresExactSettings(t *testing.T) {
	previous := Config{Version: 1, Interfaces: []Interface{{ID: "lan", Name: "enp2s0"}}}
	desired := previous
	desired.FlowControl = []FlowControlPolicy{{Interface: "lan", Autoneg: "off", RX: true, TX: false}}
	host := map[string]HostInterface{"enp2s0": {Name: "enp2s0", PauseKnown: true, PauseAutoneg: "on", PauseRX: false, PauseTX: false}}
	changes, err := buildFlowControlChanges(previous, desired, host)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || !reflect.DeepEqual(changes[0].Apply.Args, []string{"--pause", "enp2s0", "autoneg", "off", "rx", "on", "tx", "off"}) || !reflect.DeepEqual(changes[0].Rollback.Args, []string{"--pause", "enp2s0", "autoneg", "on", "rx", "off", "tx", "off"}) {
		t.Fatalf("flow-control change = %#v", changes)
	}
	removed := previous
	changes, err = buildFlowControlChanges(desired, removed, map[string]HostInterface{"enp2s0": {Name: "enp2s0", PauseKnown: true, PauseAutoneg: "off", PauseRX: true, PauseTX: false}})
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || !reflect.DeepEqual(changes[0].Apply.Args, []string{"--pause", "enp2s0", "autoneg", "on", "rx", "on", "tx", "on"}) {
		t.Fatalf("flow-control removal does not restore autoneg defaults: %#v", changes)
	}
	changes, err = buildFlowControlChanges(desired, removed, map[string]HostInterface{"enp2s0": {Name: "enp2s0", PauseKnown: true, PauseAutoneg: "on", PauseRX: true, PauseTX: true}})
	if err != nil || len(changes) != 0 {
		t.Fatalf("flow-control removal is not idempotent: %#v, err=%v", changes, err)
	}
}

func TestFlowControlRejectsBondMemberAndUnknownPauseState(t *testing.T) {
	cfg := Config{Version: 1, Interfaces: []Interface{{ID: "member", Name: "enp2s0"}}, FlowControl: []FlowControlPolicy{{Interface: "member", Autoneg: "on"}}}
	if _, err := buildFlowControlChanges(Config{Version: 1}, cfg, map[string]HostInterface{"enp2s0": {Name: "enp2s0", Master: "bond0"}, "bond0": {Name: "bond0", Kind: "bond"}}); err == nil || !strings.Contains(err.Error(), "aggregate member") {
		t.Fatalf("expected bond-member rejection, got %v", err)
	}
	if _, err := buildFlowControlChanges(Config{Version: 1}, cfg, map[string]HostInterface{"enp2s0": {Name: "enp2s0"}}); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("expected unknown driver support rejection, got %v", err)
	}
}

type scriptedPlanRunner struct{ calls []string }

func (r *scriptedPlanRunner) Available(string) bool { return true }
func (r *scriptedPlanRunner) Run(_ context.Context, tool string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, tool+" "+strings.Join(args, " "))
	return nil, nil
}
func (r *scriptedPlanRunner) RunInput(_ context.Context, tool string, input []byte, args ...string) ([]byte, error) {
	r.calls = append(r.calls, tool+" "+strings.Join(args, " ")+" < "+string(input))
	return nil, nil
}

func TestApplyPlanUsesInputBoundaryForAtomicProviderScripts(t *testing.T) {
	runner := &scriptedPlanRunner{}
	plan := Plan{Changes: []Change{{Description: "nft policy", Apply: Command{Tool: "nft", Args: []string{"-f", "-"}, Input: []byte("add table bridge test\n")}, Rollback: Command{Tool: "nft", Args: []string{"-f", "-"}, Input: []byte("delete table bridge test\n")}}}}
	if err := ApplyPlan(context.Background(), runner, plan); err != nil {
		t.Fatal(err)
	}
	if err := RollbackPlan(context.Background(), runner, plan); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 2 || !strings.Contains(runner.calls[0], "add table") || !strings.Contains(runner.calls[1], "delete table") {
		t.Fatalf("provider scripts did not pass through stdin boundary: %#v", runner.calls)
	}
}

func TestBuildTopologyPlanRejectsJumboMTUWhenHostMaximumIsUnknown(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Overrides = nil
	for i := range cfg.Networks {
		cfg.Networks[i].MTU = 9000
	}
	host := Capabilities{Features: map[string]FeatureCapability{FeatureBridgeVLAN: {State: CapabilityConditional}},
		Interfaces: []HostInterface{{Name: "enp2s0", MTU: 1500}, {Name: "enp3s0", MTU: 1500}}}
	if _, err := BuildTopologyPlan(Config{}, cfg, host); err == nil || !strings.Contains(err.Error(), "maximum MTU") {
		t.Fatalf("jumbo MTU with unknown interface maximum must be rejected, got %v", err)
	}
}

func TestBuildTopologyPlanAppliesJumboMTUWithinEveryPortMaximum(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Overrides = nil
	for i := range cfg.Networks {
		cfg.Networks[i].MTU = 9000
	}
	host := Capabilities{Features: map[string]FeatureCapability{FeatureBridgeVLAN: {State: CapabilityConditional}},
		Interfaces: []HostInterface{{Name: "enp2s0", MTU: 1500, MaxMTU: 9000}, {Name: "enp3s0", MTU: 1500, MaxMTU: 9000}}}
	plan, err := BuildTopologyPlan(Config{}, cfg, host)
	if err != nil {
		t.Fatal(err)
	}
	seenBridgeMTU, seenPortMTUs := false, 0
	for _, change := range plan.Changes {
		if change.Apply.Tool != "ip" || len(change.Apply.Args) < 6 {
			continue
		}
		args := strings.Join(change.Apply.Args, " ")
		if strings.Contains(args, "mtu 9000") && strings.Contains(args, "br-main") {
			seenBridgeMTU = true
		}
		if strings.Contains(args, "mtu 9000") && (strings.Contains(args, "enp2s0") || strings.Contains(args, "enp3s0")) {
			seenPortMTUs++
		}
	}
	if !seenBridgeMTU || seenPortMTUs != 2 {
		t.Fatalf("jumbo MTU must be applied to bridge and both ports; bridge=%t ports=%d", seenBridgeMTU, seenPortMTUs)
	}
}

func TestBuildTopologyPlanRejectsExistingBridgeWithUnknownMaximumMTU(t *testing.T) {
	previous, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	previous.Overrides = nil
	desired := previous
	desired.Networks = append([]Network(nil), previous.Networks...)
	for i := range desired.Networks {
		desired.Networks[i].MTU = 9000
	}
	host := Capabilities{Features: map[string]FeatureCapability{FeatureBridgeVLAN: {State: CapabilityConditional}},
		Interfaces: []HostInterface{
			{Name: "br-main", Kind: "bridge", MTU: 1500},
			{Name: "enp2s0", Master: "br-main", MTU: 1500, MaxMTU: 9000},
			{Name: "enp3s0", Master: "br-main", MTU: 1500, MaxMTU: 9000},
		}}
	if _, err := BuildTopologyPlan(previous, desired, host); err == nil || !strings.Contains(err.Error(), "maximum MTU") {
		t.Fatalf("jumbo MTU with unknown bridge maximum must be rejected, got %v", err)
	}
}

func TestBuildTopologyPlanInstallsScopedVirtualNetworkOverride(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	host := Capabilities{Features: map[string]FeatureCapability{
		FeatureBridgeVLAN: {State: CapabilityConditional}, FeatureVirtualNet: {State: CapabilityConditional},
	}, Interfaces: []HostInterface{{Name: "enp2s0", MTU: 1500}, {Name: "enp3s0", MTU: 1500}}}
	plan, err := BuildTopologyPlan(Config{}, cfg, host)
	if err != nil {
		t.Fatal(err)
	}
	var qdisc, dropTagged, overrideFilter, targetVLAN bool
	for _, change := range plan.Changes {
		command := change.Apply.Tool + " " + strings.Join(change.Apply.Args, " ")
		qdisc = qdisc || command == "tc qdisc add dev enp3s0 clsact"
		dropTagged = dropTagged || strings.Contains(command, "filter add dev enp3s0 ingress") && strings.Contains(command, "num_of_vlans 1") && strings.Contains(command, "action drop")
		overrideFilter = overrideFilter || strings.Contains(command, "filter add dev enp3s0 ingress") && strings.Contains(command, "src_mac 02:00:00:00:00:01") && strings.Contains(command, "vlan push") && strings.Contains(command, "id 20")
		targetVLAN = targetVLAN || command == "bridge vlan add dev enp3s0 vid 20"
	}
	if !qdisc || !dropTagged || !overrideFilter || !targetVLAN {
		t.Fatalf("override plan missing required operations: qdisc=%t drop=%t filter=%t vlan=%t", qdisc, dropTagged, overrideFilter, targetVLAN)
	}
}

func TestBuildTopologyPlanIsEmptyForVerifiedOverrideState(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	filters := expectedOverrideFilters(cfg)
	host := Capabilities{Features: map[string]FeatureCapability{
		FeatureBridgeVLAN: {State: CapabilityConditional}, FeatureVirtualNet: {State: CapabilityConditional},
	}, Interfaces: []HostInterface{
		{Name: "br-main", Kind: "bridge", MTU: 1500, AdminUp: true, VLANFiltering: true},
		{Name: "enp2s0", Master: "br-main", MTU: 1500, AdminUp: true},
		{Name: "enp3s0", Master: "br-main", MTU: 1500, AdminUp: true, TCClsact: true, TCFilters: filters["enp3s0"]},
	}, BridgeVLANs: []BridgeVLANState{
		{Device: "br-main", VLAN: 10}, {Device: "br-main", VLAN: 20},
		{Device: "enp2s0", VLAN: 10, PVID: true, Untagged: true}, {Device: "enp2s0", VLAN: 20},
		{Device: "enp3s0", VLAN: 10, PVID: true, Untagged: true}, {Device: "enp3s0", VLAN: 20},
	}}
	plan, err := BuildTopologyPlan(cfg, cfg, host)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Changes) != 0 {
		t.Fatalf("verified topology should produce no changes, got %#v", plan.Changes)
	}
}

func TestBuildTopologyPlanRejectsUnmanagedFilterInReservedPriority(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	host := Capabilities{Features: map[string]FeatureCapability{
		FeatureBridgeVLAN: {State: CapabilityConditional}, FeatureVirtualNet: {State: CapabilityConditional},
	}, Interfaces: []HostInterface{
		{Name: "enp2s0", MTU: 1500},
		{Name: "enp3s0", MTU: 1500, TCClsact: true, TCFilters: []TCFilterState{{Priority: 1, Kind: "flower", NumVLANs: 1, HasNumVLANs: true}}},
	}}
	if _, err := BuildTopologyPlan(Config{Version: 1}, cfg, host); err == nil || !strings.Contains(err.Error(), "unmanaged ingress filter") {
		t.Fatalf("unmanaged ingress filter must be preserved and reported, got %v", err)
	}
}

type planRunner struct {
	calls    []string
	failAt   map[int]bool
	cancel   context.CancelFunc
	cancelAt int
}

func (r *planRunner) Available(string) bool { return true }
func (r *planRunner) Run(ctx context.Context, tool string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, tool+" "+strings.Join(args, " "))
	if len(r.calls) == r.cancelAt && r.cancel != nil {
		r.cancel()
	}
	if r.failAt[len(r.calls)] {
		return nil, errors.New("injected failure")
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return nil, nil
}

func TestApplyPlanRollsBackInReverseOrderAfterContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	runner := &planRunner{failAt: map[int]bool{2: true}, cancel: cancel, cancelAt: 2}
	plan := Plan{Changes: []Change{
		{Description: "create", Apply: Command{Tool: "ip", Args: []string{"link", "add"}}, Rollback: Command{Tool: "ip", Args: []string{"link", "del"}}},
		{Description: "attach", Apply: Command{Tool: "ip", Args: []string{"link", "set"}}, Rollback: Command{Tool: "ip", Args: []string{"link", "set", "nomaster"}}},
	}}
	err := ApplyPlan(ctx, runner, plan)
	if err == nil || !strings.Contains(err.Error(), "injected failure") {
		t.Fatalf("expected the original operation failure, got %v", err)
	}
	want := []string{"ip link add", "ip link set", "ip link del"}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("operations did not roll back in reverse order after cancellation: got %v want %v", runner.calls, want)
	}
}

func TestApplyPlanReportsRollbackFailure(t *testing.T) {
	runner := &planRunner{failAt: map[int]bool{3: true, 4: true}}
	plan := Plan{Changes: []Change{
		{Description: "first", Apply: Command{Tool: "ip", Args: []string{"first"}}, Rollback: Command{Tool: "ip", Args: []string{"undo-first"}}},
		{Description: "second", Apply: Command{Tool: "ip", Args: []string{"second"}}, Rollback: Command{Tool: "ip", Args: []string{"undo-second"}}},
		{Description: "third", Apply: Command{Tool: "ip", Args: []string{"third"}}},
	}}
	if err := ApplyPlan(context.Background(), runner, plan); err == nil || !strings.Contains(err.Error(), "rollback failed") {
		t.Fatalf("expected rollback failure to be visible, got %v", err)
	}
}
