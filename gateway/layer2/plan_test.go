package layer2

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func withTCStats(filter TCFilterState, packets, bytes, drops uint64) TCFilterState {
	filter.Packets, filter.Bytes, filter.Drops = packets, bytes, drops
	return filter
}

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

func TestBuildTopologyPlanRejects8021XUntilTrafficEnforcementProviderExists(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Overrides = nil
	cfg.PortAuth = []PortAuth{{Interface: "lan-a", RadiusServer: "192.0.2.10", RadiusPort: 1812, SecretFile: "/etc/gamebond/8021x/lan-a.secret", NASAddress: "192.0.2.2", NASID: "gamebond-edge", FailurePolicy: "closed", ExclusivePort: true}}
	host := Capabilities{Features: map[string]FeatureCapability{
		Feature8021X:      {State: CapabilityUnsupported, Reason: "authenticator and bridge traffic enforcement are not integrated"},
		FeatureBridgeVLAN: {State: CapabilityConditional},
	}}
	if _, err := BuildTopologyPlan(Config{}, cfg, host); err == nil || !strings.Contains(err.Error(), "802.1X port authentication is unavailable") {
		t.Fatalf("802.1X without traffic enforcement was not rejected: %v", err)
	}
}

func TestBuildTopologyPlanRequiresVoiceVLANProviderAndTaggedMembership(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Overrides = nil
	cfg.Bridges[0].Ports[0].VoiceNetwork = "voice"
	host := Capabilities{Features: map[string]FeatureCapability{
		FeatureVoiceVLAN:  {State: CapabilityUnsupported, Reason: "lldpd is unavailable"},
		FeatureBridgeVLAN: {State: CapabilityConditional},
	}, Interfaces: []HostInterface{{Name: "enp2s0", MTU: 1500}, {Name: "enp3s0", MTU: 1500}}}
	if _, err := BuildTopologyPlan(Config{}, cfg, host); err == nil || !strings.Contains(err.Error(), "Voice VLAN capability is unavailable") {
		t.Fatalf("Voice VLAN without LLDP-MED provider was not rejected: %v", err)
	}
	cfg.Bridges[0].Ports[0].TaggedNetworks = nil
	host.Features[FeatureVoiceVLAN] = FeatureCapability{State: CapabilityConditional}
	if _, err := BuildTopologyPlan(Config{}, cfg, host); err == nil || !strings.Contains(err.Error(), "tagged_networks") {
		t.Fatalf("Voice VLAN outside tagged port membership was accepted: %v", err)
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
	previous.Overrides = nil
	desired := previous
	desired.Overrides = nil
	previous.Overrides = nil
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

func TestBuildTopologyPlanValidatesDSCPQoSAndDefersApplyToSharedProvider(t *testing.T) {
	previous, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	desired := previous
	desired.Overrides = nil
	desired.QoS = []QoSPolicy{{Interface: "lan-b", LinkRateBPS: 1_000_000_000, Classes: []QoSClass{
		{ID: 10, DSCP: []uint8{46}, RateBPS: 100_000_000, CeilingBPS: 1_000_000_000, Priority: 0},
		{ID: 11, DSCP: []uint8{34}, RateBPS: 200_000_000, CeilingBPS: 1_000_000_000, Priority: 1},
	}}}
	previous.QoS = nil
	host := Capabilities{Features: map[string]FeatureCapability{
		FeatureBridgeVLAN: {State: CapabilityConditional}, FeatureQoSDSCP: {State: CapabilityConditional},
	}, Interfaces: []HostInterface{{Name: "br-main", Kind: "bridge", MTU: 1500}, {Name: "enp2s0", Master: "br-main", MTU: 1500, RootQdisc: "noqueue", LinkSpeedBPS: 1_000_000_000, LinkSpeedKnown: true}, {Name: "enp3s0", Master: "br-main", MTU: 1500, RootQdisc: "noqueue", LinkSpeedBPS: 1_000_000_000, LinkSpeedKnown: true}}}
	plan, err := BuildTopologyPlan(previous, desired, host)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range plan.Changes {
		if change.Apply.Tool == "tc" && len(change.Apply.Args) > 0 && change.Apply.Args[0] == "qdisc" {
			t.Fatalf("Layer 2 planner bypassed the shared gateway QoS provider: %#v", change)
		}
	}
	unknownSpeed := host
	unknownSpeed.Interfaces = append([]HostInterface(nil), host.Interfaces...)
	unknownSpeed.Interfaces[2].LinkSpeedKnown = false
	if _, err := BuildTopologyPlan(previous, desired, unknownSpeed); err == nil || !strings.Contains(err.Error(), "link speed is unknown") {
		t.Fatalf("expected unknown link speed rejection, got %v", err)
	}
	limitedSpeed := host
	limitedSpeed.Interfaces = append([]HostInterface(nil), host.Interfaces...)
	limitedSpeed.Interfaces[2].LinkSpeedBPS = 500_000_000
	if _, err := BuildTopologyPlan(previous, desired, limitedSpeed); err == nil || !strings.Contains(err.Error(), "exceeds detected link speed") {
		t.Fatalf("expected link speed bound rejection, got %v", err)
	}
}

func TestBuildTopologyPlanConfiguresIGMPSnoopingQuerierAndPorts(t *testing.T) {
	previous, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	desired := previous
	desired.Overrides = nil
	desired.Bridges = append([]Bridge(nil), previous.Bridges...)
	enabled := true
	nonShared := false
	desired.Bridges[0].IGMPSnooping = &enabled
	desired.Bridges[0].IGMPQuerier = &enabled
	desired.Bridges[0].STPEnabled = &enabled
	desired.Bridges[0].Ports = append([]BridgePort(nil), previous.Bridges[0].Ports...)
	desired.Bridges[0].Ports[0].IGMPFastLeave = &enabled
	desired.Bridges[0].Ports[0].IGMPSharedDownstream = &nonShared
	desired.Bridges[0].Ports[1].IGMPRouterPort = &enabled
	host := Capabilities{Features: map[string]FeatureCapability{
		FeatureBridgeVLAN:   {State: CapabilityConditional},
		FeatureIGMPSnoop:    {State: CapabilityConditional},
		FeatureIGMPAdvanced: {State: CapabilityConditional},
		FeatureSTP:          {State: CapabilityConditional},
	}, STPControllerDiscovery: &STPControllerDiscovery{Known: true, Controller: "kernel"}, Interfaces: []HostInterface{
		{Name: "br-main", Kind: "bridge", MTU: 1500, IGMPBridgeKnown: true, STPKnown: true},
		{Name: "enp2s0", Master: "br-main", MTU: 1500, IGMPPortKnown: true},
		{Name: "enp3s0", Master: "br-main", MTU: 1500, IGMPPortKnown: true},
	}}
	plan, err := BuildTopologyPlan(previous, desired, host)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	wantCommands := map[string][]string{
		"configure IGMP snooping and querier on main": {"link", "set", "dev", "br-main", "type", "bridge", "mcast_snooping", "1", "mcast_querier", "1"},
		"configure IGMP port behavior on lan-a":       {"link", "set", "dev", "enp2s0", "fastleave", "on"},
		"configure IGMP port behavior on lan-b":       {"link", "set", "dev", "enp3s0", "mcast_router", "2"},
		"configure STP on main":                       {"link", "set", "dev", "br-main", "type", "bridge", "stp_state", "1"},
	}
	for _, change := range plan.Changes {
		seen[change.Description] = true
		if want, ok := wantCommands[change.Description]; ok && !reflect.DeepEqual(change.Apply.Args, want) {
			t.Errorf("%s command = %#v, want %#v", change.Description, change.Apply.Args, want)
		}
	}
	for _, description := range []string{"configure IGMP snooping and querier on main", "configure IGMP port behavior on lan-a", "configure IGMP port behavior on lan-b", "configure STP on main"} {
		if !seen[description] {
			t.Errorf("missing planned change %q", description)
		}
	}
}

func TestBuildTopologyPlanRejectsGenericLoopProtectionWhenOnlyBPDUNodeGuardExists(t *testing.T) {
	desired, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	desired.Overrides = nil
	enabled := true
	desired.Bridges[0].Ports[0].LoopProtection = &enabled
	host := Capabilities{Features: map[string]FeatureCapability{
		FeatureBridgeVLAN:  {State: CapabilityConditional},
		FeatureLoopProtect: {State: CapabilityUnsupported, Reason: "generic Linux bridge has BPDU guard but no loopback detection, blocked-state recovery timer, or recovery reason provider"},
	}}
	_, err = BuildTopologyPlan(Config{Version: 1}, desired, host)
	if err == nil || !strings.Contains(err.Error(), "loop-protection capability is unavailable") {
		t.Fatalf("generic loop protection was accepted: %v", err)
	}
}

func TestBuildTopologyPlanConfiguresPerVLANIGMPSnoopingWithRollback(t *testing.T) {
	previous, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	desired := previous
	desired.Overrides = nil
	previous.Overrides = nil
	desired.Networks = append([]Network(nil), previous.Networks...)
	desired.Bridges = append([]Bridge(nil), previous.Bridges...)
	disabled := false
	enabled := true
	desired.Bridges[0].IGMPSnooping = &enabled
	desired.Networks[0].IGMPSnooping = &disabled
	host := Capabilities{Features: map[string]FeatureCapability{
		FeatureBridgeVLAN: {State: CapabilityConditional}, FeatureIGMPSnoop: {State: CapabilityConditional}, FeatureIGMPVLAN: {State: CapabilityConditional},
	}, Interfaces: []HostInterface{
		{Name: "br-main", Kind: "bridge", MTU: 1500, IGMPBridgeKnown: true, IGMPSnooping: true, IGMPVLANKnown: true, IGMPVLANMode: false},
		{Name: "enp2s0", Master: "br-main", MTU: 1500}, {Name: "enp3s0", Master: "br-main", MTU: 1500},
	}, BridgeVLANs: []BridgeVLANState{{Device: "br-main", VLAN: desired.Networks[0].VLAN}},
		BridgeVLANGLOBALs: []BridgeVLANGLOBALState{{Bridge: "br-main", VLAN: desired.Networks[0].VLAN, Snooping: true}}}
	plan, err := BuildTopologyPlan(previous, desired, host)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range plan.Changes {
		if change.Description == "enable per-VLAN IGMP snooping mode on main" {
			if !reflect.DeepEqual(change.Apply.Args, []string{"link", "set", "dev", "br-main", "type", "bridge", "mcast_vlan_snooping", "1"}) || !reflect.DeepEqual(change.Rollback.Args, []string{"link", "set", "dev", "br-main", "type", "bridge", "mcast_vlan_snooping", "0"}) {
				t.Fatalf("mode change/rollback mismatch: %#v", change)
			}
		}
		if change.Description == "configure per-VLAN IGMP snooping on default" {
			want := []string{"vlan", "global", "set", "dev", "br-main", "vid", fmt.Sprint(desired.Networks[0].VLAN), "mcast_snooping", "0"}
			undo := []string{"vlan", "global", "set", "dev", "br-main", "vid", fmt.Sprint(desired.Networks[0].VLAN), "mcast_snooping", "1"}
			if !reflect.DeepEqual(change.Apply.Args, want) || !reflect.DeepEqual(change.Rollback.Args, undo) {
				t.Fatalf("VLAN change/rollback mismatch: %#v", change)
			}
			return
		}
	}
	t.Fatal("per-VLAN snooping change missing")
}

func TestRenderDHCPGuardTableFiltersUntrustedServerRepliesAndRateLimits(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.DHCPGuard = []DHCPGuardPort{{Interface: "lan-a", RateLimitPPS: 20, ValidateBindings: true}, {Interface: "lan-b", Trusted: true}}
	rendered := string(renderDHCPGuardTable(cfg, false))
	for _, expected := range []string{
		`add table bridge gamebond_dhcp_guard { comment "gamebond-dhcp-guard:v1"; }`,
		`prerouting iifname "enp2s0" udp sport 67 counter drop comment "gamebond-dhcp-guard:lan-a:server"`,
		`prerouting iifname "enp2s0" udp dport 67 limit rate over 20/second burst 40 packets counter drop comment "gamebond-dhcp-guard:lan-a:rate:20"`,
		`type ifname . ipv4_addr . ether_addr`,
		`iifname . ip saddr . ether saddr != @client_bindings`,
	} {
		if !strings.Contains(rendered, expected) {
			t.Errorf("DHCP guard table missing %q:\n%s", expected, rendered)
		}
	}
	if strings.Contains(rendered, `gamebond-dhcp-guard:lan-b:server`) {
		t.Fatalf("trusted server port received an untrusted-server drop rule:\n%s", rendered)
	}
}

func TestBuildDHCPGuardChangeTracksOwnershipAndRollback(t *testing.T) {
	previous, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	previous.Overrides = nil
	desired := previous
	desired.DHCPGuard = []DHCPGuardPort{{Interface: "lan-a", Trusted: false, RateLimitPPS: 20}}
	change, err := buildDHCPGuardChange(previous, desired, Capabilities{})
	if err != nil || change == nil {
		t.Fatalf("build DHCP guard change: change=%#v err=%v", change, err)
	}
	if !strings.Contains(string(change.Apply.Input), "gamebond-dhcp-guard:v1") || !strings.Contains(string(change.Rollback.Input), "delete table bridge gamebond_dhcp_guard") {
		t.Fatalf("incorrect initial apply/rollback: %#v", change)
	}
	actual := dhcpGuardRuleComments(desired)
	counters := map[string][2]uint64{}
	for _, key := range actual {
		counters[key] = [2]uint64{}
	}
	owned := Capabilities{DHCPGuardTablePresent: true, DHCPGuardTableManaged: true, DHCPGuardRuleCounters: counters}
	if change, err := buildDHCPGuardChange(desired, desired, owned); err != nil || change != nil {
		t.Fatalf("idempotent policy planned a change: change=%#v err=%v", change, err)
	}
	owned.DHCPGuardRuleCounters[actual[0]+"-drift"] = [2]uint64{}
	if _, err := buildDHCPGuardChange(desired, previous, owned); err == nil || !strings.Contains(err.Error(), "differs from saved") {
		t.Fatalf("drifted table accepted: %v", err)
	}
}

func TestBuildTopologyPlanEnablesRSTPWithMSTPControl(t *testing.T) {
	previous, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	desired := previous
	desired.Overrides = nil
	desired.Bridges = append([]Bridge(nil), previous.Bridges...)
	desired.Bridges[0].STPMode = "rstp"
	host := Capabilities{Features: map[string]FeatureCapability{
		FeatureBridgeVLAN: {State: CapabilityConditional},
		FeatureSTP:        {State: CapabilityConditional},
		FeatureRSTP:       {State: CapabilityConditional},
	}, STPControllerDiscovery: &STPControllerDiscovery{Known: true, Controller: "mstpd.service"}, Interfaces: []HostInterface{
		{Name: "br-main", Kind: "bridge", MTU: 1500, STPKnown: true, STPModeKnown: true, STPMode: "stp"},
		{Name: "enp2s0", Master: "br-main", MTU: 1500},
		{Name: "enp3s0", Master: "br-main", MTU: 1500},
	}}
	plan, err := BuildTopologyPlan(previous, desired, host)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		tool string
		args []string
	}{
		"configure STP on main":              {"ip", []string{"link", "set", "dev", "br-main", "type", "bridge", "stp_state", "1"}},
		"set spanning-tree protocol on main": {"mstpctl", []string{"setforcevers", "br-main", "rstp"}},
	}
	for _, change := range plan.Changes {
		if expected, ok := want[change.Description]; ok {
			if change.Apply.Tool != expected.tool || !reflect.DeepEqual(change.Apply.Args, expected.args) {
				t.Errorf("%s apply = %s %#v, want %s %#v", change.Description, change.Apply.Tool, change.Apply.Args, expected.tool, expected.args)
			}
			delete(want, change.Description)
		}
	}
	for description := range want {
		t.Errorf("missing spanning-tree operation %q", description)
	}
}

func TestBuildTopologyPlanRejectsAmbiguousSTPControllerOwnership(t *testing.T) {
	previous, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	desired := previous
	desired.Overrides = nil
	desired.Bridges = append([]Bridge(nil), previous.Bridges...)
	desired.Bridges[0].STPMode = "rstp"
	host := Capabilities{Features: map[string]FeatureCapability{
		FeatureBridgeVLAN: {State: CapabilityConditional},
		FeatureSTP:        {State: CapabilityConditional},
		FeatureRSTP:       {State: CapabilityConditional},
	}, Interfaces: []HostInterface{
		{Name: "br-main", Kind: "bridge", MTU: 1500, STPKnown: true, STPModeKnown: true, STPMode: "stp"},
		{Name: "enp2s0", Master: "br-main", MTU: 1500},
		{Name: "enp3s0", Master: "br-main", MTU: 1500},
	}}
	if _, err := BuildTopologyPlan(previous, desired, host); err == nil || !strings.Contains(err.Error(), "controller ownership") {
		t.Fatalf("ambiguous STP controller ownership was accepted: %v", err)
	}
}

func TestBuildTopologyPlanRejectsSTPTeardownWithoutControllerOwnership(t *testing.T) {
	previous, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	previous.Overrides = nil
	previous.Bridges = append([]Bridge(nil), previous.Bridges...)
	stpEnabled := true
	previous.Bridges[0].STPEnabled = &stpEnabled
	desired := previous
	desired.Bridges = append([]Bridge(nil), previous.Bridges...)
	desired.Bridges[0].STPEnabled = nil
	host := Capabilities{Features: map[string]FeatureCapability{
		FeatureBridgeVLAN: {State: CapabilityConditional},
		FeatureSTP:        {State: CapabilityConditional},
	}, Interfaces: []HostInterface{
		{Name: "br-main", Kind: "bridge", MTU: 1500, STPKnown: true, STPEnabled: true},
		{Name: "enp2s0", Master: "br-main", MTU: 1500},
		{Name: "enp3s0", Master: "br-main", MTU: 1500},
	}}
	if _, err := BuildTopologyPlan(previous, desired, host); err == nil || !strings.Contains(err.Error(), "controller ownership") {
		t.Fatalf("STP teardown without controller ownership was accepted: %v", err)
	}
}

func TestBuildTopologyPlanTunesSTPPriorityCostAndRootBlock(t *testing.T) {
	previous, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	previous.Overrides = nil
	desired := previous
	desired.Bridges = append([]Bridge(nil), previous.Bridges...)
	desired.Bridges[0].Ports = append([]BridgePort(nil), previous.Bridges[0].Ports...)
	bridgePriority, portPriority, cost, rootBlock := uint16(4096), uint8(16), uint32(200), true
	stpEnabled := true
	desired.Bridges[0].STPEnabled = &stpEnabled
	desired.Bridges[0].STPPriority = &bridgePriority
	desired.Bridges[0].Ports[0].STPPriority = &portPriority
	desired.Bridges[0].Ports[0].STPPathCost = &cost
	desired.Bridges[0].Ports[0].STPRootBlock = &rootBlock
	host := Capabilities{Features: map[string]FeatureCapability{FeatureBridgeVLAN: {State: CapabilityConditional}, FeatureSTP: {State: CapabilityConditional}}, STPControllerDiscovery: &STPControllerDiscovery{Known: true, Controller: "kernel"}, Interfaces: []HostInterface{
		{Name: "br-main", Kind: "bridge", MTU: 1500, STPKnown: true, STPEnabled: false, STPPriorityKnown: true, STPPriority: 32768},
		{Name: "enp2s0", Master: "br-main", MTU: 1500, STPPortKnown: true, STPPortPriority: 32, STPPathCost: 100, STPRootBlock: false},
		{Name: "enp3s0", Master: "br-main", MTU: 1500, STPPortKnown: true},
	}}
	plan, err := BuildTopologyPlan(previous, desired, host)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		tool string
		args []string
	}{
		"configure STP bridge priority on main": {"ip", []string{"link", "set", "dev", "br-main", "type", "bridge", "priority", "4096"}},
		"configure STP priority on lan-a":       {"bridge", []string{"link", "set", "dev", "enp2s0", "priority", "16"}},
		"configure STP cost on lan-a":           {"bridge", []string{"link", "set", "dev", "enp2s0", "cost", "200"}},
		"configure STP root_block on lan-a":     {"bridge", []string{"link", "set", "dev", "enp2s0", "root_block", "on"}},
	}
	for _, change := range plan.Changes {
		if expected, ok := want[change.Description]; ok {
			if change.Apply.Tool != expected.tool {
				t.Errorf("%s tool = %q, want %q", change.Description, change.Apply.Tool, expected.tool)
			}
			if !reflect.DeepEqual(change.Apply.Args, expected.args) {
				t.Errorf("%s args = %#v, want %#v", change.Description, change.Apply.Args, expected.args)
			}
			delete(want, change.Description)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing STP changes: %#v", want)
	}
}

func TestBuildTopologyPlanConfiguresRSTPEdgeP2PAndBPDUGuard(t *testing.T) {
	previous, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	previous.Overrides = nil
	desired := previous
	desired.Bridges = append([]Bridge(nil), previous.Bridges...)
	desired.Bridges[0].Ports = append([]BridgePort(nil), previous.Bridges[0].Ports...)
	desired.Bridges[0].STPMode = "rstp"
	edge, guard := true, true
	desired.Bridges[0].Ports[0].STPEdge = &edge
	desired.Bridges[0].Ports[0].STPPointToPoint = "no"
	desired.Bridges[0].Ports[0].STPBPDUGuard = &guard
	host := Capabilities{Features: map[string]FeatureCapability{FeatureBridgeVLAN: {State: CapabilityConditional}, FeatureSTP: {State: CapabilityConditional}, FeatureRSTP: {State: CapabilityConditional}}, STPControllerDiscovery: &STPControllerDiscovery{Known: true, Controller: "mstpd.service"}, Interfaces: []HostInterface{
		{Name: "br-main", Kind: "bridge", MTU: 1500, STPKnown: true, STPModeKnown: true, STPMode: "rstp"},
		{Name: "enp2s0", Master: "br-main", MTU: 1500, STPAdvancedKnown: true, STPPointToPoint: "auto"},
		{Name: "enp3s0", Master: "br-main", MTU: 1500},
	}}
	plan, err := BuildTopologyPlan(previous, desired, host)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]struct{ apply, rollback []string }{
		"configure RSTP edge on lan-a":           {[]string{"setportadminedge", "br-main", "enp2s0", "yes"}, []string{"setportadminedge", "br-main", "enp2s0", "no"}},
		"configure RSTP point-to-point on lan-a": {[]string{"setportp2p", "br-main", "enp2s0", "no"}, []string{"setportp2p", "br-main", "enp2s0", "auto"}},
		"configure RSTP BPDU guard on lan-a":     {[]string{"setbpduguard", "br-main", "enp2s0", "yes"}, []string{"setbpduguard", "br-main", "enp2s0", "no"}},
	}
	for _, change := range plan.Changes {
		if expected, ok := want[change.Description]; ok {
			if change.Apply.Tool != "mstpctl" || !reflect.DeepEqual(change.Apply.Args, expected.apply) {
				t.Errorf("%s apply = %#v, want mstpctl %#v", change.Description, change.Apply, expected.apply)
			}
			if change.Rollback.Tool != "mstpctl" || !reflect.DeepEqual(change.Rollback.Args, expected.rollback) {
				t.Errorf("%s rollback = %#v, want mstpctl %#v", change.Description, change.Rollback, expected.rollback)
			}
			delete(want, change.Description)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing RSTP port changes: %#v", want)
	}
}

func TestBuildTopologyPlanConfiguresAndVerifiesPortMirroring(t *testing.T) {
	previous, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	previous.Overrides = nil
	desired := previous
	desired.Interfaces = append([]Interface(nil), previous.Interfaces...)
	desired.Interfaces = append(desired.Interfaces, Interface{ID: "monitor", Name: "mon0"})
	desired.PortMirrors = []PortMirror{{Source: "lan-a", Destination: "monitor", Direction: "both", Network: "voice", CaptureRateBPS: 5_000_000, CaptureBurstBytes: 65536}}
	host := Capabilities{Features: map[string]FeatureCapability{
		FeatureBridgeVLAN: {State: CapabilityConditional}, FeaturePortMirror: {State: CapabilityConditional}, FeatureEgressRate: {State: CapabilityConditional},
	}, Interfaces: []HostInterface{
		{Name: "br-main", Kind: "bridge", MTU: 1500},
		{Name: "enp2s0", Master: "br-main", MTU: 1500},
		{Name: "enp3s0", Master: "br-main", MTU: 1500},
		{Name: "mon0", MTU: 1500, AdminUp: true, RootQdisc: "noqueue"},
	}}
	plan, err := BuildTopologyPlan(previous, desired, host)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"install port mirror on lan-a ingress": {"filter", "replace", "dev", "enp2s0", "ingress", "pref", "49100", "protocol", "802.1Q", "flower", "skip_hw", "vlan_id", "20", "action", "mirred", "egress", "mirror", "dev", "mon0"},
		"install port mirror on lan-a egress":  {"filter", "replace", "dev", "enp2s0", "egress", "pref", "49101", "protocol", "802.1Q", "flower", "skip_hw", "vlan_id", "20", "action", "mirred", "egress", "mirror", "dev", "mon0"},
		"apply egress TBF rate on monitor":     {"qdisc", "replace", "dev", "mon0", "root", "handle", "7fff:", "tbf", "rate", "5000000bit", "burst", "65536b", "latency", "50ms"},
	}
	for _, change := range plan.Changes {
		if expected, ok := want[change.Description]; ok {
			if change.Apply.Tool != "tc" || !reflect.DeepEqual(change.Apply.Args, expected) {
				t.Errorf("%s = %s %#v, want tc %#v", change.Description, change.Apply.Tool, change.Apply.Args, expected)
			}
			delete(want, change.Description)
		}
	}
	for description := range want {
		t.Errorf("missing mirror operation %q", description)
	}

	live := host
	live.Interfaces = append([]HostInterface(nil), host.Interfaces...)
	live.Interfaces[1].TCClsact = true
	live.Interfaces[1].TCFilters = []TCFilterState{{Priority: 49100, Kind: "flower", NumVLANs: -1, VLANID: 20, MirrorDevice: "mon0", MirrorAction: "mirror", MirrorDirection: "egress", Packets: 10, Bytes: 1200}}
	live.Interfaces[1].TCEgressFilters = []TCFilterState{{Priority: 49101, Kind: "flower", NumVLANs: -1, VLANID: 20, MirrorDevice: "mon0", MirrorAction: "mirror", MirrorDirection: "egress", Packets: 5, Bytes: 750}}
	live.Interfaces[3].RootQdisc = "tbf"
	live.Interfaces[3].RootQdiscRateBPS = 5_000_000
	live.Interfaces[3].RootQdiscBurstBytes = 65536
	applyPortMirrorStatus(&live, desired)
	if len(live.PortMirrors) != 1 || !live.PortMirrors[0].Applied || live.PortMirrors[0].Packets != 15 || live.PortMirrors[0].Bytes != 1950 || live.PortMirrors[0].Network != "voice" {
		t.Fatalf("scoped mirror status/counters = %#v", live.PortMirrors)
	}
	plan, err = BuildTopologyPlan(desired, desired, live)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range plan.Changes {
		if strings.Contains(change.Description, "port mirror") {
			t.Fatalf("already-applied mirror remained in plan: %#v", change)
		}
	}
}

func TestBuildPortMirrorUnscopedFilterUsesSoftwareMirred(t *testing.T) {
	cfg := Config{Version: 1, Interfaces: []Interface{{ID: "lan", Name: "enp2s0"}, {ID: "monitor", Name: "mon0"}}, PortMirrors: []PortMirror{{Source: "lan", Destination: "monitor", Direction: "ingress"}}}
	changes, err := buildPortMirrorChanges(Config{Version: 1}, cfg, map[string]HostInterface{
		"enp2s0": {Name: "enp2s0"}, "mon0": {Name: "mon0", AdminUp: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, change := range changes {
		joined := strings.Join(change.Apply.Args, " ")
		if strings.Contains(joined, "matchall skip_hw action mirred egress mirror dev mon0") {
			found = true
		}
	}
	if !found {
		t.Fatalf("software mirror filter missing from changes: %#v", changes)
	}
}

func TestBuildTopologyPlanConfiguresStormControlWithRollback(t *testing.T) {
	config, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	config.Overrides = nil
	config.StormControl = []StormControl{{Interface: "lan-b", BroadcastRateBPS: 1_000_000, MulticastRateBPS: 2_000_000, BurstBytes: 16_384}}
	previous := config
	previous.StormControl = nil
	host := Capabilities{Features: map[string]FeatureCapability{
		FeatureBridgeVLAN: {State: CapabilityConditional}, FeatureStormControl: {State: CapabilityConditional},
		FeatureMultiRate: {State: CapabilityConditional},
	}, Interfaces: []HostInterface{{Name: "br-main", Kind: "bridge", MTU: 1500},
		{Name: "enp2s0", Master: "br-main", MTU: 1500}, {Name: "enp3s0", Master: "br-main", MTU: 1500}}}
	plan, err := BuildTopologyPlan(previous, config, host)
	if err != nil {
		t.Fatal(err)
	}
	want := map[int][]string{
		stormBroadcastPriority: {"filter", "replace", "dev", "enp3s0", "ingress", "protocol", "all", "pref", "48010", "flower", "skip_hw", "dst_mac", "ff:ff:ff:ff:ff:ff/ff:ff:ff:ff:ff:ff", "action", "police", "rate", "1000000", "bit", "burst", "16384", "b", "drop"},
		stormMulticastPriority: {"filter", "replace", "dev", "enp3s0", "ingress", "protocol", "all", "pref", "48020", "flower", "skip_hw", "dst_mac", "01:00:00:00:00:00/01:00:00:00:00:00", "action", "police", "rate", "2000000", "bit", "burst", "16384", "b", "drop"},
	}
	found := 0
	for _, change := range plan.Changes {
		if change.Description == "configure broadcast storm control on enp3s0" || change.Description == "configure multicast storm control on enp3s0" {
			priority := stormBroadcastPriority
			if strings.Contains(change.Description, "multicast") {
				priority = stormMulticastPriority
			}
			if !reflect.DeepEqual(change.Apply.Args, want[priority]) {
				t.Errorf("%s args = %#v", change.Description, change.Apply.Args)
			}
			if change.Rollback.Tool != "tc" || change.Rollback.Args[1] != "del" {
				t.Errorf("new filter rollback = %#v", change.Rollback)
			}
			found++
		}
	}
	if found != 2 {
		t.Fatalf("found %d storm filters; plan: %#v", found, plan.Changes)
	}
}

func TestBuildTopologyPlanStormControlIsIdempotentAndRemovesManagedFilters(t *testing.T) {
	config, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	config.Overrides = nil
	config.StormControl = []StormControl{{Interface: "lan-b", BroadcastRateBPS: 1_000_000, BurstBytes: 16_384}}
	host := Capabilities{Features: map[string]FeatureCapability{
		FeatureBridgeVLAN: {State: CapabilityConditional}, FeatureStormControl: {State: CapabilityConditional},
		FeatureMultiRate: {State: CapabilityConditional},
	}, Interfaces: []HostInterface{{Name: "br-main", Kind: "bridge", MTU: 1500},
		{Name: "enp2s0", Master: "br-main", MTU: 1500}, {Name: "enp3s0", Master: "br-main", MTU: 1500, TCClsact: true,
			TCFilters: []TCFilterState{withTCStats(stormFilter(1_000_000, 16_384, false), 12, 2048, 4)}}}}
	plan, err := BuildTopologyPlan(config, config, host)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range plan.Changes {
		if strings.Contains(change.Description, "storm control") {
			t.Fatalf("matching storm filter remained in plan: %#v", change)
		}
	}
	removed := config
	removed.StormControl = nil
	plan, err = BuildTopologyPlan(config, removed, host)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, change := range plan.Changes {
		if change.Description == "remove broadcast storm control on enp3s0" {
			found = true
			if change.Apply.Tool != "tc" || change.Apply.Args[1] != "del" || change.Rollback.Args[1] != "add" {
				t.Fatalf("unexpected removal/rollback: %#v", change)
			}
		}
	}
	if !found {
		t.Fatalf("managed storm filter removal absent from plan: %#v", plan.Changes)
	}
}

func TestBuildTopologyPlanAppliesMulticastBroadcastLimitsWithSoftwarePolicers(t *testing.T) {
	previous, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	previous.Overrides = nil
	desired := previous
	desired.MulticastBroadcastLimits = []MulticastBroadcastRateLimit{{Interface: "lan-b", BroadcastRateBPS: 1_000_000, MulticastRateBPS: 2_000_000, BurstBytes: 16384}}
	host := Capabilities{Features: map[string]FeatureCapability{FeatureBridgeVLAN: {State: CapabilityConditional}, FeatureMultiRate: {State: CapabilityConditional}}, Interfaces: []HostInterface{
		{Name: "br-main", Kind: "bridge", MTU: 1500}, {Name: "enp2s0", Master: "br-main", MTU: 1500}, {Name: "enp3s0", Master: "br-main", MTU: 1500, TCClsact: true},
	}}
	plan, err := BuildTopologyPlan(previous, desired, host)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"configure broadcast multicast/broadcast rate limit on enp3s0": {"filter", "replace", "dev", "enp3s0", "ingress", "protocol", "all", "pref", "48030", "flower", "skip_hw", "dst_mac", "ff:ff:ff:ff:ff:ff/ff:ff:ff:ff:ff:ff", "action", "police", "rate", "1000000", "bit", "burst", "16384", "b", "drop"},
		"configure multicast multicast/broadcast rate limit on enp3s0": {"filter", "replace", "dev", "enp3s0", "ingress", "protocol", "all", "pref", "48040", "flower", "skip_hw", "dst_mac", "01:00:00:00:00:00/01:00:00:00:00:00", "action", "police", "rate", "2000000", "bit", "burst", "16384", "b", "drop"},
	}
	for _, change := range plan.Changes {
		if expected, ok := want[change.Description]; ok {
			if change.Apply.Tool != "tc" || !reflect.DeepEqual(change.Apply.Args, expected) {
				t.Errorf("%s command = %#v, want tc %#v", change.Description, change.Apply, expected)
			}
			if change.Rollback.Tool != "tc" || change.Rollback.Args[1] != "del" {
				t.Errorf("%s rollback = %#v", change.Description, change.Rollback)
			}
			delete(want, change.Description)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing rate policers: %#v", want)
	}
	live := host
	live.Interfaces = append([]HostInterface(nil), host.Interfaces...)
	for i := range live.Interfaces {
		if live.Interfaces[i].Name == "enp3s0" {
			live.Interfaces[i].TCFilters = []TCFilterState{withTCStats(ingressRateFilter(1_000_000, 16384, false, multiBroadcastPriority), 10, 1200, 2), withTCStats(ingressRateFilter(2_000_000, 16384, true, multiMulticastPriority), 14, 1500, 3)}
		}
	}
	applyMulticastBroadcastRateStatus(&live, desired)
	if len(live.MulticastBroadcastRateLimits) != 1 || !live.MulticastBroadcastRateLimits[0].Applied || live.MulticastBroadcastRateLimits[0].Enforcement != "software tc ingress policer" || live.MulticastBroadcastRateLimits[0].BroadcastDrops != 2 || live.MulticastBroadcastRateLimits[0].MulticastDrops != 3 {
		t.Fatalf("effective rate status = %#v", live.MulticastBroadcastRateLimits)
	}
	idempotent, err := BuildTopologyPlan(desired, desired, live)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range idempotent.Changes {
		if strings.Contains(change.Description, "multicast/broadcast rate limit") {
			t.Fatalf("matching limit remains in plan: %#v", change)
		}
	}
	removed := desired
	removed.MulticastBroadcastLimits = nil
	removal, err := BuildTopologyPlan(desired, removed, live)
	if err != nil {
		t.Fatal(err)
	}
	removedClasses := 0
	for _, change := range removal.Changes {
		if strings.HasPrefix(change.Description, "remove ") && strings.Contains(change.Description, "multicast/broadcast rate limit") {
			removedClasses++
			if change.Apply.Args[1] != "del" || change.Rollback.Args[1] != "add" {
				t.Errorf("bad policer rollback: %#v", change)
			}
		}
	}
	if removedClasses != 2 {
		t.Fatalf("removed %d rate classes, want 2; changes=%#v", removedClasses, removal.Changes)
	}
}

func TestBuildTopologyPlanEnforcesRoutedIsolationBetweenNamedNetworks(t *testing.T) {
	desired, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	desired.Overrides = nil
	desired.Networks[0].RouteInterface = "br-main.10"
	desired.Networks[1].RouteInterface = "br-main.20"
	desired.NetworkACL = []NetworkACLRule{{ID: "av-control", SourceNetwork: "default", DestinationNetwork: "voice", Protocol: "tcp", Port: 443}}
	previous := desired
	previous.NetworkACL = nil
	host := Capabilities{Features: map[string]FeatureCapability{
		FeatureBridgeVLAN: {State: CapabilityConditional}, FeatureNetworkIsolation: {State: CapabilityConditional},
	}, Interfaces: []HostInterface{{Name: "br-main", Kind: "bridge", MTU: 1500},
		{Name: "enp2s0", Master: "br-main", MTU: 1500}, {Name: "enp3s0", Master: "br-main", MTU: 1500},
		{Name: "br-main.10", Kind: "vlan", MTU: 1500, AdminUp: true}, {Name: "br-main.20", Kind: "vlan", MTU: 1500, AdminUp: true}}}
	plan, err := BuildTopologyPlan(previous, desired, host)
	if err != nil {
		t.Fatal(err)
	}
	var change *Change
	for i := range plan.Changes {
		if strings.Contains(plan.Changes[i].Description, "routed network isolation") {
			change = &plan.Changes[i]
			break
		}
	}
	if change == nil {
		t.Fatalf("routed isolation absent from plan: %#v", plan.Changes)
	}
	script := string(change.Apply.Input)
	for _, fragment := range []string{"table inet gamebond_l2_isolation", `iifname "br-main.10" oifname "br-main.20" meta l4proto tcp tcp dport 443 counter accept`, `iifname "br-main.10" oifname "br-main.20" counter drop`, `iifname "br-main.20" oifname "br-main.10" counter drop`} {
		if !strings.Contains(script, fragment) {
			t.Errorf("isolation script missing %q: %s", fragment, script)
		}
	}
	if change.Rollback.Tool != "nft" || !strings.Contains(string(change.Rollback.Input), "delete table inet gamebond_l2_isolation") {
		t.Fatalf("new isolation rollback = %#v", change.Rollback)
	}
}

func TestBuildTopologyPlanRemovesRoutedIsolationAndCanRestoreIt(t *testing.T) {
	previous, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	previous.Overrides = nil
	previous.Networks[0].RouteInterface, previous.Networks[1].RouteInterface = "br-main.10", "br-main.20"
	previous.NetworkACL = []NetworkACLRule{{ID: "allow-control", SourceNetwork: "default", DestinationNetwork: "voice"}}
	desired := previous
	desired.NetworkACL = nil
	host := Capabilities{Features: map[string]FeatureCapability{
		FeatureBridgeVLAN: {State: CapabilityConditional}, FeatureNetworkIsolation: {State: CapabilityConditional},
	}, NetworkIsolationTablePresent: true, NetworkIsolationTableManaged: true,
		NetworkIsolationRuleCounters: map[string][2]uint64{}}
	for _, comment := range networkIsolationRuleComments(previous) {
		host.NetworkIsolationRuleCounters[comment] = [2]uint64{}
	}
	for _, name := range []string{"br-main", "enp2s0", "enp3s0", "br-main.10", "br-main.20"} {
		kind := ""
		if name == "br-main" {
			kind = "bridge"
		}
		host.Interfaces = append(host.Interfaces, HostInterface{Name: name, Kind: kind, MTU: 1500, AdminUp: true})
	}
	plan, err := BuildTopologyPlan(previous, desired, host)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, change := range plan.Changes {
		if change.Description == "apply routed network isolation" {
			found = true
			if string(change.Apply.Input) != "delete table inet gamebond_l2_isolation\n" {
				t.Fatalf("removal script = %q", change.Apply.Input)
			}
			if !strings.Contains(string(change.Rollback.Input), "add table inet gamebond_l2_isolation") {
				t.Fatalf("rollback does not restore prior rules: %s", change.Rollback.Input)
			}
		}
	}
	if !found {
		t.Fatalf("routed isolation removal missing: %#v", plan.Changes)
	}
}

func TestBuildTopologyPlanRoutedIsolationIsIdempotentFromRenderedComments(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Overrides = nil
	cfg.Networks[0].RouteInterface, cfg.Networks[1].RouteInterface = "br-main.10", "br-main.20"
	cfg.NetworkACL = []NetworkACLRule{{ID: "allow-control", SourceNetwork: "default", DestinationNetwork: "voice"}}
	host := Capabilities{
		Features: map[string]FeatureCapability{
			FeatureBridgeVLAN: {State: CapabilityConditional}, FeatureNetworkIsolation: {State: CapabilityConditional},
		},
		Interfaces: []HostInterface{
			{Name: "br-main", Kind: "bridge", MTU: 1500, AdminUp: true},
			{Name: "enp2s0", Master: "br-main", MTU: 1500, AdminUp: true},
			{Name: "enp3s0", Master: "br-main", MTU: 1500, AdminUp: true},
			{Name: "br-main.10", Kind: "vlan", MTU: 1500, AdminUp: true},
			{Name: "br-main.20", Kind: "vlan", MTU: 1500, AdminUp: true},
		},
		NetworkIsolationTablePresent: true,
		NetworkIsolationTableManaged: true,
		NetworkIsolationRuleCounters: renderedRuleCounters(renderNetworkIsolationTable(cfg, false), "gamebond-l2-isolation:"),
	}
	plan, err := BuildTopologyPlan(cfg, cfg, host)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range plan.Changes {
		if change.Description == "apply routed network isolation" {
			t.Fatalf("rendered routed-isolation state did not converge: %#v", change)
		}
	}
}

func TestACLAndDHCPPolicyEditsWithStableIDsTriggerReplacement(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Overrides = nil

	t.Run("IP ACL action", func(t *testing.T) {
		previous := cfg
		previous.IPACL = []IPACLRule{{ID: "web", Interface: "lan-b", Network: "default", Direction: "ingress", Family: "ipv4", Source: "192.0.2.0/24", Protocol: "tcp", Port: 443, Action: "allow"}}
		desired := previous
		desired.IPACL = append([]IPACLRule(nil), previous.IPACL...)
		desired.IPACL[0].Action = "deny"
		host := Capabilities{IPACLTablePresent: true, IPACLTableManaged: true, IPACLRuleCounters: countersFor(ipACLRuleComments(previous))}
		change, err := buildIPACLChange(previous, desired, host)
		if err != nil || change == nil {
			t.Fatalf("same-ID IP ACL edit was not reconciled: change=%#v err=%v", change, err)
		}
		if !strings.Contains(string(change.Apply.Input), "counter drop") {
			t.Fatalf("replacement does not contain edited action: %s", change.Apply.Input)
		}
	})

	t.Run("MAC ACL match", func(t *testing.T) {
		previous := cfg
		previous.MACACL = []MACACLRule{{ID: "device", Interface: "lan-b", Network: "default", Direction: "ingress", SourceMAC: "02:00:00:00:00:04", Action: "deny"}}
		desired := previous
		desired.MACACL = append([]MACACLRule(nil), previous.MACACL...)
		desired.MACACL[0].SourceMAC = "02:00:00:00:00:05"
		host := Capabilities{MACACLTablePresent: true, MACACLTableManaged: true, MACACLRuleCounters: countersFor(macACLRuleComments(previous))}
		change, err := buildMACACLChange(previous, desired, host)
		if err != nil || change == nil {
			t.Fatalf("same-ID MAC ACL edit was not reconciled: change=%#v err=%v", change, err)
		}
		if !strings.Contains(string(change.Apply.Input), "ether saddr 02:00:00:00:00:05") {
			t.Fatalf("replacement does not contain edited match: %s", change.Apply.Input)
		}
	})

	t.Run("DHCP request rate", func(t *testing.T) {
		previous := cfg
		previous.DHCPGuard = []DHCPGuardPort{{Interface: "lan-a", RateLimitPPS: 20}}
		desired := previous
		desired.DHCPGuard = append([]DHCPGuardPort(nil), previous.DHCPGuard...)
		desired.DHCPGuard[0].RateLimitPPS = 100
		host := Capabilities{DHCPGuardTablePresent: true, DHCPGuardTableManaged: true, DHCPGuardRuleCounters: countersFor(dhcpGuardRuleComments(previous))}
		change, err := buildDHCPGuardChange(previous, desired, host)
		if err != nil || change == nil {
			t.Fatalf("DHCP rate edit was not reconciled: change=%#v err=%v", change, err)
		}
		if !strings.Contains(string(change.Apply.Input), "limit rate over 100/second") {
			t.Fatalf("replacement does not contain edited rate: %s", change.Apply.Input)
		}
	})
}

func countersFor(comments []string) map[string][2]uint64 {
	result := make(map[string][2]uint64, len(comments))
	for _, comment := range comments {
		result[comment] = [2]uint64{}
	}
	return result
}

func renderedRuleCounters(script []byte, prefix string) map[string][2]uint64 {
	result := map[string][2]uint64{}
	for _, line := range strings.Split(string(script), "\n") {
		if !strings.HasPrefix(line, "add rule ") {
			continue
		}
		marker := `comment "` + prefix
		start := strings.Index(line, marker)
		if start < 0 {
			continue
		}
		comment := line[start+len(`comment "`):]
		if end := strings.IndexByte(comment, '"'); end >= 0 {
			result[comment[:end]] = [2]uint64{}
		}
	}
	return result
}

func TestBuildTopologyPlanResetsRemovedBridgePoliciesToLinuxDefaults(t *testing.T) {
	previous, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	enabled := true
	nonShared := false
	previous.Bridges[0].IGMPSnooping = &enabled
	previous.Bridges[0].IGMPQuerier = &enabled
	previous.Bridges[0].STPEnabled = &enabled
	previous.Bridges[0].Ports[0].IGMPFastLeave = &enabled
	previous.Bridges[0].Ports[0].IGMPSharedDownstream = &nonShared
	previous.Bridges[0].Ports[0].IGMPRouterPort = &enabled
	desired := previous
	desired.Overrides = nil
	desired.Bridges = append([]Bridge(nil), previous.Bridges...)
	desired.Bridges[0].Ports = append([]BridgePort(nil), previous.Bridges[0].Ports...)
	desired.Bridges[0].IGMPSnooping = nil
	desired.Bridges[0].IGMPQuerier = nil
	desired.Bridges[0].STPEnabled = nil
	desired.Bridges[0].Ports[0].IGMPFastLeave = nil
	desired.Bridges[0].Ports[0].IGMPRouterPort = nil
	host := Capabilities{Features: map[string]FeatureCapability{FeatureBridgeVLAN: {State: CapabilityConditional}, FeatureSTP: {State: CapabilityConditional}}, STPControllerDiscovery: &STPControllerDiscovery{Known: true, Controller: "kernel"}, Interfaces: []HostInterface{
		{Name: "br-main", Kind: "bridge", MTU: 1500, IGMPBridgeKnown: true, IGMPSnooping: true, IGMPQuerier: true, STPKnown: true, STPEnabled: true},
		{Name: "enp2s0", Master: "br-main", MTU: 1500, IGMPPortKnown: true, IGMPFastLeave: true, IGMPRouterMode: 2},
		{Name: "enp3s0", Master: "br-main", MTU: 1500, IGMPPortKnown: true},
	}}
	plan, err := BuildTopologyPlan(previous, desired, host)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"configure STP on main":                       {"link", "set", "dev", "br-main", "type", "bridge", "stp_state", "0"},
		"configure IGMP snooping and querier on main": {"link", "set", "dev", "br-main", "type", "bridge", "mcast_snooping", "1", "mcast_querier", "0"},
		"configure IGMP port behavior on lan-a":       {"link", "set", "dev", "enp2s0", "fastleave", "off", "mcast_router", "1"},
	}
	for _, change := range plan.Changes {
		if expected, ok := want[change.Description]; ok {
			if !reflect.DeepEqual(change.Apply.Args, expected) {
				t.Errorf("%s = %#v, want %#v", change.Description, change.Apply.Args, expected)
			}
			delete(want, change.Description)
		}
	}
	for description := range want {
		t.Errorf("missing reset operation %q", description)
	}
}

func TestBuildTopologyPlanResetsRemovedSTPAndRSTPControls(t *testing.T) {
	previous, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	previous.Overrides = nil
	bridgePriority, portPriority, pathCost, enabled := uint16(4096), uint8(16), uint32(200), true
	previous.Bridges[0].STPMode = "rstp"
	previous.Bridges[0].STPPriority = &bridgePriority
	previous.Bridges[0].Ports[0].STPPriority = &portPriority
	previous.Bridges[0].Ports[0].STPPathCost = &pathCost
	previous.Bridges[0].Ports[0].STPRootBlock = &enabled
	previous.Bridges[0].Ports[0].STPEdge = &enabled
	previous.Bridges[0].Ports[0].STPPointToPoint = "yes"
	previous.Bridges[0].Ports[0].STPBPDUGuard = &enabled
	desired := previous
	desired.Bridges = append([]Bridge(nil), previous.Bridges...)
	desired.Bridges[0].Ports = append([]BridgePort(nil), previous.Bridges[0].Ports...)
	desired.Bridges[0].STPPriority = nil
	desired.Bridges[0].Ports[0].STPPriority = nil
	desired.Bridges[0].Ports[0].STPPathCost = nil
	desired.Bridges[0].Ports[0].STPRootBlock = nil
	desired.Bridges[0].Ports[0].STPEdge = nil
	desired.Bridges[0].Ports[0].STPPointToPoint = ""
	desired.Bridges[0].Ports[0].STPBPDUGuard = nil
	host := Capabilities{Features: map[string]FeatureCapability{
		FeatureBridgeVLAN: {State: CapabilityConditional}, FeatureSTP: {State: CapabilityConditional}, FeatureRSTP: {State: CapabilityConditional},
	}, STPControllerDiscovery: &STPControllerDiscovery{Known: true, Controller: "mstpd.service"}, Interfaces: []HostInterface{
		{Name: "br-main", Kind: "bridge", MTU: 1500, STPKnown: true, STPEnabled: true, STPModeKnown: true, STPMode: "rstp", STPPriorityKnown: true, STPPriority: bridgePriority},
		{Name: "enp2s0", Master: "br-main", MTU: 1500, LinkSpeedKnown: true, LinkSpeedBPS: 1_000_000_000, STPPortKnown: true, STPPortPriority: portPriority, STPPathCost: pathCost, STPRootBlock: true, STPAdvancedKnown: true, STPEdge: true, STPPointToPoint: "yes", STPBPDUGuard: true},
		{Name: "enp3s0", Master: "br-main", MTU: 1500},
	}}
	plan, err := BuildTopologyPlan(previous, desired, host)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"configure STP bridge priority on main":  "priority 32768",
		"configure STP priority on lan-a":        "priority 32",
		"configure STP cost on lan-a":            "cost 5",
		"configure STP root_block on lan-a":      "root_block off",
		"configure RSTP edge on lan-a":           "setportadminedge br-main enp2s0 no",
		"configure RSTP point-to-point on lan-a": "setportp2p br-main enp2s0 auto",
		"configure RSTP BPDU guard on lan-a":     "setbpduguard br-main enp2s0 no",
	}
	for _, change := range plan.Changes {
		if suffix, ok := want[change.Description]; ok {
			if !strings.HasSuffix(strings.Join(change.Apply.Args, " "), suffix) {
				t.Errorf("%s apply = %v, want suffix %q", change.Description, change.Apply.Args, suffix)
			}
			delete(want, change.Description)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing STP/RSTP resets: %v", want)
	}
}

func TestBuildTopologyPlanDetachesRemovedPortAndCleansItsVLANs(t *testing.T) {
	previous, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	previous.Overrides = nil
	desired := previous
	desired.Bridges = append([]Bridge(nil), previous.Bridges...)
	desired.Bridges[0].Ports = append([]BridgePort(nil), previous.Bridges[0].Ports[1:]...)
	host := Capabilities{Features: map[string]FeatureCapability{FeatureBridgeVLAN: {State: CapabilityConditional}}, Interfaces: []HostInterface{
		{Name: "br-main", Kind: "bridge", MTU: 1500},
		{Name: "enp2s0", Master: "br-main", MTU: 1500},
		{Name: "enp3s0", Master: "br-main", MTU: 1500},
	}, BridgeVLANs: []BridgeVLANState{{Device: "enp2s0", VLAN: 10, PVID: true, Untagged: true}, {Device: "enp2s0", VLAN: 20}}}
	plan, err := BuildTopologyPlan(previous, desired, host)
	if err != nil {
		t.Fatal(err)
	}
	var vlanRemovals, detached int
	for _, change := range plan.Changes {
		if change.Apply.Tool == "bridge" && len(change.Apply.Args) > 3 && change.Apply.Args[0] == "vlan" && change.Apply.Args[1] == "del" && change.Apply.Args[3] == "enp2s0" {
			vlanRemovals++
		}
		if reflect.DeepEqual(change.Apply.Args, []string{"link", "set", "dev", "enp2s0", "nomaster"}) {
			detached++
		}
	}
	if vlanRemovals != 2 || detached != 1 {
		t.Fatalf("removed port cleanup: VLAN removals=%d detach=%d changes=%#v", vlanRemovals, detached, plan.Changes)
	}
}

func TestBuildTopologyPlanDeletesRemovedManagedBridgeReversibly(t *testing.T) {
	previous, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	previous.Overrides = nil
	desired := previous
	desired.Bridges = nil
	desired.Networks = nil
	host := Capabilities{Interfaces: []HostInterface{
		{Name: "br-main", Kind: "bridge", MTU: 1500, AdminUp: true, VLANFiltering: true},
		{Name: "enp2s0", Master: "br-main", MTU: 1500},
		{Name: "enp3s0", Master: "br-main", MTU: 1500},
	}, BridgeVLANs: []BridgeVLANState{{Device: "br-main", VLAN: 10}, {Device: "enp2s0", VLAN: 10, PVID: true, Untagged: true}}}
	plan, err := BuildTopologyPlan(previous, desired, host)
	if err != nil {
		t.Fatal(err)
	}
	var deletion *Change
	for i := range plan.Changes {
		if reflect.DeepEqual(plan.Changes[i].Apply.Args, []string{"link", "del", "dev", "br-main"}) {
			deletion = &plan.Changes[i]
			break
		}
	}
	if deletion == nil || deletion.Rollback.Tool != "ip" || !strings.Contains(strings.Join(deletion.Rollback.Args, " "), "link add name br-main") {
		t.Fatalf("removed bridge deletion is missing or not reversible: %#v", deletion)
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
