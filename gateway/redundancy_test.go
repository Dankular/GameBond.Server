package gateway

import (
	"strings"
	"testing"
	"time"

	"github.com/Dankular/GameBond.Server/gateway/layer2"
)

func TestEvaluateRedundancyCoordinatesLACPRSTPAndVRRP(t *testing.T) {
	config := &layer2.Config{
		Version: 1,
		Bonds:   []layer2.Bond{{ID: "uplink", Interface: "bond0", Members: []string{"port-a", "port-b"}, MinLinks: 1}},
		Bridges: []layer2.Bridge{{ID: "lan", Name: "br-lan", STPMode: "rstp"}},
	}
	policy := RedundancyConfig{Enabled: true, Groups: []RedundancyGroup{{ID: "gateway", Bonds: []string{"uplink"}, Bridges: []string{"lan"}, TrackVRRP: true}}}
	state := &layer2.Capabilities{
		Bonds:      []layer2.BondStatus{{ID: "uplink", ActiveMembers: 2, MinimumActive: 1, Applied: true}},
		Interfaces: []layer2.HostInterface{{Name: "br-lan", STPKnown: true, STPEnabled: true, STPMode: "rstp", STPModeKnown: true, STPControllerKnown: true}},
	}
	got := evaluateRedundancy(policy, config, state, VRRPSnapshot{Enabled: true, ServiceActive: true, Role: "BACKUP"})
	if len(got) != 1 || got[0].State != "healthy" || got[0].Role != "standby" || len(got[0].Mechanisms) != 3 {
		t.Fatalf("healthy standby status = %#v", got)
	}
	if got[0].Mechanisms[0].Recovery == "" || got[0].Mechanisms[1].Recovery == "" || got[0].Mechanisms[2].Recovery == "" {
		t.Fatalf("mechanism recovery guidance missing: %#v", got[0].Mechanisms)
	}
	state.Bonds[0].ActiveMembers = 0
	got = evaluateRedundancy(policy, config, state, VRRPSnapshot{Enabled: true, ServiceActive: true, Role: "MASTER"})
	if got[0].State != "degraded" || got[0].Cause != "lacp" {
		t.Fatalf("failed LACP status = %#v", got[0])
	}
}

func TestRuntimeRecordsRedundancyTransitions(t *testing.T) {
	runtime := &Runtime{
		redundancyLast:    map[string]RedundancyGroupStatus{},
		redundancyHistory: map[string][]RedundancyTransition{},
	}
	cfg := RedundancyConfig{Enabled: true, Groups: []RedundancyGroup{{ID: "gateway", TrackVRRP: true}}}
	firstAt := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	first := runtime.updateRedundancy(cfg, nil, nil, VRRPSnapshot{Enabled: true, ServiceActive: true, Role: "BACKUP"}, firstAt)
	if len(first) != 1 || first[0].Role != "standby" || len(first[0].Transitions) != 1 || !first[0].Transitions[0].At.Equal(firstAt) {
		t.Fatalf("initial redundancy observation = %#v", first)
	}
	secondAt := firstAt.Add(time.Second)
	second := runtime.updateRedundancy(cfg, nil, nil, VRRPSnapshot{Enabled: true, ServiceActive: true, Role: "MASTER"}, secondAt)
	if len(second[0].Transitions) != 2 {
		t.Fatalf("transition history = %#v", second[0].Transitions)
	}
	transition := second[0].Transitions[1]
	if transition.FromRole != "standby" || transition.ToRole != "active" || !transition.At.Equal(secondAt) {
		t.Fatalf("role transition = %#v", transition)
	}
}

func TestRuntimeAttributesAdditionalDegradationTransitionToOwningMechanism(t *testing.T) {
	runtime := &Runtime{redundancyLast: map[string]RedundancyGroupStatus{}, redundancyHistory: map[string][]RedundancyTransition{}}
	l2cfg := &layer2.Config{Version: 1, Bonds: []layer2.Bond{{ID: "uplink", Interface: "bond0", Members: []string{"a", "b"}, MinLinks: 1}}, Bridges: []layer2.Bridge{{ID: "lan", Name: "br-lan", STPMode: "rstp"}}}
	policy := RedundancyConfig{Enabled: true, Groups: []RedundancyGroup{{ID: "edge", Bonds: []string{"uplink"}, Bridges: []string{"lan"}}}}
	live := &layer2.Capabilities{Bonds: []layer2.BondStatus{{ID: "uplink", ActiveMembers: 2, MinimumActive: 1, Applied: true}}, Interfaces: []layer2.HostInterface{{Name: "br-lan", STPKnown: true, STPEnabled: true, STPMode: "rstp", STPModeKnown: true, STPControllerKnown: true}}}
	at := time.Date(2026, 11, 14, 11, 0, 0, 0, time.UTC)
	runtime.updateRedundancy(policy, l2cfg, live, VRRPSnapshot{}, at)
	live.Bonds[0].ActiveMembers = 0
	first := runtime.updateRedundancy(policy, l2cfg, live, VRRPSnapshot{}, at.Add(time.Second))
	if got := first[0].Transitions[len(first[0].Transitions)-1].Cause; got != "lacp" {
		t.Fatalf("LACP transition cause = %q", got)
	}
	live.Interfaces[0].STPControllerKnown = false
	second := runtime.updateRedundancy(policy, l2cfg, live, VRRPSnapshot{}, at.Add(2*time.Second))
	if len(second[0].Transitions) != 3 {
		t.Fatalf("mechanism change did not create transition: %#v", second[0].Transitions)
	}
	if got := second[0].Transitions[2].Cause; got != "stp" {
		t.Fatalf("STP transition cause = %q", got)
	}
}

func TestValidateRedundancyRejectsUnownedOrOverlappingMechanisms(t *testing.T) {
	l2cfg := &layer2.Config{Version: 1,
		Bonds: []layer2.Bond{{ID: "uplink", Interface: "bond0", Members: []string{"port-a", "port-b"}}},
	}
	policy := RedundancyConfig{Enabled: true, Groups: []RedundancyGroup{{ID: "one", Bonds: []string{"missing"}}}}
	if err := validateRedundancy(policy, l2cfg, VRRPConfig{}, nil); err == nil {
		t.Fatal("unknown bond reference accepted")
	}
	policy = RedundancyConfig{Enabled: true, Groups: []RedundancyGroup{
		{ID: "one", Bonds: []string{"uplink"}}, {ID: "two", Bonds: []string{"uplink"}},
	}}
	if err := validateRedundancy(policy, l2cfg, VRRPConfig{}, nil); err == nil {
		t.Fatal("overlapping bond ownership accepted")
	}
}

func TestValidateRedundancyRejectsBondAndBridgeTrackedBySeparateGroups(t *testing.T) {
	l2cfg := &layer2.Config{Version: 1,
		Bonds:   []layer2.Bond{{ID: "uplink", Interface: "bond0", Members: []string{"port-a", "port-b"}}},
		Bridges: []layer2.Bridge{{ID: "lan", Name: "br-lan", Ports: []layer2.BridgePort{{Interface: "bond0"}}}},
	}
	policy := RedundancyConfig{Enabled: true, Groups: []RedundancyGroup{
		{ID: "link-health", Bonds: []string{"uplink"}}, {ID: "bridge-health", Bridges: []string{"lan"}},
	}}
	if err := validateRedundancy(policy, l2cfg, VRRPConfig{}, nil); err == nil || !strings.Contains(err.Error(), "overlap on network/interface resource") {
		t.Fatalf("overlapping LACP and bridge groups accepted: %v", err)
	}
}

func TestValidateRedundancyRejectsVRRPAndBridgeTrackedBySeparateGroups(t *testing.T) {
	l2cfg := &layer2.Config{Version: 1,
		Interfaces: []layer2.Interface{{ID: "port-a", Name: "enp2s0"}},
		Bridges:    []layer2.Bridge{{ID: "lan-bridge", Name: "br-lan", Ports: []layer2.BridgePort{{Interface: "port-a"}}}},
	}
	policy := RedundancyConfig{Enabled: true, Groups: []RedundancyGroup{
		{ID: "bridge-health", Bridges: []string{"lan-bridge"}}, {ID: "gateway-health", TrackVRRP: true},
	}}
	if err := validateRedundancy(policy, l2cfg, VRRPConfig{Enabled: true, InterfaceID: "lan"}, []Interface{{ID: "lan", Name: "br-lan"}}); err == nil || !strings.Contains(err.Error(), "overlap on network/interface resource") {
		t.Fatalf("overlapping VRRP and bridge groups accepted: %v", err)
	}
}
