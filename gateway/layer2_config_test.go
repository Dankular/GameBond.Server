package gateway

import (
	"testing"

	"github.com/Dankular/GameBond.Server/gateway/layer2"
)

func TestCloneConfigPreservesRoutedLayer2NetworkACL(t *testing.T) {
	cfg := Config{Layer2: &layer2.Config{
		Version:    1,
		Networks:   []layer2.Network{{ID: "trusted", Bridge: "main", VLAN: 10, MTU: 1500, RouteInterface: "br-main.10"}},
		NetworkACL: []layer2.NetworkACLRule{{ID: "allow-api", SourceNetwork: "trusted", DestinationNetwork: "media", Protocol: "tcp", Port: 443}},
		AVProfiles: []layer2.AVProfileSelection{{Profile: "dante", Network: "trusted"}},
	}}
	cloned := cloneConfig(cfg)
	if len(cloned.Layer2.NetworkACL) != 1 || cloned.Layer2.Networks[0].RouteInterface != "br-main.10" || len(cloned.Layer2.AVProfiles) != 1 {
		t.Fatalf("routed Layer 2 policy was lost while cloning: %#v", cloned.Layer2)
	}
	cfg.Layer2.NetworkACL[0].ID = "mutated"
	cfg.Layer2.Networks[0].RouteInterface = "br-mutated.10"
	cfg.Layer2.AVProfiles[0].Profile = "mutated"
	if cloned.Layer2.NetworkACL[0].ID != "allow-api" || cloned.Layer2.Networks[0].RouteInterface != "br-main.10" || cloned.Layer2.AVProfiles[0].Profile != "dante" {
		t.Fatalf("cloned Layer 2 policies alias the caller: %#v", cloned.Layer2)
	}
}

func TestCloneConfigDeepCopiesIGMPOverrideAndDHCPGuard(t *testing.T) {
	snooping := false
	cfg := Config{Layer2: &layer2.Config{
		Networks:  []layer2.Network{{ID: "media", Bridge: "main", VLAN: 20, MTU: 1500, IGMPSnooping: &snooping}},
		DHCPGuard: []layer2.DHCPGuardPort{{Interface: "lan-a", RateLimitPPS: 10}},
	}}
	cloned := cloneConfig(cfg)
	*cfg.Layer2.Networks[0].IGMPSnooping = true
	cfg.Layer2.DHCPGuard[0].RateLimitPPS = 99
	if *cloned.Layer2.Networks[0].IGMPSnooping || cloned.Layer2.DHCPGuard[0].RateLimitPPS != 10 {
		t.Fatalf("Layer 2 clone shares mutable feature state: %#v", cloned.Layer2)
	}
}

func TestLayer2SnapshotConfigRetainsPreviousSTPIntentForSafeTeardown(t *testing.T) {
	enabled, edge, guard := true, true, true
	priority, cost := uint16(4096), uint32(100)
	previous := layer2.Config{Version: 1, Bridges: []layer2.Bridge{{ID: "main", Name: "br-main", STPEnabled: &enabled, STPMode: "rstp", STPPriority: &priority, Ports: []layer2.BridgePort{{Interface: "lan", STPPathCost: &cost, STPEdge: &edge, STPBPDUGuard: &guard}}}}}
	desired := layer2.Config{Version: 1, Bridges: []layer2.Bridge{{ID: "main", Name: "br-main", Ports: []layer2.BridgePort{}}}}
	snapshot := mergeLayer2SnapshotConfig(previous, desired)
	if len(snapshot.Bridges) != 1 {
		t.Fatalf("snapshot bridge count = %d, want 1", len(snapshot.Bridges))
	}
	bridge := snapshot.Bridges[0]
	if bridge.STPEnabled == nil || !*bridge.STPEnabled || bridge.STPMode != "rstp" || bridge.STPPriority == nil || *bridge.STPPriority != priority {
		t.Fatalf("previous bridge STP intent was lost: %#v", bridge)
	}
	if len(bridge.Ports) != 1 || bridge.Ports[0].STPPathCost == nil || *bridge.Ports[0].STPPathCost != cost || bridge.Ports[0].STPEdge == nil || !*bridge.Ports[0].STPEdge || bridge.Ports[0].STPBPDUGuard == nil || !*bridge.Ports[0].STPBPDUGuard {
		t.Fatalf("previous port STP intent was lost: %#v", bridge.Ports)
	}
	removed := mergeLayer2SnapshotConfig(previous, layer2.Config{Version: 1})
	if len(removed.Bridges) != 1 || removed.Bridges[0].STPMode != "rstp" {
		t.Fatalf("removed bridge STP intent was lost from snapshot: %#v", removed.Bridges)
	}
}

func TestCloneConfigCopiesIGMPSharedDownstreamConfirmation(t *testing.T) {
	nonShared := false
	cfg := Config{Layer2: &layer2.Config{Version: 1, Bridges: []layer2.Bridge{{Ports: []layer2.BridgePort{{IGMPSharedDownstream: &nonShared}}}}}}
	cloned := cloneConfig(cfg)
	if cloned.Layer2.Bridges[0].Ports[0].IGMPSharedDownstream == nil || *cloned.Layer2.Bridges[0].Ports[0].IGMPSharedDownstream {
		t.Fatalf("shared-downstream confirmation was lost: %#v", cloned.Layer2.Bridges[0].Ports[0])
	}
	nonShared = true
	if *cloned.Layer2.Bridges[0].Ports[0].IGMPSharedDownstream {
		t.Fatal("cloned shared-downstream confirmation aliases the caller")
	}
}

func TestCloneConfigDeepCopiesSTPSettings(t *testing.T) {
	bridgePriority, portPriority, pathCost, rootBlock, edge, guard := uint16(4096), uint8(12), uint32(250), true, true, true
	cfg := Config{Layer2: &layer2.Config{Bridges: []layer2.Bridge{{STPPriority: &bridgePriority, Ports: []layer2.BridgePort{{STPPriority: &portPriority, STPPathCost: &pathCost, STPRootBlock: &rootBlock, STPEdge: &edge, STPPointToPoint: "auto", STPBPDUGuard: &guard}}}}}}
	cloned := cloneConfig(cfg)
	bridgePriority, portPriority, pathCost, rootBlock, edge, guard = 8192, 13, 500, false, false, false
	port := cloned.Layer2.Bridges[0].Ports[0]
	if *cloned.Layer2.Bridges[0].STPPriority != 4096 || *port.STPPriority != 12 || *port.STPPathCost != 250 || !*port.STPRootBlock || !*port.STPEdge || !*port.STPBPDUGuard || port.STPPointToPoint != "auto" {
		t.Fatalf("cloned STP policy aliases mutable input: %#v", cloned.Layer2.Bridges[0])
	}
}

func TestCloneConfigCopiesMulticastBroadcastRatePolicies(t *testing.T) {
	cfg := Config{Layer2: &layer2.Config{MulticastBroadcastLimits: []layer2.MulticastBroadcastRateLimit{{Interface: "lan-a", BroadcastRateBPS: 100000, BurstBytes: 2048}}}}
	cloned := cloneConfig(cfg)
	cfg.Layer2.MulticastBroadcastLimits[0].BroadcastRateBPS = 500000
	if cloned.Layer2.MulticastBroadcastLimits[0].BroadcastRateBPS != 100000 {
		t.Fatalf("cloned policer policy aliases input: %#v", cloned.Layer2.MulticastBroadcastLimits)
	}
}

func TestCloneConfigDeepCopiesLLDPMEDPolicy(t *testing.T) {
	priority, dscp := uint8(5), uint8(46)
	cfg := Config{Layer2: &layer2.Config{Version: 1, Bridges: []layer2.Bridge{{Ports: []layer2.BridgePort{{Interface: "lan-a", VoiceNetwork: "voice", TaggedNetworks: []string{"voice"}, LLDPMED: []layer2.LLDPMEDPolicy{{Application: "voice-signaling", Network: "voice", Tagged: true, Priority: &priority, DSCP: &dscp}}}}}}}}
	cloned := cloneConfig(cfg)
	cfg.Layer2.Bridges[0].Ports[0].TaggedNetworks[0] = "changed"
	cfg.Layer2.Bridges[0].Ports[0].LLDPMED[0].Application = "changed"
	priority, dscp = 1, 0
	policy := cloned.Layer2.Bridges[0].Ports[0].LLDPMED[0]
	if cloned.Layer2.Bridges[0].Ports[0].TaggedNetworks[0] != "voice" || policy.Application != "voice-signaling" || *policy.Priority != 5 || *policy.DSCP != 46 {
		t.Fatalf("cloned LLDP-MED policy aliases mutable input: %#v", cloned.Layer2.Bridges[0].Ports[0])
	}
}
