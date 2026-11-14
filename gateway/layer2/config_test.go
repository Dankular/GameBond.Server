package layer2

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Dankular/GameBond.Server/gateway/layer2/avprofiles"
)

const validConfig = `{"version":1,"interfaces":[{"id":"lan-a","name":"enp2s0"},{"id":"lan-b","name":"enp3s0"}],"bridges":[{"id":"main","name":"br-main","vlan_filtering":true,"ports":[{"interface":"lan-a","untagged_network":"default","tagged_networks":["voice"]},{"interface":"lan-b","untagged_network":"default"}]}],"networks":[{"id":"default","bridge":"main","vlan":10,"mtu":1500},{"id":"voice","bridge":"main","vlan":20,"mtu":1500}],"virtual_network_overrides":[{"interface":"lan-b","mac":"02:00:00:00:00:01","network":"voice"}]}`

func TestDecodeConfigAcceptsBridgeAndVirtualNetworks(t *testing.T) {
	c, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	if c.Version != 1 || len(c.Interfaces) != 2 || len(c.Bridges) != 1 || len(c.Networks) != 2 || len(c.Overrides) != 1 {
		t.Fatalf("unexpected decoded topology: %#v", c)
	}
}

func TestConfigSelectsAVProfilesPerNetworkAndRejectsConflicts(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.AVProfiles = []AVProfileSelection{{Profile: "qsys", Network: "default"}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid Pro AV profile selection rejected: %v", err)
	}
	cfg.AVProfiles = []AVProfileSelection{{Profile: "qsys", Network: "default"}, {Profile: "shure", Network: "default"}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "DSCP 46") {
		t.Fatalf("Q-SYS and Shure incompatible DSCP 46 queue requirements accepted without an active QoS map: %v", err)
	}
	cfg.AVProfiles = []AVProfileSelection{{Profile: "qsys", Network: "default"}}
	cfg.AVProfiles = append(cfg.AVProfiles, AVProfileSelection{Profile: "crestron", Network: "default"})
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "conflicts on network") {
		t.Fatalf("conflicting QoS profiles accepted: %v", err)
	}
	cfg.AVProfiles = []AVProfileSelection{{Profile: "sdvoe", Network: "default"}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "requires IGMP snooping") {
		t.Fatalf("profile selection without required IGMP snooping accepted: %v", err)
	}
	snooping, querier := true, true
	cfg.Bridges[0].IGMPSnooping, cfg.Bridges[0].IGMPQuerier = &snooping, &querier
	disabled := false
	cfg.Networks[0].IGMPSnooping = &disabled
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "requires IGMP snooping") {
		t.Fatalf("profile selection ignored disabled per-VLAN snooping: %v", err)
	}
	cfg.Networks[0].IGMPSnooping = nil
	if err := cfg.Validate(); err != nil {
		t.Fatalf("profile selection with required IGMP controls rejected: %v", err)
	}
	cfg.AVProfiles = []AVProfileSelection{{Profile: "shure", Network: "default"}, {Profile: "sdvoe", Network: "default"}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "conflicts on network") {
		t.Fatalf("opposite unregistered-multicast policies accepted: %v", err)
	}
	cfg.AVProfiles = []AVProfileSelection{{Profile: "unknown", Network: "default"}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "not a supported Pro AV profile") {
		t.Fatalf("unknown Pro AV profile accepted: %v", err)
	}
	cfg.AVProfiles = []AVProfileSelection{{Profile: "dante", Network: "missing"}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "unknown network") {
		t.Fatalf("profile selection with unknown network accepted: %v", err)
	}
	cfg.AVProfiles = []AVProfileSelection{{Profile: "qsys", Network: "default"}}
	cfg.Networks[0].MTU, cfg.Networks[1].MTU = 9000, 9000
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "MTU 1500 or less") {
		t.Fatalf("Q-SYS profile accepted jumbo MTU on its network: %v", err)
	}
}

func TestAVProfileCompatibilityNormalizesEquivalentAndOpposingSettings(t *testing.T) {
	key, filteringDisabled := normalizeAVProfileSetting(avprofiles.Setting{Key: "multicast.unregistered-filtering", Value: "disabled"})
	otherKey, floodingDisabled := normalizeAVProfileSetting(avprofiles.Setting{Key: "multicast.unregistered-flooding", Value: "disabled"})
	if key != otherKey || avProfileValuesCompatible(key, filteringDisabled, floodingDisabled) {
		t.Fatalf("Shure and SDVoE unregistered-multicast requirements were not detected as conflicting: %q=%q %q=%q", key, filteringDisabled, otherKey, floodingDisabled)
	}
	if !avProfileValuesCompatible("igmp.version", "v2-or-v3", "v2") {
		t.Fatal("a profile supporting IGMPv2 was considered incompatible with an IGMPv2 requirement")
	}
}

func TestConfigValidates8021XPortAuthentication(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.PortAuth = []PortAuth{{Interface: "lan-a", RadiusServer: "192.0.2.10", RadiusPort: 1812, SecretFile: "/etc/gamebond/8021x/lan-a.secret", NASAddress: "192.0.2.2", NASID: "gamebond-edge", ReauthSeconds: 3600, FailurePolicy: "closed", ExclusivePort: true}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid 802.1X policy rejected: %v", err)
	}
	cfg.PortAuth[0].ExclusivePort = false
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "exclusive_port") {
		t.Fatalf("shared downstream accepted for 802.1X: %v", err)
	}
	cfg.PortAuth[0].ExclusivePort = true
	cfg.PortAuth[0].SecretFile = "/tmp/radius.secret"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "secret_file") {
		t.Fatalf("unsafe RADIUS secret path accepted: %v", err)
	}
	cfg.PortAuth[0].SecretFile = "/etc/gamebond/8021x/lan-a.secret"
	cfg.PortAuth[0].FailurePolicy = "open"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "failure_policy") {
		t.Fatalf("fail-open policy accepted: %v", err)
	}
	cfg.PortAuth[0].FailurePolicy = "closed"
	cfg.PortAuth[0].Interface = "missing"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "bridge port") {
		t.Fatalf("non-bridge 802.1X port accepted: %v", err)
	}
}

func TestConfigRejects8021XOnBridgeWithUnverifiedSTPCombination(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.PortAuth = []PortAuth{{Interface: "lan-a", RadiusServer: "192.0.2.10", RadiusPort: 1812, SecretFile: "/etc/gamebond/8021x/lan-a.secret", NASAddress: "192.0.2.2", NASID: "gamebond-edge", FailurePolicy: "closed", ExclusivePort: true}}
	stp := true
	cfg.Bridges[0].STPEnabled = &stp
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "EAPOL forwarding compatibility is unverified") {
		t.Fatalf("802.1X with enabled STP was accepted: %v", err)
	}
}

func TestVoiceVLANRequiresTaggedPortMembershipAndLLDPPolicyIsValid(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Bridges[0].Ports[0].VoiceNetwork = "voice"
	priority, dscp := uint8(5), uint8(46)
	cfg.Bridges[0].Ports[0].LLDPMED = []LLDPMEDPolicy{{Application: "voice-signaling", Network: "voice", Tagged: true, Priority: &priority, DSCP: &dscp}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid voice VLAN and LLDP-MED policy rejected: %v", err)
	}
	cfg.Bridges[0].Ports[0].VoiceNetwork = "default"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "tagged separately") {
		t.Fatalf("voice VLAN assigned as access network: %v", err)
	}
	cfg.Bridges[0].Ports[0].VoiceNetwork = "voice"
	cfg.Bridges[0].Ports[0].LLDPMED[0].Application = "unknown-app"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "application") {
		t.Fatalf("unsupported LLDP-MED application accepted: %v", err)
	}
}

func TestConfigSerializationIsDeterministic(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	first, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	second, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("same desired state serialized differently:\n%s\n%s", first, second)
	}
	roundTrip, err := DecodeConfig(first)
	if err != nil {
		t.Fatal(err)
	}
	third, err := json.Marshal(roundTrip)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, third) {
		t.Fatalf("round-tripped desired state changed serialization:\n%s\n%s", first, third)
	}
}

func TestDecodeConfigAcceptsMACPortRestriction(t *testing.T) {
	input := strings.Replace(validConfig, `{"interface":"lan-a","untagged_network":"default","tagged_networks":["voice"]},`, ``, 1)
	input = strings.TrimSuffix(input, `}`) + `,"mac_port_restrictions":[{"interface":"lan-b","network":"default","allowed_macs":["02:00:00:00:00:02"],"max_devices":4,"violation_action":"drop"}]}`
	c, err := DecodeConfig([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.MACPortRestrictions) != 1 || c.MACPortRestrictions[0].MaxDevices != 4 {
		t.Fatalf("unexpected restriction: %#v", c.MACPortRestrictions)
	}
}

func TestDecodeConfigRejectsMACPortRestrictionOnUnconfiguredVLAN(t *testing.T) {
	input := strings.TrimSuffix(validConfig, `}`) + `,"mac_port_restrictions":[{"interface":"lan-b","network":"voice","allowed_macs":[],"max_devices":4,"violation_action":"drop"}]}`
	_, err := DecodeConfig([]byte(input))
	if err == nil || !strings.Contains(err.Error(), "not a member") {
		t.Fatalf("expected non-member network rejection, got %v", err)
	}
}

func TestDecodeConfigAcceptsScopedMACAddressBlock(t *testing.T) {
	input := strings.Replace(validConfig, `{"interface":"lan-a","untagged_network":"default","tagged_networks":["voice"]},`, ``, 1)
	input = strings.TrimSuffix(input, `}`) + `,"mac_address_blocks":[{"interface":"lan-b","network":"default","mac":"02:00:00:00:00:03"}]}`
	config, err := DecodeConfig([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(config.MACBlocks) != 1 {
		t.Fatalf("decoded MAC blocks = %#v", config.MACBlocks)
	}
}

func TestDecodeConfigRejectsMACAddressBlockOnMixedNetworkPort(t *testing.T) {
	input := strings.TrimSuffix(validConfig, `}`) + `,"mac_address_blocks":[{"interface":"lan-a","network":"default","mac":"02:00:00:00:00:03"}]}`
	_, err := DecodeConfig([]byte(input))
	if err == nil || !strings.Contains(err.Error(), "single-network") {
		t.Fatalf("expected network-scope rejection, got %v", err)
	}
}

func TestDecodeConfigAcceptsOrderedMACACL(t *testing.T) {
	input := strings.Replace(validConfig, `{"interface":"lan-a","untagged_network":"default","tagged_networks":["voice"]},`, ``, 1)
	input = strings.TrimSuffix(input, `}`) + `,"mac_acls":[{"id":"deny-device","interface":"lan-b","network":"default","direction":"both","source_mac":"02:00:00:00:00:04","action":"deny"}]}`
	cfg, err := DecodeConfig([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.MACACL) != 1 || cfg.MACACL[0].Action != "deny" {
		t.Fatalf("decoded MAC ACL = %#v", cfg.MACACL)
	}
}

func TestDecodeConfigRejectsAmbiguousMACACLMatch(t *testing.T) {
	input := strings.Replace(validConfig, `{"interface":"lan-a","untagged_network":"default","tagged_networks":["voice"]},`, ``, 1)
	input = strings.TrimSuffix(input, `}`) + `,"mac_acls":[{"id":"first","interface":"lan-b","network":"default","direction":"ingress","source_mac":"02:00:00:00:00:04","action":"deny"},{"id":"second","interface":"lan-b","network":"default","direction":"ingress","source_mac":"02:00:00:00:00:04","action":"allow"}]}`
	_, err := DecodeConfig([]byte(input))
	if err == nil || !strings.Contains(err.Error(), "ambiguous duplicate match") {
		t.Fatalf("expected ambiguous ACL match rejection, got %v", err)
	}
}

func TestDecodeConfigValidatesIPACLPrefixFamilyAndOrder(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Overrides = nil
	cfg.IPACL = []IPACLRule{{ID: "web", Interface: "lan-b", Network: "default", Direction: "ingress", Family: "ipv4", Source: "192.0.2.0/24", Protocol: "tcp", Port: 443, Action: "allow"}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid IP ACL rejected: %v", err)
	}
	cfg.IPACL[0].Source = "2001:db8::/32"
	if err := cfg.Validate(); err == nil {
		t.Fatal("IPv6 prefix accepted in IPv4 rule")
	}
}

func TestDecodeConfigValidatesEgressRateBoundsAndNetworkScope(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Overrides = nil
	cfg.EgressRates = []EgressRateLimit{{Interface: "lan-b", RateBPS: 10_000_000, BurstBytes: 16_384}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid egress rate rejected: %v", err)
	}
	cfg.EgressRates[0].RateBPS = 1
	if err := cfg.Validate(); err == nil {
		t.Fatal("out-of-range egress rate accepted")
	}
	cfg.EgressRates[0] = EgressRateLimit{Interface: "lan-b", Network: "default", RateBPS: 10_000_000, BurstBytes: 16_384}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "tagged VLAN") {
		t.Fatalf("expected untagged network scope rejection, got %v", err)
	}
	cfg.EgressRates[0] = EgressRateLimit{Interface: "lan-a", Network: "voice", RateBPS: 10_000_000, BurstBytes: 16_384}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("tagged VLAN network scope rejected: %v", err)
	}
}

func TestConfigValidatesRoutedNetworkIsolationReferences(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Overrides = nil
	cfg.Networks[0].RouteInterface = "br-main.10"
	cfg.Networks[1].RouteInterface = "br-main.20"
	cfg.NetworkACL = []NetworkACLRule{{ID: "av-control", SourceNetwork: "default", DestinationNetwork: "voice", Protocol: "tcp", Port: 443}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid routed isolation policy rejected: %v", err)
	}
	cfg.Networks[1].RouteInterface = ""
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "route_interface") {
		t.Fatalf("network without routed interface accepted: %v", err)
	}
	cfg.Networks[1].RouteInterface = "br-main.10"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "unique") {
		t.Fatalf("duplicate routed interface accepted: %v", err)
	}
	cfg.Networks[1].RouteInterface = "br-main.20"
	cfg.NetworkACL[0].DestinationNetwork = "missing"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "unknown network") {
		t.Fatalf("unknown destination network accepted: %v", err)
	}
}

func TestDecodeConfigValidatesStormControlBoundsAndDuplicateInterfaces(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Overrides = nil
	cfg.StormControl = []StormControl{{Interface: "lan-b", BroadcastRateBPS: 1_000_000, MulticastRateBPS: 2_000_000, BurstBytes: 16_384}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid storm control rejected: %v", err)
	}
	cfg.StormControl = append(cfg.StormControl, cfg.StormControl[0])
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("duplicate storm control accepted: %v", err)
	}
	cfg.StormControl = []StormControl{{Interface: "lan-b", BroadcastRateBPS: 1, BurstBytes: 16_384}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "rate_bps") {
		t.Fatalf("invalid storm rate accepted: %v", err)
	}
	input := strings.TrimSuffix(validConfig, `}`) + `,"storm_control":[{"interface":"lan-b","broadcast_rate_bps":1000000,"burst_bytes":16384}]}`
	decoded, err := DecodeConfig([]byte(input))
	if err != nil || len(decoded.StormControl) != 1 || decoded.StormControl[0].BroadcastRateBPS != 1_000_000 {
		t.Fatalf("storm control JSON did not round-trip: %#v, %v", decoded, err)
	}
}

func TestConfigValidatesMulticastBroadcastRateLimitsAndPrecedence(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.MulticastBroadcastLimits = []MulticastBroadcastRateLimit{{Interface: "lan-b", BroadcastRateBPS: 1_000_000, MulticastRateBPS: 2_000_000, BurstBytes: 16384}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid rate policy rejected: %v", err)
	}
	cfg.StormControl = []StormControl{{Interface: "lan-b", BroadcastRateBPS: 3_000_000, BurstBytes: 16384}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "overlaps a storm-control class") {
		t.Fatalf("overlapping policer classes accepted: %v", err)
	}
	cfg.StormControl = nil
	enabled := true
	cfg.Bridges[0].IGMPSnooping = &enabled
	cfg.MulticastBroadcastLimits[0].Interface = "lan-a"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "IGMP snooping") {
		t.Fatalf("multicast control-plane traffic policer accepted: %v", err)
	}
	cfg.Bridges[0].IGMPSnooping = nil
	cfg.MulticastBroadcastLimits[0].MulticastRateBPS = 7999
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "rates must be 8000..4294967295") {
		t.Fatalf("out-of-range rate accepted: %v", err)
	}
}

func TestConfigRejectsMulticastPoliceOnIGMPSnoopingPort(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Overrides = nil
	snooping := true
	cfg.Bridges[0].IGMPSnooping = &snooping
	cfg.StormControl = []StormControl{{Interface: "lan-b", MulticastRateBPS: 2_000_000, BurstBytes: 16_384}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "control traffic would be rate-limited") {
		t.Fatalf("multicast control traffic conflict was accepted: %v", err)
	}
}

func TestDecodeConfigValidatesFlowControlPolicy(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Overrides = nil
	cfg.FlowControl = []FlowControlPolicy{{Interface: "lan-b", Autoneg: "on", RX: true, TX: false}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid flow-control policy rejected: %v", err)
	}
	cfg.FlowControl[0].Autoneg = "auto"
	if err := cfg.Validate(); err == nil {
		t.Fatal("invalid autoneg mode accepted")
	}
}

func TestDecodeConfigValidatesDSCPQoSPolicy(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Overrides = nil
	cfg.QoS = []QoSPolicy{{Interface: "lan-b", LinkRateBPS: 1_000_000_000, Classes: []QoSClass{
		{ID: 10, DSCP: []uint8{46}, RateBPS: 100_000_000, CeilingBPS: 1_000_000_000, Priority: 0},
		{ID: 11, DSCP: []uint8{34}, RateBPS: 100_000_000, CeilingBPS: 1_000_000_000, Priority: 1},
	}}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid DSCP QoS policy rejected: %v", err)
	}
	cfg.QoS[0].Classes[1].DSCP = []uint8{46}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "DSCP 46 is assigned more than once") {
		t.Fatalf("expected duplicate DSCP rejection, got %v", err)
	}
	cfg.QoS[0].Classes[1].DSCP = []uint8{34}
	cfg.QoS[0].Classes[1].RateBPS = 1_000_000_001
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "outside the link rate") {
		t.Fatalf("expected class-rate bound rejection, got %v", err)
	}
	cfg.QoS[0].Classes[1].RateBPS = 100_000_001
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "whole kilobits per second") {
		t.Fatalf("expected shared-provider precision rejection, got %v", err)
	}
}

func TestConfigValidatesIGMPFeatureDependencies(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	querier, snooping := true, true
	cfg.Bridges[0].IGMPQuerier = &querier
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "querier requires IGMP snooping") {
		t.Fatalf("expected querier dependency validation, got %v", err)
	}
	cfg.Bridges[0].IGMPSnooping = &snooping
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid IGMP config rejected: %v", err)
	}
	cfg.Bridges[0].IGMPQuerier = nil
	fastLeave := true
	cfg.Bridges[0].IGMPSnooping = nil
	cfg.Bridges[0].Ports[0].IGMPFastLeave = &fastLeave
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "require IGMP snooping") {
		t.Fatalf("expected port IGMP dependency validation, got %v", err)
	}
	snooping = true
	cfg.Bridges[0].IGMPSnooping = &snooping
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "explicitly confirmed non-shared") {
		t.Fatalf("fast leave without downstream topology confirmation accepted: %v", err)
	}
	shared := true
	cfg.Bridges[0].Ports[0].IGMPSharedDownstream = &shared
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "explicitly confirmed non-shared") {
		t.Fatalf("fast leave on a shared downstream port accepted: %v", err)
	}
	shared = false
	if err := cfg.Validate(); err != nil {
		t.Fatalf("fast leave on an explicitly non-shared port rejected: %v", err)
	}
}

func TestConfigAcceptsExplicitSTPAndRSTPModes(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Bridges[0].STPMode = "rstp"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid RSTP mode rejected: %v", err)
	}
	cfg.Bridges[0].STPMode = "rapid"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "stp_mode must be stp or rstp") {
		t.Fatalf("invalid spanning-tree mode accepted: %v", err)
	}
}

func TestConfigValidatesSTPBridgeAndPortRanges(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	bridgePriority, portPriority, cost := uint16(4096), uint8(63), uint32(65535)
	stpEnabled := true
	cfg.Bridges[0].STPEnabled = &stpEnabled
	cfg.Bridges[0].STPPriority = &bridgePriority
	cfg.Bridges[0].Ports[0].STPPriority = &portPriority
	cfg.Bridges[0].Ports[0].STPPathCost = &cost
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid STP settings rejected: %v", err)
	}
	badPriority := uint16(4097)
	cfg.Bridges[0].STPPriority = &badPriority
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "multiple of 4096") {
		t.Fatalf("invalid bridge priority accepted: %v", err)
	}
	cfg.Bridges[0].STPPriority = nil
	badCost := uint32(0)
	cfg.Bridges[0].Ports[0].STPPathCost = &badCost
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "stp_path_cost must be 1..65535") {
		t.Fatalf("invalid port cost accepted: %v", err)
	}
}

func TestConfigRequiresRSTPForEdgeAndBPDUGuardSettings(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	edge, guard := true, true
	cfg.Bridges[0].Ports[0].STPEdge = &edge
	cfg.Bridges[0].Ports[0].STPBPDUGuard = &guard
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "require stp_mode rstp") {
		t.Fatalf("edge/BPDU guard without RSTP accepted: %v", err)
	}
	cfg.Bridges[0].STPMode = "rstp"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("edge/BPDU guard with RSTP rejected: %v", err)
	}
	cfg.Bridges[0].Ports[0].STPPointToPoint = "sometimes"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "stp_point_to_point must be") {
		t.Fatalf("invalid point-to-point mode accepted: %v", err)
	}
}

func TestConfigValidatesPortMirrorSourcesAndDestinations(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Interfaces = append(cfg.Interfaces, Interface{ID: "monitor", Name: "mon0"})
	cfg.PortMirrors = []PortMirror{{Source: "lan-a", Destination: "monitor", Direction: "both"}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid port mirror rejected: %v", err)
	}
	cfg.PortMirrors[0].Destination = "lan-a"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "must differ") {
		t.Fatalf("self-mirroring was accepted: %v", err)
	}
	cfg.PortMirrors[0] = PortMirror{Source: "lan-a", Destination: "monitor", Direction: "sideways"}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "direction") {
		t.Fatalf("invalid mirror direction was accepted: %v", err)
	}
	cfg.PortMirrors = []PortMirror{{Source: "lan-a", Destination: "monitor", Direction: "both"}, {Source: "lan-a", Destination: "monitor", Direction: "ingress"}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "direction is configured more than once") {
		t.Fatalf("overlapping mirror directions were accepted: %v", err)
	}
}

func TestConfigValidatesVLANScopedPortMirroringOnlyOnTaggedNetworks(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Interfaces = append(cfg.Interfaces, Interface{ID: "monitor", Name: "mon0"})
	cfg.PortMirrors = []PortMirror{{Source: "lan-a", Destination: "monitor", Direction: "both", Network: "voice"}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("tagged VLAN mirror rejected: %v", err)
	}
	cfg.PortMirrors[0].Network = "default"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "tagged member") {
		t.Fatalf("untagged VLAN mirror accepted: %v", err)
	}
}

func TestConfigRequiresOneMonitorAndConsistentCaptureLimit(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Interfaces = append(cfg.Interfaces, Interface{ID: "monitor", Name: "mon0"}, Interface{ID: "monitor2", Name: "mon1"})
	cfg.PortMirrors = []PortMirror{{Source: "lan-a", Destination: "monitor", Direction: "ingress", CaptureRateBPS: 5_000_000, CaptureBurstBytes: 4096},
		{Source: "lan-b", Destination: "monitor", Direction: "ingress"}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "one capture rate") {
		t.Fatalf("inconsistent capture limit accepted: %v", err)
	}
	cfg.PortMirrors[1].CaptureRateBPS, cfg.PortMirrors[1].CaptureBurstBytes = 5_000_000, 4096
	if err := cfg.Validate(); err != nil {
		t.Fatalf("consistent capture limit rejected: %v", err)
	}
	cfg.PortMirrors[1].Destination = "monitor2"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "one monitor destination") {
		t.Fatalf("multiple monitor destinations accepted: %v", err)
	}
}

func TestDecodeConfigRejectsUnknownFields(t *testing.T) {
	_, err := DecodeConfig([]byte(`{"version":1,"unexpected":true}`))
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected unknown-field error, got %v", err)
	}
}

func TestDecodeConfigRejectsPerVLANIGMPSnoopingWithoutBridgeSnooping(t *testing.T) {
	input := strings.Replace(validConfig, `"vlan":10`, `"vlan":10,"igmp_snooping":true`, 1)
	if _, err := DecodeConfig([]byte(input)); err == nil || !strings.Contains(err.Error(), "requires bridge-wide IGMP snooping") {
		t.Fatalf("per-VLAN IGMP without bridge snooping was accepted: %v", err)
	}
}

func TestDecodeConfigValidatesDHCPGuardPortsAndRateLimits(t *testing.T) {
	valid := strings.TrimSuffix(validConfig, `}`) + `,"dhcp_guard":[{"interface":"lan-a","trusted":false,"rate_limit_pps":20}]}`
	cfg, err := DecodeConfig([]byte(valid))
	if err != nil || len(cfg.DHCPGuard) != 1 || cfg.DHCPGuard[0].RateLimitPPS != 20 {
		t.Fatalf("valid DHCP guard rejected: cfg=%#v err=%v", cfg.DHCPGuard, err)
	}
	unknownPort := strings.Replace(valid, `"interface":"lan-a"`, `"interface":"lan-unknown"`, 1)
	if _, err := DecodeConfig([]byte(unknownPort)); err == nil || !strings.Contains(err.Error(), "unknown interface") {
		t.Fatalf("unknown guard port accepted: %v", err)
	}
	tooFast := strings.Replace(valid, `"rate_limit_pps":20`, `"rate_limit_pps":10001`, 1)
	if _, err := DecodeConfig([]byte(tooFast)); err == nil || !strings.Contains(err.Error(), "rate_limit_pps") {
		t.Fatalf("unbounded DHCP rate accepted: %v", err)
	}
}

func TestConfigAcceptsPerVLANIGMPSnoopingOnlyOnEnabledBridge(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	snooping := true
	cfg.Bridges[0].IGMPSnooping = &snooping
	cfg.Networks[0].IGMPSnooping = &snooping
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid per-VLAN IGMP config rejected: %v", err)
	}
	cfg.Bridges[0].IGMPSnooping = nil
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "requires bridge-wide IGMP snooping") {
		t.Fatalf("per-VLAN IGMP without bridge snooping was accepted: %v", err)
	}
}

func TestDecodeConfigRejectsMCLaGWithoutSupportedPeerProvider(t *testing.T) {
	input := strings.TrimSuffix(validConfig, "}") + `,"mc_lag":{"peer":"switch-b"}}`
	_, err := DecodeConfig([]byte(input))
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("MC-LAG configuration must be rejected without a provider, got %v", err)
	}
}

func TestDecodeConfigRejectsInterfaceAssignedToTwoBridges(t *testing.T) {
	input := strings.Replace(validConfig,
		`{"id":"main","name":"br-main","vlan_filtering":true,"ports":[{"interface":"lan-a","untagged_network":"default","tagged_networks":["voice"]},{"interface":"lan-b","untagged_network":"default"}]}`,
		`{"id":"main","name":"br-main","vlan_filtering":true,"ports":[{"interface":"lan-a","untagged_network":"default"}]},{"id":"other","name":"br-other","vlan_filtering":true,"ports":[{"interface":"lan-a"}]}`,
		1)
	_, err := DecodeConfig([]byte(input))
	if err == nil || !strings.Contains(err.Error(), "assigned to more than one bridge") {
		t.Fatalf("expected interface ownership error, got %v", err)
	}
}

func TestDecodeConfigRejectsMulticastOverrideMAC(t *testing.T) {
	input := strings.Replace(validConfig, `02:00:00:00:00:01`, `01:00:5e:00:00:01`, 1)
	_, err := DecodeConfig([]byte(input))
	if err == nil || !strings.Contains(err.Error(), "canonical unicast Ethernet address") {
		t.Fatalf("expected invalid override MAC error, got %v", err)
	}
}

func TestDecodeConfigRejectsVirtualNetworkOverrideOnTrunkPort(t *testing.T) {
	input := strings.Replace(validConfig, `"interface":"lan-b","mac":"02:00:00:00:00:01"`, `"interface":"lan-a","mac":"02:00:00:00:00:01"`, 1)
	_, err := DecodeConfig([]byte(input))
	if err == nil || !strings.Contains(err.Error(), "access port") {
		t.Fatalf("expected trunk-port override rejection, got %v", err)
	}
}

func TestDecodeConfigRejectsPortNetworkFromAnotherBridge(t *testing.T) {
	input := strings.Replace(validConfig,
		`"bridges":[{"id":"main","name":"br-main","vlan_filtering":true,"ports":[{"interface":"lan-a","untagged_network":"default","tagged_networks":["voice"]},{"interface":"lan-b","untagged_network":"default"}]}]`,
		`"bridges":[{"id":"main","name":"br-main","vlan_filtering":true,"ports":[{"interface":"lan-a","untagged_network":"default","tagged_networks":["voice"]},{"interface":"lan-b","untagged_network":"default"}]},{"id":"other","name":"br-other","vlan_filtering":true,"ports":[]}]`,
		1)
	input = strings.Replace(input, `"id":"voice","bridge":"main"`, `"id":"voice","bridge":"other"`, 1)
	_, err := DecodeConfig([]byte(input))
	if err == nil || !strings.Contains(err.Error(), `network "voice" belongs to bridge "other", not "main"`) {
		t.Fatalf("expected cross-bridge membership error, got %v", err)
	}
}

func TestDecodeConfigRejectsDuplicateVLANOnBridge(t *testing.T) {
	input := strings.Replace(validConfig, `"vlan":20`, `"vlan":10`, 1)
	_, err := DecodeConfig([]byte(input))
	if err == nil || !strings.Contains(err.Error(), "VLAN is duplicated") {
		t.Fatalf("expected duplicate VLAN error, got %v", err)
	}
}

func TestDecodeConfigRejectsOutOfRangeMTU(t *testing.T) {
	input := strings.Replace(validConfig, `"mtu":1500`, `"mtu":70000`, 1)
	_, err := DecodeConfig([]byte(input))
	if err == nil || !strings.Contains(err.Error(), "MTU must be") {
		t.Fatalf("expected MTU validation error, got %v", err)
	}
}

func TestDecodeConfigRejectsDifferentMTUsOnOneBridge(t *testing.T) {
	input := strings.Replace(validConfig, `"mtu":1500`, `"mtu":9000`, 1)
	_, err := DecodeConfig([]byte(input))
	if err == nil || !strings.Contains(err.Error(), "networks must use one MTU") {
		t.Fatalf("expected bridge MTU consistency error, got %v", err)
	}
}

func TestDecodeConfigRejectsTrailingData(t *testing.T) {
	_, err := DecodeConfig([]byte(validConfig + ` {}`))
	if err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("expected trailing-data error, got %v", err)
	}
}
