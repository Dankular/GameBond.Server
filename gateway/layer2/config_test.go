package layer2

import (
	"strings"
	"testing"
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

func TestDecodeConfigRejectsUnknownFields(t *testing.T) {
	_, err := DecodeConfig([]byte(`{"version":1,"unexpected":true}`))
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected unknown-field error, got %v", err)
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
