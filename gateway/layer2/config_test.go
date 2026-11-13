package layer2

import (
	"strings"
	"testing"
)

const validConfig = `{"version":1,"interfaces":[{"id":"lan-a","name":"enp2s0"},{"id":"lan-b","name":"enp3s0"}],"bridges":[{"id":"main","name":"br-main","vlan_filtering":true,"ports":[{"interface":"lan-a","untagged_network":"default","tagged_networks":["voice"]},{"interface":"lan-b","untagged_network":"default"}]}],"networks":[{"id":"default","bridge":"main","vlan":10,"mtu":1500},{"id":"voice","bridge":"main","vlan":20,"mtu":1500}],"virtual_network_overrides":[{"mac":"02:00:00:00:00:01","network":"voice"}]}`

func TestDecodeConfigAcceptsBridgeAndVirtualNetworks(t *testing.T) {
	c, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	if c.Version != 1 || len(c.Interfaces) != 2 || len(c.Bridges) != 1 || len(c.Networks) != 2 || len(c.Overrides) != 1 {
		t.Fatalf("unexpected decoded topology: %#v", c)
	}
}

func TestDecodeConfigRejectsUnknownFields(t *testing.T) {
	_, err := DecodeConfig([]byte(`{"version":1,"unexpected":true}`))
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected unknown-field error, got %v", err)
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
