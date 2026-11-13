package layer2

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"regexp"
)

const MaxConfigBytes = 1 << 20

var (
	stableIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	ifNamePattern   = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)
)

// Config is the versioned Layer 2 desired topology. References use stable IDs;
// interface names are resolved on the managed host when a plan is prepared.
type Config struct {
	Version    int              `json:"version"`
	Interfaces []Interface      `json:"interfaces"`
	Bridges    []Bridge         `json:"bridges"`
	Networks   []Network        `json:"networks"`
	Overrides  []DeviceOverride `json:"virtual_network_overrides,omitempty"`
}

type Interface struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Bridge struct {
	ID            string       `json:"id"`
	Name          string       `json:"name"`
	VLANFiltering bool         `json:"vlan_filtering"`
	Ports         []BridgePort `json:"ports"`
}

type BridgePort struct {
	Interface       string   `json:"interface"`
	UntaggedNetwork string   `json:"untagged_network,omitempty"`
	TaggedNetworks  []string `json:"tagged_networks,omitempty"`
}

// Network represents one VLAN-backed virtual network on a managed bridge.
type Network struct {
	ID     string `json:"id"`
	Bridge string `json:"bridge"`
	VLAN   uint16 `json:"vlan"`
	MTU    int    `json:"mtu"`
}

// DeviceOverride assigns an explicitly authorized device identity to a
// configured virtual network, taking precedence over the port's default VLAN.
type DeviceOverride struct {
	MAC     string `json:"mac"`
	Network string `json:"network"`
}

// DecodeConfig strictly decodes and validates a Layer 2 configuration before
// any host capability query or network mutation is performed.
func DecodeConfig(data []byte) (Config, error) {
	var c Config
	if len(data) > MaxConfigBytes {
		return c, fmt.Errorf("Layer 2 config exceeds %d byte limit", MaxConfigBytes)
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, fmt.Errorf("Layer 2 config: %w", err)
	}
	var trailing any
	if err := d.Decode(&trailing); err != io.EOF {
		return c, fmt.Errorf("Layer 2 config contains trailing data")
	}
	if err := c.Validate(); err != nil {
		return c, err
	}
	return c, nil
}

func (c Config) Validate() error {
	if c.Version != 1 {
		return fmt.Errorf("Layer 2 config version must be 1")
	}
	interfaceIDs := make(map[string]struct{}, len(c.Interfaces))
	interfaceNames := make(map[string]struct{}, len(c.Interfaces))
	for i, in := range c.Interfaces {
		if !stableIDPattern.MatchString(in.ID) {
			return fmt.Errorf("interfaces[%d].id must be a lowercase stable ID", i)
		}
		if _, exists := interfaceIDs[in.ID]; exists {
			return fmt.Errorf("interface ID %q is duplicated", in.ID)
		}
		interfaceIDs[in.ID] = struct{}{}
		if !ifNamePattern.MatchString(in.Name) || in.Name == "." || in.Name == ".." {
			return fmt.Errorf("interfaces[%d].name is not a valid Linux interface name", i)
		}
		if _, exists := interfaceNames[in.Name]; exists {
			return fmt.Errorf("interface name %q is duplicated", in.Name)
		}
		interfaceNames[in.Name] = struct{}{}
	}

	bridgeIDs := make(map[string]struct{}, len(c.Bridges))
	bridgeNames := make(map[string]struct{}, len(c.Bridges))
	interfaceBridge := make(map[string]string)
	for i, br := range c.Bridges {
		if !stableIDPattern.MatchString(br.ID) {
			return fmt.Errorf("bridges[%d].id must be a lowercase stable ID", i)
		}
		if _, exists := bridgeIDs[br.ID]; exists {
			return fmt.Errorf("bridge ID %q is duplicated", br.ID)
		}
		bridgeIDs[br.ID] = struct{}{}
		if !ifNamePattern.MatchString(br.Name) || br.Name == "." || br.Name == ".." {
			return fmt.Errorf("bridges[%d].name is not a valid Linux interface name", i)
		}
		if _, exists := bridgeNames[br.Name]; exists {
			return fmt.Errorf("bridge name %q is duplicated", br.Name)
		}
		if _, exists := interfaceNames[br.Name]; exists {
			return fmt.Errorf("bridge name %q conflicts with a managed interface", br.Name)
		}
		bridgeNames[br.Name] = struct{}{}
		seenPorts := make(map[string]struct{}, len(br.Ports))
		for _, port := range br.Ports {
			if _, exists := interfaceIDs[port.Interface]; !exists {
				return fmt.Errorf("bridge %q references unknown interface %q", br.ID, port.Interface)
			}
			if _, exists := seenPorts[port.Interface]; exists {
				return fmt.Errorf("bridge %q lists interface %q more than once", br.ID, port.Interface)
			}
			seenPorts[port.Interface] = struct{}{}
			if previous, exists := interfaceBridge[port.Interface]; exists {
				return fmt.Errorf("interface %q is assigned to more than one bridge (%q and %q)", port.Interface, previous, br.ID)
			}
			interfaceBridge[port.Interface] = br.ID
		}
	}

	networkIDs := make(map[string]struct{}, len(c.Networks))
	networkBridge := make(map[string]string, len(c.Networks))
	bridgeVLANs := make(map[string]map[uint16]struct{})
	bridgeMTUs := make(map[string]int)
	for i, network := range c.Networks {
		if !stableIDPattern.MatchString(network.ID) {
			return fmt.Errorf("networks[%d].id must be a lowercase stable ID", i)
		}
		if _, exists := networkIDs[network.ID]; exists {
			return fmt.Errorf("network ID %q is duplicated", network.ID)
		}
		networkIDs[network.ID] = struct{}{}
		networkBridge[network.ID] = network.Bridge
		if _, exists := bridgeIDs[network.Bridge]; !exists {
			return fmt.Errorf("network %q references unknown bridge %q", network.ID, network.Bridge)
		}
		if network.VLAN < 1 || network.VLAN > 4094 {
			return fmt.Errorf("network %q VLAN must be 1..4094", network.ID)
		}
		if network.MTU < 576 || network.MTU > 65535 {
			return fmt.Errorf("network %q MTU must be 576..65535", network.ID)
		}
		if mtu, exists := bridgeMTUs[network.Bridge]; exists && mtu != network.MTU {
			return fmt.Errorf("bridge %q networks must use one MTU", network.Bridge)
		}
		bridgeMTUs[network.Bridge] = network.MTU
		if bridgeVLANs[network.Bridge] == nil {
			bridgeVLANs[network.Bridge] = make(map[uint16]struct{})
		}
		if _, exists := bridgeVLANs[network.Bridge][network.VLAN]; exists {
			return fmt.Errorf("bridge %q VLAN is duplicated: %d", network.Bridge, network.VLAN)
		}
		bridgeVLANs[network.Bridge][network.VLAN] = struct{}{}
	}

	for _, br := range c.Bridges {
		for _, port := range br.Ports {
			seenNetworks := make(map[string]struct{}, len(port.TaggedNetworks)+1)
			if port.UntaggedNetwork != "" {
				if err := validatePortNetwork(br.ID, port.UntaggedNetwork, networkBridge); err != nil {
					return err
				}
				seenNetworks[port.UntaggedNetwork] = struct{}{}
			}
			for _, networkID := range port.TaggedNetworks {
				if err := validatePortNetwork(br.ID, networkID, networkBridge); err != nil {
					return err
				}
				if _, exists := seenNetworks[networkID]; exists {
					return fmt.Errorf("bridge %q port %q repeats network %q", br.ID, port.Interface, networkID)
				}
				seenNetworks[networkID] = struct{}{}
			}
			if len(seenNetworks) > 0 && !br.VLANFiltering {
				return fmt.Errorf("bridge %q must enable VLAN filtering for configured network membership", br.ID)
			}
		}
	}

	seenOverrides := make(map[string]struct{}, len(c.Overrides))
	for _, override := range c.Overrides {
		mac, err := net.ParseMAC(override.MAC)
		if err != nil || len(mac) != 6 || mac[0]&1 != 0 || mac.String() != override.MAC {
			return fmt.Errorf("virtual network override MAC %q must be a canonical unicast Ethernet address", override.MAC)
		}
		if _, exists := seenOverrides[override.MAC]; exists {
			return fmt.Errorf("virtual network override MAC %q is duplicated", override.MAC)
		}
		seenOverrides[override.MAC] = struct{}{}
		if _, exists := networkIDs[override.Network]; !exists {
			return fmt.Errorf("virtual network override references unknown network %q", override.Network)
		}
	}
	return nil
}

func validatePortNetwork(bridgeID, networkID string, networkBridge map[string]string) error {
	owner, exists := networkBridge[networkID]
	if !exists {
		return fmt.Errorf("bridge %q port references unknown network %q", bridgeID, networkID)
	}
	if owner != bridgeID {
		return fmt.Errorf("network %q belongs to bridge %q, not %q", networkID, owner, bridgeID)
	}
	return nil
}
