package layer2

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

const MaxConfigBytes = 1 << 20
const MaxDeviceOverrides = 4096
const MaxMACBlocks = 128
const MaxMACACLRules = 256
const MaxIPACLRules = 256

var (
	stableIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	ifNamePattern   = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)
)

// Config is the versioned Layer 2 desired topology. References use stable IDs;
// interface names are resolved on the managed host when a plan is prepared.
type Config struct {
	Version             int                  `json:"version"`
	Interfaces          []Interface          `json:"interfaces"`
	Bridges             []Bridge             `json:"bridges"`
	Networks            []Network            `json:"networks"`
	Overrides           []DeviceOverride     `json:"virtual_network_overrides,omitempty"`
	MACPortRestrictions []MACPortRestriction `json:"mac_port_restrictions,omitempty"`
	MACBlocks           []MACBlock           `json:"mac_address_blocks,omitempty"`
	MACACL              []MACACLRule         `json:"mac_acls,omitempty"`
	IPACL               []IPACLRule          `json:"ip_acls,omitempty"`
	EgressRates         []EgressRateLimit    `json:"egress_rate_limits,omitempty"`
	FlowControl         []FlowControlPolicy  `json:"flow_control,omitempty"`
	Bonds               []Bond               `json:"bonds,omitempty"`
}

type Interface struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Bond defines a Linux 802.3ad aggregate. Interface is the managed virtual
// interface ID; members are dedicated physical interface IDs.
type Bond struct {
	ID         string   `json:"id"`
	Interface  string   `json:"interface"`
	Members    []string `json:"members"`
	MinLinks   uint8    `json:"min_links"`
	LACPRate   string   `json:"lacp_rate"`
	HashPolicy string   `json:"hash_policy"`
	SystemMAC  string   `json:"system_mac,omitempty"`
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
	Isolated        bool     `json:"isolated,omitempty"`
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
	Interface string `json:"interface"`
	MAC       string `json:"mac"`
	Network   string `json:"network"`
}

// MACPortRestriction locks a bridge port to an allowed set of source MACs
// within a VLAN and caps the number of dynamically learned devices.
type MACPortRestriction struct {
	Interface       string   `json:"interface"`
	Network         string   `json:"network"`
	AllowedMACs     []string `json:"allowed_macs"`
	MaxDevices      int      `json:"max_devices"`
	ViolationAction string   `json:"violation_action"`
}

// MACBlock rejects a device address at the selected bridge port and network.
type MACBlock struct {
	Interface string `json:"interface"`
	Network   string `json:"network"`
	MAC       string `json:"mac"`
}

// MACACLRule is an ordered terminal allow/deny rule scoped to one port and network.
type MACACLRule struct {
	ID             string `json:"id"`
	Interface      string `json:"interface"`
	Network        string `json:"network"`
	Direction      string `json:"direction"`
	SourceMAC      string `json:"source_mac,omitempty"`
	DestinationMAC string `json:"destination_mac,omitempty"`
	Action         string `json:"action"`
}

// IPACLRule is an ordered IPv4/IPv6 policy on one bridge port and VLAN.
type IPACLRule struct {
	ID        string `json:"id"`
	Interface string `json:"interface"`
	Network   string `json:"network"`
	Direction string `json:"direction"`
	Family    string `json:"family"`
	Source    string `json:"source,omitempty"`
	Dest      string `json:"destination,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	Port      uint16 `json:"port,omitempty"`
	Action    string `json:"action"`
}

// EgressRateLimit caps egress on a managed physical interface using TBF.
// Network-scoped shaping is deliberately represented separately by Network;
// it is rejected until the host can prove a VLAN-aware qdisc path.
type EgressRateLimit struct {
	Interface  string `json:"interface"`
	Network    string `json:"network,omitempty"`
	RateBPS    uint64 `json:"rate_bps"`
	BurstBytes uint32 `json:"burst_bytes"`
}

type FlowControlPolicy struct {
	Interface string `json:"interface"`
	Autoneg   string `json:"autoneg"`
	RX        bool   `json:"rx"`
	TX        bool   `json:"tx"`
}

func ipACLRuleComments(cfg Config) []string {
	comments := make([]string, 0, len(cfg.IPACL)*2)
	for _, rule := range cfg.IPACL {
		if rule.Direction == "ingress" || rule.Direction == "both" {
			comments = append(comments, "gamebond-ip-acl:"+rule.ID+":in", "gamebond-ip-acl:"+rule.ID+":host-in")
		}
		if rule.Direction == "egress" || rule.Direction == "both" {
			comments = append(comments, "gamebond-ip-acl:"+rule.ID+":out", "gamebond-ip-acl:"+rule.ID+":host-out")
		}
	}
	sort.Strings(comments)
	return comments
}

func macBlockRuleComments(cfg Config) []string {
	comments := make([]string, 0, len(cfg.MACBlocks)*4)
	for _, block := range cfg.MACBlocks {
		base := "gamebond-mac-block:" + block.Interface + ":" + block.Network + ":" + block.MAC
		comments = append(comments, base+":forward-in", base+":forward-out", base+":input", base+":output")
	}
	sort.Strings(comments)
	return comments
}

func macACLRuleComments(cfg Config) []string {
	comments := make([]string, 0, len(cfg.MACACL)*4)
	for _, rule := range cfg.MACACL {
		chains := []string{}
		switch rule.Direction {
		case "ingress":
			chains = []string{"forward-in", "input"}
		case "egress":
			chains = []string{"forward-out", "output"}
		case "both":
			chains = []string{"forward-in", "forward-out", "input", "output"}
		}
		for _, chain := range chains {
			comments = append(comments, "gamebond-mac-acl:"+rule.ID+":"+chain)
		}
	}
	sort.Strings(comments)
	return comments
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
	if len(c.Bonds) > 32 {
		return fmt.Errorf("bonds exceed limit 32")
	}
	bondIDs, bondInterfaces, bondMembers := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i, bond := range c.Bonds {
		if !stableIDPattern.MatchString(bond.ID) || bondIDs[bond.ID] {
			return fmt.Errorf("bonds[%d].id is invalid or duplicated", i)
		}
		bondIDs[bond.ID] = true
		if _, ok := interfaceIDs[bond.Interface]; !ok {
			return fmt.Errorf("bond %q references unknown virtual interface %q", bond.ID, bond.Interface)
		}
		if bondInterfaces[bond.Interface] {
			return fmt.Errorf("virtual interface %q is assigned to multiple bonds", bond.Interface)
		}
		bondInterfaces[bond.Interface] = true
		bondIface, _ := findInterface(c.Interfaces, bond.Interface)
		if len(bond.Members) < 2 || len(bond.Members) > 16 {
			return fmt.Errorf("bond %q must have 2..16 members", bond.ID)
		}
		if bond.MinLinks > uint8(len(bond.Members)) {
			return fmt.Errorf("bond %q min_links cannot exceed member count", bond.ID)
		}
		if bond.LACPRate != "fast" && bond.LACPRate != "slow" {
			return fmt.Errorf("bond %q lacp_rate must be fast or slow", bond.ID)
		}
		switch bond.HashPolicy {
		case "layer2", "layer2+3", "layer3+4", "encap2+3", "encap3+4":
		default:
			return fmt.Errorf("bond %q hash_policy is unsupported", bond.ID)
		}
		if bond.SystemMAC != "" {
			mac, err := net.ParseMAC(bond.SystemMAC)
			if err != nil || len(mac) != 6 || mac[0]&1 != 0 || mac.String() != bond.SystemMAC {
				return fmt.Errorf("bond %q system_mac must be a canonical unicast Ethernet address", bond.ID)
			}
		}
		seen := map[string]bool{}
		for _, memberID := range bond.Members {
			member, ok := findInterface(c.Interfaces, memberID)
			if !ok || memberID == bond.Interface {
				return fmt.Errorf("bond %q references invalid member interface %q", bond.ID, memberID)
			}
			if seen[memberID] || bondMembers[memberID] {
				return fmt.Errorf("bond member %q is duplicated or assigned to another bond", memberID)
			}
			if member.Name == bondIface.Name {
				return fmt.Errorf("bond %q cannot contain itself", bond.ID)
			}
			seen[memberID], bondMembers[memberID] = true, true
		}
	}
	for virtualID := range bondInterfaces {
		if bondMembers[virtualID] {
			return fmt.Errorf("bond interface %q cannot be another bond member", virtualID)
		}
	}

	bridgeIDs := make(map[string]struct{}, len(c.Bridges))
	bridgeNames := make(map[string]struct{}, len(c.Bridges))
	interfaceBridge := make(map[string]string)
	interfacePorts := make(map[string]BridgePort)
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
			interfacePorts[port.Interface] = port
		}
	}
	for memberID := range bondMembers {
		if _, inBridge := interfaceBridge[memberID]; inBridge {
			return fmt.Errorf("bond member %q cannot also be a bridge port", memberID)
		}
	}
	for interfaceID := range bondInterfaces {
		if bondMembers[interfaceID] {
			return fmt.Errorf("bond interface %q cannot be another bond member", interfaceID)
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
	if len(c.MACPortRestrictions) > 4096 {
		return fmt.Errorf("MAC port restrictions exceed limit 4096")
	}
	seenRestrictionPorts := make(map[string]struct{}, len(c.MACPortRestrictions))
	for _, restriction := range c.MACPortRestrictions {
		port, exists := interfacePorts[restriction.Interface]
		if !exists {
			return fmt.Errorf("MAC port restriction references unknown bridge port %q", restriction.Interface)
		}
		if _, duplicate := seenRestrictionPorts[restriction.Interface]; duplicate {
			return fmt.Errorf("MAC port restriction for interface %q is duplicated", restriction.Interface)
		}
		seenRestrictionPorts[restriction.Interface] = struct{}{}
		if restriction.Network == "" || (port.UntaggedNetwork != restriction.Network && !containsString(port.TaggedNetworks, restriction.Network)) {
			return fmt.Errorf("MAC port restriction network %q is not a member of interface %q", restriction.Network, restriction.Interface)
		}
		if port.UntaggedNetwork != restriction.Network || len(port.TaggedNetworks) != 0 {
			return fmt.Errorf("MAC port restriction on %q requires a single-network access port", restriction.Interface)
		}
		bridgeID := interfaceBridge[restriction.Interface]
		for _, bridge := range c.Bridges {
			if bridge.ID == bridgeID && len(bridge.Ports) != 1 {
				return fmt.Errorf("MAC port restriction on %q requires a bridge with exactly one managed port because Linux learned-FDB limits are bridge-wide", restriction.Interface)
			}
		}
		if restriction.MaxDevices < 1 || restriction.MaxDevices > 4096 || restriction.MaxDevices < len(restriction.AllowedMACs) {
			return fmt.Errorf("MAC port restriction max_devices must be 1..4096 and at least the allowed MAC count")
		}
		if restriction.ViolationAction != "drop" {
			return fmt.Errorf("MAC port restriction violation_action must be drop")
		}
		seenMACs := make(map[string]struct{}, len(restriction.AllowedMACs))
		for _, macText := range restriction.AllowedMACs {
			mac, err := net.ParseMAC(macText)
			if err != nil || len(mac) != 6 || mac[0]&1 != 0 || mac.String() != macText {
				return fmt.Errorf("MAC port restriction address %q must be a canonical unicast Ethernet address", macText)
			}
			if _, duplicate := seenMACs[macText]; duplicate {
				return fmt.Errorf("MAC port restriction address %q is duplicated", macText)
			}
			seenMACs[macText] = struct{}{}
		}
	}
	if len(c.MACBlocks) > MaxMACBlocks {
		return fmt.Errorf("MAC address blocks exceed limit %d", MaxMACBlocks)
	}
	if len(c.MACACL) > MaxMACACLRules {
		return fmt.Errorf("MAC ACL rules exceed limit %d", MaxMACACLRules)
	}
	if len(c.IPACL) > MaxIPACLRules {
		return fmt.Errorf("IP ACL rules exceed limit %d", MaxIPACLRules)
	}
	seenIPACLIDs, seenIPACLMatches := map[string]bool{}, map[string]bool{}
	for i, rule := range c.IPACL {
		if !stableIDPattern.MatchString(rule.ID) || seenIPACLIDs[rule.ID] {
			return fmt.Errorf("IP ACL rule %d has an invalid or duplicated ID", i)
		}
		seenIPACLIDs[rule.ID] = true
		port, exists := interfacePorts[rule.Interface]
		if !exists || rule.Network == "" || (port.UntaggedNetwork != rule.Network && !containsString(port.TaggedNetworks, rule.Network)) {
			return fmt.Errorf("IP ACL rule %q must reference a bridge port carrying its network", rule.ID)
		}
		if (port.UntaggedNetwork != "" && len(port.TaggedNetworks) != 0) || len(port.TaggedNetworks) > 1 || (port.UntaggedNetwork == "" && len(port.TaggedNetworks) != 1) {
			return fmt.Errorf("IP ACL rule %q requires a single-network port", rule.ID)
		}
		if rule.Direction != "ingress" && rule.Direction != "egress" && rule.Direction != "both" {
			return fmt.Errorf("IP ACL rule %q direction must be ingress, egress, or both", rule.ID)
		}
		if rule.Family != "ipv4" && rule.Family != "ipv6" {
			return fmt.Errorf("IP ACL rule %q family must be ipv4 or ipv6", rule.ID)
		}
		for _, prefixText := range []string{rule.Source, rule.Dest} {
			if prefixText == "" {
				continue
			}
			prefix, err := netip.ParsePrefix(prefixText)
			if err != nil || prefix.String() != prefixText || (rule.Family == "ipv4") != prefix.Addr().Is4() {
				return fmt.Errorf("IP ACL rule %q prefix %q is invalid for %s", rule.ID, prefixText, rule.Family)
			}
		}
		if rule.Protocol != "" && rule.Protocol != "tcp" && rule.Protocol != "udp" && rule.Protocol != "icmp" && rule.Protocol != "icmpv6" {
			return fmt.Errorf("IP ACL rule %q has unsupported protocol", rule.ID)
		}
		if rule.Port != 0 && rule.Protocol != "tcp" && rule.Protocol != "udp" {
			return fmt.Errorf("IP ACL rule %q port requires tcp or udp", rule.ID)
		}
		if rule.Family == "ipv4" && rule.Protocol == "icmpv6" || rule.Family == "ipv6" && rule.Protocol == "icmp" {
			return fmt.Errorf("IP ACL rule %q protocol conflicts with address family", rule.ID)
		}
		if rule.Source == "" && rule.Dest == "" && rule.Protocol == "" {
			return fmt.Errorf("IP ACL rule %q requires at least one match", rule.ID)
		}
		if rule.Action != "allow" && rule.Action != "deny" {
			return fmt.Errorf("IP ACL rule %q action must be allow or deny", rule.ID)
		}
		match := strings.Join([]string{rule.Interface, rule.Network, rule.Direction, rule.Family, rule.Source, rule.Dest, rule.Protocol, fmt.Sprint(rule.Port)}, "/")
		if seenIPACLMatches[match] {
			return fmt.Errorf("IP ACL contains ambiguous duplicate match %q", match)
		}
		seenIPACLMatches[match] = true
	}
	if len(c.EgressRates) > 64 {
		return fmt.Errorf("egress rate limits exceed limit 64")
	}
	seenRates := map[string]bool{}
	for i, limit := range c.EgressRates {
		if _, ok := interfaceIDs[limit.Interface]; !ok {
			return fmt.Errorf("egress_rate_limits[%d] references unknown interface %q", i, limit.Interface)
		}
		if limit.RateBPS < 8000 || limit.RateBPS > 100_000_000_000 {
			return fmt.Errorf("egress_rate_limits[%d].rate_bps must be 8000..100000000000", i)
		}
		if limit.Network != "" && limit.RateBPS > 4_294_967_295 {
			return fmt.Errorf("egress_rate_limits[%d].rate_bps exceeds the Linux police action limit for VLAN-scoped policies", i)
		}
		if limit.BurstBytes < 1024 || limit.BurstBytes > 16*1024*1024 {
			return fmt.Errorf("egress_rate_limits[%d].burst_bytes must be 1024..16777216", i)
		}
		key := limit.Interface + "/" + limit.Network
		if seenRates[key] {
			return fmt.Errorf("egress rate limit for scope %q is duplicated", key)
		}
		seenRates[key] = true
		if limit.Network != "" {
			port, ok := interfacePorts[limit.Interface]
			if !ok || !containsString(port.TaggedNetworks, limit.Network) {
				return fmt.Errorf("network-scoped egress rate on %q requires its network to be a tagged VLAN on that port", limit.Interface)
			}
		}
	}
	if len(c.FlowControl) > 64 {
		return fmt.Errorf("flow control policies exceed limit 64")
	}
	seenFlow := map[string]bool{}
	for i, policy := range c.FlowControl {
		if _, ok := interfaceIDs[policy.Interface]; !ok {
			return fmt.Errorf("flow_control[%d] references unknown interface %q", i, policy.Interface)
		}
		if policy.Autoneg != "on" && policy.Autoneg != "off" {
			return fmt.Errorf("flow_control[%d].autoneg must be on or off", i)
		}
		if seenFlow[policy.Interface] {
			return fmt.Errorf("flow control policy for interface %q is duplicated", policy.Interface)
		}
		seenFlow[policy.Interface] = true
		if bondMembers[policy.Interface] {
			return fmt.Errorf("flow control policy cannot target aggregate member %q; configure the aggregate interface policy", policy.Interface)
		}
	}
	seenACLIDs, seenACLMatches := map[string]bool{}, map[string]bool{}
	for i, rule := range c.MACACL {
		if !stableIDPattern.MatchString(rule.ID) || seenACLIDs[rule.ID] {
			return fmt.Errorf("MAC ACL rule %d has an invalid or duplicated ID", i)
		}
		seenACLIDs[rule.ID] = true
		port, exists := interfacePorts[rule.Interface]
		if !exists {
			return fmt.Errorf("MAC ACL rule %q references unknown bridge port %q", rule.ID, rule.Interface)
		}
		if rule.Network == "" || (port.UntaggedNetwork != rule.Network && !containsString(port.TaggedNetworks, rule.Network)) {
			return fmt.Errorf("MAC ACL rule %q network is not a member of interface %q", rule.ID, rule.Interface)
		}
		if (port.UntaggedNetwork != "" && len(port.TaggedNetworks) != 0) || len(port.TaggedNetworks) > 1 || (port.UntaggedNetwork == "" && len(port.TaggedNetworks) != 1) {
			return fmt.Errorf("MAC ACL rule %q requires a single-network port", rule.ID)
		}
		if rule.Direction != "ingress" && rule.Direction != "egress" && rule.Direction != "both" {
			return fmt.Errorf("MAC ACL rule %q direction must be ingress, egress, or both", rule.ID)
		}
		if rule.Action != "allow" && rule.Action != "deny" {
			return fmt.Errorf("MAC ACL rule %q action must be allow or deny", rule.ID)
		}
		if rule.SourceMAC == "" && rule.DestinationMAC == "" {
			return fmt.Errorf("MAC ACL rule %q requires a source or destination MAC", rule.ID)
		}
		for _, macText := range []string{rule.SourceMAC, rule.DestinationMAC} {
			if macText == "" {
				continue
			}
			mac, err := net.ParseMAC(macText)
			if err != nil || len(mac) != 6 || mac[0]&1 != 0 || mac.String() != macText {
				return fmt.Errorf("MAC ACL rule %q address %q must be a canonical unicast Ethernet address", rule.ID, macText)
			}
		}
		match := strings.Join([]string{rule.Interface, rule.Network, rule.Direction, rule.SourceMAC, rule.DestinationMAC}, "/")
		if seenACLMatches[match] {
			return fmt.Errorf("MAC ACL rules contain an ambiguous duplicate match %q", match)
		}
		seenACLMatches[match] = true
	}
	seenBlocks := make(map[string]struct{}, len(c.MACBlocks))
	for _, block := range c.MACBlocks {
		port, exists := interfacePorts[block.Interface]
		if !exists {
			return fmt.Errorf("MAC address block references unknown bridge port %q", block.Interface)
		}
		if block.Network == "" || (port.UntaggedNetwork != block.Network && !containsString(port.TaggedNetworks, block.Network)) {
			return fmt.Errorf("MAC address block network %q is not a member of interface %q", block.Network, block.Interface)
		}
		if (port.UntaggedNetwork != "" && len(port.TaggedNetworks) != 0) || len(port.TaggedNetworks) > 1 ||
			(port.UntaggedNetwork == "" && len(port.TaggedNetworks) != 1) {
			return fmt.Errorf("MAC address block on %q requires a single-network access or trunk port", block.Interface)
		}
		mac, err := net.ParseMAC(block.MAC)
		if err != nil || len(mac) != 6 || mac[0]&1 != 0 || mac.String() != block.MAC {
			return fmt.Errorf("blocked MAC %q must be a canonical unicast Ethernet address", block.MAC)
		}
		key := block.Interface + "/" + block.Network + "/" + block.MAC
		if _, duplicate := seenBlocks[key]; duplicate {
			return fmt.Errorf("MAC address block %q is duplicated", key)
		}
		seenBlocks[key] = struct{}{}
	}

	if len(c.Overrides) > MaxDeviceOverrides {
		return fmt.Errorf("virtual network overrides exceed limit %d", MaxDeviceOverrides)
	}
	seenOverrides := make(map[string]struct{}, len(c.Overrides))
	for _, override := range c.Overrides {
		if _, exists := interfaceIDs[override.Interface]; !exists {
			return fmt.Errorf("virtual network override references unknown interface %q", override.Interface)
		}
		port, exists := interfacePorts[override.Interface]
		if !exists || port.UntaggedNetwork == "" || len(port.TaggedNetworks) != 0 {
			return fmt.Errorf("virtual network override interface %q must be a configured access port", override.Interface)
		}
		mac, err := net.ParseMAC(override.MAC)
		if err != nil || len(mac) != 6 || mac[0]&1 != 0 || mac.String() != override.MAC {
			return fmt.Errorf("virtual network override MAC %q must be a canonical unicast Ethernet address", override.MAC)
		}
		if _, exists := seenOverrides[override.MAC]; exists {
			return fmt.Errorf("virtual network override MAC %q is duplicated", override.MAC)
		}
		seenOverrides[override.MAC] = struct{}{}
		networkBridgeID, exists := networkBridge[override.Network]
		if !exists {
			return fmt.Errorf("virtual network override references unknown network %q", override.Network)
		}
		if networkBridgeID != interfaceBridge[override.Interface] {
			return fmt.Errorf("virtual network override network %q must belong to the interface's bridge", override.Network)
		}
		if override.Network == port.UntaggedNetwork {
			return fmt.Errorf("virtual network override for %q must select a different network than its access VLAN", override.MAC)
		}
	}
	return nil
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func findInterface(interfaces []Interface, id string) (Interface, bool) {
	for _, iface := range interfaces {
		if iface.ID == id {
			return iface, true
		}
	}
	return Interface{}, false
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
