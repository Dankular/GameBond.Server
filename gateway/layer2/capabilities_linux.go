//go:build linux

package layer2

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type jsonBool bool

func (b *jsonBool) UnmarshalJSON(data []byte) error {
	var flag bool
	if err := json.Unmarshal(data, &flag); err == nil {
		*b = jsonBool(flag)
		return nil
	}
	var number int
	if err := json.Unmarshal(data, &number); err == nil && (number == 0 || number == 1) {
		*b = jsonBool(number == 1)
		return nil
	}
	return fmt.Errorf("expected boolean or 0/1")
}

type CapabilityState string

const (
	CapabilitySupported   CapabilityState = "supported"
	CapabilityConditional CapabilityState = "conditional"
	CapabilityUnsupported CapabilityState = "unsupported"
	CapabilityUnavailable CapabilityState = "unavailable"
)

const (
	FeatureBridgeVLAN       = "bridge_vlan"
	FeatureVirtualNet       = "virtual_network_override"
	FeatureJumbo            = "jumbo_frames"
	FeaturePortIsolation    = "port_isolation"
	FeatureMACPort          = "mac_port_restriction"
	FeatureMACBlock         = "mac_address_blocking"
	FeatureMACACL           = "mac_acl_device_isolation"
	FeatureIPACL            = "ip_acl_network_isolation"
	FeatureNetworkIsolation = "routed_network_isolation"
	FeatureEgressRate       = "egress_rate_limit"
	FeatureFlowControl      = "flow_control"
	FeatureQoSDSCP          = "qos_dscp"
	FeatureStormControl     = "storm_control"
	FeatureMultiRate        = "multicast_broadcast_rate_limit"
	FeatureIGMPSnoop        = "igmp_snooping"
	FeatureIGMPVLAN         = "igmp_vlan_snooping"
	FeatureIGMPAdvanced     = "igmp_advanced"
	FeatureDHCPSnoop        = "dhcp_snooping_guarding"
	FeatureDHCPBinding      = "dhcp_lease_binding_guard"
	Feature8021X            = "8021x_control"
	FeatureVoiceVLAN        = "voice_vlan"
	FeatureLLDPMED          = "lldp_med"
	FeatureSTP              = "stp"
	FeatureRSTP             = "rstp"
	FeatureLoopProtect      = "loop_protection"
	FeatureLACP             = "lacp_port_aggregation"
	FeatureRedundancy       = "redundancy"
	FeatureMCLAG            = "mc_lag"
	FeatureVRRP             = "vrrp_gateway_failover"
	FeaturePortMirror       = "port_mirroring"
)

type FeatureCapability struct {
	State  CapabilityState `json:"state"`
	Reason string          `json:"reason,omitempty"`
}

// STPControllerDiscovery reports only local controller ownership signals. It
// deliberately does not treat remote bridges sending BPDUs as local control
// plane conflicts.
type STPControllerDiscovery struct {
	Known      bool   `json:"known"`
	Conflict   bool   `json:"conflict"`
	Controller string `json:"controller,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

type HostInterface struct {
	Name                string          `json:"name"`
	Kind                string          `json:"kind,omitempty"`
	Master              string          `json:"master,omitempty"`
	MTU                 int             `json:"mtu"`
	MaxMTU              int             `json:"max_mtu,omitempty"`
	OperState           string          `json:"oper_state,omitempty"`
	AdminUp             bool            `json:"admin_up"`
	VLANFiltering       bool            `json:"vlan_filtering,omitempty"`
	GroupFwdMaskKnown   bool            `json:"group_fwd_mask_known,omitempty"`
	GroupFwdMask        uint32          `json:"group_fwd_mask,omitempty"`
	TCClsact            bool            `json:"tc_clsact,omitempty"`
	LegacyIngress       bool            `json:"tc_legacy_ingress,omitempty"`
	TCFilters           []TCFilterState `json:"-"`
	TCEgressFilters     []TCFilterState `json:"-"`
	RootQdisc           string          `json:"root_qdisc,omitempty"`
	RootQdiscHandle     string          `json:"-"`
	LinkSpeedBPS        uint64          `json:"link_speed_bps,omitempty"`
	LinkSpeedKnown      bool            `json:"-"`
	IGMPBridgeKnown     bool            `json:"igmp_bridge_state_known,omitempty"`
	IGMPSnooping        bool            `json:"igmp_snooping"`
	IGMPQuerier         bool            `json:"igmp_querier"`
	IGMPVLANKnown       bool            `json:"igmp_vlan_mode_known,omitempty"`
	IGMPVLANMode        bool            `json:"igmp_vlan_mode"`
	IGMPPortKnown       bool            `json:"igmp_port_state_known,omitempty"`
	IGMPFastLeave       bool            `json:"igmp_fast_leave"`
	IGMPRouterMode      int             `json:"igmp_router_mode"`
	STPKnown            bool            `json:"stp_state_known,omitempty"`
	STPEnabled          bool            `json:"stp_enabled"`
	STPModeKnown        bool            `json:"stp_mode_known,omitempty"`
	STPMode             string          `json:"stp_mode,omitempty"`
	STPControllerKnown  bool            `json:"stp_controller_state_known,omitempty"`
	STPRootID           string          `json:"stp_root_id,omitempty"`
	STPRootPort         string          `json:"stp_root_port,omitempty"`
	STPTopologyChange   bool            `json:"stp_topology_change,omitempty"`
	STPTopologyChanges  uint64          `json:"stp_topology_change_count,omitempty"`
	STPRole             string          `json:"stp_role,omitempty"`
	STPPortState        string          `json:"stp_port_state,omitempty"`
	STPPriorityKnown    bool            `json:"stp_priority_known,omitempty"`
	STPPriority         uint16          `json:"stp_priority,omitempty"`
	STPPortKnown        bool            `json:"stp_port_state_known,omitempty"`
	STPPortPriority     uint8           `json:"stp_port_priority,omitempty"`
	STPPathCost         uint32          `json:"stp_path_cost,omitempty"`
	STPRootBlock        bool            `json:"stp_root_block,omitempty"`
	STPAdvancedKnown    bool            `json:"stp_advanced_state_known,omitempty"`
	STPEdge             bool            `json:"stp_edge,omitempty"`
	STPPointToPoint     string          `json:"stp_point_to_point,omitempty"`
	STPBPDUGuard        bool            `json:"stp_bpdu_guard,omitempty"`
	RootQdiscRateBPS    uint64          `json:"root_qdisc_rate_bps,omitempty"`
	RootQdiscBurstBytes uint32          `json:"root_qdisc_burst_bytes,omitempty"`
	PauseKnown          bool            `json:"pause_known,omitempty"`
	PauseAutoneg        string          `json:"pause_autoneg,omitempty"`
	PauseRX             bool            `json:"pause_rx,omitempty"`
	PauseTX             bool            `json:"pause_tx,omitempty"`
	PauseError          string          `json:"pause_error,omitempty"`
	Isolated            bool            `json:"isolated,omitempty"`
	IsolationKnown      bool            `json:"-"`
	Locked              bool            `json:"locked,omitempty"`
	MaxLearned          int             `json:"max_learned,omitempty"`
	BridgePortKnown     bool            `json:"-"`
	FDBMaxLearned       int             `json:"fdb_max_learned,omitempty"`
	FDBLimitKnown       bool            `json:"-"`
	BondMode            string          `json:"bond_mode,omitempty"`
	BondMinLinks        int             `json:"bond_min_links,omitempty"`
	BondHashPolicy      string          `json:"bond_hash_policy,omitempty"`
	BondLACPRate        string          `json:"bond_lacp_rate,omitempty"`
	Address             string          `json:"address,omitempty"`
}

type BondStatus struct {
	ID            string   `json:"id"`
	Interface     string   `json:"interface"`
	Mode          string   `json:"mode,omitempty"`
	PartnerSystem string   `json:"partner_system,omitempty"`
	ActiveMembers int      `json:"active_members"`
	MinimumActive int      `json:"minimum_active"`
	Members       []string `json:"members"`
	Collecting    []string `json:"collecting"`
	Distributing  []string `json:"distributing"`
	Applied       bool     `json:"applied"`
	Reason        string   `json:"reason,omitempty"`
}

type TCFilterState struct {
	Priority         int    `json:"priority"`
	Kind             string `json:"kind"`
	SourceMAC        string `json:"source_mac,omitempty"`
	DestinationMAC   string `json:"destination_mac,omitempty"`
	DestinationMask  string `json:"destination_mac_mask,omitempty"`
	NumVLANs         int    `json:"num_of_vlans"`
	HasNumVLANs      bool   `json:"has_num_of_vlans"`
	VLANAction       string `json:"vlan_action,omitempty"`
	VLANControl      string `json:"vlan_control,omitempty"`
	VLANID           uint16 `json:"vlan_id,omitempty"`
	DropTagged       bool   `json:"drop_tagged,omitempty"`
	PoliceRateBPS    uint64 `json:"police_rate_bps,omitempty"`
	PoliceBurstBytes uint32 `json:"police_burst_bytes,omitempty"`
	MirrorDevice     string `json:"mirror_device,omitempty"`
	MirrorAction     string `json:"mirror_action,omitempty"`
	MirrorDirection  string `json:"mirror_direction,omitempty"`
	Packets          uint64 `json:"packets,omitempty"`
	Bytes            uint64 `json:"bytes,omitempty"`
	Drops            uint64 `json:"drops,omitempty"`
}

type VirtualNetworkOverrideStatus struct {
	Interface string `json:"interface"`
	MAC       string `json:"mac"`
	Network   string `json:"network"`
	VLAN      uint16 `json:"vlan"`
	Applied   bool   `json:"applied"`
	Reason    string `json:"reason,omitempty"`
}

type BridgeVLANState struct {
	Device   string `json:"device"`
	VLAN     uint16 `json:"vlan"`
	PVID     bool   `json:"pvid,omitempty"`
	Untagged bool   `json:"untagged,omitempty"`
}

type BridgeVLANGLOBALState struct {
	Bridge   string `json:"bridge"`
	VLAN     uint16 `json:"vlan"`
	Snooping bool   `json:"snooping"`
}

type BridgeFDBEntry struct {
	MAC    string `json:"mac"`
	Device string `json:"device"`
	VLAN   uint16 `json:"vlan"`
	Static bool   `json:"static"`
	Locked bool   `json:"locked"`
}

type MACPortRestrictionStatus struct {
	Interface       string   `json:"interface"`
	Network         string   `json:"network"`
	VLAN            uint16   `json:"vlan"`
	AllowedMACs     []string `json:"allowed_macs"`
	MaxDevices      int      `json:"max_devices"`
	LearnedDevices  int      `json:"learned_devices"`
	LockedEntries   int      `json:"locked_entries"`
	ViolationAction string   `json:"violation_action"`
	Applied         bool     `json:"applied"`
	Reason          string   `json:"reason,omitempty"`
}

type MACBlockStatus struct {
	Interface string `json:"interface"`
	Network   string `json:"network"`
	MAC       string `json:"mac"`
	Packets   uint64 `json:"packets"`
	Bytes     uint64 `json:"bytes"`
	Applied   bool   `json:"applied"`
	Reason    string `json:"reason,omitempty"`
}

type MACACLStatus struct {
	ID        string `json:"id"`
	Direction string `json:"direction"`
	Action    string `json:"action"`
	RuleOrder int    `json:"rule_order"`
	Packets   uint64 `json:"packets"`
	Bytes     uint64 `json:"bytes"`
	Applied   bool   `json:"applied"`
	Reason    string `json:"reason,omitempty"`
}

type IPACLStatus struct {
	ID        string `json:"id"`
	Direction string `json:"direction"`
	Action    string `json:"action"`
	RuleOrder int    `json:"rule_order"`
	Packets   uint64 `json:"packets"`
	Bytes     uint64 `json:"bytes"`
	Applied   bool   `json:"applied"`
	Reason    string `json:"reason,omitempty"`
}

type NetworkIsolationStatus struct {
	ID                 string `json:"id"`
	SourceNetwork      string `json:"source_network"`
	DestinationNetwork string `json:"destination_network"`
	Packets            uint64 `json:"packets"`
	Bytes              uint64 `json:"bytes"`
	Applied            bool   `json:"applied"`
	Reason             string `json:"reason,omitempty"`
}

type EgressRateStatus struct {
	Interface           string `json:"interface"`
	Network             string `json:"network,omitempty"`
	RateBPS             uint64 `json:"rate_bps"`
	BurstBytes          uint32 `json:"burst_bytes"`
	EffectiveQdisc      string `json:"effective_qdisc,omitempty"`
	EffectiveRateBPS    uint64 `json:"effective_rate_bps,omitempty"`
	EffectiveBurstBytes uint32 `json:"effective_burst_bytes,omitempty"`
	Applied             bool   `json:"applied"`
	Reason              string `json:"reason,omitempty"`
}

type FlowControlStatus struct {
	Interface string `json:"interface"`
	Autoneg   string `json:"autoneg"`
	RX        bool   `json:"rx"`
	TX        bool   `json:"tx"`
	Supported bool   `json:"supported"`
	Applied   bool   `json:"applied"`
	Reason    string `json:"reason,omitempty"`
}

type PortMirrorStatus struct {
	Source            string `json:"source"`
	Destination       string `json:"destination"`
	Direction         string `json:"direction"`
	Network           string `json:"network,omitempty"`
	CaptureRateBPS    uint64 `json:"capture_rate_bps,omitempty"`
	CaptureBurstBytes uint32 `json:"capture_burst_bytes,omitempty"`
	Packets           uint64 `json:"packets,omitempty"`
	Bytes             uint64 `json:"bytes,omitempty"`
	Applied           bool   `json:"applied"`
	Reason            string `json:"reason,omitempty"`
}

type StormControlStatus struct {
	Interface        string `json:"interface"`
	BroadcastRateBPS uint64 `json:"broadcast_rate_bps,omitempty"`
	BroadcastDrops   uint64 `json:"broadcast_drops,omitempty"`
	MulticastRateBPS uint64 `json:"multicast_rate_bps,omitempty"`
	MulticastDrops   uint64 `json:"multicast_drops,omitempty"`
	BurstBytes       uint32 `json:"burst_bytes"`
	Applied          bool   `json:"applied"`
	Reason           string `json:"reason,omitempty"`
}

type MulticastBroadcastRateLimitStatus struct {
	Interface        string `json:"interface"`
	BroadcastRateBPS uint64 `json:"broadcast_rate_bps,omitempty"`
	BroadcastDrops   uint64 `json:"broadcast_drops,omitempty"`
	MulticastRateBPS uint64 `json:"multicast_rate_bps,omitempty"`
	MulticastDrops   uint64 `json:"multicast_drops,omitempty"`
	BurstBytes       uint32 `json:"burst_bytes"`
	Enforcement      string `json:"enforcement,omitempty"`
	Applied          bool   `json:"applied"`
	Reason           string `json:"reason,omitempty"`
}

type MDBEntryStatus struct {
	Bridge string `json:"bridge"`
	Port   string `json:"port"`
	Group  string `json:"group"`
	State  string `json:"state,omitempty"`
	VLAN   uint16 `json:"vlan,omitempty"`
}

type MulticastRouterPortStatus struct {
	Bridge string `json:"bridge"`
	Port   string `json:"port"`
	Type   string `json:"type,omitempty"`
}

type DHCPGuardStatus struct {
	Interface        string `json:"interface"`
	Trusted          bool   `json:"trusted"`
	RateLimitPPS     uint32 `json:"rate_limit_pps,omitempty"`
	ValidateBindings bool   `json:"validate_bindings,omitempty"`
	Packets          uint64 `json:"packets,omitempty"`
	Bytes            uint64 `json:"bytes,omitempty"`
	Applied          bool   `json:"applied"`
	Reason           string `json:"reason,omitempty"`
}

type Capabilities struct {
	KernelRelease                string                              `json:"kernel_release,omitempty"`
	Tools                        map[string]bool                     `json:"tools"`
	Bonding                      bool                                `json:"bonding_module"`
	Interfaces                   []HostInterface                     `json:"interfaces"`
	BridgeVLANs                  []BridgeVLANState                   `json:"bridge_vlans"`
	BridgeVLANGLOBALs            []BridgeVLANGLOBALState             `json:"bridge_vlan_multicast,omitempty"`
	BridgeFDB                    []BridgeFDBEntry                    `json:"-"`
	MACBlockTablePresent         bool                                `json:"-"`
	MACBlockTableManaged         bool                                `json:"-"`
	MACBlockRuleCounters         map[string][2]uint64                `json:"-"`
	Overrides                    []VirtualNetworkOverrideStatus      `json:"virtual_network_overrides,omitempty"`
	MACPortRestrictions          []MACPortRestrictionStatus          `json:"mac_port_restrictions,omitempty"`
	MACBlocks                    []MACBlockStatus                    `json:"mac_address_blocks,omitempty"`
	MACACLTablePresent           bool                                `json:"-"`
	MACACLTableManaged           bool                                `json:"-"`
	MACACLRuleCounters           map[string][2]uint64                `json:"-"`
	MACACL                       []MACACLStatus                      `json:"mac_acls,omitempty"`
	IPACLTablePresent            bool                                `json:"-"`
	IPACLTableManaged            bool                                `json:"-"`
	IPACLRuleCounters            map[string][2]uint64                `json:"-"`
	IPACL                        []IPACLStatus                       `json:"ip_acls,omitempty"`
	NetworkIsolationTablePresent bool                                `json:"-"`
	NetworkIsolationTableManaged bool                                `json:"-"`
	NetworkIsolationRuleCounters map[string][2]uint64                `json:"-"`
	NetworkIsolation             []NetworkIsolationStatus            `json:"inter_network_acls,omitempty"`
	EgressRates                  []EgressRateStatus                  `json:"egress_rate_limits,omitempty"`
	PortMirrors                  []PortMirrorStatus                  `json:"port_mirrors,omitempty"`
	StormControl                 []StormControlStatus                `json:"storm_control,omitempty"`
	MulticastBroadcastRateLimits []MulticastBroadcastRateLimitStatus `json:"multicast_broadcast_rate_limits,omitempty"`
	FlowControl                  []FlowControlStatus                 `json:"flow_control,omitempty"`
	MulticastDatabase            []MDBEntryStatus                    `json:"multicast_database,omitempty"`
	MulticastRouterPorts         []MulticastRouterPortStatus         `json:"multicast_router_ports,omitempty"`
	DHCPGuardTablePresent        bool                                `json:"-"`
	DHCPGuardTableManaged        bool                                `json:"-"`
	PortAuthTablePresent         bool                                `json:"-"`
	PortAuthTableManaged         bool                                `json:"-"`
	PortAuthStaticShapeValid     bool                                `json:"-"`
	PortAuthProtectedPorts       []string                            `json:"-"`
	PortAuthRuleComments         []string                            `json:"-"`
	DHCPGuardRuleCounters        map[string][2]uint64                `json:"-"`
	DHCPGuard                    []DHCPGuardStatus                   `json:"dhcp_guard,omitempty"`
	Bonds                        []BondStatus                        `json:"bonds,omitempty"`
	Features                     map[string]FeatureCapability        `json:"features"`
	STPControllerDiscovery       *STPControllerDiscovery             `json:"stp_controller_discovery,omitempty"`
}

func parseBridgeMDB(data []byte) ([]MDBEntryStatus, []MulticastRouterPortStatus, error) {
	var raw struct {
		MDB []struct {
			Bridge string `json:"dev"`
			Port   string `json:"port"`
			Group  string `json:"grp"`
			State  string `json:"state"`
			VLAN   uint16 `json:"vid"`
		} `json:"mdb"`
		Router map[string][]struct {
			Port string `json:"port"`
			Type string `json:"type"`
		} `json:"router"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, nil, fmt.Errorf("decode bridge multicast database: %w", err)
	}
	groups := make([]MDBEntryStatus, 0, len(raw.MDB))
	for _, entry := range raw.MDB {
		if entry.Bridge == "" || entry.Port == "" || entry.Group == "" {
			return nil, nil, fmt.Errorf("bridge multicast database entry is missing bridge, port, or group")
		}
		groups = append(groups, MDBEntryStatus{Bridge: entry.Bridge, Port: entry.Port, Group: entry.Group, State: entry.State, VLAN: entry.VLAN})
	}
	routers := make([]MulticastRouterPortStatus, 0)
	for bridge, ports := range raw.Router {
		for _, port := range ports {
			if bridge == "" || port.Port == "" {
				return nil, nil, fmt.Errorf("multicast router entry is missing bridge or port")
			}
			routers = append(routers, MulticastRouterPortStatus{Bridge: bridge, Port: port.Port, Type: port.Type})
		}
	}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].Bridge != groups[j].Bridge {
			return groups[i].Bridge < groups[j].Bridge
		}
		if groups[i].VLAN != groups[j].VLAN {
			return groups[i].VLAN < groups[j].VLAN
		}
		if groups[i].Group != groups[j].Group {
			return groups[i].Group < groups[j].Group
		}
		return groups[i].Port < groups[j].Port
	})
	sort.Slice(routers, func(i, j int) bool {
		if routers[i].Bridge != routers[j].Bridge {
			return routers[i].Bridge < routers[j].Bridge
		}
		return routers[i].Port < routers[j].Port
	})
	return groups, routers, nil
}

type Detection struct {
	KernelRelease string
	Tools         map[string]bool
	Bonding       bool
}

type avProfile struct {
	name    string
	feature string
}

var avProfiles = []avProfile{
	{name: "Play", feature: "pro_av.play"},
	{name: "Dante", feature: "pro_av.dante"},
	{name: "Q-SYS", feature: "pro_av.qsys"},
	{name: "NDI", feature: "pro_av.ndi"},
	{name: "SDVoE", feature: "pro_av.sdvoe"},
	{name: "Shure", feature: "pro_av.shure"},
	{name: "AES67", feature: "pro_av.aes67"},
	{name: "Crestron", feature: "pro_av.crestron"},
}

// EvaluateCapabilities converts read-only host observations into honest,
// per-feature status. Conditional means the baseline provider exists but a
// selected interface/driver/topology still needs validation before apply.
func EvaluateCapabilities(d Detection) Capabilities {
	c := Capabilities{KernelRelease: d.KernelRelease, Tools: cloneTools(d.Tools), Bonding: d.Bonding,
		Features: make(map[string]FeatureCapability)}
	set := func(name string, state CapabilityState, reason string) {
		c.Features[name] = FeatureCapability{State: state, Reason: reason}
	}
	require := func(name string, tools ...string) bool {
		for _, tool := range tools {
			if !d.Tools[tool] {
				set(name, CapabilityUnavailable, "required host tool is missing: "+tool)
				return false
			}
		}
		return true
	}
	conditional := func(name, reason string, tools ...string) {
		if require(name, tools...) {
			set(name, CapabilityConditional, reason)
		}
	}

	conditional(FeatureBridgeVLAN, "bridge VLAN filtering is available; selected interfaces still require validation", "ip", "bridge")
	conditional(FeatureJumbo, "MTU is configurable; path limits still require validation", "ip")
	conditional(FeatureVirtualNet, "tc flower VLAN push and ingress VLAN filtering require validation on the selected access port", "ip", "bridge", "tc")
	conditional(FeaturePortIsolation, "Linux bridge isolated-port forwarding is available; selected topology still requires validation", "bridge")
	conditional(FeatureMACPort, "Linux bridge locked ports and bridge-wide learned-device limits are available; selected topology and FDB state require validation", "ip", "bridge")
	conditional(FeatureMACBlock, "nftables bridge-family policy is available; selected topology and kernel support require validation", "nft", "bridge")
	conditional(FeatureMACACL, "nftables bridge-family ordered MAC ACLs are available; selected topology and kernel support require validation", "nft", "bridge")
	conditional(FeatureEgressRate, "tc TBF egress shaping is available on interfaces with an unmanaged-free default qdisc", "tc")
	conditional(FeatureFlowControl, "ethtool pause settings are available where supported by the selected interface driver", "ethtool")
	conditional(FeatureVRRP, "Keepalived shadow/standby service is available; peer subnet and VIP ownership are checked before apply", "keepalived", "ip")
	conditional(FeatureIPACL, "nftables bridge-family IPv4/IPv6 ACLs are available; selected topology and kernel support require validation", "nft", "bridge")
	conditional(FeatureNetworkIsolation, "nftables inet forward filtering is available for explicitly mapped routed Layer 2 networks", "nft")
	conditional(FeatureQoSDSCP, "software HTB DSCP classification is available on interfaces with an unmanaged-free root qdisc and known link speed", "tc", "ethtool")
	conditional(FeatureIGMPSnoop, "Linux bridge multicast snooping is available; selected bridge support is checked before apply", "ip", "bridge")
	conditional(FeatureIGMPVLAN, "Linux bridge per-VLAN multicast snooping is available; selected bridge and VLAN state is checked before apply", "ip", "bridge")
	conditional(FeatureIGMPAdvanced, "Linux bridge querier, fast-leave, and multicast-router controls are available; selected bridge support is checked before apply", "ip", "bridge")
	conditional(FeatureDHCPSnoop, "Linux bridge DHCP server-port filtering and per-port DHCP rate limiting are available; client binding checks are independently opt-in", "nft", "bridge")
	set(FeatureDHCPBinding, CapabilityUnsupported, "authoritative DHCP ingress binding metadata is unavailable; learned bridge FDB state is not trusted for port authorization")
	conditional(FeatureSTP, "Linux bridge Spanning Tree Protocol is available; selected bridge support is checked before apply", "ip", "bridge")
	conditional(FeatureRSTP, "Linux bridge STP and mstpd protocol selection are available; existing bridges are verified with mstpctl", "ip", "bridge", "mstpd", "mstpctl")
	set(FeatureLoopProtect, CapabilityUnsupported, "generic Linux bridge provides BPDU guard, not loopback detection, blocked-state recovery timer, or a recovery-reason provider")
	conditional(FeaturePortMirror, "software tc mirred port mirroring is available; an isolated veth namespace preflight runs before apply and selected source/monitor ports are checked before mutation", "ip", "tc")
	conditional(FeatureStormControl, "tc flower and police actions can cap ingress broadcast and multicast traffic by destination MAC", "tc")
	conditional(FeatureMultiRate, "tc flower and police actions can independently cap ingress broadcast and multicast traffic by destination MAC", "tc")
	conditional(FeatureVoiceVLAN, "bridge VLAN membership and lldpd LLDP-MED voice policy are available; selected bridge ports are checked before apply", "bridge", "lldpd", "lldpcli", "systemctl")
	conditional(FeatureLLDPMED, "lldpd LLDP-MED network policy support is available; selected ports and application policies are checked before apply", "lldpd", "lldpcli", "systemctl")
	conditional(Feature8021X, "hostapd wired RADIUS authentication and fail-closed nftables authorization are available; service units, local NAS address, secrets, and selected-port behavior are checked before apply", "hostapd", "hostapd_cli", "nft", "bridge", "systemctl")
	set(FeatureRedundancy, CapabilityConditional, "GameBond coordinates health and status for configured LACP, STP/RSTP, and VRRP mechanisms; each underlying provider is validated independently")
	if !d.Bonding {
		set(FeatureLACP, CapabilityUnavailable, "Linux bonding support is not loaded or exposed by the host")
	} else if require(FeatureLACP, "ip", "ethtool") {
		set(FeatureLACP, CapabilityConditional, "Linux 802.3ad bonds are available; peer negotiation is verified after apply")
	}
	set(FeatureMCLAG, CapabilityUnsupported, "no generic Linux MC-LAG peer protocol is configured")
	for _, profile := range avProfiles {
		set(profile.feature, CapabilityUnsupported, "catalog and per-network selection are available; profile-specific host enforcement is not integrated, and settings outside managed Linux providers remain advisory")
	}
	return c
}

func discoverLocalSTPControllers(ctx context.Context, runner HostRunner, cfg Config) *STPControllerDiscovery {
	if !configUsesSTPController(cfg) {
		return nil
	}
	if !runner.Available("systemctl") {
		return &STPControllerDiscovery{Reason: "local STP controller ownership is ambiguous because systemctl is unavailable"}
	}
	targets, err := stpTargetInterfaces(cfg)
	if err != nil {
		return &STPControllerDiscovery{Reason: "local STP controller ownership is ambiguous: " + err.Error()}
	}
	// Check these managers per affected bridge and port. A running manager on
	// its own is not evidence that it owns the GameBond topology.
	for _, manager := range []struct{ unit, tool string }{
		{"NetworkManager.service", "nmcli"},
		{"systemd-networkd.service", "networkctl"},
		{"openvswitch-switch.service", "ovs-vsctl"},
		{"ovs-vswitchd.service", "ovs-vsctl"},
	} {
		state, err := localServiceActiveState(ctx, runner, manager.unit)
		if err != nil {
			return &STPControllerDiscovery{Reason: fmt.Sprintf("local STP controller ownership is ambiguous: inspect %s: %v", manager.unit, err)}
		}
		if state == "active" || state == "activating" || state == "reloading" {
			if !runner.Available(manager.tool) {
				return &STPControllerDiscovery{Controller: manager.unit, Reason: fmt.Sprintf("cannot establish target bridge ownership: %s is active but %s is unavailable", manager.unit, manager.tool)}
			}
			for _, target := range targets {
				managed, err := bridgeManagerOwnsInterface(ctx, runner, manager.tool, target)
				if err != nil {
					return &STPControllerDiscovery{Controller: manager.unit, Reason: fmt.Sprintf("cannot establish target bridge ownership: inspect %s with %s: %v", target, manager.tool, err)}
				}
				if managed {
					return &STPControllerDiscovery{Controller: manager.unit, Reason: fmt.Sprintf("cannot establish exclusive bridge STP ownership: %s manages target interface %s", manager.unit, target)}
				}
			}
			continue
		}
		if !inactiveServiceState(state) {
			return &STPControllerDiscovery{Reason: fmt.Sprintf("local STP controller ownership is ambiguous: %s state is %q", manager.unit, state)}
		}
	}
	for _, unit := range []string{"rstpd.service", "rstp.service"} {
		state, err := localServiceActiveState(ctx, runner, unit)
		if err != nil {
			return &STPControllerDiscovery{Reason: fmt.Sprintf("local STP controller ownership is ambiguous: inspect %s: %v", unit, err)}
		}
		if state == "active" || state == "activating" || state == "reloading" {
			return &STPControllerDiscovery{Known: true, Conflict: true, Controller: unit, Reason: "competing local STP controller is active: " + unit}
		}
		if !inactiveServiceState(state) {
			return &STPControllerDiscovery{Reason: fmt.Sprintf("local STP controller ownership is ambiguous: %s state is %q", unit, state)}
		}
	}
	needsMSTPD := false
	for _, bridge := range cfg.Bridges {
		needsMSTPD = needsMSTPD || bridge.STPMode != ""
	}
	if needsMSTPD {
		state, err := localServiceActiveState(ctx, runner, "mstpd.service")
		if err != nil {
			return &STPControllerDiscovery{Controller: "mstpd.service", Reason: "local STP controller ownership is ambiguous: inspect mstpd.service: " + err.Error()}
		}
		if state != "active" {
			return &STPControllerDiscovery{Controller: "mstpd.service", Reason: fmt.Sprintf("selected STP controller mstpd.service is not active (state %q)", state)}
		}
		return &STPControllerDiscovery{Known: true, Controller: "mstpd.service", Reason: "selected local STP controller is active; known system and STP managers are inactive"}
	}
	return &STPControllerDiscovery{Known: true, Controller: "kernel", Reason: "kernel bridge STP selected; known system and STP managers are inactive"}
}

func stpTargetInterfaces(cfg Config) ([]string, error) {
	seen := map[string]bool{}
	var targets []string
	for _, bridge := range cfg.Bridges {
		if !bridgeUsesSTPController(bridge) {
			continue
		}
		if bridge.Name == "" {
			return nil, fmt.Errorf("managed STP bridge %q has no interface name", bridge.ID)
		}
		if !seen[bridge.Name] {
			targets = append(targets, bridge.Name)
			seen[bridge.Name] = true
		}
		for _, port := range bridge.Ports {
			iface, ok := findInterface(cfg.Interfaces, port.Interface)
			if !ok {
				return nil, fmt.Errorf("cannot resolve STP port interface %q", port.Interface)
			}
			if !seen[iface.Name] {
				targets = append(targets, iface.Name)
				seen[iface.Name] = true
			}
		}
	}
	return targets, nil
}

func bridgeManagerOwnsInterface(ctx context.Context, runner HostRunner, tool, iface string) (bool, error) {
	var args []string
	switch tool {
	case "nmcli":
		args = []string{"-g", "GENERAL.MANAGED", "device", "show", iface}
	case "networkctl":
		args = []string{"show", "--property=SetupState", "--value", iface}
	case "ovs-vsctl":
		args = []string{"--if-exists", "iface-to-br", iface}
	default:
		return false, fmt.Errorf("unsupported bridge manager probe %q", tool)
	}
	result, err := runner.Run(ctx, tool, args...)
	if err != nil {
		return false, err
	}
	state := strings.ToLower(strings.TrimSpace(string(result)))
	switch tool {
	case "nmcli":
		switch state {
		case "yes":
			return true, nil
		case "no":
			return false, nil
		default:
			return false, fmt.Errorf("unexpected GENERAL.MANAGED value %q", state)
		}
	case "networkctl":
		if state == "unmanaged" {
			return false, nil
		}
		if state == "configured" || state == "configuring" || state == "initialized" || state == "pending" || state == "failed" {
			return true, nil
		}
		return false, fmt.Errorf("unexpected SetupState value %q", state)
	case "ovs-vsctl":
		return state != "", nil
	default:
		return false, fmt.Errorf("unsupported bridge manager probe %q", tool)
	}
}

func configUsesSTPController(cfg Config) bool {
	for _, bridge := range cfg.Bridges {
		if bridgeUsesSTPController(bridge) {
			return true
		}
	}
	return false
}

func bridgeUsesSTPController(bridge Bridge) bool {
	if bridge.STPEnabled != nil || bridge.STPMode != "" || bridge.STPPriority != nil {
		return true
	}
	for _, port := range bridge.Ports {
		if port.STPPriority != nil || port.STPPathCost != nil || port.STPRootBlock != nil || port.STPEdge != nil || port.STPPointToPoint != "" || port.STPBPDUGuard != nil {
			return true
		}
	}
	return false
}

func localServiceActiveState(ctx context.Context, runner HostRunner, unit string) (string, error) {
	result, err := runner.Run(ctx, "systemctl", "show", "--property=ActiveState", "--value", unit)
	if err != nil {
		return "", err
	}
	return strings.ToLower(strings.TrimSpace(string(result))), nil
}

func inactiveServiceState(state string) bool {
	switch state {
	case "inactive", "failed", "deactivating", "not-found":
		return true
	default:
		return false
	}
}

// SnapshotCapabilities reads only host metadata. It does not load modules,
// alter links, or launch optional providers.
func SnapshotCapabilities(ctx context.Context, cfg Config, runner HostRunner) (Capabilities, error) {
	var kernel string
	if raw, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		kernel = strings.TrimSpace(string(raw))
	}
	tools := map[string]bool{}
	for _, name := range []string{"ip", "bridge", "tc", "nft", "ethtool", "conntrack", "keepalived", "lldpd", "lldpcli", "hostapd", "hostapd_cli", "mstpd", "mstpctl", "systemctl", "nmcli", "networkctl", "ovs-vsctl"} {
		tools[name] = runner.Available(name)
	}
	detection := Detection{KernelRelease: kernel, Tools: tools}
	if _, err := os.Stat("/sys/module/bonding"); err == nil {
		detection.Bonding = true
	}
	c := EvaluateCapabilities(detection)
	c.STPControllerDiscovery = discoverLocalSTPControllers(ctx, runner, cfg)
	if discovery := c.STPControllerDiscovery; discovery != nil {
		if !discovery.Known || discovery.Conflict {
			state := CapabilityUnavailable
			c.Features[FeatureSTP] = FeatureCapability{State: state, Reason: discovery.Reason}
			c.Features[FeatureRSTP] = FeatureCapability{State: state, Reason: discovery.Reason}
		}
	}
	if !runner.Available("ip") {
		return c, nil
	}
	result, err := runner.Run(ctx, "ip", "-json", "-details", "link", "show")
	if err != nil {
		return c, fmt.Errorf("read host links: %w", err)
	}
	var links []struct {
		Name      string   `json:"ifname"`
		Address   string   `json:"address"`
		MTU       int      `json:"mtu"`
		MaxMTU    int      `json:"max_mtu"`
		OperState string   `json:"operstate"`
		Master    string   `json:"master"`
		Flags     []string `json:"flags"`
		LinkInfo  struct {
			Kind     string `json:"info_kind"`
			InfoData struct {
				VLANFiltering        jsonBool        `json:"vlan_filtering"`
				GroupFwdMask         *uint32         `json:"group_fwd_mask"`
				Priority             *uint16         `json:"priority"`
				STPState             *int            `json:"stp_state"`
				McastSnooping        *jsonBool       `json:"mcast_snooping"`
				McastQuerier         *jsonBool       `json:"mcast_querier"`
				McastVLANSnooping    *jsonBool       `json:"mcast_vlan_snooping"`
				FDBMaxLearned        *int            `json:"fdb_max_learned"`
				FDBMaxLearnedEntries *int            `json:"fdb_max_learned_entries"`
				BondMode             string          `json:"mode"`
				BondMinLinks         int             `json:"min_links"`
				BondHashPolicy       json.RawMessage `json:"xmit_hash_policy"`
				BondLACPRate         json.RawMessage `json:"lacp_rate"`
			} `json:"info_data"`
		} `json:"linkinfo"`
	}
	if err := json.Unmarshal(result, &links); err != nil {
		return c, fmt.Errorf("decode host link inventory: %w", err)
	}
	c.Interfaces = make([]HostInterface, 0, len(links))
	for _, link := range links {
		adminUp := false
		for _, flag := range link.Flags {
			if strings.EqualFold(flag, "UP") {
				adminUp = true
				break
			}
		}
		hostInterface := HostInterface{Name: link.Name, Kind: link.LinkInfo.Kind, Master: link.Master, MTU: link.MTU, MaxMTU: link.MaxMTU, OperState: link.OperState, AdminUp: adminUp, VLANFiltering: bool(link.LinkInfo.InfoData.VLANFiltering), Address: strings.ToLower(link.Address)}
		if link.LinkInfo.Kind == "bridge" && link.LinkInfo.InfoData.GroupFwdMask != nil {
			hostInterface.GroupFwdMaskKnown = true
			hostInterface.GroupFwdMask = *link.LinkInfo.InfoData.GroupFwdMask
		}
		if link.LinkInfo.Kind == "bridge" && link.LinkInfo.InfoData.McastSnooping != nil && link.LinkInfo.InfoData.McastQuerier != nil {
			hostInterface.IGMPBridgeKnown = true
			hostInterface.IGMPSnooping = bool(*link.LinkInfo.InfoData.McastSnooping)
			hostInterface.IGMPQuerier = bool(*link.LinkInfo.InfoData.McastQuerier)
		}
		if link.LinkInfo.Kind == "bridge" && link.LinkInfo.InfoData.McastVLANSnooping != nil {
			hostInterface.IGMPVLANKnown = true
			hostInterface.IGMPVLANMode = bool(*link.LinkInfo.InfoData.McastVLANSnooping)
		}
		if link.LinkInfo.Kind == "bridge" && link.LinkInfo.InfoData.STPState != nil {
			hostInterface.STPKnown = true
			hostInterface.STPEnabled = *link.LinkInfo.InfoData.STPState != 0
		}
		if link.LinkInfo.Kind == "bridge" && link.LinkInfo.InfoData.Priority != nil {
			hostInterface.STPPriorityKnown = true
			hostInterface.STPPriority = *link.LinkInfo.InfoData.Priority
		}
		if link.LinkInfo.Kind == "bond" {
			hostInterface.BondMode = link.LinkInfo.InfoData.BondMode
			hostInterface.BondMinLinks = link.LinkInfo.InfoData.BondMinLinks
			hostInterface.BondHashPolicy = bondHashName(link.LinkInfo.InfoData.BondHashPolicy)
			hostInterface.BondLACPRate = bondLACPName(link.LinkInfo.InfoData.BondLACPRate)
		}
		if link.LinkInfo.Kind == "bridge" {
			limit := link.LinkInfo.InfoData.FDBMaxLearned
			if limit == nil {
				limit = link.LinkInfo.InfoData.FDBMaxLearnedEntries
			}
			if limit != nil {
				hostInterface.FDBMaxLearned = *limit
				hostInterface.FDBLimitKnown = true
			}
		}
		c.Interfaces = append(c.Interfaces, hostInterface)
	}
	interfaceIndex := make(map[string]int, len(c.Interfaces))
	for i := range c.Interfaces {
		interfaceIndex[c.Interfaces[i].Name] = i
	}
	if runner.Available("mstpctl") {
		managedNames := make(map[string]string, len(cfg.Interfaces))
		for _, iface := range cfg.Interfaces {
			managedNames[iface.ID] = iface.Name
		}
		for _, bridge := range cfg.Bridges {
			if bridge.STPMode == "" {
				continue
			}
			index, exists := interfaceIndex[bridge.Name]
			if !exists || c.Interfaces[index].Kind != "bridge" {
				continue
			}
			result, err := runner.Run(ctx, "mstpctl", "showbridge", bridge.Name)
			if err != nil {
				return c, fmt.Errorf("inspect spanning-tree mode on %s: %w", bridge.Name, err)
			}
			mode, err := parseMSTPMode(result)
			if err != nil {
				return c, fmt.Errorf("decode spanning-tree mode on %s: %w", bridge.Name, err)
			}
			c.Interfaces[index].STPMode, c.Interfaces[index].STPModeKnown = mode, true
			bridgeState, err := readMSTPBridgeState(ctx, runner, bridge.Name)
			if err != nil {
				return c, fmt.Errorf("inspect spanning-tree state on %s: %w", bridge.Name, err)
			}
			c.Interfaces[index].STPControllerKnown = true
			c.Interfaces[index].STPRootID = bridgeState.RootID
			c.Interfaces[index].STPRootPort = bridgeState.RootPort
			c.Interfaces[index].STPTopologyChange = bridgeState.TopologyChange
			c.Interfaces[index].STPTopologyChanges = bridgeState.TopologyChanges
			for _, port := range bridge.Ports {
				portName := managedNames[port.Interface]
				portIndex, found := interfaceIndex[portName]
				if !found {
					continue
				}
				if port.STPEdge != nil || port.STPPointToPoint != "" || port.STPBPDUGuard != nil {
					portResult, err := runner.Run(ctx, "mstpctl", "showportdetail", bridge.Name, portName)
					if err != nil {
						return c, fmt.Errorf("inspect spanning-tree port on %s/%s: %w", bridge.Name, portName, err)
					}
					state, err := parseMSTPPortSettings(portResult)
					if err != nil {
						return c, fmt.Errorf("decode spanning-tree port on %s/%s: %w", bridge.Name, portName, err)
					}
					c.Interfaces[portIndex].STPAdvancedKnown = true
					c.Interfaces[portIndex].STPEdge = state.Edge
					c.Interfaces[portIndex].STPPointToPoint = state.PointToPoint
					c.Interfaces[portIndex].STPBPDUGuard = state.BPDUGuard
				}
				role, err := runner.Run(ctx, "mstpctl", "showport", bridge.Name, portName, "role")
				if err != nil {
					return c, fmt.Errorf("inspect STP role on %s/%s: %w", bridge.Name, portName, err)
				}
				portState, err := runner.Run(ctx, "mstpctl", "showport", bridge.Name, portName, "state")
				if err != nil {
					return c, fmt.Errorf("inspect STP state on %s/%s: %w", bridge.Name, portName, err)
				}
				c.Interfaces[portIndex].STPRole = strings.TrimSpace(string(role))
				c.Interfaces[portIndex].STPPortState = strings.TrimSpace(string(portState))
			}
		}
	}
	qosInterfaces := map[string]bool{}
	for _, policy := range cfg.QoS {
		if in, ok := findInterface(cfg.Interfaces, policy.Interface); ok {
			qosInterfaces[in.Name] = true
		}
	}
	selectedNetworks := make(map[string]bool, len(cfg.AVProfiles))
	for _, selection := range cfg.AVProfiles {
		selectedNetworks[selection.Network] = true
	}
	selectedBridges := make(map[string]bool, len(selectedNetworks))
	for _, network := range cfg.Networks {
		if selectedNetworks[network.ID] {
			selectedBridges[network.Bridge] = true
		}
	}
	for _, bridge := range cfg.Bridges {
		if !selectedBridges[bridge.ID] {
			continue
		}
		for _, port := range bridge.Ports {
			for networkID := range selectedNetworks {
				if !portCarriesNetwork(port, networkID) {
					continue
				}
				if in, ok := findInterface(cfg.Interfaces, port.Interface); ok {
					qosInterfaces[in.Name] = true
				}
				break
			}
		}
	}
	if runner.Available("tc") {
		managed := make(map[string]bool, len(cfg.Interfaces))
		for _, in := range cfg.Interfaces {
			managed[in.Name] = true
		}
		for _, bridge := range cfg.Bridges {
			for _, port := range bridge.Ports {
				for _, in := range cfg.Interfaces {
					if in.ID == port.Interface {
						managed[in.Name] = true
					}
				}
			}
		}
		for name := range managed {
			index, ok := interfaceIndex[name]
			if !ok {
				continue
			}
			qdiscResult, err := runner.Run(ctx, "tc", "-json", "qdisc", "show", "dev", name)
			if err != nil {
				return c, fmt.Errorf("read traffic-control qdiscs for %s: %w", name, err)
			}
			var qdiscs []struct {
				Kind    string `json:"kind"`
				Handle  string `json:"handle"`
				Root    bool   `json:"root"`
				Parent  string `json:"parent"`
				Options struct {
					Rate  uint64 `json:"rate"`
					Burst uint32 `json:"burst"`
				} `json:"options"`
			}
			if err := json.Unmarshal(qdiscResult, &qdiscs); err != nil {
				return c, fmt.Errorf("decode traffic-control qdiscs for %s: %w", name, err)
			}
			for _, qdisc := range qdiscs {
				if qdisc.Root || qdisc.Parent == "root" {
					c.Interfaces[index].RootQdisc = qdisc.Kind
					c.Interfaces[index].RootQdiscHandle = qdisc.Handle
					c.Interfaces[index].RootQdiscRateBPS = qdisc.Options.Rate
					c.Interfaces[index].RootQdiscBurstBytes = qdisc.Options.Burst
				}
				switch qdisc.Kind {
				case "clsact":
					c.Interfaces[index].TCClsact = true
				case "ingress":
					c.Interfaces[index].LegacyIngress = true
				}
			}
			filterResult, err := runner.Run(ctx, "tc", "-s", "-json", "filter", "show", "dev", name, "ingress")
			if err != nil {
				return c, fmt.Errorf("read ingress filters for %s: %w", name, err)
			}
			filters, err := parseTCFilters(filterResult)
			if err != nil {
				return c, fmt.Errorf("decode ingress filters for %s: %w", name, err)
			}
			c.Interfaces[index].TCFilters = filters
			egressFilterResult, err := runner.Run(ctx, "tc", "-s", "-json", "filter", "show", "dev", name, "egress")
			if err != nil {
				return c, fmt.Errorf("read egress filters for %s: %w", name, err)
			}
			egressFilters, err := parseTCFilters(egressFilterResult)
			if err != nil {
				return c, fmt.Errorf("decode egress filters for %s: %w", name, err)
			}
			c.Interfaces[index].TCEgressFilters = egressFilters
			needsPoliceDetails := false
			for _, limit := range cfg.EgressRates {
				if limit.Interface != "" && limit.Network != "" {
					iface := interfaceByID(cfg.Interfaces, limit.Interface)
					if iface.Name == name {
						needsPoliceDetails = true
						break
					}
				}
			}
			if needsPoliceDetails {
				details, detailErr := runner.Run(ctx, "tc", "-details", "filter", "show", "dev", name, "egress")
				if detailErr != nil {
					return c, fmt.Errorf("read detailed egress policers for %s: %w", name, detailErr)
				}
				observed, parseErr := parseTCPoliceDetails(details)
				if parseErr != nil {
					return c, fmt.Errorf("decode detailed egress policers for %s: %w", name, parseErr)
				}
				for i := range c.Interfaces[index].TCEgressFilters {
					if rate, exists := observed[c.Interfaces[index].TCEgressFilters[i].Priority]; exists {
						c.Interfaces[index].TCEgressFilters[i].PoliceRateBPS = rate[0]
						if rate[1] <= uint64(^uint32(0)) {
							c.Interfaces[index].TCEgressFilters[i].PoliceBurstBytes = uint32(rate[1])
						}
					}
				}
			}
		}
	}
	if runner.Available("bridge") {
		linkResult, err := runner.Run(ctx, "bridge", "-json", "-details", "link", "show")
		if err != nil {
			return c, fmt.Errorf("read host bridge links: %w", err)
		}
		var bridgeLinks []struct {
			Name           string  `json:"ifname"`
			Isolated       *bool   `json:"isolated"`
			Locked         *bool   `json:"locked"`
			MaxLearned     *int    `json:"max_learned"`
			McastFastLeave *bool   `json:"fastleave"`
			McastRouter    *int    `json:"mcast_router"`
			Guard          *bool   `json:"guard"`
			Priority       *uint8  `json:"priority"`
			Cost           *uint32 `json:"cost"`
			RootBlock      *bool   `json:"root_block"`
		}
		if err := json.Unmarshal(linkResult, &bridgeLinks); err != nil {
			return c, fmt.Errorf("decode host bridge link inventory: %w", err)
		}
		for _, bridgeLink := range bridgeLinks {
			if index, exists := interfaceIndex[bridgeLink.Name]; exists {
				if bridgeLink.Priority != nil && bridgeLink.Cost != nil && bridgeLink.RootBlock != nil {
					c.Interfaces[index].STPPortKnown = true
					c.Interfaces[index].STPPortPriority = *bridgeLink.Priority
					c.Interfaces[index].STPPathCost = *bridgeLink.Cost
					c.Interfaces[index].STPRootBlock = *bridgeLink.RootBlock
				}
				if bridgeLink.McastFastLeave != nil && bridgeLink.McastRouter != nil {
					c.Interfaces[index].IGMPPortKnown = true
					c.Interfaces[index].IGMPFastLeave = *bridgeLink.McastFastLeave
					c.Interfaces[index].IGMPRouterMode = *bridgeLink.McastRouter
				}
				if bridgeLink.Isolated != nil {
					c.Interfaces[index].Isolated = *bridgeLink.Isolated
					c.Interfaces[index].IsolationKnown = true
				}
				if bridgeLink.Locked != nil {
					c.Interfaces[index].Locked = *bridgeLink.Locked
					if bridgeLink.MaxLearned != nil {
						c.Interfaces[index].MaxLearned = *bridgeLink.MaxLearned
					}
					c.Interfaces[index].BridgePortKnown = true
				}
			}
		}
		mdbResult, err := runner.Run(ctx, "bridge", "-json", "mdb", "show")
		if err != nil {
			return c, fmt.Errorf("read host bridge multicast database: %w", err)
		}
		c.MulticastDatabase, c.MulticastRouterPorts, err = parseBridgeMDB(mdbResult)
		if err != nil {
			return c, err
		}
		fdbResult, err := runner.Run(ctx, "bridge", "-json", "fdb", "show")
		if err != nil {
			return c, fmt.Errorf("read host bridge FDB: %w", err)
		}
		var fdbRows []struct {
			MAC   string   `json:"mac"`
			Dev   string   `json:"dev"`
			VLAN  int      `json:"vlan"`
			State string   `json:"state"`
			Flags []string `json:"flags"`
		}
		if err := json.Unmarshal(fdbResult, &fdbRows); err != nil {
			return c, fmt.Errorf("decode host bridge FDB: %w", err)
		}
		for _, row := range fdbRows {
			if row.VLAN < 1 || row.VLAN > 4094 {
				continue
			}
			entry := BridgeFDBEntry{MAC: strings.ToLower(row.MAC), Device: row.Dev, VLAN: uint16(row.VLAN), Static: row.State == "static" || row.State == "permanent", Locked: row.State == "locked"}
			for _, flag := range row.Flags {
				if flag == "static" || flag == "permanent" {
					entry.Static = true
				}
				if flag == "locked" {
					entry.Locked = true
				}
			}
			c.BridgeFDB = append(c.BridgeFDB, entry)
		}
		vlanResult, err := runner.Run(ctx, "bridge", "-json", "vlan", "show")
		if err != nil {
			return c, fmt.Errorf("read host bridge VLANs: %w", err)
		}
		var devices []struct {
			Name  string `json:"ifname"`
			VLANs []struct {
				VLAN  int      `json:"vlan"`
				Flags []string `json:"flags"`
			} `json:"vlans"`
		}
		if err := json.Unmarshal(vlanResult, &devices); err != nil {
			return c, fmt.Errorf("decode host bridge VLAN inventory: %w", err)
		}
		for _, device := range devices {
			for _, vlan := range device.VLANs {
				if vlan.VLAN < 1 || vlan.VLAN > 4094 {
					continue
				}
				state := BridgeVLANState{Device: device.Name, VLAN: uint16(vlan.VLAN)}
				for _, flag := range vlan.Flags {
					switch strings.ToLower(flag) {
					case "pvid":
						state.PVID = true
					case "egress untagged":
						state.Untagged = true
					}
				}
				c.BridgeVLANs = append(c.BridgeVLANs, state)
			}
		}
		needsVLANIGMP := false
		for _, network := range cfg.Networks {
			needsVLANIGMP = needsVLANIGMP || network.IGMPSnooping != nil
		}
		if needsVLANIGMP {
			result, err := runner.Run(ctx, "bridge", "-json", "vlan", "global", "show")
			if err != nil {
				c.Features[FeatureIGMPVLAN] = FeatureCapability{State: CapabilityUnavailable, Reason: "cannot read bridge VLAN multicast state: " + err.Error()}
				return c, nil
			}
			var globals []struct {
				Bridge string `json:"ifname"`
				VLANs  []struct {
					VLAN     int       `json:"vlan"`
					Snooping *jsonBool `json:"mcast_snooping"`
				} `json:"vlans"`
			}
			if err := json.Unmarshal(result, &globals); err != nil {
				return c, fmt.Errorf("decode bridge VLAN multicast state: %w", err)
			}
			for _, bridge := range globals {
				for _, vlan := range bridge.VLANs {
					if vlan.VLAN < 1 || vlan.VLAN > 4094 || vlan.Snooping == nil {
						continue
					}
					c.BridgeVLANGLOBALs = append(c.BridgeVLANGLOBALs, BridgeVLANGLOBALState{Bridge: bridge.Bridge, VLAN: uint16(vlan.VLAN), Snooping: bool(*vlan.Snooping)})
				}
			}
		}
	}
	if runner.Available("ethtool") {
		for name := range qosInterfaces {
			index, exists := interfaceIndex[name]
			if !exists {
				continue
			}
			result, err := runner.Run(ctx, "ethtool", name)
			if err != nil {
				continue
			}
			speed, err := parseEthtoolLinkSpeed(result)
			if err != nil {
				continue
			}
			c.Interfaces[index].LinkSpeedBPS = speed
			c.Interfaces[index].LinkSpeedKnown = true
		}
		for _, policy := range cfg.FlowControl {
			name := interfaceByID(cfg.Interfaces, policy.Interface).Name
			index, exists := interfaceIndex[name]
			if !exists {
				continue
			}
			result, err := runner.Run(ctx, "ethtool", "--show-pause", name)
			if err != nil {
				c.Interfaces[index].PauseError = err.Error()
				continue
			}
			state, err := parsePauseState(result)
			if err != nil {
				c.Interfaces[index].PauseError = err.Error()
				continue
			}
			c.Interfaces[index].PauseKnown = true
			c.Interfaces[index].PauseAutoneg = state.Autoneg
			c.Interfaces[index].PauseRX = state.RX
			c.Interfaces[index].PauseTX = state.TX
		}
	}
	applyOverrideStatus(&c, cfg)
	applyMACPortRestrictionStatus(&c, cfg)
	applyEgressRateStatus(&c, cfg)
	applyFlowControlStatus(&c, cfg)
	applyPortMirrorStatus(&c, cfg)
	applyStormControlStatus(&c, cfg)
	applyMulticastBroadcastRateStatus(&c, cfg)
	snapshotMACBlockState(ctx, runner, &c, cfg)
	snapshotMACACLState(ctx, runner, &c, cfg)
	snapshotIPACLState(ctx, runner, &c, cfg)
	snapshotNetworkIsolationState(ctx, runner, &c, cfg)
	snapshotDHCPGuardState(ctx, runner, &c, cfg)
	snapshotPortAuthState(ctx, runner, &c)
	c.Bonds = snapshotBonds(cfg, c.Interfaces)
	return c, nil
}

type pauseState struct {
	Autoneg string
	RX      bool
	TX      bool
}

func parseMSTPMode(data []byte) (string, error) {
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 && strings.EqualFold(strings.Join(fields[:3], " "), "force protocol version") {
			mode := strings.ToLower(fields[len(fields)-1])
			if mode == "stp" || mode == "rstp" || mode == "mstp" {
				return mode, nil
			}
		}
	}
	return "", fmt.Errorf("mstpctl output does not contain a force protocol version")
}

type mstpPortSettings struct {
	Edge         bool
	PointToPoint string
	BPDUGuard    bool
}

type mstpBridgeState struct {
	RootID, RootPort string
	TopologyChange   bool
	TopologyChanges  uint64
}

func readMSTPBridgeState(ctx context.Context, runner HostRunner, bridge string) (mstpBridgeState, error) {
	get := func(parameter string) (string, error) {
		data, err := runner.Run(ctx, "mstpctl", "showbridge", bridge, parameter)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(data)), nil
	}
	root, err := get("designated-root")
	if err != nil {
		return mstpBridgeState{}, err
	}
	rootPort, err := get("root-port")
	if err != nil {
		return mstpBridgeState{}, err
	}
	tc, err := get("topology-change")
	if err != nil {
		return mstpBridgeState{}, err
	}
	countText, err := get("topology-change-count")
	if err != nil {
		return mstpBridgeState{}, err
	}
	count, err := strconv.ParseUint(countText, 10, 64)
	if err != nil {
		return mstpBridgeState{}, fmt.Errorf("invalid topology-change-count %q", countText)
	}
	if root == "" || rootPort == "" || (tc != "yes" && tc != "no") {
		return mstpBridgeState{}, fmt.Errorf("incomplete mstpd bridge status")
	}
	return mstpBridgeState{RootID: root, RootPort: rootPort, TopologyChange: tc == "yes", TopologyChanges: count}, nil
}

func parseMSTPPortSettings(data []byte) (mstpPortSettings, error) {
	text := string(data)
	read := func(label string) (string, bool) {
		for _, line := range strings.Split(text, "\n") {
			if at := strings.Index(line, label); at >= 0 {
				fields := strings.Fields(line[at+len(label):])
				if len(fields) > 0 {
					return strings.ToLower(fields[0]), true
				}
			}
		}
		return "", false
	}
	edge, okEdge := read("admin edge port")
	p2p, okP2P := read("admin point-to-point")
	guard, okGuard := read("bpdu guard port")
	if !okEdge || !okP2P || !okGuard {
		return mstpPortSettings{}, fmt.Errorf("mstpd output is missing edge, point-to-point, or BPDU-guard state")
	}
	if (edge != "yes" && edge != "no") || (p2p != "yes" && p2p != "no" && p2p != "auto") || (guard != "yes" && guard != "no") {
		return mstpPortSettings{}, fmt.Errorf("mstpd output contains invalid port settings")
	}
	return mstpPortSettings{Edge: edge == "yes", PointToPoint: p2p, BPDUGuard: guard == "yes"}, nil
}

func parsePauseState(data []byte) (pauseState, error) {
	state := pauseState{}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.ToLower(strings.TrimSpace(parts[1]))
		switch key {
		case "autonegotiate":
			if value != "on" && value != "off" {
				return state, fmt.Errorf("unsupported ethtool pause autoneg value %q", value)
			}
			state.Autoneg = value
			seen[key] = true
		case "rx", "tx":
			if value != "on" && value != "off" {
				return state, fmt.Errorf("unsupported ethtool pause %s value %q", key, value)
			}
			enabled := value == "on"
			if key == "rx" {
				state.RX = enabled
			} else {
				state.TX = enabled
			}
			seen[key] = true
		}
	}
	if !seen["autonegotiate"] || !seen["rx"] || !seen["tx"] {
		return state, fmt.Errorf("ethtool did not report all pause settings")
	}
	return state, nil
}

func applyFlowControlStatus(caps *Capabilities, cfg Config) {
	for _, policy := range cfg.FlowControl {
		name := interfaceByID(cfg.Interfaces, policy.Interface).Name
		status := FlowControlStatus{Interface: name, Autoneg: policy.Autoneg, RX: policy.RX, TX: policy.TX}
		for _, host := range caps.Interfaces {
			if host.Name == name {
				status.Supported = host.PauseKnown
				status.Applied = host.PauseKnown && host.PauseAutoneg == policy.Autoneg && host.PauseRX == policy.RX && host.PauseTX == policy.TX
				if !host.PauseKnown {
					status.Reason = host.PauseError
				}
			}
		}
		if !status.Applied && status.Reason == "" {
			status.Reason = "effective pause settings do not match the requested policy"
		}
		caps.FlowControl = append(caps.FlowControl, status)
	}
}

func applyPortMirrorStatus(caps *Capabilities, cfg Config) {
	interfaces := map[string]string{}
	for _, iface := range cfg.Interfaces {
		interfaces[iface.ID] = iface.Name
	}
	hostByName := map[string]HostInterface{}
	for _, iface := range caps.Interfaces {
		hostByName[iface.Name] = iface
	}
	for _, mirror := range cfg.PortMirrors {
		status := PortMirrorStatus{Source: interfaces[mirror.Source], Destination: interfaces[mirror.Destination], Direction: mirror.Direction,
			Network: mirror.Network, CaptureRateBPS: mirror.CaptureRateBPS, CaptureBurstBytes: mirror.CaptureBurstBytes}
		directions := portMirrorDirections(mirror.Direction)
		status.Applied = status.Source != "" && status.Destination != "" && len(directions) > 0
		live, exists := hostByName[status.Source]
		if !exists {
			status.Applied = false
			status.Reason = "source interface is absent from host inventory"
		}
		for _, direction := range directions {
			if !exists {
				break
			}
			priority := portMirrorPriority(direction)
			filters := live.TCFilters
			if direction == "egress" {
				filters = live.TCEgressFilters
			}
			vlan := uint16(0)
			for _, network := range cfg.Networks {
				if network.ID == mirror.Network {
					vlan = network.VLAN
					break
				}
			}
			expected := expectedPortMirrorFilter(direction, status.Destination, vlan)
			found := false
			for _, filter := range filters {
				if filter.Priority == priority && equalTCFilter(filter, expected) {
					found = true
					status.Packets += filter.Packets
					status.Bytes += filter.Bytes
					break
				}
			}
			status.Applied = status.Applied && live.TCClsact && found
		}
		if mirror.CaptureRateBPS > 0 {
			destination, ok := hostByName[status.Destination]
			status.Applied = status.Applied && ok && destination.RootQdisc == "tbf" && destination.RootQdiscRateBPS == mirror.CaptureRateBPS && destination.RootQdiscBurstBytes == mirror.CaptureBurstBytes
		}
		if !status.Applied && status.Reason == "" {
			status.Reason = "effective mirred filters do not match the requested source, destination, and direction"
		}
		caps.PortMirrors = append(caps.PortMirrors, status)
	}
}

func applyStormControlStatus(caps *Capabilities, cfg Config) {
	names := map[string]string{}
	for _, iface := range cfg.Interfaces {
		names[iface.ID] = iface.Name
	}
	liveByName := map[string]HostInterface{}
	for _, iface := range caps.Interfaces {
		liveByName[iface.Name] = iface
	}
	for _, policy := range cfg.StormControl {
		name := names[policy.Interface]
		status := StormControlStatus{Interface: name, BroadcastRateBPS: policy.BroadcastRateBPS,
			MulticastRateBPS: policy.MulticastRateBPS, BurstBytes: policy.BurstBytes, Applied: name != ""}
		live, ok := liveByName[name]
		if !ok {
			status.Applied = false
			status.Reason = "interface is absent from host inventory"
		}
		for _, class := range []struct {
			rate      uint64
			multicast bool
		}{{policy.BroadcastRateBPS, false}, {policy.MulticastRateBPS, true}} {
			if class.rate == 0 || !ok {
				continue
			}
			expected := stormFilter(class.rate, policy.BurstBytes, class.multicast)
			found := false
			for _, actual := range live.TCFilters {
				if sameTCFilterPolicy(actual, expected) {
					found = true
					if class.multicast {
						status.MulticastDrops = actual.Drops
					} else {
						status.BroadcastDrops = actual.Drops
					}
					break
				}
			}
			status.Applied = status.Applied && live.TCClsact && found
		}
		if !status.Applied && status.Reason == "" {
			status.Reason = "effective ingress flower policers do not match the requested broadcast and multicast rates"
		}
		caps.StormControl = append(caps.StormControl, status)
	}
}

func applyMulticastBroadcastRateStatus(caps *Capabilities, cfg Config) {
	names := map[string]string{}
	for _, iface := range cfg.Interfaces {
		names[iface.ID] = iface.Name
	}
	liveByName := map[string]HostInterface{}
	for _, iface := range caps.Interfaces {
		liveByName[iface.Name] = iface
	}
	for _, policy := range cfg.MulticastBroadcastLimits {
		name := names[policy.Interface]
		status := MulticastBroadcastRateLimitStatus{Interface: name, BroadcastRateBPS: policy.BroadcastRateBPS, MulticastRateBPS: policy.MulticastRateBPS, BurstBytes: policy.BurstBytes, Applied: name != ""}
		live, ok := liveByName[name]
		if !ok {
			status.Applied = false
			status.Reason = "interface is absent from host inventory"
		}
		for _, class := range []struct {
			rate      uint64
			multicast bool
		}{{policy.BroadcastRateBPS, false}, {policy.MulticastRateBPS, true}} {
			if class.rate == 0 || !ok {
				continue
			}
			priority := multiBroadcastPriority
			if class.multicast {
				priority = multiMulticastPriority
			}
			expected := ingressRateFilter(class.rate, policy.BurstBytes, class.multicast, priority)
			found := false
			for _, actual := range live.TCFilters {
				if equalTCFilter(actual, expected) {
					found = true
					if class.multicast {
						status.MulticastDrops = actual.Drops
					} else {
						status.BroadcastDrops = actual.Drops
					}
					break
				}
			}
			status.Applied = status.Applied && live.TCClsact && found
		}
		if status.Applied {
			status.Enforcement = "software tc ingress policer"
		} else if status.Reason == "" {
			status.Reason = "effective ingress policers do not match the requested broadcast and multicast rates"
		}
		caps.MulticastBroadcastRateLimits = append(caps.MulticastBroadcastRateLimits, status)
	}
}

func sameTCFilterPolicy(actual, expected TCFilterState) bool { return equalTCFilter(actual, expected) }

func applyEgressRateStatus(caps *Capabilities, cfg Config) {
	for _, rate := range cfg.EgressRates {
		name := interfaceByID(cfg.Interfaces, rate.Interface).Name
		status := EgressRateStatus{Interface: name, Network: rate.Network, RateBPS: rate.RateBPS, BurstBytes: rate.BurstBytes}
		for _, host := range caps.Interfaces {
			if host.Name == name {
				if rate.Network == "" {
					status.EffectiveQdisc, status.EffectiveRateBPS, status.EffectiveBurstBytes = host.RootQdisc, host.RootQdiscRateBPS, host.RootQdiscBurstBytes
					status.Applied = host.RootQdisc == "tbf" && host.RootQdiscRateBPS == rate.RateBPS && host.RootQdiscBurstBytes == rate.BurstBytes
				} else {
					vlan := networkByID(cfg.Networks, rate.Network).VLAN
					for _, filter := range host.TCEgressFilters {
						if filter.Priority == egressFilterPriority(vlan) {
							status.EffectiveQdisc = "clsact/police"
							status.EffectiveRateBPS, status.EffectiveBurstBytes = filter.PoliceRateBPS, filter.PoliceBurstBytes
							status.Applied = host.TCClsact && filter.Kind == "flower" && filter.VLANID == vlan && filter.PoliceRateBPS == rate.RateBPS && filter.PoliceBurstBytes == rate.BurstBytes
						}
					}
				}
			}
		}
		if !status.Applied {
			status.Reason = "effective traffic-control rate and burst do not match the requested policy"
		}
		caps.EgressRates = append(caps.EgressRates, status)
	}
}

func snapshotIPACLState(ctx context.Context, runner HostRunner, caps *Capabilities, cfg Config) {
	if !runner.Available("nft") {
		return
	}
	inputRunner, ok := runner.(interface {
		RunInput(context.Context, string, []byte, ...string) ([]byte, error)
	})
	if !ok {
		caps.Features[FeatureIPACL] = FeatureCapability{State: CapabilityUnavailable, Reason: "gateway runner does not support nftables check-mode input"}
		return
	}
	probe := fmt.Sprintf("gamebond_ip_probe_%d", os.Getpid())
	if _, err := inputRunner.RunInput(ctx, "nft", []byte("add table bridge "+probe+"\n"), "-c", "-f", "-"); err != nil {
		caps.Features[FeatureIPACL] = FeatureCapability{State: CapabilityUnavailable, Reason: "nftables bridge-family check mode is unavailable: " + err.Error()}
		return
	}
	raw, err := runner.Run(ctx, "nft", "-j", "list", "tables")
	if err != nil {
		caps.Features[FeatureIPACL] = FeatureCapability{State: CapabilityUnavailable, Reason: "cannot inspect nftables tables: " + err.Error()}
		return
	}
	var tables struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal(raw, &tables) != nil {
		caps.Features[FeatureIPACL] = FeatureCapability{State: CapabilityUnavailable, Reason: "cannot decode nftables table inventory"}
		return
	}
	for _, item := range tables.Nftables {
		var t struct {
			Family string `json:"family"`
			Name   string `json:"name"`
		}
		if b := item["table"]; b != nil && json.Unmarshal(b, &t) == nil && t.Family == "bridge" && t.Name == ipACLTableName {
			caps.IPACLTablePresent = true
		}
	}
	if caps.IPACLTablePresent {
		raw, err = runner.Run(ctx, "nft", "-j", "list", "table", "bridge", ipACLTableName)
		if err != nil {
			caps.Features[FeatureIPACL] = FeatureCapability{State: CapabilityUnavailable, Reason: "cannot inspect GameBond IP ACL table: " + err.Error()}
			return
		}
		var objects struct {
			Nftables []map[string]json.RawMessage `json:"nftables"`
		}
		if json.Unmarshal(raw, &objects) != nil {
			caps.Features[FeatureIPACL] = FeatureCapability{State: CapabilityUnavailable, Reason: "cannot decode GameBond IP ACL table"}
			return
		}
		counts := map[string][2]uint64{}
		unmanaged := false
		for _, item := range objects.Nftables {
			if b := item["table"]; b != nil {
				var t struct {
					Comment string `json:"comment"`
				}
				if json.Unmarshal(b, &t) == nil && t.Comment == ipACLTableMarker {
					caps.IPACLTableManaged = true
				}
			}
			if b := item["rule"]; b != nil {
				var rule struct {
					Comment string                       `json:"comment"`
					Expr    []map[string]json.RawMessage `json:"expr"`
				}
				if json.Unmarshal(b, &rule) != nil || rule.Comment == "" {
					unmanaged = true
					continue
				}
				var c [2]uint64
				for _, e := range rule.Expr {
					if cr := e["counter"]; cr != nil {
						var v struct {
							Packets uint64 `json:"packets"`
							Bytes   uint64 `json:"bytes"`
						}
						if json.Unmarshal(cr, &v) == nil {
							c = [2]uint64{v.Packets, v.Bytes}
						}
					}
				}
				counts[rule.Comment] = c
			}
		}
		caps.IPACLTableManaged = caps.IPACLTableManaged && !unmanaged
		caps.IPACLRuleCounters = counts
	}
	applyIPACLStatus(caps, cfg)
}

func snapshotNetworkIsolationState(ctx context.Context, runner HostRunner, caps *Capabilities, cfg Config) {
	if len(cfg.NetworkACL) == 0 || !runner.Available("nft") {
		return
	}
	inputRunner, ok := runner.(interface {
		RunInput(context.Context, string, []byte, ...string) ([]byte, error)
	})
	if !ok {
		caps.Features[FeatureNetworkIsolation] = FeatureCapability{State: CapabilityUnavailable, Reason: "gateway runner does not support nftables check-mode input"}
		return
	}
	probe := fmt.Sprintf("gamebond_l2_probe_%d", os.Getpid())
	if _, err := inputRunner.RunInput(ctx, "nft", []byte("add table inet "+probe+"\n"), "-c", "-f", "-"); err != nil {
		caps.Features[FeatureNetworkIsolation] = FeatureCapability{State: CapabilityUnavailable, Reason: "nftables inet-family check mode is unavailable: " + err.Error()}
		return
	}
	raw, err := runner.Run(ctx, "nft", "-j", "list", "tables")
	if err != nil {
		caps.Features[FeatureNetworkIsolation] = FeatureCapability{State: CapabilityUnavailable, Reason: "cannot inspect nftables tables: " + err.Error()}
		return
	}
	var tables struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal(raw, &tables) != nil {
		caps.Features[FeatureNetworkIsolation] = FeatureCapability{State: CapabilityUnavailable, Reason: "cannot decode nftables table inventory"}
		return
	}
	for _, item := range tables.Nftables {
		var table struct {
			Family string `json:"family"`
			Name   string `json:"name"`
		}
		if data := item["table"]; data != nil && json.Unmarshal(data, &table) == nil && table.Family == "inet" && table.Name == networkIsolationTableName {
			caps.NetworkIsolationTablePresent = true
		}
	}
	if caps.NetworkIsolationTablePresent {
		raw, err = runner.Run(ctx, "nft", "-j", "list", "table", "inet", networkIsolationTableName)
		if err != nil {
			caps.Features[FeatureNetworkIsolation] = FeatureCapability{State: CapabilityUnavailable, Reason: "cannot inspect routed network isolation table: " + err.Error()}
			return
		}
		var objects struct {
			Nftables []map[string]json.RawMessage `json:"nftables"`
		}
		if json.Unmarshal(raw, &objects) != nil {
			caps.Features[FeatureNetworkIsolation] = FeatureCapability{State: CapabilityUnavailable, Reason: "cannot decode routed network isolation table"}
			return
		}
		marker, unmanaged := false, false
		counters := map[string][2]uint64{}
		for _, item := range objects.Nftables {
			if data := item["table"]; data != nil {
				var table struct {
					Comment string `json:"comment"`
				}
				if json.Unmarshal(data, &table) == nil && table.Comment == networkIsolationTableMarker {
					marker = true
				}
			}
			if data := item["rule"]; data != nil {
				var rule struct {
					Comment string                       `json:"comment"`
					Expr    []map[string]json.RawMessage `json:"expr"`
				}
				if json.Unmarshal(data, &rule) != nil || rule.Comment == "" {
					unmanaged = true
					continue
				}
				var count [2]uint64
				for _, expr := range rule.Expr {
					if rawCounter := expr["counter"]; rawCounter != nil {
						var value struct {
							Packets uint64 `json:"packets"`
							Bytes   uint64 `json:"bytes"`
						}
						if json.Unmarshal(rawCounter, &value) == nil {
							count = [2]uint64{value.Packets, value.Bytes}
						}
					}
				}
				counters[rule.Comment] = count
			}
		}
		caps.NetworkIsolationTableManaged = marker && !unmanaged
		caps.NetworkIsolationRuleCounters = counters
	}
	applyNetworkIsolationStatus(caps, cfg)
}

func applyNetworkIsolationStatus(caps *Capabilities, cfg Config) {
	expected := networkIsolationRuleComments(cfg)
	allApplied := caps.NetworkIsolationTablePresent && caps.NetworkIsolationTableManaged && exactStringSet(mapKeys(caps.NetworkIsolationRuleCounters), expected)
	for _, rule := range cfg.NetworkACL {
		status := NetworkIsolationStatus{ID: rule.ID, SourceNetwork: rule.SourceNetwork, DestinationNetwork: rule.DestinationNetwork, Applied: allApplied}
		if count, ok := caps.NetworkIsolationRuleCounters[networkIsolationAllowComment(cfg, rule)]; ok {
			status.Packets, status.Bytes = count[0], count[1]
		} else {
			status.Applied = false
		}
		if !status.Applied {
			status.Reason = "routed network isolation table or one of its default-deny/allow rules does not match the requested policy"
		}
		caps.NetworkIsolation = append(caps.NetworkIsolation, status)
	}
}

func applyIPACLStatus(caps *Capabilities, cfg Config) {
	all := ipACLRuleComments(cfg)
	for i, r := range cfg.IPACL {
		s := IPACLStatus{ID: r.ID, Direction: r.Direction, Action: r.Action, RuleOrder: i + 1, Applied: caps.IPACLTablePresent && caps.IPACLTableManaged && exactStringSet(mapKeys(caps.IPACLRuleCounters), all)}
		for _, comment := range ipACLCommentsForRule(cfg, r) {
			v, ok := caps.IPACLRuleCounters[comment]
			if !ok {
				s.Applied = false
				continue
			}
			s.Packets += v[0]
			s.Bytes += v[1]
		}
		if !s.Applied {
			s.Reason = "ordered GameBond nftables IP ACL rule is not active"
		}
		caps.IPACL = append(caps.IPACL, s)
	}
}

func snapshotMACACLState(ctx context.Context, runner HostRunner, caps *Capabilities, cfg Config) {
	if !runner.Available("nft") {
		return
	}
	inputRunner, ok := runner.(interface {
		RunInput(context.Context, string, []byte, ...string) ([]byte, error)
	})
	if !ok {
		caps.Features[FeatureMACACL] = FeatureCapability{State: CapabilityUnavailable, Reason: "gateway runner does not support nftables check-mode input"}
		return
	}
	probeTable := fmt.Sprintf("gamebond_acl_probe_%d", os.Getpid())
	if _, err := inputRunner.RunInput(ctx, "nft", []byte("add table bridge "+probeTable+"\n"), "-c", "-f", "-"); err != nil {
		caps.Features[FeatureMACACL] = FeatureCapability{State: CapabilityUnavailable, Reason: "nftables bridge-family check mode is unavailable: " + err.Error()}
		return
	}
	raw, err := runner.Run(ctx, "nft", "-j", "list", "tables")
	if err != nil {
		caps.Features[FeatureMACACL] = FeatureCapability{State: CapabilityUnavailable, Reason: "cannot inspect nftables tables: " + err.Error()}
		return
	}
	var tables struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(raw, &tables); err != nil {
		caps.Features[FeatureMACACL] = FeatureCapability{State: CapabilityUnavailable, Reason: "cannot decode nftables table inventory"}
		return
	}
	for _, item := range tables.Nftables {
		var table struct {
			Family string `json:"family"`
			Name   string `json:"name"`
		}
		if data, ok := item["table"]; ok && json.Unmarshal(data, &table) == nil && table.Family == "bridge" && table.Name == macACLTableName {
			caps.MACACLTablePresent = true
		}
	}
	if caps.MACACLTablePresent {
		raw, err = runner.Run(ctx, "nft", "-j", "list", "table", "bridge", macACLTableName)
		if err != nil {
			caps.Features[FeatureMACACL] = FeatureCapability{State: CapabilityUnavailable, Reason: "cannot inspect GameBond MAC ACL table: " + err.Error()}
			return
		}
		var objects struct {
			Nftables []map[string]json.RawMessage `json:"nftables"`
		}
		if err := json.Unmarshal(raw, &objects); err != nil {
			caps.Features[FeatureMACACL] = FeatureCapability{State: CapabilityUnavailable, Reason: "cannot decode GameBond MAC ACL table"}
			return
		}
		comments := make(map[string][2]uint64)
		marker, unmanaged := false, false
		for _, item := range objects.Nftables {
			if data, ok := item["table"]; ok {
				var table struct {
					Comment string `json:"comment"`
				}
				if json.Unmarshal(data, &table) == nil && table.Comment == macACLTableMarker {
					marker = true
				}
			}
			if data, ok := item["rule"]; ok {
				var rule struct {
					Comment string                       `json:"comment"`
					Expr    []map[string]json.RawMessage `json:"expr"`
				}
				if json.Unmarshal(data, &rule) != nil || rule.Comment == "" {
					unmanaged = true
					continue
				}
				var counts [2]uint64
				for _, expr := range rule.Expr {
					if cr, ok := expr["counter"]; ok {
						var c struct {
							Packets uint64 `json:"packets"`
							Bytes   uint64 `json:"bytes"`
						}
						if json.Unmarshal(cr, &c) == nil {
							counts = [2]uint64{c.Packets, c.Bytes}
						}
					}
				}
				comments[rule.Comment] = counts
			}
		}
		caps.MACACLTableManaged = marker && !unmanaged
		caps.MACACLRuleCounters = comments
	}
	applyMACACLStatus(caps, cfg)
}

func applyMACACLStatus(caps *Capabilities, cfg Config) {
	allComments := macACLRuleComments(cfg)
	for index, rule := range cfg.MACACL {
		status := MACACLStatus{ID: rule.ID, Direction: rule.Direction, Action: rule.Action, RuleOrder: index + 1, Applied: caps.MACACLTablePresent && caps.MACACLTableManaged && exactStringSet(mapKeys(caps.MACACLRuleCounters), allComments)}
		for _, comment := range macACLCommentsForRule(cfg, rule) {
			counter, ok := caps.MACACLRuleCounters[comment]
			if !ok {
				status.Applied = false
				continue
			}
			status.Packets += counter[0]
			status.Bytes += counter[1]
		}
		if !status.Applied {
			status.Reason = "ordered GameBond nftables MAC ACL rule is not active"
		}
		caps.MACACL = append(caps.MACACL, status)
	}
}

func snapshotMACBlockState(ctx context.Context, runner HostRunner, caps *Capabilities, cfg Config) {
	if !runner.Available("nft") {
		return
	}
	inputRunner, ok := runner.(interface {
		RunInput(context.Context, string, []byte, ...string) ([]byte, error)
	})
	if !ok {
		caps.Features[FeatureMACBlock] = FeatureCapability{State: CapabilityUnavailable, Reason: "gateway runner does not support nftables check-mode input"}
		return
	}
	probeTable := fmt.Sprintf("gamebond_capability_probe_%d", os.Getpid())
	probeScript := []byte("add table bridge " + probeTable + "\n")
	if _, err := inputRunner.RunInput(ctx, "nft", probeScript, "-c", "-f", "-"); err != nil {
		caps.Features[FeatureMACBlock] = FeatureCapability{State: CapabilityUnavailable, Reason: "nftables bridge-family check mode is unavailable: " + err.Error()}
		return
	}
	raw, err := runner.Run(ctx, "nft", "-j", "list", "tables")
	if err != nil {
		caps.Features[FeatureMACBlock] = FeatureCapability{State: CapabilityUnavailable, Reason: "cannot inspect nftables tables: " + err.Error()}
		return
	}
	var tables struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(raw, &tables); err != nil {
		caps.Features[FeatureMACBlock] = FeatureCapability{State: CapabilityUnavailable, Reason: "cannot decode nftables table inventory"}
		return
	}
	for _, item := range tables.Nftables {
		var table struct {
			Family string `json:"family"`
			Name   string `json:"name"`
		}
		if rawTable, ok := item["table"]; ok && json.Unmarshal(rawTable, &table) == nil && table.Family == "bridge" && table.Name == macBlockTableName {
			caps.MACBlockTablePresent = true
		}
	}
	if caps.MACBlockTablePresent {
		raw, err = runner.Run(ctx, "nft", "-j", "list", "table", "bridge", macBlockTableName)
		if err != nil {
			caps.Features[FeatureMACBlock] = FeatureCapability{State: CapabilityUnavailable, Reason: "cannot inspect GameBond MAC block table: " + err.Error()}
			return
		}
		var objects struct {
			Nftables []map[string]json.RawMessage `json:"nftables"`
		}
		if err := json.Unmarshal(raw, &objects); err != nil {
			caps.Features[FeatureMACBlock] = FeatureCapability{State: CapabilityUnavailable, Reason: "cannot decode GameBond MAC block table"}
			return
		}
		comments := make(map[string][2]uint64)
		unmanagedRule := false
		for _, item := range objects.Nftables {
			if rawTable, ok := item["table"]; ok {
				var table struct {
					Comment string `json:"comment"`
				}
				if json.Unmarshal(rawTable, &table) == nil && table.Comment == macBlockTableMarker {
					caps.MACBlockTableManaged = true
				}
			}
			if rawRule, ok := item["rule"]; ok {
				var rule struct {
					Comment string                       `json:"comment"`
					Expr    []map[string]json.RawMessage `json:"expr"`
				}
				if json.Unmarshal(rawRule, &rule) != nil || rule.Comment == "" {
					unmanagedRule = true
					continue
				}
				var counts [2]uint64
				for _, expression := range rule.Expr {
					if counterRaw, ok := expression["counter"]; ok {
						var counter struct {
							Packets uint64 `json:"packets"`
							Bytes   uint64 `json:"bytes"`
						}
						if json.Unmarshal(counterRaw, &counter) == nil {
							counts = [2]uint64{counter.Packets, counter.Bytes}
						}
					}
				}
				comments[rule.Comment] = counts
			}
		}
		caps.MACBlockTableManaged = caps.MACBlockTableManaged && !unmanagedRule
		caps.MACBlockRuleCounters = comments
	}
	applyMACBlockStatus(caps, cfg)
}

func snapshotDHCPGuardState(ctx context.Context, runner HostRunner, caps *Capabilities, cfg Config) {
	if !runner.Available("nft") {
		return
	}
	inputRunner, ok := runner.(interface {
		RunInput(context.Context, string, []byte, ...string) ([]byte, error)
	})
	if !ok {
		setDHCPGuardUnavailable(caps, "gateway runner does not support nftables check-mode input")
		applyDHCPGuardStatus(caps, cfg)
		return
	}
	probe := fmt.Sprintf("gamebond_dhcp_probe_%d", os.Getpid())
	if _, err := inputRunner.RunInput(ctx, "nft", []byte("add table bridge "+probe+"\n"), "-c", "-f", "-"); err != nil {
		setDHCPGuardUnavailable(caps, "nftables bridge-family check mode is unavailable: "+err.Error())
		applyDHCPGuardStatus(caps, cfg)
		return
	}
	raw, err := runner.Run(ctx, "nft", "-j", "list", "tables")
	if err != nil {
		setDHCPGuardUnavailable(caps, "cannot inspect nftables tables: "+err.Error())
		applyDHCPGuardStatus(caps, cfg)
		return
	}
	var tables struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal(raw, &tables) != nil {
		setDHCPGuardUnavailable(caps, "cannot decode nftables table inventory")
		applyDHCPGuardStatus(caps, cfg)
		return
	}
	for _, item := range tables.Nftables {
		var table struct {
			Family string `json:"family"`
			Name   string `json:"name"`
		}
		if b, ok := item["table"]; ok && json.Unmarshal(b, &table) == nil && table.Family == "bridge" && table.Name == dhcpGuardTableName {
			caps.DHCPGuardTablePresent = true
		}
	}
	if caps.DHCPGuardTablePresent {
		raw, err = runner.Run(ctx, "nft", "-j", "list", "table", "bridge", dhcpGuardTableName)
		if err != nil {
			setDHCPGuardUnavailable(caps, "cannot inspect GameBond DHCP guard table: "+err.Error())
			applyDHCPGuardStatus(caps, cfg)
			return
		}
		var objects struct {
			Nftables []map[string]json.RawMessage `json:"nftables"`
		}
		if json.Unmarshal(raw, &objects) != nil {
			setDHCPGuardUnavailable(caps, "cannot decode GameBond DHCP guard table")
			applyDHCPGuardStatus(caps, cfg)
			return
		}
		comments := make(map[string][2]uint64)
		unmanagedRule := false
		for _, item := range objects.Nftables {
			if b, ok := item["table"]; ok {
				var t struct {
					Comment string `json:"comment"`
				}
				if json.Unmarshal(b, &t) == nil && t.Comment == dhcpGuardTableMarker {
					caps.DHCPGuardTableManaged = true
				}
			}
			if b, ok := item["rule"]; ok {
				var rule struct {
					Comment string                       `json:"comment"`
					Expr    []map[string]json.RawMessage `json:"expr"`
				}
				if json.Unmarshal(b, &rule) != nil || rule.Comment == "" {
					unmanagedRule = true
					continue
				}
				var counter [2]uint64
				for _, expr := range rule.Expr {
					if b, ok := expr["counter"]; ok {
						var c struct {
							Packets uint64 `json:"packets"`
							Bytes   uint64 `json:"bytes"`
						}
						if json.Unmarshal(b, &c) == nil {
							counter = [2]uint64{c.Packets, c.Bytes}
						}
					}
				}
				comments[rule.Comment] = counter
			}
		}
		caps.DHCPGuardTableManaged = caps.DHCPGuardTableManaged && !unmanagedRule
		caps.DHCPGuardRuleCounters = comments
	}
	applyDHCPGuardStatus(caps, cfg)
}

func snapshotPortAuthState(ctx context.Context, runner HostRunner, caps *Capabilities) {
	if caps.Features[Feature8021X].State != CapabilityUnsupported && caps.Features[Feature8021X].State != CapabilityConditional {
		return
	}
	if !runner.Available("nft") {
		return
	}
	inputRunner, ok := runner.(interface {
		RunInput(context.Context, string, []byte, ...string) ([]byte, error)
	})
	if !ok {
		caps.Features[Feature8021X] = FeatureCapability{State: CapabilityUnavailable, Reason: "gateway runner does not support nftables check-mode input"}
		return
	}
	probe := fmt.Sprintf("gamebond_8021x_probe_%d", os.Getpid())
	if _, err := inputRunner.RunInput(ctx, "nft", []byte("add table bridge "+probe+"\n"), "-c", "-f", "-"); err != nil {
		caps.Features[Feature8021X] = FeatureCapability{State: CapabilityUnavailable, Reason: "nftables bridge-family support is unavailable: " + err.Error()}
		return
	}
	raw, err := runner.Run(ctx, "nft", "-j", "list", "tables")
	if err != nil {
		caps.Features[Feature8021X] = FeatureCapability{State: CapabilityUnavailable, Reason: "cannot inspect nftables tables: " + err.Error()}
		return
	}
	var tables struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(raw, &tables); err != nil {
		caps.Features[Feature8021X] = FeatureCapability{State: CapabilityUnavailable, Reason: "cannot decode nftables table inventory"}
		return
	}
	for _, item := range tables.Nftables {
		var entry struct {
			Family string `json:"family"`
			Name   string `json:"name"`
		}
		if rawTable, ok := item["table"]; ok && json.Unmarshal(rawTable, &entry) == nil && entry.Family == "bridge" && entry.Name == portAuthTableName {
			caps.PortAuthTablePresent = true
		}
	}
	if !caps.PortAuthTablePresent {
		return
	}
	raw, err = runner.Run(ctx, "nft", "-j", "list", "table", "bridge", portAuthTableName)
	if err != nil {
		caps.Features[Feature8021X] = FeatureCapability{State: CapabilityUnavailable, Reason: "cannot inspect GameBond 802.1X table: " + err.Error()}
		return
	}
	var objects struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(raw, &objects); err != nil {
		caps.Features[Feature8021X] = FeatureCapability{State: CapabilityUnavailable, Reason: "cannot decode GameBond 802.1X table"}
		return
	}
	caps.PortAuthTableManaged, caps.PortAuthStaticShapeValid, caps.PortAuthProtectedPorts, caps.PortAuthRuleComments = parsePortAuthStaticState(raw)
}

func parsePortAuthStaticState(raw []byte) (managed, valid bool, protectedPorts, ruleComments []string) {
	var objects struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal(raw, &objects) != nil {
		return false, false, nil, nil
	}
	tableCount := 0
	sets := map[string]bool{}
	chains := map[string]bool{}
	valid = true
	for _, item := range objects.Nftables {
		if rawTable, ok := item["table"]; ok {
			var table struct {
				Family  string `json:"family"`
				Name    string `json:"name"`
				Comment string `json:"comment"`
			}
			if json.Unmarshal(rawTable, &table) != nil || table.Family != "bridge" || table.Name != portAuthTableName {
				valid = false
				continue
			}
			tableCount++
			managed = table.Comment == portAuthTableMarker
			continue
		}
		if rawSet, ok := item["set"]; ok {
			var set struct {
				Family string          `json:"family"`
				Table  string          `json:"table"`
				Name   string          `json:"name"`
				Type   json.RawMessage `json:"type"`
				Elem   []any           `json:"elem"`
			}
			if json.Unmarshal(rawSet, &set) != nil || set.Family != "bridge" || set.Table != portAuthTableName || sets[set.Name] {
				valid = false
				continue
			}
			sets[set.Name] = true
			switch set.Name {
			case "protected_ports":
				if !portAuthSetType(set.Type, "ifname") {
					valid = false
				}
				for _, element := range set.Elem {
					name, ok := element.(string)
					if !ok || name == "" {
						valid = false
						continue
					}
					protectedPorts = append(protectedPorts, name)
				}
			case "authorized_ports":
				if !portAuthSetType(set.Type, "ifname") {
					valid = false
				}
			case "authenticated_clients":
				if !portAuthSetType(set.Type, "ifname", "ether_addr") {
					valid = false
				}
			default:
				valid = false
			}
			continue
		}
		if rawChain, ok := item["chain"]; ok {
			var chain struct {
				Family   string `json:"family"`
				Table    string `json:"table"`
				Name     string `json:"name"`
				Type     string `json:"type"`
				Hook     string `json:"hook"`
				Priority int    `json:"prio"`
				Policy   string `json:"policy"`
			}
			if json.Unmarshal(rawChain, &chain) != nil || chain.Family != "bridge" || chain.Table != portAuthTableName || chains[chain.Name] {
				valid = false
				continue
			}
			chains[chain.Name] = true
			wantedHook := map[string]string{"input": "input", "forward": "forward", "egress": "postrouting"}[chain.Name]
			if wantedHook == "" || chain.Type != "filter" || chain.Hook != wantedHook || chain.Priority != -300 || chain.Policy != "accept" {
				valid = false
			}
			continue
		}
		if rawRule, ok := item["rule"]; ok {
			var rule struct {
				Family  string `json:"family"`
				Table   string `json:"table"`
				Chain   string `json:"chain"`
				Comment string `json:"comment"`
			}
			if json.Unmarshal(rawRule, &rule) != nil {
				valid = false
				continue
			}
			wantedChain, knownComment := portAuthRuleChains()[rule.Comment]
			if rule.Family != "bridge" || rule.Table != portAuthTableName || !chains[rule.Chain] || !knownComment || rule.Chain != wantedChain {
				valid = false
				continue
			}
			ruleComments = append(ruleComments, rule.Comment)
		}
	}
	valid = valid && tableCount == 1 && managed && len(sets) == 3 && sets["protected_ports"] && sets["authorized_ports"] && sets["authenticated_clients"] && len(chains) == 3 && chains["input"] && chains["forward"] && chains["egress"]
	sort.Strings(protectedPorts)
	sort.Strings(ruleComments)
	return managed, valid, protectedPorts, ruleComments
}

func portAuthSetType(raw json.RawMessage, expected ...string) bool {
	var single string
	if json.Unmarshal(raw, &single) == nil {
		return len(expected) == 1 && single == expected[0]
	}
	var values []string
	if json.Unmarshal(raw, &values) == nil {
		return exactStringSet(values, expected)
	}
	return false
}

func setDHCPGuardUnavailable(caps *Capabilities, reason string) {
	capability := FeatureCapability{State: CapabilityUnavailable, Reason: reason}
	caps.Features[FeatureDHCPSnoop] = capability
}

func applyDHCPGuardStatus(caps *Capabilities, cfg Config) {
	wanted := dhcpGuardRuleComments(cfg)
	for _, policy := range cfg.DHCPGuard {
		status := DHCPGuardStatus{Interface: interfaceByID(cfg.Interfaces, policy.Interface).Name, Trusted: policy.Trusted, RateLimitPPS: policy.RateLimitPPS, ValidateBindings: policy.ValidateBindings,
			Applied: caps.DHCPGuardTablePresent && caps.DHCPGuardTableManaged && exactStringSet(mapKeys(caps.DHCPGuardRuleCounters), wanted)}
		for _, comment := range dhcpGuardRuleComments(Config{DHCPGuard: []DHCPGuardPort{policy}}) {
			counter, ok := caps.DHCPGuardRuleCounters[comment]
			if !ok {
				status.Applied = false
				continue
			}
			status.Packets += counter[0]
			status.Bytes += counter[1]
		}
		if !status.Applied {
			status.Reason = "GameBond nftables DHCP guard rules are not all active"
		}
		caps.DHCPGuard = append(caps.DHCPGuard, status)
	}
}

func mapKeys(values map[string][2]uint64) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func exactStringSet(actual, expected []string) bool {
	actual = append([]string(nil), actual...)
	expected = append([]string(nil), expected...)
	sort.Strings(actual)
	sort.Strings(expected)
	return strings.Join(actual, "\x00") == strings.Join(expected, "\x00")
}

func applyMACBlockStatus(caps *Capabilities, cfg Config) {
	for _, block := range cfg.MACBlocks {
		status := MACBlockStatus{Interface: interfaceByID(cfg.Interfaces, block.Interface).Name, Network: block.Network, MAC: block.MAC,
			Applied: caps.MACBlockTablePresent && caps.MACBlockTableManaged && exactStringSet(mapKeys(caps.MACBlockRuleCounters), macBlockRuleComments(cfg))}
		for _, comment := range macBlockRuleComments(Config{MACBlocks: []MACBlock{block}}) {
			counter, exists := caps.MACBlockRuleCounters[comment]
			if !exists {
				status.Applied = false
				continue
			}
			status.Packets += counter[0]
			status.Bytes += counter[1]
		}
		if !status.Applied {
			status.Reason = "GameBond nftables bridge rules are not all active"
		}
		caps.MACBlocks = append(caps.MACBlocks, status)
	}
}

func applyMACPortRestrictionStatus(c *Capabilities, cfg Config) {
	interfaces := make(map[string]HostInterface, len(c.Interfaces))
	for _, in := range c.Interfaces {
		interfaces[in.Name] = in
	}
	networks := make(map[string]Network, len(cfg.Networks))
	for _, network := range cfg.Networks {
		networks[network.ID] = network
	}
	for _, restriction := range cfg.MACPortRestrictions {
		in := interfaceByID(cfg.Interfaces, restriction.Interface)
		network := networks[restriction.Network]
		bridgeName := ""
		for _, bridge := range cfg.Bridges {
			for _, port := range bridge.Ports {
				if port.Interface == restriction.Interface {
					bridgeName = bridge.Name
				}
			}
		}
		status := MACPortRestrictionStatus{Interface: in.Name, Network: restriction.Network, VLAN: network.VLAN,
			AllowedMACs: append([]string(nil), restriction.AllowedMACs...), MaxDevices: restriction.MaxDevices, ViolationAction: restriction.ViolationAction}
		live, exists := interfaces[in.Name]
		bridge, bridgeExists := interfaces[bridgeName]
		if !exists || !live.BridgePortKnown || !bridgeExists || !bridge.FDBLimitKnown {
			status.Reason = "bridge port restriction state is unavailable"
			c.MACPortRestrictions = append(c.MACPortRestrictions, status)
			continue
		}
		allowed := make(map[string]bool, len(restriction.AllowedMACs))
		for _, mac := range restriction.AllowedMACs {
			allowed[mac] = false
		}
		for _, entry := range c.BridgeFDB {
			if entry.Device == in.Name && entry.VLAN == network.VLAN && !entry.Static {
				status.LearnedDevices++
			}
			if entry.Device == in.Name && entry.VLAN == network.VLAN && entry.Locked {
				status.LockedEntries++
			}
			if entry.Device == in.Name && entry.VLAN == network.VLAN && entry.Static {
				if _, ok := allowed[entry.MAC]; ok {
					allowed[entry.MAC] = true
				}
			}
		}
		allAllowed := true
		for _, present := range allowed {
			allAllowed = allAllowed && present
		}
		status.Applied = live.Locked && bridge.FDBMaxLearned == restriction.MaxDevices && allAllowed
		if !status.Applied {
			status.Reason = "locked-port state, learned-device limit, or authorized FDB entries do not match configuration"
		}
		c.MACPortRestrictions = append(c.MACPortRestrictions, status)
	}
}

func parseTCFilters(data []byte) ([]TCFilterState, error) {
	var rows []struct {
		Priority int            `json:"pref"`
		Kind     string         `json:"kind"`
		Options  map[string]any `json:"options"`
		Stats    struct {
			Packets uint64 `json:"packets"`
			Bytes   uint64 `json:"bytes"`
			Drops   uint64 `json:"drops"`
		} `json:"stats"`
	}
	if err := json.Unmarshal(data, &rows); err != nil {
		return nil, err
	}
	filters := make([]TCFilterState, 0, len(rows))
	for _, row := range rows {
		state := TCFilterState{Priority: row.Priority, Kind: row.Kind, NumVLANs: -1, Packets: row.Stats.Packets, Bytes: row.Stats.Bytes, Drops: row.Stats.Drops}
		if mac, ok := row.Options["src_mac"].(string); ok {
			state.SourceMAC = strings.ToLower(mac)
		}
		if mac, ok := row.Options["dst_mac"].(string); ok {
			parts := strings.SplitN(strings.ToLower(mac), "/", 2)
			state.DestinationMAC = parts[0]
			if len(parts) == 2 {
				state.DestinationMask = parts[1]
			}
		}
		if mask, ok := row.Options["dst_mac_mask"].(string); ok {
			state.DestinationMask = strings.ToLower(mask)
		}
		if count, ok := row.Options["num_of_vlans"].(float64); ok {
			state.NumVLANs, state.HasNumVLANs = int(count), true
		}
		actions, _ := row.Options["actions"].([]any)
		for _, rawAction := range actions {
			action, _ := rawAction.(map[string]any)
			kind, _ := action["kind"].(string)
			if kind == "vlan" {
				state.VLANAction, _ = action["vlan_action"].(string)
				control, _ := action["control_action"].(map[string]any)
				state.VLANControl, _ = control["type"].(string)
				if id, ok := action["id"].(float64); ok && id >= 1 && id <= 4094 {
					state.VLANID = uint16(id)
				}
			}
			if kind == "police" {
				if value, ok := action["rate"].(float64); ok && value >= 0 {
					state.PoliceRateBPS = uint64(value)
				}
				if value, ok := action["burst"].(float64); ok && value >= 0 {
					state.PoliceBurstBytes = uint32(value)
				}
			}
			if kind == "mirred" {
				state.MirrorAction, _ = action["mirred_action"].(string)
				state.MirrorDirection, _ = action["direction"].(string)
				state.MirrorDevice, _ = action["to_dev"].(string)
			}
			control, _ := action["control_action"].(map[string]any)
			controlType, _ := control["type"].(string)
			if kind == "gact" && controlType == "drop" {
				state.DropTagged = true
			}
		}
		if vlanID, ok := row.Options["vlan_id"].(float64); ok && vlanID >= 0 && vlanID <= 4094 {
			state.VLANID = uint16(vlanID)
		}
		if vlanID, ok := row.Options["key_vlan_id"].(float64); ok && vlanID >= 0 && vlanID <= 4094 {
			state.VLANID = uint16(vlanID)
		}
		filters = append(filters, state)
	}
	sort.Slice(filters, func(i, j int) bool { return filters[i].Priority < filters[j].Priority })
	return filters, nil
}

var tcFilterPrefPattern = regexp.MustCompile(`\bpref\s+([0-9]+)\b`)
var tcPoliceRatePattern = regexp.MustCompile(`\brate\s+([0-9]+(?:\.[0-9]+)?)([kMGT]?bit)\b`)
var tcPoliceBurstPattern = regexp.MustCompile(`\bburst\s+([0-9]+(?:\.[0-9]+)?)([kKMGT]?b|[KMGT]iB)\b`)

func parseTCPoliceDetails(data []byte) (map[int][2]uint64, error) {
	result := map[int][2]uint64{}
	priority := -1
	for _, line := range strings.Split(string(data), "\n") {
		if match := tcFilterPrefPattern.FindStringSubmatch(line); len(match) == 2 {
			p, err := strconv.Atoi(match[1])
			if err != nil {
				return nil, err
			}
			priority = p
		}
		if priority < 0 || !strings.Contains(line, "police") {
			continue
		}
		rateMatch, burstMatch := tcPoliceRatePattern.FindStringSubmatch(line), tcPoliceBurstPattern.FindStringSubmatch(line)
		if len(rateMatch) != 3 || len(burstMatch) != 3 {
			continue
		}
		rate, err := parseTCQuantity(rateMatch[1], rateMatch[2], true)
		if err != nil {
			return nil, err
		}
		burst, err := parseTCQuantity(burstMatch[1], burstMatch[2], false)
		if err != nil {
			return nil, err
		}
		result[priority] = [2]uint64{rate, burst}
	}
	return result, nil
}

func parseTCQuantity(number, unit string, rate bool) (uint64, error) {
	value, err := strconv.ParseFloat(number, 64)
	if err != nil {
		return 0, err
	}
	base := float64(1)
	if rate {
		switch unit {
		case "kbit":
			base = 1_000
		case "Mbit":
			base = 1_000_000
		case "Gbit":
			base = 1_000_000_000
		case "Tbit":
			base = 1_000_000_000_000
		}
	} else {
		switch unit {
		case "kb":
			base = 1_000
		case "Kb":
			base = 1024
		case "Mb":
			base = 1_000_000
		case "Gb":
			base = 1_000_000_000
		case "Kib":
			base = 1024
		case "Mib":
			base = 1024 * 1024
		case "Gib":
			base = 1024 * 1024 * 1024
		case "KiB":
			base = 1024
		case "MiB":
			base = 1024 * 1024
		case "GiB":
			base = 1024 * 1024 * 1024
		}
	}
	return uint64(value*base + 0.5), nil
}

func applyOverrideStatus(c *Capabilities, cfg Config) {
	interfaces := make(map[string]HostInterface, len(c.Interfaces))
	for _, in := range c.Interfaces {
		interfaces[in.Name] = in
	}
	vlans := make(map[string]bool, len(c.BridgeVLANs))
	for _, vlan := range c.BridgeVLANs {
		vlans[vlanKey(vlan.Device, vlan.VLAN)] = true
	}
	networks := make(map[string]Network, len(cfg.Networks))
	for _, network := range cfg.Networks {
		networks[network.ID] = network
	}
	for _, override := range cfg.Overrides {
		in := interfaceByID(cfg.Interfaces, override.Interface)
		status := VirtualNetworkOverrideStatus{Interface: in.Name, MAC: override.MAC, Network: override.Network}
		network := networks[override.Network]
		status.VLAN = network.VLAN
		live, exists := interfaces[in.Name]
		if !exists {
			status.Reason = "interface is absent"
			c.Overrides = append(c.Overrides, status)
			continue
		}
		desired := expectedOverrideFilters(cfg)[in.Name]
		matched := 0
		for _, want := range desired {
			for _, got := range live.TCFilters {
				if equalTCFilter(want, got) {
					matched++
				}
			}
		}
		status.Applied = live.TCClsact && matched == len(desired) && vlans[vlanKey(in.Name, network.VLAN)]
		if !status.Applied {
			status.Reason = "ingress VLAN override or bridge membership is not fully applied"
		}
		c.Overrides = append(c.Overrides, status)
	}
}

func interfaceByID(interfaces []Interface, id string) Interface {
	for _, in := range interfaces {
		if in.ID == id {
			return in
		}
	}
	return Interface{}
}

func cloneTools(in map[string]bool) map[string]bool {
	out := make(map[string]bool, len(in))
	for name, present := range in {
		out[name] = present
	}
	return out
}
