package layer2

import (
	"encoding/json"
	"fmt"
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
	FeatureWiredSupplicant  = "wired_8021x_supplicant"
	FeatureVoiceVLAN        = "voice_vlan"
	FeatureLLDPMED          = "lldp_med"
	FeatureSTP              = "stp"
	FeatureRSTP             = "rstp"
	FeatureLoopProtect      = "loop_protection"
	FeatureLACP             = "lacp_port_aggregation"
	FeatureRedundancy       = "redundancy"
	FeatureMCLAG            = "mc_lag"
	FeatureVXLAN            = "vxlan_bridge_tap"
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
	VXLANKnown          bool            `json:"vxlan_state_known,omitempty"`
	VXLANID             uint32          `json:"vxlan_id,omitempty"`
	VXLANLocal          string          `json:"vxlan_local,omitempty"`
	VXLANDstPort        uint16          `json:"vxlan_udp_port,omitempty"`
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
