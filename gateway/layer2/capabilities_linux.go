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

type CapabilityState string

const (
	CapabilitySupported   CapabilityState = "supported"
	CapabilityConditional CapabilityState = "conditional"
	CapabilityUnsupported CapabilityState = "unsupported"
	CapabilityUnavailable CapabilityState = "unavailable"
)

const (
	FeatureBridgeVLAN    = "bridge_vlan"
	FeatureVirtualNet    = "virtual_network_override"
	FeatureJumbo         = "jumbo_frames"
	FeaturePortIsolation = "port_isolation"
	FeatureMACPort       = "mac_port_restriction"
	FeatureMACBlock      = "mac_address_blocking"
	FeatureMACACL        = "mac_acl_device_isolation"
	FeatureIPACL         = "ip_acl_network_isolation"
	FeatureEgressRate    = "egress_rate_limit"
	FeatureFlowControl   = "flow_control"
	FeatureQoSDSCP       = "qos_dscp"
	FeatureStormControl  = "storm_control"
	FeatureMultiRate     = "multicast_broadcast_rate_limit"
	FeatureIGMPSnoop     = "igmp_snooping"
	FeatureIGMPAdvanced  = "igmp_advanced"
	FeatureDHCPSnoop     = "dhcp_snooping_guarding"
	Feature8021X         = "8021x_control"
	FeatureVoiceVLAN     = "voice_vlan"
	FeatureLLDPMED       = "lldp_med"
	FeatureSTP           = "stp"
	FeatureRSTP          = "rstp"
	FeatureLoopProtect   = "loop_protection"
	FeatureLACP          = "lacp_port_aggregation"
	FeatureRedundancy    = "redundancy"
	FeatureMCLAG         = "mc_lag"
	FeatureVRRP          = "vrrp_gateway_failover"
	FeaturePortMirror    = "port_mirroring"
)

type FeatureCapability struct {
	State  CapabilityState `json:"state"`
	Reason string          `json:"reason,omitempty"`
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
	TCClsact            bool            `json:"tc_clsact,omitempty"`
	LegacyIngress       bool            `json:"tc_legacy_ingress,omitempty"`
	TCFilters           []TCFilterState `json:"-"`
	TCEgressFilters     []TCFilterState `json:"-"`
	RootQdisc           string          `json:"root_qdisc,omitempty"`
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
	NumVLANs         int    `json:"num_of_vlans"`
	HasNumVLANs      bool   `json:"has_num_of_vlans"`
	VLANAction       string `json:"vlan_action,omitempty"`
	VLANControl      string `json:"vlan_control,omitempty"`
	VLANID           uint16 `json:"vlan_id,omitempty"`
	DropTagged       bool   `json:"drop_tagged,omitempty"`
	PoliceRateBPS    uint64 `json:"police_rate_bps,omitempty"`
	PoliceBurstBytes uint32 `json:"police_burst_bytes,omitempty"`
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

type Capabilities struct {
	KernelRelease        string                         `json:"kernel_release,omitempty"`
	Tools                map[string]bool                `json:"tools"`
	Bonding              bool                           `json:"bonding_module"`
	Interfaces           []HostInterface                `json:"interfaces"`
	BridgeVLANs          []BridgeVLANState              `json:"bridge_vlans"`
	BridgeFDB            []BridgeFDBEntry               `json:"-"`
	MACBlockTablePresent bool                           `json:"-"`
	MACBlockTableManaged bool                           `json:"-"`
	MACBlockRuleCounters map[string][2]uint64           `json:"-"`
	Overrides            []VirtualNetworkOverrideStatus `json:"virtual_network_overrides,omitempty"`
	MACPortRestrictions  []MACPortRestrictionStatus     `json:"mac_port_restrictions,omitempty"`
	MACBlocks            []MACBlockStatus               `json:"mac_address_blocks,omitempty"`
	MACACLTablePresent   bool                           `json:"-"`
	MACACLTableManaged   bool                           `json:"-"`
	MACACLRuleCounters   map[string][2]uint64           `json:"-"`
	MACACL               []MACACLStatus                 `json:"mac_acls,omitempty"`
	IPACLTablePresent    bool                           `json:"-"`
	IPACLTableManaged    bool                           `json:"-"`
	IPACLRuleCounters    map[string][2]uint64           `json:"-"`
	IPACL                []IPACLStatus                  `json:"ip_acls,omitempty"`
	EgressRates          []EgressRateStatus             `json:"egress_rate_limits,omitempty"`
	FlowControl          []FlowControlStatus            `json:"flow_control,omitempty"`
	Bonds                []BondStatus                   `json:"bonds,omitempty"`
	Features             map[string]FeatureCapability   `json:"features"`
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
	unsupported := []string{FeatureQoSDSCP, FeatureStormControl, FeatureMultiRate,
		FeatureIGMPSnoop, FeatureIGMPAdvanced, FeatureDHCPSnoop, Feature8021X, FeatureVoiceVLAN, FeatureLLDPMED,
		FeatureSTP, FeatureRSTP, FeatureLoopProtect, FeatureRedundancy, FeaturePortMirror}
	required := map[string][]string{
		FeatureEgressRate: {"tc"},
		FeatureQoSDSCP:    {"tc"}, FeatureStormControl: {"tc", "nft"},
		FeatureMultiRate: {"tc", "nft"}, FeatureIGMPSnoop: {"bridge"}, FeatureIGMPAdvanced: {"bridge"},
		FeatureDHCPSnoop: {"nft"}, Feature8021X: {"hostapd"}, FeatureVoiceVLAN: {"lldpd", "bridge"},
		FeatureLLDPMED: {"lldpd"}, FeatureSTP: {"bridge"}, FeatureRSTP: {"mstpd", "bridge"},
		FeatureLoopProtect: {"bridge"}, FeaturePortMirror: {"tc"},
	}
	for _, name := range unsupported {
		missing := ""
		for _, tool := range required[name] {
			if !d.Tools[tool] {
				missing = tool
				break
			}
		}
		if missing != "" {
			set(name, CapabilityUnavailable, "required host tool is missing: "+missing)
		} else {
			set(name, CapabilityUnsupported, "Linux provider is not integrated")
		}
	}
	if !d.Bonding {
		set(FeatureLACP, CapabilityUnavailable, "Linux bonding support is not loaded or exposed by the host")
	} else if require(FeatureLACP, "ip", "ethtool") {
		set(FeatureLACP, CapabilityConditional, "Linux 802.3ad bonds are available; peer negotiation is verified after apply")
	}
	set(FeatureMCLAG, CapabilityUnsupported, "no generic Linux MC-LAG peer protocol is configured")
	for _, profile := range avProfiles {
		set(profile.feature, CapabilityUnsupported, "profile has not yet been integrated and validated")
	}
	return c
}

// SnapshotCapabilities reads only host metadata. It does not load modules,
// alter links, or launch optional providers.
func SnapshotCapabilities(ctx context.Context, cfg Config, runner HostRunner) (Capabilities, error) {
	var kernel string
	if raw, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		kernel = strings.TrimSpace(string(raw))
	}
	tools := map[string]bool{}
	for _, name := range []string{"ip", "bridge", "tc", "nft", "ethtool", "conntrack", "keepalived", "lldpd", "hostapd", "mstpd"} {
		tools[name] = runner.Available(name)
	}
	detection := Detection{KernelRelease: kernel, Tools: tools}
	if _, err := os.Stat("/sys/module/bonding"); err == nil {
		detection.Bonding = true
	}
	c := EvaluateCapabilities(detection)
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
				VLANFiltering        bool            `json:"vlan_filtering"`
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
		hostInterface := HostInterface{Name: link.Name, Kind: link.LinkInfo.Kind, Master: link.Master, MTU: link.MTU, MaxMTU: link.MaxMTU, OperState: link.OperState, AdminUp: adminUp, VLANFiltering: link.LinkInfo.InfoData.VLANFiltering, Address: strings.ToLower(link.Address)}
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
			filterResult, err := runner.Run(ctx, "tc", "-json", "filter", "show", "dev", name, "ingress")
			if err != nil {
				return c, fmt.Errorf("read ingress filters for %s: %w", name, err)
			}
			filters, err := parseTCFilters(filterResult)
			if err != nil {
				return c, fmt.Errorf("decode ingress filters for %s: %w", name, err)
			}
			c.Interfaces[index].TCFilters = filters
			egressFilterResult, err := runner.Run(ctx, "tc", "-json", "filter", "show", "dev", name, "egress")
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
			Name       string `json:"ifname"`
			Isolated   *bool  `json:"isolated"`
			Locked     *bool  `json:"locked"`
			MaxLearned *int   `json:"max_learned"`
		}
		if err := json.Unmarshal(linkResult, &bridgeLinks); err != nil {
			return c, fmt.Errorf("decode host bridge link inventory: %w", err)
		}
		for _, bridgeLink := range bridgeLinks {
			if index, exists := interfaceIndex[bridgeLink.Name]; exists {
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
	}
	if runner.Available("ethtool") {
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
	snapshotMACBlockState(ctx, runner, &c, cfg)
	snapshotMACACLState(ctx, runner, &c, cfg)
	snapshotIPACLState(ctx, runner, &c, cfg)
	c.Bonds = snapshotBonds(cfg, c.Interfaces)
	return c, nil
}

type pauseState struct {
	Autoneg string
	RX      bool
	TX      bool
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

func applyIPACLStatus(caps *Capabilities, cfg Config) {
	all := ipACLRuleComments(cfg)
	for i, r := range cfg.IPACL {
		s := IPACLStatus{ID: r.ID, Direction: r.Direction, Action: r.Action, RuleOrder: i + 1, Applied: caps.IPACLTablePresent && caps.IPACLTableManaged && exactStringSet(mapKeys(caps.IPACLRuleCounters), all)}
		for _, comment := range ipACLRuleComments(Config{IPACL: []IPACLRule{r}}) {
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
		for _, comment := range macACLRuleComments(Config{MACACL: []MACACLRule{rule}}) {
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
	}
	if err := json.Unmarshal(data, &rows); err != nil {
		return nil, err
	}
	filters := make([]TCFilterState, 0, len(rows))
	for _, row := range rows {
		state := TCFilterState{Priority: row.Priority, Kind: row.Kind, NumVLANs: -1}
		if mac, ok := row.Options["src_mac"].(string); ok {
			state.SourceMAC = strings.ToLower(mac)
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
