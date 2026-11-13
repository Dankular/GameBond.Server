//go:build linux

package layer2

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
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
	Name          string `json:"name"`
	Kind          string `json:"kind,omitempty"`
	Master        string `json:"master,omitempty"`
	MTU           int    `json:"mtu"`
	MaxMTU        int    `json:"max_mtu,omitempty"`
	OperState     string `json:"oper_state,omitempty"`
	AdminUp       bool   `json:"admin_up"`
	VLANFiltering bool   `json:"vlan_filtering,omitempty"`
}

type BridgeVLANState struct {
	Device   string `json:"device"`
	VLAN     uint16 `json:"vlan"`
	PVID     bool   `json:"pvid,omitempty"`
	Untagged bool   `json:"untagged,omitempty"`
}

type Capabilities struct {
	KernelRelease string                       `json:"kernel_release,omitempty"`
	Tools         map[string]bool              `json:"tools"`
	Bonding       bool                         `json:"bonding_module"`
	Interfaces    []HostInterface              `json:"interfaces"`
	BridgeVLANs   []BridgeVLANState            `json:"bridge_vlans"`
	Features      map[string]FeatureCapability `json:"features"`
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
	unsupported := []string{FeatureVirtualNet, FeaturePortIsolation, FeatureMACPort, FeatureMACBlock, FeatureMACACL,
		FeatureIPACL, FeatureEgressRate, FeatureFlowControl, FeatureQoSDSCP, FeatureStormControl, FeatureMultiRate,
		FeatureIGMPSnoop, FeatureIGMPAdvanced, FeatureDHCPSnoop, Feature8021X, FeatureVoiceVLAN, FeatureLLDPMED,
		FeatureSTP, FeatureRSTP, FeatureLoopProtect, FeatureRedundancy, FeatureVRRP, FeaturePortMirror}
	required := map[string][]string{
		FeatureVirtualNet: {"bridge", "nft"}, FeaturePortIsolation: {"bridge", "nft"}, FeatureMACPort: {"bridge", "nft"},
		FeatureMACBlock: {"nft"}, FeatureMACACL: {"nft"}, FeatureIPACL: {"nft"}, FeatureEgressRate: {"tc"},
		FeatureFlowControl: {"ethtool"}, FeatureQoSDSCP: {"tc"}, FeatureStormControl: {"tc", "nft"},
		FeatureMultiRate: {"tc", "nft"}, FeatureIGMPSnoop: {"bridge"}, FeatureIGMPAdvanced: {"bridge"},
		FeatureDHCPSnoop: {"nft"}, Feature8021X: {"hostapd"}, FeatureVoiceVLAN: {"lldpd", "bridge"},
		FeatureLLDPMED: {"lldpd"}, FeatureSTP: {"bridge"}, FeatureRSTP: {"mstpd", "bridge"},
		FeatureLoopProtect: {"bridge"}, FeatureVRRP: {"keepalived"}, FeaturePortMirror: {"tc"},
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
	} else if require(FeatureLACP, "ip") {
		set(FeatureLACP, CapabilityUnsupported, "LACP bond configuration and peer verification provider is not integrated")
	}
	set(FeatureMCLAG, CapabilityUnsupported, "no generic Linux MC-LAG peer protocol is configured")
	for _, profile := range avProfiles {
		set(profile.feature, CapabilityUnsupported, "profile has not yet been integrated and validated")
	}
	return c
}

// SnapshotCapabilities reads only host metadata. It does not load modules,
// alter links, or launch optional providers.
func SnapshotCapabilities(ctx context.Context, runner HostRunner) (Capabilities, error) {
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
		MTU       int      `json:"mtu"`
		MaxMTU    int      `json:"max_mtu"`
		OperState string   `json:"operstate"`
		Master    string   `json:"master"`
		Flags     []string `json:"flags"`
		LinkInfo  struct {
			Kind     string `json:"info_kind"`
			InfoData struct {
				VLANFiltering bool `json:"vlan_filtering"`
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
		c.Interfaces = append(c.Interfaces, HostInterface{Name: link.Name, Kind: link.LinkInfo.Kind, Master: link.Master, MTU: link.MTU, MaxMTU: link.MaxMTU, OperState: link.OperState, AdminUp: adminUp, VLANFiltering: link.LinkInfo.InfoData.VLANFiltering})
	}
	if runner.Available("bridge") {
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
	return c, nil
}

func cloneTools(in map[string]bool) map[string]bool {
	out := make(map[string]bool, len(in))
	for name, present := range in {
		out[name] = present
	}
	return out
}
