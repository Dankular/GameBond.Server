package layer2

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Dankular/GameBond.Server/gateway/layer2/avprofiles"
)

const MaxConfigBytes = 1 << 20
const MaxDeviceOverrides = 4096
const MaxMACBlocks = 128
const MaxMACACLRules = 256
const MaxIPACLRules = 256

var (
	stableIDPattern    = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	segmentIDPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)
	ifNamePattern      = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)
	radiusHostPattern  = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$`)
	nasIDPattern       = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,253}$`)
	eapIdentityPattern = regexp.MustCompile(`^[A-Za-z0-9._@:-]{1,253}$`)
)

func enabled(value *bool) bool { return value != nil && *value }

func validRadiusHostname(value string) bool {
	return len(value) <= 253 && radiusHostPattern.MatchString(value)
}

func validLLDPMEDApplication(value string) bool {
	switch value {
	case "voice", "voice-signaling", "guest-voice", "guest-voice-signaling", "softphone-voice", "video-conferencing", "streaming-video", "video-signaling":
		return true
	default:
		return false
	}
}

func validSupplicantPath(value string) bool {
	return path.IsAbs(value) && !strings.ContainsAny(value, "\\\r\n\x00\"")
}

// Config is the versioned Layer 2 desired topology. References use stable IDs;
// interface names are resolved on the managed host when a plan is prepared.
type Config struct {
	Version                  int                           `json:"version"`
	Interfaces               []Interface                   `json:"interfaces"`
	Bridges                  []Bridge                      `json:"bridges"`
	Networks                 []Network                     `json:"networks"`
	Overrides                []DeviceOverride              `json:"virtual_network_overrides,omitempty"`
	MACPortRestrictions      []MACPortRestriction          `json:"mac_port_restrictions,omitempty"`
	MACBlocks                []MACBlock                    `json:"mac_address_blocks,omitempty"`
	MACACL                   []MACACLRule                  `json:"mac_acls,omitempty"`
	IPACL                    []IPACLRule                   `json:"ip_acls,omitempty"`
	NetworkACL               []NetworkACLRule              `json:"inter_network_acls,omitempty"`
	EgressRates              []EgressRateLimit             `json:"egress_rate_limits,omitempty"`
	StormControl             []StormControl                `json:"storm_control,omitempty"`
	MulticastBroadcastLimits []MulticastBroadcastRateLimit `json:"multicast_broadcast_rate_limits,omitempty"`
	FlowControl              []FlowControlPolicy           `json:"flow_control,omitempty"`
	QoS                      []QoSPolicy                   `json:"qos,omitempty"`
	PortMirrors              []PortMirror                  `json:"port_mirrors,omitempty"`
	Bonds                    []Bond                        `json:"bonds,omitempty"`
	VXLANDevices             []VXLANDevice                 `json:"vxlan_devices,omitempty"`
	DHCPGuard                []DHCPGuardPort               `json:"dhcp_guard,omitempty"`
	PortAuth                 []PortAuth                    `json:"port_auth,omitempty"`
	WiredSupplicants         []WiredSupplicant             `json:"wired_supplicants,omitempty"`
	AVProfiles               []AVProfileSelection          `json:"pro_av_profiles,omitempty"`
}

// AVProfileSelection records an evidence-backed AV profile for a managed
// network. It is persisted with the topology so operators can review the
// profile's recommendations alongside the effective bridge configuration.
// Profile settings that the Linux gateway cannot own remain advisory.
type AVProfileSelection struct {
	Profile string `json:"profile"`
	Network string `json:"network"`
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

// VXLANDevice attaches one persistent broker TAP and one kernel VXLAN netdevice
// to the same bridge network. The VNI and local VTEP address are discovered by
// FRR/Zebra; EVPN peer routes are not synthesized by the Layer 2 provider.
type VXLANDevice struct {
	ID                string `json:"id"`
	VNI               uint32 `json:"vni"`
	TapInterface      string `json:"tap_interface"`   // managed Interface ID opened by the edge broker
	VxlanInterface    string `json:"vxlan_interface"` // managed Interface ID created as a kernel VXLAN device
	UnderlayInterface string `json:"underlay_interface"`
	Network           string `json:"network"`
	LocalAddress      string `json:"local_address"`
	UDPPort           uint16 `json:"udp_port,omitempty"` // default 4789
}

type Bridge struct {
	ID            string       `json:"id"`
	Name          string       `json:"name"`
	VLANFiltering bool         `json:"vlan_filtering"`
	STPPriority   *uint16      `json:"stp_priority,omitempty"`
	STPEnabled    *bool        `json:"stp_enabled,omitempty"`
	STPMode       string       `json:"stp_mode,omitempty"`
	IGMPSnooping  *bool        `json:"igmp_snooping,omitempty"`
	IGMPQuerier   *bool        `json:"igmp_querier,omitempty"`
	Ports         []BridgePort `json:"ports"`
}

type BridgePort struct {
	Interface            string          `json:"interface"`
	STPPriority          *uint8          `json:"stp_priority,omitempty"`
	STPPathCost          *uint32         `json:"stp_path_cost,omitempty"`
	STPRootBlock         *bool           `json:"stp_root_block,omitempty"`
	STPEdge              *bool           `json:"stp_edge,omitempty"`
	STPPointToPoint      string          `json:"stp_point_to_point,omitempty"`
	STPBPDUGuard         *bool           `json:"stp_bpdu_guard,omitempty"`
	UntaggedNetwork      string          `json:"untagged_network,omitempty"`
	TaggedNetworks       []string        `json:"tagged_networks,omitempty"`
	VoiceNetwork         string          `json:"voice_network,omitempty"`
	LLDPMED              []LLDPMEDPolicy `json:"lldp_med,omitempty"`
	Isolated             bool            `json:"isolated,omitempty"`
	IGMPFastLeave        *bool           `json:"igmp_fast_leave,omitempty"`
	IGMPSharedDownstream *bool           `json:"igmp_shared_downstream,omitempty"`
	IGMPRouterPort       *bool           `json:"igmp_router_port,omitempty"`
	LoopProtection       *bool           `json:"loop_protection,omitempty"`
}

// LLDPMEDPolicy advertises a documented application network policy to peers.
type LLDPMEDPolicy struct {
	Application string `json:"application"`
	Network     string `json:"network,omitempty"`
	Tagged      bool   `json:"tagged,omitempty"`
	Priority    *uint8 `json:"priority,omitempty"`
	DSCP        *uint8 `json:"dscp,omitempty"`
}

// DHCPGuardPort marks a bridge port as a trusted DHCP server/relay path and
// optionally rate-limits DHCP packets received from that port.
type DHCPGuardPort struct {
	Interface        string `json:"interface"`
	Trusted          bool   `json:"trusted"`
	RateLimitPPS     uint32 `json:"rate_limit_pps,omitempty"`
	ValidateBindings bool   `json:"validate_bindings,omitempty"`
}

// PortAuth configures wired IEEE 802.1X authentication for a managed bridge
// port. RADIUS credentials are referenced from a root-owned file and never
// embedded in the API configuration.
type PortAuth struct {
	Interface     string `json:"interface"`
	ExclusivePort bool   `json:"exclusive_port"`
	RadiusServer  string `json:"radius_server"`
	RadiusPort    uint16 `json:"radius_port"`
	SecretFile    string `json:"secret_file"`
	NASAddress    string `json:"nas_address"`
	NASID         string `json:"nas_id"`
	ReauthSeconds uint32 `json:"reauth_seconds,omitempty"`
	FailurePolicy string `json:"failure_policy"`
	// Segment fields bind this hostapd interface's station events to one
	// broker-authenticated session attachment. The separate admin credential is
	// read from its protected file at event time, never copied into config.
	SegmentID             string `json:"segment_id,omitempty"`
	SegmentIdentity       string `json:"segment_identity,omitempty"`
	SegmentSocketPath     string `json:"segment_socket_path,omitempty"`
	SegmentAdminTokenFile string `json:"segment_admin_token_file,omitempty"`
	EAPOLTapName          string `json:"eapol_tap_name,omitempty"`
}

// WiredSupplicant configures a managed Linux uplink to authenticate to an
// upstream wired 802.1X network. Password and private-key passphrase material
// stays in a root-owned credential file and is never embedded in API config.
type WiredSupplicant struct {
	Interface              string `json:"interface"`
	EAPMethod              string `json:"eap_method"` // PEAP, TTLS, or TLS
	Identity               string `json:"identity"`
	AnonymousIdentity      string `json:"anonymous_identity,omitempty"`
	Phase2                 string `json:"phase2,omitempty"` // auth=PAP, auth=CHAP, auth=MSCHAP, or auth=MSCHAPV2
	PasswordFile           string `json:"password_file,omitempty"`
	CAFile                 string `json:"ca_file"`
	ClientCertFile         string `json:"client_cert_file,omitempty"`
	PrivateKeyFile         string `json:"private_key_file,omitempty"`
	PrivateKeyPasswordFile string `json:"private_key_password_file,omitempty"`
}

// Network represents one VLAN-backed virtual network on a managed bridge.
type Network struct {
	ID             string `json:"id"`
	Bridge         string `json:"bridge"`
	VLAN           uint16 `json:"vlan"`
	MTU            int    `json:"mtu"`
	IGMPSnooping   *bool  `json:"igmp_snooping,omitempty"`
	RouteInterface string `json:"route_interface,omitempty"`
}

// NetworkACLRule explicitly permits a directed flow between two routed Layer 2
// networks. Other new flows between configured routed networks are dropped.
type NetworkACLRule struct {
	ID                 string `json:"id"`
	SourceNetwork      string `json:"source_network"`
	DestinationNetwork string `json:"destination_network"`
	Protocol           string `json:"protocol,omitempty"`
	Port               uint16 `json:"port,omitempty"`
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

// StormControl applies ingress policing independently to broadcast and
// multicast destination MAC classes. A zero rate leaves that class unlimited.
type StormControl struct {
	Interface        string `json:"interface"`
	BroadcastRateBPS uint64 `json:"broadcast_rate_bps,omitempty"`
	MulticastRateBPS uint64 `json:"multicast_rate_bps,omitempty"`
	BurstBytes       uint32 `json:"burst_bytes"`
}

// MulticastBroadcastRateLimit applies ingress rate caps independently from
// storm control so operators can enable these limits on selected interfaces.
type MulticastBroadcastRateLimit struct {
	Interface        string `json:"interface"`
	BroadcastRateBPS uint64 `json:"broadcast_rate_bps,omitempty"`
	MulticastRateBPS uint64 `json:"multicast_rate_bps,omitempty"`
	BurstBytes       uint32 `json:"burst_bytes"`
}

type FlowControlPolicy struct {
	Interface string `json:"interface"`
	Autoneg   string `json:"autoneg"`
	RX        bool   `json:"rx"`
	TX        bool   `json:"tx"`
}

// QoSPolicy configures Linux software HTB classes selected by DSCP.
type QoSPolicy struct {
	Interface   string     `json:"interface"`
	LinkRateBPS uint64     `json:"link_rate_bps"`
	Classes     []QoSClass `json:"classes"`
}

type QoSClass struct {
	ID         uint8   `json:"id"`
	DSCP       []uint8 `json:"dscp"`
	RateBPS    uint64  `json:"rate_bps"`
	CeilingBPS uint64  `json:"ceiling_bps"`
	Priority   uint8   `json:"priority"`
}

// PortMirror copies selected source-port ingress or egress traffic to a
// dedicated monitor interface using tc mirred mirror actions.
type PortMirror struct {
	Source            string `json:"source"`
	Destination       string `json:"destination"`
	Direction         string `json:"direction"`
	Network           string `json:"network,omitempty"`
	CaptureRateBPS    uint64 `json:"capture_rate_bps,omitempty"`
	CaptureBurstBytes uint32 `json:"capture_burst_bytes,omitempty"`
}

func ipACLRuleComments(cfg Config) []string {
	comments := make([]string, 0, len(cfg.IPACL)*2)
	for _, rule := range cfg.IPACL {
		comments = append(comments, ipACLCommentsForRule(cfg, rule)...)
	}
	sort.Strings(comments)
	return comments
}

func ipACLCommentsForRule(cfg Config, rule IPACLRule) []string {
	comments := []string{}
	if rule.Direction == "ingress" || rule.Direction == "both" {
		comments = append(comments, ipACLRuleComment(cfg, rule, "in"), ipACLRuleComment(cfg, rule, "host-in"))
	}
	if rule.Direction == "egress" || rule.Direction == "both" {
		comments = append(comments, ipACLRuleComment(cfg, rule, "out"), ipACLRuleComment(cfg, rule, "host-out"))
	}
	return comments
}

func ipACLRuleComment(cfg Config, rule IPACLRule, suffix string) string {
	iface, network, port := configInterfaceByID(cfg.Interfaces, rule.Interface), configNetworkByID(cfg.Networks, rule.Network), bridgePortByInterface(cfg.Bridges, rule.Interface)
	fingerprint := policyFingerprint(rule.ID, rule.Interface, iface.Name, rule.Network, fmt.Sprint(network.VLAN), port.UntaggedNetwork, rule.Direction, rule.Family, rule.Source, rule.Dest, rule.Protocol, fmt.Sprint(rule.Port), rule.Action)
	return "gamebond-ip-acl:" + rule.ID + ":" + suffix + ":" + fingerprint
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
		comments = append(comments, macACLCommentsForRule(cfg, rule)...)
	}
	sort.Strings(comments)
	return comments
}

func macACLCommentsForRule(cfg Config, rule MACACLRule) []string {
	chains := []string{}
	switch rule.Direction {
	case "ingress":
		chains = []string{"forward-in", "input"}
	case "egress":
		chains = []string{"forward-out", "output"}
	case "both":
		chains = []string{"forward-in", "forward-out", "input", "output"}
	}
	comments := make([]string, 0, len(chains))
	for _, chain := range chains {
		comments = append(comments, macACLRuleComment(cfg, rule, chain))
	}
	return comments
}

func macACLRuleComment(cfg Config, rule MACACLRule, suffix string) string {
	iface, network, port := configInterfaceByID(cfg.Interfaces, rule.Interface), configNetworkByID(cfg.Networks, rule.Network), bridgePortByInterface(cfg.Bridges, rule.Interface)
	fingerprint := policyFingerprint(rule.ID, rule.Interface, iface.Name, rule.Network, fmt.Sprint(network.VLAN), port.UntaggedNetwork, rule.Direction, rule.SourceMAC, rule.DestinationMAC, rule.Action)
	return "gamebond-mac-acl:" + rule.ID + ":" + suffix + ":" + fingerprint
}

func bridgePortByInterface(bridges []Bridge, interfaceID string) BridgePort {
	for _, bridge := range bridges {
		for _, port := range bridge.Ports {
			if port.Interface == interfaceID {
				return port
			}
		}
	}
	return BridgePort{}
}

func configInterfaceByID(interfaces []Interface, id string) Interface {
	for _, iface := range interfaces {
		if iface.ID == id {
			return iface
		}
	}
	return Interface{}
}

func configNetworkByID(networks []Network, id string) Network {
	for _, network := range networks {
		if network.ID == id {
			return network
		}
	}
	return Network{}
}

func policyFingerprint(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return fmt.Sprintf("%x", sum[:16])
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
	bridgeConfigs := make(map[string]Bridge, len(c.Bridges))
	bridgeNames := make(map[string]struct{}, len(c.Bridges))
	interfaceBridge := make(map[string]string)
	interfacePorts := make(map[string]BridgePort)
	snoopingPorts := make(map[string]bool)
	for i, br := range c.Bridges {
		if !stableIDPattern.MatchString(br.ID) {
			return fmt.Errorf("bridges[%d].id must be a lowercase stable ID", i)
		}
		if _, exists := bridgeIDs[br.ID]; exists {
			return fmt.Errorf("bridge ID %q is duplicated", br.ID)
		}
		bridgeIDs[br.ID] = struct{}{}
		bridgeConfigs[br.ID] = br
		if !ifNamePattern.MatchString(br.Name) || br.Name == "." || br.Name == ".." {
			return fmt.Errorf("bridges[%d].name is not a valid Linux interface name", i)
		}
		if _, exists := bridgeNames[br.Name]; exists {
			return fmt.Errorf("bridge name %q is duplicated", br.Name)
		}
		if _, exists := interfaceNames[br.Name]; exists {
			return fmt.Errorf("bridge name %q conflicts with a managed interface", br.Name)
		}
		if br.STPMode != "" && br.STPMode != "stp" && br.STPMode != "rstp" {
			return fmt.Errorf("bridge %q stp_mode must be stp or rstp", br.ID)
		}
		if br.STPMode != "" && br.STPEnabled != nil {
			return fmt.Errorf("bridge %q cannot set both stp_mode and stp_enabled", br.ID)
		}
		if br.STPPriority != nil && (*br.STPPriority > 61440 || *br.STPPriority%4096 != 0) {
			return fmt.Errorf("bridge %q stp_priority must be a multiple of 4096 in 0..61440", br.ID)
		}
		if br.STPPriority != nil && br.STPMode == "" && !enabled(br.STPEnabled) {
			return fmt.Errorf("bridge %q STP priority requires STP to be enabled or a protocol mode selected", br.ID)
		}
		if enabled(br.IGMPQuerier) && (!enabled(br.IGMPSnooping) || br.IGMPSnooping == nil) {
			return fmt.Errorf("bridge %q IGMP querier requires IGMP snooping", br.ID)
		}
		bridgeNames[br.Name] = struct{}{}
		seenPorts := make(map[string]struct{}, len(br.Ports))
		for _, port := range br.Ports {
			if port.LoopProtection != nil && port.STPBPDUGuard != nil {
				return fmt.Errorf("bridge %q port %q cannot configure both loop_protection and stp_bpdu_guard", br.ID, port.Interface)
			}
			if port.STPPointToPoint != "" && port.STPPointToPoint != "yes" && port.STPPointToPoint != "no" && port.STPPointToPoint != "auto" {
				return fmt.Errorf("bridge %q port %q stp_point_to_point must be yes, no, or auto", br.ID, port.Interface)
			}
			if (port.STPEdge != nil || port.STPPointToPoint != "" || port.STPBPDUGuard != nil) && br.STPMode != "rstp" {
				return fmt.Errorf("bridge %q edge, point-to-point, and BPDU guard settings require stp_mode rstp", br.ID)
			}
			if (port.STPPriority != nil || port.STPPathCost != nil || port.STPRootBlock != nil) && br.STPMode == "" && !enabled(br.STPEnabled) {
				return fmt.Errorf("bridge %q STP port tuning on %q requires STP to be enabled or a protocol mode selected", br.ID, port.Interface)
			}
			if port.STPPriority != nil && *port.STPPriority > 63 {
				return fmt.Errorf("bridge %q port %q stp_priority must be 0..63", br.ID, port.Interface)
			}
			if port.STPPathCost != nil && (*port.STPPathCost < 1 || *port.STPPathCost > 65535) {
				return fmt.Errorf("bridge %q port %q stp_path_cost must be 1..65535", br.ID, port.Interface)
			}
			if enabled(br.IGMPSnooping) {
				snoopingPorts[port.Interface] = true
			}
			if (enabled(port.IGMPFastLeave) || enabled(port.IGMPRouterPort)) && !enabled(br.IGMPSnooping) {
				return fmt.Errorf("bridge %q IGMP fast leave and router-port settings require IGMP snooping", br.ID)
			}
			if enabled(port.IGMPFastLeave) && (port.IGMPSharedDownstream == nil || *port.IGMPSharedDownstream) {
				return fmt.Errorf("bridge %q fast leave requires an explicitly confirmed non-shared downstream port", br.ID)
			}
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
	if len(c.DHCPGuard) > 256 {
		return fmt.Errorf("dhcp_guard exceeds limit 256")
	}
	seenDHCPGuard := make(map[string]bool, len(c.DHCPGuard))
	for i, policy := range c.DHCPGuard {
		field := fmt.Sprintf("dhcp_guard[%d]", i)
		if _, exists := interfaceIDs[policy.Interface]; !exists {
			return fmt.Errorf("%s references unknown interface %q", field, policy.Interface)
		}
		if _, exists := interfaceBridge[policy.Interface]; !exists {
			return fmt.Errorf("%s interface %q is not a bridge port", field, policy.Interface)
		}
		if seenDHCPGuard[policy.Interface] {
			return fmt.Errorf("%s duplicates interface %q", field, policy.Interface)
		}
		seenDHCPGuard[policy.Interface] = true
		if policy.RateLimitPPS > 10000 {
			return fmt.Errorf("%s.rate_limit_pps must be 0 or 1..10000", field)
		}
	}
	if len(c.PortAuth) > 128 {
		return fmt.Errorf("port_auth exceeds limit 128")
	}
	seenPortAuth := make(map[string]bool, len(c.PortAuth))
	seenSegmentAuth := make(map[string]bool, len(c.PortAuth))
	seenSegmentTap := make(map[string]bool, len(c.PortAuth))
	for i, policy := range c.PortAuth {
		field := fmt.Sprintf("port_auth[%d]", i)
		if _, exists := interfaceIDs[policy.Interface]; !exists || interfaceBridge[policy.Interface] == "" {
			return fmt.Errorf("%s.interface %q must reference a managed bridge port", field, policy.Interface)
		}
		if seenPortAuth[policy.Interface] {
			return fmt.Errorf("%s duplicates interface %q", field, policy.Interface)
		}
		seenPortAuth[policy.Interface] = true
		if policy.RadiusServer == "" || strings.ContainsAny(policy.RadiusServer, "/\\ \t\r\n") {
			return fmt.Errorf("%s.radius_server must be an IP address or DNS name", field)
		}
		if ip, err := netip.ParseAddr(policy.RadiusServer); err != nil || ip.Zone() != "" {
			if !validRadiusHostname(policy.RadiusServer) {
				return fmt.Errorf("%s.radius_server must be an IP address or DNS name", field)
			}
		}
		if policy.RadiusPort == 0 {
			return fmt.Errorf("%s.radius_port must be 1..65535", field)
		}
		if address, err := netip.ParseAddr(policy.NASAddress); err != nil || address.Zone() != "" {
			return fmt.Errorf("%s.nas_address must be a local IPv4 or IPv6 address", field)
		}
		if policy.SecretFile != path.Join("/etc/gamebond/8021x", policy.Interface+".secret") {
			return fmt.Errorf("%s.secret_file must be the managed per-port secret path", field)
		}
		if !nasIDPattern.MatchString(policy.NASID) {
			return fmt.Errorf("%s.nas_id is invalid", field)
		}
		if policy.ReauthSeconds != 0 && (policy.ReauthSeconds < 60 || policy.ReauthSeconds > 86400) {
			return fmt.Errorf("%s.reauth_seconds must be 0 or 60..86400", field)
		}
		if policy.FailurePolicy != "closed" {
			return fmt.Errorf("%s.failure_policy must be closed; fail-open is not supported", field)
		}
		if !policy.ExclusivePort {
			return fmt.Errorf("%s.exclusive_port must be true; shared downstream 802.1X ports cannot safely receive broadcast or multicast traffic", field)
		}
		segmentMapping := policy.SegmentID != "" || policy.SegmentIdentity != "" || policy.SegmentSocketPath != "" || policy.SegmentAdminTokenFile != "" || policy.EAPOLTapName != ""
		if segmentMapping {
			if !segmentIDPattern.MatchString(policy.SegmentID) || len(policy.SegmentIdentity) > 128 || !eapIdentityPattern.MatchString(policy.SegmentIdentity) {
				return fmt.Errorf("%s.segment_id and segment_identity must be valid when broker authorization is enabled", field)
			}
			if !path.IsAbs(policy.SegmentSocketPath) || len(policy.SegmentSocketPath) >= 104 || strings.ContainsAny(policy.SegmentSocketPath, "\\\r\n\x00") {
				return fmt.Errorf("%s.segment_socket_path must be absolute and shorter than 104 bytes", field)
			}
			if !validSupplicantPath(policy.SegmentAdminTokenFile) {
				return fmt.Errorf("%s.segment_admin_token_file must be an absolute safe path", field)
			}
			iface, _ := findInterface(c.Interfaces, policy.Interface)
			if !ifNamePattern.MatchString(policy.EAPOLTapName) || iface.Name != policy.EAPOLTapName {
				return fmt.Errorf("%s.eapol_tap_name must match the managed interface name used by the edge broker TAP", field)
			}
			segmentKey := policy.SegmentID + "\x00" + policy.SegmentSocketPath
			identityKey := segmentKey + "\x00" + policy.SegmentIdentity
			tapKey := segmentKey + "\x00" + policy.EAPOLTapName
			if seenSegmentAuth[identityKey] || seenSegmentTap[tapKey] {
				return fmt.Errorf("%s duplicates a segment identity or EAPOL TAP mapping", field)
			}
			seenSegmentAuth[identityKey], seenSegmentTap[tapKey] = true, true
		}
		bridgeID := interfaceBridge[policy.Interface]
		for _, bridge := range c.Bridges {
			if bridge.ID != bridgeID {
				continue
			}
			if enabled(bridge.STPEnabled) || bridge.STPMode != "" {
				return fmt.Errorf("%s cannot be enabled on bridge %q while STP/RSTP is configured; EAPOL forwarding compatibility is unverified", field, bridge.ID)
			}
			for _, port := range bridge.Ports {
				if port.Interface == policy.Interface && (port.STPPriority != nil || port.STPPathCost != nil || enabled(port.STPRootBlock) || enabled(port.STPEdge) || enabled(port.STPBPDUGuard)) {
					return fmt.Errorf("%s cannot be enabled on port %q while STP controls are configured; EAPOL forwarding compatibility is unverified", field, policy.Interface)
				}
			}
		}
	}
	if len(c.WiredSupplicants) > 128 {
		return fmt.Errorf("wired_supplicants exceeds limit 128")
	}
	seenSupplicants := make(map[string]bool, len(c.WiredSupplicants))
	for i := range c.WiredSupplicants {
		policy := &c.WiredSupplicants[i]
		field := fmt.Sprintf("wired_supplicants[%d]", i)
		if _, exists := interfaceIDs[policy.Interface]; !exists || interfaceBridge[policy.Interface] != "" {
			return fmt.Errorf("%s.interface %q must reference a managed non-bridge interface", field, policy.Interface)
		}
		if seenSupplicants[policy.Interface] {
			return fmt.Errorf("%s duplicates interface %q", field, policy.Interface)
		}
		seenSupplicants[policy.Interface] = true
		if seenPortAuth[policy.Interface] {
			return fmt.Errorf("%s.interface %q cannot be both a wired authenticator and supplicant", field, policy.Interface)
		}
		policy.EAPMethod = strings.ToUpper(policy.EAPMethod)
		if policy.EAPMethod != "PEAP" && policy.EAPMethod != "TTLS" && policy.EAPMethod != "TLS" {
			return fmt.Errorf("%s.eap_method must be PEAP, TTLS, or TLS", field)
		}
		if !eapIdentityPattern.MatchString(policy.Identity) || (policy.AnonymousIdentity != "" && !eapIdentityPattern.MatchString(policy.AnonymousIdentity)) {
			return fmt.Errorf("%s identity values must use letters, digits, dot, underscore, at-sign, colon, or dash", field)
		}
		if policy.CAFile == "" || !validSupplicantPath(policy.CAFile) {
			return fmt.Errorf("%s.ca_file must be an absolute certificate path", field)
		}
		if policy.EAPMethod == "TLS" {
			if policy.ClientCertFile == "" || policy.PrivateKeyFile == "" || !validSupplicantPath(policy.ClientCertFile) || !validSupplicantPath(policy.PrivateKeyFile) || policy.PasswordFile != "" || policy.Phase2 != "" {
				return fmt.Errorf("%s EAP-TLS requires absolute client_cert_file and private_key_file and forbids password_file", field)
			}
			if policy.PrivateKeyPasswordFile != "" && policy.PrivateKeyPasswordFile != path.Join("/etc/gamebond/8021x/supplicants", policy.Interface+".keypass") {
				return fmt.Errorf("%s.private_key_password_file must be the managed per-interface credential path", field)
			}
		} else {
			if policy.PasswordFile != path.Join("/etc/gamebond/8021x/supplicants", policy.Interface+".secret") {
				return fmt.Errorf("%s.password_file must be the managed per-interface credential path", field)
			}
			if policy.ClientCertFile != "" || policy.PrivateKeyFile != "" || policy.PrivateKeyPasswordFile != "" {
				return fmt.Errorf("%s certificate and private-key fields require EAP-TLS", field)
			}
			if policy.Phase2 == "" {
				policy.Phase2 = "auth=MSCHAPV2"
			}
			switch policy.Phase2 {
			case "auth=PAP", "auth=CHAP", "auth=MSCHAP", "auth=MSCHAPV2":
			default:
				return fmt.Errorf("%s.phase2 must be auth=PAP, auth=CHAP, auth=MSCHAP, or auth=MSCHAPV2", field)
			}
		}
	}

	networkIDs := make(map[string]struct{}, len(c.Networks))
	networkConfigs := make(map[string]Network, len(c.Networks))
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
		networkConfigs[network.ID] = network
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
		if network.IGMPSnooping != nil && !enabled(bridgeConfigs[network.Bridge].IGMPSnooping) {
			return fmt.Errorf("network %q per-VLAN IGMP snooping requires bridge-wide IGMP snooping", network.ID)
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
	if len(c.VXLANDevices) > 64 {
		return fmt.Errorf("vxlan_devices exceeds limit 64")
	}
	seenVXLANIDs, seenVXLANVNIs, seenVXLANInterfaces := map[string]bool{}, map[uint32]bool{}, map[string]bool{}
	for i, device := range c.VXLANDevices {
		field := fmt.Sprintf("vxlan_devices[%d]", i)
		if !stableIDPattern.MatchString(device.ID) || seenVXLANIDs[device.ID] {
			return fmt.Errorf("%s.id must be a unique lowercase stable ID", field)
		}
		seenVXLANIDs[device.ID] = true
		if device.VNI == 0 || device.VNI > 16777215 || seenVXLANVNIs[device.VNI] {
			return fmt.Errorf("%s.vni must be a unique value in 1..16777215", field)
		}
		seenVXLANVNIs[device.VNI] = true
		if device.UDPPort == 0 {
			device.UDPPort = 4789
		}
		if !stableIDPattern.MatchString(device.TapInterface) || !stableIDPattern.MatchString(device.VxlanInterface) || device.TapInterface == device.VxlanInterface {
			return fmt.Errorf("%s.tap_interface and vxlan_interface must be distinct interface IDs", field)
		}
		if !stableIDPattern.MatchString(device.UnderlayInterface) {
			return fmt.Errorf("%s.underlay_interface must reference a managed underlay interface", field)
		}
		if seenVXLANInterfaces[device.TapInterface] || seenVXLANInterfaces[device.VxlanInterface] {
			return fmt.Errorf("%s reuses an interface owned by another VXLAN device", field)
		}
		seenVXLANInterfaces[device.TapInterface], seenVXLANInterfaces[device.VxlanInterface] = true, true
		if _, isBond := bondInterfaces[device.TapInterface]; isBond || bondMembers[device.TapInterface] {
			return fmt.Errorf("%s.tap_interface cannot be a bond or bond member", field)
		}
		if _, isBond := bondInterfaces[device.VxlanInterface]; isBond || bondMembers[device.VxlanInterface] {
			return fmt.Errorf("%s.vxlan_interface cannot be a bond or bond member", field)
		}
		tap, tapOK := findInterface(c.Interfaces, device.TapInterface)
		vxlan, vxlanOK := findInterface(c.Interfaces, device.VxlanInterface)
		underlay, underlayOK := findInterface(c.Interfaces, device.UnderlayInterface)
		if !tapOK || !vxlanOK || !underlayOK {
			return fmt.Errorf("%s references unknown TAP, VXLAN, or underlay interface", field)
		}
		localAddress, err := netip.ParseAddr(device.LocalAddress)
		if err != nil || localAddress.Is4In6() || localAddress.IsUnspecified() || localAddress.IsMulticast() || localAddress.IsLinkLocalUnicast() || localAddress.String() != device.LocalAddress {
			return fmt.Errorf("%s.local_address must be a canonical unicast underlay address", field)
		}
		network, networkOK := networkConfigs[device.Network]
		if !networkOK {
			return fmt.Errorf("%s references unknown network %q", field, device.Network)
		}
		if !portCarriesNetwork(interfacePorts[device.TapInterface], device.Network) || !portCarriesNetwork(interfacePorts[device.VxlanInterface], device.Network) {
			return fmt.Errorf("%s TAP and VXLAN interfaces must be bridge ports carrying network %q", field, device.Network)
		}
		if interfaceBridge[device.TapInterface] != network.Bridge || interfaceBridge[device.VxlanInterface] != network.Bridge {
			return fmt.Errorf("%s TAP and VXLAN interfaces must be attached to network %q's bridge", field, device.Network)
		}
		if _, attached := interfaceBridge[device.UnderlayInterface]; attached || seenVXLANInterfaces[device.UnderlayInterface] {
			return fmt.Errorf("%s.underlay_interface cannot be a bridge port or another VXLAN attachment interface", field)
		}
		if tap.Name == vxlan.Name || tap.Name == underlay.Name || vxlan.Name == underlay.Name {
			return fmt.Errorf("%s TAP, VXLAN, and underlay interface names must be distinct", field)
		}
	}
	if len(c.AVProfiles) > 64 {
		return fmt.Errorf("pro_av_profiles exceeds limit 64")
	}
	profileSettings := map[string]map[string]string{}
	selectedProfiles := map[string]bool{}
	for i, selection := range c.AVProfiles {
		field := fmt.Sprintf("pro_av_profiles[%d]", i)
		if !stableIDPattern.MatchString(selection.Network) {
			return fmt.Errorf("%s.network must be a lowercase stable network ID", field)
		}
		if _, exists := networkIDs[selection.Network]; !exists {
			return fmt.Errorf("%s references unknown network %q", field, selection.Network)
		}
		profile, ok := avprofiles.Lookup(selection.Profile)
		if !ok {
			return fmt.Errorf("%s.profile %q is not a supported Pro AV profile", field, selection.Profile)
		}
		selectionKey := selection.Network + "/" + selection.Profile
		if selectedProfiles[selectionKey] {
			return fmt.Errorf("%s duplicates profile %q on network %q", field, selection.Profile, selection.Network)
		}
		selectedProfiles[selectionKey] = true
		network := networkConfigs[selection.Network]
		bridge := bridgeConfigs[network.Bridge]
		if profileSettings[selection.Network] == nil {
			profileSettings[selection.Network] = map[string]string{}
		}
		profileRequiresSnooping := false
		profileRequiresQuerier := false
		for _, setting := range profile.Settings {
			if setting.Key == "igmp.snooping" && setting.Value == "enabled" {
				profileRequiresSnooping = true
			}
			if setting.Key == "igmp.querier" && setting.Value == "one-per-vlan" {
				profileRequiresQuerier = true
			}
			if setting.Key == "jumbo-frames" && setting.Value == "disabled" && network.MTU > 1500 {
				return fmt.Errorf("%s profile %q requires MTU 1500 or less on network %q", field, profile.ID, network.ID)
			}
			key, value := normalizeAVProfileSetting(setting)
			requirements := expandAVProfileSetting(key, value)
			for _, requirement := range requirements {
				if existing, found := profileSettings[selection.Network][requirement.key]; found && !avProfileValuesCompatible(requirement.key, existing, requirement.value) {
					if strings.HasPrefix(requirement.key, "qos.queue.dscp.") {
						dscp := strings.TrimPrefix(requirement.key, "qos.queue.dscp.")
						return fmt.Errorf("%s conflicts on network %q: profile %q requires DSCP %s queue rank %s but another selected profile requires rank %s", field, selection.Network, profile.ID, dscp, requirement.value, existing)
					}
					return fmt.Errorf("%s conflicts on network %q: profile %q requires %s=%q but another selected profile requires %q", field, selection.Network, profile.ID, requirement.key, requirement.value, existing)
				}
				if existing, found := profileSettings[selection.Network][requirement.key]; !found || existing == "v2-or-v3" {
					profileSettings[selection.Network][requirement.key] = requirement.value
				}
			}
		}
		snoopingEnabled := enabled(bridge.IGMPSnooping)
		if network.IGMPSnooping != nil {
			snoopingEnabled = enabled(network.IGMPSnooping)
		}
		if profileRequiresSnooping && !snoopingEnabled {
			return fmt.Errorf("%s profile %q requires IGMP snooping on network %q", field, profile.ID, network.ID)
		}
		if profileRequiresQuerier && snoopingEnabled && !enabled(bridge.IGMPQuerier) {
			return fmt.Errorf("%s profile %q requires an IGMP querier on bridge %q", field, profile.ID, bridge.ID)
		}
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
			if port.VoiceNetwork != "" {
				if port.VoiceNetwork == port.UntaggedNetwork {
					return fmt.Errorf("bridge %q port %q voice_network must be tagged separately from its untagged access network", br.ID, port.Interface)
				}
				if !containsString(port.TaggedNetworks, port.VoiceNetwork) {
					return fmt.Errorf("bridge %q port %q voice_network %q must be in tagged_networks", br.ID, port.Interface, port.VoiceNetwork)
				}
			}
			applications := map[string]bool{}
			for i, policy := range port.LLDPMED {
				field := fmt.Sprintf("bridge %q port %q lldp_med[%d]", br.ID, port.Interface, i)
				if !validLLDPMEDApplication(policy.Application) || applications[policy.Application] {
					return fmt.Errorf("%s.application is invalid or duplicated", field)
				}
				applications[policy.Application] = true
				if policy.Network != "" {
					if _, exists := seenNetworks[policy.Network]; !exists {
						return fmt.Errorf("%s.network must be a VLAN assigned to this port", field)
					}
					if policy.Tagged && policy.Network == port.UntaggedNetwork {
						return fmt.Errorf("%s tagged network cannot be the untagged access network", field)
					}
					if !policy.Tagged && policy.Network != port.UntaggedNetwork {
						return fmt.Errorf("%s untagged network must match untagged_network", field)
					}
				}
				if policy.Priority != nil && *policy.Priority > 7 {
					return fmt.Errorf("%s.priority must be 0..7", field)
				}
				if policy.DSCP != nil && *policy.DSCP > 63 {
					return fmt.Errorf("%s.dscp must be 0..63", field)
				}
			}
			if port.VoiceNetwork != "" && applications["voice"] {
				return fmt.Errorf("bridge %q port %q must not duplicate the automatic voice policy from voice_network", br.ID, port.Interface)
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
	if len(c.NetworkACL) > MaxIPACLRules {
		return fmt.Errorf("inter_network_acls exceed limit %d", MaxIPACLRules)
	}
	routedInterfaces := map[string]string{}
	for i, network := range c.Networks {
		if network.RouteInterface == "" {
			continue
		}
		if !ifNamePattern.MatchString(network.RouteInterface) || network.RouteInterface == "." || network.RouteInterface == ".." {
			return fmt.Errorf("networks[%d].route_interface is invalid", i)
		}
		if prior, exists := routedInterfaces[network.RouteInterface]; exists {
			return fmt.Errorf("routed interface %q must be unique to one network (used by %q and %q)", network.RouteInterface, prior, network.ID)
		}
		routedInterfaces[network.RouteInterface] = network.ID
	}
	if len(c.NetworkACL) > 0 {
		for i, network := range c.Networks {
			if network.RouteInterface == "" {
				return fmt.Errorf("networks[%d].route_interface is required when inter-network ACLs are configured", i)
			}
		}
	}
	seenNetworkACLIDs, seenNetworkACLMatches := map[string]bool{}, map[string]bool{}
	for i, rule := range c.NetworkACL {
		if !stableIDPattern.MatchString(rule.ID) || seenNetworkACLIDs[rule.ID] {
			return fmt.Errorf("inter_network_acls[%d].id is invalid or duplicated", i)
		}
		seenNetworkACLIDs[rule.ID] = true
		source, sourceOK := networkConfigs[rule.SourceNetwork]
		destination, destinationOK := networkConfigs[rule.DestinationNetwork]
		if !sourceOK || !destinationOK {
			return fmt.Errorf("inter-network ACL %q references an unknown network", rule.ID)
		}
		if rule.SourceNetwork == rule.DestinationNetwork || source.RouteInterface == destination.RouteInterface {
			return fmt.Errorf("inter-network ACL %q must reference two distinct routed networks", rule.ID)
		}
		if rule.Protocol != "" && rule.Protocol != "tcp" && rule.Protocol != "udp" && rule.Protocol != "icmp" && rule.Protocol != "icmpv6" {
			return fmt.Errorf("inter-network ACL %q has unsupported protocol", rule.ID)
		}
		if rule.Port != 0 && rule.Protocol != "tcp" && rule.Protocol != "udp" {
			return fmt.Errorf("inter-network ACL %q port requires tcp or udp", rule.ID)
		}
		match := strings.Join([]string{rule.SourceNetwork, rule.DestinationNetwork, rule.Protocol, fmt.Sprint(rule.Port)}, "/")
		if seenNetworkACLMatches[match] {
			return fmt.Errorf("inter-network ACL contains ambiguous duplicate match %q", match)
		}
		seenNetworkACLMatches[match] = true
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
	if len(c.StormControl) > 64 {
		return fmt.Errorf("storm control policies exceed limit 64")
	}
	seenStormControl := map[string]bool{}
	stormClasses := map[string]map[string]bool{}
	for i, policy := range c.StormControl {
		if _, ok := interfaceIDs[policy.Interface]; !ok {
			return fmt.Errorf("storm_control[%d] references unknown interface %q", i, policy.Interface)
		}
		if policy.BroadcastRateBPS == 0 && policy.MulticastRateBPS == 0 {
			return fmt.Errorf("storm_control[%d] must set a broadcast or multicast rate", i)
		}
		if policy.MulticastRateBPS > 0 && snoopingPorts[policy.Interface] {
			return fmt.Errorf("storm_control[%d] multicast policing cannot share an interface with IGMP snooping because control traffic would be rate-limited", i)
		}
		for _, rate := range []uint64{policy.BroadcastRateBPS, policy.MulticastRateBPS} {
			if rate != 0 && (rate < 8000 || rate > 4_294_967_295) {
				return fmt.Errorf("storm_control[%d].rate_bps must be 8000..4294967295", i)
			}
		}
		if policy.BurstBytes < 1024 || policy.BurstBytes > 16*1024*1024 {
			return fmt.Errorf("storm_control[%d].burst_bytes must be 1024..16777216", i)
		}
		if seenStormControl[policy.Interface] {
			return fmt.Errorf("storm control policy for interface %q is duplicated", policy.Interface)
		}
		seenStormControl[policy.Interface] = true
		stormClasses[policy.Interface] = map[string]bool{"broadcast": policy.BroadcastRateBPS > 0, "multicast": policy.MulticastRateBPS > 0}
	}
	if len(c.MulticastBroadcastLimits) > 64 {
		return fmt.Errorf("multicast_broadcast_rate_limits exceed limit 64")
	}
	seenMulticastBroadcast := map[string]bool{}
	for i, policy := range c.MulticastBroadcastLimits {
		field := fmt.Sprintf("multicast_broadcast_rate_limits[%d]", i)
		if _, ok := interfaceIDs[policy.Interface]; !ok {
			return fmt.Errorf("%s references unknown interface %q", field, policy.Interface)
		}
		if policy.BroadcastRateBPS == 0 && policy.MulticastRateBPS == 0 {
			return fmt.Errorf("%s must set a broadcast or multicast rate", field)
		}
		if policy.MulticastRateBPS > 0 && snoopingPorts[policy.Interface] {
			return fmt.Errorf("%s multicast policing cannot share an interface with IGMP snooping because control traffic would be rate-limited", field)
		}
		for _, rate := range []uint64{policy.BroadcastRateBPS, policy.MulticastRateBPS} {
			if rate != 0 && (rate < 8000 || rate > 4_294_967_295) {
				return fmt.Errorf("%s rates must be 8000..4294967295", field)
			}
		}
		if policy.BurstBytes < 1024 || policy.BurstBytes > 16*1024*1024 {
			return fmt.Errorf("%s.burst_bytes must be 1024..16777216", field)
		}
		if seenMulticastBroadcast[policy.Interface] {
			return fmt.Errorf("multicast/broadcast rate-limit policy for interface %q is duplicated", policy.Interface)
		}
		seenMulticastBroadcast[policy.Interface] = true
		if classes := stormClasses[policy.Interface]; (policy.BroadcastRateBPS > 0 && classes["broadcast"]) || (policy.MulticastRateBPS > 0 && classes["multicast"]) {
			return fmt.Errorf("%s overlaps a storm-control class on interface %q", field, policy.Interface)
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
	if len(c.QoS) > 64 {
		return fmt.Errorf("QoS policies exceed limit 64")
	}
	seenQoSInterfaces := map[string]bool{}
	for i, policy := range c.QoS {
		if _, ok := interfaceIDs[policy.Interface]; !ok {
			return fmt.Errorf("qos[%d] references unknown interface %q", i, policy.Interface)
		}
		if seenQoSInterfaces[policy.Interface] {
			return fmt.Errorf("QoS policy for interface %q is duplicated", policy.Interface)
		}
		seenQoSInterfaces[policy.Interface] = true
		if policy.LinkRateBPS < 8_000_000 || policy.LinkRateBPS > 100_000_000_000 {
			return fmt.Errorf("qos[%d].link_rate_bps must be 8000000..100000000000", i)
		}
		if policy.LinkRateBPS%1000 != 0 {
			return fmt.Errorf("qos[%d].link_rate_bps must use whole kilobits per second for the shared QoS provider", i)
		}
		if len(policy.Classes) == 0 || len(policy.Classes) > 8 {
			return fmt.Errorf("QoS policy for %q must contain 1..8 classes", policy.Interface)
		}
		classIDs, dscps := map[uint8]bool{}, map[uint8]bool{}
		var reserved uint64
		for j, class := range policy.Classes {
			if class.ID < 10 || class.ID > 99 || classIDs[class.ID] {
				return fmt.Errorf("qos[%d].classes[%d].id must be unique and between 10 and 99", i, j)
			}
			classIDs[class.ID] = true
			if len(class.DSCP) == 0 {
				return fmt.Errorf("QoS class %d must match at least one DSCP value", class.ID)
			}
			if class.RateBPS < 1000 || class.RateBPS > policy.LinkRateBPS {
				return fmt.Errorf("QoS class %d rate is outside the link rate", class.ID)
			}
			if class.RateBPS%1000 != 0 {
				return fmt.Errorf("QoS class %d rate must use whole kilobits per second for the shared QoS provider", class.ID)
			}
			if class.CeilingBPS < class.RateBPS || class.CeilingBPS > policy.LinkRateBPS {
				return fmt.Errorf("QoS class %d ceiling must be at least its rate and no more than the link rate", class.ID)
			}
			if class.CeilingBPS%1000 != 0 {
				return fmt.Errorf("QoS class %d ceiling must use whole kilobits per second for the shared QoS provider", class.ID)
			}
			if class.Priority > 7 {
				return fmt.Errorf("QoS class %d priority must be 0..7", class.ID)
			}
			reserved += class.RateBPS
			for _, dscp := range class.DSCP {
				if dscp > 63 {
					return fmt.Errorf("QoS class %d DSCP must be 0..63", class.ID)
				}
				if dscps[dscp] {
					return fmt.Errorf("DSCP %d is assigned more than once", dscp)
				}
				dscps[dscp] = true
			}
		}
		if reserved+1000 > policy.LinkRateBPS {
			return fmt.Errorf("QoS class guaranteed rates exceed link rate")
		}
		for _, rate := range c.EgressRates {
			if rate.Interface == policy.Interface && rate.Network == "" {
				return fmt.Errorf("QoS and whole-port egress rate limit cannot own the same root qdisc on %q", policy.Interface)
			}
		}
	}
	if len(c.PortMirrors) > 64 {
		return fmt.Errorf("port mirrors exceed limit 64")
	}
	seenMirrorSources := map[string]bool{}
	monitorDestination, monitorRate, monitorBurst := "", uint64(0), uint32(0)
	monitorCaptureConfigured := false
	for i, mirror := range c.PortMirrors {
		if _, ok := interfaceIDs[mirror.Source]; !ok {
			return fmt.Errorf("port_mirrors[%d].source references unknown interface %q", i, mirror.Source)
		}
		if _, ok := interfaceIDs[mirror.Destination]; !ok {
			return fmt.Errorf("port_mirrors[%d].destination references unknown interface %q", i, mirror.Destination)
		}
		if mirror.Source == mirror.Destination {
			return fmt.Errorf("port_mirrors[%d] source and destination must differ", i)
		}
		if mirror.Direction != "ingress" && mirror.Direction != "egress" && mirror.Direction != "both" {
			return fmt.Errorf("port_mirrors[%d].direction must be ingress, egress, or both", i)
		}
		if mirror.Network != "" {
			if _, exists := networkConfigs[mirror.Network]; !exists {
				return fmt.Errorf("port_mirrors[%d].network references unknown network %q", i, mirror.Network)
			}
			port, exists := interfacePorts[mirror.Source]
			if !exists {
				return fmt.Errorf("port_mirrors[%d] VLAN scope requires a bridge-port source", i)
			}
			if port.UntaggedNetwork == mirror.Network || !containsString(port.TaggedNetworks, mirror.Network) {
				return fmt.Errorf("port_mirrors[%d].network must be a tagged member of source port %q", i, mirror.Source)
			}
		}
		if bondMembers[mirror.Source] || bondInterfaces[mirror.Source] {
			return fmt.Errorf("port mirror source %q cannot be an aggregate member or bond", mirror.Source)
		}
		if bondMembers[mirror.Destination] || bondInterfaces[mirror.Destination] || interfaceBridge[mirror.Destination] != "" {
			return fmt.Errorf("port mirror destination %q must be a dedicated standalone interface", mirror.Destination)
		}
		if monitorDestination != "" && monitorDestination != mirror.Destination {
			return fmt.Errorf("port mirrors must use one monitor destination")
		}
		monitorDestination = mirror.Destination
		if mirror.CaptureRateBPS == 0 && mirror.CaptureBurstBytes != 0 {
			return fmt.Errorf("port_mirrors[%d].capture_burst_bytes requires capture_rate_bps", i)
		}
		if mirror.CaptureRateBPS != 0 {
			if mirror.CaptureRateBPS < 1000 || mirror.CaptureRateBPS > 100_000_000_000 {
				return fmt.Errorf("port_mirrors[%d].capture_rate_bps must be 1000..100000000000", i)
			}
			if mirror.CaptureBurstBytes < 1500 || mirror.CaptureBurstBytes > 1<<20 {
				return fmt.Errorf("port_mirrors[%d].capture_burst_bytes must be 1500..1048576", i)
			}
		}
		if monitorCaptureConfigured && (monitorRate != mirror.CaptureRateBPS || monitorBurst != mirror.CaptureBurstBytes) {
			return fmt.Errorf("all port mirrors sharing a monitor must use one capture rate and burst")
		}
		monitorRate, monitorBurst, monitorCaptureConfigured = mirror.CaptureRateBPS, mirror.CaptureBurstBytes, true
		directions := []string{mirror.Direction}
		if mirror.Direction == "both" {
			directions = []string{"ingress", "egress"}
		}
		for _, direction := range directions {
			key := mirror.Source + "/" + direction
			if seenMirrorSources[key] {
				return fmt.Errorf("port mirror source direction is configured more than once: %s", key)
			}
			seenMirrorSources[key] = true
		}
	}
	if monitorRate > 0 {
		for _, limit := range c.EgressRates {
			if limit.Interface == monitorDestination {
				return fmt.Errorf("capture rate and port egress rate limit cannot share the monitor qdisc")
			}
		}
		for _, policy := range c.QoS {
			if policy.Interface == monitorDestination {
				return fmt.Errorf("capture rate and QoS cannot share the monitor qdisc")
			}
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

func avProfileValuesCompatible(key, first, second string) bool {
	if first == second {
		return true
	}
	if key == "igmp.version" {
		return first == "v2-or-v3" && (second == "v2" || second == "v3") || second == "v2-or-v3" && (first == "v2" || first == "v3")
	}
	if key == "igmp.snooping" {
		return strings.HasPrefix(first, "enabled") && strings.HasPrefix(second, "enabled") || strings.HasPrefix(first, "required-") && second == "enabled" || strings.HasPrefix(second, "required-") && first == "enabled"
	}
	if key == "qos.classification" {
		return first == "diffserv-dscp" && second == "trust-dscp" || second == "diffserv-dscp" && first == "trust-dscp"
	}
	return false
}

func normalizeAVProfileSetting(setting avprofiles.Setting) (string, string) {
	switch setting.Key {
	case "multicast.unregistered-filtering":
		if setting.Value == "disabled" {
			return "multicast.unregistered-flooding", "enabled"
		}
		if setting.Value == "enabled" {
			return "multicast.unregistered-flooding", "disabled"
		}
	}
	return setting.Key, setting.Value
}

type avProfileRequirement struct{ key, value string }

func expandAVProfileSetting(key, value string) []avProfileRequirement {
	if key == "qos.queue.order" {
		parts := strings.Split(value, ">")
		requirements := make([]avProfileRequirement, 0, len(parts))
		for rank, part := range parts {
			dscp, err := strconv.ParseUint(strings.TrimSpace(part), 10, 8)
			if err != nil || dscp == 0 || dscp > 63 {
				return []avProfileRequirement{{key: key, value: value}}
			}
			requirements = append(requirements, avProfileRequirement{key: fmt.Sprintf("qos.queue.dscp.%d", dscp), value: strconv.Itoa(rank)})
		}
		return requirements
	}
	if strings.HasPrefix(key, "qos.queue.") {
		var dscpText, rank string
		switch {
		case strings.HasPrefix(key, "qos.queue.dscp"):
			dscpText, rank = strings.TrimPrefix(key, "qos.queue.dscp"), value
		default:
			dscpText, rank, _ = strings.Cut(value, ":")
		}
		if dscp, err := strconv.ParseUint(dscpText, 10, 8); err == nil && dscp > 0 && dscp <= 63 {
			if normalized, ok := normalizeAVQueueRank(rank); ok {
				return []avProfileRequirement{{key: fmt.Sprintf("qos.queue.dscp.%d", dscp), value: strconv.Itoa(normalized)}}
			}
		}
	}
	return []avProfileRequirement{{key: key, value: value}}
}

func normalizeAVQueueRank(rank string) (int, bool) {
	switch rank {
	case "highest", "strict-highest":
		return 0, true
	case "second-highest", "strict-second-highest":
		return 1, true
	case "third-highest", "strict-third-highest":
		return 2, true
	default:
		return 0, false
	}
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
