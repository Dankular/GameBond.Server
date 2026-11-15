package edge

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Dankular/GameBond.Core/bond"
	"github.com/Dankular/GameBond.Server/adminportal"
	"github.com/Dankular/GameBond.Server/l2gw"
	"github.com/Dankular/GameBond.Server/security"
)

type Config struct {
	Role            string                      `json:"role"`
	Session         string                      `json:"session"`
	Bind            [][]json.RawMessage         `json:"bind"`
	ClientIP        string                      `json:"client_tunnel_ip"`
	LanTunnelIPs    []string                    `json:"lan_tunnel_ips"`
	TunName         string                      `json:"tun_name"`
	MTU             int                         `json:"mtu"`
	Bonding         bool                        `json:"bonding_mode"`
	Redundant       bool                        `json:"redundant_mode"`
	DirectPriority  bool                        `json:"direct_priority"`
	BulkRate        float64                     `json:"bulk_rate_mbps"`
	InitialRate     float64                     `json:"bonding_initial_rate_mbps"`
	MaximumRate     float64                     `json:"bonding_max_rate_mbps"`
	ReorderMS       float64                     `json:"reorder_timeout_ms"`
	GamePorts       []uint16                    `json:"game_udp_ports"`
	Queues          map[string]bond.QueuePolicy `json:"queues"`
	QoS             bond.QoSSettings            `json:"adaptive_qos"`
	Admin           json.RawMessage             `json:"admin"`
	Security        json.RawMessage             `json:"security"`
	LossTracking    bool                        `json:"loss_tracking"`
	DelayControl    bool                        `json:"delay_control"`
	DelayAssertive  bool                        `json:"delay_assertive"`
	LabMode         bool                        `json:"lab_mode"`
	PriorityHostMax int                         `json:"priority_host_max_packet"`
	PathMTU         bool                        `json:"path_mtu_discovery"`
	Failover        bool                        `json:"failover_replay"`
	FlowPinning     bool                        `json:"flow_pinning"`
	StripeAbove     float64                     `json:"stripe_above_mbps"`
	CoDel           bool                        `json:"codel"`
	Protection      string                      `json:"protection"` // ignored: every packet is always duplicated
	ParityRowsMin   int                         `json:"parity_rows_min"`
	ParityRowsMax   int                         `json:"parity_rows_max"`
	L2              *L2Config                   `json:"l2"`
}

// L2Config turns on Ethernet carriage: a TAP port beside the TUN. Frames cross the bond like IP
// packets and pass the transport's switch core (MAC learning and cap, loop guard, storm control).
// The TAP is meant to be joined to a bridge by the host or container entrypoint.
type L2Config struct {
	Enabled                bool                     `json:"enabled"`
	SegmentID              string                   `json:"segment_id,omitempty"`
	SegmentSocketPath      string                   `json:"segment_socket_path,omitempty"`
	SegmentTokenFile       string                   `json:"segment_token_file,omitempty"`
	SegmentMembersFile     string                   `json:"segment_members_file,omitempty"`
	SegmentAdminTokenFile  string                   `json:"segment_admin_token_file,omitempty"`
	TapName                string                   `json:"tap_name"`
	FrameMTU               int                      `json:"frame_mtu"`
	MACLimit               int                      `json:"mac_limit"`
	BroadcastPPS           float64                  `json:"broadcast_pps"`
	MulticastPPS           float64                  `json:"multicast_pps"`
	UnknownUnicastPPS      float64                  `json:"unknown_unicast_pps"`
	ControlPlanePPS        float64                  `json:"control_plane_pps,omitempty"`
	ControlPlaneRates      bond.L2ControlPlaneRates `json:"control_plane_rates,omitempty"`
	TunnelVLAN             bond.L2VLANPolicy        `json:"tunnel_vlan,omitempty"`
	ExitVLAN               bond.L2VLANPolicy        `json:"exit_vlan,omitempty"`
	TunnelPrivateVLAN      *L2PrivateVLANPortConfig `json:"tunnel_private_vlan,omitempty"`
	ExitPrivateVLAN        *L2PrivateVLANPortConfig `json:"exit_private_vlan,omitempty"`
	Monitor                *L2MonitorConfig         `json:"monitor,omitempty"`
	BPDUGuardTunnel        bool                     `json:"bpdu_guard_tunnel,omitempty"`
	BPDUGuardExit          bool                     `json:"bpdu_guard_exit,omitempty"`
	RAGuardTunnel          bool                     `json:"ra_guard_tunnel,omitempty"`
	RAGuardExit            bool                     `json:"ra_guard_exit,omitempty"`
	IPv4SourceGuardTunnel  bool                     `json:"-"` // broker authorization only
	IPv6SourceGuardTunnel  bool                     `json:"-"` // broker authorization only
	MulticastRouterTunnel  bool                     `json:"multicast_router_tunnel,omitempty"`
	MVR                    *bond.L2MVRConfig        `json:"mvr,omitempty"`
	RSTP                   *L2RSTPConfig            `json:"rstp,omitempty"`
	KernelVXLANAttachments []KernelVXLANAttachment  `json:"kernel_vxlan_attachments,omitempty"`
	// VXLAN enables a static-peer RFC 7348 overlay owned by the segment broker.
	// Its underlay must be protected by WireGuard/IPsec or an equivalent trusted network.
	VXLAN *VXLANConfig `json:"vxlan,omitempty"`
	// Bridge makes the container the gateway of the carried segment: the entrypoint joins the TAP
	// to a bridge with this address, serves DHCP on it and NATs it to the internet. Without it
	// the TAP is left for the host to wire.
	Bridge       *L2Bridge `json:"bridge"`
	frameTagRoom int
}

// L2PrivateVLANPortConfig assigns one local switch port to a PVLAN primary or
// secondary VLAN. Shared segment session roles remain broker authorization data.
type L2PrivateVLANPortConfig struct {
	GroupID       uint16 `json:"group_id"`
	Role          string `json:"role"`
	CommunityID   uint16 `json:"community_id,omitempty"`
	PrimaryVLAN   uint16 `json:"primary_vlan"`
	SecondaryVLAN uint16 `json:"secondary_vlan,omitempty"`
}

func (p *L2PrivateVLANPortConfig) apply(port *bond.L2PortConfig) error {
	if p == nil {
		return nil
	}
	if p.GroupID == 0 || p.GroupID > 4094 || p.PrimaryVLAN == 0 || p.PrimaryVLAN > 4094 {
		return fmt.Errorf("private VLAN group_id and primary_vlan must be in 1..4094")
	}
	var role bond.L2PrivateVLANRole
	switch p.Role {
	case "promiscuous":
		role = bond.L2PVLANPromiscuous
		if p.SecondaryVLAN != 0 || p.CommunityID != 0 {
			return fmt.Errorf("promiscuous PVLAN port cannot set secondary_vlan or community_id")
		}
	case "isolated":
		role = bond.L2PVLANIsolated
		if p.SecondaryVLAN == 0 || p.SecondaryVLAN > 4094 || p.SecondaryVLAN == p.PrimaryVLAN || p.CommunityID != 0 {
			return fmt.Errorf("isolated PVLAN port needs a distinct secondary_vlan and cannot set community_id")
		}
	case "community":
		role = bond.L2PVLANCommunity
		if p.SecondaryVLAN == 0 || p.SecondaryVLAN > 4094 || p.SecondaryVLAN == p.PrimaryVLAN || p.CommunityID == 0 || p.CommunityID > 4094 {
			return fmt.Errorf("community PVLAN port needs a distinct secondary_vlan and community_id in 1..4094")
		}
	default:
		return fmt.Errorf("private VLAN role must be promiscuous, isolated, or community")
	}
	port.PrivateVLAN = p.GroupID
	port.PrivateVLANRole = role
	port.PVLANCommunity = p.CommunityID
	port.PVLANPrimaryVLAN = p.PrimaryVLAN
	port.PVLANSecondaryVLAN = p.SecondaryVLAN
	return nil
}

// L2RSTPConfig enables one IEEE 802.1w spanning tree on this userspace switch.
// MSTP is not part of the gVisor edge implementation.
type L2RSTPConfig struct {
	BridgePriority      *uint16 `json:"bridge_priority,omitempty"`
	BridgeMAC           string  `json:"bridge_mac,omitempty"`
	HelloTimeSeconds    uint8   `json:"hello_time_seconds,omitempty"`
	MaxAgeSeconds       uint8   `json:"max_age_seconds,omitempty"`
	ForwardDelaySeconds uint8   `json:"forward_delay_seconds,omitempty"`
}

func (c *L2RSTPConfig) validate() error {
	if c == nil {
		return nil
	}
	if c.BridgePriority != nil && (*c.BridgePriority > 61440 || *c.BridgePriority%4096 != 0) {
		return fmt.Errorf("l2.rstp.bridge_priority must be a multiple of 4096 in 0..61440")
	}
	if c.BridgeMAC != "" {
		mac, err := net.ParseMAC(c.BridgeMAC)
		if err != nil || len(mac) != 6 || mac.String() != strings.ToLower(c.BridgeMAC) || mac[0]&1 != 0 || mac.String() == "00:00:00:00:00:00" {
			return fmt.Errorf("l2.rstp.bridge_mac must be a canonical unicast Ethernet address")
		}
	}
	hello, maxAge, forward := int(c.HelloTimeSeconds), int(c.MaxAgeSeconds), int(c.ForwardDelaySeconds)
	if hello == 0 {
		hello = 2
	}
	if maxAge == 0 {
		maxAge = 20
	}
	if forward == 0 {
		forward = 15
	}
	if hello < 1 || hello > 10 || maxAge < 6 || maxAge > 40 || forward < 4 || forward > 30 || 2*(hello+1) > maxAge || maxAge > 2*(forward-1) {
		return fmt.Errorf("l2.rstp timers must satisfy hello 1..10s, max age 6..40s, forward delay 4..30s, and 2*(hello+1) <= max age <= 2*(forward-1)")
	}
	return nil
}

// RSTPSwitchConfig converts validated edge settings into the Core switch's
// single-instance RSTP configuration.
func RSTPSwitchConfig(c *L2RSTPConfig) (bond.L2SwitchConfig, error) {
	if c == nil {
		return bond.L2SwitchConfig{}, nil
	}
	if err := c.validate(); err != nil {
		return bond.L2SwitchConfig{}, err
	}
	settings := bond.L2SwitchConfig{RSTPEnabled: true}
	if c.BridgePriority != nil {
		settings.BridgePriority = *c.BridgePriority
		settings.BridgePrioritySet = true
	}
	if c.BridgeMAC != "" {
		mac, _ := net.ParseMAC(c.BridgeMAC) // validate above guarantees a six-byte address.
		copy(settings.BridgeMAC[:], mac)
	}
	if c.HelloTimeSeconds != 0 {
		settings.RSTPHelloTime = time.Duration(c.HelloTimeSeconds) * time.Second
	}
	if c.MaxAgeSeconds != 0 {
		settings.RSTPMaxAge = time.Duration(c.MaxAgeSeconds) * time.Second
	}
	if c.ForwardDelaySeconds != 0 {
		settings.RSTPForwardDelay = time.Duration(c.ForwardDelaySeconds) * time.Second
	}
	return settings, nil
}

// KernelVXLANAttachment binds an existing persistent host TAP to a VLAN in the
// broker-owned SegmentFabric. gateway/layer2 creates that TAP beside the kernel
// VXLAN device on the Linux bridge; the edge broker owns only the frame pump.
type KernelVXLANAttachment struct {
	ID      string `json:"id"`
	TapName string `json:"tap_name"`
	VLAN    uint16 `json:"vlan"`
}

var kernelVXLANIfNameRE = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)

func (l *L2Config) validateKernelVXLANAttachments() error {
	if len(l.KernelVXLANAttachments) == 0 {
		return nil
	}
	if l.VXLAN != nil {
		return fmt.Errorf("l2.vxlan static peer overlay cannot be combined with kernel_vxlan_attachments")
	}
	if l.Bridge == nil || l.SegmentSocketPath == "" || l.SegmentID == "" {
		return fmt.Errorf("kernel VXLAN TAP attachments require a broker segment gateway")
	}
	primaryTap := l.TapName
	if primaryTap == "" {
		primaryTap = "gamebond-tap0"
	}
	seenID, seenTap := map[string]bool{}, map[string]bool{}
	for _, attachment := range l.KernelVXLANAttachments {
		if !segmentIDRE.MatchString(attachment.ID) || seenID[attachment.ID] {
			return fmt.Errorf("kernel VXLAN attachment IDs must be unique stable segment IDs")
		}
		if !kernelVXLANIfNameRE.MatchString(attachment.TapName) || seenTap[attachment.TapName] || attachment.TapName == primaryTap || l.Monitor != nil && attachment.TapName == l.Monitor.TapName {
			return fmt.Errorf("kernel VXLAN attachment %q TAP name is invalid or already used", attachment.ID)
		}
		if attachment.VLAN == 0 || attachment.VLAN > 4094 {
			return fmt.Errorf("kernel VXLAN attachment %q VLAN must be in range 1..4094", attachment.ID)
		}
		seenID[attachment.ID], seenTap[attachment.TapName] = true, true
		if len(l.Bridge.VLANs) > 0 {
			found := false
			for _, entry := range l.Bridge.VLANs {
				found = found || entry.VLANID == attachment.VLAN
			}
			if !found {
				return fmt.Errorf("kernel VXLAN attachment %q VLAN %d has no configured gateway VLAN", attachment.ID, attachment.VLAN)
			}
		} else if l.ExitVLAN.AccessVLAN != attachment.VLAN {
			return fmt.Errorf("kernel VXLAN attachment %q VLAN must match the configured gateway access VLAN", attachment.ID)
		}
	}
	return nil
}

// L2SegmentMember is one broker-authorized session attachment. TokenHex is a
// unique per-session secret; VLAN and port limits are enforced by the broker.
type L2SegmentMember struct {
	Identity             string                   `json:"identity"`
	TokenHex             string                   `json:"token_hex"`
	VLAN                 bond.L2VLANPolicy        `json:"vlan"`
	MACLimit             int                      `json:"mac_limit,omitempty"`
	BroadcastPPS         float64                  `json:"broadcast_pps,omitempty"`
	MulticastPPS         float64                  `json:"multicast_pps,omitempty"`
	UnknownUnicastPPS    float64                  `json:"unknown_unicast_pps,omitempty"`
	BPDUGuard            bool                     `json:"bpdu_guard,omitempty"`
	RAGuard              bool                     `json:"ra_guard,omitempty"`
	IPv4SourceGuard      bool                     `json:"ipv4_source_guard,omitempty"`
	IPv6SourceGuard      bool                     `json:"ipv6_source_guard,omitempty"`
	StaticSourceBindings []L2SegmentSourceBinding `json:"static_source_bindings,omitempty"`
	MulticastRouter      bool                     `json:"multicast_router,omitempty"`
	PrivateVLAN          uint16                   `json:"private_vlan,omitempty"`
	PrivateVLANRole      string                   `json:"private_vlan_role,omitempty"`
	PVLANCommunity       uint16                   `json:"private_vlan_community,omitempty"`
	PVLANPrimaryVLAN     uint16                   `json:"private_vlan_primary_vlan,omitempty"`
	PVLANSecondaryVLAN   uint16                   `json:"private_vlan_secondary_vlan,omitempty"`
	MACAuth              bool                     `json:"mac_auth,omitempty"`
	EAPOLTapName         string                   `json:"eapol_tap_name,omitempty"`
	RSTPParticipant      bool                     `json:"rstp_participant,omitempty"`
	RSTPEdge             bool                     `json:"rstp_edge,omitempty"`
	RSTPSharedLink       bool                     `json:"rstp_shared_link,omitempty"`
	RSTPPathCost         uint32                   `json:"rstp_path_cost,omitempty"`
	MirrorIngress        bool                     `json:"mirror_ingress,omitempty"`
	MirrorEgress         bool                     `json:"mirror_egress,omitempty"`
}

// L2SegmentSourceBinding authorizes one static IP/MAC pair on a broker member.
// Use VLAN for a single-tag port, or outer_vlan and inner_vlan for Q-in-Q.
// When VLAN fields are omitted, an access VLAN (or Q-in-Q customer access VLAN)
// is inferred from the member's VLAN policy.
type L2SegmentSourceBinding struct {
	IP        string `json:"ip"`
	MAC       string `json:"mac"`
	VLAN      uint16 `json:"vlan,omitempty"`
	OuterVLAN uint16 `json:"outer_vlan,omitempty"`
	InnerVLAN uint16 `json:"inner_vlan,omitempty"`
}

// L2MonitorConfig creates an output-only TAP that receives software copies of
// frames entering or leaving the selected logical port. It can be captured with
// standard host tools without joining the monitor TAP to the bridged segment.
type L2MonitorConfig struct {
	TapName       string `json:"tap_name"`
	TunnelIngress bool   `json:"tunnel_ingress,omitempty"`
	TunnelEgress  bool   `json:"tunnel_egress,omitempty"`
	ExitIngress   bool   `json:"exit_ingress,omitempty"`
	ExitEgress    bool   `json:"exit_egress,omitempty"`
}

// L2Bridge is the addressing of the bridged segment. Each exit has its own config, so give the
// exits disjoint DHCP ranges (and the same Address): devices then keep their gateway across a failover.
type L2Bridge struct {
	Address           string          `json:"address"`                       // gateway address with prefix, default 10.78.0.1/24
	IPv6Address       string          `json:"ipv6_address,omitempty"`        // optional IPv6 gateway address/prefix for statically configured clients
	PrivateVLAN       uint16          `json:"private_vlan,omitempty"`        // PVLAN group for which this gateway is the promiscuous primary-VLAN port
	DHCPStart         string          `json:"dhcp_start,omitempty"`          // first leased address
	DHCPEnd           string          `json:"dhcp_end,omitempty"`            // last leased address
	DHCPRelay4        string          `json:"dhcp_relay4,omitempty"`         // upstream DHCPv4 server as IPv4:port
	DHCPRelayGateway4 string          `json:"dhcp_relay_gateway4,omitempty"` // on-link router for an off-subnet relay server
	DHCPRelay6        string          `json:"dhcp_relay6,omitempty"`         // upstream DHCPv6 server as [IPv6]:port
	DHCPRelayLink6    string          `json:"dhcp_relay_link_address,omitempty"`
	DHCPv6PDPool      string          `json:"dhcpv6_pd_pool,omitempty"`
	DHCPv6PDBits      uint8           `json:"dhcpv6_pd_prefix_bits,omitempty"`
	EgressPaths       []l2gw.ECMPPath `json:"ecmp_paths,omitempty"`
	Lease             string          `json:"lease"`            // lease time such as 12h, default 12h
	DNS               []string        `json:"dns"`              // resolvers handed out, default 1.1.1.1 and 9.9.9.9
	DNS6              []string        `json:"dns6,omitempty"`   // IPv6 resolvers advertised by RA's RDNSS option
	Hosts             []L2Host        `json:"hosts"`            // fixed leases by MAC
	Hosts6            []L2Host6       `json:"hosts6,omitempty"` // fixed DHCPv6 IA_NA leases by client DUID and IAID
	// Policy is the live rule set: per-device limits applied to the next flow. It can be reloaded
	// (SIGHUP) without restarting the exit; hosts above are reloaded with it.
	Policy        *L2Policy        `json:"policy"`
	LLDPMEDPolicy *L2LLDPMEDPolicy `json:"lldp_med_policy,omitempty"`
	VLANs         []L2BridgeVLAN   `json:"vlans,omitempty"`
}

// L2Host6 pins a DHCPv6 IA_NA address to a client DUID and IAID. ClientIDHex
// contains the DHCPv6 Client Identifier option payload, without the option header.
type L2Host6 struct {
	ClientIDHex string `json:"client_id_hex"`
	IAID        uint32 `json:"iaid"`
	MAC         string `json:"mac"`
	IP          string `json:"ip"`
	Name        string `json:"name"`
}

// L2LLDPMEDPolicy advertises a network policy for one application on the
// gateway VLAN. VLANID must match the actual access VLAN carrying this gateway.
type L2LLDPMEDPolicy struct {
	ApplicationType uint8  `json:"application_type"`
	VLANID          uint16 `json:"vlan_id"`
	Tagged          bool   `json:"tagged,omitempty"`
	L2Priority      uint8  `json:"l2_priority,omitempty"`
	DSCP            uint8  `json:"dscp,omitempty"`
}

// L2BridgeVLAN maps one tagged VLAN to an independent gateway, DHCP pool,
// static-binding set, and device policy.
type L2BridgeVLAN struct {
	VLANID        uint16           `json:"vlan_id"`
	Gateway       *L2Bridge        `json:"gateway"`
	MDNSRelayTo   []uint16         `json:"mdns_relay_to,omitempty"`
	LLDPMEDPolicy *L2LLDPMEDPolicy `json:"lldp_med_policy,omitempty"`
}

func (p *L2LLDPMEDPolicy) validate(where string) error {
	if p == nil {
		return nil
	}
	if p.VLANID == 0 || p.VLANID > 4094 || p.ApplicationType < 1 || p.ApplicationType > 8 || p.L2Priority > 7 || p.DSCP > 63 {
		return fmt.Errorf("%s must use vlan_id 1..4094, application_type 1..8, l2_priority 0..7, and dscp 0..63", where)
	}
	return nil
}

// L2Policy is the control-plane document for the gateway.
type L2Policy struct {
	Version int64            `json:"version"` // bumped by whoever pushes it; shown in the stats
	Default L2DeviceRule     `json:"default"`
	Devices []L2DevicePolicy `json:"devices"`
}

// L2DevicePolicy is the rule for one MAC.
type L2DevicePolicy struct {
	MAC  string `json:"mac"`
	Name string `json:"name"`
	L2DeviceRule
}

// L2DeviceRule limits what a device may open.
type L2DeviceRule struct {
	Deny         bool     `json:"deny"`
	AllowPrivate bool     `json:"allow_private"`
	BlockPorts   []int    `json:"block_ports"`
	BlockNets    []string `json:"block_nets"`
	MaxFlows     int      `json:"max_flows"`
}

func (r *L2DeviceRule) validate(where string) error {
	if r.MaxFlows < 0 || r.MaxFlows > 100000 {
		return fmt.Errorf("%s.max_flows must be 0 to 100000", where)
	}
	if len(r.BlockPorts) > 64 || len(r.BlockNets) > 64 {
		return fmt.Errorf("%s takes at most 64 block_ports and 64 block_nets", where)
	}
	for _, p := range r.BlockPorts {
		if p < 1 || p > 65535 {
			return fmt.Errorf("%s.block_ports has a bad port", where)
		}
	}
	for _, n := range r.BlockNets {
		if _, err := netip.ParsePrefix(n); err != nil {
			return fmt.Errorf("%s.block_nets %q is not a prefix", where, n)
		}
	}
	return nil
}

func (p *L2Policy) validate() error {
	if p.Version < 0 {
		return fmt.Errorf("l2.bridge.policy.version must not be negative")
	}
	if len(p.Devices) > 256 {
		return fmt.Errorf("l2.bridge.policy.devices takes at most 256 entries")
	}
	if err := p.Default.validate("l2.bridge.policy.default"); err != nil {
		return err
	}
	seen := map[string]bool{}
	for i := range p.Devices {
		d := &p.Devices[i]
		hw, err := net.ParseMAC(d.MAC)
		if err != nil || len(hw) != 6 || hw[0]&1 == 1 {
			return fmt.Errorf("l2.bridge.policy.devices[%d].mac is not a unicast MAC", i)
		}
		d.MAC = hw.String()
		if seen[d.MAC] {
			return fmt.Errorf("l2.bridge.policy.devices has two rules for %s", d.MAC)
		}
		seen[d.MAC] = true
		if !hostNameRE.MatchString(d.Name) {
			return fmt.Errorf("l2.bridge.policy.devices[%d].name must be letters, digits and dashes", i)
		}
		if err := d.L2DeviceRule.validate(fmt.Sprintf("l2.bridge.policy.devices[%d]", i)); err != nil {
			return err
		}
	}
	return nil
}

// L2Host pins an address to a MAC.
type L2Host struct {
	MAC  string `json:"mac"`
	IP   string `json:"ip"`
	Name string `json:"name"`
}

var (
	leaseRE     = regexp.MustCompile(`^[0-9]{1,4}[smh]$`)
	hostNameRE  = regexp.MustCompile(`^[A-Za-z0-9-]{0,32}$`)
	segmentIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)
)

func (b *L2Bridge) validate() error {
	if err := l2gw.ValidateECMPPaths(b.EgressPaths); err != nil {
		return fmt.Errorf("l2.bridge.ecmp_paths: %w", err)
	}
	if len(b.VLANs) > 0 {
		if len(b.EgressPaths) > 0 {
			return fmt.Errorf("l2.bridge.ecmp_paths must be configured on each l2.bridge.vlans gateway entry")
		}
		if b.Address != "" || b.IPv6Address != "" || b.PrivateVLAN != 0 || b.DHCPStart != "" || b.DHCPEnd != "" || b.DHCPRelay4 != "" || b.DHCPRelayGateway4 != "" || b.DHCPRelay6 != "" || b.DHCPRelayLink6 != "" || b.DHCPv6PDPool != "" || b.DHCPv6PDBits != 0 || b.Lease != "" || len(b.DNS) != 0 || len(b.DNS6) != 0 || len(b.Hosts) != 0 || len(b.Hosts6) != 0 || b.Policy != nil || b.LLDPMEDPolicy != nil {
			return fmt.Errorf("l2.bridge cannot combine top-level gateway settings with vlans")
		}
		if len(b.VLANs) > 64 {
			return fmt.Errorf("l2.bridge.vlans takes at most 64 VLANs")
		}
		seen := make(map[uint16]bool, len(b.VLANs))
		for i := range b.VLANs {
			entry := &b.VLANs[i]
			if entry.VLANID == 0 || entry.VLANID > 4094 || seen[entry.VLANID] {
				return fmt.Errorf("l2.bridge.vlans[%d].vlan_id must be unique and in range 1..4094", i)
			}
			seen[entry.VLANID] = true
			if entry.Gateway == nil || len(entry.Gateway.VLANs) != 0 {
				return fmt.Errorf("l2.bridge.vlans[%d].gateway must define one network and cannot nest vlans", i)
			}
			if entry.Gateway.LLDPMEDPolicy != nil {
				return fmt.Errorf("l2.bridge.vlans[%d].gateway.lldp_med_policy belongs on the VLAN entry", i)
			}
			if err := entry.LLDPMEDPolicy.validate(fmt.Sprintf("l2.bridge.vlans[%d].lldp_med_policy", i)); err != nil {
				return err
			}
			if entry.LLDPMEDPolicy != nil && entry.LLDPMEDPolicy.VLANID != entry.VLANID {
				return fmt.Errorf("l2.bridge.vlans[%d].lldp_med_policy.vlan_id must match vlan_id %d", i, entry.VLANID)
			}
			if err := entry.Gateway.validate(); err != nil {
				return fmt.Errorf("l2.bridge.vlans[%d].gateway: %w", i, err)
			}
		}
		// Explicit relay pairs must be mutual. That lets multicast queries and
		// multicast responses use the same reflector policy without creating a
		// one-way discovery path or an implicit VLAN-wide bridge.
		for i, entry := range b.VLANs {
			seenTargets := make(map[uint16]bool, len(entry.MDNSRelayTo))
			for _, target := range entry.MDNSRelayTo {
				if target == entry.VLANID || !seen[target] || seenTargets[target] {
					return fmt.Errorf("l2.bridge.vlans[%d].mdns_relay_to must contain unique, configured VLANs other than its own", i)
				}
				seenTargets[target] = true
				targetEntry := -1
				for j := range b.VLANs {
					if b.VLANs[j].VLANID == target {
						targetEntry = j
						break
					}
				}
				if targetEntry < 0 || !slices.Contains(b.VLANs[targetEntry].MDNSRelayTo, entry.VLANID) {
					return fmt.Errorf("l2.bridge.vlans[%d].mdns_relay_to VLAN %d must also list VLAN %d", i, target, entry.VLANID)
				}
			}
		}
		return nil
	}
	if b.PrivateVLAN > 4094 {
		return fmt.Errorf("l2.bridge.private_vlan must be in 1..4094")
	}
	if b.Address == "" {
		b.Address = "10.78.0.1/24"
	}
	pfx, err := netip.ParsePrefix(b.Address)
	if err != nil || !pfx.Addr().Is4() || pfx.Bits() < 16 || pfx.Bits() > 29 {
		return fmt.Errorf("l2.bridge.address must be an IPv4 address with a /16 to /29 prefix")
	}
	var v6 netip.Prefix
	if b.IPv6Address != "" {
		v6, err = netip.ParsePrefix(b.IPv6Address)
		if err != nil || !v6.Addr().Is6() || v6.Addr().Is4In6() || v6.Bits() < 48 || v6.Bits() > 120 {
			return fmt.Errorf("l2.bridge.ipv6_address must be a native IPv6 gateway prefix with a /48 to /120 prefix length")
		}
	}
	if b.DHCPRelay6 != "" {
		relay, err := netip.ParseAddrPort(b.DHCPRelay6)
		if err != nil || !relay.Addr().Is6() || relay.Addr().Is4In6() || relay.Addr().IsUnspecified() || relay.Addr().IsMulticast() || relay.Port() == 0 || !v6.IsValid() {
			return fmt.Errorf("l2.bridge.dhcp_relay6 requires an IPv6 gateway and a native IPv6 unicast endpoint")
		}
		if len(b.Hosts6) > 0 || b.DHCPv6PDPool != "" || b.DHCPv6PDBits != 0 {
			return fmt.Errorf("l2.bridge.dhcp_relay6 cannot be combined with local DHCPv6 reservations or a PD pool")
		}
	} else if b.DHCPRelayLink6 != "" {
		return fmt.Errorf("l2.bridge.dhcp_relay_link_address requires dhcp_relay6")
	}
	if b.DHCPRelayLink6 != "" {
		link, err := netip.ParseAddr(b.DHCPRelayLink6)
		if err != nil || !link.Is6() || link.Is4In6() || !v6.Contains(link) || link.IsUnspecified() || link.IsMulticast() {
			return fmt.Errorf("l2.bridge.dhcp_relay_link_address must be a unicast address within ipv6_address")
		}
	}
	if b.DHCPv6PDPool != "" {
		pool, err := netip.ParsePrefix(b.DHCPv6PDPool)
		if err != nil || !pool.Addr().Is6() || pool.Addr().Is4In6() || pool != pool.Masked() || !v6.IsValid() || pool.Overlaps(v6) || b.DHCPRelay6 != "" || int(b.DHCPv6PDBits) < pool.Bits() || b.DHCPv6PDBits > 120 {
			return fmt.Errorf("l2.bridge.dhcpv6_pd_pool requires a canonical IPv6 prefix and delegated prefix bits no shorter than the pool")
		}
	} else if b.DHCPv6PDBits != 0 {
		return fmt.Errorf("l2.bridge.dhcpv6_pd_prefix_bits requires dhcpv6_pd_pool")
	}
	if pfx.Masked().Overlaps(netip.MustParsePrefix("10.77.0.0/24")) || pfx.Masked().Overlaps(netip.MustParsePrefix("172.16.0.0/12")) {
		return fmt.Errorf("l2.bridge.address overlaps the tunnel (10.77.0.0/24) or the container network (172.16.0.0/12)")
	}
	gw := pfx.Addr()
	within := func(field, v string) (netip.Addr, error) {
		a, err := netip.ParseAddr(v)
		broadcast := pfx.Masked().Addr().As4()
		mask := net.CIDRMask(pfx.Bits(), 32)
		for i := range broadcast {
			broadcast[i] |= ^mask[i]
		}
		if err != nil || !a.Is4() || !pfx.Contains(a) || a == gw || a == pfx.Masked().Addr() || a.As4() == broadcast {
			return a, fmt.Errorf("l2.bridge.%s must be a host address inside %s other than the gateway", field, pfx.Masked())
		}
		return a, nil
	}
	if b.DHCPRelay4 != "" {
		relay, err := netip.ParseAddrPort(b.DHCPRelay4)
		if err != nil || !relay.Addr().Is4() || relay.Addr().IsUnspecified() || relay.Addr().IsMulticast() || relay.Port() == 0 {
			return fmt.Errorf("l2.bridge.dhcp_relay4 must be a unicast IPv4 address and UDP port")
		}
		if b.DHCPStart != "" || b.DHCPEnd != "" || len(b.Hosts) != 0 {
			return fmt.Errorf("l2.bridge.dhcp_relay4 cannot be combined with a local DHCPv4 pool or fixed hosts")
		}
		if b.DHCPRelayGateway4 != "" {
			if _, err := within("dhcp_relay_gateway4", b.DHCPRelayGateway4); err != nil {
				return err
			}
		} else if !pfx.Contains(relay.Addr()) {
			return fmt.Errorf("l2.bridge.dhcp_relay_gateway4 is required when dhcp_relay4 is off-subnet")
		}
	} else {
		if b.DHCPRelayGateway4 != "" {
			return fmt.Errorf("l2.bridge.dhcp_relay_gateway4 requires dhcp_relay4")
		}
		if b.DHCPStart == "" || b.DHCPEnd == "" {
			return fmt.Errorf("l2.bridge needs dhcp_start and dhcp_end, or dhcp_relay4")
		}
		lo, err := within("dhcp_start", b.DHCPStart)
		if err != nil {
			return err
		}
		hi, err := within("dhcp_end", b.DHCPEnd)
		if err != nil {
			return err
		}
		if hi.Less(lo) {
			return fmt.Errorf("l2.bridge.dhcp_end is before dhcp_start")
		}
	}
	if b.Lease == "" {
		b.Lease = "12h"
	}
	if !leaseRE.MatchString(b.Lease) {
		return fmt.Errorf("l2.bridge.lease must look like 30m or 12h")
	}
	if len(b.DNS) == 0 {
		b.DNS = []string{"1.1.1.1", "9.9.9.9"}
	}
	if len(b.DNS) > 3 {
		return fmt.Errorf("l2.bridge.dns takes at most three resolvers")
	}
	for _, d := range b.DNS {
		if a, err := netip.ParseAddr(d); err != nil || !a.Is4() {
			return fmt.Errorf("l2.bridge.dns %q is not an IPv4 address", d)
		}
	}
	if len(b.DNS6) > 3 {
		return fmt.Errorf("l2.bridge.dns6 takes at most three resolvers")
	}
	for _, d := range b.DNS6 {
		if a, err := netip.ParseAddr(d); err != nil || !a.Is6() || a.Is4In6() || a.IsUnspecified() || a.IsMulticast() {
			return fmt.Errorf("l2.bridge.dns6 %q is not a unicast IPv6 address", d)
		}
	}
	if len(b.Hosts) > 64 {
		return fmt.Errorf("l2.bridge.hosts takes at most 64 entries")
	}
	seenHostMACs := make(map[string]bool, len(b.Hosts))
	seenHostIPs := make(map[string]bool, len(b.Hosts))
	for i := range b.Hosts {
		h := &b.Hosts[i]
		hw, err := net.ParseMAC(h.MAC)
		if err != nil || len(hw) != 6 || hw[0]&1 == 1 {
			return fmt.Errorf("l2.bridge.hosts[%d].mac is not a unicast MAC", i)
		}
		h.MAC = hw.String()
		if seenHostMACs[h.MAC] {
			return fmt.Errorf("l2.bridge.hosts has more than one binding for %s", h.MAC)
		}
		seenHostMACs[h.MAC] = true
		if _, err := within(fmt.Sprintf("hosts[%d].ip", i), h.IP); err != nil {
			return err
		}
		if seenHostIPs[h.IP] {
			return fmt.Errorf("l2.bridge.hosts has more than one binding for %s", h.IP)
		}
		seenHostIPs[h.IP] = true
		if !hostNameRE.MatchString(h.Name) {
			return fmt.Errorf("l2.bridge.hosts[%d].name must be letters, digits and dashes", i)
		}
	}
	if len(b.Hosts6) > 64 {
		return fmt.Errorf("l2.bridge.hosts6 takes at most 64 entries")
	}
	if len(b.Hosts6) > 0 && b.IPv6Address == "" {
		return fmt.Errorf("l2.bridge.hosts6 requires l2.bridge.ipv6_address")
	}
	var v6Prefix netip.Prefix
	if b.IPv6Address != "" {
		v6Prefix, _ = netip.ParsePrefix(b.IPv6Address)
	}
	seenHost6IDs := make(map[string]bool, len(b.Hosts6))
	seenHost6IPs := make(map[string]bool, len(b.Hosts6))
	for i := range b.Hosts6 {
		h := &b.Hosts6[i]
		clientID, err := hex.DecodeString(h.ClientIDHex)
		if err != nil || len(clientID) < 2 || len(clientID) > 128 {
			return fmt.Errorf("l2.bridge.hosts6[%d].client_id_hex must encode a 2 to 128 byte DHCPv6 DUID", i)
		}
		h.ClientIDHex = strings.ToLower(h.ClientIDHex)
		key := fmt.Sprintf("%s/%08x", h.ClientIDHex, h.IAID)
		if seenHost6IDs[key] {
			return fmt.Errorf("l2.bridge.hosts6 has more than one binding for client DUID and IAID %s", key)
		}
		seenHost6IDs[key] = true
		hw, err := net.ParseMAC(h.MAC)
		if err != nil || len(hw) != 6 || hw[0]&1 == 1 {
			return fmt.Errorf("l2.bridge.hosts6[%d].mac is not a unicast MAC", i)
		}
		h.MAC = hw.String()
		ip, err := netip.ParseAddr(h.IP)
		if err != nil || !ip.Is6() || ip.Is4In6() || !v6Prefix.Contains(ip) || ip == v6Prefix.Addr() || ip.IsUnspecified() || ip.IsMulticast() {
			return fmt.Errorf("l2.bridge.hosts6[%d].ip must be a native unicast address inside %s other than the gateway", i, v6Prefix)
		}
		h.IP = ip.String()
		if seenHost6IPs[h.IP] {
			return fmt.Errorf("l2.bridge.hosts6 has more than one binding for %s", h.IP)
		}
		seenHost6IPs[h.IP] = true
		if !hostNameRE.MatchString(h.Name) {
			return fmt.Errorf("l2.bridge.hosts6[%d].name must be letters, digits and dashes", i)
		}
	}
	if b.Policy != nil {
		if err := b.Policy.validate(); err != nil {
			return err
		}
	}
	return b.LLDPMEDPolicy.validate("l2.bridge.lldp_med_policy")
}

func (l *L2Config) validate() error {
	if l == nil || !l.Enabled {
		return nil
	}
	if l.VXLAN != nil && (l.Bridge == nil || l.SegmentSocketPath == "" || l.SegmentID == "") {
		return fmt.Errorf("l2.vxlan requires broker mode with segment_socket_path, segment_id, and l2.bridge")
	}
	if err := l.RSTP.validate(); err != nil {
		return err
	}
	if l.RSTP != nil && l.BPDUGuardTunnel {
		return fmt.Errorf("l2.rstp cannot be combined with bpdu_guard_tunnel")
	}
	if l.RSTP != nil && l.Bridge == nil && l.BPDUGuardExit {
		return fmt.Errorf("l2.rstp cannot be combined with bpdu_guard_exit on a participating TAP port")
	}
	if err := l.validateKernelVXLANAttachments(); err != nil {
		return err
	}
	if l.SegmentID != "" && !segmentIDRE.MatchString(l.SegmentID) {
		return fmt.Errorf("l2.segment_id must be 1-64 letters, digits, dot, underscore, colon or dash")
	}
	if l.SegmentSocketPath != "" {
		if l.SegmentID == "" || !strings.HasPrefix(l.SegmentSocketPath, "/") || len(l.SegmentSocketPath) >= 104 {
			return fmt.Errorf("l2.segment_socket_path requires segment_id and an absolute Unix socket path shorter than 104 bytes")
		}
		if l.Bridge != nil && (l.SegmentMembersFile == "" || l.SegmentTokenFile != "") {
			return fmt.Errorf("l2.segment_members_file is required and segment_token_file is not valid in broker mode")
		}
		if l.Bridge == nil && (l.SegmentTokenFile == "" || l.SegmentMembersFile != "") {
			return fmt.Errorf("l2.segment_token_file is required and segment_members_file is not valid for a remote session attachment")
		}
		for field, value := range map[string]string{"segment_token_file": l.SegmentTokenFile, "segment_members_file": l.SegmentMembersFile, "segment_admin_token_file": l.SegmentAdminTokenFile} {
			if value != "" && (!strings.HasPrefix(value, "/") || len(value) > 4096) {
				return fmt.Errorf("l2.%s must be an absolute file path", field)
			}
		}
	} else if l.SegmentTokenFile != "" || l.SegmentMembersFile != "" || l.SegmentAdminTokenFile != "" {
		return fmt.Errorf("l2 segment token and member files require segment_socket_path")
	}
	if l.TapName == "" {
		l.TapName = "gamebond-tap0"
	}
	if len(l.TapName) > 15 || strings.ContainsAny(l.TapName, " /") {
		return fmt.Errorf("l2.tap_name must be a valid interface name")
	}
	if l.Monitor != nil {
		if l.Monitor.TapName == "" || len(l.Monitor.TapName) > 15 || strings.ContainsAny(l.Monitor.TapName, " /") || l.Monitor.TapName == l.TapName {
			return fmt.Errorf("l2.monitor.tap_name must be a valid interface name distinct from l2.tap_name")
		}
		if !l.Monitor.TunnelIngress && !l.Monitor.TunnelEgress && !l.Monitor.ExitIngress && !l.Monitor.ExitEgress {
			return fmt.Errorf("l2.monitor must enable at least one ingress or egress direction")
		}
	}
	if l.FrameMTU == 0 {
		l.FrameMTU = bond.DefaultL2FrameMTU
	}
	if l.FrameMTU < 600 || l.FrameMTU > 1500 {
		return fmt.Errorf("l2.frame_mtu must be 600-1500")
	}
	if err := l.TunnelVLAN.Validate(); err != nil {
		return fmt.Errorf("l2.tunnel_vlan: %w", err)
	}
	if err := l.ExitVLAN.Validate(); err != nil {
		return fmt.Errorf("l2.exit_vlan: %w", err)
	}
	if l.MVR != nil {
		if err := l.MVR.Validate(); err != nil {
			return fmt.Errorf("l2.mvr: %w", err)
		}
		if l.SegmentSocketPath == "" {
			source := l.MulticastRouterTunnel && edgePolicyAdmitsVLAN(l.TunnelVLAN, l.MVR.MulticastVLAN)
			if l.Bridge != nil && edgePolicyAdmitsVLAN(l.ExitVLAN, l.MVR.MulticastVLAN) {
				source = true
			}
			if l.Bridge != nil {
				for _, entry := range l.Bridge.VLANs {
					if entry.VLANID == l.MVR.MulticastVLAN {
						source = true
					}
				}
			}
			if !source {
				return fmt.Errorf("l2.mvr multicast_vlan must be admitted by a multicast-router tunnel or gateway port")
			}
			for _, group := range l.MVR.Groups {
				for _, receiverVLAN := range group.ReceiverVLANIDs() {
					receiver := edgePolicyAdmitsVLAN(l.TunnelVLAN, receiverVLAN) || edgePolicyAdmitsVLAN(l.ExitVLAN, receiverVLAN)
					if l.Bridge != nil {
						for _, entry := range l.Bridge.VLANs {
							if entry.VLANID == receiverVLAN {
								receiver = true
							}
						}
					}
					if !receiver {
						return fmt.Errorf("l2.mvr receiver VLAN %d has no configured L2 port", receiverVLAN)
					}
				}
			}
		}
	}
	if l.Bridge != nil {
		if l.RAGuardExit {
			return fmt.Errorf("l2.ra_guard_exit cannot guard the trusted gateway service port; use ra_guard on session ports")
		}
		hasNestedPVLANGateway := false
		for _, entry := range l.Bridge.VLANs {
			hasNestedPVLANGateway = hasNestedPVLANGateway || entry.Gateway != nil && entry.Gateway.PrivateVLAN != 0
		}
		if hasNestedPVLANGateway && l.SegmentID == "" {
			return fmt.Errorf("multi-VLAN PVLAN gateway roles require the shared segment broker")
		}
		if len(l.Bridge.VLANs) == 0 && l.Bridge.PrivateVLAN != 0 && l.ExitVLAN.AccessVLAN == 0 {
			return fmt.Errorf("l2.bridge.private_vlan requires l2.exit_vlan.access_vlan as the PVLAN primary VLAN")
		}
		if len(l.Bridge.VLANs) > 0 {
			if l.Bridge.PrivateVLAN != 0 {
				return fmt.Errorf("l2.bridge.private_vlan belongs on each l2.bridge.vlans gateway entry")
			}
			if l.Bridge.LLDPMEDPolicy != nil {
				return fmt.Errorf("l2.bridge.lldp_med_policy must be configured on an l2.bridge.vlans entry")
			}
			if l.ExitVLAN.AccessVLAN != 0 || len(l.ExitVLAN.AllowedVLANs) != 0 || l.ExitVLAN.NativeVLAN != 0 {
				return fmt.Errorf("l2.exit_vlan is configured per l2.bridge.vlans entry")
			}
			if len(l.TunnelVLAN.AllowedVLANs) == 0 {
				return fmt.Errorf("l2.tunnel_vlan must be a trunk when l2.bridge.vlans is configured")
			}
			for i := range l.Bridge.VLANs {
				entry := &l.Bridge.VLANs[i]
				if !slices.Contains(l.TunnelVLAN.AllowedVLANs, entry.VLANID) {
					return fmt.Errorf("l2.tunnel_vlan does not admit gateway VLAN %d", entry.VLANID)
				}
				if err := l.validateLLDPMEDMembership(entry.LLDPMEDPolicy, entry.VLANID, fmt.Sprintf("l2.bridge.vlans[%d].lldp_med_policy", i)); err != nil {
					return err
				}
			}
		} else if len(l.ExitVLAN.AllowedVLANs) != 0 {
			return fmt.Errorf("l2.exit_vlan must be an access VLAN for a single-network gVisor gateway")
		} else if l.Bridge.LLDPMEDPolicy != nil {
			if err := l.validateLLDPMEDMembership(l.Bridge.LLDPMEDPolicy, l.Bridge.LLDPMEDPolicy.VLANID, "l2.bridge.lldp_med_policy"); err != nil {
				return err
			}
		}
	}
	if l.SegmentID != "" && (l.TunnelPrivateVLAN != nil || l.ExitPrivateVLAN != nil) {
		return fmt.Errorf("shared segment PVLAN roles must be configured on broker members and the gateway, not local tunnel/exit ports")
	}
	if l.Bridge != nil && l.ExitPrivateVLAN != nil {
		return fmt.Errorf("l2.exit_private_vlan cannot override the gVisor gateway PVLAN role")
	}
	tunnelPVLANPort := bond.L2PortConfig{Name: "tunnel", VLAN: l.TunnelVLAN}
	if err := l.TunnelPrivateVLAN.apply(&tunnelPVLANPort); err != nil {
		return fmt.Errorf("l2.tunnel_private_vlan: %w", err)
	}
	exitPVLANPort := bond.L2PortConfig{Name: "exit", VLAN: l.ExitVLAN}
	if err := l.ExitPrivateVLAN.apply(&exitPVLANPort); err != nil {
		return fmt.Errorf("l2.exit_private_vlan: %w", err)
	}
	if l.Bridge != nil && len(l.Bridge.VLANs) == 0 && l.Bridge.PrivateVLAN != 0 {
		exitPVLANPort.PrivateVLAN = l.Bridge.PrivateVLAN
		exitPVLANPort.PrivateVLANRole = bond.L2PVLANPromiscuous
		exitPVLANPort.PVLANPrimaryVLAN = l.ExitVLAN.AccessVLAN
	}
	if tunnelPVLANPort.PVLANPrimaryVLAN != 0 || exitPVLANPort.PVLANPrimaryVLAN != 0 {
		if err := bond.ValidatePVLANPorts([]bond.L2PortConfig{tunnelPVLANPort, exitPVLANPort}); err != nil {
			return fmt.Errorf("l2 PVLAN port configuration: %w", err)
		}
	}
	// A remote segment member's VLAN policy is broker-owned, so the client
	// cannot infer trunk membership from its local config. Reserve tag room for
	// that port even though the broker remains authoritative for VLAN admission.
	tagRoom := max(l2VLANTagOverhead(l.TunnelVLAN), l2VLANTagOverhead(l.ExitVLAN))
	if l.SegmentSocketPath != "" {
		tagRoom = max(tagRoom, 8)
	} // broker member policy may select a Q-in-Q trunk
	if tagRoom > l.frameTagRoom {
		l.FrameMTU += tagRoom - l.frameTagRoom
		l.frameTagRoom = tagRoom
	}
	if l.MACLimit < 0 || l.MACLimit > 4096 || l.BroadcastPPS < 0 || l.MulticastPPS < 0 || l.UnknownUnicastPPS < 0 {
		return fmt.Errorf("l2 limits must not be negative (mac_limit <= 4096)")
	}
	if math.IsNaN(l.ControlPlanePPS) || math.IsInf(l.ControlPlanePPS, 0) || l.ControlPlanePPS < 0 || l.ControlPlanePPS > 1000000 || (l.ControlPlanePPS > 0 && l.ControlPlanePPS < 1) {
		return fmt.Errorf("l2.control_plane_pps must be 0 (disabled) or 1..1000000 frames per second")
	}
	if l.ControlPlanePPS > 0 && l.Bridge == nil {
		return fmt.Errorf("l2.control_plane_pps requires an l2.bridge gVisor gateway")
	}
	if err := l.ControlPlaneRates.Validate(l.Bridge != nil); err != nil {
		return fmt.Errorf("l2.control_plane_rates: %w", err)
	}
	if l.Bridge != nil {
		return l.Bridge.validate()
	}
	return nil
}

func edgePolicyAdmitsVLAN(policy bond.L2VLANPolicy, vlan uint16) bool {
	if policy.ServiceVLAN != 0 {
		return false
	}
	if policy.AccessVLAN != 0 {
		return policy.AccessVLAN == vlan
	}
	return slices.Contains(policy.AllowedVLANs, vlan)
}

// l2VLANTagOverhead is the maximum tag growth this port can add to an
// untagged customer frame: one C-tag for a normal trunk, or S-tag+C-tag for a
// Q-in-Q service trunk. Access policies strip tags on egress.
func l2VLANTagOverhead(policy bond.L2VLANPolicy) int {
	return policy.EgressTagOverhead()
}

func gatewayStackMTU(config *L2Config) int {
	if config == nil {
		return 0
	}
	overhead := max(l2VLANTagOverhead(config.TunnelVLAN), l2VLANTagOverhead(config.ExitVLAN))
	if config.SegmentSocketPath != "" {
		overhead = max(overhead, 8)
	}
	return config.FrameMTU - overhead - bond.EthHeaderLen
}

func (l *L2Config) validateLLDPMEDMembership(policy *L2LLDPMEDPolicy, vlanID uint16, where string) error {
	if policy == nil {
		return nil
	}
	if err := policy.validate(where); err != nil {
		return err
	}
	if policy.VLANID != vlanID {
		return fmt.Errorf("%s.vlan_id must match gateway VLAN %d", where, vlanID)
	}
	multiVLAN := l.Bridge != nil && len(l.Bridge.VLANs) > 0
	if !multiVLAN && l.ExitVLAN.AccessVLAN != vlanID {
		return fmt.Errorf("%s.vlan_id must match the configured l2.exit_vlan.access_vlan", where)
	}
	if l.TunnelVLAN.AccessVLAN != 0 {
		if l.TunnelVLAN.AccessVLAN != vlanID || policy.Tagged {
			return fmt.Errorf("%s must match the untagged access membership on l2.tunnel_vlan", where)
		}
		return nil
	}
	if len(l.TunnelVLAN.AllowedVLANs) == 0 || !slices.Contains(l.TunnelVLAN.AllowedVLANs, vlanID) {
		return fmt.Errorf("%s requires explicit membership on l2.tunnel_vlan", where)
	}
	wantTagged := l.TunnelVLAN.NativeVLAN != vlanID
	if policy.Tagged != wantTagged {
		return fmt.Errorf("%s.tagged must match the tunnel trunk native VLAN behavior", where)
	}
	return nil
}

func DecodeConfig(data []byte) (Config, bond.SessionOptions, netip.AddrPort, []byte, error) {
	c := Config{MTU: 1280, TunName: "gamebond0", InitialRate: 1, MaximumRate: 100, ReorderMS: 30, QoS: bond.DefaultQoSSettings()}
	options := bond.DefaultSessionOptions()
	fail := func(err error) (Config, bond.SessionOptions, netip.AddrPort, []byte, error) {
		return c, options, netip.AddrPort{}, nil, err
	}
	if len(data) > 1024*1024 {
		return fail(fmt.Errorf("configuration exceeds size limit"))
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&c); err != nil {
		return fail(err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fail(fmt.Errorf("trailing configuration data"))
	}
	if c.Role != "server" || !c.Bonding || c.TunName != "gamebond0" || c.MTU != 1280 || c.ClientIP != "10.77.0.2" || c.BulkRate != 0 {
		return fail(fmt.Errorf("native container requires bonded IPv4 server, gamebond0, MTU1280, client 10.77.0.2 and bulk_rate_mbps=0"))
	}
	if len(c.Bind) != 1 || len(c.Bind[0]) != 2 {
		return fail(fmt.Errorf("one numeric IPv4 UDP bind required"))
	}
	var address string
	var port int
	if json.Unmarshal(c.Bind[0][0], &address) != nil || json.Unmarshal(c.Bind[0][1], &port) != nil || address != "0.0.0.0" || port != 4433 {
		return fail(fmt.Errorf("native container bind must be 0.0.0.0:4433"))
	}
	if len(c.Admin) > 0 && string(bytes.TrimSpace(c.Admin)) != "null" {
		if _, err := adminportal.ParseSettings(c.Admin); err != nil {
			return fail(err)
		}
	}
	if len(c.Security) > 0 && string(bytes.TrimSpace(c.Security)) != "null" {
		if _, err := security.Parse(c.Security); err != nil {
			return fail(fmt.Errorf("security: %w", err))
		}
	}
	session, err := hex.DecodeString(c.Session)
	if err != nil || len(session) != 16 {
		return fail(fmt.Errorf("invalid session identifier"))
	}
	if err := c.L2.validate(); err != nil {
		return fail(err)
	}
	if c.L2 != nil && c.L2.Enabled {
		options.L2, options.L2FrameMTU = true, c.L2.FrameMTU
	}
	options.MTU = c.MTU
	options.ClientIP = netip.MustParseAddr(c.ClientIP)
	if len(c.LanTunnelIPs) > 32 {
		return fail(fmt.Errorf("lan_tunnel_ips must list at most 32 addresses"))
	}
	for _, text := range c.LanTunnelIPs {
		ip, err := netip.ParseAddr(text)
		if err != nil || !ip.Is4() || ip.String() != text {
			return fail(fmt.Errorf("lan_tunnel_ips: %q is not a dotted IPv4 address", text))
		}
		b := ip.As4()
		if b[0] != 10 || b[1] != 77 || b[2] != 0 || b[3] < 3 || b[3] > 254 {
			return fail(fmt.Errorf("lan_tunnel_ips: %s must be 10.77.0.3 to 10.77.0.254", text))
		}
		if slices.Contains(options.DeviceIPs, ip) {
			return fail(fmt.Errorf("lan_tunnel_ips must be distinct"))
		}
		options.DeviceIPs = append(options.DeviceIPs, ip)
	}
	options.InitialRate = c.InitialRate
	options.MaximumRate = c.MaximumRate
	options.Redundant = c.Redundant
	options.GamePorts = c.GamePorts
	options.QoS = c.QoS
	options.LossTracking, options.PathMTUDiscovery, options.FailoverReplay = c.LossTracking, c.PathMTU, c.Failover
	options.FlowPinning, options.CoDel = c.FlowPinning, c.CoDel
	if c.StripeAbove < 0 || c.StripeAbove > 1000 {
		return fail(fmt.Errorf("stripe_above_mbps must be 0..1000"))
	}
	options.StripeAbove = c.StripeAbove
	if c.ParityRowsMin < 0 || c.ParityRowsMax < 0 || c.ParityRowsMax > 3 || (c.ParityRowsMax != 0 && c.ParityRowsMin > c.ParityRowsMax) {
		return fail(fmt.Errorf("parity_rows_min/max must satisfy 0 <= min <= max <= 3"))
	}
	options.ParityRowsMin, options.ParityRowsMax = c.ParityRowsMin, c.ParityRowsMax
	options.DelayControl = c.DelayControl
	options.DelayAssertive = c.DelayAssertive
	options.LabMode = c.LabMode
	if c.PriorityHostMax < 0 || c.PriorityHostMax > 1280 {
		return fail(fmt.Errorf("priority_host_max_packet must be 0 to 1280"))
	}
	options.PriorityHostMax = c.PriorityHostMax
	if c.ReorderMS < 1 || c.ReorderMS > 200 {
		return fail(fmt.Errorf("reorder timeout must be 1..200ms"))
	}
	options.ReorderTimeout = time.Duration(c.ReorderMS * float64(time.Millisecond))
	options.Policies = make(map[byte]bond.QueuePolicy)
	for tag, p := range c.Queues {
		n, err := strconv.Atoi(tag)
		if err != nil || n < 0 || n > 63 || p.Validate() != nil {
			return fail(fmt.Errorf("invalid queue policy"))
		}
		options.Policies[byte(n)] = p
	}
	if options.QoS.Validate() != nil {
		return fail(fmt.Errorf("invalid adaptive QoS settings"))
	}
	if _, err := bond.NewBudget(options.InitialRate, options.MaximumRate); err != nil {
		return fail(err)
	}
	for _, port := range options.GamePorts {
		if port == 0 {
			return fail(fmt.Errorf("invalid game port"))
		}
	}
	return c, options, netip.AddrPortFrom(netip.MustParseAddr(address), uint16(port)), session, nil
}
