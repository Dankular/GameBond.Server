package edge

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Dankular/GameBond.Core/bond"
	"github.com/Dankular/GameBond.Server/adminportal"
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
	Enabled           bool    `json:"enabled"`
	TapName           string  `json:"tap_name"`
	FrameMTU          int     `json:"frame_mtu"`
	MACLimit          int     `json:"mac_limit"`
	BroadcastPPS      float64 `json:"broadcast_pps"`
	MulticastPPS      float64 `json:"multicast_pps"`
	UnknownUnicastPPS float64 `json:"unknown_unicast_pps"`
	// Bridge makes the container the gateway of the carried segment: the entrypoint joins the TAP
	// to a bridge with this address, serves DHCP on it and NATs it to the internet. Without it
	// the TAP is left for the host to wire.
	Bridge *L2Bridge `json:"bridge"`
}

// L2Bridge is the addressing of the bridged segment. Each exit has its own config, so give the
// exits disjoint DHCP ranges (and the same Address): devices then keep their gateway across a failover.
type L2Bridge struct {
	Address   string   `json:"address"`    // gateway address with prefix, default 10.78.0.1/24
	DHCPStart string   `json:"dhcp_start"` // first leased address
	DHCPEnd   string   `json:"dhcp_end"`   // last leased address
	Lease     string   `json:"lease"`      // lease time such as 12h, default 12h
	DNS       []string `json:"dns"`        // resolvers handed out, default 1.1.1.1 and 9.9.9.9
	Hosts     []L2Host `json:"hosts"`      // fixed leases by MAC
	// Policy is the live rule set: per-device limits applied to the next flow. It can be reloaded
	// (SIGHUP) without restarting the exit; hosts above are reloaded with it.
	Policy *L2Policy `json:"policy"`
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
	leaseRE    = regexp.MustCompile(`^[0-9]{1,4}[smh]$`)
	hostNameRE = regexp.MustCompile(`^[A-Za-z0-9-]{0,32}$`)
)

func (b *L2Bridge) validate() error {
	if b.Address == "" {
		b.Address = "10.78.0.1/24"
	}
	pfx, err := netip.ParsePrefix(b.Address)
	if err != nil || !pfx.Addr().Is4() || pfx.Bits() < 16 || pfx.Bits() > 29 {
		return fmt.Errorf("l2.bridge.address must be an IPv4 address with a /16 to /29 prefix")
	}
	if pfx.Masked().Overlaps(netip.MustParsePrefix("10.77.0.0/24")) || pfx.Masked().Overlaps(netip.MustParsePrefix("172.16.0.0/12")) {
		return fmt.Errorf("l2.bridge.address overlaps the tunnel (10.77.0.0/24) or the container network (172.16.0.0/12)")
	}
	gw := pfx.Addr()
	within := func(field, v string) (netip.Addr, error) {
		a, err := netip.ParseAddr(v)
		if err != nil || !a.Is4() || !pfx.Contains(a) || a == gw || a == pfx.Masked().Addr() {
			return a, fmt.Errorf("l2.bridge.%s must be a host address inside %s other than the gateway", field, pfx.Masked())
		}
		return a, nil
	}
	if b.DHCPStart == "" || b.DHCPEnd == "" {
		return fmt.Errorf("l2.bridge needs dhcp_start and dhcp_end")
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
	if len(b.Hosts) > 64 {
		return fmt.Errorf("l2.bridge.hosts takes at most 64 entries")
	}
	for i := range b.Hosts {
		h := &b.Hosts[i]
		hw, err := net.ParseMAC(h.MAC)
		if err != nil || len(hw) != 6 || hw[0]&1 == 1 {
			return fmt.Errorf("l2.bridge.hosts[%d].mac is not a unicast MAC", i)
		}
		h.MAC = hw.String()
		if _, err := within(fmt.Sprintf("hosts[%d].ip", i), h.IP); err != nil {
			return err
		}
		if !hostNameRE.MatchString(h.Name) {
			return fmt.Errorf("l2.bridge.hosts[%d].name must be letters, digits and dashes", i)
		}
	}
	if b.Policy != nil {
		return b.Policy.validate()
	}
	return nil
}

func (l *L2Config) validate() error {
	if l == nil || !l.Enabled {
		return nil
	}
	if l.TapName == "" {
		l.TapName = "gamebond-tap0"
	}
	if len(l.TapName) > 15 || strings.ContainsAny(l.TapName, " /") {
		return fmt.Errorf("l2.tap_name must be a valid interface name")
	}
	if l.FrameMTU == 0 {
		l.FrameMTU = bond.DefaultL2FrameMTU
	}
	if l.FrameMTU < 600 || l.FrameMTU > 1500 {
		return fmt.Errorf("l2.frame_mtu must be 600-1500")
	}
	if l.MACLimit < 0 || l.MACLimit > 4096 || l.BroadcastPPS < 0 || l.MulticastPPS < 0 || l.UnknownUnicastPPS < 0 {
		return fmt.Errorf("l2 limits must not be negative (mac_limit <= 4096)")
	}
	if l.Bridge != nil {
		return l.Bridge.validate()
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
