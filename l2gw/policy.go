package l2gw

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
)

// Policy is the live rule set the control plane pushes to the gateway. It replaces the previous
// one atomically and takes effect for the next flow; flows already open are never cut by a change.
type Policy struct {
	Version int64 // set by whoever pushes it; reported in the stats so both exits can be compared
	// Hosts are the fixed leases by MAC. They take effect for the next DHCP exchange.
	Hosts []Host
	// Devices are per-device rules, matched by the MAC that holds the flow's source address.
	Devices []DevicePolicy
	// Default applies to devices without an entry.
	Default DeviceRule
}

// DevicePolicy is the rule for one device.
type DevicePolicy struct {
	MAC  net.HardwareAddr
	Name string
	Rule DeviceRule
}

// DeviceRule limits what one device may open.
type DeviceRule struct {
	Deny         bool           // no new flows at all
	AllowPrivate bool           // may reach private ranges despite the gateway default
	BlockPorts   []uint16       // destination ports refused (TCP and UDP)
	BlockNets    []netip.Prefix // destinations refused
	MaxFlows     int            // concurrent flows; 0 is unlimited
}

// Validate rejects a policy the gateway could not apply.
func (p *Policy) Validate() error {
	if len(p.Devices) > 256 {
		return errors.New("l2gw: at most 256 device rules")
	}
	seen := map[[6]byte]bool{}
	for i, d := range p.Devices {
		if len(d.MAC) != 6 || d.MAC[0]&1 == 1 {
			return fmt.Errorf("l2gw: device rule %d needs a unicast MAC", i)
		}
		var k [6]byte
		copy(k[:], d.MAC)
		if seen[k] {
			return fmt.Errorf("l2gw: device %s has two rules", d.MAC)
		}
		seen[k] = true
		if d.Rule.MaxFlows < 0 {
			return fmt.Errorf("l2gw: device %s has a negative max_flows", d.MAC)
		}
	}
	if p.Default.MaxFlows < 0 {
		return errors.New("l2gw: default max_flows is negative")
	}
	return nil
}

type compiledPolicy struct {
	Policy
	byMAC map[[6]byte]DeviceRule
}

func compile(p Policy) *compiledPolicy {
	c := &compiledPolicy{Policy: p, byMAC: map[[6]byte]DeviceRule{}}
	for _, d := range p.Devices {
		var k [6]byte
		copy(k[:], d.MAC)
		c.byMAC[k] = d.Rule
	}
	return c
}

// verdict is why a flow was or was not allowed.
type verdict int

const (
	allow verdict = iota
	denyDevice
	denyDest
	denyPort
	denyLimit
)

// deviceCounters are the per-device numbers the control plane reads.
type deviceCounters struct {
	flows   atomic.Int64
	total   atomic.Uint64
	denied  atomic.Uint64
	lastNew atomic.Int64 // unix nanoseconds
}

// DeviceStat is one device's view in the stats.
type DeviceStat struct {
	MAC    string
	IP     string
	Flows  int
	Total  uint64
	Denied uint64
}

type devices struct {
	mu sync.Mutex
	m  map[[6]byte]*deviceCounters
}

func (d *devices) get(mac [6]byte) *deviceCounters {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.m == nil {
		d.m = map[[6]byte]*deviceCounters{}
	}
	c := d.m[mac]
	if c == nil {
		c = &deviceCounters{}
		d.m[mac] = c
	}
	return c
}

// SetPolicy applies a new rule set. Fixed hosts go to the DHCP server in the same step.
func (g *Gateway) SetPolicy(p Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if err := g.dhcp.setHosts(p.Hosts); err != nil {
		return err
	}
	g.policy.Store(compile(p))
	g.installFirewall()
	return nil
}

// PolicyVersion is the version of the rule set in force.
func (g *Gateway) PolicyVersion() int64 {
	if c := g.policy.Load(); c != nil {
		return c.Version
	}
	return 0
}

// decide applies the rules to a new flow from src to dst:port. A nil error result means open it.
// The caller releases the slot with the returned function once the flow ends.
func (g *Gateway) decide(src netip.Addr, dst netip.AddrPort) (func(), verdict) {
	mac, known := g.dhcp.macFor(src)
	rule := DeviceRule{}
	if c := g.policy.Load(); c != nil {
		rule = c.Default
		if known {
			if r, ok := c.byMAC[mac]; ok {
				rule = r
			}
		}
	}
	var ctr *deviceCounters
	if known {
		ctr = g.devs.get(mac)
	}
	deny := func(v verdict) (func(), verdict) {
		if ctr != nil {
			ctr.denied.Add(1)
		}
		return nil, v
	}
	if ctr == nil {
		return func() {}, allow
	}
	if rule.MaxFlows > 0 && ctr.flows.Load() >= int64(rule.MaxFlows) {
		return deny(denyLimit)
	}
	ctr.flows.Add(1)
	ctr.total.Add(1)
	return func() { ctr.flows.Add(-1) }, allow
}

// blockedHard names destinations no device rule can open: the unspecified, loopback, link-local
// and multicast ranges, and anything that would reach this host or the container network.
func blockedHard(a netip.Addr) bool {
	for _, p := range hardBlocked {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

var hardBlocked = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("224.0.0.0/3"),
}

// DeviceStats lists every device the gateway has seen.
func (g *Gateway) DeviceStats() []DeviceStat {
	g.devs.mu.Lock()
	defer g.devs.mu.Unlock()
	var out []DeviceStat
	for mac, c := range g.devs.m {
		s := DeviceStat{MAC: net.HardwareAddr(mac[:]).String(), Flows: int(c.flows.Load()), Total: c.total.Load(), Denied: c.denied.Load()}
		if ip, ok := g.dhcp.ipFor(mac); ok {
			s.IP = ip.String()
		}
		out = append(out, s)
	}
	return out
}
