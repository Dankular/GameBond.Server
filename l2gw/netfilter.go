package l2gw

import (
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// The gateway's firewall is the netstack's own: the policy compiles to a filter table whose Input chain every
// packet from a device walks before it reaches a flow, the same hook and rule engine an iptables user would
// program. Rules are ordinary stack.Rule values (destination prefix filters, a MAC matcher, a port matcher) and
// the verdict is a rejecting target that also counts, so a refusal costs the device one ICMP error rather than a
// timeout and shows up in the stats. The forwarders only relay what the table let through.

// macMatcher matches packets whose source address is held by one device.
type macMatcher struct {
	g   *Gateway
	mac [6]byte
}

func (m macMatcher) Match(_ stack.Hook, pkt *stack.PacketBuffer, _, _ string) (bool, bool) {
	nh := pkt.NetworkHeader().Slice()
	if len(nh) < header.IPv4MinimumSize {
		return false, false
	}
	mac, ok := m.g.dhcp.macFor(addrOf(header.IPv4(nh).SourceAddress()))
	return ok && mac == m.mac, false
}

// newFlowMatcher matches the packets that start something: a TCP SYN without ACK, and any non-TCP packet. A rule
// that carries it refuses new connections and leaves established TCP connections alone, which is how a policy
// change applies "to the next flow" without cutting one that is already open.
type newFlowMatcher struct{}

func (newFlowMatcher) Match(_ stack.Hook, pkt *stack.PacketBuffer, _, _ string) (bool, bool) {
	nh := pkt.NetworkHeader().Slice()
	if len(nh) < header.IPv4MinimumSize {
		return false, false
	}
	ip := header.IPv4(nh)
	if ip.TransportProtocol() != header.TCPProtocolNumber {
		return true, false
	}
	if ip.FragmentOffset() != 0 {
		return false, false
	}
	th := pkt.TransportHeader().Slice()
	if len(th) < 14 {
		var ok bool
		if th, ok = pkt.Data().PullUp(14); !ok {
			return false, false
		}
	}
	flags := th[13]
	return flags&0x02 != 0 && flags&0x10 == 0, false
}

// portMatcher matches TCP and UDP packets to any of the destination ports.
type portMatcher struct{ ports []uint16 }

func (m portMatcher) Match(_ stack.Hook, pkt *stack.PacketBuffer, _, _ string) (bool, bool) {
	nh := pkt.NetworkHeader().Slice()
	if len(nh) < header.IPv4MinimumSize {
		return false, false
	}
	ip := header.IPv4(nh)
	if p := ip.TransportProtocol(); p != header.TCPProtocolNumber && p != header.UDPProtocolNumber {
		return false, false
	}
	if ip.FragmentOffset() != 0 {
		return false, false
	}
	th := pkt.TransportHeader().Slice()
	if len(th) < 4 {
		var ok bool
		if th, ok = pkt.Data().PullUp(4); !ok {
			return false, false
		}
	}
	dst := uint16(th[2])<<8 | uint16(th[3])
	for _, p := range m.ports {
		if p == dst {
			return true, false
		}
	}
	return false, false
}

// refuseTarget counts a refusal against the gateway and the device, then rejects the packet with an ICMP
// "administratively prohibited" so the device fails fast.
type refuseTarget struct {
	g      *Gateway
	reject stack.Target
}

func (t *refuseTarget) Action(pkt *stack.PacketBuffer, hook stack.Hook, r *stack.Route, ep stack.AddressableEndpoint) (stack.RuleVerdict, int) {
	t.g.blocked.Add(1)
	if nh := pkt.NetworkHeader().Slice(); len(nh) >= header.IPv4MinimumSize {
		if mac, ok := t.g.dhcp.macFor(addrOf(header.IPv4(nh).SourceAddress())); ok {
			t.g.devs.get(mac).denied.Add(1)
		}
	}
	if t.reject != nil {
		t.reject.Action(pkt, hook, r, ep)
	}
	return stack.RuleDrop, 0
}

func prefixFilter(p netip.Prefix) stack.IPHeaderFilter {
	f := stack.EmptyFilter4()
	f.Dst = tcpip.AddrFrom4(p.Masked().Addr().As4())
	f.DstMask = tcpip.AddrFrom4(maskOf(p.Bits()))
	return f
}

func maskOf(bits int) [4]byte {
	var m [4]byte
	for i := 0; i < 4; i++ {
		n := min(8, max(0, bits-8*i))
		m[i] = byte(0xff << (8 - n))
	}
	return m
}

// firewallTable compiles the policy and the gateway's own configuration into the filter table.
func (g *Gateway) firewallTable(c *compiledPolicy) stack.Table {
	var rules []stack.Rule
	accept := &stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}
	var rejecter stack.Target
	if rh, ok := g.stack.NetworkProtocolInstance(ipv4.ProtocolNumber).(stack.RejectIPv4WithHandler); ok {
		rejecter = &stack.RejectIPv4Target{Handler: rh, RejectWith: stack.RejectIPv4WithICMPAdminProhibited}
	}
	refuse := &refuseTarget{g: g, reject: rejecter}
	add := func(f stack.IPHeaderFilter, m []stack.Matcher, t stack.Target) {
		rules = append(rules, stack.Rule{Filter: f, Matchers: m, Target: t})
	}

	// Traffic for the gateway itself, and the DHCP broadcast, is never filtered.
	add(prefixFilter(netip.PrefixFrom(g.cfg.Address.Addr(), 32)), nil, accept)
	add(prefixFilter(netip.MustParsePrefix("255.255.255.255/32")), nil, accept)

	block := func(rule DeviceRule, who []stack.Matcher) {
		who = append(append([]stack.Matcher(nil), who...), newFlowMatcher{})
		if rule.Deny {
			add(stack.EmptyFilter4(), who, refuse)
			return
		}
		switch {
		case !rule.AllowPrivate && !g.cfg.AllowPrivate:
			for _, p := range blockedPrefixes {
				add(prefixFilter(p), who, refuse)
			}
		case rule.AllowPrivate && !g.cfg.AllowPrivate:
			for _, p := range hardBlocked {
				add(prefixFilter(p), who, refuse)
			}
		}
		if len(rule.BlockPorts) > 0 {
			add(stack.EmptyFilter4(), append(append([]stack.Matcher(nil), who...), portMatcher{ports: rule.BlockPorts}), refuse)
		}
		for _, n := range rule.BlockNets {
			if n.Addr().Is4() {
				add(prefixFilter(n), who, refuse)
			}
		}
	}
	var def DeviceRule
	if c != nil {
		for mac, r := range c.byMAC {
			who := []stack.Matcher{macMatcher{g: g, mac: mac}}
			block(r, who)
			// A device with its own rule is judged by it alone.
			add(stack.EmptyFilter4(), who, accept)
		}
		def = c.Default
	}
	block(def, nil)

	in := len(rules)
	rules = append(rules,
		stack.Rule{Filter: stack.EmptyFilter4(), Target: accept}, // Input policy: accept
		stack.Rule{Filter: stack.EmptyFilter4(), Target: accept}, // Forward
		stack.Rule{Filter: stack.EmptyFilter4(), Target: accept}, // Output
		stack.Rule{Filter: stack.EmptyFilter4(), Target: &stack.ErrorTarget{NetworkProtocol: header.IPv4ProtocolNumber}})
	return stack.Table{
		Rules:         rules,
		BuiltinChains: [stack.NumHooks]int{stack.Prerouting: stack.HookUnset, stack.Input: 0, stack.Forward: in + 1, stack.Output: in + 2, stack.Postrouting: stack.HookUnset},
		Underflows:    [stack.NumHooks]int{stack.Prerouting: stack.HookUnset, stack.Input: in, stack.Forward: in + 1, stack.Output: in + 2, stack.Postrouting: stack.HookUnset},
	}
}

// dnsRedirect matches DNS (TCP and UDP port 53) while the DNS filter is on.
type dnsRedirect struct {
	g *Gateway
	p portMatcher
}

func (m dnsRedirect) Match(h stack.Hook, pkt *stack.PacketBuffer, in, out string) (bool, bool) {
	if !m.g.dnsOn() {
		return false, false
	}
	return m.p.Match(h, pkt, in, out)
}

// natTable redirects every device's DNS to the gateway's own resolver port, whatever resolver the device was
// given. Conntrack reverses the rewrite on the way back, so the answer still comes from the address the device
// asked.
func (g *Gateway) natTable() stack.Table {
	accept := func() stack.Rule {
		return stack.Rule{Filter: stack.EmptyFilter4(), Target: &stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}}
	}
	rules := []stack.Rule{
		{Filter: stack.EmptyFilter4(), Matchers: []stack.Matcher{dnsRedirect{g: g, p: portMatcher{ports: []uint16{53}}}},
			Target: &stack.RedirectTarget{Port: 53, NetworkProtocol: header.IPv4ProtocolNumber}},
		accept(), // Prerouting policy
		accept(), // Input
		accept(), // Output
		accept(), // Postrouting
		{Filter: stack.EmptyFilter4(), Target: &stack.ErrorTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
	}
	return stack.Table{
		Rules:         rules,
		BuiltinChains: [stack.NumHooks]int{stack.Prerouting: 0, stack.Input: 2, stack.Forward: stack.HookUnset, stack.Output: 3, stack.Postrouting: 4},
		Underflows:    [stack.NumHooks]int{stack.Prerouting: 1, stack.Input: 2, stack.Forward: stack.HookUnset, stack.Output: 3, stack.Postrouting: 4},
	}
}

// installFirewall loads the filter and NAT tables into the stack.
func (g *Gateway) installFirewall() {
	it := g.stack.IPTables()
	it.ForceReplaceTable(stack.FilterID, g.firewallTable(g.policy.Load()), false)
	if g.cfg.DNSFilter != nil {
		it.ForceReplaceTable(stack.NATID, g.natTable(), false)
	}
}
