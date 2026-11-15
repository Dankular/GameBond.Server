package l2gw

import (
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
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
	src, ok := sourceAddress(pkt)
	if !ok {
		return false, false
	}
	mac, ok := m.g.macForIP(src)
	return ok && mac == m.mac, false
}

func sourceAddress(pkt *stack.PacketBuffer) (netip.Addr, bool) {
	nh := pkt.NetworkHeader().Slice()
	switch pkt.NetworkProtocolNumber {
	case header.IPv4ProtocolNumber:
		if len(nh) < header.IPv4MinimumSize {
			return netip.Addr{}, false
		}
		return addrOf(header.IPv4(nh).SourceAddress()), true
	case header.IPv6ProtocolNumber:
		if len(nh) < header.IPv6MinimumSize {
			return netip.Addr{}, false
		}
		return netip.AddrFrom16([16]byte(nh[8:24])), true
	default:
		return netip.Addr{}, false
	}
}

// newFlowMatcher matches the packets that start something: a TCP SYN without ACK, and any non-TCP packet. A rule
// that carries it refuses new connections and leaves established TCP connections alone, which is how a policy
// change applies "to the next flow" without cutting one that is already open.
type newFlowMatcher struct{}

func (newFlowMatcher) Match(_ stack.Hook, pkt *stack.PacketBuffer, _, _ string) (bool, bool) {
	if pkt.NetworkProtocolNumber != header.IPv4ProtocolNumber && pkt.NetworkProtocolNumber != header.IPv6ProtocolNumber {
		return false, false
	}
	if pkt.TransportProtocolNumber != header.TCPProtocolNumber {
		return true, false
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
	if p := pkt.TransportProtocolNumber; p != header.TCPProtocolNumber && p != header.UDPProtocolNumber {
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
	g       *Gateway
	reject4 stack.Target
	reject6 stack.Target
}

func (t *refuseTarget) Action(pkt *stack.PacketBuffer, hook stack.Hook, r *stack.Route, ep stack.AddressableEndpoint) (stack.RuleVerdict, int) {
	t.g.blocked.Add(1)
	if src, ok := sourceAddress(pkt); ok {
		if mac, ok := t.g.macForIP(src); ok {
			t.g.devs.get(mac).denied.Add(1)
		}
	}
	reject := t.reject4
	if pkt.NetworkProtocolNumber == header.IPv6ProtocolNumber {
		reject = t.reject6
	}
	if reject != nil {
		reject.Action(pkt, hook, r, ep)
	}
	return stack.RuleDrop, 0
}

func prefixFilter(p netip.Prefix) stack.IPHeaderFilter {
	if p.Addr().Is4() {
		f := stack.EmptyFilter4()
		f.Dst = tcpip.AddrFrom4(p.Masked().Addr().As4())
		f.DstMask = tcpip.AddrFrom4(maskOf(p.Bits()))
		return f
	}
	f := stack.EmptyFilter6()
	f.Dst = tcpip.AddrFrom16(p.Masked().Addr().As16())
	f.DstMask = tcpip.AddrFrom16(maskOf16(p.Bits()))
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

func maskOf16(bits int) [16]byte {
	var m [16]byte
	for i := 0; i < 16; i++ {
		n := min(8, max(0, bits-8*i))
		m[i] = byte(0xff << (8 - n))
	}
	return m
}

// firewallTable compiles the policy and the gateway's own configuration into the filter table.
func (g *Gateway) firewallTable(c *compiledPolicy) stack.Table {
	var rules []stack.Rule
	accept4 := &stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}
	accept6 := &stack.AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber}
	var reject4, reject6 stack.Target
	if rh, ok := g.stack.NetworkProtocolInstance(ipv4.ProtocolNumber).(stack.RejectIPv4WithHandler); ok {
		reject4 = &stack.RejectIPv4Target{Handler: rh, RejectWith: stack.RejectIPv4WithICMPAdminProhibited}
	}
	if rh, ok := g.stack.NetworkProtocolInstance(ipv6.ProtocolNumber).(stack.RejectIPv6WithHandler); ok {
		reject6 = &stack.RejectIPv6Target{Handler: rh, RejectWith: stack.RejectIPv6WithICMPAdminProhibited}
	}
	refuse := &refuseTarget{g: g, reject4: reject4, reject6: reject6}
	add := func(f stack.IPHeaderFilter, m []stack.Matcher, t stack.Target) {
		rules = append(rules, stack.Rule{Filter: f, Matchers: m, Target: t})
	}

	// Traffic for the gateway itself, and the DHCP broadcast, is never filtered.
	add(prefixFilter(netip.PrefixFrom(g.cfg.Address.Addr(), 32)), nil, accept4)
	add(prefixFilter(netip.MustParsePrefix("255.255.255.255/32")), nil, accept4)
	if g.cfg.IPv6Address.IsValid() {
		add(prefixFilter(netip.PrefixFrom(g.cfg.IPv6Address.Addr(), 128)), nil, accept6)
	}

	block := func(rule DeviceRule, who []stack.Matcher) {
		who = append(append([]stack.Matcher(nil), who...), newFlowMatcher{})
		if rule.Deny {
			add(stack.EmptyFilter4(), who, refuse)
			if g.cfg.IPv6Address.IsValid() {
				add(stack.EmptyFilter6(), who, refuse)
			}
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
			if g.cfg.IPv6Address.IsValid() {
				add(stack.EmptyFilter6(), append(append([]stack.Matcher(nil), who...), portMatcher{ports: rule.BlockPorts}), refuse)
			}
		}
		for _, n := range rule.BlockNets {
			if n.Addr().Is4() || g.cfg.IPv6Address.IsValid() {
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
			add(stack.EmptyFilter4(), who, accept4)
			if g.cfg.IPv6Address.IsValid() {
				add(stack.EmptyFilter6(), who, accept6)
			}
		}
		def = c.Default
	}
	block(def, nil)

	in := len(rules)
	rules = append(rules,
		stack.Rule{Filter: stack.EmptyFilter4(), Target: accept4}, // Input policy: accept
		stack.Rule{Filter: stack.EmptyFilter4(), Target: accept4}, // Forward
		stack.Rule{Filter: stack.EmptyFilter4(), Target: accept4}, // Output
		stack.Rule{Filter: stack.EmptyFilter4(), Target: &stack.ErrorTarget{NetworkProtocol: header.IPv4ProtocolNumber}})
	if g.cfg.IPv6Address.IsValid() {
		rules = append(rules,
			stack.Rule{Filter: stack.EmptyFilter6(), Target: accept6},
			stack.Rule{Filter: stack.EmptyFilter6(), Target: accept6},
			stack.Rule{Filter: stack.EmptyFilter6(), Target: accept6},
			stack.Rule{Filter: stack.EmptyFilter6(), Target: &stack.ErrorTarget{NetworkProtocol: header.IPv6ProtocolNumber}})
	}
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
	redir := dnsRedirect{g: g, p: portMatcher{ports: []uint16{53}}}
	rules := []stack.Rule{
		{Filter: stack.EmptyFilter4(), Matchers: []stack.Matcher{redir}, Target: &stack.RedirectTarget{Port: 53, NetworkProtocol: header.IPv4ProtocolNumber}},
		{Filter: stack.EmptyFilter4(), Target: &stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}}, // Prerouting policy
		{Filter: stack.EmptyFilter4(), Target: &stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}}, // Input
		{Filter: stack.EmptyFilter4(), Target: &stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}}, // Output
		{Filter: stack.EmptyFilter4(), Target: &stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}}, // Postrouting
		{Filter: stack.EmptyFilter4(), Target: &stack.ErrorTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
	}
	chains := [stack.NumHooks]int{0, 2, stack.HookUnset, 3, 4}
	underflows := [stack.NumHooks]int{1, 2, stack.HookUnset, 3, 4}
	if g.cfg.IPv6Address.IsValid() {
		rules = []stack.Rule{
			{Filter: stack.EmptyFilter4(), Matchers: []stack.Matcher{redir}, Target: &stack.RedirectTarget{Port: 53, NetworkProtocol: header.IPv4ProtocolNumber}},
			{Filter: stack.EmptyFilter6(), Matchers: []stack.Matcher{redir}, Target: &stack.RedirectTarget{Port: 53, NetworkProtocol: header.IPv6ProtocolNumber}},
			{Filter: stack.EmptyFilter4(), Target: &stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
			{Filter: stack.EmptyFilter6(), Target: &stack.AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
			{Filter: stack.EmptyFilter4(), Target: &stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
			{Filter: stack.EmptyFilter6(), Target: &stack.AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
			{Filter: stack.EmptyFilter4(), Target: &stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
			{Filter: stack.EmptyFilter6(), Target: &stack.AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
			{Filter: stack.EmptyFilter4(), Target: &stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
			{Filter: stack.EmptyFilter6(), Target: &stack.AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
			{Filter: stack.EmptyFilter4(), Target: &stack.ErrorTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
			{Filter: stack.EmptyFilter6(), Target: &stack.ErrorTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
		}
		chains = [stack.NumHooks]int{0, 4, stack.HookUnset, 6, 8}
		underflows = [stack.NumHooks]int{2, 4, stack.HookUnset, 6, 8}
	}
	return stack.Table{
		Rules:         rules,
		BuiltinChains: chains,
		Underflows:    underflows,
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
