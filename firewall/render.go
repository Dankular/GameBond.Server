package firewall

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// Table is the nftables table this package owns.
const Table = "gamebond_fw"

// Inputs are the things a configuration cannot say for itself.
type Inputs struct {
	Tunnel  string         // the TUN interface, gamebond0
	Gateway string         // the server's tunnel address, 10.77.0.1
	Geo     []netip.Prefix // addresses of the selected countries (empty: not loaded)
	Regions map[string][]netip.Prefix
	Blocked []Block // active intrusion prevention blocks, kept across a re-render
}

// Block is an address blocked until Remaining runs out.
type Block struct {
	IP        string
	Remaining time.Duration
}

func (in Inputs) tunnel() string {
	if in.Tunnel == "" {
		return "gamebond0"
	}
	return in.Tunnel
}

func (in Inputs) gateway() string {
	if in.Gateway == "" {
		return "10.77.0.1"
	}
	return in.Gateway
}

// protectedAddress is never blocked by prevention: blocking the client PC or the server would end the tunnel.
func protectedAddress(ip string) bool {
	return ip == "10.77.0.1" || ip == "10.77.0.2" || ip == "10.77.0.0"
}

// Render produces the nft script that replaces the table. With the firewall off it only removes the table.
// warnings lists protections that could not be installed (for example a country list that has not loaded).
func Render(c Config, in Inputs) (script string, warnings []string, err error) {
	c = c.normalised()
	if err := c.Validate(); err != nil {
		return "", nil, err
	}
	var b strings.Builder
	// add then delete: replaces the table in one transaction whether or not it exists.
	fmt.Fprintf(&b, "add table ip %s\ndelete table ip %s\n", Table, Table)
	if !c.Enabled {
		return b.String(), nil, nil
	}
	tun, gw := in.tunnel(), in.gateway()
	fmt.Fprintf(&b, "table ip %s {\n", Table)

	// Sets.
	fmt.Fprintf(&b, "\tset ips_block {\n\t\ttype ipv4_addr\n\t\tflags timeout\n")
	var blocks []string
	for _, bl := range in.Blocked {
		if protectedAddress(bl.IP) || bl.Remaining <= time.Second {
			continue
		}
		blocks = append(blocks, fmt.Sprintf("%s timeout %ds", bl.IP, int(bl.Remaining.Seconds())))
	}
	if len(blocks) > 0 {
		fmt.Fprintf(&b, "\t\telements = { %s }\n", strings.Join(blocks, ", "))
	}
	b.WriteString("\t}\n")
	geoOn := c.Countries.Mode != "off"
	if geoOn {
		b.WriteString("\tset geo {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\tauto-merge\n")
		if len(in.Geo) > 0 {
			els := make([]string, len(in.Geo))
			for i, p := range in.Geo {
				els[i] = p.String()
			}
			fmt.Fprintf(&b, "\t\telements = { %s }\n", strings.Join(els, ", "))
		}
		b.WriteString("\t}\n")
		if len(in.Geo) == 0 {
			warnings = append(warnings, "the country lists are not loaded yet, so the country filter is not enforcing anything")
		}
	}
	for _, z := range c.Zones {
		members := append([]string(nil), z.Members...)
		sort.Strings(members)
		fmt.Fprintf(&b, "\tset zone_%s {\n\t\ttype ipv4_addr\n\t\telements = { %s }\n\t}\n", z.Name, strings.Join(members, ", "))
	}
	regionCodes := map[string]bool{}
	for _, r := range c.Rules {
		if !r.Enabled {
			continue
		}
		for _, code := range r.Regions {
			if regionCodes[code] {
				continue
			}
			regionCodes[code] = true
			prefixes := in.Regions[code]
			if len(prefixes) == 0 {
				warnings = append(warnings, "region "+code+" is not loaded; rules that depend on it cannot match")
			}
			els := make([]string, len(prefixes))
			for i, p := range prefixes {
				els[i] = p.String()
			}
			sort.Strings(els)
			fmt.Fprintf(&b, "\tset region_%s {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\tauto-merge\n", code)
			if len(els) > 0 {
				fmt.Fprintf(&b, "\t\telements = { %s }\n", strings.Join(els, ", "))
			}
			b.WriteString("\t}\n")
		}
	}

	// Input: the server's own services.
	b.WriteString("\tchain input {\n\t\ttype filter hook input priority -10; policy accept;\n")
	b.WriteString("\t\tct state invalid counter drop comment \"invalid\"\n")
	b.WriteString("\t\tip saddr @ips_block counter drop comment \"ips\"\n")
	b.WriteString("\t\tct state established,related accept\n")
	b.WriteString("\t\tiifname \"lo\" accept\n")
	if c.ServerProtected() {
		fmt.Fprintf(&b, "\t\tiifname \"%s\" udp dport 4436 accept\n", tun)
		if c.InspectTLS {
			fmt.Fprintf(&b, "\t\tiifname \"%s\" ct status dnat tcp dport %d accept\n", tun, 9445)
		}
		fmt.Fprintf(&b, "\t\tiifname \"%s\" ip daddr %s udp dport 53 accept\n", tun, gw)
		fmt.Fprintf(&b, "\t\tiifname \"%s\" ip daddr %s tcp dport 53 accept\n", tun, gw)
		fmt.Fprintf(&b, "\t\tiifname \"%s\" icmp type echo-request accept\n", tun)
		fmt.Fprintf(&b, "\t\tiifname \"%s\" counter drop comment \"protect\"\n", tun)
	}
	b.WriteString("\t}\n")

	// Forward.
	fmt.Fprintf(&b, "\tchain forward {\n\t\ttype filter hook forward priority -10; policy accept;\n")
	b.WriteString("\t\tct state invalid counter drop comment \"invalid\"\n")
	b.WriteString("\t\tip saddr @ips_block counter drop comment \"ips\"\n")
	b.WriteString("\t\tip daddr @ips_block counter drop comment \"ips\"\n")
	out := fmt.Sprintf("iifname \"%s\" oifname != \"%s\"", tun, tun)
	inb := fmt.Sprintf("iifname != \"%s\" oifname \"%s\"", tun, tun)
	both := fmt.Sprintf("iifname \"%s\" oifname \"%s\"", tun, tun)
	countryOut := c.Countries.Direction == "outbound" || c.Countries.Direction == "both"
	countryIn := c.Countries.Direction == "inbound" || c.Countries.Direction == "both"
	// Country filter. Block mode also cuts connections that are already open; allow-only mode is skipped while
	// the lists are empty, because it would otherwise block everything.
	if geoOn && c.Countries.Mode == "block" {
		if countryOut {
			fmt.Fprintf(&b, "\t\t%s ip daddr @geo counter drop comment \"geo\"\n", out)
		}
		if countryIn {
			fmt.Fprintf(&b, "\t\t%s ip saddr @geo counter drop comment \"geo\"\n", inb)
		}
	}
	if geoOn && c.Countries.Mode == "allow" && len(in.Geo) > 0 {
		if countryOut {
			fmt.Fprintf(&b, "\t\t%s ip daddr != @geo counter drop comment \"geo\"\n", out)
		}
		if countryIn {
			fmt.Fprintf(&b, "\t\t%s ip saddr != @geo counter drop comment \"geo\"\n", inb)
		}
	}
	b.WriteString("\t\tct state established,related accept\n")
	if c.BlockDoT {
		fmt.Fprintf(&b, "\t\tiifname \"%s\" tcp dport 853 ct state new counter drop comment \"dot\"\n", tun)
	}
	for _, r := range c.Rules {
		if !r.Enabled {
			continue
		}
		m, err := r.match(tun)
		if err != nil {
			return "", nil, err
		}
		verdict := "accept"
		if r.Action == "deny" {
			verdict = "drop"
		}
		fmt.Fprintf(&b, "\t\tct state new %s counter %s comment \"%s\"\n", m, verdict, r.ID)
	}
	for _, p := range c.Segmentation.Allow {
		fmt.Fprintf(&b, "\t\tct state new %s ip saddr @zone_%s ip daddr @zone_%s counter accept comment \"seg\"\n", both, p.From, p.To)
	}
	if c.Segmentation.IsolateDevices {
		fmt.Fprintf(&b, "\t\tct state new %s counter drop comment \"isolate\"\n", both)
	}
	if c.DefaultOutbound == "deny" {
		fmt.Fprintf(&b, "\t\tct state new %s counter drop comment \"default\"\n", out)
	}
	if c.DefaultInbound == "deny" {
		fmt.Fprintf(&b, "\t\tct state new %s counter drop comment \"default_in\"\n", inb)
	}
	b.WriteString("\t}\n")

	if c.ForceDNS {
		fmt.Fprintf(&b, "\tchain dns_redirect {\n\t\ttype nat hook prerouting priority -100; policy accept;\n")
		fmt.Fprintf(&b, "\t\tiifname \"%s\" ip daddr != %s udp dport 53 counter redirect to :53 comment \"dns\"\n", tun, gw)
		fmt.Fprintf(&b, "\t\tiifname \"%s\" ip daddr != %s tcp dport 53 counter redirect to :53 comment \"dns\"\n", tun, gw)
		b.WriteString("\t}\n")
	}
	if c.InspectTLS {
		fmt.Fprintf(&b, "\tchain tls_redirect {\n\t\ttype nat hook prerouting priority -100; policy accept;\n")
		fmt.Fprintf(&b, "\t\tiifname \"%s\" ip daddr != 10.77.0.0/24 tcp dport 443 counter redirect to :9445 comment \"tls_inspect\"\n", tun)
		b.WriteString("\t}\n")
	}
	b.WriteString("}\n")
	return b.String(), warnings, nil
}

// match builds the nft match for a rule's direction, endpoints and protocol.
func (r Rule) match(tun string) (string, error) {
	var parts []string
	switch r.Direction {
	case "outbound":
		parts = append(parts, fmt.Sprintf("iifname \"%s\" oifname != \"%s\"", tun, tun))
	case "inbound":
		parts = append(parts, fmt.Sprintf("iifname != \"%s\" oifname \"%s\"", tun, tun))
	case "between":
		parts = append(parts, fmt.Sprintf("iifname \"%s\" oifname \"%s\"", tun, tun))
	default:
		return "", fmt.Errorf("rule %s: bad direction", r.ID)
	}
	ep := func(kind, v string) string {
		switch {
		case v == "any":
			return ""
		case strings.HasPrefix(v, "zone:"):
			return fmt.Sprintf("ip %s @zone_%s", kind, strings.TrimPrefix(v, "zone:"))
		}
		return fmt.Sprintf("ip %s %s", kind, v)
	}
	if s := ep("saddr", r.Source); s != "" {
		parts = append(parts, s)
	}
	if d := ep("daddr", r.Dest); d != "" {
		parts = append(parts, d)
	}
	if len(r.Regions) > 0 {
		field := "daddr"
		if r.Direction == "inbound" {
			field = "saddr"
		}
		regions := make([]string, 0, len(r.Regions))
		for _, code := range r.Regions {
			regions = append(regions, fmt.Sprintf("ip %s @region_%s", field, code))
		}
		parts = append(parts, "("+strings.Join(regions, " or ")+")")
	}
	if len(r.Apps) > 0 {
		byProto := map[string]map[string]bool{}
		for _, app := range r.Apps {
			v := appPorts[app]
			protos := []string{v.proto}
			if app == "dns" {
				protos = []string{"tcp", "udp"}
			}
			for _, proto := range protos {
				if byProto[proto] == nil {
					byProto[proto] = map[string]bool{}
				}
				for _, port := range strings.Split(v.ports, ", ") {
					byProto[proto][port] = true
				}
			}
		}
		appMatches := make([]string, 0, len(byProto))
		for _, proto := range []string{"tcp", "udp"} {
			ports := byProto[proto]
			if len(ports) == 0 {
				continue
			}
			list := make([]string, 0, len(ports))
			for port := range ports {
				list = append(list, port)
			}
			sort.Strings(list)
			appMatches = append(appMatches, fmt.Sprintf("meta l4proto %s %s dport { %s }", proto, proto, strings.Join(list, ", ")))
		}
		parts = append(parts, "("+strings.Join(appMatches, " or ")+")")
	}
	switch r.Proto {
	case "icmp":
		parts = append(parts, "ip protocol icmp")
	case "tcp", "udp":
		if len(r.Ports) == 0 {
			parts = append(parts, "meta l4proto "+r.Proto)
		} else if len(r.Ports) == 1 {
			parts = append(parts, fmt.Sprintf("%s dport %s", r.Proto, r.Ports[0]))
		} else {
			parts = append(parts, fmt.Sprintf("%s dport { %s }", r.Proto, strings.Join(r.Ports, ", ")))
		}
	}
	return strings.Join(parts, " "), nil
}
