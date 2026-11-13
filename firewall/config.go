// Package firewall is the server's stateful firewall for tunnel traffic. It owns one nftables table
// (gamebond_fw) that it replaces atomically, so rules change live and never leave a half-applied ruleset.
//
// Behaviour, in the order a forwarded packet meets it:
//
//  1. invalid connection state: dropped
//  2. addresses blocked by intrusion prevention, and (in block mode) blocked countries: dropped, even on a
//     connection that is already established, so a block takes effect at once
//  3. established and related connections: accepted (the stateful part: replies need no rule)
//  4. new connections: your rules in order, then segmentation, then the default policy
//
// Rules apply to new connections only. Changing a rule does not cut a connection that is already open,
// except by blocking its address or country; Manager.FlushConnections ends open connections when conntrack
// is available.
package firewall

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

const (
	MaxRules     = 200
	MaxZones     = 32
	MaxZoneSize  = 64
	MaxPairs     = 64
	MaxCountries = 40
	maxComment   = 64
)

// Config is the "firewall" part of the security settings.
type Config struct {
	Enabled bool `json:"enabled"`
	// DefaultOutbound is what happens to a new connection from a tunnel device to the internet that no rule
	// matched: "allow" (default) or "deny".
	DefaultOutbound string `json:"default_outbound"`
	// DefaultInbound is what happens to a new connection from the internet to a tunnel device (what reverse port
	// forwarding delivers) that no rule matched: "allow" (default, so forwarded ports keep working) or "deny".
	DefaultInbound string `json:"default_inbound"`
	// ProtectServer drops everything tunnel devices send to the server itself except the services they need
	// (the stream gateway, DNS and ping). Default true.
	ProtectServer *bool `json:"protect_server,omitempty"`
	// BlockDoT drops DNS over TLS (port 853) from tunnel devices, so they cannot go around the DNS filter.
	BlockDoT bool `json:"block_dot"`
	// ForceDNS redirects every DNS query from a tunnel device to the server's filtering resolver.
	ForceDNS     bool         `json:"force_dns"`
	Segmentation Segmentation `json:"segmentation"`
	Zones        []Zone       `json:"zones"`
	Rules        []Rule       `json:"rules"`
	Countries    Countries    `json:"countries"`
}

// Segmentation controls traffic between devices on the tunnel network.
type Segmentation struct {
	// IsolateDevices stops tunnel devices reaching each other (zones listed in Allow excepted).
	IsolateDevices bool       `json:"isolate_devices"`
	Allow          []ZonePair `json:"allow"`
}

// ZonePair allows new connections from one zone to another (replies are always allowed).
type ZonePair struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// Zone is a named group of tunnel addresses. 10.77.0.2 is the client PC itself.
type Zone struct {
	Name    string   `json:"name"`
	Members []string `json:"members"`
}

// Rule is one firewall rule. Source and Dest are "any", an IPv4 address, a CIDR or "zone:<name>".
type Rule struct {
	ID        string   `json:"id"`
	Enabled   bool     `json:"enabled"`
	Action    string   `json:"action"`    // allow or deny
	Direction string   `json:"direction"` // outbound (device to internet, default), inbound (internet to device), between (device to device)
	Source    string   `json:"source"`
	Dest      string   `json:"dest"`
	Proto     string   `json:"proto"` // any, tcp, udp or icmp
	Ports     []string `json:"ports"` // destination ports: "443" or "8000-8100"; tcp and udp only
	Comment   string   `json:"comment"`
}

// Countries blocks or allows traffic by country of the remote address.
type Countries struct {
	Mode      string   `json:"mode"`      // off, block or allow (only the listed countries)
	Codes     []string `json:"codes"`     // ISO 3166 alpha-2
	Direction string   `json:"direction"` // outbound, inbound or both
}

var (
	idPattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,23}$`)
	zonePattern    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,23}$`)
	countryPattern = regexp.MustCompile(`^[A-Z]{2}$`)
	commentPattern = regexp.MustCompile(`^[A-Za-z0-9 ._,:()/+-]*$`)
)

// Parse decodes and validates a firewall configuration. Unknown fields are refused so a typo cannot silently
// leave a protection switched off.
func Parse(raw json.RawMessage) (Config, error) {
	var c Config
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return c.normalised(), nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("firewall: %w", err)
	}
	c = c.normalised()
	return c, c.Validate()
}

func (c Config) normalised() Config {
	if c.DefaultOutbound == "" {
		c.DefaultOutbound = "allow"
	}
	if c.DefaultInbound == "" {
		c.DefaultInbound = "allow"
	}
	if c.Countries.Mode == "" {
		c.Countries.Mode = "off"
	}
	if c.Countries.Direction == "" {
		c.Countries.Direction = "outbound"
	}
	for i := range c.Rules {
		if c.Rules[i].Direction == "" {
			c.Rules[i].Direction = "outbound"
		}
		if c.Rules[i].Source == "" {
			c.Rules[i].Source = "any"
		}
		if c.Rules[i].Dest == "" {
			c.Rules[i].Dest = "any"
		}
		if c.Rules[i].Proto == "" {
			c.Rules[i].Proto = "any"
		}
	}
	return c
}

// ServerProtected reports whether tunnel devices are kept away from the server's own services.
func (c Config) ServerProtected() bool { return c.ProtectServer == nil || *c.ProtectServer }

// tunnelAddr accepts the addresses the tunnel uses for devices and the client PC.
func tunnelAddr(s string) error {
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() || a.String() != s {
		return fmt.Errorf("%q is not an IPv4 address", s)
	}
	b := a.As4()
	if b[0] != 10 || b[1] != 77 || b[2] != 0 || b[3] < 2 || b[3] > 254 {
		return fmt.Errorf("%s is not a tunnel device address (10.77.0.2 to 10.77.0.254)", s)
	}
	return nil
}

// endpoint validates a rule's source or destination.
func (c Config) endpoint(s string, zones map[string]bool) error {
	switch {
	case s == "any":
		return nil
	case strings.HasPrefix(s, "zone:"):
		if !zones[strings.TrimPrefix(s, "zone:")] {
			return fmt.Errorf("%q names a zone that does not exist", s)
		}
		return nil
	case strings.Contains(s, "/"):
		p, err := netip.ParsePrefix(s)
		if err != nil || !p.Addr().Is4() || p.Masked() != p {
			return fmt.Errorf("%q is not an IPv4 network such as 192.0.2.0/24", s)
		}
		if p.Bits() == 0 {
			return fmt.Errorf("%q matches everything; use any", s)
		}
		return nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() || a.String() != s {
		return fmt.Errorf("%q is not any, an IPv4 address, a network or zone:<name>", s)
	}
	return nil
}

func portSpec(s string) error {
	lo, hi, isRange := strings.Cut(s, "-")
	a, err := strconv.Atoi(lo)
	if err != nil || a < 1 || a > 65535 || strconv.Itoa(a) != lo {
		return fmt.Errorf("%q is not a port or a range such as 8000-8100", s)
	}
	if isRange {
		b, err := strconv.Atoi(hi)
		if err != nil || b < a || b > 65535 || strconv.Itoa(b) != hi {
			return fmt.Errorf("%q is not a valid port range", s)
		}
	}
	return nil
}

// Validate checks every field.
func (c Config) Validate() error {
	if c.DefaultOutbound != "allow" && c.DefaultOutbound != "deny" {
		return errors.New("firewall: default_outbound must be allow or deny")
	}
	if c.DefaultInbound != "allow" && c.DefaultInbound != "deny" {
		return errors.New("firewall: default_inbound must be allow or deny")
	}
	zones := map[string]bool{}
	if len(c.Zones) > MaxZones {
		return fmt.Errorf("firewall: at most %d zones", MaxZones)
	}
	for _, z := range c.Zones {
		if !zonePattern.MatchString(z.Name) {
			return fmt.Errorf("firewall: zone name %q must be lowercase letters, digits and underscores, starting with a letter", z.Name)
		}
		if zones[z.Name] {
			return fmt.Errorf("firewall: zone %q is listed twice", z.Name)
		}
		zones[z.Name] = true
		if len(z.Members) == 0 || len(z.Members) > MaxZoneSize {
			return fmt.Errorf("firewall: zone %q needs between 1 and %d members", z.Name, MaxZoneSize)
		}
		seen := map[string]bool{}
		for _, m := range z.Members {
			if err := tunnelAddr(m); err != nil {
				return fmt.Errorf("firewall: zone %q: %w", z.Name, err)
			}
			if seen[m] {
				return fmt.Errorf("firewall: zone %q lists %s twice", z.Name, m)
			}
			seen[m] = true
		}
	}
	if len(c.Segmentation.Allow) > MaxPairs {
		return fmt.Errorf("firewall: at most %d segmentation exceptions", MaxPairs)
	}
	for _, p := range c.Segmentation.Allow {
		if !zones[p.From] || !zones[p.To] {
			return fmt.Errorf("firewall: segmentation exception %s to %s names a zone that does not exist", p.From, p.To)
		}
	}
	if len(c.Rules) > MaxRules {
		return fmt.Errorf("firewall: at most %d rules", MaxRules)
	}
	ids := map[string]bool{}
	for i, r := range c.Rules {
		at := fmt.Sprintf("firewall: rule %d", i+1)
		if !idPattern.MatchString(r.ID) {
			return fmt.Errorf("%s: id %q must be 1 to 24 lowercase letters, digits, hyphens or underscores", at, r.ID)
		}
		if ids[r.ID] {
			return fmt.Errorf("%s: id %q is used twice", at, r.ID)
		}
		ids[r.ID] = true
		if r.Action != "allow" && r.Action != "deny" {
			return fmt.Errorf("%s: action must be allow or deny", at)
		}
		switch r.Direction {
		case "outbound", "inbound", "between":
		default:
			return fmt.Errorf("%s: direction must be outbound, inbound or between", at)
		}
		if err := c.endpoint(r.Source, zones); err != nil {
			return fmt.Errorf("%s: source: %w", at, err)
		}
		if err := c.endpoint(r.Dest, zones); err != nil {
			return fmt.Errorf("%s: destination: %w", at, err)
		}
		switch r.Proto {
		case "any", "icmp":
			if len(r.Ports) > 0 {
				return fmt.Errorf("%s: ports need protocol tcp or udp", at)
			}
		case "tcp", "udp":
			if len(r.Ports) > 16 {
				return fmt.Errorf("%s: at most 16 ports", at)
			}
			for _, p := range r.Ports {
				if err := portSpec(p); err != nil {
					return fmt.Errorf("%s: %w", at, err)
				}
			}
		default:
			return fmt.Errorf("%s: protocol must be any, tcp, udp or icmp", at)
		}
		if len(r.Comment) > maxComment || !commentPattern.MatchString(r.Comment) {
			return fmt.Errorf("%s: the comment may use letters, digits, spaces and . , : ( ) / + - up to %d characters", at, maxComment)
		}
	}
	switch c.Countries.Mode {
	case "off", "block", "allow":
	default:
		return errors.New("firewall: countries mode must be off, block or allow")
	}
	switch c.Countries.Direction {
	case "outbound", "inbound", "both":
	default:
		return errors.New("firewall: countries direction must be outbound, inbound or both")
	}
	if len(c.Countries.Codes) > MaxCountries {
		return fmt.Errorf("firewall: at most %d countries", MaxCountries)
	}
	seen := map[string]bool{}
	for _, cc := range c.Countries.Codes {
		if !countryPattern.MatchString(cc) {
			return fmt.Errorf("firewall: %q is not a two-letter country code in capitals", cc)
		}
		if seen[cc] {
			return fmt.Errorf("firewall: country %s is listed twice", cc)
		}
		seen[cc] = true
	}
	if c.Countries.Mode != "off" && len(c.Countries.Codes) == 0 {
		return errors.New("firewall: choose at least one country, or switch the country filter off")
	}
	return nil
}
