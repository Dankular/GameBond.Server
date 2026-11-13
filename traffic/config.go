// Package traffic classifies observed tunnel flows and evaluates application policies.
package traffic

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	pathpkg "path"
	"regexp"
	"strings"
)

const (
	MaxRules = 128
	MaxTerms = 32
)

var labelPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
var zoneNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,23}$`)

// Config is the domain and inspected URL policy block. It is independent of TLS interception.
type Config struct {
	Enabled bool   `json:"enabled"`
	Rules   []Rule `json:"rules"`
}

// Rule matches a domain suffix and, optionally, URL path prefixes.
type Rule struct {
	ID      string   `json:"id"`
	Enabled bool     `json:"enabled"`
	Action  string   `json:"action"`
	Domains []string `json:"domains"`
	Paths   []string `json:"paths,omitempty"`
	Zones   []string `json:"zones,omitempty"`
}

// Parse decodes a strict traffic policy configuration.
func Parse(raw json.RawMessage) (Config, error) {
	var c Config
	b := bytes.TrimSpace(raw)
	if len(b) == 0 || string(b) == "null" {
		return c, nil
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, fmt.Errorf("traffic: %w", err)
	}
	return c, c.Validate()
}

func (c Config) Validate() error {
	if len(c.Rules) > MaxRules {
		return fmt.Errorf("traffic: at most %d rules", MaxRules)
	}
	seen := make(map[string]bool, len(c.Rules))
	for i, r := range c.Rules {
		at := fmt.Sprintf("traffic: rule %d", i+1)
		if !labelPattern.MatchString(r.ID) || seen[r.ID] {
			return fmt.Errorf("%s: id must be unique and use lowercase letters, digits, dot, underscore or hyphen", at)
		}
		seen[r.ID] = true
		if r.Action != "allow" && r.Action != "deny" && r.Action != "log" {
			return fmt.Errorf("%s: action must be allow, deny or log", at)
		}
		n := len(r.Domains)
		if n == 0 || n > MaxTerms {
			return fmt.Errorf("%s: provide between 1 and %d match terms", at, MaxTerms)
		}
		for _, domain := range r.Domains {
			domain = strings.TrimPrefix(strings.ToLower(strings.TrimSuffix(domain, ".")), "*.")
			if len(domain) == 0 || len(domain) > 253 || net.ParseIP(domain) != nil || strings.ContainsAny(domain, "/: ") {
				return fmt.Errorf("%s: %q is not a domain suffix", at, domain)
			}
			for _, label := range strings.Split(domain, ".") {
				if len(label) == 0 || len(label) > 63 || !labelPattern.MatchString(label) || strings.Contains(label, "_") {
					return fmt.Errorf("%s: %q is not a valid domain suffix", at, domain)
				}
			}
		}
		if len(r.Paths) > 32 {
			return fmt.Errorf("%s: at most 32 URL paths", at)
		}
		for _, path := range r.Paths {
			if len(path) == 0 || len(path) > 256 || path[0] != '/' || strings.ContainsAny(path, "\r\n\x00") {
				return fmt.Errorf("%s: URL paths must start with / and be at most 256 characters", at)
			}
		}
		if len(r.Paths) > 0 && len(r.Domains) == 0 {
			return fmt.Errorf("%s: URL path rules need at least one domain", at)
		}
		if len(r.Zones) > 32 {
			return fmt.Errorf("%s: at most 32 zones", at)
		}
		zoneSeen := map[string]bool{}
		for _, zone := range r.Zones {
			if !zoneNamePattern.MatchString(zone) || zoneSeen[zone] {
				return fmt.Errorf("%s: zone names must be unique lowercase letters, digits and underscores", at)
			}
			zoneSeen[zone] = true
		}
	}
	return nil
}

// MatchDomain returns the first explicit domain rule match. A leading "*." is equivalent to a suffix match.
func (c Config) MatchDomain(name string) (string, string, bool) {
	return c.MatchDomainFor(netip.Addr{}, name, nil)
}

// MatchDomainFor additionally constrains a domain rule to any of its configured device zones.
func (c Config) MatchDomainFor(device netip.Addr, name string, members map[string]map[netip.Addr]bool) (string, string, bool) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if !c.Enabled {
		return "", "", false
	}
	for _, r := range c.Rules {
		if !r.Enabled {
			continue
		}
		if !inZones(device, r.Zones, members) {
			continue
		}
		for _, pattern := range r.Domains {
			if len(r.Paths) > 0 {
				continue
			}
			pattern = strings.TrimPrefix(strings.ToLower(strings.TrimSuffix(pattern, ".")), "*.")
			if name == pattern || strings.HasSuffix(name, "."+pattern) {
				return r.ID, r.Action, true
			}
		}
	}
	return "", "", false
}

// MatchURL applies hostname and optional path rules after a TLS connection is inspected.
func (c Config) MatchURL(host, path string) (string, string, bool) {
	return c.MatchURLFor(netip.Addr{}, host, path, nil)
}

// MatchURLFor evaluates a path rule for a client device and its current zone membership.
func (c Config) MatchURLFor(device netip.Addr, host, path string, members map[string]map[netip.Addr]bool) (string, string, bool) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	paths := []string{path}
	if decoded, err := url.PathUnescape(path); err == nil {
		paths = append(paths, decoded, pathpkg.Clean(decoded), pathpkg.Clean(strings.ReplaceAll(decoded, "\\", "/")))
	}
	if !c.Enabled {
		return "", "", false
	}
	for _, r := range c.Rules {
		if !r.Enabled || len(r.Paths) == 0 {
			continue
		}
		if !inZones(device, r.Zones, members) {
			continue
		}
		for _, pattern := range r.Domains {
			pattern = strings.TrimPrefix(strings.ToLower(strings.TrimSuffix(pattern, ".")), "*.")
			if host != pattern && !strings.HasSuffix(host, "."+pattern) {
				continue
			}
			for _, prefix := range r.Paths {
				for _, candidate := range paths {
					if strings.HasPrefix(candidate, prefix) {
						return r.ID, r.Action, true
					}
				}
			}
		}
	}
	return "", "", false
}

func inZones(device netip.Addr, zones []string, members map[string]map[netip.Addr]bool) bool {
	if len(zones) == 0 {
		return true
	}
	for _, zone := range zones {
		if members[zone][device] {
			return true
		}
	}
	return false
}

func (c Config) HasPathRules() bool {
	for _, r := range c.Rules {
		if r.Enabled && len(r.Paths) > 0 {
			return true
		}
	}
	return false
}

// InspectionConfig controls optional TLS interception.
type InspectionConfig struct {
	Enabled          bool   `json:"enabled"`
	MaxSessions      int    `json:"max_sessions"`
	ExhaustionAction string `json:"exhaustion_action"`
}

func (c *InspectionConfig) Normalize() {
	if c.MaxSessions == 0 {
		c.MaxSessions = 64
	}
	if c.ExhaustionAction == "" {
		c.ExhaustionAction = "deny"
	}
}

func (c InspectionConfig) Validate() error {
	if c.MaxSessions < 1 || c.MaxSessions > 512 {
		return errors.New("inspection: max_sessions must be between 1 and 512")
	}
	if c.ExhaustionAction != "bypass" && c.ExhaustionAction != "deny" {
		return errors.New("inspection: exhaustion_action must be bypass or deny")
	}
	return nil
}
