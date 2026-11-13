// Package security ties the server's firewall, country filter, DNS filter and intrusion detection together behind one
// settings block that is validated as a whole and applied live, without restarting the server or dropping the tunnel.
package security

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Dankular/GameBond.Server/dnsfilter"
	"github.com/Dankular/GameBond.Server/firewall"
	"github.com/Dankular/GameBond.Server/ids"
	"github.com/Dankular/GameBond.Server/traffic"
)

// Settings is the "security" block of the server configuration.
type Settings struct {
	Firewall   firewall.Config          `json:"firewall"`
	DNSFilter  dnsfilter.Config         `json:"dns_filter"`
	IDS        ids.Config               `json:"ids"`
	Traffic    traffic.Config           `json:"traffic"`
	Inspection traffic.InspectionConfig `json:"inspection"`
}

// Parse validates the whole block. Unknown sections are refused, so a typo cannot silently leave a protection off.
func Parse(raw json.RawMessage) (Settings, error) {
	var s Settings
	t := bytes.TrimSpace(raw)
	var parts map[string]json.RawMessage
	if len(t) > 0 && string(t) != "null" {
		dec := json.NewDecoder(bytes.NewReader(raw))
		if err := dec.Decode(&parts); err != nil {
			return s, fmt.Errorf("security: %w", err)
		}
	}
	for k := range parts {
		switch k {
		case "firewall", "dns_filter", "ids", "traffic", "inspection":
		default:
			return s, fmt.Errorf("security: unknown section %q (use firewall, dns_filter, ids, traffic or inspection)", k)
		}
	}
	var err error
	if s.Firewall, err = firewall.Parse(parts["firewall"]); err != nil {
		return s, err
	}
	if s.DNSFilter, err = dnsfilter.Parse(parts["dns_filter"]); err != nil {
		return s, err
	}
	if s.IDS, err = ids.Parse(parts["ids"]); err != nil {
		return s, err
	}
	if s.Traffic, err = traffic.Parse(parts["traffic"]); err != nil {
		return s, err
	}
	if len(parts["inspection"]) > 0 && string(bytes.TrimSpace(parts["inspection"])) != "null" {
		dec := json.NewDecoder(bytes.NewReader(parts["inspection"]))
		dec.DisallowUnknownFields()
		if err = dec.Decode(&s.Inspection); err != nil {
			return s, fmt.Errorf("inspection: %w", err)
		}
	}
	s.Inspection.Normalize()
	if err = s.Inspection.Validate(); err != nil {
		return s, err
	}
	return s, s.crossCheck()
}

// crossCheck catches combinations that would lock the operator out or silently do nothing.
func (s Settings) crossCheck() error {
	zones := make(map[string]bool, len(s.Firewall.Zones))
	for _, zone := range s.Firewall.Zones {
		zones[zone.Name] = true
	}
	for _, rule := range s.Traffic.Rules {
		for _, zone := range rule.Zones {
			if !zones[zone] {
				return fmt.Errorf("security: traffic rule %q names unknown zone %q", rule.ID, zone)
			}
		}
	}
	if s.Inspection.Enabled && !s.Firewall.Enabled {
		return errors.New("security: TLS inspection needs the firewall switched on")
	}
	if s.Traffic.HasPathRules() && !s.Inspection.Enabled {
		return errors.New("security: URL path rules need TLS inspection enabled")
	}
	if s.Traffic.HasPathRules() && !s.Traffic.Enabled {
		return errors.New("security: URL path rules need traffic policy enabled")
	}
	if s.Firewall.Enabled && s.Firewall.ForceDNS && !s.Firewall.ServerProtected() {
		return nil // allowed: the server is merely less protected
	}
	if s.Firewall.ForceDNS && !s.Firewall.Enabled {
		return errors.New("security: force_dns needs the firewall switched on (it is a firewall rule)")
	}
	return nil
}

// JSON is the settings with every default filled in.
func (s Settings) JSON() json.RawMessage {
	b, _ := json.Marshal(s)
	return b
}
