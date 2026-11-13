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
)

// Settings is the "security" block of the server configuration.
type Settings struct {
	Firewall  firewall.Config  `json:"firewall"`
	DNSFilter dnsfilter.Config `json:"dns_filter"`
	IDS       ids.Config       `json:"ids"`
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
		case "firewall", "dns_filter", "ids":
		default:
			return s, fmt.Errorf("security: unknown section %q (use firewall, dns_filter or ids)", k)
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
	return s, s.crossCheck()
}

// crossCheck catches combinations that would lock the operator out or silently do nothing.
func (s Settings) crossCheck() error {
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
