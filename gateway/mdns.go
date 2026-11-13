package gateway

import (
	"errors"
	"fmt"
	"strings"
)

// MDNSConfig enables an allowlist-scoped multicast DNS reflector.
type MDNSConfig struct {
	Enabled        bool     `json:"enabled"`
	InterfaceIDs   []string `json:"interface_ids"`
	ReflectFilters []string `json:"reflect_filters,omitempty"`
}

func (c MDNSConfig) Validate(interfaces []Interface) error {
	if !c.Enabled {
		return nil
	}
	if len(c.InterfaceIDs) < 2 || len(c.InterfaceIDs) > 32 {
		return errors.New("interface_ids must contain 2..32 interfaces")
	}
	byID := make(map[string]Interface, len(interfaces))
	for _, iface := range interfaces {
		byID[iface.ID] = iface
	}
	seen := map[string]bool{}
	for _, id := range c.InterfaceIDs {
		iface, ok := byID[id]
		if !ok || seen[id] {
			return fmt.Errorf("interface_ids contains an unknown or duplicate interface %q", id)
		}
		if iface.Role == "vpn" {
			return fmt.Errorf("mDNS reflection cannot use VPN interface %q", id)
		}
		seen[id] = true
	}
	if len(c.ReflectFilters) > 128 {
		return errors.New("reflect_filters may contain at most 128 service names")
	}
	seenFilter := map[string]bool{}
	for _, filter := range c.ReflectFilters {
		if len(filter) > 255 || strings.TrimSpace(filter) != filter || strings.ContainsAny(filter, "\r\n,") || filter == "" || seenFilter[filter] {
			return fmt.Errorf("invalid or duplicate mDNS reflect filter %q", filter)
		}
		seenFilter[filter] = true
	}
	return nil
}
