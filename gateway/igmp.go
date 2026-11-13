package gateway

import (
	"errors"
	"fmt"
	"net/netip"
)

// IGMPProxyConfig relays IPv4 multicast membership between one WAN and LANs.
type IGMPProxyConfig struct {
	Enabled                bool     `json:"enabled"`
	UpstreamInterfaceID    string   `json:"upstream_interface_id,omitempty"`
	DownstreamInterfaceIDs []string `json:"downstream_interface_ids,omitempty"`
	AllowedSources         []string `json:"allowed_sources,omitempty"`
	QuickLeave             bool     `json:"quick_leave,omitempty"`
}

func (c IGMPProxyConfig) Validate(interfaces []Interface) error {
	if !c.Enabled {
		return nil
	}
	byID := make(map[string]Interface, len(interfaces))
	for _, iface := range interfaces {
		byID[iface.ID] = iface
	}
	upstream, ok := byID[c.UpstreamInterfaceID]
	if !ok || upstream.Role != "wan" {
		return errors.New("upstream_interface_id must reference a configured WAN")
	}
	if len(c.DownstreamInterfaceIDs) == 0 || len(c.DownstreamInterfaceIDs) > 64 {
		return errors.New("downstream_interface_ids must contain 1..64 configured LANs")
	}
	seen := map[string]bool{}
	for i, id := range c.DownstreamInterfaceIDs {
		iface, ok := byID[id]
		if !ok || iface.Role != "lan" {
			return fmt.Errorf("downstream_interface_ids[%d] must reference a configured LAN", i)
		}
		if seen[id] || id == c.UpstreamInterfaceID {
			return fmt.Errorf("downstream interface %q is duplicated or is also upstream", id)
		}
		seen[id] = true
	}
	if len(c.AllowedSources) > 128 {
		return errors.New("allowed_sources may contain at most 128 IPv4 prefixes")
	}
	seenPrefixes := map[netip.Prefix]bool{}
	for i, value := range c.AllowedSources {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.Addr().Is4() || prefix.Masked().String() != value {
			return fmt.Errorf("allowed_sources[%d] must be a canonical IPv4 prefix", i)
		}
		if seenPrefixes[prefix] {
			return fmt.Errorf("allowed_sources[%d] is duplicated", i)
		}
		seenPrefixes[prefix] = true
	}
	return nil
}
