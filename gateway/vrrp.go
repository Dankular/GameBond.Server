package gateway

import (
	"errors"
	"fmt"
	"net/netip"
)

// VRRPConfig configures this gateway as the non-preempting shadow/standby peer.
type VRRPConfig struct {
	Enabled                   bool           `json:"enabled"`
	InterfaceID               string         `json:"interface_id,omitempty"`
	VirtualRouterID           uint8          `json:"virtual_router_id,omitempty"`
	Priority                  uint8          `json:"priority,omitempty"`
	AdvertisementIntervalSecs uint8          `json:"advertisement_interval_seconds,omitempty"`
	Peers                     []string       `json:"peers,omitempty"`
	VirtualAddresses          []string       `json:"virtual_addresses,omitempty"`
	BFD                       *VRRPBFDConfig `json:"bfd,omitempty"`
}

// VRRPBFDConfig tracks an independent upstream health target. The target must
// not be the VRRP peer: tracking the backup itself could prevent takeover when
// that peer is unavailable.
type VRRPBFDConfig struct {
	Enabled       bool   `json:"enabled"`
	Neighbor      string `json:"neighbor"`
	MinIntervalMS uint16 `json:"min_interval_ms"`
	Multiplier    uint8  `json:"multiplier"`
}

func (c VRRPConfig) Validate(interfaces []Interface) error {
	if !c.Enabled {
		return nil
	}
	if c.InterfaceID == "" {
		return errors.New("enabled VRRP requires interface_id")
	}
	lan := false
	for _, iface := range interfaces {
		if iface.ID == c.InterfaceID && iface.Role == "lan" {
			lan = true
		}
	}
	if !lan {
		return errors.New("interface_id must reference a configured LAN interface")
	}
	if c.VirtualRouterID == 0 {
		return errors.New("virtual_router_id must be 1..255")
	}
	if c.Priority == 0 || c.Priority == 255 {
		return errors.New("priority must be 1..254 for a shadow peer")
	}
	if c.AdvertisementIntervalSecs < 1 || c.AdvertisementIntervalSecs > 10 {
		return errors.New("advertisement_interval_seconds must be 1..10")
	}
	if len(c.Peers) == 0 || len(c.Peers) > 16 {
		return errors.New("peers must contain 1..16 unicast peer addresses")
	}
	if len(c.VirtualAddresses) == 0 || len(c.VirtualAddresses) > 64 {
		return errors.New("virtual_addresses must contain 1..64 addresses")
	}
	family, err := addressFamily(c.VirtualAddresses[0])
	if err != nil {
		return fmt.Errorf("virtual_addresses[0]: %w", err)
	}
	seenPeers := make(map[netip.Addr]bool, len(c.Peers))
	for i, value := range c.Peers {
		addr, err := netip.ParseAddr(value)
		if err != nil || !addr.IsValid() || addr.IsUnspecified() || addr.IsMulticast() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || (addr.Is4() != (family == 4)) {
			return fmt.Errorf("peers[%d] must be a unicast address matching the virtual address family", i)
		}
		if seenPeers[addr] {
			return fmt.Errorf("peers[%d] is duplicated", i)
		}
		seenPeers[addr] = true
	}
	if c.BFD != nil && c.BFD.Enabled {
		bfd := c.BFD
		neighbor, err := netip.ParseAddr(bfd.Neighbor)
		if err != nil || !neighbor.IsValid() || neighbor.IsUnspecified() || neighbor.IsMulticast() || neighbor.IsLoopback() || neighbor.IsLinkLocalUnicast() || (neighbor.Is4() != (family == 4)) {
			return errors.New("bfd.neighbor must be a unicast address matching the virtual address family")
		}
		if seenPeers[neighbor] {
			return errors.New("bfd.neighbor must be independent of the VRRP peers")
		}
		if bfd.MinIntervalMS < 50 || bfd.MinIntervalMS > 10000 {
			return errors.New("bfd.min_interval_ms must be 50..10000")
		}
		if bfd.Multiplier < 3 || bfd.Multiplier > 20 {
			return errors.New("bfd.multiplier must be 3..20")
		}
	}
	seenVIPs := make(map[netip.Prefix]bool, len(c.VirtualAddresses))
	for i, value := range c.VirtualAddresses {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.Addr().IsValid() || prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() || prefix.Addr().IsLoopback() || prefix.Addr().IsLinkLocalUnicast() || (prefix.Addr().Is4() != (family == 4)) || prefix.String() != value {
			return fmt.Errorf("virtual_addresses[%d] must be a canonical unicast address/prefix of one address family", i)
		}
		if seenVIPs[prefix] {
			return fmt.Errorf("virtual_addresses[%d] is duplicated", i)
		}
		seenVIPs[prefix] = true
	}
	return nil
}

func addressFamily(prefix string) (int, error) {
	parsed, err := netip.ParsePrefix(prefix)
	if err != nil {
		return 0, errors.New("must be a virtual address in CIDR form")
	}
	if parsed.Addr().Is4() {
		return 4, nil
	}
	return 6, nil
}
