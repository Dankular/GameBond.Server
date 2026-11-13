package gateway

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// DynamicRoutingConfig describes GameBond-owned OSPFv2 and BGP protocols.
type DynamicRoutingConfig struct {
	Enabled  bool       `json:"enabled"`
	RouterID string     `json:"router_id"`
	OSPF     OSPFConfig `json:"ospf"`
	BGP      BGPConfig  `json:"bgp"`
}

type OSPFConfig struct {
	Enabled    bool            `json:"enabled"`
	Interfaces []OSPFInterface `json:"interfaces"`
}

type OSPFInterface struct {
	InterfaceID string `json:"interface_id"`
	Area        string `json:"area"`
	Passive     bool   `json:"passive"`
}

type BGPConfig struct {
	Enabled   bool          `json:"enabled"`
	LocalAS   uint32        `json:"local_as"`
	Neighbors []BGPNeighbor `json:"neighbors"`
}

type BGPNeighbor struct {
	ID                      string   `json:"id"`
	Address                 string   `json:"address"`
	RemoteAS                uint32   `json:"remote_as"`
	UpdateSourceInterfaceID string   `json:"update_source_interface_id,omitempty"`
	Import                  []string `json:"import_prefixes"`
	Export                  []string `json:"export_prefixes"`
}

func (c DynamicRoutingConfig) Validate(interfaces []Interface) error {
	if !c.Enabled {
		if c.OSPF.Enabled || c.BGP.Enabled {
			return errors.New("OSPF and BGP require dynamic_routing.enabled")
		}
		return nil
	}
	rid, err := netip.ParseAddr(c.RouterID)
	if err != nil || !rid.Is4() || rid.IsUnspecified() || rid.IsMulticast() || rid.IsLoopback() || rid.String() != c.RouterID {
		return errors.New("router_id must be a canonical unicast IPv4 address")
	}
	byID := make(map[string]Interface, len(interfaces))
	for _, iface := range interfaces {
		byID[iface.ID] = iface
	}
	if !c.OSPF.Enabled && !c.BGP.Enabled {
		return errors.New("dynamic_routing.enabled requires OSPF or BGP")
	}
	if c.OSPF.Enabled {
		if len(c.OSPF.Interfaces) == 0 || len(c.OSPF.Interfaces) > 64 {
			return errors.New("ospf.interfaces must contain 1..64 interfaces")
		}
		seen := map[string]bool{}
		for i, item := range c.OSPF.Interfaces {
			iface, ok := byID[item.InterfaceID]
			if !ok || seen[item.InterfaceID] {
				return fmt.Errorf("ospf.interfaces[%d].interface_id is unknown or duplicated", i)
			}
			seen[item.InterfaceID] = true
			if iface.Role == "vpn" {
				return fmt.Errorf("ospf.interfaces[%d] cannot use a VPN interface", i)
			}
			if !validOSArea(item.Area) {
				return fmt.Errorf("ospf.interfaces[%d].area must be an IPv4 area ID or 0..4294967295", i)
			}
		}
	}
	if c.BGP.Enabled {
		if c.BGP.LocalAS == 0 || c.BGP.LocalAS > 4294967295 {
			return errors.New("bgp.local_as must be a 32-bit ASN greater than zero")
		}
		if len(c.BGP.Neighbors) == 0 || len(c.BGP.Neighbors) > 256 {
			return errors.New("bgp.neighbors must contain 1..256 peers")
		}
		ids, addresses := map[string]bool{}, map[netip.Addr]bool{}
		for i, peer := range c.BGP.Neighbors {
			field := fmt.Sprintf("bgp.neighbors[%d]", i)
			if !validID(peer.ID) || ids[peer.ID] {
				return fmt.Errorf("%s.id is invalid or duplicated", field)
			}
			ids[peer.ID] = true
			addr, e := netip.ParseAddr(peer.Address)
			if e != nil || addr.IsUnspecified() || addr.IsMulticast() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.String() != peer.Address || addresses[addr] {
				return fmt.Errorf("%s.address must be a unique canonical unicast peer address", field)
			}
			addresses[addr] = true
			if peer.RemoteAS == 0 || peer.RemoteAS > 4294967295 {
				return fmt.Errorf("%s.remote_as must be a 32-bit ASN greater than zero", field)
			}
			if peer.UpdateSourceInterfaceID != "" {
				if _, ok := byID[peer.UpdateSourceInterfaceID]; !ok {
					return fmt.Errorf("%s.update_source_interface_id is unknown", field)
				}
			}
			if len(peer.Import) > 256 || len(peer.Export) > 256 {
				return fmt.Errorf("%s prefix filters may contain at most 256 prefixes", field)
			}
			for _, list := range [][]string{peer.Import, peer.Export} {
				seen := map[netip.Prefix]bool{}
				for _, value := range list {
					p, e := netip.ParsePrefix(value)
					if e != nil || p.Addr().Is4() != addr.Is4() || p.Masked().String() != value || seen[p] {
						return fmt.Errorf("%s filters require unique canonical prefixes matching peer address family", field)
					}
					seen[p] = true
				}
			}
		}
	}
	return nil
}

func validOSArea(value string) bool {
	if p, err := netip.ParseAddr(value); err == nil {
		return p.Is4() && p.String() == value
	}
	if value == "" || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	_, err := strconv.ParseUint(value, 10, 32)
	return err == nil
}
