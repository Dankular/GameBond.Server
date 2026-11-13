package gateway

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// DHCPConfig describes an IPv4 Kea service managed by GameBond.
type DHCPConfig struct {
	Enabled bool         `json:"enabled"`
	Subnets []DHCPSubnet `json:"subnets,omitempty"`
}

type DHCPSubnet struct {
	ID           string            `json:"id"`
	InterfaceID  string            `json:"interface_id"`
	Prefix       string            `json:"prefix"`
	PoolStart    string            `json:"pool_start"`
	PoolEnd      string            `json:"pool_end"`
	Router       string            `json:"router"`
	DNS          []string          `json:"dns"`
	Domain       string            `json:"domain,omitempty"`
	LeaseSeconds uint32            `json:"lease_seconds"`
	Reservations []DHCPReservation `json:"reservations,omitempty"`
	Options      []DHCPOption      `json:"options,omitempty"`
}

type DHCPReservation struct {
	MAC      string `json:"mac"`
	Address  string `json:"address"`
	Hostname string `json:"hostname,omitempty"`
}

// DataHex contains the RFC 2132 option payload as hexadecimal octets.
type DHCPOption struct {
	Code    uint8  `json:"code"`
	DataHex string `json:"data_hex"`
}

func (c DHCPConfig) Validate(interfaces []Interface) error {
	if len(c.Subnets) > 128 {
		return errors.New("subnets may contain at most 128 entries")
	}
	byID := make(map[string]Interface, len(interfaces))
	for _, iface := range interfaces {
		byID[iface.ID] = iface
	}
	ids, networks, ifaces := map[string]bool{}, map[string]bool{}, map[string]bool{}
	var prefixes []netip.Prefix
	for i, subnet := range c.Subnets {
		field := fmt.Sprintf("subnets[%d]", i)
		if !validID(subnet.ID) || ids[subnet.ID] {
			return fmt.Errorf("%s.id is invalid or duplicated", field)
		}
		ids[subnet.ID] = true
		iface, ok := byID[subnet.InterfaceID]
		if !ok || iface.Role != "lan" {
			return fmt.Errorf("%s.interface_id must reference a configured LAN interface", field)
		}
		if ifaces[iface.Name] {
			return fmt.Errorf("%s duplicates a DHCP interface", field)
		}
		ifaces[iface.Name] = true
		prefix, err := netip.ParsePrefix(subnet.Prefix)
		if err != nil || !prefix.Addr().Is4() || prefix.Masked().String() != subnet.Prefix || prefix.Bits() > 30 {
			return fmt.Errorf("%s.prefix must be a canonical IPv4 subnet with prefix length at most 30", field)
		}
		if networks[subnet.Prefix] {
			return fmt.Errorf("%s.prefix is duplicated", field)
		}
		for _, prior := range prefixes {
			if prior.Contains(prefix.Addr()) || prefix.Contains(prior.Addr()) {
				return fmt.Errorf("%s.prefix overlaps another DHCP subnet", field)
			}
		}
		prefixes = append(prefixes, prefix)
		networks[subnet.Prefix] = true
		start, startOK := parseUnicast4(subnet.PoolStart)
		end, endOK := parseUnicast4(subnet.PoolEnd)
		router, routerOK := parseUnicast4(subnet.Router)
		if !startOK || !endOK || !routerOK || !prefix.Contains(start) || !prefix.Contains(end) || !prefix.Contains(router) || start.Compare(end) > 0 || start.String() != subnet.PoolStart || end.String() != subnet.PoolEnd || router.String() != subnet.Router {
			return fmt.Errorf("%s pool and router must be ordered unicast IPv4 addresses inside prefix", field)
		}
		if start == prefix.Addr() || end == prefix.Addr() || start == lastIPv4(prefix) || end == lastIPv4(prefix) || router == prefix.Addr() || router == lastIPv4(prefix) {
			return fmt.Errorf("%s pool and router cannot use subnet network or broadcast addresses", field)
		}
		if start.Compare(router) <= 0 && router.Compare(end) <= 0 {
			return fmt.Errorf("%s router cannot be inside the dynamic pool", field)
		}
		if len(subnet.DNS) == 0 || len(subnet.DNS) > 8 {
			return fmt.Errorf("%s.dns must contain 1..8 IPv4 addresses", field)
		}
		for j, value := range subnet.DNS {
			if addr, ok := parseUnicast4(value); !ok || addr.String() != value {
				return fmt.Errorf("%s.dns[%d] must be a canonical unicast IPv4 address", field, j)
			}
		}
		if subnet.LeaseSeconds < 60 || subnet.LeaseSeconds > 604800 {
			return fmt.Errorf("%s.lease_seconds must be 60..604800", field)
		}
		if subnet.Domain != "" && !validDomainName(subnet.Domain) {
			return fmt.Errorf("%s.domain is invalid", field)
		}
		if len(subnet.Reservations) > 4096 {
			return fmt.Errorf("%s.reservations may contain at most 4096 entries", field)
		}
		macs, addrs := map[string]bool{}, map[string]bool{}
		for j, reservation := range subnet.Reservations {
			mac, err := net.ParseMAC(reservation.MAC)
			if err != nil || len(mac) != 6 || mac[0]&1 != 0 || strings.ToLower(mac.String()) != reservation.MAC {
				return fmt.Errorf("%s.reservations[%d].mac must be a lowercase unicast MAC", field, j)
			}
			addr, ok := parseUnicast4(reservation.Address)
			if !ok || addr.String() != reservation.Address || !prefix.Contains(addr) || addr == prefix.Addr() || addr == lastIPv4(prefix) || addr == router || (addr.Compare(start) >= 0 && addr.Compare(end) <= 0) {
				return fmt.Errorf("%s.reservations[%d].address must be canonical, inside subnet, and outside pool", field, j)
			}
			if macs[reservation.MAC] || addrs[reservation.Address] {
				return fmt.Errorf("%s reservation MACs and addresses must be unique", field)
			}
			macs[reservation.MAC], addrs[reservation.Address] = true, true
			if reservation.Hostname != "" && !validHostname(reservation.Hostname) {
				return fmt.Errorf("%s.reservations[%d].hostname is invalid", field, j)
			}
		}
		codes := map[uint8]bool{}
		for j, option := range subnet.Options {
			if option.Code == 0 || option.Code == 255 || option.Code == 1 || option.Code == 3 || option.Code == 6 || option.Code == 51 || codes[option.Code] {
				return fmt.Errorf("%s.options[%d].code is reserved or duplicated", field, j)
			}
			codes[option.Code] = true
			if len(option.DataHex) == 0 || len(option.DataHex) > 2048 || len(option.DataHex)%2 != 0 {
				return fmt.Errorf("%s.options[%d].data_hex must contain 1..1024 complete octets", field, j)
			}
			if _, err := hex.DecodeString(option.DataHex); err != nil || strings.ToLower(option.DataHex) != option.DataHex {
				return fmt.Errorf("%s.options[%d].data_hex must be lowercase hexadecimal", field, j)
			}
		}
	}
	if c.Enabled && len(c.Subnets) == 0 {
		return errors.New("enabled DHCP requires at least one subnet")
	}
	return nil
}

func parseUnicast4(value string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(value)
	return addr, err == nil && addr.Is4() && !addr.IsUnspecified() && !addr.IsMulticast() && !addr.IsLoopback()
}

func lastIPv4(prefix netip.Prefix) netip.Addr {
	addr := prefix.Masked().Addr().As4()
	maskBits := prefix.Bits()
	for bit := maskBits; bit < 32; bit++ {
		addr[bit/8] |= 1 << (7 - bit%8)
	}
	return netip.AddrFrom4(addr)
}

func validHostname(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

func validDomainName(domain string) bool { return validHostname(domain) }
