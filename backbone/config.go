package backbone

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"regexp"
	"strings"
)

var interfaceNameRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,14}$`)
var peerIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$`)

// Config describes the private WireGuard and eBGP mesh inside one exit
// container. Each peer gets a dedicated WireGuard interface so equal BGP
// prefixes can use independent next hops without WireGuard AllowedIPs
// selecting the wrong peer.
type Config struct {
	RouterID              string   `json:"router_id"`
	LocalAS               uint32   `json:"local_as"`
	KeepaliveSeconds      uint16   `json:"keepalive_seconds,omitempty"`
	HoldSeconds           uint16   `json:"hold_seconds,omitempty"`
	RecoveryHoldDownMS    int      `json:"recovery_hold_down_ms,omitempty"`
	TransitSourcePrefixes []string `json:"transit_source_prefixes,omitempty"`
	Peers                 []Peer   `json:"peers"`
}

type Peer struct {
	ID                         string   `json:"id"`
	Interface                  string   `json:"interface"`
	Address                    string   `json:"address"`      // local WireGuard IPv4 address and prefix
	PeerAddress                string   `json:"peer_address"` // remote WireGuard/BGP next-hop address
	ListenPort                 uint16   `json:"listen_port"`
	PrivateKeyFile             string   `json:"private_key_file"`
	PublicKey                  string   `json:"public_key"`
	Endpoint                   string   `json:"endpoint"` // remote public IPv4:UDP port
	AllowedIPs                 []string `json:"allowed_ips"`
	PersistentKeepaliveSeconds uint16   `json:"persistent_keepalive_seconds,omitempty"`
	RemoteAS                   uint32   `json:"remote_as"`
	ImportPrefixes             []string `json:"import_prefixes"`
	ExportPrefixes             []string `json:"export_prefixes"`
}

func (c Config) Validate() error {
	routerID, err := netip.ParseAddr(c.RouterID)
	if err != nil || !routerID.Is4() || routerID.IsUnspecified() || routerID.IsLoopback() || routerID.IsMulticast() || routerID.String() != c.RouterID {
		return errors.New("exit_backbone.router_id must be a canonical unicast IPv4 address")
	}
	if c.LocalAS == 0 {
		return errors.New("exit_backbone.local_as must be greater than zero")
	}
	if (c.KeepaliveSeconds == 0) != (c.HoldSeconds == 0) || c.KeepaliveSeconds > 60 || c.HoldSeconds > 3600 || c.HoldSeconds != 0 && uint32(c.HoldSeconds) < uint32(c.KeepaliveSeconds)*3 {
		return errors.New("exit_backbone keepalive_seconds and hold_seconds must both be zero or satisfy keepalive 1..60 and hold 3x keepalive..3600")
	}
	if c.RecoveryHoldDownMS < 0 || c.RecoveryHoldDownMS > 60000 {
		return errors.New("exit_backbone.recovery_hold_down_ms must be 0..60000")
	}
	if len(c.Peers) == 0 || len(c.Peers) > 3 {
		return errors.New("exit_backbone.peers must contain 1..3 peers")
	}
	ids, interfaces, endpoints, addresses, ports := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[netip.Addr]bool{}, map[uint16]bool{}
	localNetworks := make([]netip.Prefix, 0, len(c.Peers))
	for i, peer := range c.Peers {
		field := fmt.Sprintf("exit_backbone.peers[%d]", i)
		if !peerIDRE.MatchString(peer.ID) || ids[peer.ID] {
			return fmt.Errorf("%s.id is invalid or duplicated", field)
		}
		ids[peer.ID] = true
		if !interfaceNameRE.MatchString(peer.Interface) || interfaces[peer.Interface] {
			return fmt.Errorf("%s.interface is invalid or duplicated", field)
		}
		interfaces[peer.Interface] = true
		localPrefix, e := netip.ParsePrefix(peer.Address)
		if e != nil || !localPrefix.Addr().Is4() || localPrefix.Addr().IsUnspecified() || localPrefix.Addr().IsMulticast() || localPrefix.Bits() < 30 {
			return fmt.Errorf("%s.address must be an IPv4 /30..32 host prefix", field)
		}
		for _, previous := range localNetworks {
			if previous.Overlaps(localPrefix) {
				return fmt.Errorf("%s.address overlaps another WireGuard peer subnet", field)
			}
		}
		localNetworks = append(localNetworks, localPrefix)
		peerAddr, e := netip.ParseAddr(peer.PeerAddress)
		if e != nil || !peerAddr.Is4() || peerAddr.IsUnspecified() || peerAddr.IsMulticast() || peerAddr.IsLoopback() || peerAddr == localPrefix.Addr() || addresses[peerAddr] {
			return fmt.Errorf("%s.peer_address must be a unique unicast IPv4 tunnel address", field)
		}
		addresses[peerAddr] = true
		if localPrefix.Bits() < 32 && !localPrefix.Contains(peerAddr) {
			return fmt.Errorf("%s.peer_address must be on-link with address", field)
		}
		if peer.ListenPort < 51820 || peer.ListenPort > 51822 || ports[peer.ListenPort] {
			return fmt.Errorf("%s.listen_port must be unique and in 51820..51822", field)
		}
		ports[peer.ListenPort] = true
		if !validPrivateKeyPath(peer.PrivateKeyFile) {
			return fmt.Errorf("%s.private_key_file must be under /run/secrets/gamebond-backbone", field)
		}
		if !validWireGuardKey(peer.PublicKey) {
			return fmt.Errorf("%s.public_key must be a base64 WireGuard public key", field)
		}
		endpoint, e := netip.ParseAddrPort(peer.Endpoint)
		if e != nil || !endpoint.Addr().Is4() || endpoint.Addr().IsUnspecified() || endpoint.Addr().IsMulticast() || endpoint.Addr().IsLoopback() || endpoint.Port() == 0 || endpoints[peer.Endpoint] {
			return fmt.Errorf("%s.endpoint must be a unique IPv4 address and UDP port", field)
		}
		endpoints[peer.Endpoint] = true
		if peer.PersistentKeepaliveSeconds > 120 {
			return fmt.Errorf("%s.persistent_keepalive_seconds must be 0..120", field)
		}
		if peer.RemoteAS == 0 {
			return fmt.Errorf("%s.remote_as must be greater than zero", field)
		}
		if len(peer.AllowedIPs) == 0 || len(peer.AllowedIPs) > 32 {
			return fmt.Errorf("%s.allowed_ips must contain 1..32 prefixes", field)
		}
		allowed := make([]netip.Prefix, 0, len(peer.AllowedIPs))
		for _, raw := range peer.AllowedIPs {
			prefix, e := netip.ParsePrefix(raw)
			if e != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() {
				return fmt.Errorf("%s.allowed_ips must contain canonical IPv4 prefixes", field)
			}
			allowed = append(allowed, prefix)
		}
		if !prefixListContains(allowed, netip.PrefixFrom(peerAddr, 32)) {
			return fmt.Errorf("%s.allowed_ips must include the BGP peer address", field)
		}
		for listIndex, list := range [][]string{peer.ImportPrefixes, peer.ExportPrefixes} {
			if len(list) > 64 {
				return fmt.Errorf("%s BGP prefix filters may contain at most 64 prefixes", field)
			}
			seen := map[netip.Prefix]bool{}
			for _, raw := range list {
				prefix, e := netip.ParsePrefix(raw)
				if e != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || seen[prefix] {
					return fmt.Errorf("%s BGP prefix filters require unique canonical IPv4 prefixes", field)
				}
				if listIndex == 0 && !prefixListContains(allowed, prefix) {
					return fmt.Errorf("%s.allowed_ips must cover imported prefix %s", field, prefix)
				}
				seen[prefix] = true
			}
		}
	}
	if len(c.TransitSourcePrefixes) > 16 {
		return errors.New("exit_backbone.transit_source_prefixes may contain at most 16 prefixes")
	}
	seenTransit := map[netip.Prefix]bool{}
	for _, raw := range c.TransitSourcePrefixes {
		prefix, e := netip.ParsePrefix(raw)
		if e != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || !prefix.Addr().IsPrivate() || prefix.Bits() < 16 || seenTransit[prefix] {
			return errors.New("exit_backbone.transit_source_prefixes must contain unique private IPv4 prefixes no broader than /16")
		}
		if prefix.Overlaps(netip.MustParsePrefix("10.77.0.0/24")) || prefix.Overlaps(netip.MustParsePrefix("172.16.0.0/12")) {
			return fmt.Errorf("exit_backbone transit prefix %s overlaps a GameBond client or container network", prefix)
		}
		seenTransit[prefix] = true
	}
	return nil
}

func validPrivateKeyPath(value string) bool {
	const root = "/run/secrets/gamebond-backbone/"
	return strings.HasPrefix(value, root) && filepath.Clean(value) == value && !strings.Contains(value[len(root):], "..")
}

func validWireGuardKey(value string) bool {
	decoded, err := base64.StdEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func prefixListContains(container []netip.Prefix, wanted netip.Prefix) bool {
	for _, prefix := range container {
		if prefix.Bits() <= wanted.Bits() && prefix.Contains(wanted.Addr()) {
			return true
		}
	}
	return false
}
