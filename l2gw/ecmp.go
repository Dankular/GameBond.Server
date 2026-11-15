package l2gw

import (
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"net/netip"
	"strings"
	"time"
)

// ECMPPath is one host-routed egress member. The operating system must have a
// usable route through Interface; Gateway binds each flow to the selected
// interface and keeps the selection stable for that flow.
type ECMPPath struct {
	Name      string `json:"name"`
	Interface string `json:"interface"`
	Mark      uint32 `json:"mark,omitempty"` // host ip rule/fwmark selector; requires preconfigured policy routing
	Weight    uint16 `json:"weight,omitempty"`
}

// ECMPFlowKey encodes a stable direction-specific tuple for weighted path
// selection. source and destination should include their transport ports.
func ECMPFlowKey(network string, source, destination netip.AddrPort) []byte {
	return []byte(network + "\x00" + source.String() + "\x00" + destination.String())
}

// ValidateECMPPaths rejects ambiguous or unusable weighted ECMP members.
func ValidateECMPPaths(paths []ECMPPath) error {
	if len(paths) == 0 {
		return nil
	}
	if len(paths) > 16 {
		return errors.New("l2gw: at most 16 ECMP paths are supported")
	}
	names, routeSelectors := make(map[string]bool, len(paths)), make(map[string]bool, len(paths))
	for i, path := range paths {
		if path.Name == "" || len(path.Name) > 32 || strings.ContainsAny(path.Name, "\x00\r\n\t ") {
			return fmt.Errorf("l2gw: ECMP path %d has an invalid name", i)
		}
		if path.Interface == "" && path.Mark == 0 || len(path.Interface) > 15 || strings.ContainsAny(path.Interface, "\x00\r\n\t /\\") {
			return fmt.Errorf("l2gw: ECMP path %q needs an interface or host route mark, and interface names must be at most 15 characters", path.Name)
		}
		if path.Weight > 1000 {
			return fmt.Errorf("l2gw: ECMP path %q weight must be 1..1000", path.Name)
		}
		selector := fmt.Sprintf("%s/%d", path.Interface, path.Mark)
		if names[path.Name] || routeSelectors[selector] {
			return fmt.Errorf("l2gw: ECMP path names and interface/mark selectors must be unique")
		}
		names[path.Name], routeSelectors[selector] = true, true
	}
	return nil
}

// DialWithECMP selects and dials one member. With no paths it delegates to
// fallback, preserving the legacy single-route behavior.
func DialWithECMP(fallback func(network, address string, timeout time.Duration) (net.Conn, error), network, address string, timeout time.Duration, paths []ECMPPath, flowKey []byte) (net.Conn, ECMPPath, error) {
	if len(paths) == 0 {
		if fallback == nil {
			return nil, ECMPPath{}, errors.New("l2gw: no default dialer configured")
		}
		conn, err := fallback(network, address, timeout)
		return conn, ECMPPath{}, err
	}
	path, err := SelectECMPPath(paths, flowKey)
	if err != nil {
		return nil, ECMPPath{}, err
	}
	conn, err := dialECMPPath(network, address, path, timeout)
	return conn, path, err
}

// ListenPacketOnECMP opens the endpoint-independent UDP socket for one chosen
// path. Keep the selection keyed to the device endpoint so all peers of a
// console mapping retain the same public egress path.
func ListenPacketOnECMP(path ECMPPath, family string) (net.PacketConn, error) {
	if path.Interface == "" && path.Mark == 0 {
		return nil, errors.New("l2gw: ECMP interface is empty")
	}
	if family != "udp4" && family != "udp6" {
		return nil, errors.New("l2gw: ECMP UDP family must be udp4 or udp6")
	}
	return listenPacketECMP(path, family)
}

// SelectECMPPath chooses a deterministic weighted path for a flow key. It is
// rendezvous-like in that a stable key stays on one member until membership or
// weights change; callers should include the complete transport tuple.
func SelectECMPPath(paths []ECMPPath, flowKey []byte) (ECMPPath, error) {
	if len(paths) == 0 {
		return ECMPPath{}, errors.New("l2gw: no ECMP paths configured")
	}
	if err := ValidateECMPPaths(paths); err != nil {
		return ECMPPath{}, err
	}
	var total uint64
	for _, path := range paths {
		weight := path.Weight
		if weight == 0 {
			weight = 1
		}
		total += uint64(weight)
	}
	h := fnv.New64a()
	_, _ = h.Write(flowKey)
	selection := h.Sum64() % total
	for _, path := range paths {
		weight := path.Weight
		if weight == 0 {
			weight = 1
		}
		if selection < uint64(weight) {
			return path, nil
		}
		selection -= uint64(weight)
	}
	return ECMPPath{}, errors.New("l2gw: internal ECMP selection error")
}
