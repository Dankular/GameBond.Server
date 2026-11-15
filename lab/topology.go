// Package lab defines the versioned desired state for a single-host network lab.
// It deliberately describes generic Linux nodes; vendor appliance images and
// their control planes belong to a different runtime.
package lab

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	TopologyVersion  = 1
	MaxTopologyBytes = 1 << 20
	MaxNodes         = 128
	MaxLinks         = 512
	MaxAssertions    = 1024
)

var idPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// Topology is declarative state. Validation is completed before a runtime is
// allowed to create namespaces, interfaces, or processes.
type Topology struct {
	Version    int         `json:"version"`
	ID         string      `json:"id"`
	Name       string      `json:"name"`
	Nodes      []Node      `json:"nodes"`
	Links      []Link      `json:"links"`
	Assertions []Assertion `json:"assertions,omitempty"`
}

// Assertion is a safe, allowlisted check that a node backend can execute for
// teaching labs and repeatable validation. It is never an arbitrary command.
type Assertion struct {
	ID       string `json:"id"`
	Node     string `json:"node"`
	Kind     string `json:"kind"` // ping, traceroute, ospf-neighbor, bgp-neighbor, interface-up
	Target   string `json:"target,omitempty"`
	Expected string `json:"expected,omitempty"`
}

// SFlowConfig controls the generic interface-counter exporter available in
// lab nodes. It emits standard sFlow v5 counter samples to a topology-reachable
// collector.
type SFlowConfig struct {
	Collector      string `json:"collector"`
	AgentIP        string `json:"agent_ip,omitempty"`
	PollingSeconds uint32 `json:"polling_seconds,omitempty"`
}

func DecodeSFlowConfig(raw string) (SFlowConfig, error) {
	var config SFlowConfig
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return config, fmt.Errorf("decode sFlow configuration: %w", err)
	}
	if decoder.Decode(new(any)) != io.EOF {
		return config, fmt.Errorf("sFlow configuration must contain exactly one JSON value")
	}
	host, portText, err := net.SplitHostPort(config.Collector)
	port, portErr := strconv.Atoi(portText)
	if err != nil || host == "" || strings.ContainsAny(host, " \t\r\n") || portErr != nil || port < 1 || port > 65535 {
		return config, fmt.Errorf("sFlow collector must be a host:port with a valid UDP port")
	}
	if config.AgentIP != "" {
		ip := net.ParseIP(config.AgentIP).To4()
		if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
			return config, fmt.Errorf("sFlow agent_ip must be a unicast IPv4 address")
		}
	}
	if config.PollingSeconds > 3600 {
		return config, fmt.Errorf("sFlow polling_seconds must be at most 3600")
	}
	return config, nil
}

type Node struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Role         string            `json:"role"` // host, router, or switch
	Interfaces   []Interface       `json:"interfaces"`
	Daemons      []string          `json:"daemons,omitempty"`
	Resources    Resources         `json:"resources,omitempty"`
	DaemonConfig map[string]string `json:"daemon_config,omitempty"`
	Position     *Position         `json:"position,omitempty"`
}

type Interface struct {
	ID        string   `json:"id"`
	Name      string   `json:"name,omitempty"` // guest-side name; empty lets the runtime allocate one
	MTU       int      `json:"mtu,omitempty"`
	MAC       string   `json:"mac,omitempty"`
	Addresses []string `json:"addresses,omitempty"` // CIDR prefixes assigned inside the node
}

type Resources struct {
	CPUShares uint32 `json:"cpu_shares,omitempty"`
	MemoryMiB uint32 `json:"memory_mib,omitempty"`
}

type Position struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

type Link struct {
	ID         string     `json:"id"`
	A          Endpoint   `json:"a"`
	B          Endpoint   `json:"b"`
	Impairment Impairment `json:"impairment,omitempty"`
}

type Endpoint struct {
	Node      string `json:"node"`
	Interface string `json:"interface"`
}

// Impairment values are applied symmetrically in real time. Delay and jitter
// use milliseconds, loss is a percentage, and bandwidth is bits per second.
type Impairment struct {
	LatencyMS    uint32  `json:"latency_ms,omitempty"`
	JitterMS     uint32  `json:"jitter_ms,omitempty"`
	LossPct      float64 `json:"loss_pct,omitempty"`
	CorruptPct   float64 `json:"corrupt_pct,omitempty"`
	BandwidthBPS uint64  `json:"bandwidth_bps,omitempty"`
}

// DecodeTopology rejects oversized, malformed, trailing, and unknown input so
// an API caller cannot silently request state the runtime does not understand.
func DecodeTopology(data []byte) (Topology, error) {
	var topology Topology
	if len(data) == 0 || len(data) > MaxTopologyBytes {
		return topology, fmt.Errorf("topology must be between 1 and %d bytes", MaxTopologyBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&topology); err != nil {
		return topology, fmt.Errorf("decode topology: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return topology, fmt.Errorf("topology must contain exactly one JSON value")
	}
	if err := topology.Validate(); err != nil {
		return topology, err
	}
	return topology, nil
}

func (t Topology) Validate() error {
	if t.Version != TopologyVersion {
		return fmt.Errorf("version must be %d", TopologyVersion)
	}
	if !idPattern.MatchString(t.ID) {
		return fmt.Errorf("topology id must be a lowercase stable id")
	}
	if err := validName("topology name", t.Name); err != nil {
		return err
	}
	if len(t.Nodes) == 0 || len(t.Nodes) > MaxNodes {
		return fmt.Errorf("topology must contain 1..%d nodes", MaxNodes)
	}
	if len(t.Links) > MaxLinks {
		return fmt.Errorf("topology may contain at most %d links", MaxLinks)
	}
	if len(t.Assertions) > MaxAssertions {
		return fmt.Errorf("topology may contain at most %d assertions", MaxAssertions)
	}

	nodes := make(map[string]Node, len(t.Nodes))
	addresses := map[netip.Addr]string{}
	for i, n := range t.Nodes {
		at := fmt.Sprintf("nodes[%d]", i)
		if !idPattern.MatchString(n.ID) {
			return fmt.Errorf("%s.id must be a lowercase stable id", at)
		}
		if _, exists := nodes[n.ID]; exists {
			return fmt.Errorf("%s.id %q is duplicated", at, n.ID)
		}
		if err := validName(at+".name", n.Name); err != nil {
			return err
		}
		if n.Role != "host" && n.Role != "router" && n.Role != "switch" {
			return fmt.Errorf("%s.role must be host, router, or switch", at)
		}
		if len(n.Interfaces) > 32 {
			return fmt.Errorf("%s may contain at most 32 interfaces", at)
		}
		if n.Resources.CPUShares > 262144 {
			return fmt.Errorf("%s.resources.cpu_shares exceeds 262144", at)
		}
		if n.Resources.MemoryMiB > 1048576 {
			return fmt.Errorf("%s.resources.memory_mib exceeds 1048576", at)
		}
		if n.Position != nil && (!finite(n.Position.X) || !finite(n.Position.Y) || math.Abs(n.Position.X) > 1e6 || math.Abs(n.Position.Y) > 1e6) {
			return fmt.Errorf("%s.position must contain finite coordinates within +/-1000000", at)
		}
		seenIf := map[string]bool{}
		seenName := map[string]bool{}
		if len(n.DaemonConfig) > len(allowedDaemons) {
			return fmt.Errorf("%s.daemon_config contains too many daemon files", at)
		}
		configBytes := 0
		for daemon, config := range n.DaemonConfig {
			if !allowedDaemons[daemon] || !contains(n.Daemons, daemon) {
				return fmt.Errorf("%s.daemon_config key %q must name an enabled daemon", at, daemon)
			}
			if len(config) > 65536 || strings.ContainsRune(config, '\x00') {
				return fmt.Errorf("%s.daemon_config.%s exceeds 65536 bytes or contains NUL", at, daemon)
			}
			configBytes += len(config)
		}
		if configBytes > 262144 {
			return fmt.Errorf("%s daemon configuration exceeds 262144 bytes", at)
		}
		for j, in := range n.Interfaces {
			if !idPattern.MatchString(in.ID) {
				return fmt.Errorf("%s.interfaces[%d].id must be a lowercase stable id", at, j)
			}
			if seenIf[in.ID] {
				return fmt.Errorf("%s has duplicate interface id %q", at, in.ID)
			}
			seenIf[in.ID] = true
			if in.Name != "" && (!interfaceNamePattern.MatchString(in.Name) || seenName[in.Name]) {
				return fmt.Errorf("%s.interfaces[%d].name is invalid or duplicated", at, j)
			}
			if in.Name != "" {
				seenName[in.Name] = true
			}
			if in.MTU != 0 && (in.MTU < 576 || in.MTU > 65535) {
				return fmt.Errorf("%s.interfaces[%d].mtu must be 576..65535", at, j)
			}
			if in.MAC != "" {
				mac, err := net.ParseMAC(in.MAC)
				if err != nil || len(mac) != 6 || mac[0]&1 != 0 {
					return fmt.Errorf("%s.interfaces[%d].mac must be a unicast six-byte MAC", at, j)
				}
			}
			if len(in.Addresses) > 16 {
				return fmt.Errorf("%s.interfaces[%d] may have at most 16 addresses", at, j)
			}
			for _, prefixText := range in.Addresses {
				prefix, err := netip.ParsePrefix(prefixText)
				if err != nil || prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() {
					return fmt.Errorf("%s.interfaces[%d] has invalid address prefix %q", at, j, prefixText)
				}
				addr := prefix.Addr().Unmap()
				if prior, duplicate := addresses[addr]; duplicate {
					return fmt.Errorf("%s address %s duplicates %s", at, addr, prior)
				}
				addresses[addr] = at + ".interfaces[" + in.ID + "]"
			}
		}
		if len(n.Interfaces) < 1 {
			return fmt.Errorf("%s must define at least one interface", at)
		}
		seenDaemon := map[string]bool{}
		for _, d := range n.Daemons {
			if !allowedDaemons[d] {
				return fmt.Errorf("%s has unsupported daemon %q", at, d)
			}
			if seenDaemon[d] {
				return fmt.Errorf("%s has duplicate daemon %q", at, d)
			}
			seenDaemon[d] = true
			if d == "snmpd" && strings.TrimSpace(n.DaemonConfig[d]) == "" {
				return fmt.Errorf("nodes[%s].daemon_config.snmpd must define an explicit access policy", n.ID)
			}
			if d == "sflow" {
				if strings.TrimSpace(n.DaemonConfig[d]) == "" {
					return fmt.Errorf("nodes[%s].daemon_config.sflow is required", n.ID)
				}
				if _, err := DecodeSFlowConfig(n.DaemonConfig[d]); err != nil {
					return fmt.Errorf("nodes[%s].daemon_config.sflow: %w", n.ID, err)
				}
			}
		}
		nodes[n.ID] = n
	}
	usedEndpoints := map[string]string{}
	linkIDs := map[string]bool{}
	for i, l := range t.Links {
		at := fmt.Sprintf("links[%d]", i)
		if !idPattern.MatchString(l.ID) {
			return fmt.Errorf("%s.id must be a lowercase stable id", at)
		}
		if linkIDs[l.ID] {
			return fmt.Errorf("%s.id %q is duplicated", at, l.ID)
		}
		linkIDs[l.ID] = true
		if l.A == l.B {
			return fmt.Errorf("%s endpoints must be different", at)
		}
		for _, e := range []Endpoint{l.A, l.B} {
			n, ok := nodes[e.Node]
			if !ok {
				return fmt.Errorf("%s references unknown node %q", at, e.Node)
			}
			found := false
			for _, in := range n.Interfaces {
				if in.ID == e.Interface {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("%s references unknown interface %q on node %q", at, e.Interface, e.Node)
			}
			key := e.Node + "/" + e.Interface
			if prior, used := usedEndpoints[key]; used {
				return fmt.Errorf("%s reuses endpoint %s already used by link %q", at, key, prior)
			}
			usedEndpoints[key] = l.ID
		}
		p := l.Impairment
		if p.LatencyMS > 60000 || p.JitterMS > 60000 {
			return fmt.Errorf("%s latency and jitter must be at most 60000 ms", at)
		}
		if p.BandwidthBPS > 1_000_000_000_000 {
			return fmt.Errorf("%s bandwidth_bps must be at most 1000000000000", at)
		}
		if !finite(p.LossPct) || p.LossPct < 0 || p.LossPct > 100 {
			return fmt.Errorf("%s loss_pct must be between 0 and 100", at)
		}
		if !finite(p.CorruptPct) || p.CorruptPct < 0 || p.CorruptPct > 100 {
			return fmt.Errorf("%s corrupt_pct must be between 0 and 100", at)
		}
	}
	assertionIDs := map[string]bool{}
	for i, a := range t.Assertions {
		at := fmt.Sprintf("assertions[%d]", i)
		if !idPattern.MatchString(a.ID) {
			return fmt.Errorf("%s.id must be a lowercase stable id", at)
		}
		if assertionIDs[a.ID] {
			return fmt.Errorf("%s.id %q is duplicated", at, a.ID)
		}
		assertionIDs[a.ID] = true
		if _, ok := nodes[a.Node]; !ok {
			return fmt.Errorf("%s references unknown node %q", at, a.Node)
		}
		switch a.Kind {
		case "ping", "traceroute", "ospf-neighbor", "bgp-neighbor", "interface-up":
		default:
			return fmt.Errorf("%s.kind is unsupported", at)
		}
		if len(a.Target) > 253 || strings.ContainsAny(a.Target, "\r\n\x00") || len(a.Expected) > 128 || strings.ContainsAny(a.Expected, "\r\n\x00") {
			return fmt.Errorf("%s target or expected value is invalid", at)
		}
		if (a.Kind == "ping" || a.Kind == "traceroute" || a.Kind == "ospf-neighbor" || a.Kind == "bgp-neighbor") && strings.TrimSpace(a.Target) == "" {
			return fmt.Errorf("%s.target is required for %s", at, a.Kind)
		}
		if a.Kind == "ping" || a.Kind == "traceroute" || a.Kind == "ospf-neighbor" || a.Kind == "bgp-neighbor" {
			if _, err := netip.ParseAddr(a.Target); err != nil && !idPattern.MatchString(a.Target) {
				return fmt.Errorf("%s.target must be an IP address or node id", at)
			}
		}
		if a.Kind == "ospf-neighbor" || a.Kind == "bgp-neighbor" {
			hasFRR := false
			for _, daemon := range nodes[a.Node].Daemons {
				hasFRR = hasFRR || daemon == "frr"
			}
			if !hasFRR {
				return fmt.Errorf("%s requires frr on node %q", at, a.Node)
			}
		}
		if a.Kind == "interface-up" {
			node := nodes[a.Node]
			found := false
			for _, in := range node.Interfaces {
				found = found || in.ID == a.Target || in.Name == a.Target
			}
			if !found {
				return fmt.Errorf("%s.target interface is required", at)
			}
		}
	}
	return nil
}

func (t Topology) Hash() (string, error) {
	if err := t.Validate(); err != nil {
		return "", err
	}
	b, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func validName(field, value string) error {
	if strings.TrimSpace(value) == "" || len(value) > 128 || strings.ContainsAny(value, "\r\n\x00") {
		return fmt.Errorf("%s must be non-empty, at most 128 characters, and contain no control line breaks", field)
	}
	return nil
}

func finite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

var interfaceNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)
var allowedDaemons = map[string]bool{"frr": true, "mstpd": true, "keepalived": true, "hostapd": true, "wpa_supplicant": true, "snmpd": true, "sflow": true}

// SortedNodeIDs is useful for stable runtime plans and UI snapshots.
func (t Topology) SortedNodeIDs() []string {
	out := make([]string, 0, len(t.Nodes))
	for _, n := range t.Nodes {
		out = append(out, n.ID)
	}
	sort.Strings(out)
	return out
}
