package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"strings"

	"github.com/Dankular/GameBond.Server/gateway/layer2"
)

const maxConfigBytes = 1 << 20

// Config is the versioned desired state for the Linux gateway host process.
type Config struct {
	Version     int              `json:"version"`
	SocketPath  string           `json:"socket_path"`
	SocketGroup string           `json:"socket_group"`
	Interfaces  []Interface      `json:"interfaces"`
	WANs        []WAN            `json:"wans"`
	Bridges     []Bridge         `json:"bridges"`
	Telemetry   Telemetry        `json:"telemetry"`
	Features    FeatureSelection `json:"features"`
	Layer2      *layer2.Config   `json:"layer2,omitempty"`
}

// Interface assigns one Linux interface to one managed network role.
type Interface struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Role string `json:"role"`
}

// WAN describes an uplink and the active probes used to measure it.
type WAN struct {
	ID                string   `json:"id"`
	InterfaceID       string   `json:"interface_id"`
	ProbeTargets      []string `json:"probe_targets"`
	IntervalSeconds   int      `json:"interval_seconds"`
	TimeoutMS         int      `json:"timeout_ms"`
	FailureThreshold  int      `json:"failure_threshold"`
	RecoveryThreshold int      `json:"recovery_threshold"`
}

// Bridge configures visibility and an enforceable learned-FDB ceiling.
type Bridge struct {
	ID                string `json:"id"`
	InterfaceName     string `json:"interface_name"`
	MaxLearnedEntries uint32 `json:"max_learned_entries"`
}

// Telemetry bounds the size and lifetime of operational data.
type Telemetry struct {
	FlowMaxRecords      int `json:"flow_max_records"`
	FlowRetentionHours  int `json:"flow_retention_hours"`
	OutageRetentionDays int `json:"outage_retention_days"`
	OutageMaxBytes      int `json:"outage_max_bytes"`
}

// FeatureSelection keeps capability inventory separate from active configuration.
type FeatureSelection struct {
	WanQuality bool `json:"wan_quality"`
	FlowReport bool `json:"flow_report"`
	MacLimit   bool `json:"mac_limit"`
}

// DecodeConfig reads exactly one strict JSON document and validates it before returning.
func DecodeConfig(r io.Reader) (Config, error) {
	limited := io.LimitReader(r, maxConfigBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return Config{}, fmt.Errorf("read gateway config: %w", err)
	}
	if len(data) > maxConfigBytes {
		return Config{}, errors.New("gateway config exceeds 1 MiB")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("gateway config: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return Config{}, errors.New("gateway config must contain one JSON document")
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate checks references and resource bounds before any host adapter is called.
func (c Config) Validate() error {
	if c.Version != 1 {
		return fmt.Errorf("version must be 1, got %d", c.Version)
	}
	if c.Layer2 != nil {
		if err := c.Layer2.Validate(); err != nil {
			return fmt.Errorf("layer2: %w", err)
		}
	}
	if !validSocketPath(c.SocketPath) {
		return errors.New("socket_path must be under /run/gamebond, without parent traversal, and shorter than 100 bytes")
	}
	if c.SocketGroup != "" && !validID(c.SocketGroup) {
		return errors.New("socket_group must be a lowercase group name")
	}
	if c.Telemetry.FlowMaxRecords < 0 || c.Telemetry.FlowMaxRecords > 100000 {
		return errors.New("telemetry.flow_max_records must be 0..100000")
	}
	if c.Telemetry.FlowRetentionHours < 0 || c.Telemetry.FlowRetentionHours > 720 {
		return errors.New("telemetry.flow_retention_hours must be 0..720")
	}
	if c.Telemetry.OutageRetentionDays < 1 || c.Telemetry.OutageRetentionDays > 90 {
		return errors.New("telemetry.outage_retention_days must be 1..90")
	}
	if c.Telemetry.OutageMaxBytes < 4096 || c.Telemetry.OutageMaxBytes > 64<<20 {
		return errors.New("telemetry.outage_max_bytes must be 4096..67108864")
	}

	interfaces := make(map[string]Interface, len(c.Interfaces))
	interfaceNames := make(map[string]string, len(c.Interfaces))
	for i, nic := range c.Interfaces {
		field := fmt.Sprintf("interfaces[%d]", i)
		if !validID(nic.ID) {
			return fmt.Errorf("%s.id is invalid", field)
		}
		if !validIfName(nic.Name) {
			return fmt.Errorf("%s.name is invalid", field)
		}
		if nic.Role != "wan" && nic.Role != "lan" && nic.Role != "vpn" {
			return fmt.Errorf("%s.role must be wan, lan, or vpn", field)
		}
		if _, exists := interfaces[nic.ID]; exists {
			return fmt.Errorf("duplicate interface id %q", nic.ID)
		}
		if prior, exists := interfaceNames[nic.Name]; exists {
			return fmt.Errorf("interface %q is assigned to both %q and %q", nic.Name, prior, nic.ID)
		}
		interfaces[nic.ID] = nic
		interfaceNames[nic.Name] = nic.ID
	}

	wanIDs := make(map[string]bool, len(c.WANs))
	for i, wan := range c.WANs {
		field := fmt.Sprintf("wans[%d]", i)
		if !validID(wan.ID) || wanIDs[wan.ID] {
			return fmt.Errorf("%s.id is invalid or duplicated", field)
		}
		wanIDs[wan.ID] = true
		iface, ok := interfaces[wan.InterfaceID]
		if !ok || iface.Role != "wan" {
			return fmt.Errorf("%s.interface_id must reference a configured WAN interface", field)
		}
		if len(wan.ProbeTargets) == 0 || len(wan.ProbeTargets) > 8 {
			return fmt.Errorf("%s.probe_targets must contain 1..8 targets", field)
		}
		for j, target := range wan.ProbeTargets {
			ap, err := netip.ParseAddrPort(target)
			if err != nil || !ap.Addr().IsValid() || ap.Addr().IsUnspecified() || ap.Addr().IsMulticast() || ap.Addr().IsLoopback() || ap.Port() == 0 {
				return fmt.Errorf("%s.probe_targets[%d] must be a unicast IPv4 or IPv6 address and nonzero port", field, j)
			}
		}
		if wan.IntervalSeconds < 1 || wan.IntervalSeconds > 300 {
			return fmt.Errorf("%s.interval_seconds must be 1..300", field)
		}
		if wan.TimeoutMS < 100 || wan.TimeoutMS > 10000 || wan.TimeoutMS >= wan.IntervalSeconds*1000 {
			return fmt.Errorf("%s.timeout_ms must be 100..10000 and less than the interval", field)
		}
		if wan.FailureThreshold < 1 || wan.FailureThreshold > 20 {
			return fmt.Errorf("%s.failure_threshold must be 1..20", field)
		}
		if wan.RecoveryThreshold < 1 || wan.RecoveryThreshold > 20 {
			return fmt.Errorf("%s.recovery_threshold must be 1..20", field)
		}
	}

	bridgeIDs := make(map[string]bool, len(c.Bridges))
	bridgeNames := make(map[string]bool, len(c.Bridges))
	for i, bridge := range c.Bridges {
		field := fmt.Sprintf("bridges[%d]", i)
		if !validID(bridge.ID) || bridgeIDs[bridge.ID] {
			return fmt.Errorf("%s.id is invalid or duplicated", field)
		}
		if !validIfName(bridge.InterfaceName) || bridgeNames[bridge.InterfaceName] {
			return fmt.Errorf("%s.interface_name is invalid or duplicated", field)
		}
		if bridge.MaxLearnedEntries > 1_000_000 {
			return fmt.Errorf("%s.max_learned_entries must be 0..1000000", field)
		}
		if nic, ok := interfaceNames[bridge.InterfaceName]; !ok {
			return fmt.Errorf("%s.interface_name must reference a configured interface", field)
		} else if interfaces[nic].Role != "lan" {
			return fmt.Errorf("%s.interface_name must reference a LAN interface", field)
		}
		bridgeIDs[bridge.ID] = true
		bridgeNames[bridge.InterfaceName] = true
	}
	if c.Features.WanQuality && len(c.WANs) == 0 {
		return errors.New("features.wan_quality requires at least one WAN")
	}
	if c.Features.FlowReport && (c.Telemetry.FlowMaxRecords == 0 || c.Telemetry.FlowRetentionHours == 0) {
		return errors.New("features.flow_report requires a record cap and retention")
	}
	if c.Features.MacLimit && len(c.Bridges) == 0 {
		return errors.New("features.mac_limit requires at least one configured bridge")
	}
	for _, bridge := range c.Bridges {
		if bridge.MaxLearnedEntries > 0 && !c.Features.MacLimit {
			return errors.New("a nonzero bridge max_learned_entries requires features.mac_limit")
		}
	}
	return nil
}

func validSocketPath(p string) bool {
	return len(p) > len("/run/gamebond/") && len(p) < 100 && filepath.IsAbs(p) && strings.HasPrefix(filepath.Clean(p), "/run/gamebond/") && filepath.Clean(p) == p && !strings.Contains(p, "..")
}

func validID(s string) bool {
	if len(s) < 1 || len(s) > 48 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func validIfName(s string) bool {
	if len(s) < 1 || len(s) > 15 || s == "." || s == ".." {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}
