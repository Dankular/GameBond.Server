// Package ids is the server's intrusion detection and prevention for tunnel traffic. It follows the approach of
// NIST SP 800-94 for the parts that can be done without reading payloads: behaviour analysis of network flows (scans,
// floods, brute force, unusual DNS, upload spikes against a device's own baseline) and policy signatures (connections
// to ports that should not be used). It sees packet headers only. Prevention adds the offender to the firewall's
// block set for a while; it never blocks the client PC or the server, nor an address on the never-block list.
package ids

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
)

// Mode is how the detector reacts.
const (
	ModeOff     = "off"
	ModeDetect  = "detect"  // record findings only
	ModePrevent = "prevent" // also block the offender where the detector's action is block
)

// Detector kinds.
const (
	PortScan      = "port_scan"
	SynFlood      = "syn_flood"
	UDPFlood      = "udp_flood"
	ICMPFlood     = "icmp_flood"
	BruteForce    = "brute_force"
	RiskyPort     = "risky_port"
	InboundScan   = "inbound_scan"
	InboundFlood  = "inbound_flood"
	DNSAnomaly    = "dns_anomaly"
	UploadAnomaly = "upload_anomaly"
)

// Spec describes a detector: what it looks for and its defaults.
type Spec struct {
	Kind      string `json:"kind"`
	Title     string `json:"title"`
	Help      string `json:"help"`
	Severity  string `json:"severity"` // low, medium or high
	Action    string `json:"default_action"`
	Threshold int    `json:"default_threshold"`
	Unit      string `json:"unit"`
	// Inbound detectors look at traffic from the internet, so the offender is an outside address.
	Inbound bool `json:"inbound"`
}

// Specs lists every detector in display order.
var Specs = []Spec{
	{PortScan, "Port scan", "A device probes many ports on one host, or one uncommon port across many hosts, in ten seconds.", "high", "block", 40, "targets in 10 s", false},
	{SynFlood, "SYN flood", "A device opens connections at a rate that only an attack or a broken program produces.", "high", "block", 500, "new connections per second", false},
	{UDPFlood, "UDP flood", "A device sends UDP at a rate far above normal traffic, for example while taking part in an attack.", "high", "block", 4000, "packets per second", false},
	{ICMPFlood, "ICMP flood", "A device sends pings at an attack rate.", "medium", "block", 200, "packets per second", false},
	{BruteForce, "Brute force", "A device keeps connecting to a login port (SSH, RDP, SMB, databases, ...) on one host.", "high", "block", 25, "connections in 10 s", false},
	{RiskyPort, "Risky port", "A device connects out to a port that should not be used from a home network: Telnet, SMB, RPC, IRC, well-known backdoor ports.", "medium", "alert", 3, "connections in 10 s", false},
	{InboundScan, "Inbound scan", "An address on the internet probes many of your exposed ports or devices.", "high", "block", 15, "targets in 10 s", true},
	{InboundFlood, "Inbound flood", "An address on the internet sends traffic at an attack rate.", "high", "block", 800, "packets per second", true},
	{DNSAnomaly, "DNS anomaly", "A device asks for many names that do not exist, or very long names (typical of malware looking for its server, or DNS tunnelling).", "medium", "alert", 50, "suspicious queries per minute", false},
	{UploadAnomaly, "Upload spike", "A device uploads far more than its own normal, which can mean a compromised device sending data out.", "medium", "alert", 40, "Mbit/s above baseline", false},
}

func spec(kind string) (Spec, bool) {
	for _, s := range Specs {
		if s.Kind == kind {
			return s, true
		}
	}
	return Spec{}, false
}

// DetectorConfig overrides a detector's defaults.
type DetectorConfig struct {
	Enabled   *bool  `json:"enabled,omitempty"`   // default true
	Action    string `json:"action,omitempty"`    // alert or block
	Threshold int    `json:"threshold,omitempty"` // 0 = the default (scaled by sensitivity)
}

// Config is the "ids" part of the security settings.
type Config struct {
	Mode string `json:"mode"`
	// Sensitivity scales every default threshold: low (twice as tolerant), medium, high (half).
	Sensitivity string `json:"sensitivity"`
	// BlockMinutes is how long the first block lasts; a repeat offender within a day is blocked twice as long, up to a day.
	BlockMinutes int `json:"block_minutes"`
	// NeverBlock lists addresses that are only ever alerted about.
	NeverBlock []string                  `json:"never_block"`
	Detectors  map[string]DetectorConfig `json:"detectors"`
}

// Parse decodes and validates the configuration; unknown fields are refused.
func Parse(raw json.RawMessage) (Config, error) {
	var c Config
	if t := bytes.TrimSpace(raw); len(t) == 0 || string(t) == "null" {
		return c.normalised(), nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("ids: %w", err)
	}
	c = c.normalised()
	return c, c.Validate()
}

func (c Config) normalised() Config {
	if c.Mode == "" {
		c.Mode = ModeOff
	}
	if c.Sensitivity == "" {
		c.Sensitivity = "medium"
	}
	if c.BlockMinutes == 0 {
		c.BlockMinutes = 10
	}
	return c
}

// Validate checks every field.
func (c Config) Validate() error {
	switch c.Mode {
	case ModeOff, ModeDetect, ModePrevent:
	default:
		return errors.New("ids: mode must be off, detect or prevent")
	}
	switch c.Sensitivity {
	case "low", "medium", "high":
	default:
		return errors.New("ids: sensitivity must be low, medium or high")
	}
	if c.BlockMinutes < 1 || c.BlockMinutes > 1440 {
		return errors.New("ids: block_minutes must be between 1 and 1440")
	}
	if len(c.NeverBlock) > 64 {
		return errors.New("ids: at most 64 never_block addresses")
	}
	for _, a := range c.NeverBlock {
		if ip, err := netip.ParseAddr(a); err != nil || !ip.Is4() || ip.String() != a {
			return fmt.Errorf("ids: never_block: %q is not an IPv4 address", a)
		}
	}
	for kind, d := range c.Detectors {
		if _, ok := spec(kind); !ok {
			return fmt.Errorf("ids: %q is not a detector", kind)
		}
		if d.Action != "" && d.Action != "alert" && d.Action != "block" {
			return fmt.Errorf("ids: %s: action must be alert or block", kind)
		}
		if d.Threshold < 0 || d.Threshold > 1_000_000 {
			return fmt.Errorf("ids: %s: threshold out of range", kind)
		}
	}
	return nil
}

// resolved is a detector's effective settings.
type resolved struct {
	Spec
	enabled   bool
	action    string
	threshold int
}

func (c Config) resolve(kind string) resolved {
	s, _ := spec(kind)
	r := resolved{Spec: s, enabled: true, action: s.Action, threshold: s.Threshold}
	scale := map[string]float64{"low": 2, "medium": 1, "high": 0.5}[c.Sensitivity]
	if scale == 0 {
		scale = 1
	}
	r.threshold = int(float64(s.Threshold)*scale + 0.5)
	if r.threshold < 1 {
		r.threshold = 1
	}
	if d, ok := c.Detectors[kind]; ok {
		if d.Enabled != nil {
			r.enabled = *d.Enabled
		}
		if d.Action != "" {
			r.action = d.Action
		}
		if d.Threshold > 0 {
			r.threshold = d.Threshold // an explicit threshold is used as given
		}
	}
	return r
}
