package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Runner runs a command, feeding stdin. Tests replace it.
type Runner interface {
	Run(ctx context.Context, stdin string, name string, args ...string) ([]byte, error)
}

// ExecRunner runs real commands (nft and conntrack).
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, stdin string, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if len(msg) > 400 {
			msg = msg[:400]
		}
		return out.Bytes(), fmt.Errorf("%s: %v: %s", name, err, msg)
	}
	return out.Bytes(), nil
}

// Manager applies configurations and reports their counters. It remembers the active prevention blocks so
// that replacing the table does not lift them.
type Manager struct {
	Run    Runner
	Tunnel string
	// Geo returns the prefixes for the selected countries (nil when the lists are not loaded).
	Geo func(codes []string) []netip.Prefix

	mu       sync.Mutex
	cfg      Config
	applied  bool
	warnings []string
	blocks   map[string]time.Time // address -> when the block ends
	now      func() time.Time
}

func NewManager(run Runner) *Manager {
	if run == nil {
		run = ExecRunner{}
	}
	return &Manager{Run: run, blocks: map[string]time.Time{}, now: time.Now}
}

// Apply validates and installs a configuration. On failure the previous table stays in force.
func (m *Manager) Apply(ctx context.Context, c Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.applyLocked(ctx, c)
}

func (m *Manager) applyLocked(ctx context.Context, c Config) error {
	var geo []netip.Prefix
	if c.Enabled && c.Countries.Mode != "off" && m.Geo != nil {
		geo = m.Geo(c.Countries.Codes)
	}
	in := Inputs{Tunnel: m.Tunnel, Geo: geo, Blocked: m.activeBlocks()}
	script, warnings, err := Render(c, in)
	if err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if _, err := m.Run.Run(cctx, script, "nft", "-f", "-"); err != nil {
		return fmt.Errorf("the firewall rules were not accepted by nftables; the previous rules stay in force: %w", err)
	}
	m.cfg, m.applied, m.warnings = c, true, warnings
	return nil
}

// Reapply installs the current configuration again (for example after the country lists arrive).
func (m *Manager) Reapply(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.applied {
		return nil
	}
	return m.applyLocked(ctx, m.cfg)
}

func (m *Manager) activeBlocks() []Block {
	now := m.now()
	var out []Block
	for ip, until := range m.blocks {
		if until.After(now) {
			out = append(out, Block{IP: ip, Remaining: until.Sub(now)})
		} else {
			delete(m.blocks, ip)
		}
	}
	return out
}

// ErrProtected is returned when asked to block an address that must stay reachable.
var ErrProtected = errors.New("that address is the client or the server itself and is never blocked")

// BlockAddress blocks an address for a while. It takes effect at once, also on open connections.
func (m *Manager) BlockAddress(ctx context.Context, ip string, d time.Duration) error {
	a, err := netip.ParseAddr(ip)
	if err != nil || !a.Is4() {
		return fmt.Errorf("%q is not an IPv4 address", ip)
	}
	if protectedAddress(ip) {
		return ErrProtected
	}
	if d < time.Second || d > 30*24*time.Hour {
		return errors.New("a block lasts between a second and 30 days")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.blocks[ip] = m.now().Add(d)
	if !m.applied || !m.cfg.Enabled {
		return nil // remembered; installed when the firewall is switched on
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_, err = m.Run.Run(cctx, "", "nft", "add", "element", "ip", Table, "ips_block", fmt.Sprintf("{ %s timeout %ds }", ip, int(d.Seconds())))
	return err
}

// UnblockAddress lifts a block.
func (m *Manager) UnblockAddress(ctx context.Context, ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.blocks, ip)
	if !m.applied || !m.cfg.Enabled {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_, err := m.Run.Run(cctx, "", "nft", "delete", "element", "ip", Table, "ips_block", fmt.Sprintf("{ %s }", ip))
	if err != nil && strings.Contains(err.Error(), "No such file") {
		return nil // already expired
	}
	return err
}

// Blocked lists the active blocks with the time left.
func (m *Manager) Blocked() []Block {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.activeBlocks()
}

// FlushConnections ends every open connection (conntrack must be installed).
func (m *Manager) FlushConnections(ctx context.Context) error {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := m.Run.Run(cctx, "", "conntrack", "-F"); err != nil {
		if strings.Contains(err.Error(), "executable file not found") {
			return errors.New("open connections cannot be ended: conntrack is not installed in this image")
		}
		return err
	}
	return nil
}

// Counter is what a rule has matched.
type Counter struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// Status is what the GUI shows about the firewall.
type Status struct {
	Enabled  bool               `json:"enabled"`
	Applied  bool               `json:"applied"`
	Warnings []string           `json:"warnings"`
	Counters map[string]Counter `json:"counters"` // by rule id, or "invalid", "ips", "geo", "dot", "isolate", "default", "seg", "protect", "dns"
	Blocked  []BlockedView      `json:"blocked"`
}

// BlockedView is a block with its time left, for the GUI.
type BlockedView struct {
	IP        string `json:"ip"`
	ExpiresIn int    `json:"expires_in_s"`
}

// Status reads the counters from nftables.
func (m *Manager) Status(ctx context.Context) Status {
	m.mu.Lock()
	st := Status{Enabled: m.cfg.Enabled, Applied: m.applied, Warnings: append([]string{}, m.warnings...), Counters: map[string]Counter{}, Blocked: []BlockedView{}}
	for _, b := range m.activeBlocks() {
		st.Blocked = append(st.Blocked, BlockedView{b.IP, int(b.Remaining.Seconds())})
	}
	enabled := m.cfg.Enabled && m.applied
	m.mu.Unlock()
	if !enabled {
		return st
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	raw, err := m.Run.Run(cctx, "", "nft", "-j", "list", "table", "ip", Table)
	if err != nil {
		st.Warnings = append(st.Warnings, "could not read the firewall counters: "+err.Error())
		return st
	}
	st.Counters = parseCounters(raw)
	return st
}

// parseCounters reads rule counters out of `nft -j list table`, keyed by the rule's comment.
func parseCounters(raw []byte) map[string]Counter {
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	out := map[string]Counter{}
	if json.Unmarshal(raw, &doc) != nil {
		return out
	}
	for _, item := range doc.Nftables {
		ruleRaw, ok := item["rule"]
		if !ok {
			continue
		}
		var rule struct {
			Comment string                       `json:"comment"`
			Expr    []map[string]json.RawMessage `json:"expr"`
		}
		if json.Unmarshal(ruleRaw, &rule) != nil || rule.Comment == "" {
			continue
		}
		for _, e := range rule.Expr {
			cr, ok := e["counter"]
			if !ok {
				continue
			}
			var c Counter
			if json.Unmarshal(cr, &c) == nil {
				prev := out[rule.Comment]
				out[rule.Comment] = Counter{prev.Packets + c.Packets, prev.Bytes + c.Bytes}
			}
		}
	}
	return out
}

// Remove deletes the table (the firewall off, or the process ending).
func (m *Manager) Remove(ctx context.Context) error {
	return m.Apply(ctx, Config{DefaultOutbound: "allow", Countries: Countries{Mode: "off", Direction: "outbound"}})
}
