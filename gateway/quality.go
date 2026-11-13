package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// QualitySample is one active TCP reachability observation.
type QualitySample struct {
	At      time.Time `json:"at"`
	RTTMS   float64   `json:"rtt_ms,omitempty"`
	Success bool      `json:"success"`
	Target  string    `json:"target"`
	Error   string    `json:"error,omitempty"`
}

// OutageEvent records a WAN health transition.
type OutageEvent struct {
	WANID string    `json:"wan_id"`
	State string    `json:"state"`
	At    time.Time `json:"at"`
	Cause string    `json:"cause,omitempty"`
}

// WANQuality is the current state and bounded recent history for one uplink.
type WANQuality struct {
	WANID       string          `json:"wan_id"`
	Interface   string          `json:"interface"`
	State       string          `json:"state"`
	RTTMS       float64         `json:"rtt_ms,omitempty"`
	LossPercent float64         `json:"loss_percent"`
	CheckedAt   time.Time       `json:"checked_at,omitempty"`
	Samples     []QualitySample `json:"samples"`
}

// QualitySnapshot is safe to expose through the local management API.
type QualitySnapshot struct {
	WANs         []WANQuality  `json:"wans"`
	Outages      []OutageEvent `json:"outages"`
	JournalError string        `json:"journal_error,omitempty"`
}

type tcpProber interface {
	Probe(context.Context, string, string, time.Duration) (time.Duration, error)
}

type interfaceTCPProber struct{}

func (interfaceTCPProber) Probe(ctx context.Context, iface, target string, timeout time.Duration) (time.Duration, error) {
	start := time.Now()
	dialer := net.Dialer{Timeout: timeout, ControlContext: func(ctx context.Context, network, address string, raw syscall.RawConn) error {
		var socketErr error
		if err := raw.Control(func(fd uintptr) {
			socketErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
		}); err != nil {
			return err
		}
		return socketErr
	}}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return time.Since(start), err
	}
	_ = conn.Close()
	return time.Since(start), nil
}

type qualityState struct {
	cfg       WAN
	iface     string
	state     string
	failures  int
	successes int
	checked   time.Time
	rtt       time.Duration
	samples   []QualitySample
}

// QualityMonitor probes every configured WAN without blocking other service paths.
type QualityMonitor struct {
	mu           sync.RWMutex
	states       map[string]*qualityState
	outages      []OutageEvent
	journal      string
	maxBytes     int
	retention    time.Duration
	prober       tcpProber
	journalError string
}

// NewQualityMonitor creates a monitor and loads its bounded outage history.
func NewQualityMonitor(cfg Config, journal string, prober tcpProber) (*QualityMonitor, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if prober == nil {
		prober = interfaceTCPProber{}
	}
	m := &QualityMonitor{states: make(map[string]*qualityState), journal: journal, maxBytes: cfg.Telemetry.OutageMaxBytes, retention: time.Duration(cfg.Telemetry.OutageRetentionDays) * 24 * time.Hour, prober: prober}
	ifaceNames := make(map[string]string, len(cfg.Interfaces))
	for _, iface := range cfg.Interfaces {
		ifaceNames[iface.ID] = iface.Name
	}
	for _, wan := range cfg.WANs {
		m.states[wan.ID] = &qualityState{cfg: wan, iface: ifaceNames[wan.InterfaceID], state: "unknown", samples: make([]QualitySample, 0, 32)}
	}
	if journal != "" {
		if data, err := os.ReadFile(journal); err == nil {
			_ = json.Unmarshal(data, &m.outages)
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("read outage journal: %w", err)
		}
	}
	m.trimOutages(time.Now())
	return m, nil
}

// Start runs one bounded probe loop per WAN until ctx is cancelled.
func (m *QualityMonitor) Start(ctx context.Context) {
	for id := range m.states {
		go m.runWAN(ctx, id)
	}
}

func (m *QualityMonitor) runWAN(ctx context.Context, id string) {
	m.mu.RLock()
	state := m.states[id]
	m.mu.RUnlock()
	if state == nil {
		return
	}
	interval := time.Duration(state.cfg.IntervalSeconds) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for ctx.Err() == nil {
		m.probeOnce(ctx, id)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (m *QualityMonitor) probeOnce(parent context.Context, id string) {
	m.mu.RLock()
	state := m.states[id]
	if state == nil {
		m.mu.RUnlock()
		return
	}
	cfg, iface := state.cfg, state.iface
	m.mu.RUnlock()
	var sample QualitySample
	sample.At = time.Now().UTC()
	type probeResult struct {
		target string
		rtt    time.Duration
		err    error
	}
	results := make(chan probeResult, len(cfg.ProbeTargets))
	var workers sync.WaitGroup
	for _, target := range cfg.ProbeTargets {
		target := target
		workers.Add(1)
		go func() {
			defer workers.Done()
			ctx, cancel := context.WithTimeout(parent, time.Duration(cfg.TimeoutMS)*time.Millisecond)
			defer cancel()
			rtt, err := m.prober.Probe(ctx, iface, target, time.Duration(cfg.TimeoutMS)*time.Millisecond)
			results <- probeResult{target: target, rtt: rtt, err: err}
		}()
	}
	workers.Wait()
	close(results)
	var lastErr error
	for result := range results {
		if result.err == nil && (!sample.Success || result.rtt < time.Duration(sample.RTTMS*float64(time.Millisecond))) {
			sample.Success, sample.Target, sample.RTTMS = true, result.target, float64(result.rtt.Microseconds())/1000
		} else if result.err != nil {
			lastErr = result.err
			if !sample.Success {
				sample.Target = result.target
			}
		}
	}
	if !sample.Success && lastErr != nil {
		sample.Error = lastErr.Error()
	}
	m.record(id, sample)
}

func (m *QualityMonitor) record(id string, sample QualitySample) {
	m.mu.Lock()
	defer m.mu.Unlock()
	state := m.states[id]
	if state == nil {
		return
	}
	state.checked = sample.At
	state.samples = append(state.samples, sample)
	if len(state.samples) > 120 {
		state.samples = append([]QualitySample(nil), state.samples[len(state.samples)-120:]...)
	}
	previous := state.state
	if sample.Success {
		state.successes++
		state.failures = 0
		state.rtt = time.Duration(sample.RTTMS * float64(time.Millisecond))
		if state.state == "outage" && state.successes < state.cfg.RecoveryThreshold {
			state.state = "degraded"
		} else {
			state.state = "up"
		}
	} else {
		state.failures++
		state.successes = 0
		if state.failures >= state.cfg.FailureThreshold {
			state.state = "outage"
		} else {
			state.state = "degraded"
		}
	}
	if previous != state.state {
		cause := ""
		if !sample.Success {
			cause = sample.Error
		}
		m.outages = append(m.outages, OutageEvent{WANID: id, State: state.state, At: sample.At, Cause: cause})
		m.trimOutages(sample.At)
		if err := m.saveOutages(); err != nil {
			m.journalError = err.Error()
		} else {
			m.journalError = ""
		}
	}
}

// Snapshot returns stable, sorted health and outage data.
func (m *QualityMonitor) Snapshot() QualitySnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := QualitySnapshot{WANs: make([]WANQuality, 0, len(m.states)), Outages: append([]OutageEvent(nil), m.outages...), JournalError: m.journalError}
	for _, state := range m.states {
		total, failed := len(state.samples), 0
		for _, sample := range state.samples {
			if !sample.Success {
				failed++
			}
		}
		loss := 0.0
		if total > 0 {
			loss = float64(failed) * 100 / float64(total)
		}
		out.WANs = append(out.WANs, WANQuality{WANID: state.cfg.ID, Interface: state.iface, State: state.state, RTTMS: float64(state.rtt.Microseconds()) / 1000, LossPercent: loss, CheckedAt: state.checked, Samples: append([]QualitySample(nil), state.samples...)})
	}
	sort.Slice(out.WANs, func(i, j int) bool { return out.WANs[i].WANID < out.WANs[j].WANID })
	return out
}

func (m *QualityMonitor) trimOutages(now time.Time) {
	cutoff := now.Add(-m.retention)
	kept := m.outages[:0]
	for _, event := range m.outages {
		if event.At.After(cutoff) {
			kept = append(kept, event)
		}
	}
	m.outages = kept
	for len(m.outages) > 0 {
		data, _ := json.Marshal(m.outages)
		if len(data) <= m.maxBytes {
			break
		}
		m.outages = m.outages[1:]
	}
}

func (m *QualityMonitor) saveOutages() error {
	if m.journal == "" {
		return nil
	}
	data, err := json.Marshal(m.outages)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.journal), 0700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(m.journal), ".outages-*.tmp")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer os.Remove(name)
	if err = temp.Chmod(0600); err == nil {
		_, err = temp.Write(data)
	}
	if err == nil {
		err = temp.Sync()
	}
	closeErr := temp.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(name, m.journal); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(m.journal))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func parseProbeTarget(target string) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(target)
	if err != nil || ap.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf("invalid probe target %q", target)
	}
	return ap, nil
}
