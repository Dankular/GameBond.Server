package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Dankular/GameBond.Server/gateway/layer2"
)

// Applier prepares a complete candidate before making any host change.
type Applier interface {
	Prepare(context.Context, Config, Config) (PreparedChange, error)
}

// PreparedChange is a reversible host-state transition.
type PreparedChange interface {
	Apply(context.Context) error
	Verify(context.Context) error
	Rollback(context.Context) error
}

// Manager serializes configuration transactions and owns the last known-good copy.
type Manager struct {
	mu      sync.RWMutex
	path    string
	current Config
	applier Applier
	status  ApplyStatus
}

// ApplyStatus describes the most recent transaction without exposing secrets.
type ApplyStatus struct {
	ID            uint64    `json:"id"`
	State         string    `json:"state"`
	UpdatedAt     time.Time `json:"updated_at"`
	Error         string    `json:"error,omitempty"`
	RollbackError string    `json:"rollback_error,omitempty"`
}

// NewManager validates the persisted config before returning a usable manager.
func NewManager(path string, initial Config, applier Applier) (*Manager, error) {
	if !filepath.IsAbs(path) || path == "/" {
		return nil, errors.New("gateway config path must be absolute")
	}
	if err := initial.Validate(); err != nil {
		return nil, err
	}
	if applier == nil {
		return nil, errors.New("gateway applier is required")
	}
	return &Manager{path: path, current: initial, applier: applier, status: ApplyStatus{State: "ready"}}, nil
}

// Current returns a copy of the active desired configuration.
func (m *Manager) Current() Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return cloneConfig(m.current)
}

// Status returns the latest transaction state.
func (m *Manager) Status() ApplyStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status
}

// Apply validates and applies a complete config transaction, rolling back on any failure.
func (m *Manager) Apply(ctx context.Context, desired Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.status.ID++
	m.status.UpdatedAt = time.Now().UTC()
	m.status.State, m.status.Error, m.status.RollbackError = "preparing", "", ""
	fail := func(state string, cause error, change PreparedChange, applied bool) error {
		m.status.State, m.status.Error = state, cause.Error()
		if applied && change != nil {
			rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := change.Rollback(rollbackCtx); err != nil {
				m.status.RollbackError = err.Error()
				m.status.State = "rollback_failed"
			}
		}
		m.status.UpdatedAt = time.Now().UTC()
		log.Printf("gateway config transaction=%d state=%s error=%q rollback_error=%q", m.status.ID, m.status.State, m.status.Error, m.status.RollbackError)
		return cause
	}
	if err := desired.Validate(); err != nil {
		return fail("rejected", err, nil, false)
	}
	change, err := m.applier.Prepare(ctx, cloneConfig(m.current), cloneConfig(desired))
	if err != nil {
		return fail("prepare_failed", err, nil, false)
	}
	if change == nil {
		return fail("prepare_failed", errors.New("applier returned no prepared change"), nil, false)
	}
	m.status.State = "applying"
	if err := change.Apply(ctx); err != nil {
		return fail("apply_failed", err, change, true)
	}
	if err := change.Verify(ctx); err != nil {
		return fail("verify_failed", err, change, true)
	}
	if err := writeConfigAtomic(m.path, desired); err != nil {
		return fail("persist_failed", err, change, true)
	}
	m.current = cloneConfig(desired)
	m.status.State = "applied"
	m.status.UpdatedAt = time.Now().UTC()
	log.Printf("gateway config transaction=%d state=%s", m.status.ID, m.status.State)
	return nil
}

func writeConfigAtomic(path string, cfg Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("encode gateway config: %w", err)
	}
	data = append(data, '\n')
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".gamebond-router-*.tmp")
	if err != nil {
		return fmt.Errorf("create config temp file: %w", err)
	}
	temp := f.Name()
	defer os.Remove(temp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return fmt.Errorf("write config temp file: %w", err)
	}
	if closeErr != nil {
		return fmt.Errorf("close config temp file: %w", closeErr)
	}
	if err := os.Rename(temp, path); err != nil {
		return fmt.Errorf("replace gateway config: %w", err)
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func cloneConfig(cfg Config) Config {
	copy := cfg
	copy.Interfaces = append([]Interface(nil), cfg.Interfaces...)
	copy.WANs = append([]WAN(nil), cfg.WANs...)
	for i := range copy.WANs {
		copy.WANs[i].ProbeTargets = append([]string(nil), cfg.WANs[i].ProbeTargets...)
	}
	copy.Bridges = append([]Bridge(nil), cfg.Bridges...)
	if cfg.Layer2 != nil {
		layer2Copy := *cfg.Layer2
		layer2Copy.Interfaces = append([]layer2.Interface(nil), cfg.Layer2.Interfaces...)
		layer2Copy.Bridges = append([]layer2.Bridge(nil), cfg.Layer2.Bridges...)
		for i := range layer2Copy.Bridges {
			layer2Copy.Bridges[i].Ports = append([]layer2.BridgePort(nil), cfg.Layer2.Bridges[i].Ports...)
			for j := range layer2Copy.Bridges[i].Ports {
				layer2Copy.Bridges[i].Ports[j].TaggedNetworks = append([]string(nil), cfg.Layer2.Bridges[i].Ports[j].TaggedNetworks...)
			}
		}
		layer2Copy.Networks = append([]layer2.Network(nil), cfg.Layer2.Networks...)
		layer2Copy.Overrides = append([]layer2.DeviceOverride(nil), cfg.Layer2.Overrides...)
		copy.Layer2 = &layer2Copy
	}
	return copy
}
