//go:build linux

package gateway

import (
	"context"
	"sync"

	"github.com/Dankular/GameBond.Server/gateway/layer2"
)

// RuntimeSnapshot combines operational views for the local API.
type RuntimeSnapshot struct {
	Capabilities Capabilities         `json:"capabilities"`
	Quality      QualitySnapshot      `json:"quality"`
	Flows        *FlowSnapshot        `json:"flows,omitempty"`
	Bridges      []BridgeSnapshot     `json:"bridges"`
	Layer2       *layer2.Capabilities `json:"layer2,omitempty"`
	Layer2Error  string               `json:"layer2_error,omitempty"`
}

// Runtime owns the background telemetry providers for the current desired config.
type Runtime struct {
	mu      sync.RWMutex
	cfg     Config
	ctx     context.Context
	cancel  context.CancelFunc
	quality *QualityMonitor
	flows   *FlowCollector
	runner  Runner
	journal string
}

// NewRuntime initializes provider state and starts the initial telemetry loops.
func NewRuntime(ctx context.Context, cfg Config, runner Runner, journal string) (*Runtime, error) {
	r := &Runtime{ctx: ctx, runner: runner, journal: journal}
	if err := r.Reconfigure(cfg); err != nil {
		return nil, err
	}
	return r, nil
}

// Reconfigure prepares providers before swapping, then cancels the old workers.
func (r *Runtime) Reconfigure(cfg Config) error {
	providers, err := r.PrepareConfig(cfg)
	if err != nil {
		return err
	}
	r.Activate(providers)
	r.SetConfig(cfg)
	return nil
}

type runtimeProviders struct {
	quality *QualityMonitor
	flows   *FlowCollector
}

// PrepareConfig validates and constructs provider state without disturbing current workers.
func (r *Runtime) PrepareConfig(cfg Config) (*runtimeProviders, error) {
	var quality *QualityMonitor
	var err error
	if cfg.Features.WanQuality {
		quality, err = NewQualityMonitor(cfg, r.journal, nil)
		if err != nil {
			return nil, err
		}
	}
	var flows *FlowCollector
	if cfg.Features.FlowReport {
		flows, err = NewFlowCollector(cfg, "")
		if err != nil {
			return nil, err
		}
	}
	return &runtimeProviders{quality: quality, flows: flows}, nil
}

// Activate swaps in a prepared provider set and stops the previous workers.
func (r *Runtime) Activate(providers *runtimeProviders) {
	if providers == nil {
		return
	}
	providerCtx, cancel := context.WithCancel(r.ctx)
	if providers.quality != nil {
		providers.quality.Start(providerCtx)
	}
	if providers.flows != nil {
		go providers.flows.Start(providerCtx)
	}
	r.mu.Lock()
	oldCancel := r.cancel
	// The caller updates cfg through SetConfig after the desired state is applied.
	r.quality, r.flows, r.cancel = providers.quality, providers.flows, cancel
	r.mu.Unlock()
	if oldCancel != nil {
		oldCancel()
	}
}

// SetConfig updates the runtime's config snapshot after Activate.
func (r *Runtime) SetConfig(cfg Config) {
	r.mu.Lock()
	r.cfg = cloneConfig(cfg)
	r.mu.Unlock()
}

// Snapshot reads the latest provider state and current kernel capabilities.
func (r *Runtime) Snapshot(ctx context.Context) RuntimeSnapshot {
	r.mu.RLock()
	cfg, quality, flows := cloneConfig(r.cfg), r.quality, r.flows
	r.mu.RUnlock()
	caps, err := (LinuxCapabilities{Runner: r.runner}).Snapshot(ctx, cfg)
	if err != nil {
		caps = Capabilities{Tools: map[string]bool{}, Error: err.Error()}
	}
	out := RuntimeSnapshot{Capabilities: caps, Bridges: (BridgeInventory{Runner: r.runner}).Snapshot(ctx, cfg)}
	if cfg.Layer2 != nil {
		if l2Caps, err := layer2.SnapshotCapabilities(ctx, layer2RunnerAdapter{runner: r.runner}); err == nil {
			out.Layer2 = &l2Caps
		} else {
			out.Layer2Error = err.Error()
		}
	}
	if quality != nil {
		out.Quality = quality.Snapshot()
	}
	if flows != nil {
		snapshot := flows.Snapshot()
		out.Flows = &snapshot
	}
	return out
}

// Close stops telemetry workers.
func (r *Runtime) Close() {
	r.mu.Lock()
	cancel := r.cancel
	r.cancel = nil
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}
