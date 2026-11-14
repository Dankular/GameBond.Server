//go:build linux

package gateway

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Dankular/GameBond.Server/gateway/layer2"
)

// RuntimeSnapshot combines operational views for the local API.
type RuntimeSnapshot struct {
	Capabilities   Capabilities            `json:"capabilities"`
	Quality        QualitySnapshot         `json:"quality"`
	Flows          *FlowSnapshot           `json:"flows,omitempty"`
	Bridges        []BridgeSnapshot        `json:"bridges"`
	Layer2         *layer2.Capabilities    `json:"layer2,omitempty"`
	Layer2Error    string                  `json:"layer2_error,omitempty"`
	NAT            NATSnapshot             `json:"nat"`
	Routing        RoutingSnapshot         `json:"routing"`
	QoS            QoSSnapshot             `json:"qos"`
	DHCP           DHCPSnapshot            `json:"dhcp"`
	DHCPGuardSync  DHCPGuardSyncSnapshot   `json:"dhcp_guard_sync"`
	VRRP           VRRPSnapshot            `json:"vrrp"`
	IGMPProxy      IGMPProxySnapshot       `json:"igmp_proxy"`
	DynamicRouting DynamicRoutingSnapshot  `json:"dynamic_routing"`
	MDNS           MDNSSnapshot            `json:"mdns"`
	RADIUS         RADIUSSnapshot          `json:"radius"`
	Redundancy     []RedundancyGroupStatus `json:"redundancy,omitempty"`
	LLDPMED        LLDPMEDSnapshot         `json:"lldp_med"`
	PortAuth       PortAuthSnapshot        `json:"port_auth"`
}

type DHCPGuardSyncSnapshot struct {
	Applied       bool      `json:"applied"`
	BindingCount  int       `json:"binding_count,omitempty"`
	ConflictCount int       `json:"conflict_count,omitempty"`
	LastAttemptAt time.Time `json:"last_attempt_at,omitempty"`
	Error         string    `json:"error,omitempty"`
}

// Runtime owns the background telemetry providers for the current desired config.
type Runtime struct {
	mu                sync.RWMutex
	cfg               Config
	ctx               context.Context
	cancel            context.CancelFunc
	quality           *QualityMonitor
	flows             *FlowCollector
	runner            Runner
	journal           string
	dhcpGuardSync     DHCPGuardSyncSnapshot
	redundancyLast    map[string]RedundancyGroupStatus
	redundancyHistory map[string][]RedundancyTransition
}

// NewRuntime initializes provider state and starts the initial telemetry loops.
func NewRuntime(ctx context.Context, cfg Config, runner Runner, journal string) (*Runtime, error) {
	r := &Runtime{ctx: ctx, runner: runner, journal: journal, redundancyLast: map[string]RedundancyGroupStatus{}, redundancyHistory: map[string][]RedundancyTransition{}}
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
	cfg     Config
}

// PrepareConfig validates and constructs provider state without disturbing current workers.
func (r *Runtime) PrepareConfig(cfg Config) (*runtimeProviders, error) {
	if err := validateDHCPBindingAuthority(cfg.Layer2); err != nil {
		return nil, err
	}
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
	return &runtimeProviders{quality: quality, flows: flows, cfg: cloneConfig(cfg)}, nil
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
	if providers.cfg.DHCP.Enabled && hasDHCPBindingGuard(providers.cfg.Layer2) {
		go r.runDHCPGuardBindingSync(providerCtx, providers.cfg)
	}
	r.mu.Lock()
	oldCancel := r.cancel
	// The caller updates cfg through SetConfig after the desired state is applied.
	r.quality, r.flows, r.cancel = providers.quality, providers.flows, cancel
	if !providers.cfg.DHCP.Enabled || !hasDHCPBindingGuard(providers.cfg.Layer2) {
		r.dhcpGuardSync = DHCPGuardSyncSnapshot{}
	}
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
	dhcpGuardSync := r.dhcpGuardSync
	r.mu.RUnlock()
	caps, err := (LinuxCapabilities{Runner: r.runner}).Snapshot(ctx, cfg)
	if err != nil {
		caps = Capabilities{Tools: map[string]bool{}, Error: err.Error()}
	}
	out := RuntimeSnapshot{Capabilities: caps, Bridges: (BridgeInventory{Runner: r.runner}).Snapshot(ctx, cfg)}
	out.NAT = snapshotNAT(ctx, r.runner, cfg.NAT.Enabled)
	out.Routing = snapshotRouting(ctx, r.runner, cfg)
	effectiveQoS, qosErr := effectiveQoSConfig(cfg)
	if qosErr != nil {
		out.QoS = QoSSnapshot{Enabled: cfg.QoS.Enabled, Error: qosErr.Error()}
	} else {
		out.QoS = snapshotQoS(ctx, r.runner, effectiveQoS)
	}
	out.DHCP = snapshotDHCP(ctx, r.runner, cfg.DHCP)
	out.DHCPGuardSync = dhcpGuardSync
	out.VRRP = snapshotVRRP(ctx, r.runner, cfg)
	out.IGMPProxy = snapshotIGMP(ctx, r.runner, cfg.IGMPProxy.Enabled)
	out.DynamicRouting = snapshotDynamicRouting(ctx, r.runner, cfg.DynamicRouting)
	out.MDNS = snapshotMDNS(ctx, r.runner, cfg.MDNS.Enabled)
	out.RADIUS = snapshotRADIUS(ctx, r.runner, cfg.RADIUS)
	if cfg.Layer2 != nil {
		if l2Caps, err := layer2.SnapshotCapabilities(ctx, *cfg.Layer2, layer2RunnerAdapter{runner: r.runner}); err == nil {
			out.Layer2 = &l2Caps
		} else {
			out.Layer2Error = err.Error()
		}
		out.LLDPMED = snapshotLLDPMED(ctx, r.runner, *cfg.Layer2)
		out.PortAuth = snapshotPortAuth(ctx, r.runner, *cfg.Layer2)
	}
	if quality != nil {
		out.Quality = quality.Snapshot()
	}
	if flows != nil {
		snapshot := flows.Snapshot()
		out.Flows = &snapshot
	}
	out.Redundancy = r.updateRedundancy(cfg.Redundancy, cfg.Layer2, out.Layer2, out.VRRP, time.Now())
	return out
}

func (r *Runtime) updateRedundancy(cfg RedundancyConfig, desired *layer2.Config, live *layer2.Capabilities, vrrp VRRPSnapshot, now time.Time) []RedundancyGroupStatus {
	statuses := evaluateRedundancy(cfg, desired, live, vrrp)
	r.mu.Lock()
	defer r.mu.Unlock()
	active := make(map[string]bool, len(statuses))
	for i := range statuses {
		status := &statuses[i]
		active[status.ID] = true
		previous, exists := r.redundancyLast[status.ID]
		if !exists || previous.State != status.State || previous.Role != status.Role || redundancyMechanismsChanged(previous.Mechanisms, status.Mechanisms) {
			transition := RedundancyTransition{At: now, ToState: status.State, ToRole: status.Role, Cause: redundancyTransitionCause(previous, *status, exists)}
			if exists {
				transition.FromState, transition.FromRole = previous.State, previous.Role
			}
			history := append(r.redundancyHistory[status.ID], transition)
			if len(history) > 64 {
				history = append([]RedundancyTransition(nil), history[len(history)-64:]...)
			}
			r.redundancyHistory[status.ID] = history
			status.LastChange = now
		} else {
			status.LastChange = previous.LastChange
		}
		status.Transitions = append([]RedundancyTransition(nil), r.redundancyHistory[status.ID]...)
		r.redundancyLast[status.ID] = *status
	}
	for id := range r.redundancyLast {
		if !active[id] {
			delete(r.redundancyLast, id)
			delete(r.redundancyHistory, id)
		}
	}
	return statuses
}

func redundancyMechanismsChanged(previous, current []RedundancyMechanismStatus) bool {
	if len(previous) != len(current) {
		return true
	}
	for i := range current {
		if previous[i].Mechanism != current[i].Mechanism || previous[i].ID != current[i].ID || previous[i].State != current[i].State || previous[i].Reason != current[i].Reason {
			return true
		}
	}
	return false
}

func redundancyTransitionCause(previous RedundancyGroupStatus, current RedundancyGroupStatus, exists bool) string {
	if exists && previous.Role != current.Role {
		for _, mechanism := range current.Mechanisms {
			if mechanism.Mechanism == "vrrp" {
				return "vrrp"
			}
		}
	}
	changed := map[string]bool{}
	if !exists {
		for _, mechanism := range current.Mechanisms {
			changed[mechanism.Mechanism] = true
		}
	} else {
		old := map[string]RedundancyMechanismStatus{}
		for _, mechanism := range previous.Mechanisms {
			old[mechanism.Mechanism+":"+mechanism.ID] = mechanism
		}
		for _, mechanism := range current.Mechanisms {
			before, ok := old[mechanism.Mechanism+":"+mechanism.ID]
			if !ok || before.State != mechanism.State || before.Reason != mechanism.Reason {
				changed[mechanism.Mechanism] = true
			}
		}
	}
	causes := make([]string, 0, len(changed))
	for mechanism := range changed {
		causes = append(causes, mechanism)
	}
	sort.Strings(causes)
	return strings.Join(causes, ",")
}

func (r *Runtime) runDHCPGuardBindingSync(ctx context.Context, initial Config) {
	refresh := func(cfg Config) {
		count, conflicts, err := syncDHCPGuardBindings(ctx, r.runner, cfg, keaLeasePath, time.Now())
		status := DHCPGuardSyncSnapshot{Applied: err == nil, LastAttemptAt: time.Now()}
		if err != nil {
			status.Error = err.Error()
		} else {
			status.BindingCount = count
			status.ConflictCount = conflicts
		}
		r.mu.Lock()
		r.dhcpGuardSync = status
		r.mu.Unlock()
	}
	refresh(initial)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.mu.RLock()
			cfg := cloneConfig(r.cfg)
			r.mu.RUnlock()
			if cfg.DHCP.Enabled && hasDHCPBindingGuard(cfg.Layer2) {
				refresh(cfg)
			}
		}
	}
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
