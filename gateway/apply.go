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
	copy.NAT.Rules = append([]NATRule(nil), cfg.NAT.Rules...)
	copy.Routing.Policies = append([]RoutePolicy(nil), cfg.Routing.Policies...)
	copy.QoS.Interfaces = append([]QoSInterface(nil), cfg.QoS.Interfaces...)
	for i := range copy.QoS.Interfaces {
		copy.QoS.Interfaces[i].Classes = append([]QoSClass(nil), cfg.QoS.Interfaces[i].Classes...)
	}
	copy.DHCP.Subnets = append([]DHCPSubnet(nil), cfg.DHCP.Subnets...)
	for i := range copy.DHCP.Subnets {
		copy.DHCP.Subnets[i].DNS = append([]string(nil), cfg.DHCP.Subnets[i].DNS...)
		copy.DHCP.Subnets[i].Reservations = append([]DHCPReservation(nil), cfg.DHCP.Subnets[i].Reservations...)
		copy.DHCP.Subnets[i].Options = append([]DHCPOption(nil), cfg.DHCP.Subnets[i].Options...)
	}
	copy.VRRP.Peers = append([]string(nil), cfg.VRRP.Peers...)
	copy.VRRP.VirtualAddresses = append([]string(nil), cfg.VRRP.VirtualAddresses...)
	copy.IGMPProxy.DownstreamInterfaceIDs = append([]string(nil), cfg.IGMPProxy.DownstreamInterfaceIDs...)
	copy.IGMPProxy.AllowedSources = append([]string(nil), cfg.IGMPProxy.AllowedSources...)
	copy.DynamicRouting.OSPF.Interfaces = append([]OSPFInterface(nil), cfg.DynamicRouting.OSPF.Interfaces...)
	copy.MDNS.InterfaceIDs = append([]string(nil), cfg.MDNS.InterfaceIDs...)
	copy.MDNS.ReflectFilters = append([]string(nil), cfg.MDNS.ReflectFilters...)
	copy.RADIUS.Clients = append([]RADIUSClient(nil), cfg.RADIUS.Clients...)
	copy.RADIUS.Users = append([]RADIUSUser(nil), cfg.RADIUS.Users...)
	copy.DynamicRouting.BGP.Neighbors = append([]BGPNeighbor(nil), cfg.DynamicRouting.BGP.Neighbors...)
	for i := range copy.DynamicRouting.BGP.Neighbors {
		copy.DynamicRouting.BGP.Neighbors[i].Import = append([]string(nil), cfg.DynamicRouting.BGP.Neighbors[i].Import...)
		copy.DynamicRouting.BGP.Neighbors[i].Export = append([]string(nil), cfg.DynamicRouting.BGP.Neighbors[i].Export...)
	}
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
		layer2Copy.Bonds = append([]layer2.Bond(nil), cfg.Layer2.Bonds...)
		for i := range layer2Copy.Bonds {
			layer2Copy.Bonds[i].Members = append([]string(nil), cfg.Layer2.Bonds[i].Members...)
		}
		layer2Copy.Overrides = append([]layer2.DeviceOverride(nil), cfg.Layer2.Overrides...)
		layer2Copy.MACBlocks = append([]layer2.MACBlock(nil), cfg.Layer2.MACBlocks...)
		layer2Copy.MACACL = append([]layer2.MACACLRule(nil), cfg.Layer2.MACACL...)
		layer2Copy.IPACL = append([]layer2.IPACLRule(nil), cfg.Layer2.IPACL...)
		layer2Copy.EgressRates = append([]layer2.EgressRateLimit(nil), cfg.Layer2.EgressRates...)
		layer2Copy.FlowControl = append([]layer2.FlowControlPolicy(nil), cfg.Layer2.FlowControl...)
		layer2Copy.MACPortRestrictions = append([]layer2.MACPortRestriction(nil), cfg.Layer2.MACPortRestrictions...)
		for i := range layer2Copy.MACPortRestrictions {
			layer2Copy.MACPortRestrictions[i].AllowedMACs = append([]string(nil), cfg.Layer2.MACPortRestrictions[i].AllowedMACs...)
		}
		copy.Layer2 = &layer2Copy
	}
	return copy
}
