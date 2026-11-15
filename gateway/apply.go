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
	mu       sync.RWMutex
	path     string
	current  Config
	previous *Config
	applier  Applier
	status   ApplyStatus
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

// Previous returns the last successfully committed config before Current.
func (m *Manager) Previous() (Config, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.previous == nil {
		return Config{}, false
	}
	return cloneConfig(*m.previous), true
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
	return m.applyLocked(ctx, desired)
}

// Rollback reapplies the previous successfully committed desired config.
// The history is intentionally one step and in-memory; the operation is
// unavailable after restart until another successful apply.
func (m *Manager) Rollback(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.previous == nil {
		return errors.New("no previous successful gateway configuration is available for rollback")
	}
	return m.applyLocked(ctx, cloneConfig(*m.previous))
}

func (m *Manager) applyLocked(ctx context.Context, desired Config) error {
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
	previous := cloneConfig(m.current)
	m.previous = &previous
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
	if cfg.VRRP.BFD != nil {
		bfdCopy := *cfg.VRRP.BFD
		copy.VRRP.BFD = &bfdCopy
	}
	copy.IGMPProxy.DownstreamInterfaceIDs = append([]string(nil), cfg.IGMPProxy.DownstreamInterfaceIDs...)
	copy.IGMPProxy.AllowedSources = append([]string(nil), cfg.IGMPProxy.AllowedSources...)
	copy.DynamicRouting.OSPF.Interfaces = append([]OSPFInterface(nil), cfg.DynamicRouting.OSPF.Interfaces...)
	copy.MDNS.InterfaceIDs = append([]string(nil), cfg.MDNS.InterfaceIDs...)
	copy.MDNS.ReflectFilters = append([]string(nil), cfg.MDNS.ReflectFilters...)
	copy.RADIUS.Clients = append([]RADIUSClient(nil), cfg.RADIUS.Clients...)
	copy.RADIUS.Users = append([]RADIUSUser(nil), cfg.RADIUS.Users...)
	copy.DynamicRouting.BGP.Neighbors = append([]BGPNeighbor(nil), cfg.DynamicRouting.BGP.Neighbors...)
	copy.DynamicRouting.BGP.EVPN.Neighbors = append([]string(nil), cfg.DynamicRouting.BGP.EVPN.Neighbors...)
	copy.DynamicRouting.BGP.EVPN.EthernetSegments = append([]BGPFlowEVPNEthernetSegment(nil), cfg.DynamicRouting.BGP.EVPN.EthernetSegments...)
	for i := range copy.DynamicRouting.BGP.Neighbors {
		copy.DynamicRouting.BGP.Neighbors[i].Import = append([]string(nil), cfg.DynamicRouting.BGP.Neighbors[i].Import...)
		copy.DynamicRouting.BGP.Neighbors[i].Export = append([]string(nil), cfg.DynamicRouting.BGP.Neighbors[i].Export...)
	}
	if cfg.Layer2 != nil {
		layer2Copy := *cfg.Layer2
		layer2Copy.Interfaces = append([]layer2.Interface(nil), cfg.Layer2.Interfaces...)
		layer2Copy.Bridges = append([]layer2.Bridge(nil), cfg.Layer2.Bridges...)
		for i := range layer2Copy.Bridges {
			if cfg.Layer2.Bridges[i].STPPriority != nil {
				value := *cfg.Layer2.Bridges[i].STPPriority
				layer2Copy.Bridges[i].STPPriority = &value
			}
			if cfg.Layer2.Bridges[i].STPEnabled != nil {
				value := *cfg.Layer2.Bridges[i].STPEnabled
				layer2Copy.Bridges[i].STPEnabled = &value
			}
			if cfg.Layer2.Bridges[i].IGMPSnooping != nil {
				value := *cfg.Layer2.Bridges[i].IGMPSnooping
				layer2Copy.Bridges[i].IGMPSnooping = &value
			}
			if cfg.Layer2.Bridges[i].IGMPQuerier != nil {
				value := *cfg.Layer2.Bridges[i].IGMPQuerier
				layer2Copy.Bridges[i].IGMPQuerier = &value
			}
			layer2Copy.Bridges[i].Ports = append([]layer2.BridgePort(nil), cfg.Layer2.Bridges[i].Ports...)
			for j := range layer2Copy.Bridges[i].Ports {
				if cfg.Layer2.Bridges[i].Ports[j].STPPriority != nil {
					value := *cfg.Layer2.Bridges[i].Ports[j].STPPriority
					layer2Copy.Bridges[i].Ports[j].STPPriority = &value
				}
				if cfg.Layer2.Bridges[i].Ports[j].STPPathCost != nil {
					value := *cfg.Layer2.Bridges[i].Ports[j].STPPathCost
					layer2Copy.Bridges[i].Ports[j].STPPathCost = &value
				}
				if cfg.Layer2.Bridges[i].Ports[j].STPRootBlock != nil {
					value := *cfg.Layer2.Bridges[i].Ports[j].STPRootBlock
					layer2Copy.Bridges[i].Ports[j].STPRootBlock = &value
				}
				if cfg.Layer2.Bridges[i].Ports[j].STPEdge != nil {
					value := *cfg.Layer2.Bridges[i].Ports[j].STPEdge
					layer2Copy.Bridges[i].Ports[j].STPEdge = &value
				}
				if cfg.Layer2.Bridges[i].Ports[j].STPBPDUGuard != nil {
					value := *cfg.Layer2.Bridges[i].Ports[j].STPBPDUGuard
					layer2Copy.Bridges[i].Ports[j].STPBPDUGuard = &value
				}
				if cfg.Layer2.Bridges[i].Ports[j].LoopProtection != nil {
					value := *cfg.Layer2.Bridges[i].Ports[j].LoopProtection
					layer2Copy.Bridges[i].Ports[j].LoopProtection = &value
				}
				if cfg.Layer2.Bridges[i].Ports[j].IGMPFastLeave != nil {
					value := *cfg.Layer2.Bridges[i].Ports[j].IGMPFastLeave
					layer2Copy.Bridges[i].Ports[j].IGMPFastLeave = &value
				}
				if cfg.Layer2.Bridges[i].Ports[j].IGMPSharedDownstream != nil {
					value := *cfg.Layer2.Bridges[i].Ports[j].IGMPSharedDownstream
					layer2Copy.Bridges[i].Ports[j].IGMPSharedDownstream = &value
				}
				if cfg.Layer2.Bridges[i].Ports[j].IGMPRouterPort != nil {
					value := *cfg.Layer2.Bridges[i].Ports[j].IGMPRouterPort
					layer2Copy.Bridges[i].Ports[j].IGMPRouterPort = &value
				}
				layer2Copy.Bridges[i].Ports[j].TaggedNetworks = append([]string(nil), cfg.Layer2.Bridges[i].Ports[j].TaggedNetworks...)
				layer2Copy.Bridges[i].Ports[j].LLDPMED = append([]layer2.LLDPMEDPolicy(nil), cfg.Layer2.Bridges[i].Ports[j].LLDPMED...)
				for k := range layer2Copy.Bridges[i].Ports[j].LLDPMED {
					if cfg.Layer2.Bridges[i].Ports[j].LLDPMED[k].Priority != nil {
						value := *cfg.Layer2.Bridges[i].Ports[j].LLDPMED[k].Priority
						layer2Copy.Bridges[i].Ports[j].LLDPMED[k].Priority = &value
					}
					if cfg.Layer2.Bridges[i].Ports[j].LLDPMED[k].DSCP != nil {
						value := *cfg.Layer2.Bridges[i].Ports[j].LLDPMED[k].DSCP
						layer2Copy.Bridges[i].Ports[j].LLDPMED[k].DSCP = &value
					}
				}
			}
		}
		layer2Copy.Networks = append([]layer2.Network(nil), cfg.Layer2.Networks...)
		for i := range layer2Copy.Networks {
			if cfg.Layer2.Networks[i].IGMPSnooping != nil {
				value := *cfg.Layer2.Networks[i].IGMPSnooping
				layer2Copy.Networks[i].IGMPSnooping = &value
			}
		}
		layer2Copy.NetworkACL = append([]layer2.NetworkACLRule(nil), cfg.Layer2.NetworkACL...)
		layer2Copy.Bonds = append([]layer2.Bond(nil), cfg.Layer2.Bonds...)
		for i := range layer2Copy.Bonds {
			layer2Copy.Bonds[i].Members = append([]string(nil), cfg.Layer2.Bonds[i].Members...)
		}
		layer2Copy.Overrides = append([]layer2.DeviceOverride(nil), cfg.Layer2.Overrides...)
		layer2Copy.MACBlocks = append([]layer2.MACBlock(nil), cfg.Layer2.MACBlocks...)
		layer2Copy.MACACL = append([]layer2.MACACLRule(nil), cfg.Layer2.MACACL...)
		layer2Copy.IPACL = append([]layer2.IPACLRule(nil), cfg.Layer2.IPACL...)
		layer2Copy.EgressRates = append([]layer2.EgressRateLimit(nil), cfg.Layer2.EgressRates...)
		layer2Copy.StormControl = append([]layer2.StormControl(nil), cfg.Layer2.StormControl...)
		layer2Copy.MulticastBroadcastLimits = append([]layer2.MulticastBroadcastRateLimit(nil), cfg.Layer2.MulticastBroadcastLimits...)
		layer2Copy.FlowControl = append([]layer2.FlowControlPolicy(nil), cfg.Layer2.FlowControl...)
		layer2Copy.QoS = append([]layer2.QoSPolicy(nil), cfg.Layer2.QoS...)
		layer2Copy.PortMirrors = append([]layer2.PortMirror(nil), cfg.Layer2.PortMirrors...)
		for i := range layer2Copy.QoS {
			layer2Copy.QoS[i].Classes = append([]layer2.QoSClass(nil), cfg.Layer2.QoS[i].Classes...)
			for j := range layer2Copy.QoS[i].Classes {
				layer2Copy.QoS[i].Classes[j].DSCP = append([]uint8(nil), cfg.Layer2.QoS[i].Classes[j].DSCP...)
			}
		}
		layer2Copy.MACPortRestrictions = append([]layer2.MACPortRestriction(nil), cfg.Layer2.MACPortRestrictions...)
		for i := range layer2Copy.MACPortRestrictions {
			layer2Copy.MACPortRestrictions[i].AllowedMACs = append([]string(nil), cfg.Layer2.MACPortRestrictions[i].AllowedMACs...)
		}
		layer2Copy.DHCPGuard = append([]layer2.DHCPGuardPort(nil), cfg.Layer2.DHCPGuard...)
		layer2Copy.PortAuth = append([]layer2.PortAuth(nil), cfg.Layer2.PortAuth...)
		layer2Copy.AVProfiles = append([]layer2.AVProfileSelection(nil), cfg.Layer2.AVProfiles...)
		copy.Layer2 = &layer2Copy
	}
	copy.Redundancy.Groups = append([]RedundancyGroup(nil), cfg.Redundancy.Groups...)
	for i := range copy.Redundancy.Groups {
		copy.Redundancy.Groups[i].Bonds = append([]string(nil), cfg.Redundancy.Groups[i].Bonds...)
		copy.Redundancy.Groups[i].Bridges = append([]string(nil), cfg.Redundancy.Groups[i].Bridges...)
	}
	return copy
}
