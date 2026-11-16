package l2gw

import (
	"errors"
	"fmt"
	"sync"
)

// EgressPathPolicy controls how a new proxied flow selects one configured path.
// Existing sockets are deliberately not moved when health changes.
type EgressPathPolicy string

const (
	EgressPathLocal    EgressPathPolicy = "local"
	EgressPathFailover EgressPathPolicy = "failover"
	EgressPathWeighted EgressPathPolicy = "weighted"
)

var ErrNoHealthyEgressPath = errors.New("l2gw: no healthy egress path")
var ErrUnknownEgressPath = errors.New("l2gw: unknown egress path")

// EgressPathSelector selects one healthy Linux egress member per new flow.
// Health is supplied by the routing control plane (for example, BGP/BFD state).
type EgressPathSelector interface {
	Select(flowKey []byte) (ECMPPath, error)
	SetHealth(name string, healthy bool, reason string) error
	Snapshot() []EgressPathHealth
}

// EgressPathHealth is the current control-plane view of one configured path.
type EgressPathHealth struct {
	Name    string `json:"name"`
	Healthy bool   `json:"healthy"`
	Reason  string `json:"reason,omitempty"`
}

type selectedPath struct {
	path    ECMPPath
	healthy bool
	reason  string
}

// NewEgressPathSelector creates a stable selector. Dynamic paths start
// unhealthy until the routing control plane confirms their peers are up.
func NewEgressPathSelector(policy EgressPathPolicy, paths []ECMPPath) (EgressPathSelector, error) {
	if policy != EgressPathFailover && policy != EgressPathWeighted {
		return nil, fmt.Errorf("l2gw: egress path policy must be failover or weighted")
	}
	if len(paths) == 0 {
		return nil, errors.New("l2gw: selected egress path policy requires configured paths")
	}
	if err := ValidateECMPPaths(paths); err != nil {
		return nil, err
	}
	s := &egressPathSelector{policy: policy, byName: make(map[string]int, len(paths))}
	for i, path := range paths {
		s.byName[path.Name] = i
		s.paths = append(s.paths, selectedPath{path: path, reason: "waiting for routing health"})
	}
	return s, nil
}

type egressPathSelector struct {
	mu     sync.RWMutex
	policy EgressPathPolicy
	paths  []selectedPath
	byName map[string]int
}

func (s *egressPathSelector) Select(flowKey []byte) (ECMPPath, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var healthy []ECMPPath
	for _, member := range s.paths {
		if member.healthy {
			if s.policy == EgressPathFailover {
				return member.path, nil
			}
			healthy = append(healthy, member.path)
		}
	}
	if len(healthy) == 0 {
		return ECMPPath{}, ErrNoHealthyEgressPath
	}
	return SelectECMPPath(healthy, flowKey)
}

func (s *egressPathSelector) SetHealth(name string, healthy bool, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	index, ok := s.byName[name]
	if !ok {
		return fmt.Errorf("%w %q", ErrUnknownEgressPath, name)
	}
	s.paths[index].healthy = healthy
	s.paths[index].reason = reason
	return nil
}

func (s *egressPathSelector) Snapshot() []EgressPathHealth {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]EgressPathHealth, 0, len(s.paths))
	for _, member := range s.paths {
		out = append(out, EgressPathHealth{Name: member.path.Name, Healthy: member.healthy, Reason: member.reason})
	}
	return out
}

func (g *Gateway) egressPaths(flowKey []byte) ([]ECMPPath, error) {
	if g.cfg.EgressSelector == nil {
		return g.cfg.ECMPPaths, nil
	}
	path, err := g.cfg.EgressSelector.Select(flowKey)
	if err != nil {
		return nil, err
	}
	return []ECMPPath{path}, nil
}
