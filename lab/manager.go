package lab

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// NodeProcess and VirtualLink are owned runtime objects. Concrete backends can
// use namespaces, gVisor, or another single-host sandbox implementation.
type NodeProcess interface {
	Start(context.Context) error
	Pause(context.Context) error
	Resume(context.Context) error
	Restart(context.Context) error
	Close(context.Context) error
	Console(context.Context) (io.ReadWriteCloser, error)
	Stats(context.Context) (map[string]any, error)
	Check(context.Context, Assertion) (AssertionResult, error)
}

type AssertionResult struct {
	ID       string        `json:"id"`
	Node     string        `json:"node"`
	Kind     string        `json:"kind"`
	Passed   bool          `json:"passed"`
	Details  string        `json:"details,omitempty"`
	Duration time.Duration `json:"duration_ns"`
}

type VirtualLink interface {
	SetImpairment(context.Context, Impairment) error
	SetEndpointFault(context.Context, string, string, Impairment) error
	SetUp(context.Context, bool) error
	Stats(context.Context) (map[string]any, error)
	Capture(context.Context, io.Writer, time.Duration) error
	Close(context.Context) error
}

// Backend starts one isolated node and connects its interfaces into a private
// point-to-point link. Run IDs must be unique so a replacement can be prepared
// before the currently applied generation is removed.
type Backend interface {
	StartNode(context.Context, string, Node) (NodeProcess, error)
	Connect(context.Context, string, Link, NodeProcess, NodeProcess) (VirtualLink, error)
}

type Limits struct {
	Nodes     int
	CPUShares uint64
	MemoryMiB uint64
}

type State struct {
	Topology Topology  `json:"topology"`
	RunID    string    `json:"run_id"`
	Status   string    `json:"status"`
	Updated  time.Time `json:"updated"`
}

type generation struct {
	state  Topology
	runID  string
	nodes  map[string]NodeProcess
	links  map[string]VirtualLink
	status string
}

// Manager coordinates one topology on one host. A replacement is prepared in
// a fresh generation; failed preparation is closed without disturbing the
// active generation. Callers must provide an OS sandbox backend.
type Manager struct {
	mu        sync.Mutex
	backend   Backend
	limits    Limits
	sequence  uint64
	namespace uint64
	active    *generation
	previous  *Topology
}

var managerNamespace atomic.Uint64

func NewManager(backend Backend, limits Limits) (*Manager, error) {
	if backend == nil {
		return nil, errors.New("lab runtime backend is required")
	}
	if limits.Nodes < 1 {
		limits.Nodes = MaxNodes
	}
	if limits.Nodes > MaxNodes {
		limits.Nodes = MaxNodes
	}
	return &Manager{backend: backend, limits: limits, namespace: managerNamespace.Add(1)}, nil
}

// Close releases the active generation and its host resources during a clean
// portal shutdown. A manager with no applied topology is already closed.
func (m *Manager) Close(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active == nil {
		return nil
	}
	active := m.active
	m.active = nil
	m.previous = nil
	return closeGeneration(ctx, active)
}

func (m *Manager) Apply(ctx context.Context, topology Topology) (State, error) {
	if err := topology.Validate(); err != nil {
		return State{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkCapacity(topology); err != nil {
		return State{}, err
	}
	m.sequence++
	runID := fmt.Sprintf("%s-%d-%d", topology.ID, m.namespace, m.sequence)
	next := &generation{state: topology, runID: runID, nodes: make(map[string]NodeProcess), links: make(map[string]VirtualLink), status: "starting"}
	cleanup := func() { _ = closeGeneration(context.Background(), next) }
	for _, nodeID := range topology.SortedNodeIDs() {
		node := findNode(topology, nodeID)
		process, err := m.backend.StartNode(ctx, runID, node)
		if err != nil {
			cleanup()
			return State{}, fmt.Errorf("start node %s: %w", nodeID, err)
		}
		next.nodes[nodeID] = process
	}
	links := append([]Link(nil), topology.Links...)
	sort.Slice(links, func(i, j int) bool { return links[i].ID < links[j].ID })
	for _, link := range links {
		virtual, err := m.backend.Connect(ctx, runID, link, next.nodes[link.A.Node], next.nodes[link.B.Node])
		if err != nil {
			cleanup()
			return State{}, fmt.Errorf("connect link %s: %w", link.ID, err)
		}
		next.links[link.ID] = virtual
	}
	for _, nodeID := range topology.SortedNodeIDs() {
		if err := next.nodes[nodeID].Start(ctx); err != nil {
			cleanup()
			return State{}, fmt.Errorf("configure node %s: %w", nodeID, err)
		}
	}
	next.status = "running"
	previous := m.active
	m.active = next
	if previous != nil {
		if err := closeGeneration(ctx, previous); err != nil {
			m.active = previous
			cleanup()
			return State{}, fmt.Errorf("remove previous generation: %w", err)
		}
		old := cloneTopology(previous.state)
		m.previous = &old
	}
	return State{Topology: cloneTopology(topology), RunID: runID, Status: next.status, Updated: time.Now().UTC()}, nil
}

// Rollback reapplies the last topology generation that was replaced.
func (m *Manager) Rollback(ctx context.Context) (State, error) {
	m.mu.Lock()
	if m.previous == nil {
		m.mu.Unlock()
		return State{}, errors.New("no previous lab topology is available")
	}
	prior := cloneTopology(*m.previous)
	m.mu.Unlock()
	return m.Apply(ctx, prior)
}

func (m *Manager) Snapshot() (State, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active == nil {
		return State{}, false
	}
	return State{Topology: cloneTopology(m.active.state), RunID: m.active.runID, Status: m.active.status, Updated: time.Now().UTC()}, true
}

// Observe returns a bounded status snapshot from the active node and link
// handles. Backend-provided maps must already be safe for JSON encoding.
func (m *Manager) Observe(ctx context.Context) (map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active == nil {
		return map[string]any{"running": false}, nil
	}
	nodes := make(map[string]any, len(m.active.nodes))
	links := make(map[string]any, len(m.active.links))
	for id, node := range m.active.nodes {
		stats, err := node.Stats(ctx)
		if err != nil {
			return nil, fmt.Errorf("node %s stats: %w", id, err)
		}
		nodes[id] = stats
	}
	for id, link := range m.active.links {
		stats, err := link.Stats(ctx)
		if err != nil {
			return nil, fmt.Errorf("link %s stats: %w", id, err)
		}
		links[id] = stats
	}
	return map[string]any{"running": true, "run_id": m.active.runID, "status": m.active.status, "topology": cloneTopology(m.active.state), "nodes": nodes, "links": links}, nil
}

func (m *Manager) RunAssertions(ctx context.Context) ([]AssertionResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active == nil {
		return nil, errors.New("no lab is running")
	}
	results := make([]AssertionResult, 0, len(m.active.state.Assertions))
	for _, assertion := range m.active.state.Assertions {
		started := time.Now()
		result, err := m.active.nodes[assertion.Node].Check(ctx, assertion)
		if err != nil {
			return results, fmt.Errorf("assertion %s: %w", assertion.ID, err)
		}
		result.ID, result.Node, result.Kind = assertion.ID, assertion.Node, assertion.Kind
		if result.Duration == 0 {
			result.Duration = time.Since(started)
		}
		results = append(results, result)
	}
	return results, nil
}

func (m *Manager) CaptureLink(ctx context.Context, id string, duration time.Duration) (string, error) {
	if duration < 100*time.Millisecond || duration > 30*time.Second {
		return "", errors.New("capture duration must be 100ms..30s")
	}
	m.mu.Lock()
	if m.active == nil {
		m.mu.Unlock()
		return "", errors.New("no lab is running")
	}
	link, ok := m.active.links[id]
	m.mu.Unlock()
	if !ok {
		return "", fmt.Errorf("unknown link %q", id)
	}
	buffer := &limitedCapture{remaining: 1 << 20}
	if err := link.Capture(ctx, buffer, duration); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buffer.data.Bytes()), nil
}

type limitedCapture struct {
	data      bytes.Buffer
	remaining int
}

func (w *limitedCapture) Write(p []byte) (int, error) {
	if len(p) > w.remaining {
		n, _ := w.data.Write(p[:w.remaining])
		w.remaining = 0
		return n, errors.New("capture exceeded 1 MiB")
	}
	n, err := w.data.Write(p)
	w.remaining -= n
	return n, err
}

func (m *Manager) Pause(ctx context.Context) error {
	return m.withNodes(ctx, "paused", func(n NodeProcess) error { return n.Pause(ctx) })
}
func (m *Manager) Resume(ctx context.Context) error {
	return m.withNodes(ctx, "running", func(n NodeProcess) error { return n.Resume(ctx) })
}

func (m *Manager) RestartNode(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active == nil {
		return errors.New("no lab is running")
	}
	node, ok := m.active.nodes[id]
	if !ok {
		return fmt.Errorf("unknown node %q", id)
	}
	return node.Restart(ctx)
}

func (m *Manager) SetLinkUp(ctx context.Context, id string, up bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active == nil {
		return errors.New("no lab is running")
	}
	link, ok := m.active.links[id]
	if !ok {
		return fmt.Errorf("unknown link %q", id)
	}
	return link.SetUp(ctx, up)
}

func (m *Manager) FlapLink(ctx context.Context, id string, duration time.Duration) error {
	if duration < 100*time.Millisecond || duration > time.Minute {
		return errors.New("link flap duration must be 100ms..60s")
	}
	m.mu.Lock()
	if m.active == nil {
		m.mu.Unlock()
		return errors.New("no lab is running")
	}
	generation := m.active
	link, ok := generation.links[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("unknown link %q", id)
	}
	if err := link.SetUp(ctx, false); err != nil {
		m.mu.Unlock()
		return err
	}
	m.mu.Unlock()
	go func() {
		timer := time.NewTimer(duration)
		defer timer.Stop()
		<-timer.C
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.active == generation {
			_ = link.SetUp(context.Background(), true)
		}
	}()
	return nil
}

func (m *Manager) SetImpairment(ctx context.Context, id string, impairment Impairment) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active == nil {
		return errors.New("no lab is running")
	}
	var candidate = Topology{Version: TopologyVersion, ID: m.active.state.ID, Name: m.active.state.Name, Nodes: m.active.state.Nodes,
		Links: append([]Link(nil), m.active.state.Links...)}
	found := false
	for i := range candidate.Links {
		if candidate.Links[i].ID == id {
			candidate.Links[i].Impairment = impairment
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("unknown link %q", id)
	}
	if err := candidate.Validate(); err != nil {
		return err
	}
	if err := m.active.links[id].SetImpairment(ctx, impairment); err != nil {
		return err
	}
	m.active.state = candidate
	return nil
}

// SetInterfaceFault injects receive-independent wire errors on the named
// node interface's egress. Only packet loss and corruption are accepted here;
// latency, shaping, and bandwidth remain link properties.
func (m *Manager) SetInterfaceFault(ctx context.Context, nodeID, interfaceID string, fault Impairment) error {
	if fault.LatencyMS != 0 || fault.JitterMS != 0 || fault.BandwidthBPS != 0 || !finite(fault.LossPct) || !finite(fault.CorruptPct) || fault.LossPct < 0 || fault.LossPct > 100 || fault.CorruptPct < 0 || fault.CorruptPct > 100 {
		return errors.New("interface fault accepts loss_pct and corrupt_pct from 0 to 100")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active == nil {
		return errors.New("no lab is running")
	}
	for _, spec := range m.active.state.Links {
		for _, endpoint := range []Endpoint{spec.A, spec.B} {
			if endpoint.Node == nodeID && endpoint.Interface == interfaceID {
				return m.active.links[spec.ID].SetEndpointFault(ctx, nodeID, interfaceID, fault)
			}
		}
	}
	return fmt.Errorf("interface %s/%s is not connected to a lab link", nodeID, interfaceID)
}

func (m *Manager) NodeConsole(ctx context.Context, id string) (io.ReadWriteCloser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active == nil {
		return nil, errors.New("no lab is running")
	}
	node, ok := m.active.nodes[id]
	if !ok {
		return nil, fmt.Errorf("unknown node %q", id)
	}
	return node.Console(ctx)
}

func (m *Manager) withNodes(ctx context.Context, status string, action func(NodeProcess) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active == nil {
		return errors.New("no lab is running")
	}
	ids := make([]string, 0, len(m.active.nodes))
	for id := range m.active.nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	done := make([]NodeProcess, 0, len(ids))
	for _, id := range ids {
		node := m.active.nodes[id]
		if err := action(node); err != nil {
			for i := len(done) - 1; i >= 0; i-- {
				if status == "paused" {
					_ = done[i].Resume(context.Background())
				} else {
					_ = done[i].Pause(context.Background())
				}
			}
			return fmt.Errorf("update node %s: %w", id, err)
		}
		done = append(done, node)
	}
	m.active.status = status
	return nil
}

func (m *Manager) checkCapacity(t Topology) error {
	if len(t.Nodes) > m.limits.Nodes {
		return fmt.Errorf("topology requests %d nodes; host limit is %d", len(t.Nodes), m.limits.Nodes)
	}
	var cpu, memory uint64
	for _, n := range t.Nodes {
		shares := n.Resources.CPUShares
		if shares == 0 {
			shares = 1024
		}
		mem := n.Resources.MemoryMiB
		if mem == 0 {
			mem = 256
		}
		cpu += uint64(shares)
		memory += uint64(mem)
	}
	if m.limits.CPUShares > 0 && cpu > m.limits.CPUShares {
		return fmt.Errorf("topology requests %d CPU shares; host limit is %d", cpu, m.limits.CPUShares)
	}
	if m.limits.MemoryMiB > 0 && memory > m.limits.MemoryMiB {
		return fmt.Errorf("topology requests %d MiB; host limit is %d MiB", memory, m.limits.MemoryMiB)
	}
	return nil
}

func closeGeneration(ctx context.Context, g *generation) error {
	var first error
	linkIDs := make([]string, 0, len(g.links))
	for id := range g.links {
		linkIDs = append(linkIDs, id)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(linkIDs)))
	for _, id := range linkIDs {
		if err := g.links[id].Close(ctx); err != nil && first == nil {
			first = err
		}
	}
	nodeIDs := make([]string, 0, len(g.nodes))
	for id := range g.nodes {
		nodeIDs = append(nodeIDs, id)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(nodeIDs)))
	for _, id := range nodeIDs {
		if err := g.nodes[id].Close(ctx); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func findNode(t Topology, id string) Node {
	for _, n := range t.Nodes {
		if n.ID == id {
			return n
		}
	}
	return Node{}
}

func cloneTopology(t Topology) Topology {
	data, _ := json.Marshal(t)
	var out Topology
	_ = json.Unmarshal(data, &out)
	return out
}
