package edge

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Dankular/GameBond.Core/bond"
)

const (
	defaultSegmentQueue = 256
	maxSegmentQueue     = 65536
)

type segmentPortRole uint8

const (
	segmentPortGeneric segmentPortRole = iota
	segmentPortSession
	segmentPortService
	segmentPortMonitor
)

// SegmentFabric is the shared Layer 2 switch boundary for several edge sessions that
// belong to the same broadcast domain. A session supervisor creates one fabric per
// segment and attaches each session's Ethernet endpoint. Linux deployments can expose
// the fabric across processes through the authenticated local Unix-socket broker.
type SegmentFabric struct {
	mu              sync.Mutex
	identity        string
	sw              *bond.L2Switch
	ports           map[bond.PortID]*SegmentPort
	nextPort        bond.PortID
	drops           uint64
	mirrorFrames    uint64
	mirrorDrops     uint64
	monitorTAPDrops uint64
	monitor         *SegmentPort
	remoteSocket    string
	remoteIdentity  string
	remoteToken     []byte
	remoteCtx       context.Context
	remoteAttach    bool
}

// SegmentPort is one session or gateway attachment to a SegmentFabric. Send learns
// and switches an ingress frame; Receive yields frames switched to this attachment.
type SegmentPort struct {
	fabric           *SegmentFabric
	id               bond.PortID
	cfgName          string
	rx               chan SegmentFrame
	remote           SegmentAttachment
	role             segmentPortRole
	mirrorIngress    bool
	mirrorEgress     bool
	sourceGuard      bool
	sourceGuardDrops uint64 // protected by fabric.mu; attributed to the authenticated attachment name
	closed           bool   // protected by fabric.mu
}

// SegmentAttachment is the common shape required by edge runtime session and
// service ports. In-process and socket-backed attachments implement it.
type SegmentAttachment interface {
	ID() bond.PortID
	Receive() <-chan SegmentFrame
	Send(frame []byte, now time.Time) bond.L2Verdict
	Close()
}

// SegmentFrame preserves the authenticated ingress attachment selected by the
// supervisor alongside the switched frame. Services use IngressPort for DHCP
// snooping and per-session policy; they must not infer identity from MAC/IP.
type SegmentFrame struct {
	Frame           []byte
	IngressPort     bond.PortID
	IngressIdentity string
}

// NewSegmentFabric constructs a segment-scoped switch. Port IDs and policy come from
// Attach, so callers cannot accidentally create endpoints outside this shared domain.
func NewSegmentFabric(cfg bond.L2SwitchConfig) *SegmentFabric {
	return NewNamedSegmentFabric("", cfg)
}

// NewSegmentFabricChecked constructs a broker switch whose ports attach later.
func NewSegmentFabricChecked(cfg bond.L2SwitchConfig) (*SegmentFabric, error) {
	return NewNamedSegmentFabricChecked("", cfg)
}

// NewNamedSegmentFabric binds switch state to a stable segment identity. A
// supervisor must select this same identity before attaching any session.
func NewNamedSegmentFabric(identity string, cfg bond.L2SwitchConfig) *SegmentFabric {
	fabric, err := NewNamedSegmentFabricChecked(identity, cfg)
	if err != nil {
		panic(err)
	}
	return fabric
}

// NewNamedSegmentFabricChecked binds switch state to a segment identity and
// validates settings before any dynamic session ports can attach.
func NewNamedSegmentFabricChecked(identity string, cfg bond.L2SwitchConfig) (*SegmentFabric, error) {
	cfg.DynamicPorts = true
	cfg.Ports = nil
	// Attach assigns dynamic port IDs. Dynamic mirror rules are added when their
	// source and monitor ports attach.
	cfg.Mirrors = nil
	sw, err := bond.NewL2SwitchChecked(cfg)
	if err != nil {
		return nil, err
	}
	return &SegmentFabric{
		identity: identity,
		sw:       sw,
		ports:    make(map[bond.PortID]*SegmentPort),
	}, nil
}

// Identity returns the stable segment name assigned by the supervisor.
func (f *SegmentFabric) Identity() string {
	if f == nil {
		return ""
	}
	return f.identity
}

// SetMACAuthorization changes the authenticated source-MAC allowlist for one
// broker-owned session identity. Identity is resolved from the attachment
// name assigned during authenticated socket attach, never from an event peer.
func (f *SegmentFabric) SetMACAuthorization(identity string, mac [6]byte, authorized bool) error {
	if f == nil || identity == "" {
		return errors.New("segment fabric: identity is required for MAC authorization")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.remoteSocket != "" {
		return errors.New("segment fabric: MAC authorization must be applied by the broker")
	}
	for _, port := range f.ports {
		if !port.closed && port.role == segmentPortSession && port.cfgName == identity {
			return f.sw.SetPortMACAuthorized(port.id, mac, authorized)
		}
	}
	return fmt.Errorf("segment fabric: session identity %q is not attached", identity)
}

func isDHCPv4LeaseFrame(frame []byte) bool {
	info, err := bond.ParseFrame(frame)
	if err != nil || info.IP == nil {
		return false
	}
	return info.IP.Protocol == 17 && info.IP.HasPorts && info.IP.SourcePort == 68 && info.IP.DestinationPort == 67
}

// Attach registers a session or service endpoint. queueDepth bounds memory consumed
// by a slow recipient; zero selects 256 frames. A full recipient queue drops that
// egress copy and increments the fabric's drop count without blocking other ports.
func (f *SegmentFabric) Attach(cfg bond.L2PortConfig, queueDepth int) (*SegmentPort, error) {
	return f.attach(cfg, queueDepth, segmentPortGeneric, false, false)
}

// AttachSession registers a tunnel/session attachment and optionally mirrors
// its ingress and egress frames to the segment's monitor port.
func (f *SegmentFabric) AttachSession(cfg bond.L2PortConfig, queueDepth int, mirrorIngress, mirrorEgress bool) (*SegmentPort, error) {
	return f.attach(cfg, queueDepth, segmentPortSession, mirrorIngress, mirrorEgress)
}

// AttachService registers a gateway/service port and its monitor directions.
func (f *SegmentFabric) AttachService(cfg bond.L2PortConfig, queueDepth int, mirrorIngress, mirrorEgress bool) (*SegmentPort, error) {
	return f.attach(cfg, queueDepth, segmentPortService, mirrorIngress, mirrorEgress)
}

// AttachMonitor creates the one output-only monitor port for a segment.
func (f *SegmentFabric) AttachMonitor(name string, queueDepth int) (*SegmentPort, error) {
	return f.attach(bond.L2PortConfig{Name: name, Monitor: true}, queueDepth, segmentPortMonitor, false, false)
}

func (f *SegmentFabric) attach(cfg bond.L2PortConfig, queueDepth int, role segmentPortRole, mirrorIngress, mirrorEgress bool) (*SegmentPort, error) {
	if f == nil {
		return nil, errors.New("segment fabric is nil")
	}
	if queueDepth == 0 {
		queueDepth = defaultSegmentQueue
	}
	if queueDepth < 1 || queueDepth > maxSegmentQueue {
		return nil, fmt.Errorf("segment queue depth must be 1..%d", maxSegmentQueue)
	}
	if cfg.Monitor && role != segmentPortMonitor {
		return nil, errors.New("segment monitor ports must use AttachMonitor")
	}
	if role == segmentPortMonitor && f.remoteSocket != "" {
		return nil, errors.New("remote session fabrics cannot host a segment monitor")
	}
	if f.remoteSocket != "" {
		port, err := f.attachRemote(cfg, queueDepth)
		if err != nil {
			return nil, err
		}
		port.role, port.mirrorIngress, port.mirrorEgress, port.sourceGuard = role, mirrorIngress, mirrorEgress, cfg.IPv4SourceGuard || cfg.IPv6SourceGuard
		return port, nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextPort++
	if f.nextPort <= 0 {
		return nil, errors.New("segment port ID space exhausted")
	}
	cfg.ID = f.nextPort
	if cfg.Name == "" {
		cfg.Name = fmt.Sprintf("segment-%d", cfg.ID)
	}
	for _, port := range f.ports {
		if port.cfgName == cfg.Name {
			return nil, fmt.Errorf("segment port name %q is already attached", cfg.Name)
		}
	}
	if err := f.sw.AddPort(cfg); err != nil {
		return nil, err
	}
	p := &SegmentPort{fabric: f, id: cfg.ID, cfgName: cfg.Name, rx: make(chan SegmentFrame, queueDepth), role: role,
		mirrorIngress: mirrorIngress, mirrorEgress: mirrorEgress, sourceGuard: cfg.IPv4SourceGuard || cfg.IPv6SourceGuard}
	if role == segmentPortMonitor {
		if f.monitor != nil {
			f.sw.RemovePort(p.id)
			return nil, errors.New("segment fabric already has a monitor port")
		}
		f.monitor = p
	}
	f.ports[p.id] = p
	if role == segmentPortMonitor {
		for _, source := range f.ports {
			if source == p {
				continue
			}
			if err := f.addPortMirror(source); err != nil {
				f.sw.RemovePort(p.id)
				delete(f.ports, p.id)
				f.monitor = nil
				return nil, err
			}
		}
	} else if f.monitor != nil {
		if err := f.addPortMirror(p); err != nil {
			f.sw.RemovePort(p.id)
			delete(f.ports, p.id)
			return nil, err
		}
	}
	return p, nil
}

// ReplaceDHCPSourceBindings refreshes guarded session ports from leases whose
// ingress identities were supplied by authenticated fabric attachments.
func (f *SegmentFabric) ReplaceDHCPSourceBindings(byIdentity map[string][]bond.L2SourceBinding) error {
	if f == nil {
		return errors.New("segment fabric is nil")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.remoteSocket != "" {
		return errors.New("DHCP source bindings must be installed by the fabric broker")
	}
	for _, port := range f.ports {
		if port.closed || port.role != segmentPortSession || !port.sourceGuard {
			continue
		}
		if err := f.sw.SetPortSourceBindings(port.id, byIdentity[port.cfgName]); err != nil {
			return fmt.Errorf("refresh source bindings for %q: %w", port.cfgName, err)
		}
	}
	return nil
}

func (f *SegmentFabric) addPortMirror(source *SegmentPort) error {
	if f.monitor == nil || source == nil || source.role == segmentPortMonitor || (!source.mirrorIngress && !source.mirrorEgress) {
		return nil
	}
	return f.sw.AddMirror(bond.L2Mirror{Source: source.id, Monitor: f.monitor.id, Ingress: source.mirrorIngress, Egress: source.mirrorEgress})
}

// RecordMonitorTAPDrop counts a mirrored frame that the kernel monitor TAP
// could not accept.
func (f *SegmentFabric) RecordMonitorTAPDrop() {
	if f == nil {
		return
	}
	f.mu.Lock()
	f.monitorTAPDrops++
	f.mu.Unlock()
}

// ID returns the switch port ID assigned at attachment time.
func (p *SegmentPort) ID() bond.PortID {
	if p == nil {
		return 0
	}
	return p.id
}

// Receive exposes the bounded frame queue switched to this attachment. The channel
// closes when the port is detached from its fabric.
func (p *SegmentPort) Receive() <-chan SegmentFrame {
	if p == nil {
		return nil
	}
	if p.remote != nil {
		return p.remote.Receive()
	}
	return p.rx
}

// Send forwards a frame from this attachment to the other eligible ports. Each
// recipient receives an independent frame copy, so callers may reuse their buffer.
func (p *SegmentPort) Send(frame []byte, now time.Time) bond.L2Verdict {
	if p != nil && p.remote != nil {
		return p.remote.Send(frame, now)
	}
	if p == nil || p.fabric == nil {
		return bond.L2Verdict{Drop: bond.L2DropNoPort}
	}
	f := p.fabric
	f.mu.Lock()
	defer f.mu.Unlock()
	if p.closed || f.ports[p.id] != p {
		return bond.L2Verdict{Drop: bond.L2DropNoPort}
	}
	v := f.sw.Forward(p.id, frame, now)
	if v.Drop == bond.L2DropSourceGuard {
		p.sourceGuardDrops++
	}
	for _, id := range v.Mirror {
		out := f.ports[id]
		if out == nil || out.closed || out.role != segmentPortMonitor {
			continue
		}
		copyFrame := append([]byte(nil), v.FrameFor(id, frame)...)
		select {
		case out.rx <- SegmentFrame{Frame: copyFrame, IngressPort: p.id, IngressIdentity: p.cfgName}:
			f.mirrorFrames++
		default:
			f.mirrorDrops++
			f.drops++
		}
	}
	if v.Drop != bond.L2Forward {
		return v
	}
	for _, id := range v.Out {
		out := f.ports[id]
		if out == nil || out.closed {
			continue
		}
		copyFrame := append([]byte(nil), v.FrameFor(id, frame)...)
		select {
		case out.rx <- SegmentFrame{Frame: copyFrame, IngressPort: p.id, IngressIdentity: p.cfgName}:
		default:
			f.drops++
		}
	}
	return v
}

// Close removes the port and all FDB and multicast state learned behind it, then
// closes its receive queue. It is safe to call more than once.
func (p *SegmentPort) Close() {
	if p == nil || p.fabric == nil {
		return
	}
	f := p.fabric
	f.mu.Lock()
	if p.closed {
		f.mu.Unlock()
		return
	}
	p.closed = true
	delete(f.ports, p.id)
	if p == f.monitor {
		f.monitor = nil
	}
	if p.remote != nil {
		f.mu.Unlock()
		p.remote.Close()
		return
	}
	f.sw.RemovePort(p.id)
	for len(p.rx) > 0 {
		<-p.rx // discard queued frames so detach cannot leak stale traffic to a replacement port
		f.drops++
	}
	close(p.rx)
	f.mu.Unlock()
}

// Stats returns the switch snapshot and the number of attached endpoints and bounded
// queue copies dropped because a recipient could not keep up.
func (f *SegmentFabric) Stats() map[string]any {
	if f == nil {
		return map[string]any{}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.remoteSocket != "" {
		var incoming, outgoing uint64
		for _, port := range f.ports {
			if drops, ok := port.remote.(interface{ QueueDrops() (uint64, uint64) }); ok {
				in, out := drops.QueueDrops()
				incoming += in
				outgoing += out
			}
		}
		return map[string]any{"segment_id": f.identity, "remote": true, "attached_ports": len(f.ports), "queue_drops": map[string]uint64{"incoming": incoming, "outgoing": outgoing}}
	}
	sourceGuardDrops := make(map[string]uint64)
	for _, port := range f.ports {
		if port.sourceGuardDrops > 0 {
			sourceGuardDrops[port.cfgName] = port.sourceGuardDrops
		}
	}
	return map[string]any{
		"attached_ports":     len(f.ports),
		"queue_drops":        f.drops,
		"source_guard_drops": sourceGuardDrops,
		"mirrored_frames":    f.mirrorFrames,
		"mirror_queue_drops": f.mirrorDrops,
		"monitor_tap_drops":  f.monitorTAPDrops,
		"switch":             f.sw.Stats(),
		"rstp":               f.sw.RSTPStatus(),
	}
}

// EmitRSTPBPDUs sends timer-driven protocol frames directly to their selected
// switch ports. BPDUs are link-local and must never re-enter normal forwarding.
func (f *SegmentFabric) EmitRSTPBPDUs(now time.Time) int {
	if f == nil {
		return 0
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.remoteSocket != "" {
		return 0 // the broker owning the switch emits its protocol frames
	}
	dropped := 0
	for id, frame := range f.sw.DueRSTPBPDUs(now) {
		out := f.ports[id]
		if out == nil || out.closed {
			continue
		}
		copyFrame := append([]byte(nil), frame...)
		select {
		case out.rx <- SegmentFrame{Frame: copyFrame}:
		default:
			f.drops++
			dropped++
		}
	}
	return dropped
}

// RSTPStatus snapshots bridge election and per-port role/state for the admin surface.
func (f *SegmentFabric) RSTPStatus() bond.L2RSTPStatus {
	if f == nil {
		return bond.L2RSTPStatus{}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sw.RSTPStatus()
}

// Sweep removes expired forwarding and multicast entries from the shared switch.
func (f *SegmentFabric) Sweep(now time.Time) int {
	if f == nil {
		return 0
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.remoteSocket != "" {
		return 0
	}
	return f.sw.Sweep(now)
}

// EmitMulticastQueries generates due IGMP/MLD queries on the switch's
// configured querier ports and forwards them through ordinary switch policy.
// It is a no-op for a remote adapter because the broker owns switch state.
func (f *SegmentFabric) EmitMulticastQueries(now time.Time) int {
	if f == nil {
		return 0
	}
	f.mu.Lock()
	if f.remoteSocket != "" {
		f.mu.Unlock()
		return 0
	}
	queries := f.sw.DueMulticastQueries(now)
	ports := make(map[bond.PortID]*SegmentPort, len(queries))
	for _, query := range queries {
		ports[query.IngressPort] = f.ports[query.IngressPort]
	}
	f.mu.Unlock()
	dropped := 0
	for _, query := range queries {
		port := ports[query.IngressPort]
		if port == nil || port.Send(query.Frame, now).Drop != bond.L2Forward {
			dropped++
		}
	}
	return dropped
}

// SwitchStats returns a snapshot of the shared switching tables and counters.
func (f *SegmentFabric) SwitchStats() bond.L2SwitchStats {
	if f == nil {
		return bond.L2SwitchStats{}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.remoteSocket != "" {
		return bond.L2SwitchStats{}
	}
	return f.sw.Stats()
}
