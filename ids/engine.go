package ids

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// Blocker is the firewall's block set.
type Blocker interface {
	BlockAddress(ctx context.Context, ip string, d time.Duration) error
	UnblockAddress(ctx context.Context, ip string) error
}

// Event is one finding.
type Event struct {
	ID       uint64 `json:"id"`
	Time     int64  `json:"time"`  // last seen
	First    int64  `json:"first"` // first seen
	Kind     string `json:"kind"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	// Offender is the address that did it: a device, or for inbound detectors an address on the internet.
	Offender string `json:"offender"`
	Peer     string `json:"peer,omitempty"`
	Detail   string `json:"detail"`
	Count    int    `json:"count"` // how many times this was seen (repeats within a minute are merged)
	// Action is what was done: alert, blocked, would_block (detect mode or never-block list), block_failed.
	Action  string `json:"action"`
	Blocked int    `json:"blocked_for_s,omitempty"`
	Error   string `json:"error,omitempty"`
}

const (
	maxEvents   = 500
	mergeWindow = 60 * time.Second
	maxDevices  = 300
	maxExternal = 4096
	maxSet      = 4096
)

var tunnelPrefix = netip.MustParsePrefix("10.77.0.0/24")

func isDevice(a netip.Addr) bool {
	return tunnelPrefix.Contains(a) && a != netip.MustParseAddr("10.77.0.1")
}

func protected(a netip.Addr) bool {
	return a == netip.MustParseAddr("10.77.0.1") || a == netip.MustParseAddr("10.77.0.2")
}

type pkt struct {
	src, dst     netip.Addr
	proto        byte
	sport, dport uint16
	flags        byte
	size         int
	icmpType     byte
	ports        bool
}

func parse(b []byte) (pkt, bool) {
	var p pkt
	if len(b) < 20 || b[0]>>4 != 4 {
		return p, false
	}
	hl := int(b[0]&15) * 4
	if hl < 20 || len(b) < hl {
		return p, false
	}
	p.size = int(binary.BigEndian.Uint16(b[2:]))
	if p.size == 0 || p.size > len(b) {
		p.size = len(b)
	}
	p.src, p.dst, p.proto = netip.AddrFrom4([4]byte(b[12:16])), netip.AddrFrom4([4]byte(b[16:20])), b[9]
	if binary.BigEndian.Uint16(b[6:])&0x1fff != 0 { // not the first fragment: no ports to read
		return p, true
	}
	switch p.proto {
	case 6:
		if len(b) >= hl+14 {
			p.sport, p.dport, p.flags, p.ports = binary.BigEndian.Uint16(b[hl:]), binary.BigEndian.Uint16(b[hl+2:]), b[hl+13], true
		}
	case 17:
		if len(b) >= hl+4 {
			p.sport, p.dport, p.ports = binary.BigEndian.Uint16(b[hl:]), binary.BigEndian.Uint16(b[hl+2:]), true
		}
	case 1:
		if len(b) > hl {
			p.icmpType = b[hl]
		}
	}
	return p, true
}

func pairKey(a netip.Addr, port uint16) uint64 {
	b := a.As4()
	return uint64(binary.BigEndian.Uint32(b[:]))<<16 | uint64(port)
}

// flowKey identifies what a device talked to.
func flowKey(device, remote netip.Addr, port uint16) uint64 {
	d, r := device.As4(), remote.As4()
	h := uint64(14695981039346656037)
	for _, b := range append(append(d[:], r[:]...), byte(port>>8), byte(port)) {
		h ^= uint64(b)
		h *= 1099511628211
	}
	return h
}

const (
	replyWindow  = 120 // seconds a contacted endpoint counts as a conversation
	maxContacted = 262144
)

var (
	authPorts  = map[uint16]bool{21: true, 22: true, 23: true, 110: true, 143: true, 445: true, 1433: true, 3306: true, 3389: true, 5432: true, 5900: true, 5985: true, 6379: true}
	riskyPorts = map[uint16]bool{23: true, 135: true, 139: true, 445: true, 4444: true, 6667: true, 31337: true}
	webPorts   = map[uint16]bool{80: true, 443: true, 8080: true, 8443: true, 53: true, 123: true, 853: true}
)

// dev is what is known about one tunnel device.
type dev struct {
	synSec, udpSec, icmpSec int
	upSec                   uint64
	runSyn, runUDP, runICMP int
	win                     time.Time
	portsByDst              map[netip.Addr]map[uint16]struct{}
	dstsByPort              map[uint16]map[netip.Addr]struct{}
	synTo                   map[uint64]int
	risky                   map[uint64]int
	dnsWin                  time.Time
	dnsTotal, dnsNX, dnsLen int
	baseline, baselineAge   float64 // bytes per second, seconds observed
	upRun                   int
	lastUp                  float64
	lastSeen                time.Time
}

func newDev(now time.Time) *dev {
	d := &dev{dnsWin: now}
	d.resetWindow(now)
	return d
}

func (d *dev) resetWindow(now time.Time) {
	d.win = now
	d.portsByDst, d.dstsByPort = map[netip.Addr]map[uint16]struct{}{}, map[uint16]map[netip.Addr]struct{}{}
	d.synTo, d.risky = map[uint64]int{}, map[uint64]int{}
}

// ext is an address on the internet that sent something to a device.
type ext struct {
	pktSec  int
	run     int
	win     time.Time
	targets map[uint64]struct{}
	last    time.Time
}

// Engine analyses packets and applies the response.
type Engine struct {
	mu       sync.Mutex
	cfg      Config
	blocker  Blocker
	now      func() time.Time
	devs     map[netip.Addr]*dev
	ext      map[netip.Addr]*ext
	events   []Event
	nextID   uint64
	counts   map[string]uint64
	offences map[netip.Addr][]time.Time
	lastTick time.Time
	// contacted remembers the remote endpoints each device opened or sent to (by device, address, port) so that what
	// comes back is recognised as a reply and not counted as unsolicited inbound traffic.
	contacted map[uint64]int64
	packets   uint64
	dropped   uint64 // outside addresses not tracked because the table was full
	jobs      chan blockJob
}

type blockJob struct {
	event  uint64
	ip     netip.Addr
	d      time.Duration
	unlock bool
}

// New returns an engine. The blocker may be nil (detection only).
func New(b Blocker) *Engine {
	return &Engine{blocker: b, now: time.Now, devs: map[netip.Addr]*dev{}, ext: map[netip.Addr]*ext{}, contacted: map[uint64]int64{}, counts: map[string]uint64{}, offences: map[netip.Addr][]time.Time{}, jobs: make(chan blockJob, 128)}
}

// Apply installs a configuration.
func (e *Engine) Apply(c Config) {
	c = c.normalised()
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg = c
}

// Config returns the configuration in force.
func (e *Engine) Config() Config {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cfg
}

// Observe takes one IPv4 packet. fromDevice is the leg a device sent into the tunnel; false is the leg delivered to a
// device. A packet between two devices crosses both legs, so it is only counted on the first.
func (e *Engine) Observe(fromDevice bool, packet []byte) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cfg.Mode == "" || e.cfg.Mode == ModeOff {
		return
	}
	p, ok := parse(packet)
	if !ok {
		return
	}
	e.packets++
	now := e.now()
	if fromDevice {
		if !isDevice(p.src) {
			return
		}
		d := e.dev(p.src, now)
		d.upSec += uint64(p.size)
		if p.dst == netip.MustParseAddr("10.77.0.1") {
			return // the server's own services (DNS, the stream gateway) are not traffic to the internet
		}
		if p.ports && len(e.contacted) < maxContacted {
			e.contacted[flowKey(p.src, p.dst, p.dport)] = now.Unix()
		}
		switch p.proto {
		case 6:
			if p.flags&0x12 == 0x02 { // SYN without ACK: a new connection attempt
				d.synSec++
				if len(d.portsByDst) < maxSet && len(d.dstsByPort) < maxSet {
					addSet(d.portsByDst, p.dst, p.dport)
					addSetPort(d.dstsByPort, p.dport, p.dst)
				}
				if authPorts[p.dport] && len(d.synTo) < maxSet {
					d.synTo[pairKey(p.dst, p.dport)]++
				}
				if riskyPorts[p.dport] && len(d.risky) < maxSet {
					d.risky[pairKey(p.dst, p.dport)]++
				}
			}
		case 17:
			d.udpSec++
		case 1:
			if p.icmpType == 8 {
				d.icmpSec++
			}
		}
		return
	}
	if isDevice(p.src) || !isDevice(p.dst) {
		return
	}
	if p.proto == 1 && (p.icmpType == 0 || p.icmpType == 3 || p.icmpType == 11) {
		return // an echo reply or an error about something the device sent
	}
	if p.ports {
		if t, ok := e.contacted[flowKey(p.dst, p.src, p.sport)]; ok && now.Unix()-t < replyWindow {
			return // a reply to something the device started
		}
	}
	x := e.ext[p.src]
	if x == nil {
		if len(e.ext) >= maxExternal {
			e.dropped++
			return
		}
		x = &ext{win: now, targets: map[uint64]struct{}{}}
		e.ext[p.src] = x
	}
	x.pktSec++
	x.last = now
	if len(x.targets) < maxSet && (p.proto != 6 || p.flags&0x12 == 0x02) && p.ports { // distinct (device, port) pairs it tried to open
		x.targets[pairKey(p.dst, p.dport)] = struct{}{}
	}
}

func addSet(m map[netip.Addr]map[uint16]struct{}, a netip.Addr, port uint16) {
	s := m[a]
	if s == nil {
		s = map[uint16]struct{}{}
		m[a] = s
	}
	if len(s) < maxSet {
		s[port] = struct{}{}
	}
}

func addSetPort(m map[uint16]map[netip.Addr]struct{}, port uint16, a netip.Addr) {
	s := m[port]
	if s == nil {
		s = map[netip.Addr]struct{}{}
		m[port] = s
	}
	if len(s) < maxSet {
		s[a] = struct{}{}
	}
}

func (e *Engine) dev(a netip.Addr, now time.Time) *dev {
	d := e.devs[a]
	if d == nil {
		if len(e.devs) >= maxDevices { // make room by dropping the device that has been idle longest
			var oldest netip.Addr
			var at time.Time
			for k, v := range e.devs {
				if at.IsZero() || v.lastSeen.Before(at) {
					oldest, at = k, v.lastSeen
				}
			}
			delete(e.devs, oldest)
		}
		d = newDev(now)
		e.devs[a] = d
	}
	d.lastSeen = now
	return d
}

// DNSQuery is what the detector needs from the DNS filter.
type DNSQuery struct {
	Client netip.Addr
	Name   string
	RCode  int // 3 is NXDOMAIN
}

// ObserveDNS counts a query: many names that do not exist, or very long names, are what malware looking for its
// server and DNS tunnelling look like.
func (e *Engine) ObserveDNS(q DNSQuery) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cfg.Mode == "" || e.cfg.Mode == ModeOff || !isDevice(q.Client) {
		return
	}
	d := e.dev(q.Client, e.now())
	d.dnsTotal++
	if q.RCode == 3 {
		d.dnsNX++
	}
	long := len(q.Name) >= 52
	for _, l := range strings.Split(q.Name, ".") {
		if len(l) >= 40 {
			long = true
		}
	}
	if long {
		d.dnsLen++
	}
}

type finding struct {
	kind     string
	offender netip.Addr
	peer     string
	detail   string
}

// Tick evaluates what was seen since the last call. The edge calls it once a second.
func (e *Engine) Tick() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cfg.Mode == "" || e.cfg.Mode == ModeOff {
		return
	}
	now := e.now()
	dt := 1.0
	if !e.lastTick.IsZero() {
		dt = now.Sub(e.lastTick).Seconds()
	}
	e.lastTick = now
	if dt < 0.25 {
		return
	}
	if dt > 5 {
		dt = 5
	}
	if now.Unix()%10 == 0 || len(e.contacted) >= maxContacted {
		for k, t := range e.contacted {
			if now.Unix()-t >= replyWindow {
				delete(e.contacted, k)
			}
		}
	}
	var found []finding
	for ip, d := range e.devs {
		found = append(found, e.tickDevice(ip, d, now, dt)...)
		if now.Sub(d.lastSeen) > 10*time.Minute {
			delete(e.devs, ip)
		}
	}
	for ip, x := range e.ext {
		found = append(found, e.tickExternal(ip, x, now, dt)...)
		if now.Sub(x.last) > time.Minute {
			delete(e.ext, ip)
		}
	}
	sort.Slice(found, func(i, j int) bool {
		return found[i].kind+found[i].offender.String() < found[j].kind+found[j].offender.String()
	})
	for _, f := range found {
		e.emit(now, f)
	}
}

func (e *Engine) rate(kind string) resolved { return e.cfg.resolve(kind) }

func (e *Engine) tickDevice(ip netip.Addr, d *dev, now time.Time, dt float64) []finding {
	var out []finding
	sustained := func(run *int, over bool, need int) bool {
		if over {
			*run++
		} else {
			*run = 0
		}
		return *run == need // once per episode; the event merges if it continues
	}
	if r := e.rate(SynFlood); r.enabled {
		rate := float64(d.synSec) / dt
		if sustained(&d.runSyn, rate >= float64(r.threshold), 3) {
			out = append(out, finding{SynFlood, ip, "", fmt.Sprintf("%.0f new connections per second for 3 seconds or more (limit %d)", rate, r.threshold)})
		}
	}
	if r := e.rate(UDPFlood); r.enabled {
		rate := float64(d.udpSec) / dt
		if sustained(&d.runUDP, rate >= float64(r.threshold), 3) {
			out = append(out, finding{UDPFlood, ip, "", fmt.Sprintf("%.0f UDP packets per second for 3 seconds or more (limit %d)", rate, r.threshold)})
		}
	}
	if r := e.rate(ICMPFlood); r.enabled {
		rate := float64(d.icmpSec) / dt
		if sustained(&d.runICMP, rate >= float64(r.threshold), 3) {
			out = append(out, finding{ICMPFlood, ip, "", fmt.Sprintf("%.0f pings per second for 3 seconds or more (limit %d)", rate, r.threshold)})
		}
	}
	if r := e.rate(UploadAnomaly); r.enabled {
		cur := float64(d.upSec) / dt
		over := d.baselineAge >= 300 && cur >= d.baseline*8 && (cur-d.baseline)*8/1e6 >= float64(r.threshold)
		if !over { // the baseline only learns from normal behaviour
			if d.baselineAge == 0 {
				d.baseline = cur
			} else {
				d.baseline = 0.995*d.baseline + 0.005*cur
			}
			d.baselineAge += dt
		}
		if sustained(&d.upRun, over, 10) {
			out = append(out, finding{UploadAnomaly, ip, "", fmt.Sprintf("uploading %.0f Mbit/s, normally about %.1f", cur*8/1e6, d.baseline*8/1e6)})
		}
	}
	d.synSec, d.udpSec, d.icmpSec, d.upSec = 0, 0, 0, 0
	if now.Sub(d.win) >= 10*time.Second {
		out = append(out, e.evalWindow(ip, d)...)
		d.resetWindow(now)
	}
	if now.Sub(d.dnsWin) >= time.Minute {
		if r := e.rate(DNSAnomaly); r.enabled {
			sus := d.dnsNX + d.dnsLen
			if sus >= r.threshold && float64(sus) >= 0.5*float64(d.dnsTotal) {
				out = append(out, finding{DNSAnomaly, ip, "", fmt.Sprintf("%d of %d queries in the last minute were for names that do not exist (%d) or were very long (%d)", sus, d.dnsTotal, d.dnsNX, d.dnsLen)})
			}
		}
		d.dnsWin, d.dnsTotal, d.dnsNX, d.dnsLen = now, 0, 0, 0
	}
	return out
}

// evalWindow looks at what a device did in the last ten seconds.
func (e *Engine) evalWindow(ip netip.Addr, d *dev) []finding {
	var out []finding
	if r := e.rate(PortScan); r.enabled {
		var bestDst netip.Addr
		best := 0
		for dst, ports := range d.portsByDst {
			if len(ports) > best || (len(ports) == best && dst.Less(bestDst)) {
				best, bestDst = len(ports), dst
			}
		}
		if best >= r.threshold {
			out = append(out, finding{PortScan, ip, bestDst.String(), fmt.Sprintf("tried %d different ports on %s in ten seconds (limit %d)", best, bestDst, r.threshold)})
		} else {
			var bestPort uint16
			hosts := 0
			for port, dsts := range d.dstsByPort {
				if !webPorts[port] && (len(dsts) > hosts || (len(dsts) == hosts && port < bestPort)) {
					hosts, bestPort = len(dsts), port
				}
			}
			if hosts >= r.threshold*4 {
				out = append(out, finding{PortScan, ip, fmt.Sprintf("port %d", bestPort), fmt.Sprintf("tried port %d on %d different hosts in ten seconds (limit %d)", bestPort, hosts, r.threshold*4)})
			}
		}
	}
	if r := e.rate(BruteForce); r.enabled {
		var bestKey uint64
		best := 0
		for k, n := range d.synTo {
			if n > best || (n == best && k < bestKey) {
				best, bestKey = n, k
			}
		}
		if best >= r.threshold {
			a := netip.AddrFrom4([4]byte{byte(bestKey >> 40), byte(bestKey >> 32), byte(bestKey >> 24), byte(bestKey >> 16)})
			out = append(out, finding{BruteForce, ip, fmt.Sprintf("%s:%d", a, bestKey&0xffff), fmt.Sprintf("%d connections to %s port %d in ten seconds (limit %d)", best, a, bestKey&0xffff, r.threshold)})
		}
	}
	if r := e.rate(RiskyPort); r.enabled {
		total, bestKey, best := 0, uint64(0), 0
		for k, n := range d.risky {
			total += n
			if n > best || (n == best && k < bestKey) {
				best, bestKey = n, k
			}
		}
		if total >= r.threshold {
			a := netip.AddrFrom4([4]byte{byte(bestKey >> 40), byte(bestKey >> 32), byte(bestKey >> 24), byte(bestKey >> 16)})
			out = append(out, finding{RiskyPort, ip, fmt.Sprintf("%s:%d", a, bestKey&0xffff), fmt.Sprintf("%d connections to risky ports in ten seconds, mostly %s port %d", total, a, bestKey&0xffff)})
		}
	}
	return out
}

func (e *Engine) tickExternal(ip netip.Addr, x *ext, now time.Time, dt float64) []finding {
	var out []finding
	if r := e.rate(InboundFlood); r.enabled {
		rate := float64(x.pktSec) / dt
		if rate >= float64(r.threshold) {
			x.run++
		} else {
			x.run = 0
		}
		if x.run == 3 {
			out = append(out, finding{InboundFlood, ip, "", fmt.Sprintf("%.0f packets per second from this address for 3 seconds or more (limit %d)", rate, r.threshold)})
		}
	}
	x.pktSec = 0
	if now.Sub(x.win) >= 10*time.Second {
		if r := e.rate(InboundScan); r.enabled && len(x.targets) >= r.threshold {
			out = append(out, finding{InboundScan, ip, "", fmt.Sprintf("tried %d different ports or devices in ten seconds (limit %d)", len(x.targets), r.threshold)})
		}
		x.win, x.targets = now, map[uint64]struct{}{}
	}
	return out
}

// emit records a finding and, in prevent mode, blocks the offender.
func (e *Engine) emit(now time.Time, f finding) {
	r := e.rate(f.kind)
	e.counts[f.kind]++
	for i := len(e.events) - 1; i >= 0 && i >= len(e.events)-60; i-- { // merge repeats
		ev := &e.events[i]
		if ev.Kind == f.kind && ev.Offender == f.offender.String() && ev.Peer == f.peer && now.Unix()-ev.Time < int64(mergeWindow.Seconds()) {
			ev.Count++
			ev.Time, ev.Detail = now.Unix(), f.detail
			return
		}
	}
	e.nextID++
	ev := Event{ID: e.nextID, Time: now.Unix(), First: now.Unix(), Kind: f.kind, Title: r.Title, Severity: r.Severity, Offender: f.offender.String(), Peer: f.peer, Detail: f.detail, Count: 1, Action: "alert"}
	if r.action == "block" {
		switch {
		case e.neverBlock(f.offender):
			ev.Action = "would_block"
			ev.Error = "this address is on the never-block list or is the client or server itself"
		case e.cfg.Mode != ModePrevent || e.blocker == nil:
			ev.Action = "would_block"
		default:
			d := e.blockDuration(f.offender, now)
			ev.Action, ev.Blocked = "blocking", int(d.Seconds())
			select {
			case e.jobs <- blockJob{event: ev.ID, ip: f.offender, d: d}:
			default:
				ev.Action, ev.Error = "block_failed", "the block queue is full"
			}
		}
	}
	e.events = append(e.events, ev)
	if len(e.events) > maxEvents {
		e.events = e.events[len(e.events)-maxEvents:]
	}
}

func (e *Engine) neverBlock(a netip.Addr) bool {
	if protected(a) {
		return true
	}
	for _, n := range e.cfg.NeverBlock {
		if n == a.String() {
			return true
		}
	}
	return false
}

// blockDuration doubles for each block of the same address in the last day, up to a day.
func (e *Engine) blockDuration(a netip.Addr, now time.Time) time.Duration {
	recent := e.offences[a][:0]
	for _, t := range e.offences[a] {
		if now.Sub(t) < 24*time.Hour {
			recent = append(recent, t)
		}
	}
	d := time.Duration(e.cfg.BlockMinutes) * time.Minute
	for range recent {
		d *= 2
		if d > 24*time.Hour {
			d = 24 * time.Hour
			break
		}
	}
	e.offences[a] = append(recent, now)
	return d
}

// Flush runs the queued block jobs now. Start's worker calls it; tests call it directly.
func (e *Engine) Flush(ctx context.Context) {
	for {
		select {
		case j := <-e.jobs:
			e.runJob(ctx, j)
		default:
			return
		}
	}
}

func (e *Engine) runJob(ctx context.Context, j blockJob) {
	var err error
	if j.unlock {
		err = e.blocker.UnblockAddress(ctx, j.ip.String())
	} else {
		err = e.blocker.BlockAddress(ctx, j.ip.String(), j.d)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := range e.events {
		if e.events[i].ID == j.event && !j.unlock {
			if err != nil {
				e.events[i].Action, e.events[i].Error = "block_failed", err.Error()
			} else {
				e.events[i].Action = "blocked"
			}
		}
	}
}

// Run applies block jobs in the background (so the packet loop never waits for nft) and ticks every second.
func (e *Engine) Run(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case j := <-e.jobs:
			e.runJob(ctx, j)
		case <-t.C:
			e.Tick()
		}
	}
}

// Unblock lifts a block by hand.
func (e *Engine) Unblock(ctx context.Context, ip string) error {
	a, err := netip.ParseAddr(ip)
	if err != nil || !a.Is4() {
		return fmt.Errorf("%q is not an IPv4 address", ip)
	}
	if e.blocker == nil {
		return fmt.Errorf("blocking is not available")
	}
	e.mu.Lock()
	delete(e.offences, a)
	for i := range e.events {
		if e.events[i].Offender == ip && e.events[i].Action == "blocked" {
			e.events[i].Action = "unblocked"
		}
	}
	e.mu.Unlock()
	return e.blocker.UnblockAddress(ctx, ip)
}

// ClearEvents empties the event list.
func (e *Engine) ClearEvents() {
	e.mu.Lock()
	e.events = nil
	e.mu.Unlock()
}

// DetectorStatus is a detector as the GUI shows it.
type DetectorStatus struct {
	Spec
	Enabled   bool   `json:"enabled"`
	Action    string `json:"action"`
	Threshold int    `json:"threshold"`
	Seen      uint64 `json:"seen"`
}

// Status is what the GUI shows.
type Status struct {
	Mode         string           `json:"mode"`
	Sensitivity  string           `json:"sensitivity"`
	BlockMinutes int              `json:"block_minutes"`
	NeverBlock   []string         `json:"never_block"`
	Detectors    []DetectorStatus `json:"detectors"`
	Events       []Event          `json:"events"`
	Packets      uint64           `json:"packets"`
	Tracked      int              `json:"tracked_devices"`
	Dropped      uint64           `json:"untracked_sources"`
}

// Status snapshots the engine, newest events first.
func (e *Engine) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := Status{Mode: e.cfg.Mode, Sensitivity: e.cfg.Sensitivity, BlockMinutes: e.cfg.BlockMinutes, NeverBlock: append([]string{}, e.cfg.NeverBlock...), Packets: e.packets, Tracked: len(e.devs), Dropped: e.dropped,
		Detectors: []DetectorStatus{}, Events: []Event{}}
	if st.Mode == "" {
		st.Mode, st.Sensitivity, st.BlockMinutes = ModeOff, "medium", 10
	}
	for _, s := range Specs {
		r := e.cfg.resolve(s.Kind)
		st.Detectors = append(st.Detectors, DetectorStatus{Spec: s, Enabled: r.enabled, Action: r.action, Threshold: r.threshold, Seen: e.counts[s.Kind]})
	}
	for i := len(e.events) - 1; i >= 0 && len(st.Events) < 200; i-- {
		st.Events = append(st.Events, e.events[i])
	}
	return st
}
