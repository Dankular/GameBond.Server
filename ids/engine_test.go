package ids

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- helpers

func packet(src, dst string, proto byte, sport, dport uint16, flags byte, size int) []byte {
	l4 := 20
	switch proto {
	case 17:
		l4 = 8
	case 1:
		l4 = 8
	}
	if size < 20+l4 {
		size = 20 + l4
	}
	b := make([]byte, size)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(size))
	b[9] = proto
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(b[12:], s[:])
	copy(b[16:], d[:])
	switch proto {
	case 6:
		binary.BigEndian.PutUint16(b[20:], sport)
		binary.BigEndian.PutUint16(b[22:], dport)
		b[33] = flags
	case 17:
		binary.BigEndian.PutUint16(b[20:], sport)
		binary.BigEndian.PutUint16(b[22:], dport)
	case 1:
		b[20] = byte(sport) // the ICMP type, passed in sport for brevity
	}
	return b
}

func syn(src, dst string, port uint16) []byte     { return packet(src, dst, 6, 40000, port, 0x02, 60) }
func synack(src, dst string, sport uint16) []byte { return packet(src, dst, 6, sport, 40000, 0x12, 60) }

type fakeBlocker struct {
	mu      sync.Mutex
	blocks  []string
	unblock []string
	err     error
	last    time.Duration
}

func (f *fakeBlocker) BlockAddress(_ context.Context, ip string, d time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.blocks, f.last = append(f.blocks, ip), d
	return nil
}
func (f *fakeBlocker) UnblockAddress(_ context.Context, ip string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unblock = append(f.unblock, ip)
	return nil
}

type rig struct {
	e     *Engine
	b     *fakeBlocker
	clock time.Time
}

func newRig(t *testing.T, cfg string) *rig {
	t.Helper()
	b := &fakeBlocker{}
	e := New(b)
	r := &rig{e: e, b: b, clock: time.Unix(1_700_000_000, 0)}
	e.now = func() time.Time { return r.clock }
	c, err := Parse(json.RawMessage(cfg))
	if err != nil {
		t.Fatal(err)
	}
	e.Apply(c)
	return r
}

// run advances the clock a second at a time, ticking the engine.
func (r *rig) run(seconds int) {
	for i := 0; i < seconds; i++ {
		r.clock = r.clock.Add(time.Second)
		r.e.Tick()
	}
	r.e.Flush(context.Background())
}

func (r *rig) events() []Event { return r.e.Status().Events }

func (r *rig) kinds() string {
	var k []string
	for _, e := range r.events() {
		k = append(k, e.Kind+":"+e.Action)
	}
	return strings.Join(k, ",")
}

const prevent = `{"mode":"prevent"}`

// ---- configuration

func TestParse(t *testing.T) {
	c, err := Parse(nil)
	if err != nil || c.Mode != ModeOff || c.BlockMinutes != 10 || c.Sensitivity != "medium" {
		t.Fatalf("%+v %v", c, err)
	}
	for in, want := range map[string]string{
		`{"typo":1}`: "unknown field", `{"mode":"loud"}`: "mode", `{"sensitivity":"paranoid"}`: "sensitivity", `{"block_minutes":0,"mode":"detect","sensitivity":"low"}`: "",
		`{"block_minutes":9999}`: "block_minutes", `{"never_block":["bad"]}`: "never_block", `{"detectors":{"nope":{}}}`: "not a detector",
		`{"detectors":{"port_scan":{"action":"nuke"}}}`: "action", `{"detectors":{"port_scan":{"threshold":-1}}}`: "threshold",
	} {
		_, err := Parse(json.RawMessage(in))
		if want == "" && err != nil || want != "" && (err == nil || !strings.Contains(err.Error(), want)) {
			t.Errorf("%s: expected %q, got %v", in, want, err)
		}
	}
}

func TestSensitivityScalesThresholdsAndExplicitOnesWin(t *testing.T) {
	low, _ := Parse(json.RawMessage(`{"sensitivity":"low"}`))
	high, _ := Parse(json.RawMessage(`{"sensitivity":"high"}`))
	if low.resolve(PortScan).threshold != 80 || high.resolve(PortScan).threshold != 20 {
		t.Fatalf("%d %d", low.resolve(PortScan).threshold, high.resolve(PortScan).threshold)
	}
	c, _ := Parse(json.RawMessage(`{"sensitivity":"high","detectors":{"port_scan":{"threshold":7,"enabled":false,"action":"alert"}}}`))
	if r := c.resolve(PortScan); r.threshold != 7 || r.enabled || r.action != "alert" {
		t.Fatalf("%+v", r)
	}
	if len(Specs) != 10 {
		t.Fatal("ten detectors")
	}
}

// ---- what must not trigger anything

func TestOffModeDoesNothing(t *testing.T) {
	r := newRig(t, `{"mode":"off"}`)
	for p := uint16(1); p <= 200; p++ {
		r.e.Observe(true, syn("10.77.0.3", "198.51.100.7", p))
	}
	r.run(15)
	if len(r.events()) != 0 || r.e.Status().Packets != 0 {
		t.Fatal("an engine that is off must not even count packets")
	}
}

func TestNormalTrafficIsQuiet(t *testing.T) {
	r := newRig(t, prevent)
	for s := 0; s < 60; s++ {
		for i := 0; i < 30; i++ { // a busy page: many hosts on 443
			r.e.Observe(true, syn("10.77.0.3", fmt.Sprintf("203.0.%d.%d", s%200, i+1), 443))
		}
		for i := 0; i < 120; i++ { // a game: 120 UDP packets a second
			r.e.Observe(true, packet("10.77.0.4", "198.51.100.9", 17, 3074, 3074, 0, 200))
		}
		for i := 0; i < 5; i++ {
			r.e.Observe(true, packet("10.77.0.3", "1.1.1.1", 1, 8, 0, 0, 84))
		}
		r.run(1)
	}
	if got := r.kinds(); got != "" {
		t.Fatalf("browsing, gaming and the odd ping must raise nothing: %s", got)
	}
	if len(r.b.blocks) != 0 {
		t.Fatal("and certainly no block")
	}
}

func TestRepliesToADevicesOwnConnectionsAreNotInboundTraffic(t *testing.T) {
	r := newRig(t, prevent)
	r.e.Observe(true, packet("10.77.0.3", "198.51.100.50", 6, 40000, 443, 0x02, 60)) // the device connects out
	for s := 0; s < 20; s++ {
		for i := 0; i < 2000; i++ { // a fast download: 2000 packets a second from that server
			r.e.Observe(false, packet("198.51.100.50", "10.77.0.3", 6, 443, 40000, 0x10, 1400))
		}
		r.run(1)
	}
	if got := r.kinds(); got != "" {
		t.Fatalf("a download is not an inbound flood: %s", got)
	}
	r.e.Observe(false, packet("198.51.100.77", "10.77.0.3", 17, 53, 5353, 0, 100)) // ... but a stranger's packet is unsolicited
	if x := r.e.ext[netip.MustParseAddr("198.51.100.77")]; x == nil {
		t.Fatal("an unsolicited packet must be tracked")
	}
	r.e.Observe(false, packet("198.51.100.78", "10.77.0.3", 1, 0, 0, 0, 84)) // an ICMP echo reply is not unsolicited
	if r.e.ext[netip.MustParseAddr("198.51.100.78")] != nil {
		t.Fatal("echo replies are replies")
	}
}

func TestTrafficBetweenDevicesIsCountedOnceAndTheServerIsNotATarget(t *testing.T) {
	r := newRig(t, prevent)
	for p := uint16(1000); p < 1100; p++ { // D1 scans D2: seen on the sending leg, then again on the delivering leg
		pk := syn("10.77.0.3", "10.77.0.4", p)
		r.e.Observe(true, pk)
		r.e.Observe(false, pk)
	}
	if len(r.e.ext) != 0 {
		t.Fatal("the second leg of a device-to-device packet must be ignored")
	}
	r.run(10)
	if k := r.kinds(); k != "port_scan:blocked" {
		t.Fatalf("a device scanning another device is a port scan: %s", k)
	}
	r2 := newRig(t, prevent)
	for p := uint16(1); p < 300; p++ { // DNS, the stream gateway and so on to the server itself
		r2.e.Observe(true, syn("10.77.0.3", "10.77.0.1", p))
	}
	r2.run(10)
	if r2.kinds() != "" {
		t.Fatalf("traffic to the server's own services is not scanning: %s", r2.kinds())
	}
}

// ---- detectors

func TestPortScanVerticalAndHorizontal(t *testing.T) {
	r := newRig(t, prevent)
	for p := uint16(1); p <= 45; p++ {
		r.e.Observe(true, syn("10.77.0.3", "198.51.100.7", p))
	}
	r.run(10)
	evs := r.events()
	if len(evs) != 1 || evs[0].Kind != PortScan || evs[0].Offender != "10.77.0.3" || evs[0].Peer != "198.51.100.7" || evs[0].Severity != "high" || evs[0].Action != "blocked" {
		t.Fatalf("%+v", evs)
	}
	if len(r.b.blocks) != 1 || r.b.blocks[0] != "10.77.0.3" || r.b.last != 10*time.Minute {
		t.Fatalf("blocks=%v for %v", r.b.blocks, r.b.last)
	}
	h := newRig(t, prevent)
	for i := 0; i < 170; i++ { // one SSH-ish port across many hosts
		h.e.Observe(true, syn("10.77.0.4", fmt.Sprintf("203.0.113.%d", i%250+1)[:0]+fmt.Sprintf("198.51.%d.%d", i/200+1, i%200+1), 2222))
	}
	h.run(10)
	if k := h.kinds(); k != "port_scan:blocked" {
		t.Fatalf("a sweep of one port: %s", k)
	}
	web := newRig(t, prevent)
	for i := 0; i < 400; i++ {
		web.e.Observe(true, syn("10.77.0.4", fmt.Sprintf("198.51.%d.%d", i/200+1, i%200+1), 443))
	}
	web.run(10)
	if web.kinds() != "" {
		t.Fatalf("many hosts on 443 is browsing: %s", web.kinds())
	}
}

func TestFloodsNeedToBeSustained(t *testing.T) {
	r := newRig(t, prevent)
	for s := 0; s < 2; s++ { // two seconds of 700 SYN/s is a burst, not a flood
		for i := 0; i < 700; i++ {
			r.e.Observe(true, syn("10.77.0.3", "198.51.100.7", 443))
		}
		r.run(1)
	}
	r.run(2)
	if r.kinds() != "" {
		t.Fatalf("%s", r.kinds())
	}
	for s := 0; s < 4; s++ {
		for i := 0; i < 700; i++ {
			r.e.Observe(true, syn("10.77.0.3", "198.51.100.7", 443))
		}
		r.run(1)
	}
	if k := r.kinds(); k != "syn_flood:blocked" {
		t.Fatalf("%s", k)
	}
	u := newRig(t, prevent)
	for s := 0; s < 4; s++ {
		for i := 0; i < 5000; i++ {
			u.e.Observe(true, packet("10.77.0.5", "198.51.100.9", 17, 1, 2, 0, 100))
		}
		u.run(1)
	}
	if k := u.kinds(); k != "udp_flood:blocked" {
		t.Fatalf("%s", k)
	}
	i := newRig(t, prevent)
	for s := 0; s < 4; s++ {
		for n := 0; n < 300; n++ {
			i.e.Observe(true, packet("10.77.0.5", "198.51.100.9", 1, 8, 0, 0, 84))
		}
		i.run(1)
	}
	if k := i.kinds(); k != "icmp_flood:blocked" {
		t.Fatalf("%s", k)
	}
}

func TestBruteForceOnlyOnLoginPorts(t *testing.T) {
	r := newRig(t, prevent)
	for i := 0; i < 30; i++ {
		r.e.Observe(true, syn("10.77.0.3", "198.51.100.7", 22))
		r.e.Observe(true, syn("10.77.0.4", "198.51.100.7", 443))
	}
	r.run(10)
	evs := r.events()
	if len(evs) != 1 || evs[0].Kind != BruteForce || evs[0].Offender != "10.77.0.3" || evs[0].Peer != "198.51.100.7:22" {
		t.Fatalf("%+v", evs)
	}
}

func TestRiskyPortIsOnlyEverAnAlert(t *testing.T) {
	r := newRig(t, prevent)
	for i := 0; i < 4; i++ {
		r.e.Observe(true, syn("10.77.0.3", "198.51.100.7", 445))
	}
	r.run(10)
	if k := r.kinds(); k != "risky_port:alert" || len(r.b.blocks) != 0 {
		t.Fatalf("a policy signature alerts and does not block by default: %s", k)
	}
	b := newRig(t, `{"mode":"prevent","detectors":{"risky_port":{"action":"block"}}}`)
	for i := 0; i < 4; i++ {
		b.e.Observe(true, syn("10.77.0.3", "198.51.100.7", 445))
	}
	b.run(10)
	if k := b.kinds(); k != "risky_port:blocked" {
		t.Fatalf("but the operator can choose to block it: %s", k)
	}
}

func TestInboundScanAndFloodBlockTheOutsideAddress(t *testing.T) {
	r := newRig(t, prevent)
	for p := uint16(1000); p < 1030; p++ {
		r.e.Observe(false, syn("198.51.100.66", "10.77.0.2", p))
	}
	r.run(10)
	evs := r.events()
	if len(evs) != 1 || evs[0].Kind != InboundScan || evs[0].Offender != "198.51.100.66" || evs[0].Action != "blocked" || r.b.blocks[0] != "198.51.100.66" {
		t.Fatalf("%+v %v", evs, r.b.blocks)
	}
	f := newRig(t, prevent)
	for s := 0; s < 4; s++ {
		for i := 0; i < 1000; i++ {
			f.e.Observe(false, packet("198.51.100.67", "10.77.0.2", 17, 4000, 25565, 0, 100))
		}
		f.run(1)
	}
	if k := f.kinds(); k != "inbound_flood:blocked" {
		t.Fatalf("%s", k)
	}
}

func TestDNSAnomaly(t *testing.T) {
	r := newRig(t, prevent)
	r.run(1)
	for i := 0; i < 70; i++ { // a device looking for a command server: lots of names that do not exist
		r.e.ObserveDNS(DNSQuery{Client: netip.MustParseAddr("10.77.0.3"), Name: fmt.Sprintf("x%dkq.example.net", i), RCode: 3})
	}
	for i := 0; i < 10; i++ {
		r.e.ObserveDNS(DNSQuery{Client: netip.MustParseAddr("10.77.0.3"), Name: "www.example.com", RCode: 0})
	}
	r.run(61)
	if k := r.kinds(); k != "dns_anomaly:alert" {
		t.Fatalf("%s", k)
	}
	q := newRig(t, prevent)
	q.run(1)
	for i := 0; i < 400; i++ { // a busy but normal device
		q.e.ObserveDNS(DNSQuery{Client: netip.MustParseAddr("10.77.0.3"), Name: fmt.Sprintf("host%d.example.com", i%30), RCode: map[bool]int{true: 3, false: 0}[i%20 == 0]})
	}
	q.run(61)
	if q.kinds() != "" {
		t.Fatalf("a few NXDOMAINs among many good answers is normal: %s", q.kinds())
	}
	l := newRig(t, prevent)
	l.run(1)
	for i := 0; i < 60; i++ { // DNS tunnelling: very long names
		l.e.ObserveDNS(DNSQuery{Client: netip.MustParseAddr("10.77.0.4"), Name: strings.Repeat("a1b2c3d4", 8) + ".t.example.net"})
	}
	l.run(61)
	if k := l.kinds(); k != "dns_anomaly:alert" {
		t.Fatalf("%s", k)
	}
}

func TestUploadAnomalyLearnsABaselineFirst(t *testing.T) {
	r := newRig(t, prevent)
	push := func(bytesPerSec int) {
		for sent := 0; sent < bytesPerSec; sent += 1400 {
			r.e.Observe(true, packet("10.77.0.3", "198.51.100.9", 6, 1, 443, 0x10, 1400))
		}
		r.run(1)
	}
	for i := 0; i < 20; i++ { // a spike before the baseline exists is not judged
		push(7_000_000)
	}
	if r.kinds() != "" {
		t.Fatalf("no verdict without a baseline: %s", r.kinds())
	}
	n := newRig(t, prevent)
	push = func(bytesPerSec int) {
		for sent := 0; sent < bytesPerSec; sent += 1400 {
			n.e.Observe(true, packet("10.77.0.3", "198.51.100.9", 6, 1, 443, 0x10, 1400))
		}
		n.run(1)
	}
	for i := 0; i < 320; i++ { // five minutes at about 1 Mbit/s
		push(125_000)
	}
	for i := 0; i < 15; i++ { // then 60 Mbit/s
		push(7_500_000)
	}
	if k := n.kinds(); k != "upload_anomaly:alert" {
		t.Fatalf("%s", k)
	}
}

// ---- response

func TestDetectModeAndProtectedAddressesAreNeverBlocked(t *testing.T) {
	d := newRig(t, `{"mode":"detect"}`)
	for p := uint16(1); p <= 45; p++ {
		d.e.Observe(true, syn("10.77.0.3", "198.51.100.7", p))
	}
	d.run(10)
	if k := d.kinds(); k != "port_scan:would_block" || len(d.b.blocks) != 0 {
		t.Fatalf("detect mode records and does not block: %s", k)
	}
	for _, offender := range []string{"10.77.0.2", "10.77.0.9"} {
		r := newRig(t, `{"mode":"prevent","never_block":["10.77.0.9"]}`)
		for p := uint16(1); p <= 45; p++ {
			r.e.Observe(true, syn(offender, "198.51.100.7", p))
		}
		r.run(10)
		evs := r.events()
		if len(evs) != 1 || evs[0].Action != "would_block" || evs[0].Error == "" || len(r.b.blocks) != 0 {
			t.Fatalf("%s must never be blocked: %+v", offender, evs)
		}
	}
}

func TestRepeatsMergeAndBlocksEscalate(t *testing.T) {
	r := newRig(t, `{"mode":"prevent","block_minutes":10}`)
	scan := func() {
		for p := uint16(1); p <= 45; p++ {
			r.e.Observe(true, syn("10.77.0.3", "198.51.100.7", p))
		}
		r.run(10)
	}
	scan()
	scan()
	evs := r.events()
	if len(evs) != 1 || evs[0].Count != 2 {
		t.Fatalf("a repeat within a minute merges into one event: %+v", evs)
	}
	r.run(120)
	var durations []time.Duration
	for i := 0; i < 5; i++ {
		scan()
		r.run(70)
		durations = append(durations, r.b.last)
	}
	if durations[0] != 20*time.Minute || durations[1] != 40*time.Minute || durations[2] != 80*time.Minute {
		t.Fatalf("a repeat offender is blocked for longer each time: %v", durations)
	}
	for i := 0; i < 12; i++ {
		scan()
		r.run(70)
	}
	if r.b.last > 24*time.Hour {
		t.Fatalf("never longer than a day: %v", r.b.last)
	}
}

func TestBlockFailuresAreReported(t *testing.T) {
	r := newRig(t, prevent)
	r.b.err = errors.New("nft: no such table")
	for p := uint16(1); p <= 45; p++ {
		r.e.Observe(true, syn("10.77.0.3", "198.51.100.7", p))
	}
	r.run(10)
	evs := r.events()
	if len(evs) != 1 || evs[0].Action != "block_failed" || !strings.Contains(evs[0].Error, "no such table") {
		t.Fatalf("%+v", evs)
	}
}

func TestUnblockClearsHistoryAndCallsTheBlocker(t *testing.T) {
	r := newRig(t, prevent)
	for p := uint16(1); p <= 45; p++ {
		r.e.Observe(true, syn("10.77.0.3", "198.51.100.7", p))
	}
	r.run(10)
	if err := r.e.Unblock(context.Background(), "10.77.0.3"); err != nil || len(r.b.unblock) != 1 {
		t.Fatalf("%v %v", err, r.b.unblock)
	}
	if r.events()[0].Action != "unblocked" {
		t.Fatalf("%+v", r.events()[0])
	}
	if r.e.Unblock(context.Background(), "nope") == nil {
		t.Fatal("garbage address")
	}
}

func TestStatusAndEventBounds(t *testing.T) {
	r := newRig(t, `{"mode":"detect"}`)
	st := r.e.Status()
	if len(st.Detectors) != 10 || st.Mode != "detect" {
		t.Fatalf("%+v", st)
	}
	r.e.mu.Lock()
	for i := 0; i < 700; i++ {
		r.e.emit(r.clock, finding{PortScan, netip.MustParseAddr(fmt.Sprintf("10.77.0.%d", i%250+3)), fmt.Sprintf("p%d", i), "x"})
	}
	r.e.mu.Unlock()
	st = r.e.Status()
	if len(st.Events) != 200 || st.Events[0].ID < st.Events[1].ID || st.Detectors[0].Seen != 700 {
		t.Fatalf("newest first, bounded: %d events, first ids %d %d, seen %d", len(st.Events), st.Events[0].ID, st.Events[1].ID, st.Detectors[0].Seen)
	}
	r.e.ClearEvents()
	if len(r.e.Status().Events) != 0 {
		t.Fatal("clear")
	}
}

func TestExternalTableIsBounded(t *testing.T) {
	r := newRig(t, prevent)
	for i := 0; i < maxExternal+500; i++ {
		src := fmt.Sprintf("%d.%d.%d.%d", 11+i/65536, (i/256)%256, i%256, 9)
		r.e.Observe(false, packet(src, "10.77.0.2", 17, 1, 2, 0, 60))
	}
	if len(r.e.ext) != maxExternal || r.e.Status().Dropped != 500 {
		t.Fatalf("%d tracked, %d dropped: a flood of spoofed sources must not grow memory", len(r.e.ext), r.e.Status().Dropped)
	}
}

func TestJunkPacketsAreIgnored(t *testing.T) {
	r := newRig(t, prevent)
	v6 := make([]byte, 60)
	v6[0] = 0x60
	badIHL := packet("10.77.0.3", "1.2.3.4", 6, 1, 2, 2, 60)
	badIHL[0] = 0x4f
	frag := packet("10.77.0.3", "1.2.3.4", 6, 1, 2, 2, 60)
	binary.BigEndian.PutUint16(frag[6:], 0x0010) // not the first fragment: its "ports" are payload
	for _, p := range [][]byte{nil, {1, 2, 3}, make([]byte, 19), v6, badIHL, frag, packet("10.77.0.3", "1.2.3.4", 6, 1, 2, 2, 20)[:25]} {
		r.e.Observe(true, p)
		r.e.Observe(false, p)
	}
	r.run(12)
	if r.kinds() != "" {
		t.Fatalf("%s", r.kinds())
	}
}

func TestRunProcessesBlocksInTheBackground(t *testing.T) {
	r := newRig(t, prevent)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.e.Run(ctx)
	for p := uint16(1); p <= 45; p++ {
		r.e.Observe(true, syn("10.77.0.3", "198.51.100.7", p))
	}
	r.clock = r.clock.Add(11 * time.Second)
	r.e.Tick()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		r.b.mu.Lock()
		n := len(r.b.blocks)
		r.b.mu.Unlock()
		if n == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the worker must apply the block without the caller waiting for nft")
}
