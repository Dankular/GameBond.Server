package dnsfilter

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func buildQuery(t *testing.T, id uint16, name string, qt dnsmessage.Type) []byte {
	t.Helper()
	n, err := dnsmessage.NewName(name)
	if err != nil {
		t.Fatal(err)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	b.EnableCompression()
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: n, Type: qt, Class: dnsmessage.ClassINET})
	out, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func unpack(t *testing.T, b []byte) dnsmessage.Message {
	t.Helper()
	var m dnsmessage.Message
	if err := m.Unpack(b); err != nil {
		t.Fatalf("not a DNS message: %v", err)
	}
	return m
}

// fakeUpstream is a resolver on loopback that answers A queries with 192.0.2.1 and counts them.
type fakeUpstream struct {
	udp     net.PacketConn
	tcp     net.Listener
	hits    atomic.Int32
	tcpHits atomic.Int32
	mu      sync.Mutex
	behave  func(req dnsmessage.Message) (reply []byte)
}

func startUpstream(t *testing.T) *fakeUpstream {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp4", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	u := &fakeUpstream{udp: pc, tcp: l}
	answer := func(req []byte, trunc bool) []byte {
		var m dnsmessage.Message
		if m.Unpack(req) != nil || len(m.Questions) != 1 {
			return nil
		}
		u.mu.Lock()
		behave := u.behave
		u.mu.Unlock()
		if behave != nil {
			if r := behave(m); r != nil {
				return r
			}
		}
		q := m.Questions[0]
		resp := dnsmessage.Message{Header: dnsmessage.Header{ID: m.ID, Response: true, RecursionDesired: true, RecursionAvailable: true, Truncated: trunc}, Questions: m.Questions}
		if q.Type == dnsmessage.TypeA && !trunc {
			resp.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 300}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}}}}
		}
		out, _ := resp.Pack()
		return out
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			u.hits.Add(1)
			var m dnsmessage.Message
			trunc := m.Unpack(buf[:n]) == nil && len(m.Questions) == 1 && m.Questions[0].Name.String() == "big.example.com."
			if r := answer(append([]byte(nil), buf[:n]...), trunc); r != nil {
				pc.WriteTo(r, from)
			}
		}
	}()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				req, err := readTCPMessage(c)
				if err != nil {
					return
				}
				u.tcpHits.Add(1)
				if r := answer(req, false); r != nil {
					writeTCPMessage(c, r)
				}
			}()
		}
	}()
	t.Cleanup(func() { pc.Close(); l.Close() })
	return u
}

func (u *fakeUpstream) addr() string { return u.udp.LocalAddr().String() }

func newTestServer(t *testing.T, cfg Config, up *fakeUpstream) *Server {
	t.Helper()
	ls, srv := newListServer(t)
	withCatalog(t, srv.URL)
	ls.bodies["/ads-hosts"], ls.etags["/ads-hosts"] = "0.0.0.0 ads.example.com\n", `"a"`
	f := NewFilter()
	f.HTTP = srv.Client()
	cfg.Enabled = true
	cfg.Upstreams = []string{up.addr()}
	if cfg.Categories == nil {
		cfg.Categories = []string{"ads"}
	}
	f.Apply(cfg)
	f.Refresh(context.Background(), false)
	return NewServer(f)
}

var (
	laptop = netip.MustParseAddr("10.77.0.3")
	ps5    = netip.MustParseAddr("10.77.0.4")
)

func TestBlockedNameGetsNXDOMAIN(t *testing.T) {
	up := startUpstream(t)
	s := newTestServer(t, Config{}, up)
	var seen []Query
	s.Observer = func(q Query) { seen = append(seen, q) }
	resp := s.Handle(context.Background(), laptop, buildQuery(t, 0x1234, "cdn.ads.example.com.", dnsmessage.TypeA), false)
	m := unpack(t, resp)
	if m.ID != 0x1234 || !m.Response || m.RCode != dnsmessage.RCodeNameError || !m.RecursionAvailable || len(m.Answers) != 0 || len(m.Questions) != 1 {
		t.Fatalf("%+v", m)
	}
	if up.hits.Load() != 0 {
		t.Fatal("a blocked name must never be sent upstream")
	}
	if len(seen) != 1 || !seen[0].Blocked || seen[0].List != "ads-hosts" || seen[0].Client != laptop || seen[0].Name != "cdn.ads.example.com" {
		t.Fatalf("%+v", seen)
	}
	st := s.Stats()
	if st.Queries != 1 || st.Blocked != 1 || st.BlockedByList["ads-hosts"] != 1 || st.TopBlocked[0].Domain != "ads.example.com" || st.Clients[0].Client != "10.77.0.3" {
		t.Fatalf("%+v", st)
	}
}

func TestNullBlockMode(t *testing.T) {
	up := startUpstream(t)
	s := newTestServer(t, Config{BlockMode: "null"}, up)
	a := unpack(t, s.Handle(context.Background(), laptop, buildQuery(t, 1, "ads.example.com.", dnsmessage.TypeA), false))
	if a.RCode != dnsmessage.RCodeSuccess || len(a.Answers) != 1 || a.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{} {
		t.Fatalf("%+v", a)
	}
	aaaa := unpack(t, s.Handle(context.Background(), laptop, buildQuery(t, 2, "ads.example.com.", dnsmessage.TypeAAAA), false))
	if len(aaaa.Answers) != 1 || aaaa.Answers[0].Body.(*dnsmessage.AAAAResource).AAAA != [16]byte{} {
		t.Fatalf("%+v", aaaa)
	}
	https := unpack(t, s.Handle(context.Background(), laptop, buildQuery(t, 3, "ads.example.com.", dnsmessage.TypeHTTPS), false))
	if https.RCode != dnsmessage.RCodeSuccess || len(https.Answers) != 0 {
		t.Fatalf("an HTTPS record query for a blocked name gets an empty answer, so a browser cannot find another route: %+v", https)
	}
}

func TestOtherNamesAreForwardedAndCached(t *testing.T) {
	up := startUpstream(t)
	s := newTestServer(t, Config{}, up)
	ctx := context.Background()
	m := unpack(t, s.Handle(ctx, laptop, buildQuery(t, 0x0a0a, "fine.example.org.", dnsmessage.TypeA), false))
	if m.ID != 0x0a0a || len(m.Answers) != 1 || m.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{192, 0, 2, 1} {
		t.Fatalf("%+v", m)
	}
	m2 := unpack(t, s.Handle(ctx, ps5, buildQuery(t, 0x0b0b, "FINE.example.org.", dnsmessage.TypeA), false))
	if m2.ID != 0x0b0b || len(m2.Answers) != 1 || up.hits.Load() != 1 {
		t.Fatalf("the second ask is a cache hit with the asker's own ID: id=%x hits=%d", m2.ID, up.hits.Load())
	}
	s.Handle(ctx, laptop, buildQuery(t, 5, "fine.example.org.", dnsmessage.TypeAAAA), false)
	if up.hits.Load() != 2 {
		t.Fatal("a different record type is a different question")
	}
	if st := s.Stats(); st.Cached != 1 || st.Queries != 3 {
		t.Fatalf("%+v", st)
	}
}

func TestExemptClientIsNotFiltered(t *testing.T) {
	up := startUpstream(t)
	s := newTestServer(t, Config{Exempt: []string{"10.77.0.4"}}, up)
	if m := unpack(t, s.Handle(context.Background(), ps5, buildQuery(t, 1, "ads.example.com.", dnsmessage.TypeA), false)); len(m.Answers) != 1 {
		t.Fatalf("the exempt device resolves a blocked name: %+v", m)
	}
	if m := unpack(t, s.Handle(context.Background(), laptop, buildQuery(t, 2, "ads.example.com.", dnsmessage.TypeA), false)); m.RCode != dnsmessage.RCodeNameError {
		t.Fatal("the others are still filtered")
	}
}

func TestDisabledFilterOnlyForwards(t *testing.T) {
	up := startUpstream(t)
	s := newTestServer(t, Config{}, up)
	cfg := s.F.Config()
	cfg.Enabled = false
	s.F.Apply(cfg)
	if m := unpack(t, s.Handle(context.Background(), laptop, buildQuery(t, 1, "ads.example.com.", dnsmessage.TypeA), false)); len(m.Answers) != 1 {
		t.Fatalf("%+v", m)
	}
}

func TestTCPAndTruncationFallBack(t *testing.T) {
	up := startUpstream(t)
	s := newTestServer(t, Config{}, up)
	// The upstream truncates "big.example.com" over UDP; the server must fetch the full answer over TCP.
	up.mu.Lock()
	up.behave = nil
	up.mu.Unlock()
	m := unpack(t, s.Handle(context.Background(), laptop, buildQuery(t, 7, "big.example.com.", dnsmessage.TypeA), false))
	if m.Truncated || len(m.Answers) != 1 || up.tcpHits.Load() != 1 {
		t.Fatalf("truncated=%v answers=%d tcp=%d", m.Truncated, len(m.Answers), up.tcpHits.Load())
	}
	viaTCP := unpack(t, s.Handle(context.Background(), laptop, buildQuery(t, 8, "other.example.org.", dnsmessage.TypeA), true))
	if len(viaTCP.Answers) != 1 || up.tcpHits.Load() != 2 {
		t.Fatalf("a TCP client is forwarded over TCP: %+v tcp=%d", viaTCP, up.tcpHits.Load())
	}
}

func TestSpoofedAndMismatchedAnswersAreIgnored(t *testing.T) {
	up := startUpstream(t)
	s := newTestServer(t, Config{}, up)
	up.mu.Lock()
	up.behave = func(req dnsmessage.Message) []byte { // answers with the wrong ID first
		bad := dnsmessage.Message{Header: dnsmessage.Header{ID: req.ID + 1, Response: true}, Questions: req.Questions}
		out, _ := bad.Pack()
		return out
	}
	up.mu.Unlock()
	m := unpack(t, s.Handle(context.Background(), laptop, buildQuery(t, 0x4444, "x.example.org.", dnsmessage.TypeA), false))
	if m.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("an answer with the wrong ID must not be accepted: %+v", m)
	}
	up.mu.Lock()
	up.behave = func(req dnsmessage.Message) []byte { // right ID, wrong question
		n, _ := dnsmessage.NewName("evil.example.org.")
		bad := dnsmessage.Message{Header: dnsmessage.Header{ID: req.ID, Response: true}, Questions: []dnsmessage.Question{{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
		out, _ := bad.Pack()
		return out
	}
	up.mu.Unlock()
	if m := unpack(t, s.Handle(context.Background(), laptop, buildQuery(t, 0x5555, "y.example.org.", dnsmessage.TypeA), false)); m.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("an answer to a different question must not be accepted: %+v", m)
	}
	if s.Stats().UpstreamErrors != 2 {
		t.Fatalf("%+v", s.Stats())
	}
}

func TestUpstreamFailoverAndFailure(t *testing.T) {
	dead := startUpstream(t)
	dead.udp.Close()
	dead.tcp.Close()
	live := startUpstream(t)
	s := newTestServer(t, Config{}, live)
	cfg := s.F.Config()
	cfg.Upstreams = []string{dead.addr(), live.addr()}
	s.F.Apply(cfg)
	if m := unpack(t, s.Handle(context.Background(), laptop, buildQuery(t, 1, "z.example.org.", dnsmessage.TypeA), false)); len(m.Answers) != 1 {
		t.Fatalf("the second upstream must answer when the first is down: %+v", m)
	}
	cfg.Upstreams = []string{dead.addr()}
	s.F.Apply(cfg)
	s.ClearCache()
	if m := unpack(t, s.Handle(context.Background(), laptop, buildQuery(t, 2, "w.example.org.", dnsmessage.TypeA), false)); m.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("%+v", m)
	}
}

func TestMalformedPacketsDoNotPanic(t *testing.T) {
	up := startUpstream(t)
	s := newTestServer(t, Config{}, up)
	for _, junk := range [][]byte{nil, {1}, make([]byte, 11), make([]byte, 12), []byte("GET / HTTP/1.1\r\n\r\n"), append(make([]byte, 12), 0xff, 0xff)} {
		_ = s.Handle(context.Background(), laptop, junk, false)
	}
	two := dnsmessage.Message{Header: dnsmessage.Header{ID: 9}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("a.example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}, {Name: dnsmessage.MustNewName("b.example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	pkt, _ := two.Pack()
	if m := unpack(t, s.Handle(context.Background(), laptop, pkt, false)); m.RCode != dnsmessage.RCodeFormatError {
		t.Fatalf("two questions: %+v", m)
	}
	resp := buildQuery(t, 1, "a.example.com.", dnsmessage.TypeA)
	resp[2] |= 0x80 // a response, not a query
	if s.Handle(context.Background(), laptop, resp, false) != nil {
		t.Fatal("a response is not answered")
	}
}

func TestServeOverRealSockets(t *testing.T) {
	up := startUpstream(t)
	s := newTestServer(t, Config{}, up)
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.ServeUDP(ctx, pc)
	go s.ServeTCP(ctx, l)

	c, _ := net.Dial("udp4", pc.LocalAddr().String())
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write(buildQuery(t, 0x7777, "ads.example.com.", dnsmessage.TypeA))
	buf := make([]byte, 2048)
	n, err := c.Read(buf)
	if err != nil || unpack(t, buf[:n]).RCode != dnsmessage.RCodeNameError {
		t.Fatalf("udp: %v", err)
	}
	tc, _ := net.Dial("tcp4", l.Addr().String())
	tc.SetDeadline(time.Now().Add(3 * time.Second))
	writeTCPMessage(tc, buildQuery(t, 0x8888, "good.example.org.", dnsmessage.TypeA))
	r, err := readTCPMessage(tc)
	if err != nil || binary.BigEndian.Uint16(r) != 0x8888 || len(unpack(t, r).Answers) != 1 {
		t.Fatalf("tcp: %v", err)
	}
	writeTCPMessage(tc, buildQuery(t, 0x9999, "ads.example.com.", dnsmessage.TypeA))
	if r, err = readTCPMessage(tc); err != nil || unpack(t, r).RCode != dnsmessage.RCodeNameError {
		t.Fatalf("a second query on the same connection: %v", err)
	}
}

func TestChangingTheFilterTakesEffectOnceTheCacheIsCleared(t *testing.T) {
	up := startUpstream(t)
	s := newTestServer(t, Config{Categories: []string{}}, up) // nothing blocked yet
	ctx := context.Background()
	if m := unpack(t, s.Handle(ctx, laptop, buildQuery(t, 1, "ads.example.com.", dnsmessage.TypeA), false)); len(m.Answers) != 1 {
		t.Fatal("not blocked yet")
	}
	cfg := s.F.Config()
	cfg.Categories = []string{"ads"}
	s.F.Apply(cfg)
	s.F.Refresh(ctx, false)
	if m := unpack(t, s.Handle(ctx, laptop, buildQuery(t, 2, "ads.example.com.", dnsmessage.TypeA), false)); m.RCode != dnsmessage.RCodeNameError {
		t.Fatal("a block is checked before the cache, so it applies at once")
	}
}

func TestRecentLogIsBounded(t *testing.T) {
	up := startUpstream(t)
	s := newTestServer(t, Config{}, up)
	for i := 0; i < 1000; i++ {
		s.Handle(context.Background(), laptop, buildQuery(t, uint16(i), "ads.example.com.", dnsmessage.TypeA), false)
	}
	if st := s.Stats(); len(st.Recent) > recentMax || st.Blocked != 1000 {
		t.Fatalf("%d recent, %d blocked", len(st.Recent), st.Blocked)
	}
}
