package dnsfilter

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Query is one question the server answered, passed to the Observer (the intrusion detector watches these).
type Query struct {
	Time    time.Time
	Client  netip.Addr
	Name    string
	Answers []netip.Addr
	Type    uint16
	Blocked bool
	List    string
	Cached  bool
	RCode   int // dnsmessage.RCode of the answer
}

type DomainPolicy func(client netip.Addr, name string) (ruleID string, action string, matched bool)
type domainPolicyHolder struct{ fn DomainPolicy }

const (
	cacheMax     = 4096
	recentMax    = 300
	topMax       = 2000
	maxInflight  = 256
	upstreamWait = 2500 * time.Millisecond
)

type cacheKey struct {
	name  string
	qtype dnsmessage.Type
}

type cacheEntry struct {
	resp    []byte
	expires time.Time
}

// Server answers DNS for the tunnel devices: names on the active lists are blocked, everything else is forwarded.
type Server struct {
	F        *Filter
	Observer func(Query)
	policy   atomic.Pointer[domainPolicyHolder]

	dial func(ctx context.Context, network, addr string) (net.Conn, error) // tests replace it
	now  func() time.Time

	mu       sync.Mutex
	cache    map[cacheKey]cacheEntry
	recent   []RecentQuery
	top      map[string]uint64
	byList   map[string]uint64
	byClient map[string]*clientCount

	queries, blocked, cached, upstreamErrors atomic.Uint64
}

// SetPolicy atomically replaces the optional domain policy callback.
func (s *Server) SetPolicy(fn DomainPolicy) {
	if fn == nil {
		s.policy.Store(nil)
		return
	}
	s.policy.Store(&domainPolicyHolder{fn: fn})
}

type clientCount struct{ Queries, Blocked uint64 }

// NewServer returns a server using f.
func NewServer(f *Filter) *Server {
	d := &net.Dialer{Timeout: upstreamWait}
	return &Server{F: f, dial: d.DialContext, now: time.Now, cache: map[cacheKey]cacheEntry{}, top: map[string]uint64{}, byList: map[string]uint64{}, byClient: map[string]*clientCount{}}
}

// Handle answers one DNS message from client. A nil result means the packet was not worth answering.
func (s *Server) Handle(ctx context.Context, client netip.Addr, req []byte, tcp bool) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(req)
	if err != nil {
		return nil // not DNS: dropped, like any resolver would
	}
	if h.Response {
		return nil
	}
	q, err := p.Question()
	if err != nil {
		return formErr(h)
	}
	if _, err := p.Question(); err == nil || !errors.Is(err, dnsmessage.ErrSectionDone) {
		return formErr(h) // more than one question: nobody sends that
	}
	name := strings.ToLower(strings.TrimSuffix(q.Name.String(), "."))
	s.queries.Add(1)
	ev := Query{Time: s.now(), Client: client, Name: name, Type: uint16(q.Type)}
	policyAction := ""
	policyID := ""
	if h.OpCode == 0 && q.Class == dnsmessage.ClassINET {
		if policy := s.policy.Load(); policy != nil {
			policyID, policyAction, _ = policy.fn(client, name)
		}
	}
	if policyAction == "allow" || policyAction == "log" {
		ev.List = "traffic:" + policyID
	}
	if policyAction == "deny" {
		s.blocked.Add(1)
		ev.Blocked, ev.List, ev.RCode = true, "traffic:"+policyID, int(dnsmessage.RCodeNameError)
		resp := s.blockedResponse(h, q, "nxdomain")
		s.record(ev, Decision{Blocked: true, Matched: name, List: ev.List})
		return resp
	}
	if policyAction != "allow" && h.OpCode == 0 && q.Class == dnsmessage.ClassINET && s.F != nil && s.F.Config().Enabled && !s.F.ClientExempt(client) {
		if d := s.F.Match(name); d.Blocked {
			s.blocked.Add(1)
			resp := s.blockedResponse(h, q, s.F.Config().BlockMode)
			ev.Blocked, ev.List, ev.RCode = true, d.List, int(rcodeOf(resp))
			s.record(ev, d)
			return resp
		}
	}
	key := cacheKey{name, q.Type}
	s.mu.Lock()
	if e, ok := s.cache[key]; ok && s.now().Before(e.expires) {
		resp := append([]byte(nil), e.resp...)
		s.mu.Unlock()
		binary.BigEndian.PutUint16(resp, h.ID)
		s.cached.Add(1)
		ev.Answers = answerAddresses(resp)
		ev.Cached, ev.RCode = true, int(rcodeOf(resp))
		s.record(ev, Decision{})
		return resp
	}
	s.mu.Unlock()
	resp, err := s.forward(ctx, req, h.ID, q, tcp)
	if err != nil {
		s.upstreamErrors.Add(1)
		ev.RCode = int(dnsmessage.RCodeServerFailure)
		s.record(ev, Decision{})
		return servFail(h, q)
	}
	ev.RCode = int(rcodeOf(resp))
	ev.Answers = answerAddresses(resp)
	s.store(key, resp)
	s.record(ev, Decision{})
	return resp
}

func answerAddresses(resp []byte) []netip.Addr {
	var msg dnsmessage.Message
	if msg.Unpack(resp) != nil {
		return nil
	}
	addrs := make([]netip.Addr, 0, len(msg.Answers))
	for _, rr := range msg.Answers {
		switch body := rr.Body.(type) {
		case *dnsmessage.AResource:
			addrs = append(addrs, netip.AddrFrom4(body.A))
		case *dnsmessage.AAAAResource:
			addrs = append(addrs, netip.AddrFrom16(body.AAAA))
		}
	}
	return addrs
}

func rcodeOf(resp []byte) dnsmessage.RCode {
	if len(resp) < 4 {
		return dnsmessage.RCodeServerFailure
	}
	return dnsmessage.RCode(resp[3] & 0x0f)
}

func header(h dnsmessage.Header, rcode dnsmessage.RCode) dnsmessage.Header {
	return dnsmessage.Header{ID: h.ID, Response: true, OpCode: h.OpCode, RecursionDesired: h.RecursionDesired, RecursionAvailable: true, RCode: rcode}
}

func formErr(h dnsmessage.Header) []byte {
	b := dnsmessage.NewBuilder(nil, header(h, dnsmessage.RCodeFormatError))
	out, _ := b.Finish()
	return out
}

func servFail(h dnsmessage.Header, q dnsmessage.Question) []byte {
	b := dnsmessage.NewBuilder(nil, header(h, dnsmessage.RCodeServerFailure))
	b.EnableCompression()
	_ = b.StartQuestions()
	_ = b.Question(q)
	out, _ := b.Finish()
	return out
}

// blockedResponse builds the answer for a blocked name. nxdomain: the name does not exist. null: A and AAAA queries
// get 0.0.0.0 and ::, anything else (including HTTPS records, which would let a browser find another route) gets an
// empty answer.
func (s *Server) blockedResponse(h dnsmessage.Header, q dnsmessage.Question, mode string) []byte {
	if mode != "null" {
		b := dnsmessage.NewBuilder(nil, header(h, dnsmessage.RCodeNameError))
		b.EnableCompression()
		_ = b.StartQuestions()
		_ = b.Question(q)
		out, _ := b.Finish()
		return out
	}
	b := dnsmessage.NewBuilder(nil, header(h, dnsmessage.RCodeSuccess))
	b.EnableCompression()
	_ = b.StartQuestions()
	_ = b.Question(q)
	_ = b.StartAnswers()
	rh := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}
	switch q.Type {
	case dnsmessage.TypeA:
		rh.Type = dnsmessage.TypeA
		_ = b.AResource(rh, dnsmessage.AResource{A: [4]byte{}})
	case dnsmessage.TypeAAAA:
		rh.Type = dnsmessage.TypeAAAA
		_ = b.AAAAResource(rh, dnsmessage.AAAAResource{AAAA: [16]byte{}})
	}
	out, _ := b.Finish()
	return out
}

// forward asks the upstream resolvers in turn and returns the first valid answer. An answer is valid when it is a
// response with the question's ID and the same question, so a stray or spoofed packet is ignored.
func (s *Server) forward(ctx context.Context, req []byte, id uint16, q dnsmessage.Question, tcp bool) ([]byte, error) {
	if s.F == nil {
		return nil, errors.New("no upstream")
	}
	var last error
	for _, up := range s.F.Config().Upstreams {
		var resp []byte
		var err error
		if tcp {
			resp, err = s.exchangeTCP(ctx, up, req)
		} else {
			resp, err = s.exchangeUDP(ctx, up, req, id, q)
			if err == nil && len(resp) > 3 && resp[2]&0x02 != 0 { // truncated: ask again over TCP and give the client the full answer
				if full, terr := s.exchangeTCP(ctx, up, req); terr == nil {
					resp = full
				}
			}
		}
		if err == nil && validResponse(resp, id, q) {
			return resp, nil
		}
		if err == nil {
			err = errors.New("the answer did not match the question")
		}
		last = err
	}
	if last == nil {
		last = errors.New("no upstream resolvers configured")
	}
	return nil, last
}

func validResponse(resp []byte, id uint16, q dnsmessage.Question) bool {
	var p dnsmessage.Parser
	h, err := p.Start(resp)
	if err != nil || !h.Response || h.ID != id {
		return false
	}
	got, err := p.Question()
	return err == nil && strings.EqualFold(got.Name.String(), q.Name.String()) && got.Type == q.Type && got.Class == q.Class
}

func (s *Server) exchangeUDP(ctx context.Context, upstream string, req []byte, id uint16, q dnsmessage.Question) ([]byte, error) {
	c, err := s.dial(ctx, "udp", upstream)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(upstreamWait))
	if _, err := c.Write(req); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	for { // ignore packets that are not our answer until the deadline
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		if validResponse(buf[:n], id, q) {
			return append([]byte(nil), buf[:n]...), nil
		}
	}
}

func (s *Server) exchangeTCP(ctx context.Context, upstream string, req []byte) ([]byte, error) {
	c, err := s.dial(ctx, "tcp", upstream)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * upstreamWait))
	if err := writeTCPMessage(c, req); err != nil {
		return nil, err
	}
	return readTCPMessage(c)
}

func writeTCPMessage(w io.Writer, msg []byte) error {
	if len(msg) > 65535 {
		return errors.New("message too long")
	}
	out := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(out, uint16(len(msg)))
	copy(out[2:], msg)
	_, err := w.Write(out)
	return err
}

func readTCPMessage(r io.Reader) ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(l[:]))
	if n < 12 {
		return nil, errors.New("short DNS message")
	}
	msg := make([]byte, n)
	_, err := io.ReadFull(r, msg)
	return msg, err
}

// store caches an answer for as long as its shortest record lives (30 s for an NXDOMAIN, at most an hour).
func (s *Server) store(key cacheKey, resp []byte) {
	var m dnsmessage.Message
	if m.Unpack(resp) != nil || m.Truncated || (m.RCode != dnsmessage.RCodeSuccess && m.RCode != dnsmessage.RCodeNameError) {
		return
	}
	ttl := uint32(3600)
	if len(m.Answers) == 0 {
		ttl = 30
	}
	for _, rr := range m.Answers {
		if rr.Header.TTL < ttl {
			ttl = rr.Header.TTL
		}
	}
	if ttl < 5 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.cache) >= cacheMax {
		now := s.now()
		for k, e := range s.cache {
			if now.After(e.expires) {
				delete(s.cache, k)
			}
		}
		for k := range s.cache {
			if len(s.cache) < cacheMax {
				break
			}
			delete(s.cache, k)
		}
	}
	s.cache[key] = cacheEntry{append([]byte(nil), resp...), s.now().Add(time.Duration(ttl) * time.Second)}
}

// RecentQuery is a line of the live query log.
type RecentQuery struct {
	Time    int64  `json:"t"`
	Client  string `json:"client"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Blocked bool   `json:"blocked"`
	List    string `json:"list,omitempty"`
	Cached  bool   `json:"cached,omitempty"`
}

func (s *Server) record(ev Query, d Decision) {
	if s.Observer != nil {
		s.Observer(ev)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c := ev.Client.String()
	cc := s.byClient[c]
	if cc == nil && len(s.byClient) < 256 {
		cc = &clientCount{}
		s.byClient[c] = cc
	}
	if cc != nil {
		cc.Queries++
		if ev.Blocked {
			cc.Blocked++
		}
	}
	if ev.Blocked {
		s.byList[ev.List]++
		if _, ok := s.top[d.Matched]; ok || len(s.top) < topMax {
			s.top[d.Matched]++
		}
	}
	if ev.Blocked || len(s.recent) < recentMax { // keep the log informative: every block, and queries while there is room
		s.recent = append(s.recent, RecentQuery{Time: ev.Time.Unix(), Client: c, Name: ev.Name, Type: dnsmessage.Type(ev.Type).String(), Blocked: ev.Blocked, List: ev.List, Cached: ev.Cached})
		if len(s.recent) > recentMax {
			s.recent = s.recent[len(s.recent)-recentMax:]
		}
	}
}

// Stats is what the GUI shows about the server.
type Stats struct {
	Queries        uint64            `json:"queries"`
	Blocked        uint64            `json:"blocked"`
	Cached         uint64            `json:"cached"`
	UpstreamErrors uint64            `json:"upstream_errors"`
	BlockedByList  map[string]uint64 `json:"blocked_by_list"`
	TopBlocked     []TopEntry        `json:"top_blocked"`
	Clients        []ClientEntry     `json:"clients"`
	Recent         []RecentQuery     `json:"recent"`
}

type TopEntry struct {
	Domain string `json:"domain"`
	Count  uint64 `json:"count"`
}

type ClientEntry struct {
	Client  string `json:"client"`
	Queries uint64 `json:"queries"`
	Blocked uint64 `json:"blocked"`
}

// Stats snapshots the counters.
func (s *Server) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Stats{Queries: s.queries.Load(), Blocked: s.blocked.Load(), Cached: s.cached.Load(), UpstreamErrors: s.upstreamErrors.Load(),
		BlockedByList: map[string]uint64{}, TopBlocked: []TopEntry{}, Clients: []ClientEntry{}, Recent: append([]RecentQuery{}, s.recent...)}
	for k, v := range s.byList {
		st.BlockedByList[k] = v
	}
	for d, n := range s.top {
		st.TopBlocked = append(st.TopBlocked, TopEntry{d, n})
	}
	sort.Slice(st.TopBlocked, func(i, j int) bool {
		if st.TopBlocked[i].Count != st.TopBlocked[j].Count {
			return st.TopBlocked[i].Count > st.TopBlocked[j].Count
		}
		return st.TopBlocked[i].Domain < st.TopBlocked[j].Domain
	})
	if len(st.TopBlocked) > 20 {
		st.TopBlocked = st.TopBlocked[:20]
	}
	for c, n := range s.byClient {
		st.Clients = append(st.Clients, ClientEntry{c, n.Queries, n.Blocked})
	}
	sort.Slice(st.Clients, func(i, j int) bool { return st.Clients[i].Client < st.Clients[j].Client })
	return st
}

// ClearCache forgets cached answers (after the filter changed, so a name that is now blocked is not served from it).
func (s *Server) ClearCache() {
	s.mu.Lock()
	s.cache = map[cacheKey]cacheEntry{}
	s.mu.Unlock()
}

// ServeUDP answers datagrams until ctx ends.
func (s *Server) ServeUDP(ctx context.Context, pc net.PacketConn) {
	go func() { <-ctx.Done(); pc.Close() }()
	sem := make(chan struct{}, maxInflight)
	buf := make([]byte, 4096)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		pkt := append([]byte(nil), buf[:n]...)
		ap, _ := netip.ParseAddrPort(from.String())
		select {
		case sem <- struct{}{}:
		default:
			continue // overloaded: drop, the client retries
		}
		go func() {
			defer func() { <-sem }()
			qctx, cancel := context.WithTimeout(ctx, 6*time.Second)
			defer cancel()
			if resp := s.Handle(qctx, ap.Addr(), pkt, false); resp != nil {
				_, _ = pc.WriteTo(resp, from)
			}
		}()
	}
}

// ServeTCP answers DNS over TCP until ctx ends.
func (s *Server) ServeTCP(ctx context.Context, l net.Listener) {
	go func() { <-ctx.Done(); l.Close() }()
	sem := make(chan struct{}, maxInflight)
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			c.Close()
			continue
		}
		go func() {
			defer func() { <-sem }()
			defer c.Close()
			ap, _ := netip.ParseAddrPort(c.RemoteAddr().String())
			for i := 0; i < 8; i++ { // a few queries per connection
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				req, err := readTCPMessage(c)
				if err != nil {
					return
				}
				qctx, cancel := context.WithTimeout(ctx, 8*time.Second)
				resp := s.Handle(qctx, ap.Addr(), req, true)
				cancel()
				if resp == nil || writeTCPMessage(c, resp) != nil {
					return
				}
			}
		}()
	}
}

// ListenAndServe binds UDP and TCP on addr (retrying while the interface is not up yet) and serves until ctx ends.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	var pc net.PacketConn
	var l net.Listener
	var err error
	for pc == nil || l == nil {
		if pc == nil {
			pc, err = net.ListenPacket("udp4", addr)
		}
		if err == nil && l == nil {
			l, err = net.Listen("tcp4", addr)
		}
		if err != nil {
			select {
			case <-ctx.Done():
				if pc != nil {
					pc.Close()
				}
				return ctx.Err()
			case <-time.After(250 * time.Millisecond):
			}
		}
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); s.ServeUDP(ctx, pc) }()
	go func() { defer wg.Done(); s.ServeTCP(ctx, l) }()
	wg.Wait()
	return nil
}
