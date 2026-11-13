package dnsfilter

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

const maxListBytes = 64 << 20

// listState is one list's data and how fresh it is.
type listState struct {
	List
	hashes     []uint64 // sorted, unique
	stats      ParseStats
	fetchedAt  time.Time // when the data last changed
	checkedAt  time.Time // when the provider was last asked
	etag, lmod string
	err        string
	bytes      int64
}

// Filter holds the active lists, consolidated for matching, and keeps them current.
type Filter struct {
	HTTP *http.Client

	mu      sync.RWMutex
	cfg     Config
	lists   map[string]*listState // by id; a list stays loaded while its configuration changes
	active  []*listState          // in catalog order
	block   map[string]bool
	allow   map[string]bool
	unique  int // domains across all active lists, duplicates between lists counted once
	now     func() time.Time
	refresh sync.Mutex // one refresh at a time
}

// NewFilter returns a filter that fetches through a client which refuses private addresses.
func NewFilter() *Filter {
	return &Filter{HTTP: safeClient(), lists: map[string]*listState{}, block: map[string]bool{}, allow: map[string]bool{}, now: time.Now}
}

// safeClient only connects to public addresses, checked after name resolution, so a custom list URL cannot be
// used to reach the server's own networks.
func safeClient() *http.Client {
	dialer := &net.Dialer{Timeout: 20 * time.Second}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
			if err != nil || len(ips) == 0 {
				return nil, fmt.Errorf("could not resolve %s", host)
			}
			for _, ip := range ips {
				if !publicAddr(ip) {
					return nil, errors.New("the list address resolves to a private or local address")
				}
			}
			return dialer.DialContext(ctx, "tcp4", net.JoinHostPort(ips[0].String(), port))
		},
		TLSHandshakeTimeout: 15 * time.Second, ResponseHeaderTimeout: 60 * time.Second, DisableCompression: false, MaxIdleConnsPerHost: 2,
	}
	return &http.Client{Transport: tr, Timeout: 5 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 4 {
			return errors.New("too many redirects")
		}
		if req.URL.Scheme != "https" {
			return errors.New("a redirect to plain http is refused")
		}
		return nil
	}}
}

// Apply installs a configuration. Lists that are no longer used are dropped from memory; new ones are fetched by
// the next Refresh. It returns at once.
func (f *Filter) Apply(c Config) {
	c = c.normalised()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cfg = c
	want := map[string]List{}
	var order []string
	for _, l := range c.ActiveLists() {
		want[l.ID] = l
		order = append(order, l.ID)
	}
	for id := range f.lists {
		if _, ok := want[id]; !ok {
			delete(f.lists, id)
		}
	}
	f.active = f.active[:0]
	for _, id := range order {
		st := f.lists[id]
		if st == nil {
			st = &listState{}
			f.lists[id] = st
		}
		if st.URL != want[id].URL { // a changed URL is a different list
			*st = listState{}
		}
		st.List = want[id]
		f.active = append(f.active, st)
	}
	f.block, f.allow = normalisedSet(c.Block), normalisedSet(c.Allow)
	f.unique = f.countUniqueLocked()
}

// Config returns the configuration in force.
func (f *Filter) Config() Config {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.cfg
}

func (f *Filter) countUniqueLocked() int {
	total := 0
	for _, l := range f.active {
		total += len(l.hashes)
	}
	if len(f.active) <= 1 {
		return total
	}
	all := make([]uint64, 0, total)
	for _, l := range f.active {
		all = append(all, l.hashes...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })
	n := 0
	for i, h := range all {
		if i == 0 || h != all[i-1] {
			n++
		}
	}
	return n
}

// Decision is the answer to "is this name blocked".
type Decision struct {
	Blocked  bool   `json:"blocked"`
	List     string `json:"list,omitempty"` // list id, "custom" for the user's own block list
	ListName string `json:"list_name,omitempty"`
	Category string `json:"category,omitempty"`
	Matched  string `json:"matched,omitempty"` // the domain that matched: the name itself or a parent
	Allowed  bool   `json:"allowed,omitempty"` // the user's allow list overrode a block
}

// Match decides about a name. The user's allow list wins, then the user's block list, then the lists in order.
func (f *Filter) Match(name string) Decision {
	cands := suffixes(name)
	if len(cands) == 0 {
		return Decision{}
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	for _, c := range cands {
		if f.allow[c] {
			return Decision{Allowed: true, Matched: c}
		}
	}
	for _, c := range cands {
		if f.block[c] {
			return Decision{Blocked: true, List: "custom", ListName: "Your block list", Matched: c}
		}
	}
	for _, c := range cands {
		h := hash64(c)
		for _, l := range f.active {
			if contains(l.hashes, h) {
				return Decision{Blocked: true, List: l.ID, ListName: l.Name, Category: l.Category, Matched: c}
			}
		}
	}
	return Decision{}
}

// Refresh fetches every active list that has never loaded or has not been checked for the refresh interval (all of
// them when force is set). A list that fails keeps its old data. It returns the lists that changed.
func (f *Filter) Refresh(ctx context.Context, force bool) (changed []string) {
	f.refresh.Lock()
	defer f.refresh.Unlock()
	f.mu.RLock()
	interval := time.Duration(f.cfg.RefreshHours) * time.Hour
	var todo []*listState
	for _, l := range f.active {
		if force || l.checkedAt.IsZero() || f.now().Sub(l.checkedAt) >= interval {
			todo = append(todo, l)
		}
	}
	f.mu.RUnlock()
	var wg sync.WaitGroup
	var cm sync.Mutex
	sem := make(chan struct{}, 3)
	for _, l := range todo {
		wg.Add(1)
		go func(l *listState) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if f.fetch(ctx, l) {
				cm.Lock()
				changed = append(changed, l.ID)
				cm.Unlock()
			}
		}(l)
	}
	wg.Wait()
	if len(changed) > 0 {
		f.mu.Lock()
		f.unique = f.countUniqueLocked()
		f.mu.Unlock()
	}
	return changed
}

// fetch downloads one list with a conditional request. It reports whether the data changed.
func (f *Filter) fetch(ctx context.Context, l *listState) bool {
	f.mu.RLock()
	url, etag, lmod := l.URL, l.etag, l.lmod
	f.mu.RUnlock()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		f.setErr(l, err.Error())
		return false
	}
	req.Header.Set("User-Agent", "GameBond-dnsfilter")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if lmod != "" {
		req.Header.Set("If-Modified-Since", lmod)
	}
	resp, err := f.HTTP.Do(req)
	if err != nil {
		f.setErr(l, "could not download: "+shorten(err.Error()))
		return false
	}
	defer resp.Body.Close()
	now := f.now()
	switch {
	case resp.StatusCode == http.StatusNotModified:
		f.mu.Lock()
		l.checkedAt, l.err = now, ""
		f.mu.Unlock()
		return false
	case resp.StatusCode != http.StatusOK:
		f.setErr(l, fmt.Sprintf("the provider answered HTTP %d", resp.StatusCode))
		return false
	}
	body := &countingReader{r: io.LimitReader(resp.Body, maxListBytes+1)}
	hashes, st, err := ParseList(body, MaxDomainsPerList)
	if err != nil || body.n > maxListBytes {
		msg := "the list is too large"
		if err != nil {
			msg = err.Error()
		}
		f.setErr(l, msg)
		return false
	}
	if len(hashes) == 0 {
		f.setErr(l, "the list contained no domains")
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.totalWithLocked(l, len(hashes)) > MaxActiveDomain {
		l.err, l.checkedAt = fmt.Sprintf("not loaded: together the active lists would exceed %d domains; switch some off", MaxActiveDomain), now
		return false
	}
	l.hashes, l.stats, l.bytes = hashes, st, body.n
	l.etag, l.lmod = resp.Header.Get("ETag"), resp.Header.Get("Last-Modified")
	l.fetchedAt, l.checkedAt, l.err = now, now, ""
	return true
}

func (f *Filter) totalWithLocked(l *listState, n int) int {
	total := n
	for _, o := range f.active {
		if o != l {
			total += len(o.hashes)
		}
	}
	return total
}

func (f *Filter) setErr(l *listState, msg string) {
	f.mu.Lock()
	l.err, l.checkedAt = msg, f.now()
	f.mu.Unlock()
}

func shorten(s string) string {
	if len(s) > 160 {
		return s[:160]
	}
	return s
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// ListStatus is one list as the GUI shows it.
type ListStatus struct {
	List
	Active      bool   `json:"active"`
	Domains     int    `json:"domains"`
	Skipped     int    `json:"skipped"`
	UpdatedAt   int64  `json:"updated_at,omitempty"`
	CheckedAt   int64  `json:"checked_at,omitempty"`
	Error       string `json:"error,omitempty"`
	SourceName  string `json:"source_name"`
	SourceLic   string `json:"license"`
	SourceCheck bool   `json:"verified"`
}

// Status is what the GUI shows about the lists.
type Status struct {
	Enabled bool         `json:"enabled"`
	Lists   []ListStatus `json:"lists"`
	// Unique is how many different domains the active lists block together (duplicates between lists counted once).
	Unique    int `json:"unique_domains"`
	Total     int `json:"total_domains"`
	Custom    int `json:"custom_block"`
	Allowed   int `json:"custom_allow"`
	Loading   int `json:"loading"`
	WithError int `json:"with_error"`
}

// Status describes every catalog list (active or not) and the totals.
func (f *Filter) Status() Status {
	f.mu.RLock()
	defer f.mu.RUnlock()
	srcs := map[string]Source{}
	for _, s := range Sources {
		srcs[s.ID] = s
	}
	st := Status{Enabled: f.cfg.Enabled, Unique: f.unique, Custom: len(f.block), Allowed: len(f.allow), Lists: []ListStatus{}}
	activeIDs := map[string]*listState{}
	for _, l := range f.active {
		activeIDs[l.ID] = l
	}
	add := func(l List, ls *listState) {
		s := ListStatus{List: l, Active: ls != nil}
		if src, ok := srcs[l.Source]; ok {
			s.SourceName, s.SourceLic, s.SourceCheck = src.Name, src.License, src.Verified
		} else {
			s.SourceName, s.SourceLic = "Your own list", "unknown"
		}
		if ls != nil {
			s.Domains, s.Skipped, s.Error = len(ls.hashes), ls.stats.Skipped, ls.err
			if !ls.fetchedAt.IsZero() {
				s.UpdatedAt = ls.fetchedAt.Unix()
			}
			if !ls.checkedAt.IsZero() {
				s.CheckedAt = ls.checkedAt.Unix()
			}
			st.Total += len(ls.hashes)
			if ls.checkedAt.IsZero() {
				st.Loading++
			}
			if ls.err != "" {
				st.WithError++
			}
		}
		st.Lists = append(st.Lists, s)
	}
	for _, l := range Lists {
		add(l, activeIDs[l.ID])
	}
	for _, l := range f.active {
		if l.Source == "custom" {
			add(l.List, l)
		}
	}
	return st
}

// Run keeps the active lists current until ctx ends: it loads them at once and then every hour checks which are due.
func (f *Filter) Run(ctx context.Context, changed func([]string)) {
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if f.Config().Enabled {
			if ids := f.Refresh(ctx, false); len(ids) > 0 && changed != nil {
				changed(ids)
			}
		}
		t.Reset(15 * time.Minute)
	}
}

// ClientExempt reports whether a client address is exempt from filtering.
func (f *Filter) ClientExempt(a netip.Addr) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	for _, e := range f.cfg.Exempt {
		if strings.EqualFold(e, a.String()) {
			return true
		}
	}
	return false
}
