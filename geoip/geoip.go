// Package geoip supplies the IPv4 address ranges of countries for the firewall's country filter. The ranges come
// from ipdeny.com's aggregated per-country lists, one file per ISO 3166 code. Every line is validated: a list that
// is corrupt, or tampered with to cover the whole internet, must never become a firewall rule.
package geoip

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	DefaultBaseURL = "https://www.ipdeny.com"
	// MaxEntries bounds one country's list (the largest real ones have a few thousand aggregated ranges).
	MaxEntries = 60000
	maxBytes   = 4 << 20
	// MinPrefixBits refuses ranges wider than a /5. Real lists do contain very wide blocks (the US list has /6s),
	// but a /0 to /4 would cover a sixteenth of the internet or more, and one such line could block everything.
	MinPrefixBits = 5
	// MaxCoverage refuses a list that covers more than half of IPv4. The largest real one (the US) is about a third.
	MaxCoverage = uint64(1) << 31
	// FreshFor is how long a fetched list is used without asking again.
	FreshFor = 7 * 24 * time.Hour
)

var codePattern = regexp.MustCompile(`^[A-Z]{2}$`)

// Store keeps the lists in memory and, when given a directory, on disk.
type Store struct {
	Dir     string
	BaseURL string
	HTTP    *http.Client

	mu     sync.Mutex
	data   map[string][]netip.Prefix
	at     map[string]time.Time
	errs   map[string]string
	now    func() time.Time
	loaded bool
}

// New returns a store; dir may be empty for memory only.
func New(dir string) *Store {
	return &Store{Dir: dir, BaseURL: DefaultBaseURL, HTTP: &http.Client{Timeout: 45 * time.Second},
		data: map[string][]netip.Prefix{}, at: map[string]time.Time{}, errs: map[string]string{}, now: time.Now}
}

// Parse reads an ipdeny zone file: one IPv4 CIDR per line, optional blank lines and # comments.
func Parse(r io.Reader) ([]netip.Prefix, error) {
	var out []netip.Prefix
	var coverage uint64
	sc := bufio.NewScanner(io.LimitReader(r, maxBytes))
	n := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		n++
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p, err := netip.ParsePrefix(line)
		if err != nil || !p.Addr().Is4() {
			return nil, fmt.Errorf("line %d is not an IPv4 range: %.40q", n, line)
		}
		if p.Masked() != p {
			p = p.Masked()
		}
		if p.Bits() < MinPrefixBits {
			return nil, fmt.Errorf("line %d: %s is wider than a /%d", n, line, MinPrefixBits)
		}
		out = append(out, p)
		coverage += uint64(1) << (32 - p.Bits())
		if coverage > MaxCoverage {
			return nil, fmt.Errorf("the list covers more than half of the IPv4 address space")
		}
		if len(out) > MaxEntries {
			return nil, fmt.Errorf("more than %d ranges", MaxEntries)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errors.New("the list is empty")
	}
	return out, nil
}

func (s *Store) path(cc string) string { return filepath.Join(s.Dir, strings.ToLower(cc)+".zone") }

// load reads cached files once (a missing or damaged file is simply not loaded).
func (s *Store) loadDisk(cc string) {
	if s.Dir == "" {
		return
	}
	f, err := os.Open(s.path(cc))
	if err != nil {
		return
	}
	defer f.Close()
	st, _ := f.Stat()
	p, err := Parse(f)
	if err != nil || st == nil {
		return
	}
	s.data[cc], s.at[cc] = p, st.ModTime()
}

func (s *Store) fetch(ctx context.Context, cc string) ([]netip.Prefix, error) {
	url := fmt.Sprintf("%s/ipblocks/data/aggregated/%s-aggregated.zone", strings.TrimSuffix(s.BaseURL, "/"), strings.ToLower(cc))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not fetch the list for %s: %w", cc, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%s is not a country code the list provider knows", cc)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the list provider answered HTTP %d for %s", resp.StatusCode, cc)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxBytes {
		return nil, fmt.Errorf("the list for %s is larger than %d bytes", cc, maxBytes)
	}
	p, err := Parse(strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("the list for %s is not usable: %w", cc, err)
	}
	if s.Dir != "" {
		if err := os.MkdirAll(s.Dir, 0o755); err == nil {
			tmp := s.path(cc) + ".tmp"
			if os.WriteFile(tmp, body, 0o644) == nil {
				_ = os.Rename(tmp, s.path(cc))
			}
		}
	}
	return p, nil
}

// Ensure makes sure the lists for codes are loaded and fresh. A list that cannot be refreshed keeps its older copy;
// the error says which ones failed. It reports whether anything changed.
func (s *Store) Ensure(ctx context.Context, codes []string) (changed bool, err error) {
	var failed []string
	var wg sync.WaitGroup
	sem := make(chan struct{}, 3)
	for _, cc := range codes {
		if !codePattern.MatchString(cc) {
			failed = append(failed, cc+": not a country code")
			continue
		}
		s.mu.Lock()
		if _, ok := s.data[cc]; !ok {
			s.loadDisk(cc)
		}
		fresh := s.now().Sub(s.at[cc]) < FreshFor && len(s.data[cc]) > 0
		s.mu.Unlock()
		if fresh {
			continue
		}
		wg.Add(1)
		go func(cc string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			p, ferr := s.fetch(ctx, cc)
			s.mu.Lock()
			defer s.mu.Unlock()
			if ferr != nil {
				s.errs[cc] = ferr.Error()
				failed = append(failed, ferr.Error())
				return
			}
			delete(s.errs, cc)
			s.data[cc], s.at[cc] = p, s.now()
			changed = true
		}(cc)
	}
	wg.Wait()
	if len(failed) > 0 {
		sort.Strings(failed)
		return changed, errors.New(strings.Join(failed, "; "))
	}
	return changed, nil
}

// Prefixes returns the ranges of the given countries that are loaded, sorted and without duplicates.
func (s *Store) Prefixes(codes []string) []netip.Prefix {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	for _, cc := range codes {
		for _, p := range s.data[cc] {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if c := out[i].Addr().Compare(out[j].Addr()); c != 0 {
			return c < 0
		}
		return out[i].Bits() < out[j].Bits()
	})
	return out
}

// CountryStatus is what the GUI shows for one country.
type CountryStatus struct {
	Code      string `json:"code"`
	Ranges    int    `json:"ranges"`
	FetchedAt int64  `json:"fetched_at,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Status reports the countries in codes.
func (s *Store) Status(codes []string) []CountryStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]CountryStatus, 0, len(codes))
	for _, cc := range codes {
		st := CountryStatus{Code: cc, Ranges: len(s.data[cc]), Error: s.errs[cc]}
		if t := s.at[cc]; !t.IsZero() {
			st.FetchedAt = t.Unix()
		}
		out = append(out, st)
	}
	return out
}

// Run keeps the lists for the current selection fresh until ctx ends, calling changed when new data arrived.
func (s *Store) Run(ctx context.Context, codes func() []string, changed func()) {
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if cc := codes(); len(cc) > 0 {
			if ch, _ := s.Ensure(ctx, cc); ch && changed != nil {
				changed()
			}
		}
		t.Reset(6 * time.Hour)
	}
}
