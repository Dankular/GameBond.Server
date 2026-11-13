package geoip

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	p, err := Parse(strings.NewReader("# Russia\n2.56.24.0/22\n\n  5.8.0.0/19  \n2.56.24.5/22\n"))
	if err != nil || len(p) != 3 || p[0].String() != "2.56.24.0/22" || p[2].String() != "2.56.24.0/22" {
		t.Fatalf("%v %v (a host bit is masked off, not rejected)", p, err)
	}
	for name, bad := range map[string]string{
		"everything":   "0.0.0.0/0\n",
		"too wide":     "16.0.0.0/4\n",
		"half the net": "0.0.0.0/5\n8.0.0.0/5\n16.0.0.0/5\n24.0.0.0/5\n32.0.0.0/5\n40.0.0.0/5\n48.0.0.0/5\n56.0.0.0/5\n64.0.0.0/5\n72.0.0.0/5\n80.0.0.0/5\n88.0.0.0/5\n96.0.0.0/5\n104.0.0.0/5\n112.0.0.0/5\n120.0.0.0/5\n128.0.0.0/5\n",
		"ipv6":         "2001:db8::/32\n",
		"not a range":  "example.com\n",
		"no mask":      "1.2.3.4\n",
		"empty":        "# nothing\n\n",
		"injection":    "1.2.3.0/24 }; flush ruleset; {\n",
		"mixed a bad":  "1.2.3.0/24\nnope\n",
	} {
		if _, err := Parse(strings.NewReader(bad)); err == nil {
			t.Errorf("%s must be refused", name)
		}
	}
	if p, err := Parse(strings.NewReader("6.0.0.0/7\n16.0.0.0/6\n20.0.0.0/7\n")); err != nil || len(p) != 3 {
		t.Errorf("the real wide blocks of the US list must be accepted: %v %v", p, err)
	}
	var many strings.Builder
	for i := 0; i <= MaxEntries; i++ {
		fmt.Fprintf(&many, "%d.%d.%d.0/24\n", 11+i/65536, (i/256)%256, i%256)
	}
	if _, err := Parse(strings.NewReader(many.String())); err == nil {
		t.Error("an oversized list must be refused")
	}
}

type provider struct {
	hits    atomic.Int32
	lists   map[string]string
	failing atomic.Bool
}

func (p *provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.hits.Add(1)
	if p.failing.Load() {
		w.WriteHeader(503)
		return
	}
	cc := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/ipblocks/data/aggregated/"), "-aggregated.zone")
	body, ok := p.lists[cc]
	if !ok {
		w.WriteHeader(404)
		return
	}
	fmt.Fprint(w, body)
}

func newStore(t *testing.T, dir string) (*Store, *provider) {
	p := &provider{lists: map[string]string{"ru": "2.56.24.0/22\n5.8.0.0/19\n", "kp": "175.45.176.0/22\n", "cn": "1.0.1.0/24\n5.8.0.0/19\n", "bad": "0.0.0.0/0\n"}}
	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)
	s := New(dir)
	s.BaseURL = srv.URL
	return s, p
}

func TestEnsureFetchesCachesAndMerges(t *testing.T) {
	s, p := newStore(t, t.TempDir())
	ctx := context.Background()
	changed, err := s.Ensure(ctx, []string{"RU", "KP"})
	if err != nil || !changed || p.hits.Load() != 2 {
		t.Fatalf("%v %v %d", changed, err, p.hits.Load())
	}
	if changed, err := s.Ensure(ctx, []string{"RU", "KP"}); err != nil || changed || p.hits.Load() != 2 {
		t.Fatalf("fresh lists must not be fetched again: %v %v %d", changed, err, p.hits.Load())
	}
	s.Ensure(ctx, []string{"CN"})
	got := s.Prefixes([]string{"RU", "CN"})
	if len(got) != 3 || got[0].String() != "1.0.1.0/24" || got[1].String() != "2.56.24.0/22" || got[2].String() != "5.8.0.0/19" {
		t.Fatalf("a range both countries list must appear once, sorted: %v", got)
	}
	if len(s.Prefixes([]string{"DE"})) != 0 {
		t.Fatal("a country that is not loaded has no ranges")
	}
}

func TestEnsureRefusesBadListsAndUnknownCountries(t *testing.T) {
	s, _ := newStore(t, "")
	_, err := s.Ensure(context.Background(), []string{"BAD", "XX", "ru", "KP"})
	if err == nil {
		t.Fatal("expected errors")
	}
	if !strings.Contains(err.Error(), "XX is not a country code the list provider knows") && !strings.Contains(err.Error(), "not a country code") {
		t.Fatalf("%v", err)
	}
	if len(s.Prefixes([]string{"KP"})) != 1 {
		t.Fatal("a failure for one country must not stop the others loading")
	}
	if len(s.Prefixes([]string{"BAD"})) != 0 {
		t.Fatal("a list that covers everything must never be loaded")
	}
	if st := s.Status([]string{"XX"}); st[0].Error == "" {
		t.Fatalf("%+v", st)
	}
}

func TestStaleListIsKeptWhenARefreshFails(t *testing.T) {
	s, p := newStore(t, t.TempDir())
	clock := time.Now()
	s.now = func() time.Time { return clock }
	s.Ensure(context.Background(), []string{"KP"})
	clock = clock.Add(FreshFor + time.Hour)
	p.failing.Store(true)
	changed, err := s.Ensure(context.Background(), []string{"KP"})
	if err == nil || changed {
		t.Fatalf("%v %v", changed, err)
	}
	if len(s.Prefixes([]string{"KP"})) != 1 {
		t.Fatal("the older copy must keep protecting while the provider is down")
	}
	if st := s.Status([]string{"KP"})[0]; st.Ranges != 1 || st.Error == "" {
		t.Fatalf("%+v", st)
	}
}

func TestDiskCacheSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	s, p := newStore(t, dir)
	s.Ensure(context.Background(), []string{"RU"})
	if _, err := os.Stat(filepath.Join(dir, "ru.zone")); err != nil {
		t.Fatal(err)
	}
	s2, _ := newStore(t, dir)
	s2.BaseURL = "http://127.0.0.1:1" // unreachable: the cache must be enough
	if changed, err := s2.Ensure(context.Background(), []string{"RU"}); err != nil || changed {
		t.Fatalf("%v %v", changed, err)
	}
	if len(s2.Prefixes([]string{"RU"})) != 2 {
		t.Fatal("not restored from disk")
	}
	_ = p
	os.WriteFile(filepath.Join(dir, "kp.zone"), []byte("0.0.0.0/0\n"), 0o644) // a tampered cache file
	s3, _ := newStore(t, dir)
	s3.Ensure(context.Background(), []string{"KP"})
	if got := s3.Prefixes([]string{"KP"}); len(got) != 1 || got[0] != netip.MustParsePrefix("175.45.176.0/22") {
		t.Fatalf("a bad cache file must be ignored and replaced: %v", got)
	}
}

func TestOversizedResponseIsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < 200000; i++ {
			fmt.Fprintf(w, "1.%d.%d.0/24\n", (i/256)%256, i%256)
		}
	}))
	defer srv.Close()
	s := New("")
	s.BaseURL = srv.URL
	if _, err := s.Ensure(context.Background(), []string{"ZZ"}); err == nil {
		t.Fatal("a huge answer must be refused")
	}
}

// TestLiveProvider checks the real ipdeny lists parse (GAMEBOND_GEOIP_LIVE=1; it uses the network).
func TestLiveProvider(t *testing.T) {
	if os.Getenv("GAMEBOND_GEOIP_LIVE") != "1" {
		t.Skip("set GAMEBOND_GEOIP_LIVE=1 to fetch the real lists")
	}
	s := New(t.TempDir())
	for _, cc := range []string{"RU", "CN", "NL", "US"} {
		if _, err := s.Ensure(context.Background(), []string{cc}); err != nil {
			t.Fatalf("%s: %v", cc, err)
		}
		t.Logf("%s: %d ranges", cc, len(s.Prefixes([]string{cc})))
	}
}
