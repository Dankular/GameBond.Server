package dnsfilter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// listServer serves fixture lists with ETags, counts requests and can fail.
type listServer struct {
	mu      sync.Mutex
	bodies  map[string]string
	etags   map[string]string
	hits    map[string]int
	cond    map[string]int // requests that carried If-None-Match
	failing map[string]bool
}

func newListServer(t *testing.T) (*listServer, *httptest.Server) {
	ls := &listServer{bodies: map[string]string{}, etags: map[string]string{}, hits: map[string]int{}, cond: map[string]int{}, failing: map[string]bool{}}
	srv := httptest.NewServer(ls)
	t.Cleanup(srv.Close)
	return ls, srv
}

func (l *listServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()
	p := r.URL.Path
	l.hits[p]++
	if l.failing[p] {
		w.WriteHeader(503)
		return
	}
	body, ok := l.bodies[p]
	if !ok {
		w.WriteHeader(404)
		return
	}
	if inm := r.Header.Get("If-None-Match"); inm != "" {
		l.cond[p]++
		if inm == l.etags[p] {
			w.WriteHeader(304)
			return
		}
	}
	w.Header().Set("ETag", l.etags[p])
	fmt.Fprint(w, body)
}

func withCatalog(t *testing.T, base string) {
	t.Helper()
	old := Lists
	Lists = []List{
		{"ads-hosts", "stevenblack", "Ads (hosts)", "ads", base + "/ads-hosts", "hosts", 1, true},
		{"ads-wild", "oisd", "Ads (wildcard)", "ads", base + "/ads-wild", "wildcard", 1, true},
		{"ads-extra", "hagezi", "Ads extra", "ads", base + "/ads-extra", "wildcard", 1, false},
		{"adult", "stevenblack", "Adult", "adult", base + "/adult", "hosts", 1, true},
		{"malware", "blocklistproject", "Malware", "malware", base + "/malware", "hosts", 1, true},
	}
	t.Cleanup(func() { Lists = old })
}

func fixture(t *testing.T) (*Filter, *listServer) {
	ls, srv := newListServer(t)
	withCatalog(t, srv.URL)
	ls.bodies["/ads-hosts"], ls.etags["/ads-hosts"] = "0.0.0.0 ads.example.com\n0.0.0.0 shared.example.net\n", `"a1"`
	ls.bodies["/ads-wild"], ls.etags["/ads-wild"] = "*.tracker.example.org\n*.shared.example.net\n", `"w1"`
	ls.bodies["/ads-extra"], ls.etags["/ads-extra"] = "extra.example.com\n", `"e1"`
	ls.bodies["/adult"], ls.etags["/adult"] = "0.0.0.0 adult.example.com\n", `"x1"`
	ls.bodies["/malware"], ls.etags["/malware"] = "0.0.0.0 evil.example.com\n", `"m1"`
	f := NewFilter()
	f.HTTP = srv.Client()
	return f, ls
}

func TestCategoriesDefaultsAndOverrides(t *testing.T) {
	f, _ := fixture(t)
	f.Apply(Config{Enabled: true, Categories: []string{"ads"}})
	f.Refresh(context.Background(), false)
	for name, want := range map[string]bool{"ads.example.com": true, "x.tracker.example.org": true, "extra.example.com": false, "adult.example.com": false, "evil.example.com": false, "fine.example.com": false} {
		if got := f.Match(name).Blocked; got != want {
			t.Errorf("%s blocked=%v, want %v", name, got, want)
		}
	}
	f.Apply(Config{Enabled: true, Categories: []string{"ads", "adult"}, EnableLists: []string{"ads-extra"}, DisableLists: []string{"ads-wild"}})
	f.Refresh(context.Background(), false)
	for name, want := range map[string]bool{"ads.example.com": true, "extra.example.com": true, "adult.example.com": true, "x.tracker.example.org": false} {
		if got := f.Match(name).Blocked; got != want {
			t.Errorf("%s blocked=%v, want %v", name, got, want)
		}
	}
}

func TestMatchAttributionAndSubdomains(t *testing.T) {
	f, _ := fixture(t)
	f.Apply(Config{Enabled: true, Categories: []string{"ads", "malware"}})
	f.Refresh(context.Background(), false)
	d := f.Match("deep.sub.ads.example.com.")
	if !d.Blocked || d.List != "ads-hosts" || d.Category != "ads" || d.Matched != "ads.example.com" || d.ListName != "Ads (hosts)" {
		t.Fatalf("a subdomain of a blocked domain is blocked, and says which list and which parent: %+v", d)
	}
	if d := f.Match("EVIL.Example.COM"); !d.Blocked || d.Category != "malware" {
		t.Fatalf("%+v", d)
	}
	if f.Match("example.com").Blocked || f.Match("com").Blocked || f.Match("").Blocked {
		t.Fatal("a parent of a blocked domain is not blocked")
	}
}

func TestAllowAndBlockOverridesInOrder(t *testing.T) {
	f, _ := fixture(t)
	f.Apply(Config{Enabled: true, Categories: []string{"ads"}, Block: []string{"mine.example.com"}, Allow: []string{"ads.example.com"}})
	f.Refresh(context.Background(), false)
	if d := f.Match("ads.example.com"); d.Blocked || !d.Allowed {
		t.Fatalf("the user's allow list wins over a list: %+v", d)
	}
	if d := f.Match("cdn.ads.example.com"); d.Blocked {
		t.Fatalf("allowing a domain allows its subdomains: %+v", d)
	}
	if d := f.Match("www.mine.example.com"); !d.Blocked || d.List != "custom" {
		t.Fatalf("%+v", d)
	}
	f.Apply(Config{Enabled: true, Categories: []string{"ads"}, Block: []string{"x.ads.example.com"}, Allow: []string{"x.ads.example.com"}})
	if d := f.Match("x.ads.example.com"); d.Blocked {
		t.Fatal("allow beats the user's own block as well")
	}
}

func TestConditionalRequestsAndFailuresKeepOldData(t *testing.T) {
	f, ls := fixture(t)
	f.Apply(Config{Enabled: true, Categories: []string{"ads"}})
	if changed := f.Refresh(context.Background(), false); len(changed) != 2 {
		t.Fatalf("first load: %v", changed)
	}
	if changed := f.Refresh(context.Background(), false); len(changed) != 0 || ls.hits["/ads-hosts"] != 1 {
		t.Fatalf("lists checked a moment ago must not be fetched again: %v %d", changed, ls.hits["/ads-hosts"])
	}
	if changed := f.Refresh(context.Background(), true); len(changed) != 0 || ls.cond["/ads-hosts"] != 1 {
		t.Fatalf("a forced refresh asks conditionally and a 304 changes nothing: %v cond=%d", changed, ls.cond["/ads-hosts"])
	}
	ls.mu.Lock()
	ls.bodies["/ads-hosts"], ls.etags["/ads-hosts"] = "0.0.0.0 new.example.com\n", `"a2"`
	ls.mu.Unlock()
	if changed := f.Refresh(context.Background(), true); len(changed) != 1 || changed[0] != "ads-hosts" {
		t.Fatalf("an updated list is picked up: %v", changed)
	}
	if !f.Match("new.example.com").Blocked || f.Match("ads.example.com").Blocked {
		t.Fatal("the new content replaces the old")
	}
	ls.mu.Lock()
	ls.failing["/ads-hosts"] = true
	ls.mu.Unlock()
	f.Refresh(context.Background(), true)
	if !f.Match("new.example.com").Blocked {
		t.Fatal("a failed refresh must keep protecting with the old data")
	}
	var st ListStatus
	for _, l := range f.Status().Lists {
		if l.ID == "ads-hosts" {
			st = l
		}
	}
	if !st.Active || st.Domains != 1 || !strings.Contains(st.Error, "503") || st.UpdatedAt == 0 {
		t.Fatalf("%+v", st)
	}
}

func TestRefreshIntervalIsHonoured(t *testing.T) {
	f, ls := fixture(t)
	clock := time.Now()
	f.now = func() time.Time { return clock }
	f.Apply(Config{Enabled: true, Categories: []string{"ads"}, RefreshHours: 6})
	f.Refresh(context.Background(), false)
	clock = clock.Add(5 * time.Hour)
	f.Refresh(context.Background(), false)
	if ls.hits["/ads-hosts"] != 1 {
		t.Fatal("not due yet")
	}
	clock = clock.Add(2 * time.Hour)
	f.Refresh(context.Background(), false)
	if ls.hits["/ads-hosts"] != 2 {
		t.Fatal("due: the list must be checked again, at runtime, without a restart")
	}
}

func TestConsolidationCountsSharedDomainsOnce(t *testing.T) {
	f, _ := fixture(t)
	f.Apply(Config{Enabled: true, Categories: []string{"ads"}})
	f.Refresh(context.Background(), false)
	st := f.Status()
	if st.Total != 4 || st.Unique != 3 {
		t.Fatalf("ads.example.com, shared.example.net and tracker.example.org, with the shared one in both lists: %+v", st)
	}
	if d := f.Match("shared.example.net"); d.List != "ads-hosts" {
		t.Fatalf("a domain in two lists is attributed to the first in catalog order: %+v", d)
	}
}

func TestLeavingACategoryDropsItsListsFromMemory(t *testing.T) {
	f, _ := fixture(t)
	f.Apply(Config{Enabled: true, Categories: []string{"ads", "adult"}})
	f.Refresh(context.Background(), false)
	f.Apply(Config{Enabled: true, Categories: []string{"ads"}})
	if f.Match("adult.example.com").Blocked {
		t.Fatal("a category switched off must stop blocking at once")
	}
	if _, kept := f.lists["adult"]; kept {
		t.Fatal("and its domains must be freed")
	}
}

func TestMemoryCap(t *testing.T) {
	f, _ := fixture(t)
	old := MaxActiveDomain
	MaxActiveDomain = 3
	defer func() { MaxActiveDomain = old }()
	f.Apply(Config{Enabled: true, Categories: []string{"ads", "adult", "malware"}})
	f.Refresh(context.Background(), false)
	st := f.Status()
	if st.Total > 3 || st.WithError == 0 {
		t.Fatalf("lists that would exceed the cap must not be loaded, and must say why: %+v", st)
	}
}

func TestStatusDescribesTheWholeCatalogWithLicences(t *testing.T) {
	f, _ := fixture(t)
	f.Apply(Config{Enabled: true, Categories: []string{"ads"}, CustomLists: []CustomList{{ID: "custom-mine", Name: "Mine", URL: "https://example.com/x.txt"}}})
	st := f.Status()
	if len(st.Lists) != len(Lists)+1 {
		t.Fatalf("%d lists", len(st.Lists))
	}
	byID := map[string]ListStatus{}
	for _, l := range st.Lists {
		byID[l.ID] = l
	}
	if byID["ads-hosts"].SourceName != "StevenBlack/hosts" || byID["ads-hosts"].SourceLic != "MIT" || !byID["ads-hosts"].Active || byID["adult"].Active {
		t.Fatalf("%+v %+v", byID["ads-hosts"], byID["adult"])
	}
	if c := byID["custom-mine"]; !c.Active || c.SourceName != "Your own list" {
		t.Fatalf("%+v", c)
	}
}

func TestListsAreNeverFetchedFromPrivateAddresses(t *testing.T) {
	_, srv := newListServer(t) // on 127.0.0.1
	f := NewFilter()           // the real, guarded client
	f.Apply(Config{Enabled: true, CustomLists: []CustomList{{ID: "custom-lo", Name: "Loopback", URL: srv.URL + "/x"}}})
	f.Refresh(context.Background(), false)
	for _, l := range f.Status().Lists {
		if l.ID == "custom-lo" && !strings.Contains(l.Error, "could not download") {
			t.Fatalf("the server must not fetch from its own network on a user's behalf: %+v", l)
		}
	}
}

func TestParseConfig(t *testing.T) {
	parse := func(s string) (Config, error) { return Parse(json.RawMessage(s)) }
	c, err := parse(`{"enabled":true,"categories":["ads","adult"]}`)
	if err != nil || c.BlockMode != "nxdomain" || c.RefreshHours != 12 || len(c.Upstreams) != 2 {
		t.Fatalf("%+v %v", c, err)
	}
	bad := map[string]string{
		`{"typo":1}`: "unknown field", `{"block_mode":"sinkhole"}`: "block_mode", `{"refresh_hours":999}`: "refresh_hours",
		`{"categories":["nope"]}`: "unknown category", `{"categories":["ads","ads"]}`: "twice",
		`{"upstreams":["8.8.8.8"]}`: "host:port", `{"upstreams":["127.0.0.1:53"]}`: "loop", `{"upstreams":["10.77.0.1:53"]}`: "loop", `{"upstreams":["dns.google:53"]}`: "IPv4",
		`{"enable_lists":["made-up"]}`: "not in the catalog", `{"block":["not a domain"]}`: "not a domain", `{"allow":["com"]}`: "not a domain",
		`{"exempt":["10.77.0.x"]}`: "IPv4", `{"custom_lists":[{"id":"bad","name":"x","url":"https://example.com/a"}]}`: "custom-",
		`{"custom_lists":[{"id":"custom-a","name":"x","url":"http://example.com/a"}]}`:                   "https",
		`{"custom_lists":[{"id":"custom-a","name":"x","url":"https://10.0.0.5/a"}]}`:                     "private",
		`{"custom_lists":[{"id":"custom-a","name":"x","url":"https://127.0.0.1/a"}]}`:                    "private",
		`{"custom_lists":[{"id":"custom-a","name":"","url":"https://example.com/a"}]}`:                   "name",
		`{"custom_lists":[{"id":"custom-a","name":"x","url":"https://example.com/a","category":"zzz"}]}`: "category",
	}
	for in, want := range bad {
		if _, err := parse(in); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: expected %q, got %v", in, want, err)
		}
	}
}
