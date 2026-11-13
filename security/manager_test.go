package security

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type recorder struct {
	mu      sync.Mutex
	scripts []string
	calls   [][]string
	fail    bool
	out     []byte
}

func (r *recorder) Run(_ context.Context, stdin string, name string, args ...string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, append([]string{name}, args...))
	if stdin != "" {
		r.scripts = append(r.scripts, stdin)
	}
	if r.fail && name == "nft" {
		return nil, errors.New("nft: Error: syntax error")
	}
	return r.out, nil
}

func newManager(t *testing.T) (*Manager, *recorder) {
	t.Helper()
	rec := &recorder{}
	geo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/ru-") {
			fmt.Fprint(w, "2.56.24.0/22\n5.8.0.0/19\n")
			return
		}
		w.WriteHeader(404)
	}))
	t.Cleanup(geo.Close)
	m := New(Options{Runner: rec, GeoDir: t.TempDir()})
	m.Geo.BaseURL = geo.URL
	return m, rec
}

func TestParseSettings(t *testing.T) {
	s, err := Parse(nil)
	if err != nil || s.Firewall.Enabled || s.DNSFilter.Enabled || s.IDS.Mode != "off" {
		t.Fatalf("%+v %v", s, err)
	}
	s, err = Parse(json.RawMessage(`{"firewall":{"enabled":true,"force_dns":true},"dns_filter":{"enabled":true,"categories":["ads"]},"ids":{"mode":"detect"}}`))
	if err != nil || !s.Firewall.ForceDNS || s.IDS.Mode != "detect" || s.DNSFilter.BlockMode != "nxdomain" {
		t.Fatalf("%+v %v", s, err)
	}
	for in, want := range map[string]string{
		`{"firewal":{}}`:                         "unknown section",
		`{"firewall":{"enabled":true,"x":1}}`:    "unknown field",
		`{"dns_filter":{"categories":["nope"]}}`: "unknown category",
		`{"ids":{"mode":"loud"}}`:                "mode",
		`{"firewall":{"force_dns":true}}`:        "force_dns needs the firewall",
		`[]`:                                     "",
	} {
		_, err := Parse(json.RawMessage(in))
		if want == "" && err == nil || want != "" && (err == nil || !strings.Contains(err.Error(), want)) {
			t.Errorf("%s: expected %q, got %v", in, want, err)
		}
	}
	round, err := Parse(s.JSON())
	if err != nil || round.JSON() == nil || string(round.JSON()) != string(s.JSON()) {
		t.Fatalf("the settings must survive a round trip through JSON: %v", err)
	}
}

func TestApplyInstallsEveryEngine(t *testing.T) {
	m, rec := newManager(t)
	err := m.Apply(context.Background(), json.RawMessage(`{"firewall":{"enabled":true,"countries":{"mode":"block","codes":["RU"],"direction":"outbound"},"rules":[{"id":"r1","enabled":true,"action":"deny","proto":"tcp","ports":["23"]}]},
	  "dns_filter":{"enabled":true,"categories":["ads"],"block":["bad.example.com"]},"ids":{"mode":"prevent"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.scripts) != 1 {
		t.Fatalf("one atomic nft script: %d", len(rec.scripts))
	}
	for _, want := range []string{"2.56.24.0/22", "5.8.0.0/19", `comment "r1"`, "tcp dport 23"} {
		if !strings.Contains(rec.scripts[0], want) {
			t.Errorf("the firewall script lacks %q:\n%s", want, rec.scripts[0])
		}
	}
	if m.IDS.Config().Mode != "prevent" || !m.List.Config().Enabled || m.Settings().Firewall.Rules[0].ID != "r1" {
		t.Fatal("every engine must have its part")
	}
	if d := m.List.Match("www.bad.example.com"); !d.Blocked || d.List != "custom" {
		t.Fatalf("%+v", d)
	}
}

func TestARefusedFirewallRollsEverythingBack(t *testing.T) {
	m, rec := newManager(t)
	if err := m.Apply(context.Background(), json.RawMessage(`{"dns_filter":{"enabled":true,"block":["old.example.com"]},"ids":{"mode":"detect"}}`)); err != nil {
		t.Fatal(err)
	}
	rec.fail = true
	err := m.Apply(context.Background(), json.RawMessage(`{"firewall":{"enabled":true},"dns_filter":{"enabled":true,"block":["new.example.com"]},"ids":{"mode":"prevent"}}`))
	if err == nil || !strings.Contains(err.Error(), "previous rules stay in force") {
		t.Fatalf("%v", err)
	}
	if m.IDS.Config().Mode != "detect" || m.List.Match("old.example.com").Blocked == false || m.List.Match("new.example.com").Blocked {
		t.Fatal("the detector and the DNS filter must return to what they were: all of it applies or none")
	}
	if m.Settings().Firewall.Enabled {
		t.Fatal("and the recorded settings must not change")
	}
}

func TestInvalidSettingsChangeNothing(t *testing.T) {
	m, rec := newManager(t)
	if err := m.Apply(context.Background(), json.RawMessage(`{"ids":{"mode":"detect"}}`)); err != nil {
		t.Fatal(err)
	}
	calls := len(rec.calls)
	if err := m.Apply(context.Background(), json.RawMessage(`{"ids":{"mode":"prevent"},"firewall":{"default_outbound":"maybe"}}`)); err == nil {
		t.Fatal("expected a validation error")
	}
	if m.IDS.Config().Mode != "detect" || len(rec.calls) != calls {
		t.Fatal("a configuration that does not validate must touch nothing")
	}
}

func TestUnavailableCountryListsDoNotBlockApplyAndAreReported(t *testing.T) {
	m, _ := newManager(t)
	err := m.Apply(context.Background(), json.RawMessage(`{"firewall":{"enabled":true,"countries":{"mode":"allow","codes":["ZZ"],"direction":"both"}}}`))
	if err != nil {
		t.Fatalf("the firewall must still apply: %v", err)
	}
	ov := m.Overview(context.Background()).(map[string]any)
	fw := ov["firewall"].(interface{})
	raw, _ := json.Marshal(fw)
	if !strings.Contains(string(raw), "not loaded") {
		t.Fatalf("the operator must be told the country filter is not enforcing: %s", raw)
	}
	raw, _ = json.Marshal(ov["countries"])
	if !strings.Contains(string(raw), "ZZ") || !strings.Contains(string(raw), "error") {
		t.Fatalf("%s", raw)
	}
}

func TestOverviewAndCatalogShape(t *testing.T) {
	m, _ := newManager(t)
	m.Apply(context.Background(), json.RawMessage(`{"dns_filter":{"enabled":true},"ids":{"mode":"detect"}}`))
	raw, _ := json.Marshal(m.Overview(context.Background()))
	var ov map[string]json.RawMessage
	json.Unmarshal(raw, &ov)
	for _, k := range []string{"settings", "firewall", "countries", "dns", "ids"} {
		if _, ok := ov[k]; !ok {
			t.Errorf("overview lacks %s", k)
		}
	}
	var cat struct {
		Categories []struct{ ID string }   `json:"categories"`
		Sources    []struct{ ID string }   `json:"sources"`
		Lists      []struct{ ID string }   `json:"lists"`
		Detectors  []struct{ Kind string } `json:"detectors"`
		Countries  []string                `json:"countries"`
	}
	craw, _ := json.Marshal(m.Catalog())
	json.Unmarshal(craw, &cat)
	if len(cat.Categories) != 12 || len(cat.Sources) != 10 || len(cat.Lists) < 40 || len(cat.Detectors) != 10 || len(cat.Countries) < 240 {
		t.Fatalf("%d categories, %d sources, %d lists, %d detectors, %d countries", len(cat.Categories), len(cat.Sources), len(cat.Lists), len(cat.Detectors), len(cat.Countries))
	}
	seen := map[string]bool{}
	for _, c := range cat.Countries {
		if len(c) != 2 || seen[c] {
			t.Fatalf("bad or repeated country code %q", c)
		}
		seen[c] = true
	}
}

func TestActions(t *testing.T) {
	m, rec := newManager(t)
	ctx := context.Background()
	m.Apply(ctx, json.RawMessage(`{"firewall":{"enabled":true},"dns_filter":{"enabled":true,"block":["x.example.com"]},"ids":{"mode":"prevent"}}`))
	if _, err := m.Do(ctx, "block", map[string]any{"ip": "10.77.0.9", "seconds": float64(60)}); err != nil {
		t.Fatal(err)
	}
	if last := rec.calls[len(rec.calls)-1]; !strings.Contains(strings.Join(last, " "), "add element ip gamebond_fw ips_block { 10.77.0.9 timeout 60s }") {
		t.Fatalf("%v", last)
	}
	if _, err := m.Do(ctx, "block", map[string]any{"ip": "10.77.0.2"}); err == nil {
		t.Fatal("the client PC must not be blockable from the GUI either")
	}
	if _, err := m.Do(ctx, "unblock", map[string]any{"ip": "10.77.0.9"}); err != nil {
		t.Fatal(err)
	}
	d, err := m.Do(ctx, "check_domain", map[string]any{"domain": "a.x.example.com"})
	if err != nil || !strings.Contains(fmt.Sprint(d), "true") {
		t.Fatalf("%v %v", d, err)
	}
	for _, bad := range []string{"check_domain", "nope"} {
		if _, err := m.Do(ctx, bad, map[string]any{}); err == nil {
			t.Errorf("%s with no usable arguments must fail", bad)
		}
	}
	if _, err := m.Do(ctx, "clear_events", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Do(ctx, "flush_connections", nil); err != nil || rec.calls[len(rec.calls)-1][0] != "conntrack" {
		t.Fatalf("%v", err)
	}
	if _, err := m.Do(ctx, "refresh_lists", nil); err != nil {
		t.Fatal(err)
	}
}

func TestTapFeedsTheDetector(t *testing.T) {
	m, _ := newManager(t)
	m.Apply(context.Background(), json.RawMessage(`{"ids":{"mode":"detect"}}`))
	pk := make([]byte, 60)
	pk[0], pk[9] = 0x45, 6
	copy(pk[12:], []byte{10, 77, 0, 3})
	copy(pk[16:], []byte{198, 51, 100, 7})
	pk[33] = 0x02
	m.Tap(true, pk)
	if m.IDS.Status().Packets != 1 {
		t.Fatal("the tap must reach the detector")
	}
	_ = time.Second
}
