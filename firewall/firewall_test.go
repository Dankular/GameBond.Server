package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

func parse(t *testing.T, text string) Config {
	t.Helper()
	c, err := Parse(json.RawMessage(text))
	if err != nil {
		t.Fatalf("%v\n%s", err, text)
	}
	return c
}

func parseErr(t *testing.T, text, want string) {
	t.Helper()
	if _, err := Parse(json.RawMessage(text)); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("expected an error containing %q for %s, got %v", want, text, err)
	}
}

func TestParseDefaultsAndRejects(t *testing.T) {
	c := parse(t, `{"enabled":true}`)
	if c.DefaultOutbound != "allow" || c.DefaultInbound != "allow" || c.Countries.Mode != "off" || !c.ServerProtected() {
		t.Fatalf("defaults: %+v", c)
	}
	if c, err := Parse(nil); err != nil || c.Enabled {
		t.Fatalf("an empty configuration is a disabled firewall: %+v %v", c, err)
	}
	parseErr(t, `{"enabled":true,"typo_field":1}`, "unknown field")
	parseErr(t, `{"default_outbound":"maybe"}`, "default_outbound")
	parseErr(t, `{"default_inbound":"maybe"}`, "default_inbound")
	parseErr(t, `{"zones":[{"name":"Bad Name","members":["10.77.0.3"]}]}`, "zone name")
	parseErr(t, `{"zones":[{"name":"a","members":["10.0.0.3"]}]}`, "not a tunnel device address")
	parseErr(t, `{"zones":[{"name":"a","members":["10.77.0.1"]}]}`, "not a tunnel device address")
	parseErr(t, `{"zones":[{"name":"a","members":[]}]}`, "between 1 and")
	parseErr(t, `{"zones":[{"name":"a","members":["10.77.0.3"]},{"name":"a","members":["10.77.0.4"]}]}`, "twice")
	parseErr(t, `{"segmentation":{"allow":[{"from":"a","to":"b"}]}}`, "does not exist")
	parseErr(t, `{"rules":[{"id":"Bad ID","action":"allow"}]}`, "id")
	parseErr(t, `{"rules":[{"id":"r1","action":"permit"}]}`, "action")
	parseErr(t, `{"rules":[{"id":"r1","action":"allow","direction":"sideways"}]}`, "direction")
	parseErr(t, `{"rules":[{"id":"r1","action":"allow","source":"zone:nope"}]}`, "zone that does not exist")
	parseErr(t, `{"rules":[{"id":"r1","action":"allow","dest":"0.0.0.0/0"}]}`, "matches everything")
	parseErr(t, `{"rules":[{"id":"r1","action":"allow","dest":"192.0.2.5/24"}]}`, "not an IPv4 network")
	parseErr(t, `{"rules":[{"id":"r1","action":"allow","dest":"example.com"}]}`, "not any")
	parseErr(t, `{"rules":[{"id":"r1","action":"allow","proto":"icmp","ports":["80"]}]}`, "ports need")
	parseErr(t, `{"rules":[{"id":"r1","action":"allow","proto":"tcp","ports":["0"]}]}`, "port")
	parseErr(t, `{"rules":[{"id":"r1","action":"allow","proto":"tcp","ports":["90-80"]}]}`, "range")
	parseErr(t, `{"rules":[{"id":"r1","action":"allow","proto":"gre"}]}`, "protocol")
	parseErr(t, `{"rules":[{"id":"r1","action":"allow","comment":"x\" ; flush ruleset ; \""}]}`, "comment")
	parseErr(t, `{"rules":[{"id":"r1","action":"allow"},{"id":"r1","action":"deny"}]}`, "twice")
	parseErr(t, `{"countries":{"mode":"block","codes":[]}}`, "at least one country")
	parseErr(t, `{"countries":{"mode":"block","codes":["ru"]}}`, "two-letter")
	parseErr(t, `{"countries":{"mode":"sometimes"}}`, "mode")
	parseErr(t, `{"countries":{"mode":"block","codes":["RU","RU"]}}`, "twice")
}

func TestRuleLimits(t *testing.T) {
	var rules []string
	for i := 0; i <= MaxRules; i++ {
		rules = append(rules, `{"id":"r`+itoa(i)+`","action":"allow"}`)
	}
	parseErr(t, `{"rules":[`+strings.Join(rules, ",")+`]}`, "at most")
}

func itoa(i int) string { return strconv.Itoa(i) }

func render(t *testing.T, c Config, in Inputs) string {
	t.Helper()
	s, _, err := Render(c, in)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRenderIsStatefulAndOrdered(t *testing.T) {
	c := parse(t, `{"enabled":true,"default_outbound":"deny","default_inbound":"deny","block_dot":true,"force_dns":true,
	 "zones":[{"name":"gaming","members":["10.77.0.4","10.77.0.3"]},{"name":"lan","members":["10.77.0.5"]}],
	 "segmentation":{"isolate_devices":true,"allow":[{"from":"lan","to":"gaming"}]},
	 "rules":[{"id":"web","enabled":true,"action":"allow","proto":"tcp","ports":["80","443","8000-8100"],"source":"zone:gaming"},
	          {"id":"off","enabled":false,"action":"deny"},
	          {"id":"in","enabled":true,"action":"allow","direction":"inbound","proto":"tcp","ports":["25565"],"dest":"10.77.0.4"}],
	 "countries":{"mode":"block","codes":["RU"],"direction":"both"}}`)
	s := render(t, c, Inputs{Geo: []netip.Prefix{netip.MustParsePrefix("2.56.24.0/22")}})
	order := []string{
		`ct state invalid counter drop comment "invalid"`,
		`ip saddr @ips_block counter drop comment "ips"`,
		`ip daddr @geo counter drop comment "geo"`,
		`ct state established,related accept`,
		`tcp dport 853 ct state new counter drop comment "dot"`,
		`tcp dport { 80, 443, 8000-8100 }`,
		`comment "seg"`,
		`counter drop comment "isolate"`,
		`counter drop comment "default"`,
		`counter drop comment "default_in"`,
	}
	last := strings.Index(s, "chain forward")
	for _, want := range order {
		i := strings.Index(s[last:], want)
		if i < 0 {
			t.Fatalf("missing %q in forward chain:\n%s", want, s)
		}
		last += i
	}
	for _, want := range []string{"set zone_gaming", "elements = { 10.77.0.3, 10.77.0.4 }", "ip saddr @zone_gaming", "2.56.24.0/22", "redirect to :53", "ip daddr 10.77.0.4 tcp dport 25565"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, `comment "off"`) {
		t.Fatal("a disabled rule must not be rendered")
	}
	// Sorted so the same configuration always renders the same script.
	if s != render(t, c, Inputs{Geo: []netip.Prefix{netip.MustParsePrefix("2.56.24.0/22")}}) {
		t.Fatal("rendering must be deterministic")
	}
}

func TestDisabledFirewallOnlyRemovesTheTable(t *testing.T) {
	s := render(t, Config{DefaultOutbound: "allow", DefaultInbound: "allow", Countries: Countries{Mode: "off", Direction: "outbound"}}, Inputs{})
	if strings.Contains(s, "chain") || !strings.Contains(s, "delete table ip "+Table) {
		t.Fatalf("%s", s)
	}
}

func TestCountryAllowModeIsSkippedWhileTheListsAreEmpty(t *testing.T) {
	c := parse(t, `{"enabled":true,"countries":{"mode":"allow","codes":["NL"],"direction":"outbound"}}`)
	s, warnings, err := Render(c, Inputs{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(s, "ip daddr != @geo") {
		t.Fatalf("allow-only with no data would block everything:\n%s", s)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "not loaded") {
		t.Fatalf("the operator must be told: %v", warnings)
	}
	s, _, _ = Render(c, Inputs{Geo: []netip.Prefix{netip.MustParsePrefix("31.0.0.0/16")}})
	if !strings.Contains(s, "ip daddr != @geo") {
		t.Fatalf("with data the allow-only rule must be installed:\n%s", s)
	}
}

func TestBlocksSurviveARenderAndProtectedAddressesAreNeverBlocked(t *testing.T) {
	c := parse(t, `{"enabled":true}`)
	s := render(t, c, Inputs{Blocked: []Block{{"10.77.0.9", 5 * time.Minute}, {"10.77.0.2", time.Hour}, {"10.77.0.1", time.Hour}, {"203.0.113.9", 0}}})
	if !strings.Contains(s, "10.77.0.9 timeout 300s") || strings.Contains(s, "10.77.0.2 timeout") || strings.Contains(s, "10.77.0.1 timeout") || strings.Contains(s, "203.0.113.9") {
		t.Fatalf("%s", s)
	}
}

func TestProtectServerLeavesOnlyTheNeededServices(t *testing.T) {
	s := render(t, parse(t, `{"enabled":true}`), Inputs{})
	for _, want := range []string{"udp dport 4436 accept", "udp dport 53 accept", "tcp dport 53 accept", "echo-request accept", `comment "protect"`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q", want)
		}
	}
	off := render(t, parse(t, `{"enabled":true,"protect_server":false}`), Inputs{})
	if strings.Contains(off, `comment "protect"`) {
		t.Fatal("protect_server:false must not lock the tunnel out of the server")
	}
}

// nft is the real thing: the script must parse (nft -c loads nothing).
func nftCheck(t *testing.T, script string) {
	t.Helper()
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft is not installed")
	}
	_, err := ExecRunner{}.Run(context.Background(), script, "nft", "-c", "-f", "-")
	if err != nil && (strings.Contains(err.Error(), "Operation not permitted") || strings.Contains(err.Error(), "Permission denied")) {
		t.Skip("nft needs privileges")
	}
	if err != nil {
		t.Fatalf("nft rejected the script: %v\n%s", err, script)
	}
}

func TestRenderedScriptsAreAcceptedByNft(t *testing.T) {
	full := parse(t, `{"enabled":true,"default_outbound":"deny","default_inbound":"deny","block_dot":true,"force_dns":true,
	 "zones":[{"name":"gaming","members":["10.77.0.3","10.77.0.4"]},{"name":"lan","members":["10.77.0.5"]}],
	 "segmentation":{"isolate_devices":true,"allow":[{"from":"lan","to":"gaming"}]},
	 "rules":[{"id":"web","enabled":true,"action":"allow","proto":"tcp","ports":["80","443","8000-8100"],"source":"zone:gaming","dest":"192.0.2.0/24"},
	          {"id":"ping","enabled":true,"action":"deny","proto":"icmp"},{"id":"any-udp","enabled":true,"action":"deny","proto":"udp"},
	          {"id":"in","enabled":true,"action":"allow","direction":"inbound","proto":"tcp","ports":["25565"],"dest":"10.77.0.4"},
	          {"id":"btw","enabled":true,"action":"allow","direction":"between","source":"zone:lan","dest":"zone:gaming"}],
	 "countries":{"mode":"block","codes":["RU"],"direction":"both"}}`)
	nftCheck(t, render(t, full, Inputs{Geo: []netip.Prefix{netip.MustParsePrefix("2.56.24.0/22"), netip.MustParsePrefix("5.8.0.0/19")}, Blocked: []Block{{"10.77.0.9", time.Minute}}}))
	allow := parse(t, `{"enabled":true,"countries":{"mode":"allow","codes":["NL"],"direction":"both"}}`)
	nftCheck(t, render(t, allow, Inputs{Geo: []netip.Prefix{netip.MustParsePrefix("31.0.0.0/16")}}))
	nftCheck(t, render(t, Config{DefaultOutbound: "allow", DefaultInbound: "allow", Countries: Countries{Mode: "off", Direction: "outbound"}}, Inputs{}))
}

// fakeRunner records commands and can fail.
type fakeRunner struct {
	calls   [][]string
	scripts []string
	fail    bool
	out     []byte
}

func (f *fakeRunner) Run(_ context.Context, stdin string, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	if stdin != "" {
		f.scripts = append(f.scripts, stdin)
	}
	if f.fail {
		return nil, errors.New("nft: Error: syntax error")
	}
	return f.out, nil
}

func TestAFailedApplyKeepsThePreviousRules(t *testing.T) {
	f := &fakeRunner{}
	m := NewManager(f)
	if err := m.Apply(context.Background(), parse(t, `{"enabled":true}`)); err != nil {
		t.Fatal(err)
	}
	f.fail = true
	err := m.Apply(context.Background(), parse(t, `{"enabled":true,"default_outbound":"deny"}`))
	if err == nil || !strings.Contains(err.Error(), "previous rules stay in force") {
		t.Fatalf("%v", err)
	}
	if m.cfg.DefaultOutbound != "allow" {
		t.Fatal("the manager must not adopt a configuration nft refused")
	}
	if err := m.Apply(context.Background(), Config{DefaultOutbound: "maybe"}); err == nil || len(f.scripts) != 2 {
		t.Fatal("an invalid configuration must be refused before nft is even asked")
	}
}

func TestBlockingIsImmediateRemembersAcrossApplyAndRefusesProtectedAddresses(t *testing.T) {
	f := &fakeRunner{}
	m := NewManager(f)
	ctx := context.Background()
	if err := m.BlockAddress(ctx, "10.77.0.2", time.Minute); !errors.Is(err, ErrProtected) {
		t.Fatalf("the client PC must never be blocked: %v", err)
	}
	if err := m.BlockAddress(ctx, "10.77.0.1", time.Minute); !errors.Is(err, ErrProtected) {
		t.Fatal("nor the server")
	}
	if err := m.BlockAddress(ctx, "not-an-ip", time.Minute); err == nil {
		t.Fatal("garbage")
	}
	if err := m.BlockAddress(ctx, "10.77.0.9", 0); err == nil {
		t.Fatal("a zero duration")
	}
	m.Apply(ctx, parse(t, `{"enabled":true}`))
	if err := m.BlockAddress(ctx, "10.77.0.9", 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	last := f.calls[len(f.calls)-1]
	if strings.Join(last[:6], " ") != "nft add element ip "+Table+" ips_block" || !strings.Contains(last[6], "10.77.0.9 timeout 600s") {
		t.Fatalf("a block must reach nft at once: %v", last)
	}
	m.Reapply(ctx)
	if !strings.Contains(f.scripts[len(f.scripts)-1], "10.77.0.9 timeout") {
		t.Fatal("replacing the table must not lift a block")
	}
	if b := m.Blocked(); len(b) != 1 || b[0].IP != "10.77.0.9" {
		t.Fatalf("%v", b)
	}
	m.UnblockAddress(ctx, "10.77.0.9")
	if len(m.Blocked()) != 0 {
		t.Fatal("unblock")
	}
}

func TestCountersAreReadFromNftJSON(t *testing.T) {
	f := &fakeRunner{out: []byte(`{"nftables":[{"metainfo":{}},{"rule":{"chain":"forward","comment":"web","expr":[{"match":{}},{"counter":{"packets":7,"bytes":420}},{"accept":null}]}},
	 {"rule":{"chain":"forward","comment":"geo","expr":[{"counter":{"packets":3,"bytes":180}},{"drop":null}]}},
	 {"rule":{"chain":"input","comment":"geo","expr":[{"counter":{"packets":2,"bytes":100}},{"drop":null}]}},{"rule":{"chain":"forward","expr":[{"accept":null}]}}]}`)}
	m := NewManager(f)
	m.Apply(context.Background(), parse(t, `{"enabled":true}`))
	st := m.Status(context.Background())
	if st.Counters["web"] != (Counter{7, 420}) || st.Counters["geo"] != (Counter{5, 280}) || !st.Enabled || !st.Applied {
		t.Fatalf("%+v", st)
	}
	off := NewManager(f)
	if st := off.Status(context.Background()); st.Enabled || len(st.Counters) != 0 {
		t.Fatalf("a firewall that was never applied has no counters: %+v", st)
	}
}

func TestFlushConnectionsWithoutConntrack(t *testing.T) {
	f := &fakeRunner{}
	m := NewManager(f)
	if err := m.FlushConnections(context.Background()); err != nil || f.calls[0][0] != "conntrack" {
		t.Fatalf("%v %v", err, f.calls)
	}
}
