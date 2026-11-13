package dnsfilter

import (
	"strings"
	"testing"
)

func domainsOf(t *testing.T, text string) (map[string]bool, ParseStats) {
	t.Helper()
	hashes, st, err := ParseList(strings.NewReader(text), 1000)
	if err != nil {
		t.Fatal(err)
	}
	set := map[uint64]bool{}
	for _, h := range hashes {
		set[h] = true
	}
	out := map[string]bool{}
	for _, cand := range []string{"ads.example.com", "tracker.example.net", "example.org", "evil.test", "a.b.example.com", "multi.example.com", "second.example.com", "ad.001zb.com", "royalbluefireplace.com", "wild.example.com", "device-messaging-na.amazon.com", "ip6.example.com", "kept.example.com", "x.example.com", "trail.example.com"} {
		if set[hash64(cand)] {
			out[cand] = true
		}
	}
	return out, st
}

func TestParseHostsFormat(t *testing.T) {
	got, st := domainsOf(t, "# Title\n127.0.0.1 localhost\n127.0.0.1 localhost.localdomain\n::1 ip6-localhost\n0.0.0.0 0.0.0.0\n0.0.0.0 ads.example.com # trailing\n127.0.0.1\ttracker.example.net\n0.0.0.0 multi.example.com second.example.com\n::1 ip6.example.com\n")
	for _, want := range []string{"ads.example.com", "tracker.example.net", "multi.example.com", "ip6.example.com"} {
		if !got[want] {
			t.Errorf("%s missing: %v", want, got)
		}
	}
	if got["second.example.com"] {
		t.Log("only the first name on a hosts line is taken; the rest are aliases")
	}
	if st.Domains != 4 {
		t.Fatalf("localhost, the address 0.0.0.0 and single-label names must not count: %+v", st)
	}
}

func TestParseDomainAndWildcardFormats(t *testing.T) {
	got, st := domainsOf(t, "# Version: 1\n\nexample.org\n*.wild.example.com\n*.ad.001zb.com\nEXAMPLE.ORG\ndevice-messaging-na.amazon.com\ncom\nlocalhost\n")
	for _, want := range []string{"example.org", "wild.example.com", "ad.001zb.com", "device-messaging-na.amazon.com"} {
		if !got[want] {
			t.Errorf("%s missing: %v", want, got)
		}
	}
	if st.Domains != 4 || st.Skipped < 2 {
		t.Fatalf("a duplicate counts once and a bare TLD must be skipped: %+v", st)
	}
}

func TestParseAdblockFormat(t *testing.T) {
	text := `[Adblock Plus 2.0]
! Title: AdGuard DNS filter
||royalbluefireplace.com^
||evil.test^$third-party
||important.example.com^$important
||cacheserve.*/promodisplay/
||online.example.com/promoredirect?key=
||x.example.com^$script
||y.example.com^$domain=foo.com
@@||allowed.example.com^
||pattern*.example.com^
||withport.example.com:8080^
/regex/
##.banner
example.com##.ad
`
	got, st := domainsOf(t, text)
	if !got["royalbluefireplace.com"] || !got["evil.test"] {
		t.Fatalf("plain rules, also with third-party, must apply: %v", got)
	}
	if got["x.example.com"] {
		t.Fatal("a rule restricted to scripts is browser-only")
	}
	if st.Domains != 3 || st.Excepted != 1 {
		t.Fatalf("%+v (royalbluefireplace, evil.test and important.example.com)", st)
	}
	if st.Skipped < 6 {
		t.Fatalf("paths, patterns, ports, cosmetic and option rules must be skipped: %+v", st)
	}
}

func TestParseRejectsGarbageAndLimits(t *testing.T) {
	_, st := domainsOf(t, "not a domain at all\n-bad.example.com\nbad-.example.\n.leading.example\nexa mple.com\nhttp://x.example.com/path\n1.2.3.4\n0.0.0.0 1.2.3.4\nex@mple.com\n")
	if st.Domains != 0 {
		t.Fatalf("%+v", st)
	}
	if _, _, err := ParseList(strings.NewReader("a.example.com\nb.example.com\nc.example.com\n"), 2); err == nil {
		t.Fatal("a list over the limit must be refused")
	}
	long := strings.Repeat("a", 64) + "." + strings.Repeat("b.", 125) + "com"
	if _, ok := NormalizeDomain(long); ok {
		t.Fatal("a name over 253 characters is not a domain")
	}
}

func TestNormalizeDomain(t *testing.T) {
	for in, want := range map[string]string{"Example.COM": "example.com", "example.com.": "example.com", "  a.b-c.example.com ": "a.b-c.example.com", "_dmarc.example.com": "_dmarc.example.com", "xn--80ak6aa92e.com": "xn--80ak6aa92e.com"} {
		if got, ok := NormalizeDomain(in); !ok || got != want {
			t.Errorf("%q -> %q %v", in, got, ok)
		}
	}
	for _, bad := range []string{"", "com", "a..b.com", ".a.com", "a.com..", "a b.com", "ü.com", "10.0.0.1", "::1", "a.b/c"} {
		if _, ok := NormalizeDomain(bad); ok {
			t.Errorf("%q must be refused", bad)
		}
	}
}

func TestSuffixes(t *testing.T) {
	got := suffixes("A.B.Example.com.")
	if strings.Join(got, ",") != "a.b.example.com,b.example.com,example.com" {
		t.Fatalf("%v", got)
	}
	if len(suffixes("com")) != 0 || len(suffixes("")) != 0 {
		t.Fatal("a bare TLD is never looked up")
	}
}

func TestContains(t *testing.T) {
	h, _, _ := ParseList(strings.NewReader("a.example.com\nb.example.com\nc.example.com\n"), 10)
	if !contains(h, hash64("b.example.com")) || contains(h, hash64("d.example.com")) || contains(nil, 1) {
		t.Fatal("binary search")
	}
}
