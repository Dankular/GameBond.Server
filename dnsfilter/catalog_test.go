package dnsfilter

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCatalogIsConsistent(t *testing.T) {
	sources := map[string]Source{}
	for _, s := range Sources {
		if _, dup := sources[s.ID]; dup || s.Name == "" || s.License == "" || !strings.HasPrefix(s.Repo, "https://") {
			t.Fatalf("bad source %+v", s)
		}
		sources[s.ID] = s
	}
	if len(Sources) != 10 {
		t.Fatalf("the ten referenced projects: %d", len(Sources))
	}
	ids := map[string]bool{}
	perCategory := map[string]int{}
	defaults := map[string]int{}
	for _, l := range Lists {
		if ids[l.ID] || l.Name == "" {
			t.Fatalf("bad list %+v", l)
		}
		ids[l.ID] = true
		src, ok := sources[l.Source]
		if !ok {
			t.Errorf("%s: unknown source %s", l.ID, l.Source)
		}
		if !src.Verified {
			t.Errorf("%s: a list from a source whose files were not verified must not be in the catalog", l.ID)
		}
		if !categoryKnown(l.Category) {
			t.Errorf("%s: unknown category %s", l.ID, l.Category)
		}
		if !strings.HasPrefix(l.URL, "https://") {
			t.Errorf("%s: the URL must be https", l.ID)
		}
		perCategory[l.Category]++
		if l.Default {
			defaults[l.Category]++
		}
	}
	for _, c := range Categories {
		if perCategory[c.ID] == 0 || defaults[c.ID] == 0 {
			t.Errorf("category %s needs lists and at least one default", c.ID)
		}
	}
	// The licences are shown to the user exactly as the project states them.
	for id, want := range map[string]string{"stevenblack": "MIT", "hagezi": "GPL-3.0", "adguard": "GPL-3.0", "blocklistproject": "Unlicense", "onehosts": "MPL-2.0", "perflyst": "MIT"} {
		if sources[id].License != want {
			t.Errorf("%s licence %q, want %q", id, sources[id].License, want)
		}
	}
	for _, id := range []string{"easylist", "mullvad"} {
		if sources[id].License != "not verified" {
			t.Errorf("%s must say its licence is not verified", id)
		}
	}
	if sources["mullvad"].Verified {
		t.Error("mullvad has no verified download")
	}
}

// TestLiveCatalog downloads and parses every list (GAMEBOND_DNSFILTER_LIVE=1; about 300 MB).
func TestLiveCatalog(t *testing.T) {
	if os.Getenv("GAMEBOND_DNSFILTER_LIVE") != "1" {
		t.Skip("set GAMEBOND_DNSFILTER_LIVE=1 to download the real lists")
	}
	client := &http.Client{Timeout: 3 * time.Minute}
	for _, l := range Lists {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, l.URL, nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Errorf("%s: %v", l.ID, err)
			continue
		}
		hashes, st, err := ParseList(resp.Body, MaxDomainsPerList)
		resp.Body.Close()
		if resp.StatusCode != 200 || err != nil {
			t.Errorf("%s: HTTP %d %v", l.ID, resp.StatusCode, err)
			continue
		}
		min := 200
		if l.SizeMB <= 1 {
			min = 5
		}
		if len(hashes) < min {
			t.Errorf("%s: only %d domains parsed (%+v)", l.ID, len(hashes), st)
		}
		t.Logf("%-28s %8d domains  (%d lines, %d skipped, %d exceptions)", l.ID, len(hashes), st.Lines, st.Skipped, st.Excepted)
	}
}
