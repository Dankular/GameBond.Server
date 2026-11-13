package avprofiles

import (
	"strings"
	"testing"
)

func TestAES67ProfileDocumentsStandardTrafficClasses(t *testing.T) {
	profile := AES67()
	if profile.ID != "aes67" || profile.Name != "AES67" {
		t.Fatalf("identity = %q, %q", profile.ID, profile.Name)
	}

	want := map[string]string{
		"timing.ptp-version": "ieee-1588-2008",
		"qos.dscp.ptp":       "46",
		"qos.dscp.audio":     "34",
		"qos.dscp.other":     "0",
	}
	if len(profile.Settings) != len(want) {
		t.Fatalf("settings = %#v", profile.Settings)
	}
	for _, setting := range profile.Settings {
		if value, ok := want[setting.Key]; !ok || setting.Value != value {
			t.Errorf("setting %q = %q, want %q", setting.Key, setting.Value, value)
		}
		if setting.Rationale == "" {
			t.Errorf("setting %q has no rationale", setting.Key)
		}
		assertHTTPSURL(t, setting.Key, setting.SourceURL)
		if setting.SourceURL != "https://www.aes.org/publications/standards/preview.cfm?ID=96" {
			t.Errorf("setting %q source = %q", setting.Key, setting.SourceURL)
		}
	}
	if len(profile.Caveats) != 4 {
		t.Fatalf("caveats = %#v", profile.Caveats)
	}
	if !strings.Contains(profile.Caveats[0], "different markings") || !strings.Contains(profile.Caveats[1], "PTP") || !strings.Contains(profile.Caveats[2], "does not choose") || !strings.Contains(profile.Caveats[3], "does not establish") {
		t.Errorf("caveats do not preserve marking, timing, deployment, and conformance limits: %#v", profile.Caveats)
	}
}
