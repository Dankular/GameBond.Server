package avprofiles

import (
	"net/url"
	"strings"
	"testing"
)

func TestSDVoEProfileDocumentsAllianceSwitchRequirements(t *testing.T) {
	profile := SDVoE()
	if profile.ID != "sdvoe" || profile.Name != "SDVoE" {
		t.Fatalf("identity = %q, %q", profile.ID, profile.Name)
	}

	want := map[string]string{
		"link.minimum-speed":              "10-gbps-per-endpoint",
		"igmp.version":                    "v2",
		"igmp.snooping":                   "enabled",
		"igmp.fast-leave":                 "enabled",
		"multicast.unregistered-flooding": "disabled",
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
		if setting.SourceURL != "https://sdvoe.org/blog/the-four-commandments-of-an-sdvoe-network-switch/" {
			t.Errorf("setting %q source = %q", setting.Key, setting.SourceURL)
		}
	}
	if len(profile.Caveats) != 3 {
		t.Fatalf("caveats = %#v", profile.Caveats)
	}
	if !strings.Contains(profile.Caveats[0], "additional") || !strings.Contains(profile.Caveats[1], "uplink") || !strings.Contains(profile.Caveats[2], "does not certify") {
		t.Errorf("caveats do not preserve vendor, capacity, and certification limits: %#v", profile.Caveats)
	}
}

func assertHTTPSURL(t *testing.T, key, raw string) {
	t.Helper()
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		t.Errorf("setting %q source URL = %q, parse error = %v", key, raw, err)
	}
}
