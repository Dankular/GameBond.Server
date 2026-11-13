package avprofiles

import (
	"strings"
	"testing"
)

func TestShureProfileDocumentsManagedSwitchPolicy(t *testing.T) {
	profile := Shure()
	if profile.ID != "shure" || profile.Name != "Shure Dante/AES67" {
		t.Fatalf("identity = %q, %q", profile.ID, profile.Name)
	}

	want := map[string]string{
		"link.minimum-speed":               "1-gbps",
		"energy-efficient-ethernet":        "disabled",
		"multicast.storm-control":          "disabled",
		"igmp.version":                     "v2",
		"igmp.snooping":                    "enabled",
		"igmp.querier":                     "one-per-vlan",
		"igmp.query-interval":              "30-seconds",
		"igmp.fast-leave":                  "enabled",
		"multicast.unregistered-filtering": "disabled",
		"qos.classification":               "trust-dscp",
		"qos.queue.dscp56":                 "highest",
		"qos.queue.dscp46":                 "second-highest",
		"qos.queue.dscp34":                 "third-highest",
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
		if !strings.HasPrefix(setting.SourceURL, "https://service.shure.com/") {
			t.Errorf("setting %q source = %q, want official Shure documentation", setting.Key, setting.SourceURL)
		}
	}
	if len(profile.Caveats) != 5 {
		t.Fatalf("caveats = %#v", profile.Caveats)
	}
	if !strings.Contains(profile.Caveats[0], "firmware") || !strings.Contains(profile.Caveats[1], "Small isolated") || !strings.Contains(profile.Caveats[2], "conflicts with SDVoE") || !strings.Contains(profile.Caveats[3], "PoE") || !strings.Contains(profile.Caveats[4], "does not certify") {
		t.Errorf("caveats do not preserve firmware, topology, conflict, power, and certification limits: %#v", profile.Caveats)
	}
}
