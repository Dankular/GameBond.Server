package avprofiles

import (
	"strings"
	"testing"
)

func TestCrestronProfileDocumentsDMNVXNetworkRequirements(t *testing.T) {
	profile := Crestron()
	if profile.ID != "crestron" || profile.Name != "Crestron DM NVX" {
		t.Fatalf("identity = %q, %q", profile.ID, profile.Name)
	}

	want := map[string]string{
		"link.minimum-speed": "1-gbps-per-endpoint",
		"switch.backplane":   "nonblocking",
		"switch.layer":       "layer-3",
		"vlan.scope":         "dedicated-segment",
		"igmp.version":       "v2",
		"igmp.snooping":      "enabled",
		"igmp.querier":       "one-per-vlan",
		"igmp.fast-leave":    "enabled",
		"qos.classification": "802.1p-with-802.1q",
		"qos.queue.igmp":     "highest",
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
		if setting.SourceURL != "https://docs.crestron.com/en-us/9496/Content/Topics/AV-over-IP_Network-Design.htm" {
			t.Errorf("setting %q source = %q", setting.Key, setting.SourceURL)
		}
	}
	if len(profile.Caveats) != 6 {
		t.Fatalf("caveats = %#v", profile.Caveats)
	}
	if !strings.Contains(profile.Caveats[0], "DM NVX") || !strings.Contains(profile.Caveats[1], "uplink") || !strings.Contains(profile.Caveats[2], "examples") || !strings.Contains(profile.Caveats[3], "IGMPv3") || !strings.Contains(profile.Caveats[4], "PIM") || !strings.Contains(profile.Caveats[5], "does not certify") {
		t.Errorf("caveats do not preserve scope, capacity, QoS, IGMP, routing, and certification limits: %#v", profile.Caveats)
	}
}
