package avprofiles

import (
	"strings"
	"testing"
)

func TestQSYSMatchesQSYSNetworkRequirements(t *testing.T) {
	p := QSYS()

	if p.ID != "qsys" {
		t.Fatalf("ID = %q, want %q", p.ID, "qsys")
	}
	if p.Name != "Q-SYS" {
		t.Fatalf("Name = %q, want %q", p.Name, "Q-SYS")
	}

	want := map[string]string{
		"link.minimum-speed":   "1-gbps",
		"qos.classification":   "diffserv-dscp",
		"qos.queue.ptpv2":      "46:strict-highest",
		"qos.queue.audio":      "34:strict-second-highest",
		"qos.queue.video":      "26:third-highest",
		"igmp.version":         "v2",
		"igmp.snooping":        "enabled-for-multicast",
		"igmp.querier":         "one-per-vlan",
		"vlan.endpoint-frames": "untagged",
		"jumbo-frames":         "disabled",
	}
	if len(p.Settings) != len(want) {
		t.Fatalf("len(Settings) = %d, want %d", len(p.Settings), len(want))
	}
	for _, setting := range p.Settings {
		value, ok := want[setting.Key]
		if !ok {
			t.Errorf("unexpected setting key %q", setting.Key)
			continue
		}
		if setting.Value != value {
			t.Errorf("%s = %q, want %q", setting.Key, setting.Value, value)
		}
		if setting.Rationale == "" {
			t.Errorf("%s has an empty rationale", setting.Key)
		}
		if !strings.HasPrefix(setting.SourceURL, "https://") || !strings.Contains(setting.SourceURL, "qsys.com/") {
			t.Errorf("%s SourceURL = %q, want an official Q-SYS URL", setting.Key, setting.SourceURL)
		}
	}

	if len(p.Caveats) != 3 {
		t.Fatalf("len(Caveats) = %d, want 3", len(p.Caveats))
	}
	if !strings.Contains(p.Caveats[0], "recommended") || !strings.Contains(p.Caveats[0], "mixed") {
		t.Errorf("QoS caveat missing: %q", p.Caveats[0])
	}
	if !strings.Contains(p.Caveats[1], "multicast") {
		t.Errorf("multicast caveat missing: %q", p.Caveats[1])
	}
	if !strings.Contains(p.Caveats[2], "Q-LAN-only") {
		t.Errorf("Q-LAN scope caveat missing: %q", p.Caveats[2])
	}
}
