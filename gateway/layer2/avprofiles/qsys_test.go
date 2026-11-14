package avprofiles

import (
	"strings"
	"testing"
)

const (
	qsysNetworkSource   = "https://help.qsys.com/Content/Networking/Switches_Infrastructure.htm"
	qsysChecklistSource = "https://www.qsys.com/products-solutions/q-sys/networking/q-sys-networking-solutions/qsc-q-sys-network-support-checklist/"
)

func TestQSYSMatchesQSYSNetworkRequirements(t *testing.T) {
	p := QSYS()

	if p.ID != "qsys" {
		t.Fatalf("ID = %q, want %q", p.ID, "qsys")
	}
	if p.Name != "Q-SYS" {
		t.Fatalf("Name = %q, want %q", p.Name, "Q-SYS")
	}

	type expectedSetting struct {
		value  string
		source string
	}
	want := map[string]expectedSetting{
		"link.minimum-speed":   {value: "1-gbps", source: qsysNetworkSource},
		"qos.classification":   {value: "diffserv-dscp", source: qsysNetworkSource},
		"qos.queue.ptpv2":      {value: "46:strict-highest", source: qsysNetworkSource},
		"qos.queue.audio":      {value: "34:strict-second-highest", source: qsysNetworkSource},
		"qos.queue.video":      {value: "26:third-highest", source: qsysNetworkSource},
		"igmp.version":         {value: "v2", source: qsysNetworkSource},
		"igmp.snooping":        {value: "enabled-for-multicast", source: qsysNetworkSource},
		"igmp.querier":         {value: "one-per-vlan", source: qsysChecklistSource},
		"vlan.endpoint-frames": {value: "untagged", source: qsysChecklistSource},
		"jumbo-frames":         {value: "disabled", source: qsysChecklistSource},
	}
	if len(p.Settings) != len(want) {
		t.Fatalf("len(Settings) = %d, want %d", len(p.Settings), len(want))
	}
	seen := make(map[string]int, len(want))
	for _, setting := range p.Settings {
		expected, ok := want[setting.Key]
		if !ok {
			t.Errorf("unexpected setting key %q", setting.Key)
			continue
		}
		seen[setting.Key]++
		if setting.Value != expected.value {
			t.Errorf("%s = %q, want %q", setting.Key, setting.Value, expected.value)
		}
		if setting.Rationale == "" {
			t.Errorf("%s has an empty rationale", setting.Key)
		}
		if setting.SourceURL != expected.source {
			t.Errorf("%s SourceURL = %q, want %q", setting.Key, setting.SourceURL, expected.source)
		}
	}
	for key := range want {
		if seen[key] != 1 {
			t.Errorf("setting %q occurs %d times, want exactly once", key, seen[key])
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
