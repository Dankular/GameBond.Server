package avprofiles

import (
	"strings"
	"testing"
)

const (
	danteNetworkAdminSource = "https://assets.audinate.com/wp-content/uploads/2022/03/dante-information-for-network-admins.pdf"
	danteSnoopingSource     = "https://go.audinate.com/hubfs/implementing-dante-AV-over-IP_techpaper-20220314-en.pdf?hsLang=en"
)

func TestDanteMatchesAudinateNetworkAdministratorGuidance(t *testing.T) {
	p := Dante()

	if p.ID != "dante" {
		t.Fatalf("ID = %q, want %q", p.ID, "dante")
	}
	if p.Name != "Dante" {
		t.Fatalf("Name = %q, want %q", p.Name, "Dante")
	}

	type expectedSetting struct {
		value  string
		source string
	}
	want := map[string]expectedSetting{
		"qos.queueing":              {value: "strict-priority", source: danteNetworkAdminSource},
		"qos.queue.order":           {value: "56>46>8", source: danteNetworkAdminSource},
		"qos.dscp.ptp":              {value: "56", source: danteNetworkAdminSource},
		"qos.dscp.audio-ptpv2":      {value: "46", source: danteNetworkAdminSource},
		"qos.dscp.reserved":         {value: "8", source: danteNetworkAdminSource},
		"qos.dscp.other":            {value: "0", source: danteNetworkAdminSource},
		"igmp.snooping":             {value: "enabled-when-needed", source: danteSnoopingSource},
		"igmp.version":              {value: "v2-or-v3", source: danteNetworkAdminSource},
		"igmp.querier":              {value: "one-per-vlan", source: danteNetworkAdminSource},
		"energy-efficient-ethernet": {value: "disabled", source: danteNetworkAdminSource},
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
	if !strings.Contains(p.Caveats[0], "QoS") || !strings.Contains(p.Caveats[0], "mixed-use") {
		t.Errorf("QoS caveat missing its deployment condition: %q", p.Caveats[0])
	}
	if !strings.Contains(p.Caveats[1], "IGMP") || !strings.Contains(p.Caveats[1], "few or no multicast") {
		t.Errorf("IGMP caveat missing its deployment condition: %q", p.Caveats[1])
	}
	if !strings.Contains(p.Caveats[2], "re-marked") {
		t.Errorf("DSCP re-marking caveat missing: %q", p.Caveats[2])
	}
}
