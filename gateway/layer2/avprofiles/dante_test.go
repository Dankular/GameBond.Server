package avprofiles

import (
	"strings"
	"testing"
)

func TestDanteMatchesAudinateNetworkAdministratorGuidance(t *testing.T) {
	p := Dante()

	if p.ID != "dante" {
		t.Fatalf("ID = %q, want %q", p.ID, "dante")
	}
	if p.Name != "Dante" {
		t.Fatalf("Name = %q, want %q", p.Name, "Dante")
	}

	want := map[string]string{
		"qos.queueing":              "strict-priority",
		"qos.dscp.ptp":              "56",
		"qos.dscp.audio-ptpv2":      "46",
		"qos.dscp.reserved":         "8",
		"qos.dscp.other":            "0",
		"igmp.snooping":             "enabled-when-needed",
		"igmp.version":              "v2-or-v3",
		"igmp.querier":              "one-per-vlan",
		"energy-efficient-ethernet": "disabled",
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
		if !strings.HasPrefix(setting.SourceURL, "https://assets.audinate.com/") {
			t.Errorf("%s SourceURL = %q, want an official Audinate URL", setting.Key, setting.SourceURL)
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
