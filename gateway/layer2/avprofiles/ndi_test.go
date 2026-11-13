package avprofiles

import (
	"strings"
	"testing"
)

func TestNDIMatchesCurrentNDINetworkGuidance(t *testing.T) {
	p := NDI()

	if p.ID != "ndi" {
		t.Fatalf("ID = %q, want %q", p.ID, "ndi")
	}
	if p.Name != "NDI" {
		t.Fatalf("Name = %q, want %q", p.Name, "NDI")
	}

	want := map[string]string{
		"transport.preferred": "reliable-udp",
		"multicast.send":      "disabled",
		"igmp.snooping":       "required-when-multicast-enabled",
		"igmp.querier":        "required-when-multicast-enabled",
		"link.minimum-speed":  "1-gbps-full-duplex",
		"jumbo-frames":        "not-required",
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
		if !strings.HasPrefix(setting.SourceURL, "https://docs.ndi.video/") {
			t.Errorf("%s SourceURL = %q, want an official NDI documentation URL", setting.Key, setting.SourceURL)
		}
	}

	if len(p.Caveats) != 2 {
		t.Fatalf("len(Caveats) = %d, want 2", len(p.Caveats))
	}
	if !strings.Contains(p.Caveats[0], "discourages multicast") {
		t.Errorf("multicast caveat missing: %q", p.Caveats[0])
	}
	if !strings.Contains(p.Caveats[1], "DSCP") || !strings.Contains(p.Caveats[1], "VLAN") {
		t.Errorf("unsupported-setting caveat missing: %q", p.Caveats[1])
	}
}
