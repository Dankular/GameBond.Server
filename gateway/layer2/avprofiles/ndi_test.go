package avprofiles

import (
	"strings"
	"testing"
)

const (
	ndiConfigurationSource = "https://docs.ndi.video/all/developing-with-ndi/sdk/configuration-files"
	ndiMulticastSource     = "https://docs.ndi.video/all/getting-started/white-paper/multicast"
	ndiLayoutSource        = "https://docs.ndi.video/all/getting-started/white-paper/network-layout"
)

func TestNDIMatchesCurrentNDINetworkGuidance(t *testing.T) {
	p := NDI()

	if p.ID != "ndi" {
		t.Fatalf("ID = %q, want %q", p.ID, "ndi")
	}
	if p.Name != "NDI" {
		t.Fatalf("Name = %q, want %q", p.Name, "NDI")
	}

	type expectedSetting struct {
		value  string
		source string
	}
	want := map[string]expectedSetting{
		"transport.preferred": {value: "reliable-udp", source: ndiConfigurationSource},
		"multicast.send":      {value: "disabled", source: ndiMulticastSource},
		"igmp.snooping":       {value: "required-when-multicast-enabled", source: ndiMulticastSource},
		"igmp.querier":        {value: "required-when-multicast-enabled", source: ndiMulticastSource},
		"link.minimum-speed":  {value: "1-gbps-full-duplex", source: ndiLayoutSource},
		"jumbo-frames":        {value: "not-required", source: ndiConfigurationSource},
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
