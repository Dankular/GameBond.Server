package avprofiles

import "testing"

func TestCatalogueContainsEveryRequestedProfileWithEvidence(t *testing.T) {
	want := []string{"aes67", "crestron", "dante", "ndi", "play", "qsys", "sdvoe", "shure"}
	profiles := All()
	if len(profiles) != len(want) {
		t.Fatalf("catalogue has %d profiles, want %d", len(profiles), len(want))
	}
	for i, profile := range profiles {
		if profile.ID != want[i] {
			t.Errorf("profile[%d].ID = %q, want %q", i, profile.ID, want[i])
		}
		if len(profile.Settings) == 0 {
			t.Errorf("profile %q has no documented settings", profile.ID)
		}
		for _, setting := range profile.Settings {
			if setting.Key == "" || setting.Value == "" || setting.Rationale == "" || setting.SourceURL == "" {
				t.Errorf("profile %q contains an incomplete setting: %#v", profile.ID, setting)
			}
		}
	}
}
