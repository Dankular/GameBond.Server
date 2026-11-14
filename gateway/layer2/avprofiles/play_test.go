package avprofiles

import (
	"strings"
	"testing"
)

const playSourceURL = "https://help.ui.com/hc/en-us/articles/29946699826199-Getting-Started-with-UniFi-Play"

func TestPlayDocumentsOnlyPublishedUniFiPlayNetworkGuidance(t *testing.T) {
	p := Play()

	if p.ID != "play" {
		t.Fatalf("ID = %q, want %q", p.ID, "play")
	}
	if p.Name != "UniFi Play" {
		t.Fatalf("Name = %q, want %q", p.Name, "UniFi Play")
	}
	if len(p.Settings) != 1 {
		t.Fatalf("len(Settings) = %d, want 1", len(p.Settings))
	}

	setting := p.Settings[0]
	if setting.Key != "vlan.scope" || setting.Value != "same-vlan" {
		t.Fatalf("setting = %#v, want vlan.scope=same-vlan", setting)
	}
	if setting.Rationale == "" {
		t.Fatal("setting rationale is empty")
	}
	if setting.SourceURL != playSourceURL {
		t.Fatalf("SourceURL = %q, want %q", setting.SourceURL, playSourceURL)
	}

	if len(p.Caveats) != 2 {
		t.Fatalf("len(Caveats) = %d, want 2", len(p.Caveats))
	}
	if !strings.Contains(p.Caveats[0], "interpreted as Ubiquiti UniFi Play") {
		t.Fatalf("first caveat = %q, want the Play identity qualification", p.Caveats[0])
	}
	if !strings.Contains(p.Caveats[0], "does not publish") {
		t.Fatalf("first caveat = %q, want the unpublished preset limitation", p.Caveats[0])
	}
}
