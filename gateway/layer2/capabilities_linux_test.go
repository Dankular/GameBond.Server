//go:build linux

package layer2

import (
	"context"
	"testing"
)

func TestEvaluateCapabilitiesReportsMissingTools(t *testing.T) {
	c := EvaluateCapabilities(Detection{KernelRelease: "6.12.0", Tools: map[string]bool{"ip": true}})
	if got := c.Features[FeatureBridgeVLAN]; got.State != CapabilityUnavailable || got.Reason == "" {
		t.Fatalf("bridge VLAN without bridge tool must be unavailable, got %#v", got)
	}
	if got := c.Features[FeatureFlowControl]; got.State != CapabilityUnavailable {
		t.Fatalf("flow control without ethtool must be unavailable, got %#v", got)
	}
}

func TestEvaluateCapabilitiesDoesNotClaimGenericMCLAG(t *testing.T) {
	c := EvaluateCapabilities(Detection{Tools: map[string]bool{
		"ip": true, "bridge": true, "tc": true, "nft": true, "ethtool": true,
	}})
	if got := c.Features[FeatureMCLAG]; got.State != CapabilityUnsupported {
		t.Fatalf("generic Linux provider must not claim MC-LAG support, got %#v", got)
	}
}

func TestEvaluateCapabilitiesRequiresProvidersForProtocolFeatures(t *testing.T) {
	c := EvaluateCapabilities(Detection{Tools: map[string]bool{"ip": true, "bridge": true}})
	if got := c.Features[FeatureVRRP]; got.State != CapabilityUnavailable {
		t.Fatalf("VRRP without provider must be unavailable, got %#v", got)
	}
	if got := c.Features[FeatureRSTP]; got.State != CapabilityUnavailable {
		t.Fatalf("RSTP without provider must be unavailable, got %#v", got)
	}
	if got := c.Features[FeatureLLDPMED]; got.State != CapabilityUnavailable {
		t.Fatalf("LLDP-MED without provider must be unavailable, got %#v", got)
	}
}

func TestEvaluateCapabilitiesMarksProfilesUnsupportedUntilIntegrated(t *testing.T) {
	c := EvaluateCapabilities(Detection{Tools: map[string]bool{"ip": true, "bridge": true, "tc": true, "nft": true}})
	for _, profile := range avProfiles {
		if got := c.Features[profile.feature]; got.State != CapabilityUnsupported {
			t.Errorf("profile %s must stay unsupported before integration, got %#v", profile.name, got)
		}
	}
}

type capabilityRunner struct{}

func (capabilityRunner) Available(tool string) bool { return tool == "ip" || tool == "bridge" }
func (capabilityRunner) Run(_ context.Context, tool string, _ ...string) ([]byte, error) {
	if tool == "ip" {
		return []byte(`[{"ifname":"enp2s0","mtu":1500,"max_mtu":9000,"flags":["UP"]}]`), nil
	}
	return []byte(`[]`), nil
}

func TestSnapshotCapabilitiesReportsInterfaceMaximumMTU(t *testing.T) {
	caps, err := SnapshotCapabilities(context.Background(), capabilityRunner{})
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range caps.Interfaces {
		if iface.Name == "enp2s0" {
			if iface.MaxMTU != 9000 {
				t.Fatalf("max_mtu = %d, want 9000", iface.MaxMTU)
			}
			return
		}
	}
	t.Fatalf("expected interface in snapshot, got %d interfaces", len(caps.Interfaces))
}
