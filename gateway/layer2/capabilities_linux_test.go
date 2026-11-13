//go:build linux

package layer2

import "testing"

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
