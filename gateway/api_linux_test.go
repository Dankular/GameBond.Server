//go:build linux

package gateway

import (
	"context"
	"testing"

	"github.com/Dankular/GameBond.Server/gateway/layer2"
)

func TestValidateLayer2PlanAgainstCurrentRecognizesManagedBridge(t *testing.T) {
	configured := layer2.Config{
		Version: 1,
		Bridges: []layer2.Bridge{{ID: "main", Name: "br-main"}},
	}
	current := Config{Layer2: &configured}
	host := layer2.Capabilities{
		Features: map[string]layer2.FeatureCapability{
			layer2.FeatureBridgeVLAN: {State: layer2.CapabilitySupported},
		},
		Interfaces: []layer2.HostInterface{{
			Name: "br-main", Kind: "bridge", MTU: 1500, AdminUp: true,
		}},
	}

	if err := validateLayer2PlanAgainstCurrent(current, configured, host); err != nil {
		t.Fatalf("validation rejected a bridge already managed by the current config: %v", err)
	}

	if err := validateLayer2PlanAgainstCurrent(Config{}, configured, host); err == nil {
		t.Fatal("validation accepted an existing bridge without current GameBond ownership")
	}
}

type apiSTPValidationRunner struct{}

func (apiSTPValidationRunner) Available(tool string) bool {
	return tool == "ip" || tool == "bridge" || tool == "systemctl"
}

func (apiSTPValidationRunner) Run(_ context.Context, tool string, args ...string) (CommandResult, error) {
	switch tool {
	case "systemctl":
		return CommandResult{Stdout: []byte("inactive\n")}, nil
	case "ip":
		return CommandResult{Stdout: []byte(`[{"ifname":"br-main","mtu":1500,"operstate":"UP","flags":["UP"],"linkinfo":{"info_kind":"bridge","info_data":{"stp_state":1,"vlan_filtering":false}}}]`)}, nil
	case "bridge":
		if len(args) >= 2 && args[1] == "mdb" {
			return CommandResult{Stdout: []byte(`{"mdb":[],"router":{}}`)}, nil
		}
		return CommandResult{Stdout: []byte(`[]`)}, nil
	default:
		return CommandResult{}, nil
	}
}

func TestValidateLayer2PlanAgainstCurrentCanValidateSTPTeardown(t *testing.T) {
	enabled := true
	previousLayer2 := layer2.Config{
		Version: 1,
		Bridges: []layer2.Bridge{{ID: "main", Name: "br-main", STPEnabled: &enabled}},
	}
	desiredLayer2 := layer2.Config{
		Version: 1,
		Bridges: []layer2.Bridge{{ID: "main", Name: "br-main"}},
	}
	current := Config{Layer2: &previousLayer2}

	caps, err := snapshotLayer2ValidationCapabilities(context.Background(), current, desiredLayer2, apiSTPValidationRunner{})
	if err != nil {
		t.Fatalf("snapshot current plus requested config: %v", err)
	}
	if caps.STPControllerDiscovery == nil || !caps.STPControllerDiscovery.Known {
		t.Fatalf("STP ownership was not discovered for teardown: %#v", caps.STPControllerDiscovery)
	}
	if err := validateLayer2PlanAgainstCurrent(current, desiredLayer2, caps); err != nil {
		t.Fatalf("STP teardown failed validation: %v", err)
	}
}
