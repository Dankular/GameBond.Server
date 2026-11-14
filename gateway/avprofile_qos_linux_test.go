//go:build linux

package gateway

import (
	"context"
	"strings"
	"testing"

	"github.com/Dankular/GameBond.Server/gateway/layer2"
)

func TestLinuxApplierAcceptsAdaptiveQoSMatchingSelectedAVProfile(t *testing.T) {
	cfg := adaptiveQSYSConfig()
	if _, err := (LinuxApplier{Runner: adaptiveAVSnapshotRunner{}}).Prepare(context.Background(), cfg, cfg); err != nil {
		t.Fatalf("adaptive QoS satisfying Q-SYS was rejected: %v", err)
	}
}

func TestLinuxApplierRejectsAdaptiveQoSPriorityConflictWithSelectedAVProfile(t *testing.T) {
	cfg := adaptiveQSYSConfig()
	cfg.QoS.Interfaces[0].Classes[0].Priority = 1
	_, err := (LinuxApplier{Runner: adaptiveAVSnapshotRunner{}}).Prepare(context.Background(), cfg, cfg)
	if err == nil || !strings.Contains(err.Error(), "Q-SYS") || !strings.Contains(err.Error(), "DSCP 46") || !strings.Contains(err.Error(), "priority 0") {
		t.Fatalf("adaptive QoS priority conflict was not rejected: %v", err)
	}
}

func adaptiveQSYSConfig() Config {
	return Config{
		Version:    1,
		Interfaces: []Interface{{ID: "lan-main", Name: "enp2s0", Role: "lan"}},
		QoS: QoSConfig{Enabled: true, Interfaces: []QoSInterface{{
			InterfaceID: "lan-main",
			TotalKbit:   1_000_000,
			Classes: []QoSClass{
				{ID: "ptp", DSCP: 46, RateKbit: 100_000, CeilKbit: 1_000_000, Priority: 0},
				{ID: "audio", DSCP: 34, RateKbit: 100_000, CeilKbit: 1_000_000, Priority: 1},
				{ID: "video", DSCP: 26, RateKbit: 100_000, CeilKbit: 1_000_000, Priority: 2},
			},
		}}},
		Layer2: &layer2.Config{
			Version:    1,
			Interfaces: []layer2.Interface{{ID: "access", Name: "enp2s0"}},
			Bridges: []layer2.Bridge{{ID: "main", Name: "br-main", VLANFiltering: true, Ports: []layer2.BridgePort{{
				Interface: "access", UntaggedNetwork: "media",
			}}}},
			Networks:   []layer2.Network{{ID: "media", Bridge: "main", VLAN: 10, MTU: 1500}},
			AVProfiles: []layer2.AVProfileSelection{{Profile: "qsys", Network: "media"}},
		},
	}
}

type adaptiveAVSnapshotRunner struct{}

func (adaptiveAVSnapshotRunner) Available(tool string) bool {
	return tool == "ip" || tool == "bridge" || tool == "tc" || tool == "ethtool"
}

func (adaptiveAVSnapshotRunner) Run(_ context.Context, tool string, args ...string) (CommandResult, error) {
	joined := strings.Join(args, " ")
	switch tool {
	case "ip":
		return CommandResult{Stdout: []byte(`[{"ifname":"br-main","mtu":1500,"flags":["UP"],"linkinfo":{"info_kind":"bridge","info_data":{"vlan_filtering":true}}},{"ifname":"enp2s0","master":"br-main","mtu":1500,"flags":["UP"]}]`)}, nil
	case "tc":
		if strings.Contains(joined, "qdisc show") {
			return CommandResult{Stdout: []byte(`[{"kind":"noqueue","root":true}]`)}, nil
		}
		return CommandResult{Stdout: []byte(`[]`)}, nil
	case "ethtool":
		return CommandResult{Stdout: []byte("Settings for enp2s0:\n\tSpeed: 1000Mb/s\n")}, nil
	case "bridge":
		switch {
		case strings.Contains(joined, "link show"):
			return CommandResult{Stdout: []byte(`[{"ifname":"enp2s0"}]`)}, nil
		case strings.Contains(joined, "mdb show"):
			return CommandResult{Stdout: []byte(`{"mdb":[],"router":{}}`)}, nil
		case strings.Contains(joined, "fdb show"):
			return CommandResult{Stdout: []byte(`[]`)}, nil
		case strings.Contains(joined, "vlan show"):
			return CommandResult{Stdout: []byte(`[{"ifname":"br-main","vlans":[{"vlan":10}]},{"ifname":"enp2s0","vlans":[{"vlan":10,"flags":["PVID","Egress Untagged"]}]}]`)}, nil
		}
	}
	return CommandResult{Stdout: []byte(`[]`)}, nil
}
