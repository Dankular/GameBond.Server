//go:build linux

package gateway

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Dankular/GameBond.Server/gateway/layer2"
)

type lldpMEDSnapshotRunner struct {
	neighborJSON []byte
	neighborErr  error
}

func (lldpMEDSnapshotRunner) Available(string) bool { return true }

func (r lldpMEDSnapshotRunner) Run(_ context.Context, tool string, args ...string) (CommandResult, error) {
	switch {
	case tool == "systemctl" && strings.Contains(strings.Join(args, " "), "is-active"):
		return CommandResult{}, nil
	case tool == "lldpcli" && strings.Contains(strings.Join(args, " "), "show configuration"):
		return CommandResult{Stdout: []byte("configure ports enp2s0 med policy application voice tagged vlan 20\n")}, nil
	case tool == "lldpcli" && strings.Contains(strings.Join(args, " "), "show neighbors"):
		return CommandResult{Stdout: r.neighborJSON}, r.neighborErr
	default:
		return CommandResult{}, errors.New("unexpected command")
	}
}

func TestSnapshotLLDPMEDReportsAdvertisedPolicyAndReceivedNeighbors(t *testing.T) {
	cfg, err := layer2.DecodeConfig([]byte(`{"version":1,"interfaces":[{"id":"lan-a","name":"enp2s0"}],"bridges":[{"id":"main","name":"br-main","vlan_filtering":true,"ports":[{"interface":"lan-a","untagged_network":"users","tagged_networks":["voice"],"voice_network":"voice"}]}],"networks":[{"id":"users","bridge":"main","vlan":10,"mtu":1500},{"id":"voice","bridge":"main","vlan":20,"mtu":1500}]}`))
	if err != nil {
		t.Fatal(err)
	}
	status := snapshotLLDPMED(context.Background(), lldpMEDSnapshotRunner{neighborJSON: []byte(`{"lldp":{"interface":"enp2s0","neighbors":[{"chassis":"switch-1"}]}}`)}, cfg)
	if !status.Enabled || !status.Active || len(status.Advertised) != 1 || status.Advertised[0].Application != "voice" || status.Advertised[0].VLAN != 20 {
		t.Fatalf("advertised policy status = %#v", status)
	}
	if len(status.Ports) != 1 || !strings.Contains(string(status.Ports[0].Neighbors), "switch-1") || status.Ports[0].Error != "" {
		t.Fatalf("received neighbor status = %#v", status.Ports)
	}
}

func TestSnapshotLLDPMEDBoundsUntrustedNeighborOutput(t *testing.T) {
	cfg := layer2.Config{Version: 1, Interfaces: []layer2.Interface{{ID: "lan-a", Name: "enp2s0"}}, Bridges: []layer2.Bridge{{ID: "main", Name: "br-main", Ports: []layer2.BridgePort{{Interface: "lan-a", VoiceNetwork: "voice", TaggedNetworks: []string{"voice"}}}}}, Networks: []layer2.Network{{ID: "voice", Bridge: "main", VLAN: 20, MTU: 1500}}}
	status := snapshotLLDPMED(context.Background(), lldpMEDSnapshotRunner{neighborJSON: []byte("not-json")}, cfg)
	if len(status.Ports) != 1 || !strings.Contains(status.Ports[0].Error, "not valid JSON") || len(status.Ports[0].Neighbors) != 0 {
		t.Fatalf("invalid LLDP input was exposed: %#v", status.Ports)
	}
	large := []byte(`{"neighbors":"` + strings.Repeat("x", 33*1024) + `"}`)
	status = snapshotLLDPMED(context.Background(), lldpMEDSnapshotRunner{neighborJSON: large}, cfg)
	if len(status.Ports) != 1 || !strings.Contains(status.Ports[0].Error, "exceeds 32 KiB") || len(status.Ports[0].Neighbors) != 0 {
		t.Fatalf("oversized LLDP input was exposed: %#v", status.Ports)
	}
}
