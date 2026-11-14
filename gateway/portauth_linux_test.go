//go:build linux

package gateway

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Dankular/GameBond.Server/gateway/layer2"
)

type portAuthTestRunner struct {
	commands  []string
	inputs    [][]byte
	failInput bool
	addresses []byte
	setJSON   []byte
}

func (r *portAuthTestRunner) Available(string) bool { return true }
func (r *portAuthTestRunner) Run(_ context.Context, tool string, args ...string) (CommandResult, error) {
	r.commands = append(r.commands, tool+" "+strings.Join(args, " "))
	if tool == "ip" {
		return CommandResult{Stdout: r.addresses}, nil
	}
	if tool == "nft" && strings.Contains(strings.Join(args, " "), "list set") {
		if len(r.setJSON) == 0 {
			return CommandResult{Stdout: []byte(`{"nftables":[{"set":{"family":"bridge","table":"gamebond_8021x","name":"authenticated_clients","elem":[]}}]}`)}, nil
		}
		return CommandResult{Stdout: r.setJSON}, nil
	}
	return CommandResult{Stdout: []byte("loaded\n")}, nil
}
func (r *portAuthTestRunner) RunInput(_ context.Context, tool string, input []byte, args ...string) (CommandResult, error) {
	r.inputs = append(r.inputs, append([]byte(nil), input...))
	if r.failInput {
		return CommandResult{}, errors.New("nft failed")
	}
	return CommandResult{}, nil
}

func gatewayPortAuthConfig() layer2.Config {
	return layer2.Config{Version: 1,
		Interfaces: []layer2.Interface{{ID: "lan-a", Name: "enp2s0"}},
		Bridges:    []layer2.Bridge{{ID: "main", Name: "br-main", VLANFiltering: true, Ports: []layer2.BridgePort{{Interface: "lan-a", UntaggedNetwork: "users"}}}},
		Networks:   []layer2.Network{{ID: "users", Bridge: "main", VLAN: 10, MTU: 1500}},
		PortAuth:   []layer2.PortAuth{{Interface: "lan-a", RadiusServer: "192.0.2.10", RadiusPort: 1812, SecretFile: "/etc/gamebond/8021x/lan-a.secret", NASAddress: "192.0.2.2", NASID: "edge-1", FailurePolicy: "closed", ExclusivePort: true}},
	}
}

func TestHandlePortAuthEventAllowsOnlySuccessfulEAPAndKnownPorts(t *testing.T) {
	cfg := gatewayPortAuthConfig()
	runner := &portAuthTestRunner{}
	if err := HandlePortAuthEvent(context.Background(), runner, cfg, "enp2s0", "CTRL-EVENT-EAP-STARTED", "02:00:00:00:00:01"); err != nil {
		t.Fatal(err)
	}
	if len(runner.inputs) != 0 {
		t.Fatalf("EAP start did not fail closed: %q", runner.inputs)
	}
	if err := HandlePortAuthEvent(context.Background(), runner, cfg, "enp2s0", "CTRL-EVENT-EAP-SUCCESS", "02:00:00:00:00:01"); err != nil {
		t.Fatal(err)
	}
	if len(runner.inputs) != 1 || !strings.Contains(string(runner.inputs[0]), `"enp2s0" . 02:00:00:00:00:01`) || !strings.Contains(string(runner.inputs[0]), `authorized_ports { "enp2s0" }`) {
		t.Fatalf("success update = %q", runner.inputs)
	}
	if err := HandlePortAuthEvent(context.Background(), runner, cfg, "enp9s0", "CTRL-EVENT-EAP-SUCCESS", "02:00:00:00:00:01"); err == nil {
		t.Fatal("unmanaged interface accepted")
	}
}

func TestHandlePortAuthEventRevokesOnFailureAndRejectsInvalidMAC(t *testing.T) {
	runner := &portAuthTestRunner{setJSON: []byte(`{"nftables":[{"set":{"family":"bridge","table":"gamebond_8021x","name":"authenticated_clients","elem":[{"concat":[{"string":"enp2s0"},{"ether_addr":"02:00:00:00:00:02"}]}]}}]}`)}
	cfg := gatewayPortAuthConfig()
	if err := HandlePortAuthEvent(context.Background(), runner, cfg, "enp2s0", "CTRL-EVENT-EAP-FAILURE", "02:00:00:00:00:02"); err != nil {
		t.Fatal(err)
	}
	if len(runner.inputs) != 1 || !strings.Contains(string(runner.inputs[0]), "delete element") || !strings.Contains(string(runner.inputs[0]), "authorized_ports") {
		t.Fatalf("failure update = %q", runner.inputs)
	}
	if err := HandlePortAuthEvent(context.Background(), runner, cfg, "enp2s0", "CTRL-EVENT-EAP-SUCCESS", "not-a-mac"); err == nil {
		t.Fatal("invalid station MAC accepted")
	}
}

func TestHandlePortAuthEventFailsClosedOnSecondStation(t *testing.T) {
	runner := &portAuthTestRunner{setJSON: []byte(`{"nftables":[{"set":{"family":"bridge","table":"gamebond_8021x","name":"authenticated_clients","elem":[{"concat":[{"string":"enp2s0"},{"ether_addr":"02:00:00:00:00:02"}]}]}}]}`)}
	err := HandlePortAuthEvent(context.Background(), runner, gatewayPortAuthConfig(), "enp2s0", "CTRL-EVENT-EAP-SUCCESS", "02:00:00:00:00:03")
	if err == nil || !strings.Contains(err.Error(), "already has an authenticated station") {
		t.Fatalf("second station was not rejected: %v", err)
	}
	if len(runner.inputs) != 1 || !strings.Contains(string(runner.inputs[0]), "delete element") || !strings.Contains(string(runner.inputs[0]), "authorized_ports") {
		t.Fatalf("second station did not revoke the exclusive port: %q", runner.inputs)
	}
}

func TestApplyPortAuthTransitionStartsAuthenticatorAndEventMonitor(t *testing.T) {
	runner := &portAuthTestRunner{}
	if err := reconcilePortAuthServices(context.Background(), runner, layer2.Config{Version: 1}, gatewayPortAuthConfig()); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.commands, "\n")
	if !strings.Contains(joined, "restart gamebond-hostapd@lan-a.service") || !strings.Contains(joined, "restart gamebond-8021x-events@lan-a.service") {
		t.Fatalf("service transition = %s", joined)
	}
}

func TestPausePortAuthStopsEventMonitorBeforeAuthenticator(t *testing.T) {
	runner := &portAuthTestRunner{}
	if err := pausePortAuthServices(context.Background(), runner, gatewayPortAuthConfig()); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 2 || !strings.Contains(runner.commands[0], "stop gamebond-8021x-events@lan-a.service") || !strings.Contains(runner.commands[1], "stop gamebond-hostapd@lan-a.service") {
		t.Fatalf("service pause order = %#v", runner.commands)
	}
}

func TestValidatePortAuthNASAddressMustBelongToManagedBridge(t *testing.T) {
	cfg := gatewayPortAuthConfig()
	runner := &portAuthTestRunner{addresses: []byte(`[{"addr_info":[{"local":"192.0.2.2","prefixlen":24}]}]`)}
	if err := validatePortAuthNASAddresses(context.Background(), runner, cfg); err != nil {
		t.Fatalf("local NAS address rejected: %v", err)
	}
	cfg.PortAuth[0].NASAddress = "192.0.2.3"
	if err := validatePortAuthNASAddresses(context.Background(), runner, cfg); err == nil || !strings.Contains(err.Error(), "not assigned") {
		t.Fatalf("unassigned NAS address accepted: %v", err)
	}
}

func TestParsePortAuthClientsReportsOnlyConfiguredProtectedPorts(t *testing.T) {
	cfg := gatewayPortAuthConfig()
	data := []byte(`{"nftables":[{"set":{"family":"bridge","table":"gamebond_8021x","name":"authenticated_clients","elem":[{"concat":[{"string":"enp2s0"},{"ether_addr":"02:00:00:00:00:02"}]},{"concat":[{"string":"eth9"},{"ether_addr":"02:00:00:00:00:03"}]}]}}]}`)
	clients, err := parsePortAuthClients(data, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(clients["enp2s0"]) != 1 || clients["enp2s0"][0] != "02:00:00:00:00:02" || len(clients["eth9"]) != 0 {
		t.Fatalf("authorization snapshot = %#v", clients)
	}
	if _, err := parsePortAuthClients([]byte(strings.Repeat("x", 128*1024+1)), cfg); err == nil {
		t.Fatal("oversized authorization set accepted")
	}
}

func TestFlushPortAuthClientsRevokesOnlySelectedPort(t *testing.T) {
	cfg := gatewayPortAuthConfig()
	cfg.Interfaces = append(cfg.Interfaces, layer2.Interface{ID: "lan-b", Name: "enp3s0"})
	cfg.Bridges[0].Ports = append(cfg.Bridges[0].Ports, layer2.BridgePort{Interface: "lan-b"})
	cfg.PortAuth = append(cfg.PortAuth, layer2.PortAuth{Interface: "lan-b", RadiusServer: "192.0.2.11", RadiusPort: 1812, SecretFile: "/etc/gamebond/8021x/lan-b.secret", NASAddress: "192.0.2.2", NASID: "edge-2", FailurePolicy: "closed", ExclusivePort: true})
	runner := &portAuthTestRunner{setJSON: []byte(`{"nftables":[{"set":{"family":"bridge","table":"gamebond_8021x","name":"authenticated_clients","elem":[{"concat":[{"string":"enp2s0"},{"ether_addr":"02:00:00:00:00:02"}]},{"concat":[{"string":"enp3s0"},{"ether_addr":"02:00:00:00:00:03"}]}]}}]}`)}
	if err := FlushPortAuthClients(context.Background(), runner, cfg, "lan-a"); err != nil {
		t.Fatal(err)
	}
	if len(runner.inputs) != 1 || !strings.Contains(string(runner.inputs[0]), `"enp2s0" . 02:00:00:00:00:02`) || strings.Contains(string(runner.inputs[0]), "enp3s0") {
		t.Fatalf("port flush affected wrong authorizations: %q", runner.inputs)
	}
	if !strings.Contains(string(runner.inputs[0]), `authorized_ports { "enp2s0" }`) {
		t.Fatalf("port flush left group egress authorized: %q", runner.inputs)
	}
}
