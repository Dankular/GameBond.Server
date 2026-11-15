//go:build linux

package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Dankular/GameBond.Server/gateway/layer2"
)

type portAuthTestRunner struct {
	commands         []string
	inputs           [][]byte
	failInput        bool
	addresses        []byte
	setJSON          []byte
	supplicantStatus []byte
}

func (r *portAuthTestRunner) Available(string) bool { return true }
func (r *portAuthTestRunner) Run(_ context.Context, tool string, args ...string) (CommandResult, error) {
	r.commands = append(r.commands, tool+" "+strings.Join(args, " "))
	if tool == "wpa_cli" {
		return CommandResult{Stdout: r.supplicantStatus}, nil
	}
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

func TestPortAuthBrokerMappingRequiresMatchingTapName(t *testing.T) {
	cfg := gatewayPortAuthConfig()
	cfg.PortAuth[0].SegmentID = "venue-a"
	cfg.PortAuth[0].SegmentIdentity = "session-000102030405060708090a0b0c0d0e0f"
	cfg.PortAuth[0].SegmentSocketPath = "/run/gamebond/fabric.sock"
	cfg.PortAuth[0].SegmentAdminTokenFile = "/etc/gamebond/segments/admin.token"
	cfg.PortAuth[0].EAPOLTapName = "enp2s0"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid broker mapping rejected: %v", err)
	}
	cfg.PortAuth[0].EAPOLTapName = "gb-auth0"
	if err := cfg.Validate(); err == nil {
		t.Fatal("broker mapping with a different TAP name was accepted")
	}
}

func TestLoadPortAuthAdminTokenRequiresOwnerOnlyFile(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned token validation requires root")
	}
	path := filepath.Join(t.TempDir(), "admin.token")
	value := strings.Repeat("ab", 32)
	if err := os.WriteFile(path, []byte(value+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	token, err := loadPortAuthAdminToken(path)
	if err != nil || len(token) != 32 || token[0] != 0xab {
		t.Fatalf("valid admin token rejected: len=%d err=%v", len(token), err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPortAuthAdminToken(path); err == nil {
		t.Fatal("group-readable broker admin token accepted")
	}
}

func TestSendPortAuthEventViaGatewayUnixAPI(t *testing.T) {
	path := filepath.Join(t.TempDir(), fmt.Sprintf("api-%d.sock", time.Now().UnixNano()))
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	seen := make(chan string, 1)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/layer2/port-auth/events" || r.Method != http.MethodPost {
			http.Error(w, "unexpected route", http.StatusNotFound)
			return
		}
		data, _ := io.ReadAll(r.Body)
		seen <- string(data)
		w.WriteHeader(http.StatusNoContent)
	})}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()
	if err := SendPortAuthEventViaAPI(context.Background(), path, "enp2s0", "CTRL-EVENT-EAP-SUCCESS", "02:00:00:00:00:01"); err != nil {
		t.Fatal(err)
	}
	select {
	case body := <-seen:
		if !strings.Contains(body, `"event":"CTRL-EVENT-EAP-SUCCESS"`) || strings.Contains(body, "token") || strings.Contains(body, "secret") {
			t.Fatalf("event API payload has wrong fields: %s", body)
		}
	case <-time.After(time.Second):
		t.Fatal("gateway API did not receive event")
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

func TestWiredSupplicantServicesAreOrchestratedAndReported(t *testing.T) {
	cfg := layer2.Config{Version: 1,
		Interfaces:       []layer2.Interface{{ID: "wan", Name: "enp4s0"}},
		WiredSupplicants: []layer2.WiredSupplicant{{Interface: "wan", EAPMethod: "PEAP", Identity: "device-1", PasswordFile: "/etc/gamebond/8021x/supplicants/wan.secret", CAFile: "/etc/ssl/certs/ca.pem"}},
	}
	runner := &portAuthTestRunner{supplicantStatus: []byte("wpa_state=COMPLETED\n")}
	if err := reconcileWiredSupplicantServices(context.Background(), runner, layer2.Config{}, cfg); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 1 || !strings.Contains(runner.commands[0], "restart gamebond-wpa_supplicant@wan.service") {
		t.Fatalf("supplicant service transition = %#v", runner.commands)
	}
	status := snapshotPortAuth(context.Background(), runner, cfg)
	if !status.Enabled || !status.Active || len(status.Ports) != 1 || status.Ports[0].SupplicantServiceActive == nil || !*status.Ports[0].SupplicantServiceActive || status.Ports[0].SupplicantState != "COMPLETED" || status.Ports[0].SupplicantAuthenticated == nil || !*status.Ports[0].SupplicantAuthenticated {
		t.Fatalf("supplicant runtime status = %+v", status)
	}
	runner.commands = nil
	if err := pausePortAuthServices(context.Background(), runner, cfg); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 1 || !strings.Contains(runner.commands[0], "stop gamebond-wpa_supplicant@wan.service") {
		t.Fatalf("supplicant pause = %#v", runner.commands)
	}
}

func TestParseWiredSupplicantStatusDoesNotInferAuthenticationFromProcessState(t *testing.T) {
	state, authenticated, err := parseWiredSupplicantStatus([]byte("wpa_state=ASSOCIATING\n"))
	if err != nil || state != "ASSOCIATING" || authenticated {
		t.Fatalf("associating status = %q authenticated=%v err=%v", state, authenticated, err)
	}
	if _, _, err := parseWiredSupplicantStatus([]byte("wpa_state=COMPLETED\nwpa_state=COMPLETED\n")); err == nil {
		t.Fatal("duplicate EAP state was accepted")
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
