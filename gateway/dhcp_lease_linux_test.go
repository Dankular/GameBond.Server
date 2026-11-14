//go:build linux

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Dankular/GameBond.Server/gateway/layer2"
)

type dhcpGuardSyncRunner struct {
	fdb    []byte
	inputs [][]byte
}

func (r *dhcpGuardSyncRunner) Available(string) bool { return true }
func (r *dhcpGuardSyncRunner) Run(_ context.Context, tool string, args ...string) (CommandResult, error) {
	if tool == "bridge" {
		return CommandResult{Stdout: r.fdb}, nil
	}
	if tool == "nft" && strings.Contains(strings.Join(args, " "), "list table") {
		return CommandResult{Stdout: []byte(`{"nftables":[{"table":{"family":"bridge","name":"gamebond_dhcp_guard","comment":"gamebond-dhcp-guard:v1"}}]}`)}, nil
	}
	return CommandResult{}, nil
}
func (r *dhcpGuardSyncRunner) RunInput(_ context.Context, _ string, input []byte, _ ...string) (CommandResult, error) {
	r.inputs = append(r.inputs, append([]byte(nil), input...))
	return CommandResult{}, nil
}

func TestParseKeaLeaseCSVUsesLatestActiveLeaseByAddress(t *testing.T) {
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	csv := "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id\n" +
		"192.0.2.10,001122334455,,3600,2026-11-14 11:00:00,1,0,0,old,0,,\n" +
		"192.0.2.10,aabbccddeeff,,3600,2026-11-14 13:00:00,1,0,0,current,0,,\n" +
		"192.0.2.11,001122334466,,3600,2026-11-14 13:00:00,1,0,0,declined,1,,\n" +
		"192.0.2.12,001122334477,,3600,2026-11-14 11:59:59,1,0,0,expired,0,,\n" +
		"192.0.2.13,001122334488,,3600,2026-11-14 13:00:00,1,0,0,active,0,,\n" +
		"192.0.2.13,001122334488,,3600,2026-11-14 13:00:00,1,0,0,released,3,,\n"
	leases, err := parseKeaLeaseCSV(strings.NewReader(csv), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 1 || leases[0].Address != "192.0.2.10" || leases[0].MAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("active leases = %#v", leases)
	}
}

func TestSyncDHCPGuardBindingsRejectsLearnedFDBAsBindingAuthority(t *testing.T) {
	leasePath := filepath.Join(t.TempDir(), "leases4.csv")
	leaseCSV := "address,hwaddr,expire,state\n192.0.2.10,aabbccddeeff,2026-11-14 13:00:00,0\n"
	if err := os.WriteFile(leasePath, []byte(leaseCSV), 0600); err != nil {
		t.Fatal(err)
	}
	l2cfg := layer2.Config{
		Version:    1,
		Interfaces: []layer2.Interface{{ID: "lan-a", Name: "enp2s0"}},
		Bridges:    []layer2.Bridge{{ID: "main", Name: "br0", Ports: []layer2.BridgePort{{Interface: "lan-a"}}}},
		DHCPGuard:  []layer2.DHCPGuardPort{{Interface: "lan-a", ValidateBindings: true}},
	}
	cfg := Config{DHCP: DHCPConfig{Enabled: true}, Layer2: &l2cfg}
	runner := &dhcpGuardSyncRunner{fdb: []byte(`[{"mac":"aa:bb:cc:dd:ee:ff","dev":"enp2s0","master":"br0"}]`)}
	_, _, err := syncDHCPGuardBindings(context.Background(), runner, cfg, leasePath, time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC))
	if err == nil || !strings.Contains(err.Error(), "authoritative DHCP ingress metadata") {
		t.Fatalf("binding sync error = %v, want authoritative-ingress rejection", err)
	}
	if len(runner.inputs) != 0 {
		t.Fatalf("binding sync updated nftables from learned FDB state: %q", runner.inputs)
	}
}

func TestRuntimePrepareRejectsDHCPBindingGuardWithoutAuthoritativeIngress(t *testing.T) {
	cfg := dhcpBindingGuardConfig()
	runtime := &Runtime{}
	if _, err := runtime.PrepareConfig(cfg); err == nil || !strings.Contains(err.Error(), "authoritative DHCP ingress metadata") {
		t.Fatalf("runtime prepare error = %v, want authoritative-ingress rejection", err)
	}
}

func TestManagerDoesNotCommitUnsupportedDHCPBindingGuard(t *testing.T) {
	initial := Config{Version: 1, SocketPath: "/run/gamebond/control.sock", Telemetry: Telemetry{OutageRetentionDays: 1, OutageMaxBytes: 4096}}
	configPath := filepath.Join(t.TempDir(), "config.json")
	manager, err := NewManager(configPath, initial, LinuxApplier{Runner: &dhcpGuardSyncRunner{}})
	if err != nil {
		t.Fatal(err)
	}
	desired := dhcpBindingGuardConfig()
	err = manager.Apply(context.Background(), desired)
	if err == nil || !strings.Contains(err.Error(), "authoritative DHCP ingress metadata") {
		t.Fatalf("apply error = %v, want authoritative-ingress rejection", err)
	}
	if got := manager.Current(); got.Layer2 != nil || got.DHCP.Enabled {
		t.Fatalf("unsupported binding guard committed config: %#v", got)
	}
	if manager.Status().State != "prepare_failed" {
		t.Fatalf("transaction state = %q, want prepare_failed", manager.Status().State)
	}
	if _, err := os.Stat(configPath); !os.IsNotExist(err) {
		t.Fatalf("rejected binding guard persisted config: %v", err)
	}
}

func dhcpBindingGuardConfig() Config {
	return Config{
		Version:    1,
		SocketPath: "/run/gamebond/control.sock",
		Telemetry:  Telemetry{OutageRetentionDays: 1, OutageMaxBytes: 4096},
		Interfaces: []Interface{{ID: "lan", Name: "br0", Role: "lan"}},
		DHCP: DHCPConfig{Enabled: true, Subnets: []DHCPSubnet{{
			ID: "users", InterfaceID: "lan", Prefix: "192.0.2.0/24",
			PoolStart: "192.0.2.100", PoolEnd: "192.0.2.200", Router: "192.0.2.1",
			DNS: []string{"192.0.2.1"}, LeaseSeconds: 3600,
		}}},
		Layer2: &layer2.Config{
			Version:    1,
			Interfaces: []layer2.Interface{{ID: "lan-a", Name: "enp2s0"}},
			Bridges:    []layer2.Bridge{{ID: "main", Name: "br0", Ports: []layer2.BridgePort{{Interface: "lan-a"}}}},
			DHCPGuard:  []layer2.DHCPGuardPort{{Interface: "lan-a", ValidateBindings: true}},
		},
	}
}

func TestDHCPBindingValidationRequiresManagedDHCP(t *testing.T) {
	cfg := &layer2.Config{DHCPGuard: []layer2.DHCPGuardPort{{Interface: "lan-a", ValidateBindings: true}}}
	if err := validateLayer2DHCPBindings(cfg, false); err == nil {
		t.Fatal("binding validation accepted without managed DHCP")
	}
	if err := validateLayer2DHCPBindings(cfg, true); err != nil {
		t.Fatalf("binding validation rejected with managed DHCP enabled: %v", err)
	}
}

func TestParseKeaLeaseCSVRejectsMalformedRows(t *testing.T) {
	csv := "address,hwaddr,expire,state\n192.0.2.1,not-a-mac,2026-11-14 13:00:00,0\n"
	if _, err := parseKeaLeaseCSV(strings.NewReader(csv), time.Now()); err == nil {
		t.Fatal("malformed lease row accepted")
	}
}

func TestParseKeaLeaseCSVRejectsOversizedInput(t *testing.T) {
	input := "address,hwaddr,expire,state\n" + strings.Repeat("x", 16<<20)
	if _, err := parseKeaLeaseCSV(strings.NewReader(input), time.Now()); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized lease input error = %v", err)
	}
}
