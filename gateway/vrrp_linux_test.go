//go:build linux

package gateway

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

type vrrpTestRunner struct {
	active                bool
	linkJSON, addressJSON []byte
	failTool              string
}

func (r vrrpTestRunner) Available(string) bool { return true }
func (r vrrpTestRunner) Run(_ context.Context, tool string, args ...string) (CommandResult, error) {
	if tool == r.failTool {
		return CommandResult{}, errors.New("provider failed")
	}
	if tool == "systemctl" {
		if r.active {
			return CommandResult{}, nil
		}
		return CommandResult{}, errors.New("inactive")
	}
	if tool == "ip" && strings.Contains(strings.Join(args, " "), "link show") {
		return CommandResult{Stdout: r.linkJSON}, nil
	}
	if tool == "ip" && strings.Contains(strings.Join(args, " "), "addr show") {
		return CommandResult{Stdout: r.addressJSON}, nil
	}
	return CommandResult{}, nil
}

func sampleVRRPConfig() Config {
	return Config{Interfaces: []Interface{{ID: "lan", Name: "br-lan", Role: "lan"}}, VRRP: VRRPConfig{Enabled: true, InterfaceID: "lan", VirtualRouterID: 42, Priority: 100, AdvertisementIntervalSecs: 1, Peers: []string{"192.0.2.2"}, VirtualAddresses: []string{"192.0.2.1/24"}}}
}

func TestVRRPConfigValidatesShadowPeerAndSubnets(t *testing.T) {
	cfg := sampleVRRPConfig()
	if err := cfg.VRRP.Validate(cfg.Interfaces); err != nil {
		t.Fatalf("valid shadow peer rejected: %v", err)
	}
	cfg.VRRP.Priority = 255
	if err := cfg.VRRP.Validate(cfg.Interfaces); err == nil || !strings.Contains(err.Error(), "priority must be 1..254") {
		t.Fatalf("MASTER priority accepted for shadow peer: %v", err)
	}
	cfg = sampleVRRPConfig()
	cfg.VRRP.Peers[0] = "198.51.100.2"
	if err := cfg.VRRP.Validate(cfg.Interfaces); err != nil {
		t.Fatalf("valid unicast peer rejected: %v", err)
	}
	if err := validateVRRPAddressesOnSubnet(cfg.VRRP, netip.MustParsePrefix("192.0.2.0/24")); err == nil || !strings.Contains(err.Error(), "outside interface subnet") {
		t.Fatalf("off-subnet peer accepted: %v", err)
	}
	cfg = sampleVRRPConfig()
	cfg.VRRP.VirtualAddresses[0] = "198.51.100.1/24"
	if err := validateVRRPAddressesOnSubnet(cfg.VRRP, netip.MustParsePrefix("192.0.2.0/24")); err == nil || !strings.Contains(err.Error(), "outside interface subnet") {
		t.Fatalf("off-subnet VIP accepted: %v", err)
	}
}

func TestRenderKeepalivedConfigUsesNonPreemptingShadowSettings(t *testing.T) {
	cfg := sampleVRRPConfig()
	data, err := renderKeepalivedConfig(cfg.VRRP, cfg.Interfaces, "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"state BACKUP", "interface br-lan", "version 3", "virtual_router_id 42", "priority 100", "advert_int 1", "nopreempt", "unicast_src_ip 192.0.2.10", "192.0.2.2", "192.0.2.1/24 dev br-lan"} {
		if !strings.Contains(string(data), expected) {
			t.Errorf("Keepalived config lacks %q:\n%s", expected, data)
		}
	}
}

func TestSnapshotVRRPReportsMasterBackupAndFaultFromVIPOwnership(t *testing.T) {
	cfg := sampleVRRPConfig()
	link := []byte(`[{"flags":["UP"],"operstate":"UP"}]`)
	master := snapshotVRRP(context.Background(), vrrpTestRunner{active: true, linkJSON: link, addressJSON: []byte(`[{"addr_info":[{"local":"192.0.2.1","prefixlen":24}]}]`)}, cfg)
	if master.Role != "MASTER" || len(master.OwnedAddresses) != 1 || master.Error != "" {
		t.Fatalf("MASTER status = %#v", master)
	}
	backup := snapshotVRRP(context.Background(), vrrpTestRunner{active: true, linkJSON: link, addressJSON: []byte(`[{"addr_info":[]}]`)}, cfg)
	if backup.Role != "BACKUP" || backup.Error != "" {
		t.Fatalf("BACKUP status = %#v", backup)
	}
	fault := snapshotVRRP(context.Background(), vrrpTestRunner{active: true, linkJSON: []byte(`[{"flags":["DOWN"],"operstate":"DOWN"}]`)}, cfg)
	if fault.Role != "FAULT" || fault.Error == "" {
		t.Fatalf("FAULT status = %#v", fault)
	}
}
