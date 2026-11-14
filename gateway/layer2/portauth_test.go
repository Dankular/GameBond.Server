package layer2

import (
	"strings"
	"testing"
)

func portAuthTestConfig() Config {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		panic(err)
	}
	cfg.Overrides = nil
	cfg.PortAuth = []PortAuth{{Interface: "lan-a", RadiusServer: "192.0.2.10", RadiusPort: 1812, SecretFile: "/etc/gamebond/8021x/lan-a.secret", NASAddress: "192.0.2.2", NASID: "gamebond-edge", FailurePolicy: "closed", ExclusivePort: true}}
	return cfg
}

func TestRenderPortAuthTableStartsFailClosedAndPermitsEAPOL(t *testing.T) {
	script, err := RenderPortAuthTable(portAuthTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	text := string(script)
	for _, expected := range []string{
		"add set bridge gamebond_8021x protected_ports { type ifname; elements = { \"enp2s0\" }; }",
		"add set bridge gamebond_8021x authorized_ports { type ifname; }",
		"add set bridge gamebond_8021x authenticated_clients { type ifname . ether_addr; }",
		"ether type 0x888e accept",
		"add chain bridge gamebond_8021x input { type filter hook input priority -300; policy accept; }",
		"add chain bridge gamebond_8021x egress { type filter hook postrouting priority -300; policy accept; }",
		"iifname @protected_ports drop comment \"gamebond-8021x:unauthorized-host\"",
		"iifname . ether saddr @authenticated_clients accept",
		"oifname . ether daddr @authenticated_clients accept comment \"gamebond-8021x:authorized-out\"",
		"oifname @authorized_ports ether daddr & 01:00:00:00:00:00 != 00:00:00:00:00:00 accept comment \"gamebond-8021x:authorized-group-out\"",
		"iifname @protected_ports drop",
		"oifname @protected_ports drop",
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("authorization table missing %q:\n%s", expected, text)
		}
	}
}

func TestRenderPortAuthClientUpdateValidatesInterfaceAndMAC(t *testing.T) {
	cfg := portAuthTestConfig()
	got, err := RenderPortAuthClientUpdate(cfg, "enp2s0", "02:00:00:00:00:10", true)
	if err != nil || string(got) != "add element bridge gamebond_8021x authenticated_clients { \"enp2s0\" . 02:00:00:00:00:10 }\nadd element bridge gamebond_8021x authorized_ports { \"enp2s0\" }\n" {
		t.Fatalf("authorized update = %q, %v", got, err)
	}
	got, err = RenderPortAuthClientUpdate(cfg, "enp2s0", "02:00:00:00:00:10", false)
	if err != nil || string(got) != "delete element bridge gamebond_8021x authenticated_clients { \"enp2s0\" . 02:00:00:00:00:10 }\ndelete element bridge gamebond_8021x authorized_ports { \"enp2s0\" }\n" {
		t.Fatalf("revocation update = %q, %v", got, err)
	}
	if _, err := RenderPortAuthClientUpdate(cfg, "eth99", "02:00:00:00:00:10", true); err == nil {
		t.Fatal("unmanaged interface was allowed to update authorization set")
	}
	if _, err := RenderPortAuthClientUpdate(cfg, "enp2s0", "01:00:00:00:00:01", true); err == nil {
		t.Fatal("multicast station MAC was accepted")
	}
}

func TestRenderPortAuthHostapdConfigUsesWiredRADIUSAndReauthSettings(t *testing.T) {
	cfg := portAuthTestConfig()
	cfg.PortAuth[0].ReauthSeconds = 3600
	got, err := RenderPortAuthHostapdConfig(cfg, "lan-a", "a-safe-radius-secret-123")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"driver=wired", "ieee8021x=1", "use_pae_group_addr=1", "interface=enp2s0",
		"nas_identifier=gamebond-edge", "own_ip_addr=192.0.2.2", "auth_server_addr=192.0.2.10", "auth_server_port=1812",
		"auth_server_shared_secret=a-safe-radius-secret-123", "eap_reauth_period=3600",
	} {
		if !strings.Contains(string(got), expected) {
			t.Errorf("hostapd config missing %q: %s", expected, got)
		}
	}
}

func TestRenderPortAuthHostapdConfigRejectsUnknownPortsAndUnsafeSecrets(t *testing.T) {
	cfg := portAuthTestConfig()
	if _, err := RenderPortAuthHostapdConfig(cfg, "lan-b", "a-safe-radius-secret-123"); err == nil {
		t.Fatal("unknown protected port accepted")
	}
	if _, err := RenderPortAuthHostapdConfig(cfg, "lan-a", "secret with spaces and symbols!@#"); err == nil {
		t.Fatal("hostapd config injection accepted")
	}
}
