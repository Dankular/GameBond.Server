package edge

import (
	"strings"
	"testing"
	"time"

	"github.com/Dankular/GameBond.Core/bond"
)

func TestAdminSnapshotExposesLayer2MonitorAndCapabilityStatus(t *testing.T) {
	config := Config{L2: &L2Config{
		Enabled: true, SegmentID: "venue-a",
		TunnelPrivateVLAN: &L2PrivateVLANPortConfig{GroupID: 7, Role: "isolated", PrimaryVLAN: 10, SecondaryVLAN: 20},
		ControlPlaneRates: bond.L2ControlPlaneRates{ARP: 100, DHCPv4: 200, BurstSeconds: 2},
		TunnelVLAN:        bond.L2VLANPolicy{AllowedVLANs: []uint16{10, 20}, NativeVLAN: 10}, IPv4SourceGuardTunnel: true, IPv6SourceGuardTunnel: true,
		Bridge:  &L2Bridge{VLANs: []L2BridgeVLAN{{VLANID: 10, Gateway: &L2Bridge{DHCPRelay4: "192.0.2.53:67", DHCPRelayGateway4: "10.0.0.254"}}, {VLANID: 20}}},
		Monitor: &L2MonitorConfig{TapName: "gbmon0", TunnelIngress: true, ExitEgress: true},
	}}
	snapshot := AdminSnapshot(config, map[string]any{
		"l2":         map[string]any{"mirror": map[string]any{"frames": uint64(3)}},
		"mdns_relay": map[string]any{"relay_drops": uint64(2)},
	}, time.Unix(0, 0))
	if got := snapshot["mdns_relay_stats"].(map[string]any)["relay_drops"]; got != uint64(2) {
		t.Fatalf("mDNS relay counters missing from admin snapshot: %#v", snapshot["mdns_relay_stats"])
	}
	configSummary := snapshot["config"].(map[string]any)["layer2"].(map[string]any)
	if configSummary["enabled"] != true || configSummary["segment_id"] != "venue-a" || configSummary["monitor"] != config.L2.Monitor || configSummary["tunnel_private_vlan"] != config.L2.TunnelPrivateVLAN || configSummary["ipv4_source_guard_tunnel"] != true || configSummary["ipv6_source_guard_tunnel"] != true {
		t.Fatalf("Layer 2 configuration missing from admin snapshot: %#v", configSummary)
	}
	if got := len(configSummary["gateway_vlans"].([]int)); got != 2 {
		t.Fatalf("gateway VLAN membership count = %d, want 2", got)
	}
	if got := configSummary["control_plane_rates"].(bond.L2ControlPlaneRates); got != config.L2.ControlPlaneRates {
		t.Fatalf("per-protocol control-plane rates missing from admin snapshot: %#v", configSummary["control_plane_rates"])
	}
	if relays := configSummary["dhcp_relay4"].(map[string]any); relays["10"] == nil {
		t.Fatalf("DHCP relay configuration missing from admin snapshot: %#v", configSummary["dhcp_relay4"])
	}
	capabilities := snapshot["layer2_capabilities"].(map[string]any)
	pvlanReason := capabilities["private_vlan"].(map[string]any)["reason"].(string)
	if !strings.Contains(pvlanReason, "l2.tunnel_private_vlan") || !strings.Contains(pvlanReason, "broker-managed") {
		t.Fatalf("PVLAN capability does not describe standalone and broker configuration: %q", pvlanReason)
	}
	fabricReason := capabilities["segment_fabric"].(map[string]any)["reason"].(string)
	if !strings.Contains(fabricReason, "ESI identity is configured") || !strings.Contains(fabricReason, "partial MC-LAG support") {
		t.Fatalf("segment fabric capability does not describe EVPN-MH support boundary: %q", fabricReason)
	}
	for name, raw := range capabilities {
		capability, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("%s capability has unexpected shape: %#v", name, raw)
		}
		state, _ := capability["state"].(string)
		if state != "implemented" && state != "partial" && state != "unsupported" {
			t.Errorf("%s has invalid capability state %q", name, state)
		}
		if reason, _ := capability["reason"].(string); reason == "" {
			t.Errorf("%s capability has no status reason", name)
		}
	}
	for name, want := range map[string]string{
		"port_mirroring": "partial", "spanning_tree": "partial", "8021x": "partial", "mc_lag": "partial",
		"snmp": "partial", "sflow": "partial", "tacacs_plus": "unsupported", "pim": "unsupported",
		"syslog": "partial", "ntp": "partial", "ra_guard": "partial", "ip_source_guard": "partial",
		"mab": "unsupported", "q_in_q": "partial", "private_vlan": "partial", "mvr": "partial",
		"dhcp_relay": "partial", "dhcpv6_pd": "partial", "copp": "partial", "ztp": "unsupported",
		"vxlan_evpn": "partial", "gateway_bfd": "partial", "ecmp_policy_routing": "partial", "admin_rbac": "unsupported",
		"vrf": "partial", "macsec": "unsupported", "ptp": "unsupported", "isis": "unsupported",
		"rpki": "unsupported", "route_redistribution": "unsupported",
	} {
		got := capabilities[name].(map[string]any)["state"]
		if got != want {
			t.Errorf("%s state = %v, want %s", name, got, want)
		}
	}
}
