package edge

import (
	"encoding/json"
	"testing"

	"github.com/Dankular/GameBond.Core/bond"
)

func configFixture() map[string]any {
	return map[string]any{"role": "server", "session": "000102030405060708090a0b0c0d0e0f", "bind": [][]any{{"0.0.0.0", 4433}}, "client_tunnel_ip": "10.77.0.2", "tun_name": "gamebond0", "mtu": 1280, "bonding_mode": true, "redundant_mode": false, "bulk_rate_mbps": 0}
}
func TestContainerConfigAndPartialQoSRetainDefaults(t *testing.T) {
	input := configFixture()
	input["adaptive_qos"] = map[string]any{"duplicate_mbps": 2}
	data, _ := json.Marshal(input)
	_, options, address, session, err := DecodeConfig(data)
	if err != nil || address.String() != "0.0.0.0:4433" || len(session) != 16 || options.QoS.DuplicateMbps != 2 || options.QoS.CallDeadlineMS != 60 || !options.QoS.Enabled {
		t.Fatal("configuration/defaults changed", err)
	}
	if _, _, _, _, err = DecodeConfig(append(data, []byte("garbage")...)); err == nil {
		t.Fatal("trailing garbage accepted")
	}
}

func TestL2TrunkConfigAddsTagRoomAndValidatesSegmentIdentity(t *testing.T) {
	input := configFixture()
	input["l2"] = map[string]any{
		"enabled": true, "frame_mtu": 1400, "segment_id": "venue-1",
		"tunnel_vlan": map[string]any{"allowed_vlans": []int{10, 20}, "native_vlan": 10},
	}
	_, options, _, _, err := DecodeConfig(mustJSON(input))
	if err != nil || options.L2FrameMTU != 1404 {
		t.Fatalf("trunk frame limit did not include tag bytes: mtu=%d err=%v", options.L2FrameMTU, err)
	}
	input["l2"].(map[string]any)["segment_id"] = "bad segment id"
	if _, _, _, _, err := DecodeConfig(mustJSON(input)); err == nil {
		t.Fatal("invalid segment identity accepted")
	}
}

func TestQinQFrameMTUReservesEightBytesAndCustomerAccessStripsTags(t *testing.T) {
	input := configFixture()
	input["l2"] = map[string]any{
		"enabled": true, "frame_mtu": 1400,
		"tunnel_vlan": map[string]any{"service_vlan": 100, "allowed_customer_vlans": []int{10, 20}},
	}
	_, options, _, _, err := DecodeConfig(mustJSON(input))
	if err != nil || options.L2FrameMTU != 1408 {
		t.Fatalf("Q-in-Q service trunk needs eight bytes of frame room: mtu=%d err=%v", options.L2FrameMTU, err)
	}
	access := configFixture()
	access["l2"] = map[string]any{
		"enabled": true, "frame_mtu": 1400,
		"tunnel_vlan": map[string]any{"service_vlan": 100, "customer_vlan": 10},
	}
	_, accessOptions, _, _, err := DecodeConfig(mustJSON(access))
	if err != nil || accessOptions.L2FrameMTU != 1400 {
		t.Fatalf("Q-in-Q customer access egress should strip both tags: mtu=%d err=%v", accessOptions.L2FrameMTU, err)
	}
}

func TestStandalonePVLANConfigMapsTunnelAndGatewayPorts(t *testing.T) {
	input := configFixture()
	input["l2"] = map[string]any{
		"enabled":     true,
		"tunnel_vlan": map[string]any{"access_vlan": 20},
		"exit_vlan":   map[string]any{"access_vlan": 10},
		"tunnel_private_vlan": map[string]any{
			"group_id": 7, "role": "isolated", "primary_vlan": 10, "secondary_vlan": 20,
		},
		"bridge": map[string]any{
			"address": "10.78.0.1/24", "dhcp_start": "10.78.0.100", "dhcp_end": "10.78.0.110", "private_vlan": 7,
		},
	}
	config, _, _, _, err := DecodeConfig(mustJSON(input))
	if err != nil {
		t.Fatalf("standalone isolated tunnel and promiscuous gateway config rejected: %v", err)
	}
	if config.L2.TunnelPrivateVLAN == nil || config.L2.TunnelPrivateVLAN.Role != "isolated" || config.L2.Bridge.PrivateVLAN != 7 {
		t.Fatalf("standalone PVLAN config was not retained: %+v", config.L2)
	}

	// A PVLAN declaration without the promiscuous primary port would strand
	// the secondary VLAN. The validator must reject it before opening TAPs.
	delete(input["l2"].(map[string]any), "bridge")
	if _, _, _, _, err := DecodeConfig(mustJSON(input)); err == nil {
		t.Fatal("standalone PVLAN without a promiscuous primary port was accepted")
	}

	input["l2"].(map[string]any)["bridge"] = map[string]any{
		"address": "10.78.0.1/24", "dhcp_start": "10.78.0.100", "dhcp_end": "10.78.0.110", "private_vlan": 7,
	}
	input["l2"].(map[string]any)["exit_private_vlan"] = map[string]any{
		"group_id": 7, "role": "isolated", "primary_vlan": 10, "secondary_vlan": 30,
	}
	if _, _, _, _, err := DecodeConfig(mustJSON(input)); err == nil {
		t.Fatal("gateway PVLAN override with a conflicting exit role was accepted")
	}
}

func TestRSTPConfigValidatesTimersPriorityAndGuardConflict(t *testing.T) {
	input := configFixture()
	input["l2"] = map[string]any{
		"enabled": true,
		"rstp":    map[string]any{"bridge_priority": 0, "bridge_mac": "02:00:00:00:00:01", "hello_time_seconds": 2, "max_age_seconds": 20, "forward_delay_seconds": 15},
	}
	if _, _, _, _, err := DecodeConfig(mustJSON(input)); err != nil {
		t.Fatalf("valid RSTP configuration rejected: %v", err)
	}
	for name, row := range map[string]map[string]any{
		"priority": {"bridge_priority": 1},
		"timers":   {"hello_time_seconds": 10, "max_age_seconds": 6, "forward_delay_seconds": 4},
		"mac":      {"bridge_mac": "01:00:00:00:00:01"},
	} {
		input["l2"].(map[string]any)["rstp"] = row
		if _, _, _, _, err := DecodeConfig(mustJSON(input)); err == nil {
			t.Errorf("invalid RSTP %s configuration accepted", name)
		}
	}
	input["l2"].(map[string]any)["rstp"] = map[string]any{}
	input["l2"].(map[string]any)["bpdu_guard_tunnel"] = true
	if _, _, _, _, err := DecodeConfig(mustJSON(input)); err == nil {
		t.Fatal("RSTP and BPDU guard on the same tunnel port were accepted")
	}
}

func TestGatewayMTUSubtractsQinQAndSingleTagOverhead(t *testing.T) {
	qinq := &L2Config{FrameMTU: 1408, TunnelVLAN: bond.L2VLANPolicy{ServiceVLAN: 100, AllowedCustomerVLANs: []uint16{10}}}
	if got := gatewayStackMTU(qinq); got != 1386 {
		t.Fatalf("Q-in-Q gateway stack MTU=%d, want 1386", got)
	}
	exitQinQ := &L2Config{FrameMTU: 1408, ExitVLAN: bond.L2VLANPolicy{ServiceVLAN: 100, AllowedCustomerVLANs: []uint16{10}}}
	if got := gatewayStackMTU(exitQinQ); got != 1386 {
		t.Fatalf("Q-in-Q exit stack MTU=%d, want 1386", got)
	}
	access := &L2Config{FrameMTU: 1400, TunnelVLAN: bond.L2VLANPolicy{ServiceVLAN: 100, CustomerVLAN: 10}}
	if got := gatewayStackMTU(access); got != 1386 {
		t.Fatalf("customer-access gateway stack MTU=%d, want 1386", got)
	}
	trunk := &L2Config{FrameMTU: 1404, TunnelVLAN: bond.L2VLANPolicy{AllowedVLANs: []uint16{10}}}
	if got := gatewayStackMTU(trunk); got != 1386 {
		t.Fatalf("802.1Q gateway stack MTU=%d, want 1386", got)
	}
	broker := &L2Config{FrameMTU: 1402, SegmentSocketPath: "/run/fabric.sock"}
	if got := gatewayStackMTU(broker); got != 1380 {
		t.Fatalf("broker gateway stack MTU=%d, want 1380 after worst-case Q-in-Q reservation", got)
	}
}

func TestMVRConfigMapsGroupsBetweenConfiguredVLANs(t *testing.T) {
	input := configFixture()
	input["l2"] = map[string]any{
		"enabled":     true,
		"tunnel_vlan": map[string]any{"allowed_vlans": []any{10, 20}},
		"exit_vlan":   map[string]any{"access_vlan": 100},
		"mvr":         map[string]any{"multicast_vlan": 100, "groups": []any{map[string]any{"group": "239.3.3.3", "receiver_vlans": []any{10, 20}}}},
		"bridge":      map[string]any{"address": "10.78.0.1/24", "dhcp_start": "10.78.0.100", "dhcp_end": "10.78.0.110"},
	}
	if _, _, _, _, err := DecodeConfig(mustJSON(input)); err != nil {
		t.Fatalf("valid MVR config rejected: %v", err)
	}
	for _, group := range []string{"224.0.0.251", "192.0.2.10", "ff02::fb"} {
		input["l2"].(map[string]any)["mvr"] = map[string]any{"multicast_vlan": 100, "groups": []any{map[string]any{"group": group, "receiver_vlan": 10}}}
		if _, _, _, _, err := DecodeConfig(mustJSON(input)); err == nil {
			t.Errorf("invalid/link-local MVR group %q accepted", group)
		}
	}
	input["l2"].(map[string]any)["mvr"] = map[string]any{"multicast_vlan": 100, "groups": []any{map[string]any{"group": "239.3.3.3", "receiver_vlans": []any{10, 30}}}}
	if _, _, _, _, err := DecodeConfig(mustJSON(input)); err == nil {
		t.Fatal("MVR receiver VLAN without a configured port was accepted")
	}
}

func TestSegmentAdminTokenFileRequiresBrokerMode(t *testing.T) {
	input := configFixture()
	input["l2"] = map[string]any{
		"enabled": true, "segment_id": "venue-1", "segment_socket_path": "/run/gamebond/fabric.sock",
		"segment_members_file": "/run/gamebond/members.json", "segment_admin_token_file": "/run/gamebond/admin.token",
		"bridge": map[string]any{"address": "10.78.0.1/24", "dhcp_start": "10.78.0.100", "dhcp_end": "10.78.0.110"},
	}
	if _, _, _, _, err := DecodeConfig(mustJSON(input)); err != nil {
		t.Fatalf("valid broker admin token config rejected: %v", err)
	}
	input["l2"].(map[string]any)["segment_socket_path"] = ""
	if _, _, _, _, err := DecodeConfig(mustJSON(input)); err == nil {
		t.Fatal("admin token without a broker socket was accepted")
	}
}

func TestControlPlanePolicingRequiresGatewayAndValidRate(t *testing.T) {
	input := configFixture()
	input["l2"] = map[string]any{
		"enabled": true, "control_plane_pps": 100,
		"control_plane_rates": map[string]any{"arp_pps": 20, "dhcpv4_pps": 100, "neighbor_discovery_pps": 50, "burst_seconds": 2},
		"bridge":              map[string]any{"address": "10.78.0.1/24", "dhcp_start": "10.78.0.100", "dhcp_end": "10.78.0.110"},
	}
	if _, _, _, _, err := DecodeConfig(mustJSON(input)); err != nil {
		t.Fatalf("valid control-plane rate rejected: %v", err)
	}
	delete(input["l2"].(map[string]any), "bridge")
	if _, _, _, _, err := DecodeConfig(mustJSON(input)); err == nil {
		t.Fatal("control-plane policing without a gVisor gateway was accepted")
	}
	for _, rate := range []float64{-1, 0.5, 1000001} {
		input["l2"].(map[string]any)["bridge"] = map[string]any{"address": "10.78.0.1/24", "dhcp_start": "10.78.0.100", "dhcp_end": "10.78.0.110"}
		input["l2"].(map[string]any)["control_plane_pps"] = rate
		if _, _, _, _, err := DecodeConfig(mustJSON(input)); err == nil {
			t.Fatalf("invalid control-plane rate %v was accepted", rate)
		}
	}
	for name, rates := range map[string]map[string]any{
		"negative":           {"arp_pps": -1},
		"too high":           {"dhcpv6_pps": 1000001},
		"fractional":         {"lldp_pps": 0.5},
		"burst without rate": {"burst_seconds": 2},
		"short burst":        {"arp_pps": 10, "burst_seconds": 0.5},
	} {
		input["l2"].(map[string]any)["bridge"] = map[string]any{"address": "10.78.0.1/24", "dhcp_start": "10.78.0.100", "dhcp_end": "10.78.0.110"}
		input["l2"].(map[string]any)["control_plane_rates"] = rates
		if _, _, _, _, err := DecodeConfig(mustJSON(input)); err == nil {
			t.Errorf("invalid control-plane class rates %q were accepted", name)
		}
	}
}

func TestDHCPv4RelayConfigUsesUpstreamInsteadOfLocalPool(t *testing.T) {
	input := configFixture()
	input["l2"] = map[string]any{
		"enabled": true,
		"bridge":  map[string]any{"address": "10.78.0.1/24", "dhcp_relay4": "10.78.0.53:67"},
	}
	if _, _, _, _, err := DecodeConfig(mustJSON(input)); err != nil {
		t.Fatalf("valid DHCPv4 relay config rejected: %v", err)
	}
	for _, relay := range []string{"192.0.2.53", "0.0.0.0:67", "224.0.0.1:67", "10.78.0.53:0", "[2001:db8::1]:67"} {
		input["l2"].(map[string]any)["bridge"] = map[string]any{"address": "10.78.0.1/24", "dhcp_relay4": relay}
		if _, _, _, _, err := DecodeConfig(mustJSON(input)); err == nil {
			t.Errorf("invalid DHCPv4 relay target %q was accepted", relay)
		}
	}
	input["l2"].(map[string]any)["bridge"] = map[string]any{
		"address": "10.78.0.1/24", "dhcp_relay4": "10.78.0.53:67", "dhcp_start": "10.78.0.100", "dhcp_end": "10.78.0.110",
	}
	if _, _, _, _, err := DecodeConfig(mustJSON(input)); err == nil {
		t.Fatal("DHCP relay and local DHCPv4 pool were both accepted")
	}
	input["l2"].(map[string]any)["bridge"] = map[string]any{"address": "10.78.0.1/24", "dhcp_relay4": "192.0.2.53:67"}
	if _, _, _, _, err := DecodeConfig(mustJSON(input)); err == nil {
		t.Fatal("off-subnet DHCP relay without a next hop was accepted")
	}
	input["l2"].(map[string]any)["bridge"] = map[string]any{
		"address": "10.78.0.1/24", "dhcp_relay4": "192.0.2.53:67", "dhcp_relay_gateway4": "10.78.0.254",
	}
	if _, _, _, _, err := DecodeConfig(mustJSON(input)); err != nil {
		t.Fatalf("off-subnet relay with on-link next hop rejected: %v", err)
	}
}

func TestGatewayVLANsMapToIndependentDHCPPools(t *testing.T) {
	input := configFixture()
	input["l2"] = map[string]any{
		"enabled": true, "segment_id": "venue-a", "frame_mtu": 1394,
		"tunnel_vlan": map[string]any{"allowed_vlans": []int{10, 20}},
		"bridge": map[string]any{"vlans": []any{
			map[string]any{"vlan_id": 10, "gateway": map[string]any{"address": "10.78.0.1/24", "dhcp_start": "10.78.0.100", "dhcp_end": "10.78.0.110"}},
			map[string]any{"vlan_id": 20, "gateway": map[string]any{"address": "10.79.0.1/24", "dhcp_start": "10.79.0.100", "dhcp_end": "10.79.0.110"}},
		}},
	}
	c, options, _, _, err := DecodeConfig(mustJSON(input))
	if err != nil || options.L2FrameMTU != 1398 || len(c.L2.Bridge.VLANs) != 2 {
		t.Fatalf("valid VLAN gateway mapping rejected: options=%+v config=%+v err=%v", options, c.L2, err)
	}
	input["l2"].(map[string]any)["ra_guard_exit"] = true
	if _, _, _, _, err := DecodeConfig(mustJSON(input)); err == nil {
		t.Fatal("RA Guard was allowed on the trusted gateway service port")
	}
	delete(input["l2"].(map[string]any), "ra_guard_exit")
	input["l2"].(map[string]any)["tunnel_vlan"] = map[string]any{"allowed_vlans": []int{10}}
	if _, _, _, _, err := DecodeConfig(mustJSON(input)); err == nil {
		t.Fatal("gateway VLAN missing from tunnel trunk was accepted")
	}
	input = configFixture()
	input["l2"] = map[string]any{
		"enabled": true, "segment_id": "venue-a", "frame_mtu": 1394,
		"tunnel_vlan": map[string]any{"allowed_vlans": []int{10}},
		"bridge": map[string]any{"vlans": []any{
			map[string]any{"vlan_id": 10, "gateway": map[string]any{"address": "10.78.0.1/24", "dhcp_start": "10.78.0.100", "dhcp_end": "10.78.0.110"}},
			map[string]any{"vlan_id": 10, "gateway": map[string]any{"address": "10.79.0.1/24", "dhcp_start": "10.79.0.100", "dhcp_end": "10.79.0.110"}},
		}},
	}
	if _, _, _, _, err := DecodeConfig(mustJSON(input)); err == nil {
		t.Fatal("duplicate gateway VLAN was accepted")
	}
}

func TestDHCPv6ReservationsRequireUniqueDUIDIAIDAndInPrefixAddress(t *testing.T) {
	input := configFixture()
	input["l2"] = map[string]any{"enabled": true, "bridge": map[string]any{
		"ipv6_address": "fd78:78::1/64", "dhcp_start": "10.78.0.100", "dhcp_end": "10.78.0.110",
		"hosts6": []any{map[string]any{"client_id_hex": "000301020304", "iaid": 7, "mac": "02:09:08:07:06:05", "ip": "fd78:78::20", "name": "console-6"}},
	}}
	if _, _, _, _, err := DecodeConfig(mustJSON(input)); err != nil {
		t.Fatalf("valid DHCPv6 reservation rejected: %v", err)
	}
	bridge := input["l2"].(map[string]any)["bridge"].(map[string]any)
	bridge["hosts6"] = []any{
		map[string]any{"client_id_hex": "000301020304", "iaid": 7, "mac": "02:09:08:07:06:05", "ip": "fd78:78::20", "name": "console-6"},
		map[string]any{"client_id_hex": "000301020304", "iaid": 7, "mac": "02:09:08:07:06:06", "ip": "fd78:78::21", "name": "console-7"},
	}
	if _, _, _, _, err := DecodeConfig(mustJSON(input)); err == nil {
		t.Fatal("duplicate DUID and IAID reservation accepted")
	}
	bridge["hosts6"] = []any{map[string]any{"client_id_hex": "000301020304", "iaid": 7, "mac": "02:09:08:07:06:05", "ip": "2001:db8::20", "name": "console-6"}}
	if _, _, _, _, err := DecodeConfig(mustJSON(input)); err == nil {
		t.Fatal("out-of-prefix DHCPv6 reservation accepted")
	}
}

func TestLLDPMEDPolicyMustMatchConfiguredGatewayVLAN(t *testing.T) {
	input := configFixture()
	input["l2"] = map[string]any{
		"enabled": true, "segment_id": "venue-a", "frame_mtu": 1394,
		"tunnel_vlan": map[string]any{"allowed_vlans": []int{10, 20}},
		"bridge": map[string]any{"vlans": []any{
			map[string]any{"vlan_id": 10, "lldp_med_policy": map[string]any{"vlan_id": 10, "application_type": 1, "tagged": true, "l2_priority": 5, "dscp": 46},
				"gateway": map[string]any{"address": "10.78.0.1/24", "dhcp_start": "10.78.0.100", "dhcp_end": "10.78.0.110"}},
			map[string]any{"vlan_id": 20, "gateway": map[string]any{"address": "10.79.0.1/24", "dhcp_start": "10.79.0.100", "dhcp_end": "10.79.0.110"}},
		}},
	}
	if _, _, _, _, err := DecodeConfig(mustJSON(input)); err != nil {
		t.Fatalf("valid VLAN-bound LLDP-MED policy rejected: %v", err)
	}
	input["l2"].(map[string]any)["bridge"].(map[string]any)["vlans"].([]any)[0].(map[string]any)["lldp_med_policy"].(map[string]any)["vlan_id"] = 20
	if _, _, _, _, err := DecodeConfig(mustJSON(input)); err == nil {
		t.Fatal("LLDP-MED policy for another VLAN was accepted")
	}

	input = configFixture()
	input["l2"] = map[string]any{
		"enabled": true, "tunnel_vlan": map[string]any{"access_vlan": 10}, "exit_vlan": map[string]any{"access_vlan": 10},
		"bridge": map[string]any{"dhcp_start": "10.78.0.100", "dhcp_end": "10.78.0.110",
			"lldp_med_policy": map[string]any{"vlan_id": 10, "application_type": 1}},
	}
	if _, _, _, _, err := DecodeConfig(mustJSON(input)); err != nil {
		t.Fatalf("valid single access VLAN LLDP-MED policy rejected: %v", err)
	}
	delete(input["l2"].(map[string]any), "exit_vlan")
	if _, _, _, _, err := DecodeConfig(mustJSON(input)); err == nil {
		t.Fatal("LLDP-MED policy without explicit VLAN membership was accepted")
	}
}

func TestSegmentSocketConfigRequiresRoleSpecificSecretFile(t *testing.T) {
	decode := func(l2 map[string]any) error {
		input := configFixture()
		input["l2"] = l2
		data, _ := json.Marshal(input)
		_, _, _, _, err := DecodeConfig(data)
		return err
	}
	base := map[string]any{"enabled": true, "segment_id": "venue-a", "segment_socket_path": "/run/gamebond-segment/fabric.sock"}
	bridge := map[string]any{"dhcp_start": "10.78.0.100", "dhcp_end": "10.78.0.149"}
	broker := map[string]any{}
	for key, value := range base {
		broker[key] = value
	}
	broker["bridge"] = bridge
	broker["segment_members_file"] = "/run/secrets/segment-members.json"
	if err := decode(broker); err != nil {
		t.Fatalf("valid broker config rejected: %v", err)
	}
	remote := map[string]any{}
	for key, value := range base {
		remote[key] = value
	}
	remote["segment_token_file"] = "/run/secrets/segment-token"
	if err := decode(remote); err != nil {
		t.Fatalf("valid remote config rejected: %v", err)
	}
	remoteInput := configFixture()
	remoteInput["l2"] = remote
	_, remoteOptions, _, _, err := DecodeConfig(mustJSON(remoteInput))
	if err != nil || remoteOptions.L2FrameMTU != 1402 {
		t.Fatalf("remote segment did not reserve tag room for broker-owned trunks: MTU=%d err=%v", remoteOptions.L2FrameMTU, err)
	}
	brokerInput := configFixture()
	brokerInput["l2"] = broker
	_, brokerOptions, _, _, err := DecodeConfig(mustJSON(brokerInput))
	if err != nil || brokerOptions.L2FrameMTU != 1402 {
		t.Fatalf("broker segment did not reserve tag room for member Q-in-Q: MTU=%d err=%v", brokerOptions.L2FrameMTU, err)
	}
	for name, bad := range map[string]map[string]any{
		"broker lacks members file": {"enabled": true, "segment_id": "venue-a", "segment_socket_path": "/run/fabric.sock", "bridge": bridge},
		"remote lacks token":        {"enabled": true, "segment_id": "venue-a", "segment_socket_path": "/run/fabric.sock"},
		"remote defines gateway":    {"enabled": true, "segment_id": "venue-a", "segment_socket_path": "/run/fabric.sock", "segment_token_file": "/run/token", "bridge": bridge},
		"relative members file":     {"enabled": true, "segment_id": "venue-a", "segment_socket_path": "/run/fabric.sock", "segment_members_file": "members.json", "bridge": bridge},
		"socket missing":            {"enabled": true, "segment_id": "venue-a", "segment_token_file": "/run/token"},
	} {
		if err := decode(bad); err == nil {
			t.Errorf("accepted %s", name)
		}
	}
}

func TestMDNSRelayRequiresExplicitMutualVLANPairs(t *testing.T) {
	input := configFixture()
	input["l2"] = map[string]any{
		"enabled": true, "segment_id": "venue-a", "frame_mtu": 1394,
		"tunnel_vlan": map[string]any{"allowed_vlans": []int{10, 20}},
		"bridge": map[string]any{"vlans": []any{
			map[string]any{"vlan_id": 10, "mdns_relay_to": []int{20}, "gateway": map[string]any{"address": "10.78.0.1/24", "dhcp_start": "10.78.0.100", "dhcp_end": "10.78.0.110"}},
			map[string]any{"vlan_id": 20, "mdns_relay_to": []int{10}, "gateway": map[string]any{"address": "10.79.0.1/24", "dhcp_start": "10.79.0.100", "dhcp_end": "10.79.0.110"}},
		}},
	}
	if _, _, _, _, err := DecodeConfig(mustJSON(input)); err != nil {
		t.Fatalf("explicit mutual relay pair rejected: %v", err)
	}
	vlans := input["l2"].(map[string]any)["bridge"].(map[string]any)["vlans"].([]any)
	vlans[1].(map[string]any)["mdns_relay_to"] = []int{}
	if _, _, _, _, err := DecodeConfig(mustJSON(input)); err == nil {
		t.Fatal("one-way relay policy was accepted")
	}
	vlans[0].(map[string]any)["mdns_relay_to"] = []int{30}
	if _, _, _, _, err := DecodeConfig(mustJSON(input)); err == nil {
		t.Fatal("relay to an unconfigured VLAN was accepted")
	}
}

func TestUnsupportedOrUnsafeTopologyFailsBeforeOpeningDevices(t *testing.T) {
	for key, value := range map[string]any{"role": "client", "session": "bad", "bind": [][]any{{"0.0.0.0", 53}}, "client_tunnel_ip": "10.77.0.3", "tun_name": "eth0", "mtu": 1500, "bonding_mode": false, "bulk_rate_mbps": 1, "stream_relays": []any{}} {
		input := configFixture()
		input[key] = value
		data, _ := json.Marshal(input)
		if _, _, _, _, err := DecodeConfig(data); err == nil {
			t.Fatal("unsupported topology accepted", key)
		}
	}
}

func TestAdminBlockIsValidatedAtLoad(t *testing.T) {
	good := map[string]any{"enabled": true, "bind": []any{"127.0.0.1", 8443}, "password_hash": "scrypt$32768$c2FsdA==$ZGlnZXN0"}
	for name, c := range map[string]struct {
		admin any
		ok    bool
	}{"valid": {good, true}, "absent-ok": {nil, true}, "bad port": {map[string]any{"enabled": true, "bind": []any{"127.0.0.1", 0}, "password_hash": good["password_hash"]}, false},
		"bad hash": {map[string]any{"enabled": true, "bind": []any{"127.0.0.1", 8443}, "password_hash": "x"}, false}} {
		input := configFixture()
		if c.admin != nil {
			input["admin"] = c.admin
		}
		data, _ := json.Marshal(input)
		_, _, _, _, err := DecodeConfig(data)
		if (err == nil) != c.ok {
			t.Fatal(name, "ok =", c.ok, "err =", err)
		}
	}
}

func TestOptionalTransportFlagsReachSessionOptions(t *testing.T) {
	input := configFixture()
	input["failover_replay"], input["loss_tracking"], input["path_mtu_discovery"] = true, true, true
	data, _ := json.Marshal(input)
	_, o, _, _, err := DecodeConfig(data)
	if err != nil || !o.FailoverReplay || !o.LossTracking || !o.PathMTUDiscovery {
		t.Fatal("flags not applied", err, o)
	}
	_, o, _, _, err = DecodeConfig(mustJSON(configFixture()))
	if err != nil || o.FailoverReplay || o.LossTracking || o.PathMTUDiscovery {
		t.Fatal("flags must default off", err)
	}
	input["failover_replay"] = "yes"
	if _, _, _, _, err = DecodeConfig(mustJSON(input)); err == nil {
		t.Fatal("non-boolean accepted")
	}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func TestLanTunnelIPsAreValidatedAndPassedToTheSession(t *testing.T) {
	decode := func(v any) ([]string, error) {
		input := configFixture()
		input["lan_tunnel_ips"] = v
		data, _ := json.Marshal(input)
		_, options, _, _, err := DecodeConfig(data)
		var out []string
		for _, ip := range options.DeviceIPs {
			out = append(out, ip.String())
		}
		return out, err
	}
	if got, err := decode([]string{"10.77.0.3", "10.77.0.254"}); err != nil || len(got) != 2 || got[0] != "10.77.0.3" {
		t.Fatal("valid device addresses rejected", got, err)
	}
	for _, bad := range []any{[]string{"10.77.0.2"}, []string{"10.77.0.1"}, []string{"10.77.0.255"}, []string{"10.77.1.3"}, []string{"192.168.1.5"}, []string{"10.77.0.3", "10.77.0.3"}, []string{"nope"}, []string{"::1"}} {
		if _, err := decode(bad); err == nil {
			t.Fatal("bad lan_tunnel_ips accepted", bad)
		}
	}
}

func TestSecurityBlockIsValidatedAtLoad(t *testing.T) {
	for name, c := range map[string]struct {
		security any
		ok       bool
	}{
		"absent ok":       {nil, true},
		"valid":           {map[string]any{"ids": map[string]any{"mode": "detect"}, "dns_filter": map[string]any{"enabled": true, "categories": []string{"ads"}}}, true},
		"unknown section": {map[string]any{"antivirus": map[string]any{}}, false},
		"bad mode":        {map[string]any{"ids": map[string]any{"mode": "loud"}}, false},
		"force dns alone": {map[string]any{"firewall": map[string]any{"force_dns": true}}, false},
	} {
		input := configFixture()
		if c.security != nil {
			input["security"] = c.security
		}
		data, _ := json.Marshal(input)
		_, _, _, _, err := DecodeConfig(data)
		if (err == nil) != c.ok {
			t.Fatal(name, "ok =", c.ok, "err =", err)
		}
	}
}

func TestL2SectionIsOptInValidatedAndReachesSessionOptions(t *testing.T) {
	decode := func(l2 any) (Config, bool, int, error) {
		input := configFixture()
		if l2 != nil {
			input["l2"] = l2
		}
		data, _ := json.Marshal(input)
		c, options, _, _, err := DecodeConfig(data)
		return c, options.L2, options.L2FrameMTU, err
	}
	if _, on, _, err := decode(nil); err != nil || on {
		t.Fatal("L2 must be off unless configured", err, on)
	}
	if _, on, _, err := decode(map[string]any{"enabled": false}); err != nil || on {
		t.Fatal("disabled L2 section must stay off", err, on)
	}
	c, on, mtu, err := decode(map[string]any{"enabled": true, "mac_limit": 8, "broadcast_pps": 200})
	if err != nil || !on || mtu != 1394 || c.L2.TapName != "gamebond-tap0" {
		t.Fatal("defaults not applied", err, on, mtu)
	}
	for name, bad := range map[string]map[string]any{
		"mtu low":   {"enabled": true, "frame_mtu": 100},
		"mtu high":  {"enabled": true, "frame_mtu": 9000},
		"long name": {"enabled": true, "tap_name": "this-name-is-too-long"},
		"negative":  {"enabled": true, "broadcast_pps": -1},
		"unknown":   {"enabled": true, "vlan": 10},
	} {
		if _, _, _, err := decode(bad); err == nil {
			t.Fatal("accepted", name)
		}
	}
}

func TestL2BridgeSectionIsValidatedAndDefaulted(t *testing.T) {
	decode := func(bridge map[string]any) (Config, error) {
		input := configFixture()
		input["l2"] = map[string]any{"enabled": true, "bridge": bridge}
		data, _ := json.Marshal(input)
		c, _, _, _, err := DecodeConfig(data)
		return c, err
	}
	c, err := decode(map[string]any{"dhcp_start": "10.78.0.100", "dhcp_end": "10.78.0.149",
		"hosts": []map[string]any{{"mac": "AA:BB:CC:00:11:22", "ip": "10.78.0.20", "name": "ps5"}}})
	if err != nil {
		t.Fatal(err)
	}
	b := c.L2.Bridge
	if b.Address != "10.78.0.1/24" || b.Lease != "12h" || len(b.DNS) != 2 || b.Hosts[0].MAC != "aa:bb:cc:00:11:22" {
		t.Fatalf("defaults not applied: %+v", b)
	}
	for name, bad := range map[string]map[string]any{
		"no range":         {},
		"outside subnet":   {"dhcp_start": "10.79.0.5", "dhcp_end": "10.79.0.9"},
		"reversed":         {"dhcp_start": "10.78.0.50", "dhcp_end": "10.78.0.40"},
		"gateway in range": {"dhcp_start": "10.78.0.1", "dhcp_end": "10.78.0.9"},
		"tunnel overlap":   {"address": "10.77.0.1/24", "dhcp_start": "10.77.0.5", "dhcp_end": "10.77.0.9"},
		"docker overlap":   {"address": "172.18.0.1/24", "dhcp_start": "172.18.0.5", "dhcp_end": "172.18.0.9"},
		"bad lease":        {"dhcp_start": "10.78.0.5", "dhcp_end": "10.78.0.9", "lease": "forever; rm"},
		"bad dns":          {"dhcp_start": "10.78.0.5", "dhcp_end": "10.78.0.9", "dns": []string{"x"}},
		"multicast mac":    {"dhcp_start": "10.78.0.5", "dhcp_end": "10.78.0.9", "hosts": []map[string]any{{"mac": "01:00:5e:00:00:01", "ip": "10.78.0.7"}}},
		"host outside":     {"dhcp_start": "10.78.0.5", "dhcp_end": "10.78.0.9", "hosts": []map[string]any{{"mac": "aa:bb:cc:00:11:22", "ip": "10.99.0.7"}}},
		"host name":        {"dhcp_start": "10.78.0.5", "dhcp_end": "10.78.0.9", "hosts": []map[string]any{{"mac": "aa:bb:cc:00:11:22", "ip": "10.78.0.7", "name": "a b;"}}},
		"unknown field":    {"dhcp_start": "10.78.0.5", "dhcp_end": "10.78.0.9", "gateway": "x"},
	} {
		if _, err := decode(bad); err == nil {
			t.Fatal("accepted", name)
		}
	}
}

func TestL2PolicyIsValidated(t *testing.T) {
	decode := func(policy map[string]any) error {
		input := configFixture()
		input["l2"] = map[string]any{"enabled": true, "bridge": map[string]any{"dhcp_start": "10.78.0.100", "dhcp_end": "10.78.0.149", "policy": policy}}
		data, _ := json.Marshal(input)
		_, _, _, _, err := DecodeConfig(data)
		return err
	}
	if err := decode(map[string]any{"version": 3, "devices": []map[string]any{
		{"mac": "AA:BB:CC:00:11:22", "name": "ps5", "max_flows": 500, "block_ports": []int{25}, "block_nets": []string{"203.0.113.0/24"}}}}); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]map[string]any{
		"multicast mac": {"devices": []map[string]any{{"mac": "01:00:5e:00:00:01"}}},
		"duplicate":     {"devices": []map[string]any{{"mac": "aa:bb:cc:00:11:22"}, {"mac": "AA:BB:CC:00:11:22"}}},
		"bad port":      {"default": map[string]any{"block_ports": []int{70000}}},
		"bad net":       {"default": map[string]any{"block_nets": []string{"nope"}}},
		"negative":      {"default": map[string]any{"max_flows": -1}},
		"version":       {"version": -2},
	} {
		if decode(bad) == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
