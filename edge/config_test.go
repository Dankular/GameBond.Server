package edge

import (
	"encoding/json"
	"testing"
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
