//go:build linux

package main

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Dankular/GameBond.Core/bond"
	"github.com/Dankular/GameBond.Server/edge"
)

func TestParseSegmentPVLANConfig(t *testing.T) {
	for _, test := range []struct {
		vlan      uint16
		role      string
		community uint16
		want      bond.L2PrivateVLANRole
	}{
		{want: bond.L2PVLANNone},
		{vlan: 10, role: "promiscuous", want: bond.L2PVLANPromiscuous},
		{vlan: 10, role: "isolated", want: bond.L2PVLANIsolated},
		{vlan: 10, role: "community", community: 20, want: bond.L2PVLANCommunity},
	} {
		got, err := parseSegmentPVLAN(test.vlan, test.role, test.community)
		if err != nil || got != test.want {
			t.Errorf("parseSegmentPVLAN(%d,%q,%d) = %v, %v; want %v", test.vlan, test.role, test.community, got, err, test.want)
		}
	}
	for _, test := range []struct {
		vlan      uint16
		role      string
		community uint16
	}{
		{vlan: 10}, {role: "isolated"}, {vlan: 10, role: "other"},
		{vlan: 10, role: "community"}, {vlan: 10, role: "isolated", community: 20},
		{vlan: 4095, role: "isolated"}, {vlan: 10, role: "community", community: 4095},
	} {
		if _, err := parseSegmentPVLAN(test.vlan, test.role, test.community); err == nil {
			t.Errorf("invalid PVLAN config accepted: %+v", test)
		}
	}
}

func TestLoadSegmentAuthorizationsMapsMVRAndPVLAN(t *testing.T) {
	member := edge.L2SegmentMember{Identity: "session-000102030405060708090a0b0c0d0e0f", TokenHex: strings.Repeat("ab", 32), VLAN: bond.L2VLANPolicy{AccessVLAN: 10}, PrivateVLAN: 7, PrivateVLANRole: "community", PVLANCommunity: 3, MulticastRouter: false, IPv4SourceGuard: true, StaticSourceBindings: []edge.L2SegmentSourceBinding{{IP: "192.0.2.10", MAC: "02:00:00:00:00:10"}}}
	data, err := json.Marshal([]edge.L2SegmentMember{member})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "members.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	mvr := &bond.L2MVRConfig{MulticastVLAN: 100, Groups: []bond.L2MVRGroup{{Group: netip.MustParseAddr("239.3.3.3"), ReceiverVLAN: 10}}}
	l2 := &edge.L2Config{SegmentMembersFile: path, MVR: mvr, ExitVLAN: bond.L2VLANPolicy{AccessVLAN: 100}, Bridge: &edge.L2Bridge{}}
	got, err := loadSegmentAuthorizations(l2)
	if err != nil {
		t.Fatal(err)
	}
	port := got[member.Identity].Port
	if port.PrivateVLAN != 7 || port.PrivateVLANRole != bond.L2PVLANCommunity || port.PVLANCommunity != 3 {
		t.Fatalf("private VLAN mapping = %+v", port)
	}
	if port.VLAN.AccessVLAN != 10 {
		t.Fatalf("member VLAN mapping = %+v", port.VLAN)
	}
	if len(port.StaticSourceBindings) != 1 || port.StaticSourceBindings[0].IP != netip.MustParseAddr("192.0.2.10") || port.StaticSourceBindings[0].VLAN != 10 || port.StaticSourceBindings[0].MAC != [6]byte{2, 0, 0, 0, 0, 16} {
		t.Fatalf("static source binding mapping = %#v", port.StaticSourceBindings)
	}
}

func TestLoadSegmentAuthorizationsValidatesPVLANPrimaryAndSecondaryVLANs(t *testing.T) {
	member := edge.L2SegmentMember{
		Identity: "session-000102030405060708090a0b0c0d0e0f", TokenHex: strings.Repeat("cd", 32),
		VLAN: bond.L2VLANPolicy{AccessVLAN: 101}, PrivateVLAN: 7, PrivateVLANRole: "isolated",
		PVLANPrimaryVLAN: 100, PVLANSecondaryVLAN: 101,
	}
	load := func(bridge *edge.L2Bridge) error {
		data, err := json.Marshal([]edge.L2SegmentMember{member})
		if err != nil {
			return err
		}
		path := filepath.Join(t.TempDir(), "members.json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return err
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return err
		}
		_, err = loadSegmentAuthorizations(&edge.L2Config{
			SegmentMembersFile: path, ExitVLAN: bond.L2VLANPolicy{AccessVLAN: 100}, Bridge: bridge,
		})
		return err
	}
	if err := load(&edge.L2Bridge{PrivateVLAN: 7}); err != nil {
		t.Fatalf("valid primary/secondary PVLAN mapping rejected: %v", err)
	}
	if err := load(&edge.L2Bridge{PrivateVLAN: 8}); err == nil {
		t.Fatal("PVLAN mapping without its matching promiscuous gateway group was accepted")
	}
}

func TestParseSegmentStaticSourceBindings(t *testing.T) {
	member := edge.L2SegmentMember{
		VLAN: bond.L2VLANPolicy{AccessVLAN: 10}, IPv4SourceGuard: true, IPv6SourceGuard: true,
		StaticSourceBindings: []edge.L2SegmentSourceBinding{
			{IP: "192.0.2.20", MAC: "02:00:00:00:00:20"},
			{IP: "2001:db8::20", MAC: "02:00:00:00:00:21", VLAN: 10},
		},
	}
	got, err := parseSegmentSourceBindings(member)
	if err != nil {
		t.Fatalf("valid static source bindings rejected: %v", err)
	}
	if len(got) != 2 || got[0].VLAN != 10 || got[1].VLAN != 10 || got[0].MAC != [6]byte{2, 0, 0, 0, 0, 32} {
		t.Fatalf("parsed bindings = %#v", got)
	}

	for name, edit := range map[string]func(*edge.L2SegmentMember){
		"multicast IP":         func(m *edge.L2SegmentMember) { m.StaticSourceBindings[0].IP = "239.1.2.3" },
		"loopback IP":          func(m *edge.L2SegmentMember) { m.StaticSourceBindings[0].IP = "127.0.0.1" },
		"multicast MAC":        func(m *edge.L2SegmentMember) { m.StaticSourceBindings[0].MAC = "01:00:5e:01:02:03" },
		"zero MAC":             func(m *edge.L2SegmentMember) { m.StaticSourceBindings[0].MAC = "00:00:00:00:00:00" },
		"missing family guard": func(m *edge.L2SegmentMember) { m.IPv4SourceGuard = false },
		"unadmitted VLAN":      func(m *edge.L2SegmentMember) { m.StaticSourceBindings[0].VLAN = 11 },
		"duplicate IP VLAN":    func(m *edge.L2SegmentMember) { m.StaticSourceBindings[1].IP = m.StaticSourceBindings[0].IP },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := member
			invalid.StaticSourceBindings = append([]edge.L2SegmentSourceBinding(nil), member.StaticSourceBindings...)
			edit(&invalid)
			if _, err := parseSegmentSourceBindings(invalid); err == nil {
				t.Fatal("invalid static source binding was accepted")
			}
		})
	}
}

func TestParseSegmentStaticSourceBindingsQinQ(t *testing.T) {
	member := edge.L2SegmentMember{
		VLAN: bond.L2VLANPolicy{ServiceVLAN: 200, CustomerVLAN: 30}, IPv4SourceGuard: true,
		StaticSourceBindings: []edge.L2SegmentSourceBinding{{IP: "198.51.100.30", MAC: "02:00:00:00:00:30"}},
	}
	got, err := parseSegmentSourceBindings(member)
	if err != nil {
		t.Fatalf("valid Q-in-Q access binding rejected: %v", err)
	}
	if len(got) != 1 || got[0].OuterVLAN != 200 || got[0].InnerVLAN != 30 || got[0].VLAN != 0 {
		t.Fatalf("Q-in-Q binding = %#v", got)
	}

	member.VLAN = bond.L2VLANPolicy{ServiceVLAN: 200, AllowedCustomerVLANs: []uint16{30, 31}}
	member.StaticSourceBindings[0].OuterVLAN = 200
	member.StaticSourceBindings[0].InnerVLAN = 31
	got, err = parseSegmentSourceBindings(member)
	if err != nil || len(got) != 1 || got[0].InnerVLAN != 31 {
		t.Fatalf("valid Q-in-Q trunk binding = %#v, %v", got, err)
	}
	member.StaticSourceBindings[0].OuterVLAN = 201
	if _, err := parseSegmentSourceBindings(member); err == nil {
		t.Fatal("Q-in-Q binding with an unadmitted service VLAN was accepted")
	}
}

func TestLoadSegmentAuthorizationsRequiresUniquePerSessionEAPOLTAPs(t *testing.T) {
	first := edge.L2SegmentMember{Identity: "session-000102030405060708090a0b0c0d0e0f", TokenHex: strings.Repeat("ab", 32), VLAN: bond.L2VLANPolicy{AccessVLAN: 100}, MACAuth: true, EAPOLTapName: "gb-auth-a"}
	second := edge.L2SegmentMember{Identity: "session-100102030405060708090a0b0c0d0e0f", TokenHex: strings.Repeat("cd", 32), VLAN: bond.L2VLANPolicy{AccessVLAN: 100}, MACAuth: true, EAPOLTapName: "gb-auth-b"}
	path := filepath.Join(t.TempDir(), "members.json")
	writeMembers := func(members ...edge.L2SegmentMember) {
		t.Helper()
		data, err := json.Marshal(members)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	l2 := &edge.L2Config{SegmentMembersFile: path, ExitVLAN: bond.L2VLANPolicy{AccessVLAN: 100}, Bridge: &edge.L2Bridge{}}
	writeMembers(first, second)
	authorizations, err := loadSegmentAuthorizations(l2)
	if err != nil {
		t.Fatalf("valid per-session TAP mapping rejected: %v", err)
	}
	if authorizations[first.Identity].EAPOLTapName != "gb-auth-a" || authorizations[second.Identity].EAPOLTapName != "gb-auth-b" || !authorizations[first.Identity].Port.MACAuth {
		t.Fatalf("per-session EAPOL policy not mapped: %#v", authorizations)
	}
	second.EAPOLTapName = first.EAPOLTapName
	writeMembers(first, second)
	if _, err := loadSegmentAuthorizations(l2); err == nil || !strings.Contains(err.Error(), "duplicate eapol_tap_name") {
		t.Fatalf("duplicate TAP assignment was not rejected: %v", err)
	}
	second.EAPOLTapName = "gb-auth-b"
	second.VLAN = bond.L2VLANPolicy{AllowedVLANs: []uint16{100}}
	writeMembers(first, second)
	if _, err := loadSegmentAuthorizations(l2); err == nil || !strings.Contains(err.Error(), "access VLAN") {
		t.Fatalf("trunk MACAuth member was not rejected: %v", err)
	}
}
