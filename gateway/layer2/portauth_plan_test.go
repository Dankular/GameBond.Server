package layer2

import (
	"sort"
	"strings"
	"testing"
)

func TestBuildPortAuthChangeCreatesAndRollsBackManagedTable(t *testing.T) {
	desired := portAuthTestConfig()
	change, err := buildPortAuthChange(Config{Version: 1}, desired, Capabilities{})
	if err != nil {
		t.Fatal(err)
	}
	if change == nil || !strings.Contains(string(change.Apply.Input), portAuthTableMarker) || !strings.Contains(string(change.Apply.Input), "unauthorized-in") {
		t.Fatalf("authorization apply plan = %#v", change)
	}
	if !strings.Contains(string(change.Rollback.Input), "delete table bridge "+portAuthTableName) {
		t.Fatalf("authorization rollback does not remove new table: %s", change.Rollback.Input)
	}
}

func TestBuildPortAuthChangePreservesPreviousTableOnRollback(t *testing.T) {
	previous := portAuthTestConfig()
	desired := previous
	desired.PortAuth = append([]PortAuth(nil), previous.PortAuth...)
	desired.PortAuth = append(desired.PortAuth, PortAuth{Interface: "lan-b", RadiusServer: "radius.example.net", RadiusPort: 1812, SecretFile: "/etc/gamebond/8021x/lan-b.secret", NASAddress: "192.0.2.2", NASID: "gamebond-edge-b", FailurePolicy: "closed", ExclusivePort: true})
	host := convergedPortAuthCapabilities(previous)
	change, err := buildPortAuthChange(previous, desired, host)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(change.Apply.Input), "delete table bridge "+portAuthTableName) || !strings.Contains(string(change.Apply.Input), "elements = { \"enp2s0\", \"enp3s0\" }") || !strings.Contains(string(change.Rollback.Input), "elements = { \"enp2s0\" }") || !strings.Contains(string(change.Rollback.Input), portAuthTableMarker) {
		t.Fatalf("table reconcile apply/rollback = %#v", change)
	}
}

func TestBuildPortAuthChangeIsEmptyForVerifiedStaticTable(t *testing.T) {
	desired := portAuthTestConfig()
	change, err := buildPortAuthChange(desired, desired, convergedPortAuthCapabilities(desired))
	if err != nil {
		t.Fatal(err)
	}
	if change != nil {
		t.Fatalf("verified 802.1X table still produced a change: %#v", change)
	}
}

func convergedPortAuthCapabilities(cfg Config) Capabilities {
	ports := []string{}
	for _, policy := range cfg.PortAuth {
		iface, _ := findInterface(cfg.Interfaces, policy.Interface)
		ports = append(ports, iface.Name)
	}
	sort.Strings(ports)
	return Capabilities{PortAuthTablePresent: true, PortAuthTableManaged: true, PortAuthStaticShapeValid: true, PortAuthProtectedPorts: ports, PortAuthRuleComments: portAuthRuleComments()}
}

func TestBuildEAPOLForwardChangesPreservesUnrelatedMaskBits(t *testing.T) {
	desired := portAuthTestConfig()
	previous := desired
	previous.PortAuth = nil
	host := Capabilities{Interfaces: []HostInterface{{Name: "br-main", Kind: "bridge", GroupFwdMaskKnown: true, GroupFwdMask: 1}}}
	changes, err := buildEAPOLForwardChanges(previous, desired, host)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || !strings.HasSuffix(strings.Join(changes[0].Apply.Args, " "), "group_fwd_mask 9") || !strings.HasSuffix(strings.Join(changes[0].Rollback.Args, " "), "group_fwd_mask 1") {
		t.Fatalf("EAPOL forwarding change = %#v", changes)
	}
}
