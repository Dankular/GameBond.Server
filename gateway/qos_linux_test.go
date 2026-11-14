//go:build linux

package gateway

import (
	"context"
	"strings"
	"testing"
)

type qosSnapshotRunner struct{}

func (qosSnapshotRunner) Available(string) bool { return true }
func (qosSnapshotRunner) Run(_ context.Context, tool string, args ...string) (CommandResult, error) {
	if tool != "tc" {
		return CommandResult{}, nil
	}
	joined := strings.Join(args, " ")
	switch {
	case strings.Contains(joined, "qdisc show"):
		return CommandResult{Stdout: []byte(`[{"kind":"htb","handle":"7e:","root":true}]`)}, nil
	case strings.Contains(joined, "class show"):
		return CommandResult{Stdout: []byte(`[{"classid":"7e:1","stats":{"bytes":0,"packets":0}},{"classid":"7e:2","stats":{"bytes":2048,"packets":12}}]`)}, nil
	default:
		return CommandResult{}, nil
	}
}

func TestQoSSnapshotReportsEffectiveDSCPMappingAndCounters(t *testing.T) {
	cfg := Config{
		Interfaces: []Interface{{ID: "lan", Name: "eth0"}},
		QoS:        QoSConfig{Enabled: true, Interfaces: []QoSInterface{{InterfaceID: "lan", TotalKbit: 100000, Classes: []QoSClass{{ID: "game", DSCP: 46, RateKbit: 20000, CeilKbit: 90000, Priority: 1}}}}},
	}
	snapshot := snapshotQoS(context.Background(), qosSnapshotRunner{}, cfg)
	if len(snapshot.Interfaces) != 1 || len(snapshot.Interfaces[0].Classes) != 2 {
		t.Fatalf("unexpected QoS snapshot: %#v", snapshot)
	}
	class := snapshot.Interfaces[0].Classes[1]
	if class.ID != "game" || class.DSCP == nil || *class.DSCP != 46 || class.RateKbit == nil || *class.RateKbit != 20000 || class.CeilKbit == nil || *class.CeilKbit != 90000 || class.Priority == nil || *class.Priority != 1 || class.Packets != 12 || class.Bytes != 2048 {
		t.Fatalf("effective class mapping/counters = %#v", class)
	}
	if snapshot.Interfaces[0].Classes[0].DSCP != nil {
		t.Fatal("root/default class must not report a fabricated DSCP mapping")
	}
}

func TestQoSSnapshotReportsAllDSCPMappingsForSharedClass(t *testing.T) {
	cfg := Config{
		Interfaces: []Interface{{ID: "lan", Name: "eth0"}},
		QoS:        QoSConfig{Enabled: true, Interfaces: []QoSInterface{{InterfaceID: "lan", TotalKbit: 100000, Classes: []QoSClass{{ID: "media", DSCPValues: []uint8{46, 48}, RateKbit: 20000, CeilKbit: 90000, Priority: 1}}}}},
	}
	snapshot := snapshotQoS(context.Background(), qosSnapshotRunner{}, cfg)
	if len(snapshot.Interfaces) != 1 || len(snapshot.Interfaces[0].Classes) != 2 {
		t.Fatalf("unexpected QoS snapshot: %#v", snapshot)
	}
	class := snapshot.Interfaces[0].Classes[1]
	if class.ID != "media" || class.DSCP != nil || len(class.DSCPs) != 2 || class.DSCPs[0] != 46 || class.DSCPs[1] != 48 || class.RateKbit == nil || *class.RateKbit != 20000 || class.Packets != 12 {
		t.Fatalf("shared class mapping/counters = %#v", class)
	}
}
