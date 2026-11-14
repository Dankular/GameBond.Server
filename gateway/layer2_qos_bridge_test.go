package gateway

import (
	"slices"
	"strings"
	"testing"

	"github.com/Dankular/GameBond.Server/gateway/layer2"
)

func TestLayer2QoSUsesTheSharedGatewayDSCPProvider(t *testing.T) {
	cfg := Config{
		Interfaces: []Interface{{ID: "lan-main", Name: "enp3s0", Role: "lan"}},
		Layer2:     &layer2.Config{Version: 1, Interfaces: []layer2.Interface{{ID: "access", Name: "enp3s0"}}, QoS: []layer2.QoSPolicy{{Interface: "access", LinkRateBPS: 1_000_000_000, Classes: []layer2.QoSClass{{ID: 10, DSCP: []uint8{46, 48}, RateBPS: 100_000_000, CeilingBPS: 900_000_000, Priority: 0}}}}},
	}
	effective, err := effectiveQoSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !effective.QoS.Enabled || len(effective.QoS.Interfaces) != 1 {
		t.Fatalf("Layer 2 QoS was not enabled through the shared provider: %#v", effective.QoS)
	}
	want := QoSInterface{InterfaceID: "lan-main", TotalKbit: 1_000_000, Classes: []QoSClass{{ID: "l2-10", DSCPValues: []uint8{46, 48}, RateKbit: 100_000, CeilKbit: 900_000, Priority: 0}}}
	if got := effective.QoS.Interfaces[0]; !equalQoSInterface(got, want) {
		t.Fatalf("shared provider policy = %#v, want %#v", got, want)
	}
}

func TestLayer2QoSMultipleDSCPValuesShareOneHTBReservation(t *testing.T) {
	cfg := Config{
		Interfaces: []Interface{{ID: "lan-main", Name: "enp3s0", Role: "lan"}},
		Layer2:     &layer2.Config{Version: 1, Interfaces: []layer2.Interface{{ID: "access", Name: "enp3s0"}}, QoS: []layer2.QoSPolicy{{Interface: "access", LinkRateBPS: 1_000_000_000, Classes: []layer2.QoSClass{{ID: 10, DSCP: []uint8{46, 48}, RateBPS: 100_000_000, CeilingBPS: 900_000_000, Priority: 0}}}}},
	}
	effective, err := effectiveQoSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	commands := qosCommands(effective.QoS.Interfaces[0], effective.Interfaces[0])
	reservations, filters := 0, 0
	for _, command := range commands {
		joined := strings.Join(command, " ")
		if strings.HasPrefix(joined, "class replace") && strings.Contains(joined, "parent 7e:1") && !strings.Contains(joined, "classid 7e:fff") {
			reservations++
		}
		if strings.HasPrefix(joined, "filter replace") {
			filters++
			if !strings.HasSuffix(joined, "classid 7e:2") {
				t.Fatalf("multi-DSCP filter targets a different HTB reservation: %s", joined)
			}
		}
	}
	if reservations != 1 || filters != 4 {
		t.Fatalf("multi-DSCP Layer 2 class generated %d HTB reservations and %d filters, want 1 reservation and 4 filters", reservations, filters)
	}
}

func TestLayer2QoSMultipleDSCPValuesReserveGuaranteedRateOnce(t *testing.T) {
	cfg := Config{
		Interfaces: []Interface{{ID: "lan-main", Name: "enp3s0", Role: "lan"}},
		Layer2:     &layer2.Config{Version: 1, Interfaces: []layer2.Interface{{ID: "access", Name: "enp3s0"}}, QoS: []layer2.QoSPolicy{{Interface: "access", LinkRateBPS: 1_000_000_000, Classes: []layer2.QoSClass{{ID: 10, DSCP: []uint8{46, 48}, RateBPS: 600_000_000, CeilingBPS: 900_000_000, Priority: 0}}}}},
	}
	effective, err := effectiveQoSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := effective.QoS.Validate(effective.Interfaces); err != nil {
		t.Fatalf("one Layer 2 class must reserve its guaranteed rate once regardless of DSCP count: %v", err)
	}
}

func TestLayer2QoSMergesWithAdaptiveQoSAndRejectsConflictingDSCP(t *testing.T) {
	cfg := Config{
		Interfaces: []Interface{{ID: "lan-main", Name: "enp3s0", Role: "lan"}},
		QoS:        QoSConfig{Enabled: true, Interfaces: []QoSInterface{{InterfaceID: "lan-main", TotalKbit: 1_000_000, Classes: []QoSClass{{ID: "interactive", DSCP: 46, RateKbit: 100_000, CeilKbit: 500_000, Priority: 0}}}}},
		Layer2:     &layer2.Config{Version: 1, Interfaces: []layer2.Interface{{ID: "access", Name: "enp3s0"}}, QoS: []layer2.QoSPolicy{{Interface: "access", LinkRateBPS: 1_000_000_000, Classes: []layer2.QoSClass{{ID: 10, DSCP: []uint8{34}, RateBPS: 100_000_000, CeilingBPS: 900_000_000, Priority: 1}}}}},
	}
	effective, err := effectiveQoSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(effective.QoS.Interfaces) != 1 || len(effective.QoS.Interfaces[0].Classes) != 2 {
		t.Fatalf("adaptive and Layer 2 classes did not share one policy: %#v", effective.QoS)
	}
	cfg.Layer2.QoS[0].Classes[0].DSCP = []uint8{46}
	if _, err := effectiveQoSConfig(cfg); err == nil || !strings.Contains(err.Error(), "DSCP 46 is already assigned") {
		t.Fatalf("expected conflicting DSCP rejection, got %v", err)
	}
}

func equalQoSInterface(a, b QoSInterface) bool {
	if a.InterfaceID != b.InterfaceID || a.TotalKbit != b.TotalKbit || len(a.Classes) != len(b.Classes) {
		return false
	}
	for i := range a.Classes {
		if a.Classes[i].ID != b.Classes[i].ID || a.Classes[i].DSCP != b.Classes[i].DSCP || a.Classes[i].RateKbit != b.Classes[i].RateKbit || a.Classes[i].CeilKbit != b.Classes[i].CeilKbit || a.Classes[i].Priority != b.Classes[i].Priority || !slices.Equal(a.Classes[i].DSCPValues, b.Classes[i].DSCPValues) {
			return false
		}
	}
	return true
}
