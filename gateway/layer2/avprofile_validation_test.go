package layer2

import (
	"strings"
	"testing"

	"github.com/Dankular/GameBond.Server/gateway/layer2/avprofiles"
)

func TestBuildTopologyPlanRejectsAVProfileDSCPMismatch(t *testing.T) {
	previous, desired, host := qsysProfilePlanFixture(t)
	desired.QoS[0].Classes = desired.QoS[0].Classes[:2]

	_, err := BuildTopologyPlan(previous, desired, host)
	if err == nil || !strings.Contains(err.Error(), "Q-SYS") || !strings.Contains(err.Error(), "DSCP 26") {
		t.Fatalf("Q-SYS profile accepted an incomplete active DSCP map: %v", err)
	}
}

func TestBuildTopologyPlanRejectsAVProfileUnknownLinkSpeed(t *testing.T) {
	previous, desired, host := qsysProfilePlanFixture(t)
	host.Interfaces[1].LinkSpeedKnown = false

	_, err := BuildTopologyPlan(previous, desired, host)
	if err == nil || !strings.Contains(err.Error(), "Q-SYS") || !strings.Contains(err.Error(), "link speed is unknown") {
		t.Fatalf("Q-SYS profile accepted a port with unknown speed: %v", err)
	}
}

func TestBuildTopologyPlanRejectsAVProfileSlowLink(t *testing.T) {
	previous, desired, host := qsysProfilePlanFixture(t)
	host.Interfaces[1].LinkSpeedBPS = 100_000_000

	_, err := BuildTopologyPlan(previous, desired, host)
	if err == nil || !strings.Contains(err.Error(), "Q-SYS") || !strings.Contains(err.Error(), "below required 1000000000 bps") {
		t.Fatalf("Q-SYS profile accepted a 100 Mbps port: %v", err)
	}
}

func TestBuildTopologyPlanAcceptsAVProfileCompatibleHostAndQoS(t *testing.T) {
	previous, desired, host := qsysProfilePlanFixture(t)

	if _, err := BuildTopologyPlan(previous, desired, host); err != nil {
		t.Fatalf("Q-SYS profile rejected compatible host and DSCP map: %v", err)
	}
}

func TestBuildTopologyPlanKeepsAbsentAVProfileQoSAdvisory(t *testing.T) {
	previous, desired, host := qsysProfilePlanFixture(t)
	desired.QoS = nil
	previous.QoS = nil
	delete(host.Features, FeatureQoSDSCP)

	if _, err := BuildTopologyPlan(previous, desired, host); err != nil {
		t.Fatalf("Q-SYS profile made an absent advisory QoS policy mandatory: %v", err)
	}
}

func TestBuildTopologyPlanRejectsQSYSWrongQueuePriority(t *testing.T) {
	previous, desired, host := qsysProfilePlanFixture(t)
	desired.QoS[0].Classes[0].Priority = 1

	_, err := BuildTopologyPlan(previous, desired, host)
	if err == nil || !strings.Contains(err.Error(), "Q-SYS") || !strings.Contains(err.Error(), "DSCP 46") || !strings.Contains(err.Error(), "priority 0") {
		t.Fatalf("Q-SYS profile accepted DSCP 46 outside the highest-priority class: %v", err)
	}
}

func TestBuildTopologyPlanAcceptsQSYSDocumentedQueuePriorities(t *testing.T) {
	previous, desired, host := qsysProfilePlanFixture(t)

	if _, err := BuildTopologyPlan(previous, desired, host); err != nil {
		t.Fatalf("Q-SYS documented queue priorities were rejected: %v", err)
	}
}

func TestBuildTopologyPlanRejectsShureWrongQueuePriority(t *testing.T) {
	previous, desired, host := shureProfilePlanFixture(t)
	desired.QoS[1].Classes[0].Priority = 2

	_, err := BuildTopologyPlan(previous, desired, host)
	if err == nil || !strings.Contains(err.Error(), "Shure") || !strings.Contains(err.Error(), "DSCP 56") || !strings.Contains(err.Error(), "priority 0") {
		t.Fatalf("Shure profile accepted DSCP 56 outside the highest-priority class: %v", err)
	}
}

func TestBuildTopologyPlanAcceptsShureDocumentedQueuePriorities(t *testing.T) {
	previous, desired, host := shureProfilePlanFixture(t)

	if _, err := BuildTopologyPlan(previous, desired, host); err != nil {
		t.Fatalf("Shure documented queue priorities were rejected: %v", err)
	}
}

func TestValidateAVProfileCompatibilityRejectsInvertedDanteDSCPPriorityOrder(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.AVProfiles = []AVProfileSelection{{Profile: "dante", Network: "default"}}
	policy := AVQoSPolicy{InterfaceName: "enp2s0", Classes: []AVQoSClass{{DSCP: []uint8{46}, Priority: 0}, {DSCP: []uint8{56}, Priority: 1}, {DSCP: []uint8{8}, Priority: 2}}}
	if err := ValidateAVProfileCompatibility(cfg, Capabilities{}, []AVQoSPolicy{policy}); err == nil || !strings.Contains(err.Error(), "Dante") || !strings.Contains(err.Error(), "DSCP 56") {
		t.Fatalf("Dante accepted audio priority above clock priority: %v", err)
	}
}

func TestValidateAVProfileCompatibilityRejectsInvertedAES67DSCPPriorityOrder(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.AVProfiles = []AVProfileSelection{{Profile: "aes67", Network: "default"}}
	policy := AVQoSPolicy{InterfaceName: "enp2s0", Classes: []AVQoSClass{{DSCP: []uint8{34}, Priority: 0}, {DSCP: []uint8{46}, Priority: 1}}}
	if err := ValidateAVProfileCompatibility(cfg, Capabilities{}, []AVQoSPolicy{policy}); err == nil || !strings.Contains(err.Error(), "AES67") || !strings.Contains(err.Error(), "DSCP 46") {
		t.Fatalf("AES67 accepted media priority above clock priority: %v", err)
	}
}

func TestAVProfileMinimumLinkSpeedParsesEveryCurrentCatalogueValue(t *testing.T) {
	tests := map[string]uint64{
		"qsys":     1_000_000_000,
		"shure":    1_000_000_000,
		"ndi":      1_000_000_000,
		"crestron": 1_000_000_000,
		"sdvoe":    10_000_000_000,
	}
	for id, want := range tests {
		profile, ok := avprofiles.Lookup(id)
		if !ok {
			t.Fatalf("profile %q is missing", id)
		}
		if got := avProfileMinimumLinkSpeed(profile); got != want {
			t.Errorf("%s minimum speed = %d, want %d", id, got, want)
		}
	}
}

func qsysProfilePlanFixture(t *testing.T) (Config, Config, Capabilities) {
	t.Helper()
	desired, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	desired.Overrides = nil
	desired.AVProfiles = []AVProfileSelection{{Profile: "qsys", Network: "default"}}
	classes := []QoSClass{
		{ID: 10, DSCP: []uint8{46}, RateBPS: 100_000_000, CeilingBPS: 1_000_000_000, Priority: 0},
		{ID: 11, DSCP: []uint8{34}, RateBPS: 100_000_000, CeilingBPS: 1_000_000_000, Priority: 1},
		{ID: 12, DSCP: []uint8{26}, RateBPS: 100_000_000, CeilingBPS: 1_000_000_000, Priority: 2},
	}
	desired.QoS = []QoSPolicy{
		{Interface: "lan-a", LinkRateBPS: 1_000_000_000, Classes: append([]QoSClass(nil), classes...)},
		{Interface: "lan-b", LinkRateBPS: 1_000_000_000, Classes: append([]QoSClass(nil), classes...)},
	}
	previous := desired
	host := Capabilities{
		Features: map[string]FeatureCapability{
			FeatureBridgeVLAN: {State: CapabilityConditional},
			FeatureQoSDSCP:    {State: CapabilityConditional},
		},
		Interfaces: []HostInterface{
			{Name: "br-main", Kind: "bridge", MTU: 1500, AdminUp: true, VLANFiltering: true},
			{Name: "enp2s0", Master: "br-main", MTU: 1500, AdminUp: true, RootQdisc: "noqueue", LinkSpeedKnown: true, LinkSpeedBPS: 1_000_000_000},
			{Name: "enp3s0", Master: "br-main", MTU: 1500, AdminUp: true, RootQdisc: "noqueue", LinkSpeedKnown: true, LinkSpeedBPS: 1_000_000_000},
		},
	}
	return previous, desired, host
}

func shureProfilePlanFixture(t *testing.T) (Config, Config, Capabilities) {
	t.Helper()
	previous, desired, host := qsysProfilePlanFixture(t)
	desired.AVProfiles = []AVProfileSelection{{Profile: "shure", Network: "default"}}
	classes := []QoSClass{
		{ID: 10, DSCP: []uint8{56}, RateBPS: 100_000_000, CeilingBPS: 1_000_000_000, Priority: 0},
		{ID: 11, DSCP: []uint8{46}, RateBPS: 100_000_000, CeilingBPS: 1_000_000_000, Priority: 1},
		{ID: 12, DSCP: []uint8{34}, RateBPS: 100_000_000, CeilingBPS: 1_000_000_000, Priority: 2},
	}
	desired.QoS = []QoSPolicy{
		{Interface: "lan-a", LinkRateBPS: 1_000_000_000, Classes: append([]QoSClass(nil), classes...)},
		{Interface: "lan-b", LinkRateBPS: 1_000_000_000, Classes: append([]QoSClass(nil), classes...)},
	}
	enabled := true
	desired.Bridges = append([]Bridge(nil), desired.Bridges...)
	desired.Bridges[0].IGMPSnooping = &enabled
	desired.Bridges[0].IGMPQuerier = &enabled
	previous = desired
	host.Features[FeatureIGMPSnoop] = FeatureCapability{State: CapabilityConditional}
	host.Features[FeatureIGMPAdvanced] = FeatureCapability{State: CapabilityConditional}
	host.Interfaces[0].IGMPBridgeKnown = true
	host.Interfaces[0].IGMPSnooping = true
	host.Interfaces[0].IGMPQuerier = true
	return previous, desired, host
}
