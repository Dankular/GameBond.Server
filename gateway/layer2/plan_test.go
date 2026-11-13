package layer2

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestBuildTopologyPlanCreatesVLANBridgeInDependencyOrder(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Overrides = nil
	host := Capabilities{Features: map[string]FeatureCapability{
		FeatureBridgeVLAN: {State: CapabilityConditional},
	}, Interfaces: []HostInterface{
		{Name: "enp2s0", MTU: 1500, AdminUp: true},
		{Name: "enp3s0", MTU: 1500, AdminUp: true},
	}}
	plan, err := BuildTopologyPlan(Config{}, cfg, host)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Changes) < 8 {
		t.Fatalf("expected bridge, port, and VLAN operations, got %d", len(plan.Changes))
	}
	if got := strings.Join(plan.Changes[0].Apply.Args, " "); got != "link add name br-main type bridge vlan_filtering 1" {
		t.Fatalf("first operation must create a VLAN-filtering bridge, got %q", got)
	}
	wantPortVLAN := []string{"vlan", "add", "dev", "enp2s0", "vid", "10", "pvid", "untagged"}
	found := false
	for _, change := range plan.Changes {
		if change.Apply.Tool == "bridge" && reflect.DeepEqual(change.Apply.Args, wantPortVLAN) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("missing access VLAN operation %q", strings.Join(wantPortVLAN, " "))
	}
}

func TestBuildTopologyPlanRejectsUnmanagedBridge(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Overrides = nil
	host := Capabilities{Features: map[string]FeatureCapability{FeatureBridgeVLAN: {State: CapabilityConditional}},
		Interfaces: []HostInterface{{Name: "br-main", Kind: "bridge", MTU: 1500}}}
	if _, err := BuildTopologyPlan(Config{}, cfg, host); err == nil || !strings.Contains(err.Error(), "unmanaged") {
		t.Fatalf("expected refusal to adopt an unmanaged bridge, got %v", err)
	}
}

func TestBuildTopologyPlanRejectsUnmanagedPortMaster(t *testing.T) {
	cfg, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Overrides = nil
	host := Capabilities{Features: map[string]FeatureCapability{FeatureBridgeVLAN: {State: CapabilityConditional}},
		Interfaces: []HostInterface{{Name: "enp2s0", Master: "br-external", MTU: 1500}, {Name: "enp3s0", MTU: 1500}}}
	if _, err := BuildTopologyPlan(Config{}, cfg, host); err == nil || !strings.Contains(err.Error(), "unmanaged master") {
		t.Fatalf("expected refusal to steal an unmanaged port, got %v", err)
	}
}

type planRunner struct {
	calls    []string
	failAt   map[int]bool
	cancel   context.CancelFunc
	cancelAt int
}

func (r *planRunner) Available(string) bool { return true }
func (r *planRunner) Run(ctx context.Context, tool string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, tool+" "+strings.Join(args, " "))
	if len(r.calls) == r.cancelAt && r.cancel != nil {
		r.cancel()
	}
	if r.failAt[len(r.calls)] {
		return nil, errors.New("injected failure")
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return nil, nil
}

func TestApplyPlanRollsBackInReverseOrderAfterContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	runner := &planRunner{failAt: map[int]bool{2: true}, cancel: cancel, cancelAt: 2}
	plan := Plan{Changes: []Change{
		{Description: "create", Apply: Command{Tool: "ip", Args: []string{"link", "add"}}, Rollback: Command{Tool: "ip", Args: []string{"link", "del"}}},
		{Description: "attach", Apply: Command{Tool: "ip", Args: []string{"link", "set"}}, Rollback: Command{Tool: "ip", Args: []string{"link", "set", "nomaster"}}},
	}}
	err := ApplyPlan(ctx, runner, plan)
	if err == nil || !strings.Contains(err.Error(), "injected failure") {
		t.Fatalf("expected the original operation failure, got %v", err)
	}
	want := []string{"ip link add", "ip link set", "ip link del"}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("operations did not roll back in reverse order after cancellation: got %v want %v", runner.calls, want)
	}
}

func TestApplyPlanReportsRollbackFailure(t *testing.T) {
	runner := &planRunner{failAt: map[int]bool{3: true, 4: true}}
	plan := Plan{Changes: []Change{
		{Description: "first", Apply: Command{Tool: "ip", Args: []string{"first"}}, Rollback: Command{Tool: "ip", Args: []string{"undo-first"}}},
		{Description: "second", Apply: Command{Tool: "ip", Args: []string{"second"}}, Rollback: Command{Tool: "ip", Args: []string{"undo-second"}}},
		{Description: "third", Apply: Command{Tool: "ip", Args: []string{"third"}}},
	}}
	if err := ApplyPlan(context.Background(), runner, plan); err == nil || !strings.Contains(err.Error(), "rollback failed") {
		t.Fatalf("expected rollback failure to be visible, got %v", err)
	}
}
