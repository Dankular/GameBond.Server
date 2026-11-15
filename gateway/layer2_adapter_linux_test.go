//go:build linux

package gateway

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

type rtnetlinkAdapterRunner struct {
	commands []string
	links    []string
	failLink error
}

func (r *rtnetlinkAdapterRunner) Run(_ context.Context, tool string, args ...string) (CommandResult, error) {
	r.commands = append(r.commands, tool+" "+joinArgs(args))
	return CommandResult{}, nil
}
func (*rtnetlinkAdapterRunner) Available(string) bool { return true }
func (r *rtnetlinkAdapterRunner) SetLinkUp(_ context.Context, name string, up bool) error {
	r.links = append(r.links, name+" up="+strconv.FormatBool(up))
	return r.failLink
}
func (r *rtnetlinkAdapterRunner) SetMaster(_ context.Context, name, master string) error {
	r.links = append(r.links, name+" master="+master)
	return r.failLink
}
func (r *rtnetlinkAdapterRunner) SetMTU(_ context.Context, name string, mtu int) error {
	r.links = append(r.links, name+" mtu="+strconv.Itoa(mtu))
	return r.failLink
}

func TestLayer2RunnerAdapterUsesRtnetlinkForCommonLinkChanges(t *testing.T) {
	runner := &rtnetlinkAdapterRunner{}
	adapter := layer2RunnerAdapter{runner: runner}
	commands := [][]string{
		{"link", "set", "dev", "lan0", "up"},
		{"link", "set", "dev", "lan0", "down"},
		{"link", "set", "dev", "lan0", "master", "br0"},
		{"link", "set", "dev", "lan0", "nomaster"},
		{"link", "set", "dev", "lan0", "mtu", "1500"},
	}
	for _, args := range commands {
		if _, err := adapter.Run(context.Background(), "ip", args...); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"lan0 up=true", "lan0 up=false", "lan0 master=br0", "lan0 master=", "lan0 mtu=1500"}
	if !reflect.DeepEqual(runner.links, want) || len(runner.commands) != 0 {
		t.Fatalf("rtnetlink operations=%v command fallback=%v", runner.links, runner.commands)
	}
}

func TestLayer2RunnerAdapterPropagatesRtnetlinkFailure(t *testing.T) {
	wantErr := errors.New("kernel rejected link update")
	runner := &rtnetlinkAdapterRunner{failLink: wantErr}
	_, err := (layer2RunnerAdapter{runner: runner}).Run(context.Background(), "ip", "link", "set", "dev", "lan0", "up")
	if !errors.Is(err, wantErr) || len(runner.commands) != 0 {
		t.Fatalf("error=%v command fallback=%v", err, runner.commands)
	}
}

func TestLayer2RunnerAdapterKeepsOtherLinkOperationsOnCommandRunner(t *testing.T) {
	runner := &rtnetlinkAdapterRunner{}
	_, err := (layer2RunnerAdapter{runner: runner}).Run(context.Background(), "ip", "link", "set", "dev", "br0", "type", "bridge", "vlan_filtering", "1")
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.links) != 0 || len(runner.commands) != 1 {
		t.Fatalf("rtnetlink operations=%v command fallback=%v", runner.links, runner.commands)
	}
}

func joinArgs(args []string) string {
	return strings.Join(args, " ")
}
