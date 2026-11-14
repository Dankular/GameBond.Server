//go:build linux

package gateway

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

type mirrorProbeRunner struct {
	mu       sync.Mutex
	commands []string
	failOn   string
}

func (r *mirrorProbeRunner) Available(string) bool { return true }
func (r *mirrorProbeRunner) Run(_ context.Context, tool string, args ...string) (CommandResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	command := tool + " " + strings.Join(args, " ")
	r.commands = append(r.commands, command)
	if r.failOn != "" && strings.Contains(command, r.failOn) {
		return CommandResult{}, errors.New("provider action unsupported")
	}
	return CommandResult{}, nil
}

func (r *mirrorProbeRunner) snapshotCommands() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.commands...)
}

func TestValidatePortMirrorProviderUsesTemporaryNamespaceAndCleansIt(t *testing.T) {
	runner := &mirrorProbeRunner{}
	if err := validatePortMirrorProvider(context.Background(), runner); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.commands, "\n")
	for _, expected := range []string{"ip netns add gamebond-mirror-probe-", "ip netns exec gamebond-mirror-probe-", "tc filter add dev", "matchall skip_hw action mirred egress mirror dev", "ip netns del gamebond-mirror-probe-"} {
		if !strings.Contains(joined, expected) {
			t.Errorf("provider probe missing %q: %s", expected, joined)
		}
	}
}

func TestValidatePortMirrorProviderCleansNamespaceAfterActionFailure(t *testing.T) {
	runner := &mirrorProbeRunner{failOn: "tc filter add"}
	if err := validatePortMirrorProvider(context.Background(), runner); err == nil {
		t.Fatal("unsupported mirred action passed provider preflight")
	}
	if len(runner.commands) == 0 || !strings.Contains(runner.commands[len(runner.commands)-1], "ip netns del gamebond-mirror-probe-") {
		t.Fatalf("probe namespace leaked after failure: %#v", runner.commands)
	}
}

func TestValidatePortMirrorProviderAllocatesUniqueNamesConcurrently(t *testing.T) {
	runner := &mirrorProbeRunner{}
	start := make(chan struct{})
	errors := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			errors <- validatePortMirrorProvider(context.Background(), runner)
		}()
	}
	close(start)
	for range 2 {
		if err := <-errors; err != nil {
			t.Fatal(err)
		}
	}

	namespaces := map[string]bool{}
	interfaces := map[string]bool{}
	for _, command := range runner.snapshotCommands() {
		fields := strings.Fields(command)
		if len(fields) == 4 && fields[0] == "ip" && fields[1] == "netns" && fields[2] == "add" {
			namespaces[fields[3]] = true
		}
		if len(fields) >= 10 && fields[0] == "ip" && fields[1] == "netns" && fields[2] == "exec" && fields[4] == "ip" && fields[5] == "link" && fields[6] == "add" {
			for _, name := range []string{fields[7], fields[len(fields)-1]} {
				if len(name) > 15 {
					t.Fatalf("probe interface name %q exceeds Linux IFNAMSIZ", name)
				}
				interfaces[name] = true
			}
		}
	}
	if len(namespaces) != 2 || len(interfaces) != 4 {
		t.Fatalf("concurrent probes reused disposable names: namespaces=%v interfaces=%v", namespaces, interfaces)
	}
}

func TestValidatePortMirrorProviderDoesNotDeleteNamespaceItDidNotCreate(t *testing.T) {
	runner := &mirrorProbeRunner{failOn: "ip netns add"}
	if err := validatePortMirrorProvider(context.Background(), runner); err == nil {
		t.Fatal("namespace creation failure was ignored")
	}
	for _, command := range runner.snapshotCommands() {
		if strings.Contains(command, "ip netns del") {
			t.Fatalf("probe deleted a namespace after creation failed: %q", command)
		}
	}
}

func TestValidatePortMirrorProviderReportsCleanupFailure(t *testing.T) {
	runner := &mirrorProbeRunner{failOn: "ip netns del"}
	err := validatePortMirrorProvider(context.Background(), runner)
	if err == nil || !strings.Contains(err.Error(), "clean up isolated port-mirror preflight namespace") {
		t.Fatalf("namespace cleanup failure was hidden: %v", err)
	}
}
