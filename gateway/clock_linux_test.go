//go:build linux

package gateway

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type clockSnapshotRunner struct {
	available bool
	output    string
	err       error
}

func (r clockSnapshotRunner) Available(tool string) bool { return tool == "timedatectl" && r.available }
func (r clockSnapshotRunner) Run(_ context.Context, tool string, args ...string) (CommandResult, error) {
	if tool != "timedatectl" || strings.Join(args, " ") != "show --property=NTP --property=NTPSynchronized --property=Timezone" {
		return CommandResult{}, errors.New("unexpected command")
	}
	return CommandResult{Stdout: []byte(r.output)}, r.err
}

func TestSnapshotClockReportsHostSynchronizationState(t *testing.T) {
	status := snapshotClock(context.Background(), clockSnapshotRunner{available: true, output: "Timezone=Europe/London\nNTP=yes\nNTPSynchronized=no\n"})
	if status.Error != "" || status.NTPEnabled == nil || !*status.NTPEnabled || status.Synchronized == nil || *status.Synchronized || status.Timezone != "Europe/London" {
		t.Fatalf("clock snapshot = %#v", status)
	}
}

func TestSnapshotClockDoesNotInventUnavailableOrIncompleteState(t *testing.T) {
	for _, runner := range []clockSnapshotRunner{
		{},
		{available: true, output: "Timezone=Europe/London\nNTP=yes\n"},
		{available: true, err: errors.New("timed out")},
	} {
		status := snapshotClock(context.Background(), runner)
		if status.Error == "" {
			t.Fatalf("missing/error clock data reported as healthy: %#v", status)
		}
	}
}
