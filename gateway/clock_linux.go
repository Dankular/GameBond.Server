//go:build linux

package gateway

import (
	"context"
	"fmt"
	"strings"
)

// ClockSnapshot reports host clock synchronization without changing the host's
// time-service configuration. The OS remains the single clock owner.
type ClockSnapshot struct {
	NTPEnabled       *bool  `json:"ntp_enabled,omitempty"`
	Synchronized     *bool  `json:"synchronized,omitempty"`
	Timezone         string `json:"timezone,omitempty"`
	Error            string `json:"error,omitempty"`
}

func snapshotClock(ctx context.Context, runner Runner) ClockSnapshot {
	if runner == nil || !runner.Available("timedatectl") {
		return ClockSnapshot{Error: "timedatectl is unavailable; host clock synchronization state cannot be read"}
	}
	result, err := runner.Run(ctx, "timedatectl", "show", "--property=NTP", "--property=NTPSynchronized", "--property=Timezone")
	if err != nil {
		return ClockSnapshot{Error: fmt.Sprintf("read host clock synchronization state: %v", err)}
	}
	values := make(map[string]string, 3)
	for _, line := range strings.Split(string(result.Stdout), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok {
			values[key] = value
		}
	}
	ntp, ntpOK := parseTimedatectlBool(values["NTP"])
	synced, syncOK := parseTimedatectlBool(values["NTPSynchronized"])
	out := ClockSnapshot{Timezone: values["Timezone"]}
	if ntpOK {
		out.NTPEnabled = &ntp
	}
	if syncOK {
		out.Synchronized = &synced
	}
	if !ntpOK || !syncOK || out.Timezone == "" {
		out.Error = "timedatectl returned incomplete clock synchronization state"
	}
	return out
}

func parseTimedatectlBool(value string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "yes", "true", "1":
		return true, true
	case "no", "false", "0":
		return false, true
	default:
		return false, false
	}
}
