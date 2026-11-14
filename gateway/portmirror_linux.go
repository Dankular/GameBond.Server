//go:build linux

package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync/atomic"
	"time"
)

var portMirrorProbeSequence atomic.Uint32

type portMirrorProbeNames struct {
	namespace   string
	source      string
	destination string
}

func newPortMirrorProbeNames() (portMirrorProbeNames, error) {
	var entropy [5]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return portMirrorProbeNames{}, fmt.Errorf("generate port-mirror preflight identity: %w", err)
	}
	// Linux interface names are limited to 15 visible bytes. Random entropy
	// avoids stale-object collisions across process restarts, while the
	// sequence keeps concurrent allocations in this process distinct.
	suffix := fmt.Sprintf("%s%04x", hex.EncodeToString(entropy[:]), portMirrorProbeSequence.Add(1)&0xffff)
	return portMirrorProbeNames{
		namespace:   "gamebond-mirror-probe-" + suffix,
		source:      "s" + suffix,
		destination: "d" + suffix,
	}, nil
}

// validatePortMirrorProvider exercises the software tc mirred path on a
// disposable veth pair. It never adds qdiscs or filters to a managed host port.
func validatePortMirrorProvider(ctx context.Context, runner Runner) (resultErr error) {
	for _, tool := range []string{"ip", "tc"} {
		if !runner.Available(tool) {
			return fmt.Errorf("port mirroring preflight requires %s", tool)
		}
	}
	names, err := newPortMirrorProbeNames()
	if err != nil {
		return err
	}
	namespace, source, destination := names.namespace, names.source, names.destination
	if _, err := runner.Run(ctx, "ip", "netns", "add", namespace); err != nil {
		return fmt.Errorf("create isolated port-mirror preflight namespace: %w", err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := runner.Run(cleanupCtx, "ip", "netns", "del", namespace); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("clean up isolated port-mirror preflight namespace %s: %w", namespace, err))
		}
	}()
	runIP := func(args ...string) error {
		command := append([]string{"netns", "exec", namespace, "ip"}, args...)
		if _, err := runner.Run(ctx, "ip", command...); err != nil {
			return fmt.Errorf("validate software tc mirred support: %w", err)
		}
		return nil
	}
	runTC := func(args ...string) error {
		command := append([]string{"netns", "exec", namespace, "tc"}, args...)
		if _, err := runner.Run(ctx, "ip", command...); err != nil {
			return fmt.Errorf("validate software tc mirred support: %w", err)
		}
		return nil
	}
	for _, args := range [][]string{
		{"link", "add", source, "type", "veth", "peer", "name", destination},
		{"link", "set", "dev", source, "up"},
		{"link", "set", "dev", destination, "up"},
		{"link", "set", "dev", "lo", "up"},
	} {
		if err := runIP(args...); err != nil {
			return err
		}
	}
	if err := runTC("qdisc", "add", "dev", source, "clsact"); err != nil {
		return err
	}
	if err := runTC("filter", "add", "dev", source, "ingress", "pref", "49100", "matchall", "skip_hw", "action", "mirred", "egress", "mirror", "dev", destination); err != nil {
		return err
	}
	return nil
}
