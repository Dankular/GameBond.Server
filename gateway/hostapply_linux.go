//go:build linux

package gateway

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"

	"github.com/Dankular/GameBond.Server/gateway/layer2"
)

// LinuxApplier currently owns only bridge learned-FDB ceilings. Other providers are
// composed as they are delivered in later router phases.
type LinuxApplier struct{ Runner Runner }

func (a LinuxApplier) Prepare(ctx context.Context, current, desired Config) (PreparedChange, error) {
	var changes []bridgeLimitChange
	targets := make(map[string]uint32, len(desired.Bridges))
	for _, bridge := range desired.Bridges {
		targets[bridge.InterfaceName] = bridge.MaxLearnedEntries
	}
	for _, bridge := range current.Bridges {
		if _, remainsManaged := targets[bridge.InterfaceName]; !remainsManaged {
			targets[bridge.InterfaceName] = 0
		}
	}
	names := make([]string, 0, len(targets))
	for name := range targets {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		before, supported, err := a.bridgeLimit(ctx, name)
		if err != nil {
			return nil, err
		}
		after := targets[name]
		if !supported {
			if after > 0 {
				return nil, fmt.Errorf("bridge %s does not report kernel FDB learning limit support", name)
			}
			continue
		}
		if before != after {
			changes = append(changes, bridgeLimitChange{iface: name, before: before, after: after})
		}
	}
	prepared := &linuxPreparedChange{runner: a.Runner, changes: changes}
	if desired.Layer2 != nil {
		adapter := layer2RunnerAdapter{runner: a.Runner}
		host, err := layer2.SnapshotCapabilities(ctx, adapter)
		if err != nil {
			return nil, fmt.Errorf("inspect Layer 2 host: %w", err)
		}
		previous := layer2.Config{Version: 1}
		if current.Layer2 != nil {
			previous = *current.Layer2
		}
		plan, err := layer2.BuildTopologyPlan(previous, *desired.Layer2, host)
		if err != nil {
			return nil, err
		}
		prepared.layer2Plan = &plan
		prepared.layer2Desired = desired.Layer2
	}
	return prepared, nil
}

func (a LinuxApplier) bridgeLimit(ctx context.Context, name string) (uint32, bool, error) {
	result, err := a.Runner.Run(ctx, "ip", "-d", "-j", "link", "show", "dev", name)
	if err != nil {
		return 0, false, err
	}
	_, limit, supported, err := bridgeFDBStats(result.Stdout)
	if err != nil {
		return 0, false, fmt.Errorf("interface %s is not a readable Linux bridge: %w", name, err)
	}
	if !supported {
		return 0, false, nil
	}
	if limit < 0 || uint64(limit) > uint64(^uint32(0)) {
		return 0, false, fmt.Errorf("bridge %s returned an invalid FDB limit", name)
	}
	return uint32(limit), true, nil
}

type bridgeLimitChange struct {
	iface  string
	before uint32
	after  uint32
}

type linuxPreparedChange struct {
	runner        Runner
	changes       []bridgeLimitChange
	applied       int
	layer2Plan    *layer2.Plan
	layer2Desired *layer2.Config
	layer2Applied bool
}

func (p *linuxPreparedChange) Apply(ctx context.Context) error {
	for i, change := range p.changes {
		p.applied = i + 1 // include this interface in rollback if the kernel rejects a partial request
		if _, err := p.runner.Run(ctx, "ip", "link", "set", "dev", change.iface, "type", "bridge", "fdb_max_learned", strconv.FormatUint(uint64(change.after), 10)); err != nil {
			return fmt.Errorf("set bridge %s FDB limit: %w", change.iface, err)
		}
	}
	if p.layer2Plan != nil {
		if err := layer2.ApplyPlan(ctx, layer2RunnerAdapter{runner: p.runner}, *p.layer2Plan); err != nil {
			return err
		}
		p.layer2Applied = true
	}
	return nil
}

func (p *linuxPreparedChange) Verify(ctx context.Context) error {
	for _, change := range p.changes {
		got, supported, err := (LinuxApplier{Runner: p.runner}).bridgeLimit(ctx, change.iface)
		if err != nil {
			return err
		}
		if !supported || got != change.after {
			return fmt.Errorf("bridge %s FDB limit verification failed: wanted %d, got %d", change.iface, change.after, got)
		}
	}
	if p.layer2Plan != nil && p.layer2Desired != nil {
		host, err := layer2.SnapshotCapabilities(ctx, layer2RunnerAdapter{runner: p.runner})
		if err != nil {
			return err
		}
		remaining, err := layer2.BuildTopologyPlan(*p.layer2Desired, *p.layer2Desired, host)
		if err != nil {
			return err
		}
		if len(remaining.Changes) != 0 {
			return fmt.Errorf("Layer 2 topology verification left %d pending changes", len(remaining.Changes))
		}
	}
	return nil
}

func (p *linuxPreparedChange) Rollback(ctx context.Context) error {
	if p.applied > len(p.changes) {
		return errors.New("invalid bridge rollback state")
	}
	var first error
	if p.layer2Applied && p.layer2Plan != nil {
		if err := layer2.RollbackPlan(ctx, layer2RunnerAdapter{runner: p.runner}, *p.layer2Plan); err != nil {
			first = fmt.Errorf("restore Layer 2 topology: %w", err)
		}
	}
	for i := p.applied - 1; i >= 0; i-- {
		change := p.changes[i]
		_, err := p.runner.Run(ctx, "ip", "link", "set", "dev", change.iface, "type", "bridge", "fdb_max_learned", strconv.FormatUint(uint64(change.before), 10))
		if err != nil && first == nil {
			first = fmt.Errorf("restore bridge %s FDB limit: %w", change.iface, err)
		}
	}
	return first
}
