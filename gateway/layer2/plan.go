package layer2

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// HostRunner is the narrow command boundary consumed by this provider.
type HostRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
	Available(string) bool
}

type Command struct {
	Tool string
	Args []string
}

type Change struct {
	Description string
	Apply       Command
	Rollback    Command
}

type Plan struct {
	Changes []Change
}

// ApplyPlan executes a deterministic plan and reverses every completed change
// if an operation fails. Rollback errors are included in the returned error.
func ApplyPlan(ctx context.Context, runner HostRunner, plan Plan) error {
	completed := make([]Change, 0, len(plan.Changes))
	for _, change := range plan.Changes {
		if _, err := runner.Run(ctx, change.Apply.Tool, change.Apply.Args...); err != nil {
			rollbackErrors := []string{}
			rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			for i := len(completed) - 1; i >= 0; i-- {
				undo := completed[i]
				if undo.Rollback.Tool == "" {
					continue
				}
				if _, rollbackErr := runner.Run(rollbackCtx, undo.Rollback.Tool, undo.Rollback.Args...); rollbackErr != nil {
					rollbackErrors = append(rollbackErrors, fmt.Sprintf("%s: %v", undo.Description, rollbackErr))
				}
			}
			cancel()
			message := fmt.Sprintf("apply %s: %v", change.Description, err)
			if len(rollbackErrors) > 0 {
				message += "; rollback failed: " + strings.Join(rollbackErrors, "; ")
			}
			return errors.New(message)
		}
		completed = append(completed, change)
	}
	return nil
}

// RollbackPlan reverses a previously applied plan in reverse order.
func RollbackPlan(ctx context.Context, runner HostRunner, plan Plan) error {
	var failures []string
	for i := len(plan.Changes) - 1; i >= 0; i-- {
		undo := plan.Changes[i]
		if undo.Rollback.Tool == "" {
			continue
		}
		if _, err := runner.Run(ctx, undo.Rollback.Tool, undo.Rollback.Args...); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", undo.Description, err))
		}
	}
	if len(failures) != 0 {
		return errors.New(strings.Join(failures, "; "))
	}
	return nil
}

// BuildTopologyPlan builds additive bridge/VLAN operations. Existing objects
// are modified only when the previous desired configuration establishes that
// GameBond owns them; unmanaged bridges and port masters are never adopted.
func BuildTopologyPlan(previous, desired Config, host Capabilities) (Plan, error) {
	if err := desired.Validate(); err != nil {
		return Plan{}, fmt.Errorf("desired Layer 2 config: %w", err)
	}
	if previous.Version != 0 {
		if err := previous.Validate(); err != nil {
			return Plan{}, fmt.Errorf("current Layer 2 config: %w", err)
		}
	}
	if len(desired.Overrides) != 0 {
		return Plan{}, errors.New("virtual network overrides are not yet enforced by the Linux provider")
	}
	if capability, ok := host.Features[FeatureBridgeVLAN]; !ok || capability.State == CapabilityUnavailable || capability.State == CapabilityUnsupported {
		return Plan{}, fmt.Errorf("bridge VLAN capability is unavailable: %s", capability.Reason)
	}
	interfaces := make(map[string]HostInterface, len(host.Interfaces))
	for _, in := range host.Interfaces {
		interfaces[in.Name] = in
	}
	managedBridges := make(map[string]string, len(previous.Bridges))
	for _, br := range previous.Bridges {
		managedBridges[br.ID] = br.Name
	}
	managedPorts := make(map[string]string)
	for _, br := range previous.Bridges {
		for _, port := range br.Ports {
			for _, in := range previous.Interfaces {
				if in.ID == port.Interface {
					managedPorts[in.Name] = br.Name
				}
			}
		}
	}
	networkByID := make(map[string]Network, len(desired.Networks))
	for _, n := range desired.Networks {
		networkByID[n.ID] = n
	}
	interfaceByID := make(map[string]Interface, len(desired.Interfaces))
	for _, in := range desired.Interfaces {
		interfaceByID[in.ID] = in
	}
	plan := Plan{}
	currentVLANs := make(map[string]BridgeVLANState, len(host.BridgeVLANs))
	for _, vlan := range host.BridgeVLANs {
		currentVLANs[vlanKey(vlan.Device, vlan.VLAN)] = vlan
	}

	for _, bridge := range desired.Bridges {
		oldName, wasManaged := managedBridges[bridge.ID]
		if wasManaged && oldName != bridge.Name {
			return Plan{}, fmt.Errorf("managed bridge %q cannot be renamed from %q to %q in one apply", bridge.ID, oldName, bridge.Name)
		}
		liveBridge, exists := interfaces[bridge.Name]
		if exists && (!wasManaged || liveBridge.Kind != "bridge") {
			return Plan{}, fmt.Errorf("bridge name %q is already owned by an unmanaged or non-bridge interface", bridge.Name)
		}
		if !exists {
			plan.Changes = append(plan.Changes, Change{Description: "create bridge " + bridge.ID,
				Apply:    Command{Tool: "ip", Args: []string{"link", "add", "name", bridge.Name, "type", "bridge", "vlan_filtering", boolDigit(bridge.VLANFiltering)}},
				Rollback: Command{Tool: "ip", Args: []string{"link", "del", "dev", bridge.Name}}})
		}
		mtu := bridgeMTU(bridge, networkByID)
		if !exists || (liveBridge.MTU != 0 && liveBridge.MTU != mtu) {
			previousMTU := liveBridge.MTU
			if previousMTU == 0 {
				previousMTU = 1500
			}
			plan.Changes = append(plan.Changes, Change{Description: "set MTU on bridge " + bridge.ID,
				Apply:    Command{Tool: "ip", Args: []string{"link", "set", "dev", bridge.Name, "mtu", fmt.Sprint(mtu)}},
				Rollback: Command{Tool: "ip", Args: []string{"link", "set", "dev", bridge.Name, "mtu", fmt.Sprint(previousMTU)}}})
		}
		if exists && bridge.VLANFiltering != liveBridge.VLANFiltering {
			plan.Changes = append(plan.Changes, Change{Description: "enable VLAN filtering on bridge " + bridge.ID,
				Apply:    Command{Tool: "ip", Args: []string{"link", "set", "dev", bridge.Name, "type", "bridge", "vlan_filtering", boolDigit(bridge.VLANFiltering)}},
				Rollback: Command{Tool: "ip", Args: []string{"link", "set", "dev", bridge.Name, "type", "bridge", "vlan_filtering", boolDigit(liveBridge.VLANFiltering)}}})
		}
		if !exists || !liveBridge.AdminUp {
			undo := Command{}
			if exists {
				undo = Command{Tool: "ip", Args: []string{"link", "set", "dev", bridge.Name, "down"}}
			}
			plan.Changes = append(plan.Changes, Change{Description: "bring bridge up " + bridge.ID,
				Apply: Command{Tool: "ip", Args: []string{"link", "set", "dev", bridge.Name, "up"}}, Rollback: undo})
		}

		for _, port := range bridge.Ports {
			physical, ok := interfaceByID[port.Interface]
			if !ok {
				return Plan{}, fmt.Errorf("bridge %q references missing interface %q", bridge.ID, port.Interface)
			}
			livePort, exists := interfaces[physical.Name]
			if !exists {
				return Plan{}, fmt.Errorf("managed interface %q does not exist on the host", physical.Name)
			}
			if livePort.Master != "" && livePort.Master != bridge.Name && managedPorts[physical.Name] != livePort.Master {
				return Plan{}, fmt.Errorf("interface %q is attached to unmanaged master %q", physical.Name, livePort.Master)
			}
			if livePort.Master != bridge.Name {
				rollback := Command{Tool: "ip", Args: []string{"link", "set", "dev", physical.Name, "nomaster"}}
				if livePort.Master != "" {
					rollback = Command{Tool: "ip", Args: []string{"link", "set", "dev", physical.Name, "master", livePort.Master}}
				}
				plan.Changes = append(plan.Changes, Change{Description: "attach interface " + physical.ID + " to bridge " + bridge.ID,
					Apply: Command{Tool: "ip", Args: []string{"link", "set", "dev", physical.Name, "master", bridge.Name}}, Rollback: rollback})
			}
			if livePort.MTU != 0 && livePort.MTU != mtu {
				plan.Changes = append(plan.Changes, Change{Description: "set MTU on interface " + physical.ID,
					Apply:    Command{Tool: "ip", Args: []string{"link", "set", "dev", physical.Name, "mtu", fmt.Sprint(mtu)}},
					Rollback: Command{Tool: "ip", Args: []string{"link", "set", "dev", physical.Name, "mtu", fmt.Sprint(livePort.MTU)}}})
			}
			if !livePort.AdminUp {
				plan.Changes = append(plan.Changes, Change{Description: "bring interface up " + physical.ID,
					Apply:    Command{Tool: "ip", Args: []string{"link", "set", "dev", physical.Name, "up"}},
					Rollback: Command{Tool: "ip", Args: []string{"link", "set", "dev", physical.Name, "down"}}})
			}
			wanted := desiredPortVLANs(port, networkByID)
			for _, current := range host.BridgeVLANs {
				if current.Device == physical.Name && !containsVLAN(wanted, current.VLAN) {
					plan.Changes = append(plan.Changes, removeVLAN(physical.Name, current, false))
				}
			}
			for _, vlan := range wanted {
				if current, exists := currentVLANs[vlanKey(physical.Name, vlan.VLAN)]; exists && current.PVID == vlan.PVID && current.Untagged == vlan.Untagged {
					continue
				}
				if current, exists := currentVLANs[vlanKey(physical.Name, vlan.VLAN)]; exists {
					plan.Changes = append(plan.Changes, replaceVLAN(physical.Name, current, vlan, false)...)
				} else {
					plan.Changes = append(plan.Changes, addVLAN(physical.Name, vlan, false))
				}
			}
			if !containsVLAN(wanted, 1) {
				if _, exists := currentVLANs[vlanKey(physical.Name, 1)]; !exists {
					// The kernel creates a default PVID 1 when a port joins a
					// VLAN-filtering bridge. Remove it unless explicitly requested.
					plan.Changes = append(plan.Changes, Change{Description: "remove implicit VLAN 1 from " + physical.ID,
						Apply:    Command{Tool: "bridge", Args: []string{"vlan", "del", "dev", physical.Name, "vid", "1"}},
						Rollback: Command{Tool: "bridge", Args: []string{"vlan", "add", "dev", physical.Name, "vid", "1", "pvid", "untagged"}}})
				}
			}
		}

		for _, network := range desired.Networks {
			if network.Bridge != bridge.ID {
				continue
			}
			vlan := BridgeVLANState{Device: bridge.Name, VLAN: network.VLAN}
			if _, exists := currentVLANs[vlanKey(bridge.Name, network.VLAN)]; !exists {
				plan.Changes = append(plan.Changes, addVLAN(bridge.Name, vlan, true))
			}
		}
		if wasManaged {
			for _, current := range host.BridgeVLANs {
				if current.Device != bridge.Name || containsNetworkVLAN(desired.Networks, bridge.ID, current.VLAN) {
					continue
				}
				plan.Changes = append(plan.Changes, removeVLAN(bridge.Name, current, true))
			}
		}
	}

	return plan, nil
}

func bridgeMTU(bridge Bridge, networks map[string]Network) int {
	for _, port := range bridge.Ports {
		if port.UntaggedNetwork != "" {
			if network, ok := networks[port.UntaggedNetwork]; ok {
				return network.MTU
			}
		}
		for _, id := range port.TaggedNetworks {
			if network, ok := networks[id]; ok {
				return network.MTU
			}
		}
	}
	for _, network := range networks {
		if network.Bridge == bridge.ID {
			return network.MTU
		}
	}
	return 1500
}

func desiredPortVLANs(port BridgePort, networks map[string]Network) []BridgeVLANState {
	var out []BridgeVLANState
	if port.UntaggedNetwork != "" {
		if n, ok := networks[port.UntaggedNetwork]; ok {
			out = append(out, BridgeVLANState{Device: "", VLAN: n.VLAN, PVID: true, Untagged: true})
		}
	}
	for _, id := range port.TaggedNetworks {
		if n, ok := networks[id]; ok {
			out = append(out, BridgeVLANState{Device: "", VLAN: n.VLAN})
		}
	}
	return out
}

func containsVLAN(vlans []BridgeVLANState, id uint16) bool {
	for _, vlan := range vlans {
		if vlan.VLAN == id {
			return true
		}
	}
	return false
}

func containsNetworkVLAN(networks []Network, bridgeID string, vlan uint16) bool {
	for _, network := range networks {
		if network.Bridge == bridgeID && network.VLAN == vlan {
			return true
		}
	}
	return false
}

func addVLAN(device string, vlan BridgeVLANState, self bool) Change {
	args := []string{"vlan", "add", "dev", device, "vid", fmt.Sprint(vlan.VLAN)}
	if !self && vlan.PVID {
		args = append(args, "pvid")
	}
	if !self && vlan.Untagged {
		args = append(args, "untagged")
	}
	if self {
		args = append(args, "self")
	}
	delArgs := []string{"vlan", "del", "dev", device, "vid", fmt.Sprint(vlan.VLAN)}
	if self {
		delArgs = append(delArgs, "self")
	}
	return Change{Description: fmt.Sprintf("add VLAN %d on %s", vlan.VLAN, device), Apply: Command{Tool: "bridge", Args: args},
		Rollback: Command{Tool: "bridge", Args: delArgs}}
}

func removeVLAN(device string, vlan BridgeVLANState, self bool) Change {
	args := []string{"vlan", "del", "dev", device, "vid", fmt.Sprint(vlan.VLAN)}
	if self {
		args = append(args, "self")
	}
	return Change{Description: fmt.Sprintf("remove stale VLAN %d from %s", vlan.VLAN, device),
		Apply: Command{Tool: "bridge", Args: args}, Rollback: addVLAN(device, vlan, self).Apply}
}

func replaceVLAN(device string, old, desired BridgeVLANState, self bool) []Change {
	add := addVLAN(device, desired, self)
	oldAdd := addVLAN(device, old, self)
	return []Change{
		{Description: fmt.Sprintf("remove mismatched VLAN %d from %s", desired.VLAN, device),
			Apply: Command{Tool: "bridge", Args: []string{"vlan", "del", "dev", device, "vid", fmt.Sprint(old.VLAN)}}, Rollback: oldAdd.Apply},
		{Description: fmt.Sprintf("add desired VLAN %d to %s", desired.VLAN, device), Apply: add.Apply, Rollback: add.Rollback},
	}
}

func vlanKey(device string, vlan uint16) string { return fmt.Sprintf("%s/%d", device, vlan) }

func boolDigit(value bool) string {
	if value {
		return "1"
	}
	return "0"
}
