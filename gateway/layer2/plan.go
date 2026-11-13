package layer2

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// HostRunner is the narrow command boundary consumed by this provider.
type HostRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
	Available(string) bool
}

type Command struct {
	Tool  string
	Args  []string
	Input []byte
}

type Change struct {
	Description string
	Apply       Command
	Rollback    Command
}

type Plan struct {
	Changes []Change
}

const macBlockTableName = "gamebond_mac_block"
const macBlockTableMarker = "gamebond-mac-block:v1"
const macACLTableName = "gamebond_mac_acl"
const macACLTableMarker = "gamebond-mac-acl:v1"
const ipACLTableName = "gamebond_ip_acl"
const ipACLTableMarker = "gamebond-ip-acl:v1"

// ApplyPlan executes a deterministic plan and reverses every completed change
// if an operation fails. Rollback errors are included in the returned error.
func ApplyPlan(ctx context.Context, runner HostRunner, plan Plan) error {
	completed := make([]Change, 0, len(plan.Changes))
	for _, change := range plan.Changes {
		if _, err := runProviderCommand(ctx, runner, change.Apply); err != nil {
			rollbackErrors := []string{}
			rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			for i := len(completed) - 1; i >= 0; i-- {
				undo := completed[i]
				if undo.Rollback.Tool == "" {
					continue
				}
				if _, rollbackErr := runProviderCommand(rollbackCtx, runner, undo.Rollback); rollbackErr != nil {
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
		if _, err := runProviderCommand(ctx, runner, undo.Rollback); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", undo.Description, err))
		}
	}
	if len(failures) != 0 {
		return errors.New(strings.Join(failures, "; "))
	}
	return nil
}

func runProviderCommand(ctx context.Context, runner HostRunner, command Command) ([]byte, error) {
	if command.Input != nil {
		inputRunner, ok := runner.(interface {
			RunInput(context.Context, string, []byte, ...string) ([]byte, error)
		})
		if !ok {
			return nil, errors.New("host runner does not support provider input")
		}
		return inputRunner.RunInput(ctx, command.Tool, command.Input, command.Args...)
	}
	return runner.Run(ctx, command.Tool, command.Args...)
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
		capability, ok := host.Features[FeatureVirtualNet]
		if !ok || capability.State == CapabilityUnavailable || capability.State == CapabilityUnsupported {
			return Plan{}, fmt.Errorf("virtual network override capability is unavailable: %s", capability.Reason)
		}
	}
	for _, bridge := range desired.Bridges {
		for _, port := range bridge.Ports {
			if !port.Isolated {
				continue
			}
			capability, ok := host.Features[FeaturePortIsolation]
			if !ok || capability.State == CapabilityUnavailable || capability.State == CapabilityUnsupported {
				return Plan{}, fmt.Errorf("port isolation capability is unavailable: %s", capability.Reason)
			}
		}
	}
	if len(desired.MACPortRestrictions) > 0 {
		capability, ok := host.Features[FeatureMACPort]
		if !ok || capability.State == CapabilityUnavailable || capability.State == CapabilityUnsupported {
			return Plan{}, fmt.Errorf("MAC port restriction capability is unavailable: %s", capability.Reason)
		}
	}
	if len(desired.MACBlocks) > 0 {
		capability, ok := host.Features[FeatureMACBlock]
		if !ok || capability.State == CapabilityUnavailable || capability.State == CapabilityUnsupported {
			return Plan{}, fmt.Errorf("MAC address blocking capability is unavailable: %s", capability.Reason)
		}
	}
	if len(desired.MACACL) > 0 {
		capability, ok := host.Features[FeatureMACACL]
		if !ok || capability.State == CapabilityUnavailable || capability.State == CapabilityUnsupported {
			return Plan{}, fmt.Errorf("MAC ACL capability is unavailable: %s", capability.Reason)
		}
	}
	if len(desired.IPACL) > 0 {
		capability, ok := host.Features[FeatureIPACL]
		if !ok || capability.State == CapabilityUnavailable || capability.State == CapabilityUnsupported {
			return Plan{}, fmt.Errorf("IP ACL capability is unavailable: %s", capability.Reason)
		}
	}
	if len(desired.EgressRates) > 0 {
		capability, ok := host.Features[FeatureEgressRate]
		if !ok || capability.State == CapabilityUnavailable || capability.State == CapabilityUnsupported {
			return Plan{}, fmt.Errorf("egress rate limit capability is unavailable: %s", capability.Reason)
		}
	}
	if len(desired.FlowControl) > 0 {
		capability, ok := host.Features[FeatureFlowControl]
		if !ok || capability.State == CapabilityUnavailable || capability.State == CapabilityUnsupported {
			return Plan{}, fmt.Errorf("flow control capability is unavailable: %s", capability.Reason)
		}
	}
	if len(desired.Bridges) > 0 {
		if capability, ok := host.Features[FeatureBridgeVLAN]; !ok || capability.State == CapabilityUnavailable || capability.State == CapabilityUnsupported {
			return Plan{}, fmt.Errorf("bridge VLAN capability is unavailable: %s", capability.Reason)
		}
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
	bondChanges, bondTeardown, synthetic, err := buildBondChanges(previous, desired, interfaces, host.Features)
	if err != nil {
		return Plan{}, err
	}
	plan.Changes = append(plan.Changes, bondChanges...)
	for name, iface := range synthetic {
		interfaces[name] = iface
	}
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
		if mtu > 1500 && exists && (liveBridge.MaxMTU == 0 || mtu > liveBridge.MaxMTU) {
			return Plan{}, fmt.Errorf("bridge %q requested MTU %d exceeds or has unknown maximum MTU %d", bridge.ID, mtu, liveBridge.MaxMTU)
		}
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
			if mtu > 1500 && (livePort.MaxMTU == 0 || mtu > livePort.MaxMTU) {
				return Plan{}, fmt.Errorf("interface %q requested MTU %d exceeds or has unknown maximum MTU %d", physical.ID, mtu, livePort.MaxMTU)
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
			if !livePort.IsolationKnown && port.Isolated {
				return Plan{}, fmt.Errorf("port isolation state for interface %q is unknown", physical.ID)
			}
			if livePort.IsolationKnown && livePort.Isolated != port.Isolated {
				value, rollback := "off", "on"
				if port.Isolated {
					value, rollback = "on", "off"
				}
				plan.Changes = append(plan.Changes, Change{Description: "set port isolation on " + physical.ID,
					Apply:    Command{Tool: "bridge", Args: []string{"link", "set", "dev", physical.Name, "isolated", value}},
					Rollback: Command{Tool: "bridge", Args: []string{"link", "set", "dev", physical.Name, "isolated", rollback}}})
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
			for _, override := range desired.Overrides {
				if override.Interface == port.Interface {
					network := networkByID[override.Network]
					if !containsVLAN(wanted, network.VLAN) {
						wanted = append(wanted, BridgeVLANState{Device: physical.Name, VLAN: network.VLAN})
					}
				}
			}
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
	filterChanges, err := buildOverrideFilterChanges(previous, desired, interfaces)
	if err != nil {
		return Plan{}, err
	}
	plan.Changes = append(plan.Changes, filterChanges...)
	macPortChanges, err := buildMACPortRestrictionChanges(previous, desired, interfaces, host.BridgeFDB)
	if err != nil {
		return Plan{}, err
	}
	plan.Changes = append(plan.Changes, macPortChanges...)
	macBlockChange, err := buildMACBlockChange(previous, desired, host)
	if err != nil {
		return Plan{}, err
	}
	if macBlockChange != nil {
		plan.Changes = append(plan.Changes, *macBlockChange)
	}
	macACLChange, err := buildMACACLChange(previous, desired, host)
	if err != nil {
		return Plan{}, err
	}
	if macACLChange != nil {
		plan.Changes = append(plan.Changes, *macACLChange)
	}
	ipACLChange, err := buildIPACLChange(previous, desired, host)
	if err != nil {
		return Plan{}, err
	}
	if ipACLChange != nil {
		plan.Changes = append(plan.Changes, *ipACLChange)
	}
	egressChanges, err := buildEgressRateChanges(previous, desired, interfaces)
	if err != nil {
		return Plan{}, err
	}
	plan.Changes = append(plan.Changes, egressChanges...)
	networkEgressChanges, err := buildNetworkEgressRateChanges(previous, desired, interfaces)
	if err != nil {
		return Plan{}, err
	}
	plan.Changes = append(plan.Changes, networkEgressChanges...)
	flowChanges, err := buildFlowControlChanges(previous, desired, interfaces)
	if err != nil {
		return Plan{}, err
	}
	plan.Changes = append(plan.Changes, flowChanges...)
	plan.Changes = append(plan.Changes, bondTeardown...)

	return plan, nil
}

func buildFlowControlChanges(previous, desired Config, hostInterfaces map[string]HostInterface) ([]Change, error) {
	interfaces := map[string]string{}
	for _, in := range desired.Interfaces {
		interfaces[in.ID] = in.Name
	}
	for _, in := range previous.Interfaces {
		if interfaces[in.ID] == "" {
			interfaces[in.ID] = in.Name
		}
	}
	old := map[string]FlowControlPolicy{}
	for _, p := range previous.FlowControl {
		old[p.Interface] = p
	}
	wanted := map[string]FlowControlPolicy{}
	for _, p := range desired.FlowControl {
		wanted[p.Interface] = p
	}
	idsMap := map[string]bool{}
	for id := range old {
		idsMap[id] = true
	}
	for id := range wanted {
		idsMap[id] = true
	}
	ids := make([]string, 0, len(idsMap))
	for id := range idsMap {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	changes := []Change{}
	for _, id := range ids {
		name := interfaces[id]
		live, ok := hostInterfaces[name]
		if !ok {
			return nil, fmt.Errorf("flow control interface %q is absent", name)
		}
		if live.Kind == "bond" {
			return nil, fmt.Errorf("flow control cannot be configured on aggregate interface %q; configure physical member policy explicitly only after detaching it", name)
		}
		if live.Master != "" {
			if master, exists := hostInterfaces[live.Master]; exists && master.Kind == "bond" {
				return nil, fmt.Errorf("flow control policy cannot target aggregate member %q", name)
			}
		}
		if !live.PauseKnown {
			reason := live.PauseError
			if reason == "" {
				reason = "driver did not report effective RX/TX pause state"
			}
			return nil, fmt.Errorf("flow control is unavailable on %q: %s", name, reason)
		}
		prior, had := old[id]
		next, want := wanted[id]
		if want && live.PauseAutoneg == next.Autoneg && live.PauseRX == next.RX && live.PauseTX == next.TX {
			continue
		}
		if !want && had && live.PauseAutoneg == "on" && live.PauseRX && live.PauseTX {
			continue
		}
		if !want && !had {
			continue
		}
		if had && (live.PauseAutoneg != prior.Autoneg || live.PauseRX != prior.RX || live.PauseTX != prior.TX) {
			return nil, fmt.Errorf("flow control on %q differs from saved GameBond settings", name)
		}
		applyState := next
		if !want {
			applyState = FlowControlPolicy{Interface: id, Autoneg: "on", RX: true, TX: true}
		}
		apply := flowControlCommand(name, applyState)
		rollback := Command{Tool: "ethtool", Args: []string{"--pause", name, "autoneg", live.PauseAutoneg, "rx", boolOnOff(live.PauseRX), "tx", boolOnOff(live.PauseTX)}}
		changes = append(changes, Change{Description: "set Ethernet flow control on " + id, Apply: apply, Rollback: rollback})
	}
	return changes, nil
}

func flowControlCommand(name string, policy FlowControlPolicy) Command {
	return Command{Tool: "ethtool", Args: []string{"--pause", name, "autoneg", policy.Autoneg, "rx", boolOnOff(policy.RX), "tx", boolOnOff(policy.TX)}}
}

func boolOnOff(value bool) string {
	if value {
		return "on"
	}
	return "off"
}

func buildEgressRateChanges(previous, desired Config, hostInterfaces map[string]HostInterface) ([]Change, error) {
	interfaceNames := map[string]string{}
	for _, in := range desired.Interfaces {
		interfaceNames[in.ID] = in.Name
	}
	old := map[string]EgressRateLimit{}
	for _, r := range previous.EgressRates {
		if r.Network != "" {
			continue
		}
		old[r.Interface] = r
	}
	wanted := map[string]EgressRateLimit{}
	for _, r := range desired.EgressRates {
		if r.Network != "" {
			continue
		}
		wanted[r.Interface] = r
	}
	ids := map[string]bool{}
	for id := range old {
		ids[id] = true
	}
	for id := range wanted {
		ids[id] = true
	}
	ordered := make([]string, 0, len(ids))
	for id := range ids {
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)
	changes := []Change{}
	for _, id := range ordered {
		name := interfaceNames[id]
		if name == "" {
			for _, in := range previous.Interfaces {
				if in.ID == id {
					name = in.Name
				}
			}
		}
		live, ok := hostInterfaces[name]
		if !ok {
			return nil, fmt.Errorf("egress rate interface %q is missing on the host", name)
		}
		prior, had := old[id]
		next, want := wanted[id]
		if want && live.RootQdisc == "tbf" && live.RootQdiscRateBPS == next.RateBPS && live.RootQdiscBurstBytes == next.BurstBytes {
			continue
		}
		if !want && had && live.RootQdisc == "noqueue" {
			continue
		}
		if had {
			if live.RootQdisc != "tbf" || live.RootQdiscRateBPS != prior.RateBPS || live.RootQdiscBurstBytes != prior.BurstBytes {
				return nil, fmt.Errorf("egress TBF on %q differs from saved GameBond rate policy", name)
			}
		} else if want && live.RootQdisc != "noqueue" {
			return nil, fmt.Errorf("egress rate on %q requires an unmanaged-free noqueue root; found %q", name, live.RootQdisc)
		}
		if !want && !had {
			continue
		}
		if want && had && next == prior {
			continue
		}
		apply := Command{Tool: "tc"}
		rollback := Command{Tool: "tc"}
		if want {
			apply.Args = []string{"qdisc", "replace", "dev", name, "root", "handle", "7fff:", "tbf", "rate", fmt.Sprint(next.RateBPS) + "bit", "burst", fmt.Sprint(next.BurstBytes) + "b", "latency", "50ms"}
		} else {
			apply.Args = []string{"qdisc", "del", "dev", name, "root"}
		}
		if had {
			rollback.Args = []string{"qdisc", "replace", "dev", name, "root", "handle", "7fff:", "tbf", "rate", fmt.Sprint(prior.RateBPS) + "bit", "burst", fmt.Sprint(prior.BurstBytes) + "b", "latency", "50ms"}
		} else {
			rollback.Args = []string{"qdisc", "del", "dev", name, "root"}
		}
		changes = append(changes, Change{Description: "apply egress TBF rate on " + id, Apply: apply, Rollback: rollback})
	}
	return changes, nil
}

func egressFilterPriority(vlan uint16) int { return 45000 + int(vlan) }

func egressFilterCommand(verb, device string, rate EgressRateLimit, vlan uint16) Command {
	priority := egressFilterPriority(vlan)
	args := []string{"filter", verb, "dev", device, "egress", "pref", fmt.Sprint(priority)}
	if rate.Network == "" {
		args = append(args, "protocol", "all", "matchall")
	} else {
		args = append(args, "protocol", "802.1Q", "flower", "skip_hw", "vlan_id", fmt.Sprint(vlan))
	}
	args = append(args, "action", "police", "rate", fmt.Sprint(rate.RateBPS)+"bit", "burst", fmt.Sprint(rate.BurstBytes)+"b", "drop")
	return Command{Tool: "tc", Args: args}
}

func expectedEgressFilter(rate EgressRateLimit, vlan uint16) TCFilterState {
	kind := "matchall"
	if rate.Network != "" {
		kind = "flower"
	}
	return TCFilterState{Priority: egressFilterPriority(vlan), Kind: kind, VLANID: vlan, NumVLANs: -1, PoliceRateBPS: rate.RateBPS, PoliceBurstBytes: rate.BurstBytes}
}

func buildNetworkEgressRateChanges(previous, desired Config, hostInterfaces map[string]HostInterface) ([]Change, error) {
	old := map[string]EgressRateLimit{}
	for _, r := range previous.EgressRates {
		if r.Network != "" {
			old[r.Interface+"/"+r.Network] = r
		}
	}
	wanted := map[string]EgressRateLimit{}
	for _, r := range desired.EgressRates {
		if r.Network != "" {
			wanted[r.Interface+"/"+r.Network] = r
		}
	}
	keysMap := map[string]bool{}
	for k := range old {
		keysMap[k] = true
	}
	for k := range wanted {
		keysMap[k] = true
	}
	keys := make([]string, 0, len(keysMap))
	for k := range keysMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	interfaces := map[string]string{}
	for _, in := range desired.Interfaces {
		interfaces[in.ID] = in.Name
	}
	for _, in := range previous.Interfaces {
		if interfaces[in.ID] == "" {
			interfaces[in.ID] = in.Name
		}
	}
	networks := map[string]Network{}
	for _, n := range desired.Networks {
		networks[n.ID] = n
	}
	changes := []Change{}
	qdiscAdded := map[string]bool{}
	for _, key := range keys {
		prior, had := old[key]
		next, want := wanted[key]
		scope := next
		if !want {
			scope = prior
		}
		name := interfaces[scope.Interface]
		live, ok := hostInterfaces[name]
		if !ok {
			return nil, fmt.Errorf("network egress rate interface %q is absent", name)
		}
		vlan, ok := networks[scope.Network]
		if !ok {
			for _, n := range previous.Networks {
				if n.ID == scope.Network {
					vlan = n
					ok = true
					break
				}
			}
		}
		if !ok {
			return nil, fmt.Errorf("network egress rate references missing VLAN %q", scope.Network)
		}
		priority := egressFilterPriority(vlan.VLAN)
		var actual *TCFilterState
		for i := range live.TCEgressFilters {
			filter := &live.TCEgressFilters[i]
			if filter.Priority == priority {
				if actual != nil {
					return nil, fmt.Errorf("interface %q has multiple egress filters at reserved priority %d", name, priority)
				}
				actual = filter
			}
		}
		if actual != nil {
			expected := expectedEgressFilter(scope, vlan.VLAN)
			if actual.Kind != expected.Kind || actual.VLANID != expected.VLANID || actual.PoliceRateBPS != scope.RateBPS || actual.PoliceBurstBytes != scope.BurstBytes {
				if !had || !equalTCFilter(*actual, expectedEgressFilter(prior, vlan.VLAN)) {
					return nil, fmt.Errorf("egress filter priority %d on %q is not owned by the saved GameBond policy", priority, name)
				}
			}
		}
		if want && actual != nil && actual.Kind == expectedEgressFilter(next, vlan.VLAN).Kind && actual.VLANID == vlan.VLAN && actual.PoliceRateBPS == next.RateBPS && actual.PoliceBurstBytes == next.BurstBytes {
			continue
		}
		if !want && actual == nil {
			continue
		}
		if want && !live.TCClsact && !qdiscAdded[name] {
			if live.LegacyIngress {
				return nil, fmt.Errorf("interface %q has legacy ingress qdisc and cannot add clsact for egress policing", name)
			}
			changes = append(changes, Change{Description: "create clsact qdisc for egress rate limits on " + name, Apply: Command{Tool: "tc", Args: []string{"qdisc", "add", "dev", name, "clsact"}}, Rollback: Command{Tool: "tc", Args: []string{"qdisc", "del", "dev", name, "clsact"}}})
			qdiscAdded[name] = true
		}
		apply := Command{Tool: "tc"}
		rollback := Command{Tool: "tc"}
		if want {
			verb := "replace"
			apply = egressFilterCommand(verb, name, next, vlan.VLAN)
		} else {
			apply = Command{Tool: "tc", Args: []string{"filter", "del", "dev", name, "egress", "pref", fmt.Sprint(priority)}}
		}
		if had {
			rollback = egressFilterCommand("replace", name, prior, vlan.VLAN)
		} else {
			rollback = Command{Tool: "tc", Args: []string{"filter", "del", "dev", name, "egress", "pref", fmt.Sprint(priority)}}
		}
		changes = append(changes, Change{Description: "apply network egress rate on " + scope.Interface + "/" + scope.Network, Apply: apply, Rollback: rollback})
	}
	return changes, nil
}

func buildIPACLChange(previous, desired Config, host Capabilities) (*Change, error) {
	oldComments, wantedComments := ipACLRuleComments(previous), ipACLRuleComments(desired)
	if host.IPACLTablePresent {
		actual := mapKeys(host.IPACLRuleCounters)
		if !host.IPACLTableManaged {
			return nil, fmt.Errorf("nftables bridge table %q is not marked as GameBond-owned", ipACLTableName)
		}
		if exactStringSet(actual, wantedComments) {
			return nil, nil
		}
		if len(previous.IPACL) > 0 && !exactStringSet(actual, oldComments) {
			return nil, fmt.Errorf("nftables bridge table %q differs from saved GameBond IP ACL", ipACLTableName)
		}
		if len(previous.IPACL) == 0 && !exactStringSet(actual, wantedComments) {
			return nil, fmt.Errorf("nftables bridge table %q already exists and is not owned by this IP ACL config", ipACLTableName)
		}
	}
	if len(previous.IPACL) == 0 && len(desired.IPACL) == 0 {
		return nil, nil
	}
	apply := Command{Tool: "nft", Args: []string{"-f", "-"}}
	if len(desired.IPACL) == 0 {
		if !host.IPACLTablePresent {
			return nil, nil
		}
		apply.Input = []byte("delete table bridge " + ipACLTableName + "\n")
	} else {
		apply.Input = renderIPACLTable(desired, host.IPACLTablePresent)
	}
	rollback := Command{Tool: "nft", Args: []string{"-f", "-"}}
	if len(previous.IPACL) == 0 {
		rollback.Input = []byte("delete table bridge " + ipACLTableName + "\n")
	} else {
		rollback.Input = renderIPACLTable(previous, len(desired.IPACL) != 0)
	}
	return &Change{Description: "apply ordered GameBond IP ACL", Apply: apply, Rollback: rollback}, nil
}

func renderIPACLTable(cfg Config, replace bool) []byte {
	var script strings.Builder
	if replace {
		script.WriteString("delete table bridge " + ipACLTableName + "\n")
	}
	script.WriteString("add table bridge " + ipACLTableName + " { comment \"" + ipACLTableMarker + "\"; }\n")
	for _, chain := range []string{"forward", "input", "output"} {
		script.WriteString("add chain bridge " + ipACLTableName + " " + chain + " { type filter hook " + chain + " priority -180; policy accept; }\n")
	}
	interfaces := map[string]string{}
	for _, in := range cfg.Interfaces {
		interfaces[in.ID] = in.Name
	}
	networks := map[string]Network{}
	for _, n := range cfg.Networks {
		networks[n.ID] = n
	}
	ports := map[string]BridgePort{}
	for _, b := range cfg.Bridges {
		for _, p := range b.Ports {
			ports[p.Interface] = p
		}
	}
	for _, r := range cfg.IPACL {
		name, p, n := interfaces[r.Interface], ports[r.Interface], networks[r.Network]
		family := "ip"
		if r.Family == "ipv6" {
			family = "ip6"
		}
		matches := []string{family + " version " + map[bool]string{true: "6", false: "4"}[r.Family == "ipv6"]}
		if r.Source != "" {
			matches = append(matches, family+" saddr "+r.Source)
		}
		if r.Dest != "" {
			matches = append(matches, family+" daddr "+r.Dest)
		}
		if r.Protocol != "" {
			matches = append(matches, "meta l4proto "+r.Protocol)
		}
		if r.Port != 0 {
			matches = append(matches, "th dport "+fmt.Sprint(r.Port))
		}
		if p.UntaggedNetwork != r.Network {
			matches = append(matches, "vlan id "+fmt.Sprint(n.VLAN))
		}
		action := "drop"
		if r.Action == "allow" {
			action = "accept"
		}
		type inst struct{ chain, iface, comment string }
		installs := []inst{}
		if r.Direction == "ingress" || r.Direction == "both" {
			installs = append(installs, inst{"forward", `iifname "` + name + `" `, "in"}, inst{"input", `iifname "` + name + `" `, "host-in"})
		}
		if r.Direction == "egress" || r.Direction == "both" {
			installs = append(installs, inst{"forward", `oifname "` + name + `" `, "out"}, inst{"output", `oifname "` + name + `" `, "host-out"})
		}
		for _, i := range installs {
			script.WriteString("add rule bridge " + ipACLTableName + " " + i.chain + " " + i.iface + strings.Join(matches, " ") + " counter " + action + " comment \"gamebond-ip-acl:" + r.ID + ":" + i.comment + "\"\n")
		}
	}
	return []byte(script.String())
}

func buildMACACLChange(previous, desired Config, host Capabilities) (*Change, error) {
	oldComments, wantedComments := macACLRuleComments(previous), macACLRuleComments(desired)
	if host.MACACLTablePresent {
		actual := mapKeys(host.MACACLRuleCounters)
		if !host.MACACLTableManaged {
			return nil, fmt.Errorf("nftables bridge table %q is not marked as GameBond-owned", macACLTableName)
		}
		if exactStringSet(actual, wantedComments) {
			return nil, nil
		}
		if len(previous.MACACL) > 0 && !exactStringSet(actual, oldComments) {
			return nil, fmt.Errorf("nftables bridge table %q differs from the saved GameBond MAC ACL", macACLTableName)
		}
		if len(previous.MACACL) == 0 && !exactStringSet(actual, wantedComments) {
			return nil, fmt.Errorf("nftables bridge table %q already exists and is not owned by this MAC ACL configuration", macACLTableName)
		}
	}
	if len(previous.MACACL) == 0 && len(desired.MACACL) == 0 {
		return nil, nil
	}
	apply := Command{Tool: "nft", Args: []string{"-f", "-"}}
	if len(desired.MACACL) == 0 {
		if !host.MACACLTablePresent {
			return nil, nil
		}
		apply.Input = []byte("delete table bridge " + macACLTableName + "\n")
	} else {
		apply.Input = renderMACACLTable(desired, host.MACACLTablePresent)
	}
	rollback := Command{Tool: "nft", Args: []string{"-f", "-"}}
	if len(previous.MACACL) == 0 {
		rollback.Input = []byte("delete table bridge " + macACLTableName + "\n")
	} else {
		rollback.Input = renderMACACLTable(previous, len(desired.MACACL) != 0)
	}
	return &Change{Description: "apply ordered GameBond MAC ACL", Apply: apply, Rollback: rollback}, nil
}

func renderMACACLTable(cfg Config, replace bool) []byte {
	var script strings.Builder
	if replace {
		script.WriteString("delete table bridge " + macACLTableName + "\n")
	}
	script.WriteString("add table bridge " + macACLTableName + " { comment \"" + macACLTableMarker + "\"; }\n")
	for _, chain := range []string{"forward", "input", "output"} {
		script.WriteString("add chain bridge " + macACLTableName + " " + chain + " { type filter hook " + chain + " priority -190; policy accept; }\n")
	}
	interfaces := make(map[string]string, len(cfg.Interfaces))
	for _, in := range cfg.Interfaces {
		interfaces[in.ID] = in.Name
	}
	networks := make(map[string]Network, len(cfg.Networks))
	for _, n := range cfg.Networks {
		networks[n.ID] = n
	}
	ports := make(map[string]BridgePort)
	for _, b := range cfg.Bridges {
		for _, p := range b.Ports {
			ports[p.Interface] = p
		}
	}
	for _, rule := range cfg.MACACL {
		name, port, network := interfaces[rule.Interface], ports[rule.Interface], networks[rule.Network]
		vlan := ""
		if port.UntaggedNetwork != rule.Network {
			vlan = " vlan id " + fmt.Sprint(network.VLAN)
		}
		matches := []string{}
		if rule.SourceMAC != "" {
			matches = append(matches, "ether saddr "+rule.SourceMAC)
		}
		if rule.DestinationMAC != "" {
			matches = append(matches, "ether daddr "+rule.DestinationMAC)
		}
		l2 := strings.Join(matches, " ") + vlan
		action := "drop"
		if rule.Action == "allow" {
			action = "accept"
		}
		type aclInstall struct{ chain, portMatch, suffix string }
		installs := []aclInstall{}
		if rule.Direction == "ingress" || rule.Direction == "both" {
			installs = append(installs, aclInstall{"forward", "iifname \"" + name + "\" ", "forward-in"}, aclInstall{"input", "iifname \"" + name + "\" ", "input"})
		}
		if rule.Direction == "egress" || rule.Direction == "both" {
			installs = append(installs, aclInstall{"forward", "oifname \"" + name + "\" ", "forward-out"}, aclInstall{"output", "oifname \"" + name + "\" ", "output"})
		}
		base := "gamebond-mac-acl:" + rule.ID + ":"
		for _, install := range installs {
			script.WriteString("add rule bridge " + macACLTableName + " " + install.chain + " " + install.portMatch + l2 + " counter " + action + " comment \"" + base + install.suffix + "\"\n")
		}
	}
	return []byte(script.String())
}

func buildMACBlockChange(previous, desired Config, host Capabilities) (*Change, error) {
	oldComments, wantedComments := macBlockRuleComments(previous), macBlockRuleComments(desired)
	if host.MACBlockTablePresent {
		actualComments := mapKeys(host.MACBlockRuleCounters)
		if !host.MACBlockTableManaged {
			return nil, fmt.Errorf("nftables bridge table %q is not marked as GameBond-owned", macBlockTableName)
		}
		if exactStringSet(actualComments, wantedComments) {
			return nil, nil
		}
		if len(previous.MACBlocks) != 0 && !exactStringSet(actualComments, oldComments) {
			return nil, fmt.Errorf("nftables bridge table %q differs from the saved GameBond MAC block policy", macBlockTableName)
		}
		if len(previous.MACBlocks) == 0 && !exactStringSet(actualComments, wantedComments) {
			return nil, fmt.Errorf("nftables bridge table %q already exists and is not owned by this MAC block configuration", macBlockTableName)
		}
	}
	if len(previous.MACBlocks) == 0 && len(desired.MACBlocks) == 0 {
		return nil, nil
	}
	apply := Command{Tool: "nft", Args: []string{"-f", "-"}}
	if len(desired.MACBlocks) == 0 {
		if !host.MACBlockTablePresent {
			return nil, nil
		}
		apply.Input = []byte("delete table bridge " + macBlockTableName + "\n")
	} else {
		apply.Input = renderMACBlockTable(desired, host.MACBlockTablePresent)
	}
	rollback := Command{Tool: "nft", Args: []string{"-f", "-"}}
	if len(previous.MACBlocks) == 0 {
		rollback.Input = []byte("delete table bridge " + macBlockTableName + "\n")
	} else {
		rollback.Input = renderMACBlockTable(previous, len(desired.MACBlocks) != 0)
	}
	return &Change{Description: "apply GameBond MAC address blocking policy", Apply: apply, Rollback: rollback}, nil
}

func renderMACBlockTable(cfg Config, replace bool) []byte {
	var script strings.Builder
	if replace {
		script.WriteString("delete table bridge " + macBlockTableName + "\n")
	}
	script.WriteString("add table bridge " + macBlockTableName + " { comment \"" + macBlockTableMarker + "\"; }\n")
	for _, chain := range []string{"forward", "input", "output"} {
		script.WriteString("add chain bridge " + macBlockTableName + " " + chain + " { type filter hook " + chain + " priority -200; policy accept; }\n")
	}
	interfaces := make(map[string]string, len(cfg.Interfaces))
	for _, in := range cfg.Interfaces {
		interfaces[in.ID] = in.Name
	}
	networks := make(map[string]Network, len(cfg.Networks))
	for _, network := range cfg.Networks {
		networks[network.ID] = network
	}
	ports := make(map[string]BridgePort)
	for _, bridge := range cfg.Bridges {
		for _, port := range bridge.Ports {
			ports[port.Interface] = port
		}
	}
	blocks := append([]MACBlock(nil), cfg.MACBlocks...)
	sort.Slice(blocks, func(i, j int) bool {
		if blocks[i].Interface != blocks[j].Interface {
			return blocks[i].Interface < blocks[j].Interface
		}
		if blocks[i].Network != blocks[j].Network {
			return blocks[i].Network < blocks[j].Network
		}
		return blocks[i].MAC < blocks[j].MAC
	})
	for _, block := range blocks {
		name, port, network := interfaces[block.Interface], ports[block.Interface], networks[block.Network]
		vlan := ""
		if port.UntaggedNetwork != block.Network {
			vlan = " vlan id " + fmt.Sprint(network.VLAN)
		}
		base := "gamebond-mac-block:" + block.Interface + ":" + block.Network + ":" + block.MAC + ":"
		rules := []struct{ chain, match, suffix string }{
			{"forward", "iifname \"" + name + "\" ether saddr " + block.MAC + vlan, "forward-in"},
			{"forward", "oifname \"" + name + "\" ether daddr " + block.MAC + vlan, "forward-out"},
			{"input", "iifname \"" + name + "\" ether saddr " + block.MAC + vlan, "input"},
			{"output", "oifname \"" + name + "\" ether daddr " + block.MAC + vlan, "output"},
		}
		for _, rule := range rules {
			script.WriteString("add rule bridge " + macBlockTableName + " " + rule.chain + " " + rule.match + " counter drop comment \"" + base + rule.suffix + "\"\n")
		}
	}
	return []byte(script.String())
}

func buildMACPortRestrictionChanges(previous, desired Config, interfaces map[string]HostInterface, fdb []BridgeFDBEntry) ([]Change, error) {
	type restrictionState struct {
		restriction MACPortRestriction
		vlan        uint16
		bridge      string
	}
	index := func(cfg Config) map[string]restrictionState {
		out := make(map[string]restrictionState, len(cfg.MACPortRestrictions))
		for _, restriction := range cfg.MACPortRestrictions {
			in := interfaceByID(cfg.Interfaces, restriction.Interface)
			network := networkByID(cfg.Networks, restriction.Network)
			bridgeName := ""
			for _, bridge := range cfg.Bridges {
				for _, port := range bridge.Ports {
					if port.Interface == restriction.Interface {
						bridgeName = bridge.Name
					}
				}
			}
			out[in.Name] = restrictionState{restriction: restriction, vlan: network.VLAN, bridge: bridgeName}
		}
		return out
	}
	old, wanted := index(previous), index(desired)
	devices := make(map[string]bool, len(old)+len(wanted))
	for name := range old {
		devices[name] = true
	}
	for name := range wanted {
		devices[name] = true
	}
	names := make([]string, 0, len(devices))
	for name := range devices {
		names = append(names, name)
	}
	sort.Strings(names)
	fdbByMACVLAN := make(map[string]BridgeFDBEntry, len(fdb))
	for _, entry := range fdb {
		fdbByMACVLAN[entry.MAC+"/"+fmt.Sprint(entry.VLAN)] = entry
	}
	var changes []Change
	for _, name := range names {
		live, exists := interfaces[name]
		if !exists {
			return nil, fmt.Errorf("MAC port restriction interface %q is absent", name)
		}
		prior, hadPrior := old[name]
		desiredState, hasDesired := wanted[name]
		if hasDesired || hadPrior {
			if !live.BridgePortKnown {
				return nil, fmt.Errorf("MAC port restriction state for interface %q is unknown", name)
			}
		}
		if hasDesired {
			for _, candidate := range interfaces {
				if candidate.Master == desiredState.bridge && candidate.Name != name {
					return nil, fmt.Errorf("MAC port restriction on %q requires the bridge to have no other attached ports", name)
				}
			}
		}
		bridgeName := desiredState.bridge
		if bridgeName == "" {
			bridgeName = prior.bridge
		}
		bridge, bridgeExists := interfaces[bridgeName]
		if !bridgeExists {
			return nil, fmt.Errorf("MAC port restriction bridge %q is absent", bridgeName)
		}
		if hasDesired && !bridge.FDBLimitKnown {
			return nil, fmt.Errorf("bridge %q does not report learned-FDB limit support", bridgeName)
		}
		if hadPrior && !bridge.FDBLimitKnown {
			return nil, fmt.Errorf("bridge %q learned-FDB limit state is unknown", bridgeName)
		}
		oldAllowed := make(map[string]bool)
		if hadPrior {
			for _, mac := range prior.restriction.AllowedMACs {
				oldAllowed[mac+"/"+fmt.Sprint(prior.vlan)] = true
			}
		}
		newAllowed := make(map[string]bool)
		if hasDesired {
			for _, mac := range desiredState.restriction.AllowedMACs {
				newAllowed[mac+"/"+fmt.Sprint(desiredState.vlan)] = true
			}
		}
		newReady := hasDesired && live.Locked && bridge.FDBMaxLearned == desiredState.restriction.MaxDevices
		for key := range newAllowed {
			entry, found := fdbByMACVLAN[key]
			if !found || entry.Device != name || !entry.Static {
				newReady = false
			}
		}
		if !hasDesired {
			removed := hadPrior && !live.Locked && bridge.FDBMaxLearned == 0
			for key := range oldAllowed {
				if _, found := fdbByMACVLAN[key]; found {
					removed = false
				}
			}
			if removed {
				continue
			}
		}
		if !hadPrior && (live.Locked || bridge.FDBMaxLearned != 0) && !newReady {
			return nil, fmt.Errorf("interface %q has unmanaged bridge port restriction state", name)
		}
		if hadPrior && hasDesired && !newReady && (live.Locked != true || bridge.FDBMaxLearned != prior.restriction.MaxDevices) {
			return nil, fmt.Errorf("managed MAC port restriction on %q has drifted from its saved state", name)
		}
		for key := range newAllowed {
			entry, found := fdbByMACVLAN[key]
			if found && ((!oldAllowed[key] && !newReady) || entry.Device != name || !entry.Static) {
				return nil, fmt.Errorf("MAC/VLAN FDB entry %s is not owned by the GameBond policy", key)
			}
			if !found {
				parts := strings.Split(key, "/")
				changes = append(changes, Change{Description: "authorize MAC on restricted port " + name,
					Apply:    Command{Tool: "bridge", Args: []string{"fdb", "replace", parts[0], "dev", name, "master", "static", "vlan", parts[1]}},
					Rollback: Command{Tool: "bridge", Args: []string{"fdb", "del", parts[0], "dev", name, "master", "vlan", parts[1]}}})
			}
		}
		if hasDesired {
			if !live.Locked {
				changes = append(changes, Change{Description: "lock bridge port " + name,
					Apply:    Command{Tool: "bridge", Args: []string{"link", "set", "dev", name, "locked", "on"}},
					Rollback: Command{Tool: "bridge", Args: []string{"link", "set", "dev", name, "locked", "off"}}})
			}
			if bridge.FDBMaxLearned != desiredState.restriction.MaxDevices {
				changes = append(changes, Change{Description: "set learned-device limit on " + name,
					Apply:    Command{Tool: "ip", Args: []string{"link", "set", "dev", bridgeName, "type", "bridge", "fdb_max_learned", fmt.Sprint(desiredState.restriction.MaxDevices)}},
					Rollback: Command{Tool: "ip", Args: []string{"link", "set", "dev", bridgeName, "type", "bridge", "fdb_max_learned", fmt.Sprint(bridge.FDBMaxLearned)}}})
			}
		} else if hadPrior {
			if live.Locked {
				changes = append(changes, Change{Description: "unlock bridge port " + name,
					Apply:    Command{Tool: "bridge", Args: []string{"link", "set", "dev", name, "locked", "off"}},
					Rollback: Command{Tool: "bridge", Args: []string{"link", "set", "dev", name, "locked", "on"}}})
			}
			if bridge.FDBMaxLearned != 0 {
				changes = append(changes, Change{Description: "clear learned-device limit on " + name,
					Apply:    Command{Tool: "ip", Args: []string{"link", "set", "dev", bridgeName, "type", "bridge", "fdb_max_learned", "0"}},
					Rollback: Command{Tool: "ip", Args: []string{"link", "set", "dev", bridgeName, "type", "bridge", "fdb_max_learned", fmt.Sprint(bridge.FDBMaxLearned)}}})
			}
		}
		for key := range oldAllowed {
			if newAllowed[key] {
				continue
			}
			entry, found := fdbByMACVLAN[key]
			if !found {
				continue
			}
			if entry.Device != name || !entry.Static {
				return nil, fmt.Errorf("managed MAC/VLAN FDB entry %s on %q has drifted", key, name)
			}
			parts := strings.Split(key, "/")
			changes = append(changes, Change{Description: "remove authorized MAC from restricted port " + name,
				Apply:    Command{Tool: "bridge", Args: []string{"fdb", "del", parts[0], "dev", name, "master", "vlan", parts[1]}},
				Rollback: Command{Tool: "bridge", Args: []string{"fdb", "replace", parts[0], "dev", name, "master", "static", "vlan", parts[1]}}})
		}
	}
	return changes, nil
}

func expectedOverrideFilters(cfg Config) map[string][]TCFilterState {
	byInterface := make(map[string][]DeviceOverride)
	for _, override := range cfg.Overrides {
		in := interfaceByID(cfg.Interfaces, override.Interface)
		byInterface[in.Name] = append(byInterface[in.Name], override)
	}
	filters := make(map[string][]TCFilterState, len(byInterface))
	for name, overrides := range byInterface {
		sort.Slice(overrides, func(i, j int) bool { return overrides[i].MAC < overrides[j].MAC })
		filters[name] = append(filters[name], TCFilterState{Priority: 1, Kind: "flower", NumVLANs: 1, HasNumVLANs: true, DropTagged: true})
		for i, override := range overrides {
			network := networkByID(cfg.Networks, override.Network)
			filters[name] = append(filters[name], TCFilterState{Priority: i + 2, Kind: "flower", SourceMAC: override.MAC,
				NumVLANs: 0, HasNumVLANs: true, VLANAction: "push", VLANControl: "pass", VLANID: network.VLAN})
		}
	}
	return filters
}

func networkByID(networks []Network, id string) Network {
	for _, network := range networks {
		if network.ID == id {
			return network
		}
	}
	return Network{}
}

func equalTCFilter(a, b TCFilterState) bool { return a == b }

func buildOverrideFilterChanges(previous, desired Config, hostInterfaces map[string]HostInterface) ([]Change, error) {
	oldFilters, wantedFilters := expectedOverrideFilters(previous), expectedOverrideFilters(desired)
	devices := make(map[string]bool, len(oldFilters)+len(wantedFilters))
	for name := range oldFilters {
		devices[name] = true
	}
	for name := range wantedFilters {
		devices[name] = true
	}
	names := make([]string, 0, len(devices))
	for name := range devices {
		names = append(names, name)
	}
	sort.Strings(names)
	var changes []Change
	for _, name := range names {
		live, exists := hostInterfaces[name]
		if !exists {
			return nil, fmt.Errorf("virtual network override interface %q is absent", name)
		}
		if live.LegacyIngress && !live.TCClsact {
			return nil, fmt.Errorf("interface %q has a legacy ingress qdisc; convert it to clsact before applying virtual network overrides", name)
		}
		oldByPriority := make(map[int]TCFilterState, len(oldFilters[name]))
		wantedByPriority := make(map[int]TCFilterState, len(wantedFilters[name]))
		for _, filter := range oldFilters[name] {
			oldByPriority[filter.Priority] = filter
		}
		for _, filter := range wantedFilters[name] {
			wantedByPriority[filter.Priority] = filter
		}
		actualByPriority := make(map[int]TCFilterState, len(live.TCFilters))
		for _, actual := range live.TCFilters {
			if actual.Priority < 1 || actual.Priority <= MaxDeviceOverrides+1 {
				old, managed := oldByPriority[actual.Priority]
				if !managed || !equalTCFilter(actual, old) {
					return nil, fmt.Errorf("interface %q has an unmanaged ingress filter in reserved virtual network override priority %d", name, actual.Priority)
				}
			}
			if _, duplicate := actualByPriority[actual.Priority]; duplicate {
				return nil, fmt.Errorf("interface %q has multiple ingress filters at priority %d", name, actual.Priority)
			}
			actualByPriority[actual.Priority] = actual
		}
		if len(wantedFilters[name]) > 0 && !live.TCClsact {
			changes = append(changes, Change{Description: "create clsact qdisc for virtual network overrides on " + name,
				Apply:    Command{Tool: "tc", Args: []string{"qdisc", "add", "dev", name, "clsact"}},
				Rollback: Command{Tool: "tc", Args: []string{"qdisc", "del", "dev", name, "clsact"}}})
		}
		wantedPriorities := make([]int, 0, len(wantedByPriority))
		for priority := range wantedByPriority {
			wantedPriorities = append(wantedPriorities, priority)
		}
		sort.Ints(wantedPriorities)
		for _, priority := range wantedPriorities {
			wanted := wantedByPriority[priority]
			actual, exists := actualByPriority[priority]
			if exists && equalTCFilter(actual, wanted) {
				continue
			}
			command := tcFilterCommand("add", name, wanted)
			rollback := tcFilterDelete(name, priority)
			if exists {
				old, managed := oldByPriority[priority]
				if !managed || !equalTCFilter(actual, old) {
					return nil, fmt.Errorf("interface %q ingress filter priority %d is not owned by GameBond", name, priority)
				}
				command = tcFilterCommand("replace", name, wanted)
				rollback = tcFilterCommand("replace", name, old)
			}
			changes = append(changes, Change{Description: fmt.Sprintf("apply virtual network override filter %d on %s", priority, name), Apply: command, Rollback: rollback})
		}
		oldPriorities := make([]int, 0, len(oldByPriority))
		for priority := range oldByPriority {
			oldPriorities = append(oldPriorities, priority)
		}
		sort.Ints(oldPriorities)
		for _, priority := range oldPriorities {
			old := oldByPriority[priority]
			if _, remains := wantedByPriority[priority]; remains {
				continue
			}
			if actual, exists := actualByPriority[priority]; exists && equalTCFilter(actual, old) {
				changes = append(changes, Change{Description: fmt.Sprintf("remove virtual network override filter %d from %s", priority, name),
					Apply: tcFilterDelete(name, priority), Rollback: tcFilterCommand("add", name, old)})
			}
		}
	}
	return changes, nil
}

func tcFilterCommand(verb, device string, filter TCFilterState) Command {
	args := []string{"filter", verb, "dev", device, "ingress", "protocol", "all", "pref", fmt.Sprint(filter.Priority), "flower"}
	if filter.DropTagged {
		args = append(args, "num_of_vlans", "1", "action", "drop")
	} else {
		args = append(args, "src_mac", filter.SourceMAC, "num_of_vlans", "0", "action", "vlan", "push", "protocol", "802.1Q", "id", fmt.Sprint(filter.VLANID), "pass")
	}
	return Command{Tool: "tc", Args: args}
}

func tcFilterDelete(device string, priority int) Command {
	return Command{Tool: "tc", Args: []string{"filter", "del", "dev", device, "ingress", "pref", fmt.Sprint(priority)}}
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
