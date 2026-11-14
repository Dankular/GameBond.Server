package layer2

import (
	"context"
	"crypto/sha256"
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
const networkIsolationTableName = "gamebond_l2_isolation"
const networkIsolationTableMarker = "gamebond-l2-isolation:v1"
const dhcpGuardTableName = "gamebond_dhcp_guard"
const dhcpGuardTableMarker = "gamebond-dhcp-guard:v1"

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
	if len(desired.PortAuth) > 0 {
		capability, ok := host.Features[Feature8021X]
		if !ok || capability.State == CapabilityUnavailable || capability.State == CapabilityUnsupported {
			reason := capability.Reason
			if reason == "" {
				reason = "authenticator and bridge traffic enforcement are not integrated"
			}
			return Plan{}, fmt.Errorf("802.1X port authentication is unavailable: %s", reason)
		}
		if host.PortAuthTablePresent && !host.PortAuthTableManaged {
			return Plan{}, fmt.Errorf("nftables bridge table %q exists but is not marked as GameBond-owned", portAuthTableName)
		}
		if host.PortAuthTablePresent && len(previous.PortAuth) == 0 && len(desired.PortAuth) > 0 {
			return Plan{}, fmt.Errorf("nftables bridge table %q does not match the saved 802.1X config", portAuthTableName)
		}
	}
	voiceVLAN, lldpMED := false, false
	for _, bridge := range desired.Bridges {
		for _, port := range bridge.Ports {
			voiceVLAN = voiceVLAN || port.VoiceNetwork != ""
			lldpMED = lldpMED || len(port.LLDPMED) > 0
		}
	}
	for _, requirement := range []struct {
		enabled bool
		feature string
		name    string
	}{{voiceVLAN, FeatureVoiceVLAN, "Voice VLAN"}, {lldpMED, FeatureLLDPMED, "LLDP-MED"}} {
		if !requirement.enabled {
			continue
		}
		capability, ok := host.Features[requirement.feature]
		if !ok || capability.State == CapabilityUnavailable || capability.State == CapabilityUnsupported {
			return Plan{}, fmt.Errorf("%s capability is unavailable: %s", requirement.name, capability.Reason)
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
	if len(desired.DHCPGuard) > 0 || len(previous.DHCPGuard) > 0 {
		capability, ok := host.Features[FeatureDHCPSnoop]
		if !ok || capability.State == CapabilityUnavailable || capability.State == CapabilityUnsupported {
			return Plan{}, fmt.Errorf("DHCP guarding capability is unavailable: %s", capability.Reason)
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
	if len(desired.NetworkACL) > 0 || len(previous.NetworkACL) > 0 {
		capability, ok := host.Features[FeatureNetworkIsolation]
		if !ok || capability.State == CapabilityUnavailable || capability.State == CapabilityUnsupported {
			return Plan{}, fmt.Errorf("routed network isolation capability is unavailable: %s", capability.Reason)
		}
	}
	if len(desired.EgressRates) > 0 || mirrorCaptureRate(previous) > 0 || mirrorCaptureRate(desired) > 0 {
		capability, ok := host.Features[FeatureEgressRate]
		if !ok || capability.State == CapabilityUnavailable || capability.State == CapabilityUnsupported {
			return Plan{}, fmt.Errorf("egress rate limit capability is unavailable: %s", capability.Reason)
		}
	}
	if len(desired.StormControl) > 0 || len(previous.StormControl) > 0 {
		capability, ok := host.Features[FeatureStormControl]
		if !ok || capability.State == CapabilityUnavailable || capability.State == CapabilityUnsupported {
			return Plan{}, fmt.Errorf("storm control capability is unavailable: %s", capability.Reason)
		}
		for _, policy := range desired.StormControl {
			if policy.MulticastRateBPS == 0 {
				continue
			}
			capability, ok := host.Features[FeatureMultiRate]
			if !ok || capability.State == CapabilityUnavailable || capability.State == CapabilityUnsupported {
				return Plan{}, fmt.Errorf("multicast/broadcast rate-limit capability is unavailable: %s", capability.Reason)
			}
		}
	}
	if len(desired.MulticastBroadcastLimits) > 0 || len(previous.MulticastBroadcastLimits) > 0 {
		capability, ok := host.Features[FeatureMultiRate]
		if !ok || capability.State == CapabilityUnavailable || capability.State == CapabilityUnsupported {
			return Plan{}, fmt.Errorf("multicast/broadcast rate-limit capability is unavailable: %s", capability.Reason)
		}
	}
	if len(desired.FlowControl) > 0 {
		capability, ok := host.Features[FeatureFlowControl]
		if !ok || capability.State == CapabilityUnavailable || capability.State == CapabilityUnsupported {
			return Plan{}, fmt.Errorf("flow control capability is unavailable: %s", capability.Reason)
		}
	}
	if len(desired.QoS) > 0 {
		capability, ok := host.Features[FeatureQoSDSCP]
		if !ok || capability.State == CapabilityUnavailable || capability.State == CapabilityUnsupported {
			return Plan{}, fmt.Errorf("DSCP QoS capability is unavailable: %s", capability.Reason)
		}
	}
	if len(desired.PortMirrors) > 0 || len(previous.PortMirrors) > 0 {
		capability, ok := host.Features[FeaturePortMirror]
		if !ok || capability.State == CapabilityUnavailable || capability.State == CapabilityUnsupported {
			return Plan{}, fmt.Errorf("port mirroring capability is unavailable: %s", capability.Reason)
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
	if err := validateAVProfileHost(desired, host); err != nil {
		return Plan{}, err
	}
	for _, policy := range desired.QoS {
		iface, ok := findInterface(desired.Interfaces, policy.Interface)
		if !ok {
			return Plan{}, fmt.Errorf("QoS interface %q is missing", policy.Interface)
		}
		live, ok := interfaces[iface.Name]
		if !ok {
			return Plan{}, fmt.Errorf("QoS interface %q is absent from host inventory", iface.Name)
		}
		if live.Kind == "bond" {
			return Plan{}, fmt.Errorf("DSCP QoS requires a physical interface or bridge port; aggregate %q is not supported", iface.Name)
		}
		if !live.LinkSpeedKnown {
			return Plan{}, fmt.Errorf("QoS link speed is unknown on %q", iface.Name)
		}
		if policy.LinkRateBPS > live.LinkSpeedBPS {
			return Plan{}, fmt.Errorf("configured QoS link rate on %q exceeds detected link speed", iface.Name)
		}
	}
	usesSnooping, usesVLANIGMP, usesAdvancedIGMP, usesSTP, usesRSTP, usesLoopProtection := false, false, false, false, false, false
	for _, bridge := range desired.Bridges {
		usesSTP = usesSTP || bridge.STPEnabled != nil || bridge.STPMode != "" || bridge.STPPriority != nil
		usesRSTP = usesRSTP || bridge.STPMode != ""
		usesSnooping = usesSnooping || bridge.IGMPSnooping != nil
		usesAdvancedIGMP = usesAdvancedIGMP || bridge.IGMPQuerier != nil
		for _, port := range bridge.Ports {
			usesSTP = usesSTP || port.STPPriority != nil || port.STPPathCost != nil || port.STPRootBlock != nil
			usesRSTP = usesRSTP || port.STPEdge != nil || port.STPPointToPoint != "" || port.STPBPDUGuard != nil
			usesLoopProtection = usesLoopProtection || port.LoopProtection != nil
			usesAdvancedIGMP = usesAdvancedIGMP || port.IGMPFastLeave != nil || port.IGMPRouterPort != nil
		}
	}
	// Reconciliation may disable settings that were previously managed, so
	// controller ownership must gate teardown as well as configuration.
	for _, bridge := range previous.Bridges {
		usesSTP = usesSTP || bridge.STPEnabled != nil || bridge.STPMode != "" || bridge.STPPriority != nil
		usesRSTP = usesRSTP || bridge.STPMode != ""
		for _, port := range bridge.Ports {
			usesSTP = usesSTP || port.STPPriority != nil || port.STPPathCost != nil || port.STPRootBlock != nil
			usesRSTP = usesRSTP || port.STPEdge != nil || port.STPPointToPoint != "" || port.STPBPDUGuard != nil
		}
	}
	for _, network := range append(append([]Network(nil), previous.Networks...), desired.Networks...) {
		usesVLANIGMP = usesVLANIGMP || network.IGMPSnooping != nil
	}
	if usesSTP {
		capability, ok := host.Features[FeatureSTP]
		if !ok || capability.State == CapabilityUnavailable || capability.State == CapabilityUnsupported {
			return Plan{}, fmt.Errorf("STP capability is unavailable: %s", capability.Reason)
		}
		if discovery := host.STPControllerDiscovery; discovery == nil || !discovery.Known {
			reason := "local controller discovery was not performed"
			if discovery != nil && discovery.Reason != "" {
				reason = discovery.Reason
			}
			return Plan{}, fmt.Errorf("STP controller ownership is ambiguous: %s", reason)
		} else if discovery.Conflict {
			return Plan{}, fmt.Errorf("STP controller ownership conflict with %s: %s", discovery.Controller, discovery.Reason)
		}
	}
	if usesRSTP {
		capability, ok := host.Features[FeatureRSTP]
		if !ok || capability.State == CapabilityUnavailable || capability.State == CapabilityUnsupported {
			return Plan{}, fmt.Errorf("STP protocol selection capability is unavailable: %s", capability.Reason)
		}
	}
	if usesLoopProtection {
		capability, ok := host.Features[FeatureLoopProtect]
		if !ok || capability.State == CapabilityUnavailable || capability.State == CapabilityUnsupported {
			return Plan{}, fmt.Errorf("loop-protection capability is unavailable: %s", capability.Reason)
		}
	}
	if usesSnooping {
		capability, ok := host.Features[FeatureIGMPSnoop]
		if !ok || capability.State == CapabilityUnavailable || capability.State == CapabilityUnsupported {
			return Plan{}, fmt.Errorf("IGMP snooping capability is unavailable: %s", capability.Reason)
		}
	}
	if usesAdvancedIGMP {
		capability, ok := host.Features[FeatureIGMPAdvanced]
		if !ok || capability.State == CapabilityUnavailable || capability.State == CapabilityUnsupported {
			return Plan{}, fmt.Errorf("advanced IGMP capability is unavailable: %s", capability.Reason)
		}
	}
	if usesVLANIGMP {
		capability, ok := host.Features[FeatureIGMPVLAN]
		if !ok || capability.State == CapabilityUnavailable || capability.State == CapabilityUnsupported {
			return Plan{}, fmt.Errorf("per-VLAN IGMP snooping capability is unavailable: %s", capability.Reason)
		}
	}
	managedBridges := make(map[string]string, len(previous.Bridges))
	previousBridgeByID := make(map[string]Bridge, len(previous.Bridges))
	for _, br := range previous.Bridges {
		managedBridges[br.ID] = br.Name
		previousBridgeByID[br.ID] = br
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
	currentVLANIGMP := make(map[string]bool, len(host.BridgeVLANGLOBALs))
	for _, state := range host.BridgeVLANGLOBALs {
		currentVLANIGMP[vlanKey(state.Bridge, state.VLAN)] = state.Snooping
	}

	for _, bridge := range desired.Bridges {
		oldName, wasManaged := managedBridges[bridge.ID]
		if wasManaged && oldName != bridge.Name {
			return Plan{}, fmt.Errorf("managed bridge %q cannot be renamed from %q to %q in one apply", bridge.ID, oldName, bridge.Name)
		}
		liveBridge, exists := interfaces[bridge.Name]
		oldBridge, hadOldBridge := previousBridgeByID[bridge.ID]
		targetSnooping, targetQuerier, targetSTP := bridge.IGMPSnooping, bridge.IGMPQuerier, bridge.STPEnabled
		targetSTPPriority := bridge.STPPriority
		if hadOldBridge && targetSTPPriority == nil && oldBridge.STPPriority != nil {
			value := uint16(32768)
			targetSTPPriority = &value
		}
		if bridge.STPMode != "" {
			value := true
			targetSTP = &value
		}
		if hadOldBridge && bridge.STPMode == "" && targetSTP == nil && (oldBridge.STPMode != "" || oldBridge.STPEnabled != nil) {
			value := false
			targetSTP = &value
		}
		if hadOldBridge && targetSnooping == nil && oldBridge.IGMPSnooping != nil {
			value := true
			targetSnooping = &value
		}
		if hadOldBridge && targetQuerier == nil && oldBridge.IGMPQuerier != nil {
			value := false
			targetQuerier = &value
		}
		if hadOldBridge && targetSTP == nil && oldBridge.STPEnabled != nil {
			value := false
			targetSTP = &value
		}
		targetSTPMode := bridge.STPMode
		bridgeWantsVLANIGMP, bridgeHadVLANIGMP := false, false
		for _, network := range desired.Networks {
			bridgeWantsVLANIGMP = bridgeWantsVLANIGMP || (network.Bridge == bridge.ID && network.IGMPSnooping != nil)
		}
		for _, network := range previous.Networks {
			bridgeHadVLANIGMP = bridgeHadVLANIGMP || (network.Bridge == bridge.ID && network.IGMPSnooping != nil)
		}
		if exists && (!wasManaged || liveBridge.Kind != "bridge") {
			return Plan{}, fmt.Errorf("bridge name %q is already owned by an unmanaged or non-bridge interface", bridge.Name)
		}
		if !exists {
			args := []string{"link", "add", "name", bridge.Name, "type", "bridge", "vlan_filtering", boolDigit(bridge.VLANFiltering)}
			if targetSTPPriority != nil {
				args = append(args, "priority", fmt.Sprint(*targetSTPPriority))
			}
			if targetSnooping != nil {
				args = append(args, "mcast_snooping", boolDigit(*targetSnooping))
			}
			if targetQuerier != nil {
				args = append(args, "mcast_querier", boolDigit(*targetQuerier))
			}
			if bridgeWantsVLANIGMP {
				args = append(args, "mcast_vlan_snooping", "1")
			}
			if targetSTP != nil {
				args = append(args, "stp_state", boolDigit(*targetSTP))
			}
			plan.Changes = append(plan.Changes, Change{Description: "create bridge " + bridge.ID,
				Apply:    Command{Tool: "ip", Args: args},
				Rollback: Command{Tool: "ip", Args: []string{"link", "del", "dev", bridge.Name}}})
		}
		if exists && (bridgeWantsVLANIGMP || bridgeHadVLANIGMP) {
			if !liveBridge.IGMPVLANKnown {
				return Plan{}, fmt.Errorf("per-VLAN IGMP mode for bridge %q is unknown; refusing to change it without a rollback value", bridge.Name)
			}
			if liveBridge.IGMPVLANMode != bridgeWantsVLANIGMP {
				value, rollback := boolDigit(bridgeWantsVLANIGMP), boolDigit(liveBridge.IGMPVLANMode)
				plan.Changes = append(plan.Changes, Change{Description: "enable per-VLAN IGMP snooping mode on " + bridge.ID,
					Apply:    Command{Tool: "ip", Args: []string{"link", "set", "dev", bridge.Name, "type", "bridge", "mcast_vlan_snooping", value}},
					Rollback: Command{Tool: "ip", Args: []string{"link", "set", "dev", bridge.Name, "type", "bridge", "mcast_vlan_snooping", rollback}}})
			}
		}
		if exists && targetSTP != nil && *targetSTP != liveBridge.STPEnabled {
			if !liveBridge.STPKnown {
				return Plan{}, fmt.Errorf("STP state for bridge %q is unknown; refusing to change it without a rollback value", bridge.Name)
			}
			value, rollback := boolDigit(*targetSTP), boolDigit(liveBridge.STPEnabled)
			plan.Changes = append(plan.Changes, Change{Description: "configure STP on " + bridge.ID,
				Apply:    Command{Tool: "ip", Args: []string{"link", "set", "dev", bridge.Name, "type", "bridge", "stp_state", value}},
				Rollback: Command{Tool: "ip", Args: []string{"link", "set", "dev", bridge.Name, "type", "bridge", "stp_state", rollback}}})
		}
		if exists && targetSTPPriority != nil && *targetSTPPriority != liveBridge.STPPriority {
			if !liveBridge.STPPriorityKnown {
				return Plan{}, fmt.Errorf("STP bridge priority for %q is unknown; refusing to change it without a rollback value", bridge.Name)
			}
			plan.Changes = append(plan.Changes, Change{Description: "configure STP bridge priority on " + bridge.ID,
				Apply:    Command{Tool: "ip", Args: []string{"link", "set", "dev", bridge.Name, "type", "bridge", "priority", fmt.Sprint(*targetSTPPriority)}},
				Rollback: Command{Tool: "ip", Args: []string{"link", "set", "dev", bridge.Name, "type", "bridge", "priority", fmt.Sprint(liveBridge.STPPriority)}}})
		}
		if targetSTPMode != "" && (!exists || !liveBridge.STPModeKnown || targetSTPMode != liveBridge.STPMode) {
			if exists && !liveBridge.STPModeKnown {
				return Plan{}, fmt.Errorf("spanning-tree protocol mode for bridge %q is unknown; refusing to change it without a rollback value", bridge.Name)
			}
			rollbackMode := liveBridge.STPMode
			if rollbackMode == "" && hadOldBridge {
				rollbackMode = oldBridge.STPMode
			}
			if rollbackMode == "" {
				rollbackMode = "stp"
			}
			plan.Changes = append(plan.Changes, Change{Description: "set spanning-tree protocol on " + bridge.ID,
				Apply:    Command{Tool: "mstpctl", Args: []string{"setforcevers", bridge.Name, targetSTPMode}},
				Rollback: Command{Tool: "mstpctl", Args: []string{"setforcevers", bridge.Name, rollbackMode}}})
		}
		bridgeIGMPChanged := (targetSnooping != nil && *targetSnooping != liveBridge.IGMPSnooping) || (targetQuerier != nil && *targetQuerier != liveBridge.IGMPQuerier)
		if exists && bridgeIGMPChanged {
			if !liveBridge.IGMPBridgeKnown {
				return Plan{}, fmt.Errorf("IGMP bridge state for %q is unknown; refusing to change it without a rollback value", bridge.Name)
			}
			args, rollback := []string{"link", "set", "dev", bridge.Name, "type", "bridge"}, []string{"link", "set", "dev", bridge.Name, "type", "bridge"}
			if targetSnooping != nil {
				args = append(args, "mcast_snooping", boolDigit(*targetSnooping))
				rollback = append(rollback, "mcast_snooping", boolDigit(liveBridge.IGMPSnooping))
			}
			if targetQuerier != nil {
				args = append(args, "mcast_querier", boolDigit(*targetQuerier))
				rollback = append(rollback, "mcast_querier", boolDigit(liveBridge.IGMPQuerier))
			}
			plan.Changes = append(plan.Changes, Change{Description: "configure IGMP snooping and querier on " + bridge.ID,
				Apply: Command{Tool: "ip", Args: args}, Rollback: Command{Tool: "ip", Args: rollback}})
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
			var oldPort *BridgePort
			if hadOldBridge {
				for i := range oldBridge.Ports {
					if oldBridge.Ports[i].Interface == port.Interface {
						oldPort = &oldBridge.Ports[i]
						break
					}
				}
			}
			targetFastLeave, targetRouterPort := port.IGMPFastLeave, port.IGMPRouterPort
			targetSTPPortPriority, targetSTPPathCost, targetSTPRootBlock := port.STPPriority, port.STPPathCost, port.STPRootBlock
			targetSTPEdge, targetSTPPointToPoint, targetSTPBPDUGuard := port.STPEdge, port.STPPointToPoint, port.STPBPDUGuard
			if oldPort != nil {
				if targetSTPPortPriority == nil && oldPort.STPPriority != nil {
					value := uint8(32)
					targetSTPPortPriority = &value
				}
				if targetSTPRootBlock == nil && oldPort.STPRootBlock != nil {
					value := false
					targetSTPRootBlock = &value
				}
				if targetSTPEdge == nil && oldPort.STPEdge != nil {
					value := false
					targetSTPEdge = &value
				}
				if targetSTPPointToPoint == "" && oldPort.STPPointToPoint != "" {
					targetSTPPointToPoint = "auto"
				}
				if targetSTPBPDUGuard == nil && oldPort.STPBPDUGuard != nil {
					value := false
					targetSTPBPDUGuard = &value
				}
			}
			if oldPort != nil && targetFastLeave == nil && oldPort.IGMPFastLeave != nil {
				value := false
				targetFastLeave = &value
			}
			if oldPort != nil && targetRouterPort == nil && oldPort.IGMPRouterPort != nil {
				value := false
				targetRouterPort = &value
			}
			physical, ok := interfaceByID[port.Interface]
			if !ok {
				return Plan{}, fmt.Errorf("bridge %q references missing interface %q", bridge.ID, port.Interface)
			}
			livePort, exists := interfaces[physical.Name]
			if !exists {
				return Plan{}, fmt.Errorf("managed interface %q does not exist on the host", physical.Name)
			}
			if oldPort != nil && targetSTPPathCost == nil && oldPort.STPPathCost != nil {
				value, ok := defaultLinuxBridgePathCost(livePort)
				if !ok {
					return Plan{}, fmt.Errorf("link speed for interface %q is unknown; cannot safely reset its STP path cost", physical.ID)
				}
				targetSTPPathCost = &value
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
			if targetSTPPortPriority != nil || targetSTPPathCost != nil || targetSTPRootBlock != nil {
				if !livePort.STPPortKnown {
					return Plan{}, fmt.Errorf("STP port state for interface %q is unknown; refusing to change it without rollback values", physical.ID)
				}
				for _, setting := range []struct {
					name             string
					desired, current string
				}{
					{"priority", optionalInt(targetSTPPortPriority), fmt.Sprint(livePort.STPPortPriority)},
					{"cost", optionalUint32(targetSTPPathCost), fmt.Sprint(livePort.STPPathCost)},
					{"root_block", optionalBool(targetSTPRootBlock), boolOnOff(livePort.STPRootBlock)},
				} {
					if setting.desired == "" || setting.desired == setting.current {
						continue
					}
					plan.Changes = append(plan.Changes, Change{Description: "configure STP " + setting.name + " on " + physical.ID,
						Apply:    Command{Tool: "bridge", Args: []string{"link", "set", "dev", physical.Name, setting.name, setting.desired}},
						Rollback: Command{Tool: "bridge", Args: []string{"link", "set", "dev", physical.Name, setting.name, setting.current}}})
				}
			}
			if targetSTPEdge != nil || targetSTPPointToPoint != "" || targetSTPBPDUGuard != nil {
				if !livePort.STPAdvancedKnown {
					return Plan{}, fmt.Errorf("advanced RSTP port state for interface %q is unknown; refusing to change it without rollback values", physical.ID)
				}
				for _, setting := range []struct{ name, command, desired, current string }{
					{"edge", "setportadminedge", optionalBoolYesNo(targetSTPEdge), boolYesNo(livePort.STPEdge)},
					{"point-to-point", "setportp2p", targetSTPPointToPoint, livePort.STPPointToPoint},
					{"BPDU guard", "setbpduguard", optionalBoolYesNo(targetSTPBPDUGuard), boolYesNo(livePort.STPBPDUGuard)},
				} {
					if setting.desired == "" || setting.desired == setting.current {
						continue
					}
					plan.Changes = append(plan.Changes, Change{Description: "configure RSTP " + setting.name + " on " + physical.ID,
						Apply:    Command{Tool: "mstpctl", Args: []string{setting.command, bridge.Name, physical.Name, setting.desired}},
						Rollback: Command{Tool: "mstpctl", Args: []string{setting.command, bridge.Name, physical.Name, setting.current}}})
				}
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
			desiredRouterMode := 0
			if enabled(targetRouterPort) {
				desiredRouterMode = 2
			}
			if oldPort != nil && port.IGMPRouterPort == nil && oldPort.IGMPRouterPort != nil {
				desiredRouterMode = 1
			}
			igmpPortChanged := (targetFastLeave != nil && *targetFastLeave != livePort.IGMPFastLeave) || (targetRouterPort != nil && desiredRouterMode != livePort.IGMPRouterMode)
			if igmpPortChanged {
				if !livePort.IGMPPortKnown {
					return Plan{}, fmt.Errorf("IGMP port state for interface %q is unknown; refusing to change it without a rollback value", physical.ID)
				}
				args, rollback := []string{"link", "set", "dev", physical.Name}, []string{"link", "set", "dev", physical.Name}
				if targetFastLeave != nil {
					fastLeave, oldFastLeave := "off", "off"
					if *targetFastLeave {
						fastLeave = "on"
					}
					if livePort.IGMPFastLeave {
						oldFastLeave = "on"
					}
					args = append(args, "fastleave", fastLeave)
					rollback = append(rollback, "fastleave", oldFastLeave)
				}
				if targetRouterPort != nil {
					args = append(args, "mcast_router", fmt.Sprint(desiredRouterMode))
					rollback = append(rollback, "mcast_router", fmt.Sprint(livePort.IGMPRouterMode))
				}
				plan.Changes = append(plan.Changes, Change{Description: "configure IGMP port behavior on " + physical.ID,
					Apply: Command{Tool: "bridge", Args: args}, Rollback: Command{Tool: "bridge", Args: rollback}})
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
			if network.IGMPSnooping != nil {
				key := vlanKey(bridge.Name, network.VLAN)
				old, known := currentVLANIGMP[key]
				_, vlanAlreadyPresent := currentVLANs[key]
				if exists && vlanAlreadyPresent && !known {
					return Plan{}, fmt.Errorf("per-VLAN IGMP state for %s VLAN %d is unknown; refusing to change it without a rollback value", bridge.Name, network.VLAN)
				}
				if !known {
					old = true
				}
				if old != *network.IGMPSnooping {
					plan.Changes = append(plan.Changes, Change{Description: "configure per-VLAN IGMP snooping on " + network.ID,
						Apply:    Command{Tool: "bridge", Args: []string{"vlan", "global", "set", "dev", bridge.Name, "vid", fmt.Sprint(network.VLAN), "mcast_snooping", boolDigit(*network.IGMPSnooping)}},
						Rollback: Command{Tool: "bridge", Args: []string{"vlan", "global", "set", "dev", bridge.Name, "vid", fmt.Sprint(network.VLAN), "mcast_snooping", boolDigit(old)}}})
				}
			}
		}
		for _, oldNetwork := range previous.Networks {
			if oldNetwork.Bridge != bridge.ID || oldNetwork.IGMPSnooping == nil {
				continue
			}
			stillConfigured := false
			for _, network := range desired.Networks {
				if network.ID == oldNetwork.ID && network.IGMPSnooping != nil {
					stillConfigured = true
					break
				}
			}
			if stillConfigured {
				continue
			}
			key := vlanKey(bridge.Name, oldNetwork.VLAN)
			old, known := currentVLANIGMP[key]
			if !known {
				return Plan{}, fmt.Errorf("per-VLAN IGMP state for %s VLAN %d is unknown; refusing to reset it without a rollback value", bridge.Name, oldNetwork.VLAN)
			}
			if !old {
				plan.Changes = append(plan.Changes, Change{Description: "reset per-VLAN IGMP snooping on " + oldNetwork.ID,
					Apply:    Command{Tool: "bridge", Args: []string{"vlan", "global", "set", "dev", bridge.Name, "vid", fmt.Sprint(oldNetwork.VLAN), "mcast_snooping", "1"}},
					Rollback: Command{Tool: "bridge", Args: []string{"vlan", "global", "set", "dev", bridge.Name, "vid", fmt.Sprint(oldNetwork.VLAN), "mcast_snooping", "0"}}})
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
	bridgeTeardown, err := buildBridgeTeardownChanges(previous, desired, host, interfaces)
	if err != nil {
		return Plan{}, err
	}
	plan.Changes = append(plan.Changes, bridgeTeardown...)
	filterChanges, err := buildOverrideFilterChanges(previous, desired, interfaces)
	if err != nil {
		return Plan{}, err
	}
	plan.Changes = append(plan.Changes, filterChanges...)
	portMirrorChanges, err := buildPortMirrorChanges(previous, desired, interfaces)
	if err != nil {
		return Plan{}, err
	}
	plan.Changes = append(plan.Changes, portMirrorChanges...)
	stormChanges, err := buildStormControlChanges(previous, desired, interfaces)
	if err != nil {
		return Plan{}, err
	}
	plan.Changes = append(plan.Changes, stormChanges...)
	multiRateChanges, err := buildMulticastBroadcastRateChanges(previous, desired, interfaces)
	if err != nil {
		return Plan{}, err
	}
	plan.Changes = append(plan.Changes, multiRateChanges...)
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
	dhcpGuardChange, err := buildDHCPGuardChange(previous, desired, host)
	if err != nil {
		return Plan{}, err
	}
	if dhcpGuardChange != nil {
		plan.Changes = append(plan.Changes, *dhcpGuardChange)
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
	networkIsolationChange, err := buildNetworkIsolationChange(previous, desired, host)
	if err != nil {
		return Plan{}, err
	}
	if networkIsolationChange != nil {
		plan.Changes = append(plan.Changes, *networkIsolationChange)
	}
	egressChanges, err := buildEgressRateChanges(previous, desired, interfaces)
	if err != nil {
		return Plan{}, err
	}
	plan.Changes = append(plan.Changes, egressChanges...)
	mirrorEgressChanges, err := buildEgressRateChanges(mirrorCaptureConfig(previous), mirrorCaptureConfig(desired), interfaces)
	if err != nil {
		return Plan{}, err
	}
	plan.Changes = append(plan.Changes, mirrorEgressChanges...)
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
	eapolChanges, err := buildEAPOLForwardChanges(previous, desired, host)
	if err != nil {
		return Plan{}, err
	}
	plan.Changes = append(plan.Changes, eapolChanges...)
	portAuthChange, err := buildPortAuthChange(previous, desired, host)
	if err != nil {
		return Plan{}, err
	}
	if portAuthChange != nil {
		plan.Changes = append(plan.Changes, *portAuthChange)
	}
	plan.Changes = append(plan.Changes, bondTeardown...)
	plan.Changes = dedupeClsactQdiscAdds(plan.Changes)

	return plan, nil
}

func buildBridgeTeardownChanges(previous, desired Config, host Capabilities, liveInterfaces map[string]HostInterface) ([]Change, error) {
	desiredBridges := make(map[string]Bridge, len(desired.Bridges))
	desiredPortBridge := make(map[string]string)
	for _, bridge := range desired.Bridges {
		desiredBridges[bridge.ID] = bridge
		for _, port := range bridge.Ports {
			desiredPortBridge[port.Interface] = bridge.ID
		}
	}
	changes := []Change{}
	for _, oldBridge := range previous.Bridges {
		newBridge, retained := desiredBridges[oldBridge.ID]
		retainedPorts := map[string]bool{}
		if retained {
			for _, port := range newBridge.Ports {
				retainedPorts[port.Interface] = true
			}
		}
		for _, oldPort := range oldBridge.Ports {
			if retained && retainedPorts[oldPort.Interface] {
				continue
			}
			if _, moved := desiredPortBridge[oldPort.Interface]; moved {
				continue
			}
			portChanges, err := removeManagedBridgePortChanges(previous, oldBridge, oldPort, host, liveInterfaces)
			if err != nil {
				return nil, err
			}
			changes = append(changes, portChanges...)
		}
		if retained {
			continue
		}
		liveBridge, exists := liveInterfaces[oldBridge.Name]
		if !exists {
			continue
		}
		if liveBridge.Kind != "bridge" {
			return nil, fmt.Errorf("previously managed bridge %q is now a %q interface; refusing teardown", oldBridge.Name, liveBridge.Kind)
		}
		for _, vlan := range host.BridgeVLANs {
			if vlan.Device == oldBridge.Name {
				changes = append(changes, removeVLAN(oldBridge.Name, vlan, true))
			}
		}
		if liveBridge.AdminUp {
			changes = append(changes, Change{
				Description: "bring removed bridge down " + oldBridge.ID,
				Apply:       Command{Tool: "ip", Args: []string{"link", "set", "dev", oldBridge.Name, "down"}},
				Rollback:    Command{Tool: "ip", Args: []string{"link", "set", "dev", oldBridge.Name, "up"}},
			})
		}
		create := []string{"link", "add", "name", oldBridge.Name}
		if liveBridge.MTU > 0 {
			create = append(create, "mtu", fmt.Sprint(liveBridge.MTU))
		}
		create = append(create, "type", "bridge", "vlan_filtering", boolDigit(liveBridge.VLANFiltering))
		if liveBridge.STPKnown {
			create = append(create, "stp_state", boolDigit(liveBridge.STPEnabled))
		}
		if liveBridge.STPPriorityKnown {
			create = append(create, "priority", fmt.Sprint(liveBridge.STPPriority))
		}
		if liveBridge.IGMPBridgeKnown {
			create = append(create, "mcast_snooping", boolDigit(liveBridge.IGMPSnooping), "mcast_querier", boolDigit(liveBridge.IGMPQuerier))
		}
		if liveBridge.IGMPVLANKnown {
			create = append(create, "mcast_vlan_snooping", boolDigit(liveBridge.IGMPVLANMode))
		}
		changes = append(changes, Change{
			Description: "delete removed bridge " + oldBridge.ID,
			Apply:       Command{Tool: "ip", Args: []string{"link", "del", "dev", oldBridge.Name}},
			Rollback:    Command{Tool: "ip", Args: create},
		})
	}
	return changes, nil
}

func removeManagedBridgePortChanges(previous Config, bridge Bridge, port BridgePort, host Capabilities, liveInterfaces map[string]HostInterface) ([]Change, error) {
	physical := interfaceByID(previous.Interfaces, port.Interface)
	if physical.Name == "" {
		return nil, fmt.Errorf("previously managed bridge port %q has no interface definition", port.Interface)
	}
	livePort, exists := liveInterfaces[physical.Name]
	if !exists || livePort.Master != bridge.Name {
		return nil, nil
	}
	changes := []Change{}
	for _, vlan := range host.BridgeVLANs {
		if vlan.Device == physical.Name {
			changes = append(changes, removeVLAN(physical.Name, vlan, false))
		}
	}
	changes = append(changes, Change{
		Description: "detach removed interface " + port.Interface + " from bridge " + bridge.ID,
		Apply:       Command{Tool: "ip", Args: []string{"link", "set", "dev", physical.Name, "nomaster"}},
		Rollback:    Command{Tool: "ip", Args: []string{"link", "set", "dev", physical.Name, "master", bridge.Name}},
	})
	return changes, nil
}

func defaultLinuxBridgePathCost(live HostInterface) (uint32, bool) {
	if !live.LinkSpeedKnown {
		return 0, false
	}
	switch speedMbps := live.LinkSpeedBPS / 1_000_000; {
	case speedMbps > 10_000:
		return 1, true
	case speedMbps == 10_000:
		return 2, true
	case speedMbps == 5_000:
		return 3, true
	case speedMbps == 2_500:
		return 4, true
	case speedMbps == 1_000:
		return 5, true
	case speedMbps == 100:
		return 19, true
	case speedMbps == 10:
		return 100, true
	default:
		return 100, true
	}
}

func mirrorCaptureRate(cfg Config) uint64 {
	for _, mirror := range cfg.PortMirrors {
		if mirror.CaptureRateBPS != 0 {
			return mirror.CaptureRateBPS
		}
	}
	return 0
}

func mirrorCaptureConfig(cfg Config) Config {
	out := Config{Interfaces: cfg.Interfaces}
	for _, mirror := range cfg.PortMirrors {
		if mirror.CaptureRateBPS != 0 {
			out.EgressRates = []EgressRateLimit{{Interface: mirror.Destination, RateBPS: mirror.CaptureRateBPS, BurstBytes: mirror.CaptureBurstBytes}}
			break
		}
	}
	return out
}

type portMirrorFilter struct {
	SourceID  string
	Source    string
	Dest      string
	Direction string
	VLAN      uint16
}

func portMirrorDirections(direction string) []string {
	switch direction {
	case "ingress":
		return []string{"ingress"}
	case "egress":
		return []string{"egress"}
	case "both":
		return []string{"ingress", "egress"}
	default:
		return nil
	}
}

func portMirrorPriority(direction string) int {
	if direction == "egress" {
		return 49101
	}
	return 49100
}

func expectedPortMirrorFilter(direction, destination string, vlan uint16) TCFilterState {
	kind := "matchall"
	if vlan != 0 {
		kind = "flower"
	}
	return TCFilterState{Priority: portMirrorPriority(direction), Kind: kind, NumVLANs: -1, VLANID: vlan,
		MirrorDevice: destination, MirrorAction: "mirror", MirrorDirection: "egress"}
}

const stormBroadcastPriority = 48010
const stormMulticastPriority = 48020
const multiBroadcastPriority = 48030
const multiMulticastPriority = 48040

func stormFilter(rate uint64, burst uint32, multicast bool) TCFilterState {
	priority := stormBroadcastPriority
	if multicast {
		priority = stormMulticastPriority
	}
	return ingressRateFilter(rate, burst, multicast, priority)
}

func ingressRateFilter(rate uint64, burst uint32, multicast bool, priority int) TCFilterState {
	state := TCFilterState{Kind: "flower", NumVLANs: -1, PoliceRateBPS: rate, PoliceBurstBytes: burst}
	state.Priority = priority
	if multicast {
		state.DestinationMAC = "01:00:00:00:00:00"
		state.DestinationMask = "01:00:00:00:00:00"
	} else {
		state.DestinationMAC = "ff:ff:ff:ff:ff:ff"
		state.DestinationMask = "ff:ff:ff:ff:ff:ff"
	}
	return state
}

func buildStormControlChanges(previous, desired Config, hostInterfaces map[string]HostInterface) ([]Change, error) {
	return buildIngressRateChanges(previous, desired, hostInterfaces, "storm control", stormBroadcastPriority, stormMulticastPriority)
}

func buildMulticastBroadcastRateChanges(previous, desired Config, hostInterfaces map[string]HostInterface) ([]Change, error) {
	toStormShape := func(in Config) Config {
		out := in
		out.StormControl = make([]StormControl, 0, len(in.MulticastBroadcastLimits))
		for _, policy := range in.MulticastBroadcastLimits {
			out.StormControl = append(out.StormControl, StormControl{Interface: policy.Interface, BroadcastRateBPS: policy.BroadcastRateBPS, MulticastRateBPS: policy.MulticastRateBPS, BurstBytes: policy.BurstBytes})
		}
		return out
	}
	return buildIngressRateChanges(toStormShape(previous), toStormShape(desired), hostInterfaces, "multicast/broadcast rate limit", multiBroadcastPriority, multiMulticastPriority)
}

func buildIngressRateChanges(previous, desired Config, hostInterfaces map[string]HostInterface, feature string, broadcastPriority, multicastPriority int) ([]Change, error) {
	names := map[string]string{}
	for _, iface := range previous.Interfaces {
		names[iface.ID] = iface.Name
	}
	for _, iface := range desired.Interfaces {
		names[iface.ID] = iface.Name
	}
	collect := func(config Config) map[string]StormControl {
		out := map[string]StormControl{}
		for _, item := range config.StormControl {
			out[item.Interface] = item
		}
		return out
	}
	old, wanted := collect(previous), collect(desired)
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
	var changes []Change
	for _, id := range ordered {
		prior, had := old[id]
		next, want := wanted[id]
		name := names[id]
		live, exists := hostInterfaces[name]
		if !exists {
			return nil, fmt.Errorf("%s interface %q is absent from host inventory", feature, name)
		}
		if want && live.Kind == "bond" {
			return nil, fmt.Errorf("%s interface %q cannot be a bond", feature, name)
		}
		if want && live.LegacyIngress && !live.TCClsact {
			return nil, fmt.Errorf("%s interface %q has a legacy ingress qdisc; convert it to clsact first", feature, name)
		}
		for _, item := range []struct {
			key         string
			prior, next uint64
			multicast   bool
		}{
			{"broadcast", prior.BroadcastRateBPS, next.BroadcastRateBPS, false},
			{"multicast", prior.MulticastRateBPS, next.MulticastRateBPS, true},
		} {
			priority := broadcastPriority
			if item.multicast {
				priority = multicastPriority
			}
			var actual *TCFilterState
			for i := range live.TCFilters {
				if live.TCFilters[i].Priority == priority {
					actual = &live.TCFilters[i]
					break
				}
			}
			oldExpected := ingressRateFilter(item.prior, prior.BurstBytes, item.multicast, priority)
			if actual != nil && (!had || item.prior == 0 || !equalTCFilter(*actual, oldExpected)) {
				return nil, fmt.Errorf("interface %q has an unmanaged filter in reserved %s priority %d", name, feature, priority)
			}
			if !want && (!had || item.prior == 0 || actual == nil) {
				continue
			}
			if want && item.next == 0 && (actual == nil) {
				continue
			}
			if want && item.next > 0 && actual != nil && equalTCFilter(*actual, ingressRateFilter(item.next, next.BurstBytes, item.multicast, priority)) {
				continue
			}
			if want && item.next == 0 && actual == nil {
				continue
			}
			if want && !live.TCClsact {
				changes = append(changes, Change{Description: "create clsact qdisc for " + feature + " on " + name,
					Apply:    Command{Tool: "tc", Args: []string{"qdisc", "add", "dev", name, "clsact"}},
					Rollback: Command{Tool: "tc", Args: []string{"qdisc", "del", "dev", name, "clsact"}}})
				live.TCClsact = true
			}
			filterCommand := func(verb string, rate uint64, burst uint32) Command {
				filter := ingressRateFilter(rate, burst, item.multicast, priority)
				macMask := filter.DestinationMAC + "/" + filter.DestinationMask
				return Command{Tool: "tc", Args: []string{"filter", verb, "dev", name, "ingress", "protocol", "all", "pref", fmt.Sprint(priority), "flower", "skip_hw", "dst_mac", macMask, "action", "police", "rate", fmt.Sprint(rate), "bit", "burst", fmt.Sprint(burst), "b", "drop"}}
			}
			apply := Command{Tool: "tc", Args: []string{"filter", "del", "dev", name, "ingress", "pref", fmt.Sprint(priority)}}
			rollback := filterCommand("add", item.prior, prior.BurstBytes)
			if want && item.next > 0 {
				apply = filterCommand("replace", item.next, next.BurstBytes)
				if actual == nil {
					rollback = Command{Tool: "tc", Args: []string{"filter", "del", "dev", name, "ingress", "pref", fmt.Sprint(priority)}}
				} else {
					rollback = filterCommand("replace", item.prior, prior.BurstBytes)
				}
			} else if !had || item.prior == 0 {
				continue
			}
			description := "remove " + item.key + " " + feature + " on " + name
			if want && item.next > 0 {
				description = "configure " + item.key + " " + feature + " on " + name
			}
			changes = append(changes, Change{Description: description, Apply: apply, Rollback: rollback})
		}
	}
	return changes, nil
}

func buildPortMirrorChanges(previous, desired Config, hostInterfaces map[string]HostInterface) ([]Change, error) {
	interfaceNames := map[string]string{}
	for _, iface := range previous.Interfaces {
		interfaceNames[iface.ID] = iface.Name
	}
	for _, iface := range desired.Interfaces {
		interfaceNames[iface.ID] = iface.Name
	}
	collect := func(config Config) map[string]portMirrorFilter {
		out := map[string]portMirrorFilter{}
		networks := make(map[string]Network, len(config.Networks))
		for _, network := range config.Networks {
			networks[network.ID] = network
		}
		for _, mirror := range config.PortMirrors {
			for _, direction := range portMirrorDirections(mirror.Direction) {
				key := mirror.Source + "/" + direction
				out[key] = portMirrorFilter{SourceID: mirror.Source, Source: interfaceNames[mirror.Source], Dest: interfaceNames[mirror.Destination], Direction: direction, VLAN: networks[mirror.Network].VLAN}
			}
		}
		return out
	}
	old, wanted := collect(previous), collect(desired)
	keysMap := map[string]bool{}
	for key := range old {
		keysMap[key] = true
	}
	for key := range wanted {
		keysMap[key] = true
	}
	keys := make([]string, 0, len(keysMap))
	for key := range keysMap {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var changes []Change
	qdiscAdded := map[string]bool{}
	for _, key := range keys {
		prior, had := old[key]
		next, want := wanted[key]
		rule := next
		if !want {
			rule = prior
		}
		live, exists := hostInterfaces[rule.Source]
		if !exists {
			return nil, fmt.Errorf("port mirror source %q is absent from host inventory", rule.Source)
		}
		destination, destinationExists := hostInterfaces[rule.Dest]
		if want && (!destinationExists || destination.Kind == "bridge" || destination.Kind == "bond" || destination.Master != "" || !destination.AdminUp) {
			return nil, fmt.Errorf("port mirror destination %q must be an active, standalone monitor interface", rule.Dest)
		}
		if want && live.Kind == "bond" {
			return nil, fmt.Errorf("port mirror source %q cannot be a bond", rule.Source)
		}
		if want && live.LegacyIngress && !live.TCClsact {
			return nil, fmt.Errorf("port mirror source %q has a legacy ingress qdisc; convert it to clsact before mirroring", rule.Source)
		}
		priority := portMirrorPriority(rule.Direction)
		filters := live.TCFilters
		if rule.Direction == "egress" {
			filters = live.TCEgressFilters
		}
		var actual *TCFilterState
		for i := range filters {
			if filters[i].Priority == priority {
				actual = &filters[i]
				break
			}
		}
		oldExpected := expectedPortMirrorFilter(prior.Direction, prior.Dest, prior.VLAN)
		if actual != nil && (!had || !equalTCFilter(*actual, oldExpected)) {
			return nil, fmt.Errorf("interface %q has an unmanaged filter in reserved port-mirroring priority %d", rule.Source, priority)
		}
		if !want && (!had || actual == nil) {
			continue
		}
		desiredExpected := expectedPortMirrorFilter(next.Direction, next.Dest, next.VLAN)
		if want && actual != nil && equalTCFilter(*actual, desiredExpected) {
			continue
		}
		if want && !live.TCClsact && !qdiscAdded[rule.Source] {
			changes = append(changes, Change{Description: "create clsact qdisc for port mirroring on " + rule.Source,
				Apply:    Command{Tool: "tc", Args: []string{"qdisc", "add", "dev", rule.Source, "clsact"}},
				Rollback: Command{Tool: "tc", Args: []string{"qdisc", "del", "dev", rule.Source, "clsact"}}})
			qdiscAdded[rule.Source] = true
		}
		attach := rule.Direction
		filterCommand := func(verb string, item portMirrorFilter) Command {
			args := []string{"filter", verb, "dev", item.Source, attach, "pref", fmt.Sprint(priority)}
			if item.VLAN != 0 {
				args = append(args, "protocol", "802.1Q", "flower", "skip_hw", "vlan_id", fmt.Sprint(item.VLAN))
			} else {
				args = append(args, "matchall", "skip_hw")
			}
			args = append(args, "action", "mirred", "egress", "mirror", "dev", item.Dest)
			return Command{Tool: "tc", Args: args}
		}
		filterDelete := Command{Tool: "tc", Args: []string{"filter", "del", "dev", rule.Source, attach, "pref", fmt.Sprint(priority)}}
		apply, rollback := filterDelete, filterCommand("add", rule)
		if want {
			apply = filterCommand("replace", next)
			if actual != nil {
				rollback = filterCommand("replace", prior)
			}
		} else if had {
			rollback = filterCommand("add", prior)
		}
		description := "remove port mirror on " + rule.SourceID + " " + rule.Direction
		if want {
			description = "install port mirror on " + rule.SourceID + " " + rule.Direction
		}
		changes = append(changes, Change{Description: description, Apply: apply, Rollback: rollback})
	}
	return changes, nil
}

func dedupeClsactQdiscAdds(changes []Change) []Change {
	seen := map[string]bool{}
	out := make([]Change, 0, len(changes))
	for _, change := range changes {
		args := change.Apply.Args
		if change.Apply.Tool == "tc" && len(args) == 5 && args[0] == "qdisc" && args[1] == "add" && args[2] == "dev" && args[4] == "clsact" {
			if seen[args[3]] {
				continue
			}
			seen[args[3]] = true
		}
		out = append(out, change)
	}
	return out
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

func optionalInt(value *uint8) string {
	if value == nil {
		return ""
	}
	return fmt.Sprint(*value)
}

func optionalUint32(value *uint32) string {
	if value == nil {
		return ""
	}
	return fmt.Sprint(*value)
}

func optionalBool(value *bool) string {
	if value == nil {
		return ""
	}
	return boolOnOff(*value)
}

func boolYesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func optionalBoolYesNo(value *bool) string {
	if value == nil {
		return ""
	}
	return boolYesNo(*value)
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

func buildNetworkIsolationChange(previous, desired Config, host Capabilities) (*Change, error) {
	oldComments, wantedComments := networkIsolationRuleComments(previous), networkIsolationRuleComments(desired)
	if host.NetworkIsolationTablePresent {
		if !host.NetworkIsolationTableManaged {
			return nil, fmt.Errorf("nftables inet table %q is not marked as GameBond-owned", networkIsolationTableName)
		}
		actual := mapKeys(host.NetworkIsolationRuleCounters)
		if exactStringSet(actual, wantedComments) {
			return nil, nil
		}
		if len(previous.NetworkACL) > 0 && !exactStringSet(actual, oldComments) {
			return nil, fmt.Errorf("nftables inet table %q differs from saved GameBond routed network isolation", networkIsolationTableName)
		}
		if len(previous.NetworkACL) == 0 && !exactStringSet(actual, wantedComments) {
			return nil, fmt.Errorf("nftables inet table %q already exists and is not owned by this configuration", networkIsolationTableName)
		}
	}
	if len(previous.NetworkACL) == 0 && len(desired.NetworkACL) == 0 {
		return nil, nil
	}
	for _, config := range []Config{previous, desired} {
		for _, network := range config.Networks {
			if network.RouteInterface == "" {
				continue
			}
			live, exists := hostInterfaceByName(host.Interfaces, network.RouteInterface)
			if !exists || !live.AdminUp {
				return nil, fmt.Errorf("routed network %q interface %q must be present and administratively up", network.ID, network.RouteInterface)
			}
		}
	}
	apply := Command{Tool: "nft", Args: []string{"-f", "-"}}
	if len(desired.NetworkACL) == 0 {
		if !host.NetworkIsolationTablePresent {
			return nil, nil
		}
		apply.Input = []byte("delete table inet " + networkIsolationTableName + "\n")
	} else {
		apply.Input = renderNetworkIsolationTable(desired, host.NetworkIsolationTablePresent)
	}
	rollback := Command{Tool: "nft", Args: []string{"-f", "-"}}
	if len(previous.NetworkACL) == 0 {
		rollback.Input = []byte("delete table inet " + networkIsolationTableName + "\n")
	} else {
		rollback.Input = renderNetworkIsolationTable(previous, len(desired.NetworkACL) != 0)
	}
	return &Change{Description: "apply routed network isolation", Apply: apply, Rollback: rollback}, nil
}

func networkIsolationRuleComments(cfg Config) []string {
	if len(cfg.NetworkACL) == 0 {
		return nil
	}
	comments := []string{}
	for _, rule := range cfg.NetworkACL {
		source, destination := findNetwork(cfg.Networks, rule.SourceNetwork), findNetwork(cfg.Networks, rule.DestinationNetwork)
		fingerprint := networkIsolationFingerprint(rule, source, destination)
		comments = append(comments, "gamebond-l2-isolation:allow:"+fingerprint, "gamebond-l2-isolation:reply:"+fingerprint)
	}
	networks := append([]Network(nil), cfg.Networks...)
	sort.Slice(networks, func(i, j int) bool { return networks[i].ID < networks[j].ID })
	for _, source := range networks {
		if source.RouteInterface == "" {
			continue
		}
		for _, destination := range networks {
			if destination.ID == source.ID || destination.RouteInterface == "" {
				continue
			}
			comments = append(comments, networkIsolationDenyComment(source, destination))
		}
	}
	sort.Strings(comments)
	return comments
}

func findNetwork(networks []Network, id string) Network {
	for _, network := range networks {
		if network.ID == id {
			return network
		}
	}
	return Network{}
}

func networkIsolationAllowComment(cfg Config, rule NetworkACLRule) string {
	source, destination := findNetwork(cfg.Networks, rule.SourceNetwork), findNetwork(cfg.Networks, rule.DestinationNetwork)
	fingerprint := networkIsolationFingerprint(rule, source, destination)
	return "gamebond-l2-isolation:allow:" + fingerprint
}

func networkIsolationFingerprint(rule NetworkACLRule, source, destination Network) string {
	value := strings.Join([]string{rule.ID, rule.SourceNetwork, rule.DestinationNetwork, source.RouteInterface, destination.RouteInterface, rule.Protocol, fmt.Sprint(rule.Port)}, "\x00")
	sum := sha256.Sum256([]byte(value))
	return rule.ID + ":" + fmt.Sprintf("%x", sum[:])
}

func networkIsolationDenyComment(source, destination Network) string {
	value := strings.Join([]string{source.ID, source.RouteInterface, destination.ID, destination.RouteInterface}, "\x00")
	sum := sha256.Sum256([]byte(value))
	return "gamebond-l2-isolation:deny:" + fmt.Sprintf("%x", sum[:])
}

func renderNetworkIsolationTable(cfg Config, replace bool) []byte {
	var script strings.Builder
	if replace {
		script.WriteString("delete table inet " + networkIsolationTableName + "\n")
	}
	script.WriteString("add table inet " + networkIsolationTableName + " { comment \"" + networkIsolationTableMarker + "\"; }\n")
	script.WriteString("add chain inet " + networkIsolationTableName + " forward { type filter hook forward priority -180; policy accept; }\n")
	networks := make(map[string]Network, len(cfg.Networks))
	for _, network := range cfg.Networks {
		networks[network.ID] = network
	}
	for _, rule := range cfg.NetworkACL {
		source, destination := networks[rule.SourceNetwork], networks[rule.DestinationNetwork]
		match := `iifname "` + source.RouteInterface + `" oifname "` + destination.RouteInterface + `"`
		if rule.Protocol != "" {
			match += " meta l4proto " + rule.Protocol
		}
		if rule.Port != 0 {
			match += " " + rule.Protocol + " dport " + fmt.Sprint(rule.Port)
		}
		fingerprint := networkIsolationFingerprint(rule, source, destination)
		script.WriteString("add rule inet " + networkIsolationTableName + " forward ct state new " + match + " counter accept comment \"gamebond-l2-isolation:allow:" + fingerprint + "\"\n")
		reply := `iifname "` + destination.RouteInterface + `" oifname "` + source.RouteInterface + `"`
		script.WriteString("add rule inet " + networkIsolationTableName + " forward ct state established,related " + reply + " counter accept comment \"gamebond-l2-isolation:reply:" + fingerprint + "\"\n")
	}
	networksInOrder := append([]Network(nil), cfg.Networks...)
	sort.Slice(networksInOrder, func(i, j int) bool { return networksInOrder[i].ID < networksInOrder[j].ID })
	for _, source := range networksInOrder {
		if source.RouteInterface == "" {
			continue
		}
		for _, destination := range networksInOrder {
			if destination.ID == source.ID || destination.RouteInterface == "" {
				continue
			}
			match := `iifname "` + source.RouteInterface + `" oifname "` + destination.RouteInterface + `"`
			comment := networkIsolationDenyComment(source, destination)
			script.WriteString("add rule inet " + networkIsolationTableName + " forward " + match + " counter drop comment \"" + comment + "\"\n")
		}
	}
	return []byte(script.String())
}

func hostInterfaceByName(interfaces []HostInterface, name string) (HostInterface, bool) {
	for _, iface := range interfaces {
		if iface.Name == name {
			return iface, true
		}
	}
	return HostInterface{}, false
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
			script.WriteString("add rule bridge " + ipACLTableName + " " + i.chain + " " + i.iface + strings.Join(matches, " ") + " counter " + action + " comment \"" + ipACLRuleComment(cfg, r, i.comment) + "\"\n")
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
		for _, install := range installs {
			script.WriteString("add rule bridge " + macACLTableName + " " + install.chain + " " + install.portMatch + l2 + " counter " + action + " comment \"" + macACLRuleComment(cfg, rule, install.suffix) + "\"\n")
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

func dhcpGuardRuleComments(cfg Config) []string {
	comments := make([]string, 0, len(cfg.DHCPGuard)*4)
	for _, policy := range cfg.DHCPGuard {
		base := "gamebond-dhcp-guard:" + policy.Interface
		if !policy.Trusted {
			comments = append(comments, base+":server")
			if policy.ValidateBindings {
				comments = append(comments, base+":binding")
			}
		}
		if policy.RateLimitPPS > 0 {
			comments = append(comments, fmt.Sprintf("%s:rate:%d", base, policy.RateLimitPPS))
		}
	}
	sort.Strings(comments)
	return comments
}

func buildDHCPGuardChange(previous, desired Config, host Capabilities) (*Change, error) {
	oldComments, wantedComments := dhcpGuardRuleComments(previous), dhcpGuardRuleComments(desired)
	if host.DHCPGuardTablePresent {
		actual := mapKeys(host.DHCPGuardRuleCounters)
		if !host.DHCPGuardTableManaged {
			return nil, fmt.Errorf("nftables bridge table %q is not marked as GameBond-owned", dhcpGuardTableName)
		}
		if exactStringSet(actual, wantedComments) {
			return nil, nil
		}
		if len(previous.DHCPGuard) > 0 && !exactStringSet(actual, oldComments) {
			return nil, fmt.Errorf("nftables bridge table %q differs from saved GameBond DHCP guard", dhcpGuardTableName)
		}
		if len(previous.DHCPGuard) == 0 && !exactStringSet(actual, wantedComments) {
			return nil, fmt.Errorf("nftables bridge table %q already exists and is not owned by this DHCP guard config", dhcpGuardTableName)
		}
	}
	if len(previous.DHCPGuard) == 0 && len(desired.DHCPGuard) == 0 {
		return nil, nil
	}
	apply := Command{Tool: "nft", Args: []string{"-f", "-"}}
	if len(desired.DHCPGuard) == 0 {
		if !host.DHCPGuardTablePresent {
			return nil, nil
		}
		apply.Input = []byte("delete table bridge " + dhcpGuardTableName + "\n")
	} else {
		apply.Input = renderDHCPGuardTable(desired, host.DHCPGuardTablePresent)
	}
	rollback := Command{Tool: "nft", Args: []string{"-f", "-"}}
	if len(previous.DHCPGuard) == 0 {
		rollback.Input = []byte("delete table bridge " + dhcpGuardTableName + "\n")
	} else {
		rollback.Input = renderDHCPGuardTable(previous, len(desired.DHCPGuard) > 0)
	}
	return &Change{Description: "apply GameBond DHCP snooping and guard policy", Apply: apply, Rollback: rollback}, nil
}

func renderDHCPGuardTable(cfg Config, replace bool) []byte {
	var script strings.Builder
	if replace {
		script.WriteString("delete table bridge " + dhcpGuardTableName + "\n")
	}
	script.WriteString("add table bridge " + dhcpGuardTableName + " { comment \"" + dhcpGuardTableMarker + "\"; }\n")
	script.WriteString("add chain bridge " + dhcpGuardTableName + " prerouting { type filter hook prerouting priority -210; policy accept; }\n")
	script.WriteString("add set bridge " + dhcpGuardTableName + " client_bindings { type ifname . ipv4_addr . ether_addr; }\n")
	interfaces := make(map[string]string, len(cfg.Interfaces))
	for _, in := range cfg.Interfaces {
		interfaces[in.ID] = in.Name
	}
	policies := append([]DHCPGuardPort(nil), cfg.DHCPGuard...)
	sort.Slice(policies, func(i, j int) bool { return policies[i].Interface < policies[j].Interface })
	for _, policy := range policies {
		port, base := interfaces[policy.Interface], "gamebond-dhcp-guard:"+policy.Interface
		if !policy.Trusted {
			script.WriteString(fmt.Sprintf("add rule bridge %s prerouting iifname %q udp sport 67 counter drop comment %q\n", dhcpGuardTableName, port, base+":server"))
			if policy.ValidateBindings {
				script.WriteString(fmt.Sprintf("add rule bridge %s prerouting iifname %q ether type ip ip saddr != 0.0.0.0 iifname . ip saddr . ether saddr != @client_bindings counter drop comment %q\n", dhcpGuardTableName, port, base+":binding"))
			}
		}
		if policy.RateLimitPPS > 0 {
			script.WriteString(fmt.Sprintf("add rule bridge %s prerouting iifname %q udp dport 67 limit rate over %d/second burst %d packets counter drop comment %q\n", dhcpGuardTableName, port, policy.RateLimitPPS, policy.RateLimitPPS*2, fmt.Sprintf("%s:rate:%d", base, policy.RateLimitPPS)))
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

func equalTCFilter(a, b TCFilterState) bool {
	a.Packets, a.Bytes, a.Drops = 0, 0, 0
	b.Packets, b.Bytes, b.Drops = 0, 0, 0
	return a == b
}

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
