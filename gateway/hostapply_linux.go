//go:build linux

package gateway

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Dankular/GameBond.Server/gateway/layer2"
)

// LinuxApplier owns GameBond bridge FDB, Layer 2 topology, and NAT state. Each
// provider prepares and verifies its own reversible changes before config commit.
type LinuxApplier struct{ Runner Runner }

func (a LinuxApplier) Prepare(ctx context.Context, current, desired Config) (PreparedChange, error) {
	if err := validateDHCPBindingAuthority(desired.Layer2); err != nil {
		return nil, err
	}
	qosCurrent, err := effectiveQoSConfig(current)
	if err != nil {
		return nil, fmt.Errorf("current QoS policy: %w", err)
	}
	qosDesired, err := effectiveQoSConfig(desired)
	if err != nil {
		return nil, fmt.Errorf("desired QoS policy: %w", err)
	}
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
	if desired.Layer2 != nil || current.Layer2 != nil {
		adapter := layer2RunnerAdapter{runner: a.Runner}
		desiredL2 := layer2.Config{Version: 1}
		if desired.Layer2 != nil {
			desiredL2 = *desired.Layer2
		}
		previous := layer2.Config{Version: 1}
		if current.Layer2 != nil {
			previous = *current.Layer2
		}
		snapshotConfig := mergeLayer2SnapshotConfig(previous, desiredL2)
		host, err := layer2.SnapshotCapabilities(ctx, snapshotConfig, adapter)
		if err != nil {
			return nil, fmt.Errorf("inspect Layer 2 host: %w", err)
		}
		if err := layer2.ValidateAVProfileCompatibility(desiredL2, host, effectiveAVQoSPolicies(qosDesired)); err != nil {
			return nil, err
		}
		if desired.Layer2 != nil {
			if len(desiredL2.PortMirrors) > 0 {
				if err := validatePortMirrorProvider(ctx, a.Runner); err != nil {
					return nil, err
				}
			}
			var currentBonds []layer2.Bond
			if current.Layer2 != nil {
				currentBonds = current.Layer2.Bonds
			}
			if !layer2.BondConfigsEqual(currentBonds, desired.Layer2.Bonds) && len(desired.Layer2.Bonds) > 0 {
				if err := layer2.ValidateBondMembers(ctx, *desired.Layer2, adapter); err != nil {
					return nil, err
				}
				prepared.verifyBonds = true
			}
		}
		plan, err := layer2.BuildTopologyPlan(previous, desiredL2, host)
		if err != nil {
			return nil, err
		}
		for _, change := range plan.Changes {
			if change.Apply.Input == nil {
				continue
			}
			inputRunner, ok := a.Runner.(InputRunner)
			if !ok {
				return nil, errors.New("gateway runner does not support provider input")
			}
			if _, err := inputRunner.RunInput(ctx, change.Apply.Tool, change.Apply.Input, "-c", "-f", "-"); err != nil {
				return nil, fmt.Errorf("validate Layer 2 provider transaction: %w", err)
			}
		}
		prepared.layer2Plan = &plan
		prepared.layer2Previous = &previous
		prepared.layer2Desired = &desiredL2
		prepared.layer2Snapshot = snapshotConfig
		if hasLLDPMEDPolicies(previous) || hasLLDPMEDPolicies(desiredL2) {
			if err := validateLLDPMEDHost(ctx, a.Runner, previous, desiredL2); err != nil {
				return nil, err
			}
			prepared.lldpMEDCurrent = previous
			prepared.lldpMEDDesired = desiredL2
		}
		if len(previous.PortAuth) > 0 || len(desiredL2.PortAuth) > 0 {
			if err := validatePortAuthHost(ctx, a.Runner, previous); err != nil {
				return nil, fmt.Errorf("validate current 802.1X state: %w", err)
			}
			if err := validatePortAuthHost(ctx, a.Runner, desiredL2); err != nil {
				return nil, err
			}
			prepared.portAuthCurrent = previous
			prepared.portAuthDesired = desiredL2
		}
	}
	if current.NAT.Enabled || desired.NAT.Enabled {
		if !a.Runner.Available("nft") {
			return nil, errors.New("nftables is required for configured NAT")
		}
		exists, err := natTableExists(ctx, a.Runner)
		if err != nil {
			return nil, fmt.Errorf("inspect GameBond NAT table: %w", err)
		}
		if exists && !current.NAT.Enabled {
			return nil, errors.New("nftables table inet gamebond_nat exists but is not owned by the active GameBond config")
		}
		after, err := renderNATScript(desired.NAT, desired.Interfaces, exists)
		if err != nil {
			return nil, err
		}
		before, err := renderNATScript(current.NAT, current.Interfaces, exists)
		if err != nil {
			return nil, err
		}
		if !current.NAT.Enabled && !exists && strings.TrimSpace(after) != "" {
			before = "delete table inet " + natTableName + "\n"
		}
		if strings.TrimSpace(after) != "" {
			if err := applyNATScript(ctx, a.Runner, after, true); err != nil {
				return nil, fmt.Errorf("validate GameBond NAT transaction: %w", err)
			}
		}
		prepared.natScript = after
		prepared.natRollback = before
	}
	if current.Routing.Enabled || desired.Routing.Enabled {
		if err := validateRoutingHost(ctx, a.Runner, current, desired); err != nil {
			return nil, err
		}
		prepared.routingCurrent = cloneConfig(current)
		prepared.routingDesired = cloneConfig(desired)
	}
	if qosCurrent.QoS.Enabled || qosDesired.QoS.Enabled {
		if err := validateQoSHost(ctx, a.Runner, qosCurrent, qosDesired); err != nil {
			return nil, err
		}
		prepared.qosCurrent = cloneConfig(qosCurrent)
		prepared.qosDesired = cloneConfig(qosDesired)
	}
	if current.DHCP.Enabled || desired.DHCP.Enabled {
		if desired.DHCP.Enabled {
			if err := validateKeaHost(ctx, a.Runner, desired); err != nil {
				return nil, err
			}
		}
		prepared.dhcpCurrent = cloneConfig(current)
		prepared.dhcpDesired = cloneConfig(desired)
	}
	if current.VRRP.Enabled || desired.VRRP.Enabled {
		if desired.VRRP.Enabled {
			if err := validateKeepalivedHost(ctx, a.Runner, desired); err != nil {
				return nil, err
			}
		}
		prepared.vrrpCurrent = cloneConfig(current)
		prepared.vrrpDesired = cloneConfig(desired)
	}
	if current.IGMPProxy.Enabled || desired.IGMPProxy.Enabled {
		if desired.IGMPProxy.Enabled {
			if err := validateIGMPHost(ctx, a.Runner, desired); err != nil {
				return nil, err
			}
		}
		prepared.igmpCurrent = cloneConfig(current)
		prepared.igmpDesired = cloneConfig(desired)
	}
	if current.DynamicRouting.Enabled || desired.DynamicRouting.Enabled {
		if desired.DynamicRouting.Enabled {
			if err := validateFRRHost(ctx, a.Runner, desired); err != nil {
				return nil, err
			}
		}
		prepared.dynamicRoutingCurrent = cloneConfig(current)
		prepared.dynamicRoutingDesired = cloneConfig(desired)
	}
	if current.MDNS.Enabled || desired.MDNS.Enabled {
		if desired.MDNS.Enabled {
			if err := validateMDNSHost(ctx, a.Runner, desired); err != nil {
				return nil, err
			}
		}
		prepared.mdnsCurrent = cloneConfig(current)
		prepared.mdnsDesired = cloneConfig(desired)
	}
	if current.RADIUS.Enabled || desired.RADIUS.Enabled {
		if desired.RADIUS.Enabled {
			if err := validateRADIUSHost(ctx, a.Runner, desired.RADIUS); err != nil {
				return nil, err
			}
		}
		prepared.radiusCurrent = cloneConfig(current)
		prepared.radiusDesired = cloneConfig(desired)
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

func mergeLayer2SnapshotConfig(previous, desired layer2.Config) layer2.Config {
	merged := desired
	merged.Bridges = append([]layer2.Bridge(nil), desired.Bridges...)
	networkIndex := make(map[string]int, len(merged.Networks))
	for i := range merged.Networks {
		networkIndex[merged.Networks[i].ID] = i
	}
	for _, old := range previous.Networks {
		if index, exists := networkIndex[old.ID]; exists {
			if merged.Networks[index].RouteInterface == "" {
				merged.Networks[index].RouteInterface = old.RouteInterface
			}
		} else {
			merged.Networks = append(merged.Networks, old)
			networkIndex[old.ID] = len(merged.Networks) - 1
		}
	}
	networkACLIDs := map[string]bool{}
	for _, rule := range merged.NetworkACL {
		networkACLIDs[rule.ID] = true
	}
	for _, rule := range previous.NetworkACL {
		if !networkACLIDs[rule.ID] {
			merged.NetworkACL = append(merged.NetworkACL, rule)
			networkACLIDs[rule.ID] = true
		}
	}
	bridgeIndex := make(map[string]int, len(merged.Bridges))
	for i := range merged.Bridges {
		bridgeIndex[merged.Bridges[i].ID] = i
	}
	for _, old := range previous.Bridges {
		index, exists := bridgeIndex[old.ID]
		if !exists {
			// Keep removed bridges in the read-only snapshot config so STP
			// controller discovery still runs before teardown planning.
			merged.Bridges = append(merged.Bridges, old)
			bridgeIndex[old.ID] = len(merged.Bridges) - 1
			continue
		}
		bridge := merged.Bridges[index]
		if bridge.STPMode == "" {
			bridge.STPMode = old.STPMode
		}
		if bridge.STPEnabled == nil {
			bridge.STPEnabled = old.STPEnabled
		}
		if bridge.STPPriority == nil {
			bridge.STPPriority = old.STPPriority
		}
		bridge.Ports = append([]layer2.BridgePort(nil), bridge.Ports...)
		portIndex := make(map[string]int, len(bridge.Ports))
		for i := range bridge.Ports {
			portIndex[bridge.Ports[i].Interface] = i
		}
		for _, oldPort := range old.Ports {
			i, exists := portIndex[oldPort.Interface]
			if !exists {
				bridge.Ports = append(bridge.Ports, oldPort)
				portIndex[oldPort.Interface] = len(bridge.Ports) - 1
				continue
			}
			port := &bridge.Ports[i]
			if port.STPPriority == nil {
				port.STPPriority = oldPort.STPPriority
			}
			if port.STPPathCost == nil {
				port.STPPathCost = oldPort.STPPathCost
			}
			if port.STPRootBlock == nil {
				port.STPRootBlock = oldPort.STPRootBlock
			}
			if port.STPEdge == nil {
				port.STPEdge = oldPort.STPEdge
			}
			if port.STPPointToPoint == "" {
				port.STPPointToPoint = oldPort.STPPointToPoint
			}
			if port.STPBPDUGuard == nil {
				port.STPBPDUGuard = oldPort.STPBPDUGuard
			}
		}
		merged.Bridges[index] = bridge
	}
	seenNames := make(map[string]bool, len(desired.Interfaces))
	for _, in := range desired.Interfaces {
		seenNames[in.Name] = true
	}
	for _, in := range previous.Interfaces {
		if !seenNames[in.Name] {
			merged.Interfaces = append(merged.Interfaces, in)
			seenNames[in.Name] = true
		}
	}
	seenRates := map[string]bool{}
	for _, policy := range merged.EgressRates {
		seenRates[policy.Interface+"/"+policy.Network] = true
	}
	for _, policy := range previous.EgressRates {
		key := policy.Interface + "/" + policy.Network
		if !seenRates[key] {
			merged.EgressRates = append(merged.EgressRates, policy)
			seenRates[key] = true
		}
	}
	seenStorm := map[string]bool{}
	for _, policy := range merged.StormControl {
		seenStorm[policy.Interface] = true
	}
	for _, policy := range previous.StormControl {
		if !seenStorm[policy.Interface] {
			merged.StormControl = append(merged.StormControl, policy)
			seenStorm[policy.Interface] = true
		}
	}
	seenMulticastBroadcast := map[string]bool{}
	for _, policy := range merged.MulticastBroadcastLimits {
		seenMulticastBroadcast[policy.Interface] = true
	}
	for _, policy := range previous.MulticastBroadcastLimits {
		if !seenMulticastBroadcast[policy.Interface] {
			merged.MulticastBroadcastLimits = append(merged.MulticastBroadcastLimits, policy)
			seenMulticastBroadcast[policy.Interface] = true
		}
	}
	seenFlow := map[string]bool{}
	for _, policy := range merged.FlowControl {
		seenFlow[policy.Interface] = true
	}
	for _, policy := range previous.FlowControl {
		if !seenFlow[policy.Interface] {
			merged.FlowControl = append(merged.FlowControl, policy)
			seenFlow[policy.Interface] = true
		}
	}
	seenQoS := map[string]bool{}
	for _, policy := range merged.QoS {
		seenQoS[policy.Interface] = true
	}
	for _, policy := range previous.QoS {
		if !seenQoS[policy.Interface] {
			merged.QoS = append(merged.QoS, policy)
			seenQoS[policy.Interface] = true
		}
	}
	return merged
}

type linuxPreparedChange struct {
	runner                Runner
	changes               []bridgeLimitChange
	applied               int
	layer2Plan            *layer2.Plan
	layer2Previous        *layer2.Config
	layer2Desired         *layer2.Config
	layer2Snapshot        layer2.Config
	layer2Applied         bool
	natScript             string
	natRollback           string
	natApplied            bool
	routingCurrent        Config
	routingDesired        Config
	routingApplied        bool
	qosCurrent            Config
	qosDesired            Config
	qosApplied            bool
	dhcpCurrent           Config
	dhcpDesired           Config
	dhcpApplied           bool
	verifyBonds           bool
	vrrpCurrent           Config
	vrrpDesired           Config
	vrrpApplied           bool
	igmpCurrent           Config
	igmpDesired           Config
	igmpApplied           bool
	dynamicRoutingCurrent Config
	dynamicRoutingDesired Config
	dynamicRoutingApplied bool
	mdnsCurrent           Config
	mdnsDesired           Config
	mdnsApplied           bool
	radiusCurrent         Config
	radiusDesired         Config
	radiusApplied         bool
	lldpMEDCurrent        layer2.Config
	lldpMEDDesired        layer2.Config
	lldpMEDApplied        bool
	portAuthCurrent       layer2.Config
	portAuthDesired       layer2.Config
	portAuthPaused        bool
	portAuthApplied       bool
}

// Summary returns bounded, human-readable provider actions without exposing
// command strings or secrets from the prepared host transaction.
func (p *linuxPreparedChange) Summary() []string {
	operations := make([]string, 0, len(p.changes)+16)
	if len(p.changes) > 0 {
		operations = append(operations, fmt.Sprintf("reconcile %d bridge FDB learning limit(s)", len(p.changes)))
	}
	if p.layer2Plan != nil {
		for _, change := range p.layer2Plan.Changes {
			operations = append(operations, change.Description)
		}
	}
	if hasLLDPMEDPolicies(p.lldpMEDCurrent) || hasLLDPMEDPolicies(p.lldpMEDDesired) {
		operations = append(operations, "reconcile LLDP-MED and voice VLAN advertisements")
	}
	if len(p.portAuthCurrent.PortAuth) > 0 || len(p.portAuthDesired.PortAuth) > 0 {
		operations = append(operations, "reconcile wired 802.1X RADIUS authenticators and fail-closed port authorization")
	}
	if strings.TrimSpace(p.natScript) != "" {
		operations = append(operations, "reconcile GameBond NAT rules")
	}
	for _, item := range []struct {
		active bool
		name   string
	}{
		{p.routingCurrent.Routing.Enabled || p.routingDesired.Routing.Enabled, "policy routing"},
		{p.qosCurrent.QoS.Enabled || p.qosDesired.QoS.Enabled, "shared QoS"},
		{p.dhcpCurrent.DHCP.Enabled || p.dhcpDesired.DHCP.Enabled, "DHCP service"},
		{p.vrrpCurrent.VRRP.Enabled || p.vrrpDesired.VRRP.Enabled, "VRRP service"},
		{p.igmpCurrent.IGMPProxy.Enabled || p.igmpDesired.IGMPProxy.Enabled, "IGMP proxy"},
		{p.dynamicRoutingCurrent.DynamicRouting.Enabled || p.dynamicRoutingDesired.DynamicRouting.Enabled, "dynamic routing"},
		{p.mdnsCurrent.MDNS.Enabled || p.mdnsDesired.MDNS.Enabled, "mDNS reflection"},
		{p.radiusCurrent.RADIUS.Enabled || p.radiusDesired.RADIUS.Enabled, "RADIUS service"},
	} {
		if item.active {
			operations = append(operations, "reconcile "+item.name)
		}
	}
	return operations
}

func (p *linuxPreparedChange) Apply(ctx context.Context) error {
	if len(p.portAuthCurrent.PortAuth) > 0 || len(p.portAuthDesired.PortAuth) > 0 {
		p.portAuthPaused = true
		if err := pausePortAuthServices(ctx, p.runner, p.portAuthCurrent); err != nil {
			return err
		}
	}
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
	if len(p.portAuthCurrent.PortAuth) > 0 || len(p.portAuthDesired.PortAuth) > 0 {
		p.portAuthApplied = true
		if err := applyPortAuthTransition(ctx, p.runner, p.portAuthCurrent, p.portAuthDesired); err != nil {
			return err
		}
	}
	if hasLLDPMEDPolicies(p.lldpMEDCurrent) || hasLLDPMEDPolicies(p.lldpMEDDesired) {
		p.lldpMEDApplied = true
		if err := applyLLDPMEDTransition(ctx, p.runner, p.lldpMEDCurrent, p.lldpMEDDesired); err != nil {
			return err
		}
	}
	if strings.TrimSpace(p.natScript) != "" {
		if err := applyNATScript(ctx, p.runner, p.natScript, false); err != nil {
			return fmt.Errorf("apply GameBond NAT transaction: %w", err)
		}
		p.natApplied = true
	}
	if p.routingCurrent.Routing.Enabled || p.routingDesired.Routing.Enabled {
		p.routingApplied = true
		if err := applyRoutingTransition(ctx, p.runner, p.routingCurrent, p.routingDesired); err != nil {
			return fmt.Errorf("apply policy routing: %w", err)
		}
	}
	if p.qosCurrent.QoS.Enabled || p.qosDesired.QoS.Enabled {
		p.qosApplied = true
		if err := applyQoSTransition(ctx, p.runner, p.qosCurrent, p.qosDesired); err != nil {
			return fmt.Errorf("apply QoS: %w", err)
		}
	}
	if p.dhcpCurrent.DHCP.Enabled || p.dhcpDesired.DHCP.Enabled {
		p.dhcpApplied = true
		if err := applyDHCPTransition(ctx, p.runner, p.dhcpDesired); err != nil {
			return err
		}
	}
	if p.vrrpCurrent.VRRP.Enabled || p.vrrpDesired.VRRP.Enabled {
		p.vrrpApplied = true
		if err := applyVRRPTransition(ctx, p.runner, p.vrrpDesired); err != nil {
			return err
		}
	}
	if p.igmpCurrent.IGMPProxy.Enabled || p.igmpDesired.IGMPProxy.Enabled {
		p.igmpApplied = true
		if err := applyIGMPTransition(ctx, p.runner, p.igmpDesired); err != nil {
			return err
		}
	}
	if p.dynamicRoutingCurrent.DynamicRouting.Enabled || p.dynamicRoutingDesired.DynamicRouting.Enabled {
		p.dynamicRoutingApplied = true
		if err := applyDynamicRoutingTransition(ctx, p.runner, p.dynamicRoutingDesired); err != nil {
			return err
		}
	}
	if p.mdnsCurrent.MDNS.Enabled || p.mdnsDesired.MDNS.Enabled {
		p.mdnsApplied = true
		if err := applyMDNSTransition(ctx, p.runner, p.mdnsDesired); err != nil {
			return err
		}
	}
	if p.radiusCurrent.RADIUS.Enabled || p.radiusDesired.RADIUS.Enabled {
		p.radiusApplied = true
		if err := applyRADIUSTransition(ctx, p.runner, p.radiusDesired.RADIUS); err != nil {
			return err
		}
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
	if p.layer2Plan != nil && p.layer2Previous != nil && p.layer2Desired != nil {
		host, err := layer2.SnapshotCapabilities(ctx, p.layer2Snapshot, layer2RunnerAdapter{runner: p.runner})
		if err != nil {
			return err
		}
		remaining, err := layer2.BuildTopologyPlan(*p.layer2Previous, *p.layer2Desired, host)
		if err != nil {
			return err
		}
		if len(remaining.Changes) != 0 {
			return fmt.Errorf("Layer 2 topology verification left %d pending changes", len(remaining.Changes))
		}
		if p.verifyBonds {
			if err := layer2.VerifyBonds(*p.layer2Desired, host); err != nil {
				return err
			}
		}
	}
	if p.natApplied {
		exists, err := natTableExists(ctx, p.runner)
		if err != nil {
			return fmt.Errorf("verify GameBond NAT table: %w", err)
		}
		if exists != p.natTableExpected() {
			return errors.New("GameBond NAT table verification failed")
		}
	}
	if p.routingApplied {
		if err := verifyRouting(ctx, p.runner, p.routingDesired); err != nil {
			return err
		}
	}
	if p.qosApplied {
		if err := verifyQoS(ctx, p.runner, p.qosDesired); err != nil {
			return err
		}
	}
	if p.dhcpApplied {
		status := snapshotDHCP(ctx, p.runner, p.dhcpDesired.DHCP)
		if status.Error != "" || status.Active != p.dhcpDesired.DHCP.Enabled {
			return errors.New("GameBond DHCP service verification failed: " + status.Error)
		}
	}
	if p.vrrpApplied {
		if err := verifyVRRP(ctx, p.runner, p.vrrpDesired); err != nil {
			return err
		}
	}
	if p.igmpApplied {
		if err := verifyIGMP(ctx, p.runner, p.igmpDesired.IGMPProxy.Enabled); err != nil {
			return err
		}
	}
	if p.dynamicRoutingApplied {
		if err := verifyDynamicRouting(ctx, p.runner, p.dynamicRoutingDesired.DynamicRouting); err != nil {
			return err
		}
	}
	if p.mdnsApplied {
		if err := verifyMDNS(ctx, p.runner, p.mdnsDesired.MDNS.Enabled); err != nil {
			return err
		}
	}
	if p.radiusApplied {
		if err := verifyRADIUS(ctx, p.runner, p.radiusDesired.RADIUS); err != nil {
			return err
		}
	}
	if p.lldpMEDApplied {
		if err := verifyLLDPMED(ctx, p.runner, p.lldpMEDDesired); err != nil {
			return err
		}
	}
	if p.portAuthApplied {
		if err := verifyPortAuth(ctx, p.runner, p.portAuthDesired); err != nil {
			return err
		}
	}
	return nil
}

func (p *linuxPreparedChange) Rollback(ctx context.Context) error {
	if p.applied > len(p.changes) {
		return errors.New("invalid bridge rollback state")
	}
	var first error
	if p.dhcpApplied {
		if err := applyDHCPTransition(ctx, p.runner, p.dhcpCurrent); err != nil {
			first = fmt.Errorf("restore DHCP: %w", err)
		}
	}
	if p.vrrpApplied {
		if err := applyVRRPTransition(ctx, p.runner, p.vrrpCurrent); err != nil && first == nil {
			first = fmt.Errorf("restore VRRP: %w", err)
		}
	}
	if p.igmpApplied {
		if err := applyIGMPTransition(ctx, p.runner, p.igmpCurrent); err != nil && first == nil {
			first = fmt.Errorf("restore IGMP proxy: %w", err)
		}
	}
	if p.dynamicRoutingApplied {
		if err := applyDynamicRoutingTransition(ctx, p.runner, p.dynamicRoutingCurrent); err != nil && first == nil {
			first = fmt.Errorf("restore dynamic routing: %w", err)
		}
	}
	if p.mdnsApplied {
		if err := applyMDNSTransition(ctx, p.runner, p.mdnsCurrent); err != nil && first == nil {
			first = fmt.Errorf("restore mDNS reflector: %w", err)
		}
	}
	if p.radiusApplied {
		if err := applyRADIUSTransition(ctx, p.runner, p.radiusCurrent.RADIUS); err != nil && first == nil {
			first = fmt.Errorf("restore RADIUS: %w", err)
		}
	}
	if p.qosApplied {
		if err := applyQoSTransition(ctx, p.runner, p.qosDesired, p.qosCurrent); err != nil {
			if first == nil {
				first = fmt.Errorf("restore QoS: %w", err)
			}
		}
	}
	if p.routingApplied {
		if err := applyRoutingTransition(ctx, p.runner, p.routingDesired, p.routingCurrent); err != nil {
			if first == nil {
				first = fmt.Errorf("restore policy routing: %w", err)
			}
		}
	}
	if p.natApplied {
		rollback := p.natRollback
		if strings.TrimSpace(rollback) != "" {
			if err := applyNATScript(ctx, p.runner, rollback, false); err != nil && first == nil {
				first = fmt.Errorf("restore GameBond NAT rules: %w", err)
			}
		}
	}
	if p.layer2Applied && p.layer2Plan != nil {
		if err := layer2.RollbackPlan(ctx, layer2RunnerAdapter{runner: p.runner}, *p.layer2Plan); err != nil {
			if first == nil {
				first = fmt.Errorf("restore Layer 2 topology: %w", err)
			}
		}
	}
	if p.lldpMEDApplied {
		if err := applyLLDPMEDTransition(ctx, p.runner, p.lldpMEDDesired, p.lldpMEDCurrent); err != nil && first == nil {
			first = fmt.Errorf("restore LLDP-MED policy: %w", err)
		}
	}
	if p.portAuthPaused || p.portAuthApplied {
		if err := applyPortAuthTransition(ctx, p.runner, p.portAuthDesired, p.portAuthCurrent); err != nil && first == nil {
			first = fmt.Errorf("restore wired 802.1X state: %w", err)
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

func (p *linuxPreparedChange) natTableExpected() bool {
	return strings.Contains(p.natScript, "add table inet "+natTableName)
}
