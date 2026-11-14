package layer2

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const eapolGroupForwardBit uint32 = 1 << 3

func buildPortAuthChange(previous, desired Config, host Capabilities) (*Change, error) {
	if len(previous.PortAuth) == 0 && len(desired.PortAuth) == 0 && !host.PortAuthTablePresent {
		return nil, nil
	}
	if host.PortAuthTablePresent && !host.PortAuthTableManaged {
		return nil, fmt.Errorf("nftables bridge table %q exists but is not marked as GameBond-owned", portAuthTableName)
	}
	if host.PortAuthTablePresent {
		actualMatchesDesired := portAuthStaticStateMatches(desired, host)
		if actualMatchesDesired {
			return nil, nil
		}
		if len(previous.PortAuth) > 0 && !portAuthStaticStateMatches(previous, host) {
			return nil, fmt.Errorf("nftables bridge table %q differs from saved GameBond 802.1X policy", portAuthTableName)
		}
		if len(previous.PortAuth) == 0 {
			return nil, fmt.Errorf("nftables bridge table %q already exists and does not match the desired GameBond 802.1X policy", portAuthTableName)
		}
	}
	apply := strings.Builder{}
	if host.PortAuthTablePresent {
		fmt.Fprintf(&apply, "delete table bridge %s\n", portAuthTableName)
	}
	if len(desired.PortAuth) > 0 {
		script, err := RenderPortAuthTable(desired)
		if err != nil {
			return nil, err
		}
		apply.Write(script)
	}
	if apply.Len() == 0 {
		return nil, nil
	}
	rollback := strings.Builder{}
	if len(desired.PortAuth) > 0 {
		fmt.Fprintf(&rollback, "delete table bridge %s\n", portAuthTableName)
		if !host.PortAuthTablePresent || len(previous.PortAuth) == 0 {
			return &Change{
				Description: "apply fail-closed 802.1X bridge authorization policy",
				Apply:       Command{Tool: "nft", Args: []string{"-f", "-"}, Input: []byte(apply.String())},
				Rollback:    Command{Tool: "nft", Args: []string{"-f", "-"}, Input: []byte(rollback.String())},
			}, nil
		}
	}
	if host.PortAuthTablePresent && len(previous.PortAuth) > 0 {
		script, err := RenderPortAuthTable(previous)
		if err != nil {
			return nil, err
		}
		rollback.Write(script)
	}
	return &Change{
		Description: "apply fail-closed 802.1X bridge authorization policy",
		Apply:       Command{Tool: "nft", Args: []string{"-f", "-"}, Input: []byte(apply.String())},
		Rollback:    Command{Tool: "nft", Args: []string{"-f", "-"}, Input: []byte(rollback.String())},
	}, nil
}

func portAuthStaticStateMatches(cfg Config, host Capabilities) bool {
	if len(cfg.PortAuth) == 0 {
		return !host.PortAuthTablePresent
	}
	if !host.PortAuthTablePresent || !host.PortAuthTableManaged || !host.PortAuthStaticShapeValid {
		return false
	}
	ports := make([]string, 0, len(cfg.PortAuth))
	for _, policy := range cfg.PortAuth {
		iface, ok := findInterface(cfg.Interfaces, policy.Interface)
		if !ok {
			return false
		}
		ports = append(ports, iface.Name)
	}
	sort.Strings(ports)
	return exactStringSet(host.PortAuthProtectedPorts, ports) && exactStringSet(host.PortAuthRuleComments, portAuthRuleComments())
}

func buildEAPOLForwardChanges(previous, desired Config, host Capabilities) ([]Change, error) {
	previousBridges := bridgeAuthUsage(previous)
	desiredBridges := bridgeAuthUsage(desired)
	changes := make([]Change, 0, len(previousBridges)+len(desiredBridges))
	for bridgeID := range previousBridges {
		if _, exists := desiredBridges[bridgeID]; !exists {
			desiredBridges[bridgeID] = false
		}
	}
	bridgeIDs := make([]string, 0, len(desiredBridges))
	for bridgeID := range desiredBridges {
		bridgeIDs = append(bridgeIDs, bridgeID)
	}
	sort.Strings(bridgeIDs)
	for _, bridgeID := range bridgeIDs {
		enabled := desiredBridges[bridgeID]
		previousEnabled := previousBridges[bridgeID]
		if enabled == previousEnabled {
			continue
		}
		name := authBridgeName(previous, desired, bridgeID)
		var live *HostInterface
		for i := range host.Interfaces {
			if host.Interfaces[i].Name == name {
				live = &host.Interfaces[i]
				break
			}
		}
		before := uint32(0)
		if live != nil {
			if !live.GroupFwdMaskKnown {
				return nil, fmt.Errorf("bridge %s does not report group_fwd_mask; cannot safely manage EAPOL forwarding", name)
			}
			before = live.GroupFwdMask
		} else if hasBridgeID(previous, bridgeID) {
			return nil, fmt.Errorf("bridge %s is not present while reconciling 802.1X EAPOL forwarding", name)
		}
		after := before
		if enabled {
			after |= eapolGroupForwardBit
		} else {
			after &^= eapolGroupForwardBit
		}
		if before == after {
			continue
		}
		change := Change{
			Description: "enable bridge EAPOL forwarding on " + bridgeID,
			Apply:       Command{Tool: "ip", Args: []string{"link", "set", "dev", name, "type", "bridge", "group_fwd_mask", strconv.FormatUint(uint64(after), 10)}},
			Rollback:    Command{Tool: "ip", Args: []string{"link", "set", "dev", name, "type", "bridge", "group_fwd_mask", strconv.FormatUint(uint64(before), 10)}},
		}
		if !enabled {
			change.Description = "restore bridge EAPOL forwarding on " + bridgeID
		}
		changes = append(changes, change)
	}
	return changes, nil
}

func bridgeAuthUsage(cfg Config) map[string]bool {
	portAuth := make(map[string]bool, len(cfg.PortAuth))
	for _, policy := range cfg.PortAuth {
		portAuth[policy.Interface] = true
	}
	bridges := map[string]bool{}
	for _, bridge := range cfg.Bridges {
		for _, port := range bridge.Ports {
			if portAuth[port.Interface] {
				bridges[bridge.ID] = true
			}
		}
	}
	return bridges
}

func authBridgeName(previous, desired Config, bridgeID string) string {
	for _, cfg := range []Config{desired, previous} {
		for _, bridge := range cfg.Bridges {
			if bridge.ID == bridgeID {
				return bridge.Name
			}
		}
	}
	return ""
}

func hasBridgeID(cfg Config, bridgeID string) bool {
	for _, bridge := range cfg.Bridges {
		if bridge.ID == bridgeID {
			return true
		}
	}
	return false
}

func validatePortAuthChange(change *Change) error {
	if change == nil || change.Apply.Input == nil || !strings.Contains(string(change.Apply.Input), portAuthTableMarker) {
		return errors.New("invalid GameBond 802.1X table change")
	}
	return nil
}
