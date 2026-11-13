//go:build linux

package layer2

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

func rawInt(raw json.RawMessage) int {
	var value int
	if json.Unmarshal(raw, &value) == nil {
		return value
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		value, _ = strconv.Atoi(text)
	}
	return value
}

func rawString(raw json.RawMessage) string {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text
	}
	return strconv.Itoa(rawInt(raw))
}

func bondHashName(raw json.RawMessage) string {
	value := rawString(raw)
	if _, err := strconv.Atoi(value); err != nil {
		return value
	}
	switch rawInt(raw) {
	case 0:
		return "layer2"
	case 1:
		return "layer2+3"
	case 2:
		return "layer3+4"
	case 3:
		return "encap2+3"
	case 4:
		return "encap3+4"
	}
	return ""
}

func bondLACPName(raw json.RawMessage) string {
	value := strings.ToLower(rawString(raw))
	if value == "fast" || value == "slow" {
		return value
	}
	switch rawInt(raw) {
	case 0:
		return "slow"
	case 1:
		return "fast"
	}
	return ""
}

func snapshotBonds(cfg Config, host []HostInterface) []BondStatus {
	byID := make(map[string]Interface, len(cfg.Interfaces))
	byName := make(map[string]HostInterface, len(host))
	for _, iface := range cfg.Interfaces {
		byID[iface.ID] = iface
	}
	for _, iface := range host {
		byName[iface.Name] = iface
	}
	out := make([]BondStatus, 0, len(cfg.Bonds))
	for _, bond := range cfg.Bonds {
		iface := byID[bond.Interface]
		status := BondStatus{ID: bond.ID, Interface: iface.Name, Members: []string{}, Collecting: []string{}, Distributing: []string{}, MinimumActive: int(bond.MinLinks)}
		if status.MinimumActive == 0 {
			status.MinimumActive = 1
		}
		live, exists := byName[iface.Name]
		if !exists || live.Kind != "bond" {
			status.Reason = "bond interface is absent"
			out = append(out, status)
			continue
		}
		status.Mode = live.BondMode
		configMatches := live.BondMode == "802.3ad" && live.BondLACPRate == bond.LACPRate && live.BondHashPolicy == bond.HashPolicy
		if bond.MinLinks != 0 {
			configMatches = configMatches && live.BondMinLinks == int(bond.MinLinks)
		}
		if bond.SystemMAC != "" {
			configMatches = configMatches && strings.EqualFold(live.Address, bond.SystemMAC)
		}
		partner, _ := os.ReadFile("/sys/class/net/" + iface.Name + "/bonding/ad_partner_mac")
		status.PartnerSystem = strings.ToLower(strings.TrimSpace(string(partner)))
		for _, memberID := range bond.Members {
			member := byID[memberID]
			status.Members = append(status.Members, member.Name)
			mii, miiErr := os.ReadFile("/sys/class/net/" + member.Name + "/bonding_slave/mii_status")
			aggregator, aggErr := os.ReadFile("/sys/class/net/" + member.Name + "/bonding_slave/ad_aggregator_id")
			actor, actorErr := os.ReadFile("/sys/class/net/" + member.Name + "/bonding_slave/ad_actor_oper_port_state")
			peer, peerErr := os.ReadFile("/sys/class/net/" + member.Name + "/bonding_slave/ad_partner_oper_port_state")
			if miiErr != nil || aggErr != nil || actorErr != nil || peerErr != nil {
				continue
			}
			agg, _ := strconv.Atoi(strings.TrimSpace(string(aggregator)))
			actorState := parseState(string(actor))
			peerState := parseState(string(peer))
			collecting := agg > 0 && strings.EqualFold(strings.TrimSpace(string(mii)), "up") && actorState&0x08 != 0 && peerState&0x08 != 0 && actorState&0x10 != 0 && peerState&0x10 != 0
			distributing := agg > 0 && strings.EqualFold(strings.TrimSpace(string(mii)), "up") && actorState&0x08 != 0 && peerState&0x08 != 0 && actorState&0x20 != 0 && peerState&0x20 != 0
			if collecting {
				status.Collecting = append(status.Collecting, member.Name)
			}
			if distributing {
				status.Distributing = append(status.Distributing, member.Name)
			}
			if collecting && distributing {
				status.ActiveMembers++
			}
		}
		status.Applied = configMatches && len(status.Collecting) >= status.MinimumActive && len(status.Distributing) >= status.MinimumActive && status.PartnerSystem != "" && status.PartnerSystem != "00:00:00:00:00:00"
		if !configMatches {
			status.Reason = "bond mode or requested LACP/hash settings do not match"
		} else if status.PartnerSystem == "" || status.PartnerSystem == "00:00:00:00:00:00" {
			status.Reason = "no active LACP partner is negotiated"
		} else if !status.Applied {
			status.Reason = fmt.Sprintf("only %d member links are collecting and distributing; requires %d", status.ActiveMembers, status.MinimumActive)
		}
		out = append(out, status)
	}
	return out
}

// ValidateBondMembers enforces the kernel driver's speed/duplex prerequisites before links are reconfigured.
func ValidateBondMembers(ctx context.Context, cfg Config, runner HostRunner) error {
	if len(cfg.Bonds) == 0 {
		return nil
	}
	if !runner.Available("ethtool") {
		return fmt.Errorf("LACP requires ethtool for member speed and duplex validation")
	}
	interfaces := make(map[string]Interface, len(cfg.Interfaces))
	for _, iface := range cfg.Interfaces {
		interfaces[iface.ID] = iface
	}
	for _, bond := range cfg.Bonds {
		var expectedSpeed string
		for _, memberID := range bond.Members {
			member := interfaces[memberID]
			result, err := runner.Run(ctx, "ethtool", member.Name)
			if err != nil {
				return fmt.Errorf("inspect LACP member %q: %w", member.Name, err)
			}
			text := string(result)
			speed, duplex, link := "", "", ""
			for _, line := range strings.Split(text, "\n") {
				key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
				if !ok {
					continue
				}
				switch strings.TrimSpace(key) {
				case "Speed":
					speed = strings.TrimSpace(value)
				case "Duplex":
					duplex = strings.TrimSpace(value)
				case "Link detected":
					link = strings.TrimSpace(value)
				}
			}
			if speed == "" || strings.EqualFold(speed, "Unknown!") || !strings.EqualFold(duplex, "Full") || !strings.EqualFold(link, "yes") {
				return fmt.Errorf("LACP member %q must report link up, a known speed, and full duplex", member.Name)
			}
			if expectedSpeed == "" {
				expectedSpeed = speed
			} else if speed != expectedSpeed {
				return fmt.Errorf("LACP bond %q members have different link speeds", bond.ID)
			}
		}
	}
	return nil
}

func parseState(value string) int {
	value = strings.TrimSpace(value)
	parsed, err := strconv.ParseInt(value, 0, 32)
	if err != nil {
		parsed, _ = strconv.ParseInt(value, 10, 32)
	}
	return int(parsed)
}

// VerifyBonds requires active LACP negotiation before a bond transaction is committed.
func VerifyBonds(cfg Config, capabilities Capabilities) error {
	statuses := make(map[string]BondStatus, len(capabilities.Bonds))
	for _, status := range capabilities.Bonds {
		statuses[status.ID] = status
	}
	for _, bond := range cfg.Bonds {
		status, ok := statuses[bond.ID]
		if !ok || !status.Applied {
			reason := "bond status is unavailable"
			if ok {
				reason = status.Reason
			}
			return fmt.Errorf("LACP bond %q is not active: %s", bond.ID, reason)
		}
	}
	return nil
}

func BondConfigsEqual(a, b []Bond) bool { return reflect.DeepEqual(a, b) }

func buildBondChanges(previous, desired Config, host map[string]HostInterface, features map[string]FeatureCapability) ([]Change, []Change, map[string]HostInterface, error) {
	if len(desired.Bonds) > 0 {
		capability, ok := features[FeatureLACP]
		if !ok || capability.State == CapabilityUnavailable || capability.State == CapabilityUnsupported {
			return nil, nil, nil, fmt.Errorf("LACP capability is unavailable: %s", capability.Reason)
		}
	}
	old, wanted := make(map[string]Bond, len(previous.Bonds)), make(map[string]Bond, len(desired.Bonds))
	for _, bond := range previous.Bonds {
		old[bond.ID] = bond
	}
	for _, bond := range desired.Bonds {
		wanted[bond.ID] = bond
	}
	desiredInterfaces, oldInterfaces := make(map[string]Interface), make(map[string]Interface)
	for _, iface := range desired.Interfaces {
		desiredInterfaces[iface.ID] = iface
	}
	for _, iface := range previous.Interfaces {
		oldInterfaces[iface.ID] = iface
	}
	var createChanges, teardownChanges []Change
	synthetic := make(map[string]HostInterface)
	ids := make([]string, 0, len(wanted))
	for id := range wanted {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		bond := wanted[id]
		iface := desiredInterfaces[bond.Interface]
		live, exists := host[iface.Name]
		prior, wasManaged := old[id]
		if exists {
			if !wasManaged || !reflect.DeepEqual(prior, bond) || prior.Interface != bond.Interface || live.Kind != "bond" {
				return nil, nil, nil, fmt.Errorf("bond interface %q exists but is not the unchanged GameBond-owned bond", iface.Name)
			}
			if live.BondMode != "802.3ad" || live.BondHashPolicy != bond.HashPolicy || live.BondLACPRate != bond.LACPRate || (bond.MinLinks != 0 && live.BondMinLinks != int(bond.MinLinks)) {
				return nil, nil, nil, fmt.Errorf("managed LACP bond %q settings have drifted", iface.Name)
			}
			for _, memberID := range bond.Members {
				member := desiredInterfaces[memberID]
				if port, ok := host[member.Name]; !ok || port.Master != iface.Name {
					return nil, nil, nil, fmt.Errorf("managed LACP bond %q member %q is not attached", iface.Name, member.Name)
				}
			}
			continue
		}
		if wasManaged {
			return nil, nil, nil, fmt.Errorf("managed LACP bond %q is missing from the host", iface.Name)
		}
		if _, conflict := host[iface.Name]; conflict {
			return nil, nil, nil, fmt.Errorf("LACP bond name %q is used by an unmanaged interface", iface.Name)
		}
		createChanges = append(createChanges, Change{Description: "create 802.3ad bond " + iface.Name, Apply: Command{Tool: "ip", Args: bondCreateArgs(iface.Name, bond)}, Rollback: Command{Tool: "ip", Args: []string{"link", "del", "dev", iface.Name}}})
		for _, memberID := range bond.Members {
			member := desiredInterfaces[memberID]
			physical, ok := host[member.Name]
			if !ok {
				return nil, nil, nil, fmt.Errorf("LACP member interface %q is absent", member.Name)
			}
			if physical.Master != "" {
				return nil, nil, nil, fmt.Errorf("LACP member %q is already attached to master %q", member.Name, physical.Master)
			}
			if physical.AdminUp {
				createChanges = append(createChanges, Change{Description: "bring LACP member down " + member.Name, Apply: Command{Tool: "ip", Args: []string{"link", "set", "dev", member.Name, "down"}}, Rollback: Command{Tool: "ip", Args: []string{"link", "set", "dev", member.Name, "up"}}})
			}
			createChanges = append(createChanges, Change{Description: "attach LACP member " + member.Name, Apply: Command{Tool: "ip", Args: []string{"link", "set", "dev", member.Name, "master", iface.Name}}, Rollback: Command{Tool: "ip", Args: []string{"link", "set", "dev", member.Name, "nomaster"}}})
			createChanges = append(createChanges, Change{Description: "bring LACP member up " + member.Name, Apply: Command{Tool: "ip", Args: []string{"link", "set", "dev", member.Name, "up"}}, Rollback: Command{Tool: "ip", Args: []string{"link", "set", "dev", member.Name, "down"}}})
		}
		createChanges = append(createChanges, Change{Description: "bring LACP bond up " + iface.Name, Apply: Command{Tool: "ip", Args: []string{"link", "set", "dev", iface.Name, "up"}}, Rollback: Command{Tool: "ip", Args: []string{"link", "set", "dev", iface.Name, "down"}}})
		minLinks := int(bond.MinLinks)
		if minLinks == 0 {
			minLinks = 1
		}
		synthetic[iface.Name] = HostInterface{Name: iface.Name, Kind: "bond", MTU: 1500, AdminUp: true, BondMode: "802.3ad", BondMinLinks: minLinks, BondHashPolicy: bond.HashPolicy, BondLACPRate: bond.LACPRate}
	}
	for id, bond := range old {
		if _, remains := wanted[id]; remains {
			continue
		}
		iface, ok := oldInterfaces[bond.Interface]
		if !ok {
			return nil, nil, nil, fmt.Errorf("saved LACP bond %q has no interface", id)
		}
		live, exists := host[iface.Name]
		if !exists {
			continue
		}
		if live.Kind != "bond" {
			return nil, nil, nil, fmt.Errorf("managed LACP interface %q changed kind", iface.Name)
		}
		for _, bridge := range desired.Bridges {
			for _, port := range bridge.Ports {
				if port.Interface == bond.Interface {
					return nil, nil, nil, fmt.Errorf("cannot remove LACP bond %q while it remains a bridge port", id)
				}
			}
		}
		if live.Master != "" {
			managed := false
			for _, bridge := range previous.Bridges {
				if bridge.Name == live.Master {
					managed = true
				}
			}
			if !managed {
				return nil, nil, nil, fmt.Errorf("LACP bond %q is attached to unmanaged master %q", id, live.Master)
			}
			teardownChanges = append(teardownChanges, Change{Description: "detach LACP bond from bridge", Apply: Command{Tool: "ip", Args: []string{"link", "set", "dev", iface.Name, "nomaster"}}, Rollback: Command{Tool: "ip", Args: []string{"link", "set", "dev", iface.Name, "master", live.Master}}})
		}
		if live.AdminUp {
			teardownChanges = append(teardownChanges, Change{Description: "bring LACP bond down", Apply: Command{Tool: "ip", Args: []string{"link", "set", "dev", iface.Name, "down"}}, Rollback: Command{Tool: "ip", Args: []string{"link", "set", "dev", iface.Name, "up"}}})
		}
		for _, memberID := range bond.Members {
			member, ok := oldInterfaces[memberID]
			if !ok {
				return nil, nil, nil, fmt.Errorf("saved LACP member %q is missing", memberID)
			}
			physical, ok := host[member.Name]
			if !ok || physical.Master != iface.Name {
				return nil, nil, nil, fmt.Errorf("saved LACP member %q has drifted", member.Name)
			}
			if physical.AdminUp {
				teardownChanges = append(teardownChanges, Change{Description: "bring LACP member down", Apply: Command{Tool: "ip", Args: []string{"link", "set", "dev", member.Name, "down"}}, Rollback: Command{Tool: "ip", Args: []string{"link", "set", "dev", member.Name, "up"}}})
			}
			teardownChanges = append(teardownChanges, Change{Description: "detach LACP member", Apply: Command{Tool: "ip", Args: []string{"link", "set", "dev", member.Name, "nomaster"}}, Rollback: Command{Tool: "ip", Args: []string{"link", "set", "dev", member.Name, "master", iface.Name}}})
			teardownChanges = append(teardownChanges, Change{Description: "restore LACP member link", Apply: Command{Tool: "ip", Args: []string{"link", "set", "dev", member.Name, "up"}}, Rollback: Command{Tool: "ip", Args: []string{"link", "set", "dev", member.Name, "down"}}})
		}
		teardownChanges = append(teardownChanges, Change{Description: "delete LACP bond", Apply: Command{Tool: "ip", Args: []string{"link", "del", "dev", iface.Name}}, Rollback: Command{Tool: "ip", Args: bondCreateArgs(iface.Name, bond)}})
	}
	return createChanges, teardownChanges, synthetic, nil
}

func bondCreateArgs(name string, bond Bond) []string {
	args := []string{"link", "add", "name", name}
	if bond.SystemMAC != "" {
		args = append(args, "address", bond.SystemMAC)
	}
	args = append(args, "type", "bond", "mode", "802.3ad", "miimon", "100", "lacp_rate", bond.LACPRate, "xmit_hash_policy", bond.HashPolicy, "min_links", strconv.Itoa(int(bond.MinLinks)))
	return args
}
