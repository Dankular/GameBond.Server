package layer2

import (
	"fmt"
	"reflect"
	"sort"
	"strconv"
)

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
