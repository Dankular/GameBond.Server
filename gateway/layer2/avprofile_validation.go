package layer2

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Dankular/GameBond.Server/gateway/layer2/avprofiles"
)

// AVQoSPolicy is the effective shared QoS view used to reconcile profile
// recommendations after gateway and Layer 2 classes have been merged.
type AVQoSPolicy struct {
	InterfaceName string
	Classes       []AVQoSClass
}

type AVQoSClass struct {
	DSCP     []uint8
	Priority uint8
}

// validateAVProfileHost reconciles profile requirements that the managed
// Linux provider can verify without inferring endpoint or switch behavior.
// Other catalogue settings remain advisory.
func validateAVProfileHost(cfg Config, host Capabilities) error {
	interfaceNames := make(map[string]string, len(cfg.Interfaces))
	for _, iface := range cfg.Interfaces {
		interfaceNames[iface.ID] = iface.Name
	}
	policies := make([]AVQoSPolicy, 0, len(cfg.QoS))
	for _, policy := range cfg.QoS {
		classes := make([]AVQoSClass, 0, len(policy.Classes))
		for _, class := range policy.Classes {
			classes = append(classes, AVQoSClass{DSCP: append([]uint8(nil), class.DSCP...), Priority: class.Priority})
		}
		policies = append(policies, AVQoSPolicy{InterfaceName: interfaceNames[policy.Interface], Classes: classes})
	}
	return ValidateAVProfileCompatibility(cfg, host, policies)
}

// ValidateAVProfileCompatibility checks the live link path and any configured
// final shared QoS map. An absent QoS map remains advisory.
func ValidateAVProfileCompatibility(cfg Config, host Capabilities, policies []AVQoSPolicy) error {
	if len(cfg.AVProfiles) == 0 {
		return nil
	}
	networks := make(map[string]Network, len(cfg.Networks))
	for _, network := range cfg.Networks {
		networks[network.ID] = network
	}
	bridges := make(map[string]Bridge, len(cfg.Bridges))
	for _, bridge := range cfg.Bridges {
		bridges[bridge.ID] = bridge
	}
	interfaces := make(map[string]Interface, len(cfg.Interfaces))
	for _, iface := range cfg.Interfaces {
		interfaces[iface.ID] = iface
	}
	liveByName := make(map[string]HostInterface, len(host.Interfaces))
	for _, iface := range host.Interfaces {
		liveByName[iface.Name] = iface
	}
	qosByInterface := make(map[string]AVQoSPolicy, len(policies))
	for _, policy := range policies {
		qosByInterface[policy.InterfaceName] = policy
	}

	for _, selection := range cfg.AVProfiles {
		profile, ok := avprofiles.Lookup(selection.Profile)
		if !ok {
			continue // Config.Validate reports this with the selection index.
		}
		network := networks[selection.Network]
		bridge := bridges[network.Bridge]
		minimumSpeed := avProfileMinimumLinkSpeed(profile)
		requiredDSCP := avProfileRequiredDSCP(profile)
		requiredPriorities := avProfileQueuePriorities(profile)
		for _, port := range bridge.Ports {
			if !portCarriesNetwork(port, selection.Network) {
				continue
			}
			iface := interfaces[port.Interface]
			live, present := liveByName[iface.Name]
			if minimumSpeed > 0 {
				if !present {
					return fmt.Errorf("Pro AV profile %s network %q interface %q is absent from host inventory", profile.Name, selection.Network, iface.Name)
				}
				if !live.LinkSpeedKnown {
					return fmt.Errorf("Pro AV profile %s link speed is unknown on %q", profile.Name, iface.Name)
				}
				if live.LinkSpeedBPS < minimumSpeed {
					return fmt.Errorf("Pro AV profile %s link speed on %q is %d bps, below required %d bps", profile.Name, iface.Name, live.LinkSpeedBPS, minimumSpeed)
				}
			}
			if len(requiredDSCP) == 0 {
				continue
			}
			policy, configured := qosByInterface[iface.Name]
			if !configured {
				continue
			}
			active := make(map[uint8]bool)
			activePriorities := make(map[uint8]uint8)
			for _, class := range policy.Classes {
				for _, dscp := range class.DSCP {
					active[dscp] = true
					activePriorities[dscp] = class.Priority
				}
			}
			for _, dscp := range requiredDSCP {
				if !active[dscp] {
					return fmt.Errorf("Pro AV profile %s requires DSCP %d in the active QoS map on %q", profile.Name, dscp, iface.Name)
				}
				if priority, constrained := requiredPriorities[dscp]; constrained && activePriorities[dscp] != priority {
					return fmt.Errorf("Pro AV profile %s requires DSCP %d at QoS priority %d on %q", profile.Name, dscp, priority, iface.Name)
				}
			}
			for _, order := range avProfileQueueOrder(profile) {
				for i := 0; i+1 < len(order); i++ {
					higher, higherSet := activePriorities[order[i]]
					lower, lowerSet := activePriorities[order[i+1]]
					if higherSet && lowerSet && higher >= lower {
						return fmt.Errorf("Pro AV profile %s requires DSCP %d to have higher QoS priority than DSCP %d on %q", profile.Name, order[i], order[i+1], iface.Name)
					}
				}
			}
		}
	}
	return nil
}

func portCarriesNetwork(port BridgePort, networkID string) bool {
	if port.UntaggedNetwork == networkID || port.VoiceNetwork == networkID {
		return true
	}
	for _, tagged := range port.TaggedNetworks {
		if tagged == networkID {
			return true
		}
	}
	return false
}

func avProfileMinimumLinkSpeed(profile avprofiles.Profile) uint64 {
	var minimum uint64
	for _, setting := range profile.Settings {
		if setting.Key != "link.minimum-speed" {
			continue
		}
		var value uint64
		switch {
		case strings.HasPrefix(setting.Value, "1-gbps"):
			value = 1_000_000_000
		case strings.HasPrefix(setting.Value, "10-gbps"):
			value = 10_000_000_000
		}
		if value > minimum {
			minimum = value
		}
	}
	return minimum
}

func avProfileRequiredDSCP(profile avprofiles.Profile) []uint8 {
	values := map[uint8]bool{}
	for _, setting := range profile.Settings {
		value := ""
		switch {
		case strings.HasPrefix(setting.Key, "qos.dscp."):
			// DSCP 0 is satisfied by the provider's default class and does not
			// require an explicit classifier.
			value = setting.Value
		case strings.HasPrefix(setting.Key, "qos.queue.dscp"):
			value = strings.TrimPrefix(setting.Key, "qos.queue.dscp")
		case strings.HasPrefix(setting.Key, "qos.queue."):
			value, _, _ = strings.Cut(setting.Value, ":")
		}
		parsed, err := strconv.ParseUint(value, 10, 8)
		if err == nil && parsed > 0 && parsed <= 63 {
			values[uint8(parsed)] = true
		}
	}
	result := make([]int, 0, len(values))
	for value := range values {
		result = append(result, int(value))
	}
	sort.Ints(result)
	out := make([]uint8, len(result))
	for i, value := range result {
		out[i] = uint8(value)
	}
	return out
}

// avProfileQueuePriorities maps only explicit numeric DSCP queue guidance to
// the Linux QoS model, where priority 0 is highest. Nonnumeric traffic classes
// and endpoint/switch-only queue behavior remain advisory.
func avProfileQueuePriorities(profile avprofiles.Profile) map[uint8]uint8 {
	requirements := map[uint8]uint8{}
	for _, setting := range profile.Settings {
		var dscpText, rank string
		switch {
		case strings.HasPrefix(setting.Key, "qos.queue.dscp"):
			dscpText = strings.TrimPrefix(setting.Key, "qos.queue.dscp")
			rank = setting.Value
		case strings.HasPrefix(setting.Key, "qos.queue."):
			dscpText, rank, _ = strings.Cut(setting.Value, ":")
		default:
			continue
		}
		dscp, err := strconv.ParseUint(dscpText, 10, 8)
		if err != nil || dscp > 63 {
			continue
		}
		var priority uint8
		switch rank {
		case "highest", "strict-highest":
			priority = 0
		case "second-highest", "strict-second-highest":
			priority = 1
		case "third-highest", "strict-third-highest":
			priority = 2
		default:
			continue
		}
		requirements[uint8(dscp)] = priority
	}
	return requirements
}

// avProfileQueueOrder returns relative priority groups from documented profile
// guidance. Earlier DSCPs must map to a numerically lower Linux priority.
func avProfileQueueOrder(profile avprofiles.Profile) [][]uint8 {
	for _, setting := range profile.Settings {
		if setting.Key != "qos.queue.order" {
			continue
		}
		parts := strings.Split(setting.Value, ">")
		order := make([]uint8, 0, len(parts))
		for _, part := range parts {
			value, err := strconv.ParseUint(strings.TrimSpace(part), 10, 8)
			if err != nil || value == 0 || value > 63 {
				order = nil
				break
			}
			order = append(order, uint8(value))
		}
		if len(order) > 1 {
			return [][]uint8{order}
		}
	}
	return nil
}
