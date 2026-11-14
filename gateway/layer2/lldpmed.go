package layer2

import (
	"fmt"
	"sort"
	"strings"
)

// RenderLLDPMEDConfig returns persistent lldpcli commands that remove the
// previously managed policies before advertising the desired policies.
func RenderLLDPMEDConfig(previous, desired Config) ([]byte, error) {
	if err := desired.Validate(); err != nil {
		return nil, fmt.Errorf("desired Layer 2 config: %w", err)
	}
	if previous.Version != 0 {
		if err := previous.Validate(); err != nil {
			return nil, fmt.Errorf("current Layer 2 config: %w", err)
		}
	}
	var removals, commands []string
	for _, managed := range lldpMEDPolicies(previous) {
		removals = append(removals, fmt.Sprintf("unconfigure ports %s med policy application %s", managed.iface, managed.application))
	}
	for _, managed := range lldpMEDPolicies(desired) {
		command := fmt.Sprintf("configure ports %s med policy application %s", managed.iface, managed.application)
		if managed.tagged {
			command += " tagged"
		}
		if managed.vlan != 0 {
			command += fmt.Sprintf(" vlan %d", managed.vlan)
		}
		if managed.priority != nil {
			command += fmt.Sprintf(" priority %d", *managed.priority)
		}
		if managed.dscp != nil {
			command += fmt.Sprintf(" dscp %d", *managed.dscp)
		}
		commands = append(commands, command)
	}
	sort.Strings(removals)
	sort.Strings(commands)
	commands = append(removals, commands...)
	if len(commands) == 0 {
		return nil, nil
	}
	return []byte(strings.Join(commands, "\n") + "\n"), nil
}

type renderedMEDPolicy struct {
	iface       string
	application string
	vlan        uint16
	tagged      bool
	priority    *uint8
	dscp        *uint8
}

func lldpMEDPolicies(cfg Config) []renderedMEDPolicy {
	interfaces := make(map[string]string, len(cfg.Interfaces))
	for _, iface := range cfg.Interfaces {
		interfaces[iface.ID] = iface.Name
	}
	networks := make(map[string]Network, len(cfg.Networks))
	for _, network := range cfg.Networks {
		networks[network.ID] = network
	}
	var policies []renderedMEDPolicy
	for _, bridge := range cfg.Bridges {
		for _, port := range bridge.Ports {
			iface := interfaces[port.Interface]
			if port.VoiceNetwork != "" {
				network := networks[port.VoiceNetwork]
				policies = append(policies, renderedMEDPolicy{iface: iface, application: "voice", vlan: network.VLAN, tagged: true})
			}
			for _, policy := range port.LLDPMED {
				var vlan uint16
				if policy.Network != "" {
					vlan = networks[policy.Network].VLAN
				}
				policies = append(policies, renderedMEDPolicy{iface: iface, application: policy.Application, vlan: vlan, tagged: policy.Tagged, priority: policy.Priority, dscp: policy.DSCP})
			}
		}
	}
	sort.Slice(policies, func(i, j int) bool {
		if policies[i].iface != policies[j].iface {
			return policies[i].iface < policies[j].iface
		}
		return policies[i].application < policies[j].application
	})
	return policies
}
