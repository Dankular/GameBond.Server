//go:build linux

package layer2

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
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
