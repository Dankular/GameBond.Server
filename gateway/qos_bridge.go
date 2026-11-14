package gateway

import (
	"fmt"

	"github.com/Dankular/GameBond.Server/gateway/layer2"
)

// effectiveQoSConfig folds Layer 2 DSCP classes into the gateway's existing
// adaptive QoS provider so both controls share one root qdisc per interface.
func effectiveQoSConfig(cfg Config) (Config, error) {
	out := cfg
	out.QoS.Interfaces = append([]QoSInterface(nil), cfg.QoS.Interfaces...)
	for i := range out.QoS.Interfaces {
		out.QoS.Interfaces[i].Classes = append([]QoSClass(nil), cfg.QoS.Interfaces[i].Classes...)
	}
	if cfg.Layer2 == nil || len(cfg.Layer2.QoS) == 0 {
		return out, nil
	}
	out.QoS.Enabled = true
	for _, policy := range cfg.Layer2.QoS {
		l2Interface, ok := layer2.Interface{}, false
		for _, iface := range cfg.Layer2.Interfaces {
			if iface.ID == policy.Interface {
				l2Interface, ok = iface, true
				break
			}
		}
		if !ok {
			return Config{}, fmt.Errorf("Layer 2 QoS references unknown interface %q", policy.Interface)
		}
		gatewayInterfaceID := ""
		for _, iface := range out.Interfaces {
			if iface.Name == l2Interface.Name {
				gatewayInterfaceID = iface.ID
				break
			}
		}
		if gatewayInterfaceID == "" {
			gatewayInterfaceID = "l2-" + l2Interface.ID
			for _, iface := range out.Interfaces {
				if iface.ID == gatewayInterfaceID {
					return Config{}, fmt.Errorf("synthetic Layer 2 QoS interface ID %q conflicts with a gateway interface", gatewayInterfaceID)
				}
			}
			out.Interfaces = append(out.Interfaces, Interface{ID: gatewayInterfaceID, Name: l2Interface.Name, Role: "lan"})
		}
		if policy.LinkRateBPS%1000 != 0 || policy.LinkRateBPS/1000 > 100_000_000 {
			return Config{}, fmt.Errorf("Layer 2 QoS link rate on %q cannot be represented by the shared QoS provider", l2Interface.Name)
		}
		var target *QoSInterface
		for i := range out.QoS.Interfaces {
			if out.QoS.Interfaces[i].InterfaceID == gatewayInterfaceID {
				target = &out.QoS.Interfaces[i]
				break
			}
		}
		if target == nil {
			out.QoS.Interfaces = append(out.QoS.Interfaces, QoSInterface{InterfaceID: gatewayInterfaceID, TotalKbit: uint32(policy.LinkRateBPS / 1000)})
			target = &out.QoS.Interfaces[len(out.QoS.Interfaces)-1]
		} else if uint64(target.TotalKbit)*1000 != policy.LinkRateBPS {
			return Config{}, fmt.Errorf("adaptive and Layer 2 QoS link rates conflict on %q", l2Interface.Name)
		}
		seenDSCP, seenIDs := map[uint8]bool{}, map[string]bool{}
		for _, existing := range target.Classes {
			for _, dscp := range existing.dscpValues() {
				seenDSCP[dscp] = true
			}
			seenIDs[existing.ID] = true
		}
		for _, class := range policy.Classes {
			if class.RateBPS%1000 != 0 || class.CeilingBPS%1000 != 0 {
				return Config{}, fmt.Errorf("Layer 2 QoS class %d on %q uses rates the shared QoS provider cannot represent", class.ID, l2Interface.Name)
			}
			id := fmt.Sprintf("l2-%d", class.ID)
			if seenIDs[id] {
				return Config{}, fmt.Errorf("Layer 2 QoS class ID %q conflicts with an adaptive QoS class on %q", id, l2Interface.Name)
			}
			for _, dscp := range class.DSCP {
				if seenDSCP[dscp] {
					return Config{}, fmt.Errorf("DSCP %d is already assigned in the adaptive QoS policy on %q", dscp, l2Interface.Name)
				}
				seenDSCP[dscp] = true
			}
			seenIDs[id] = true
			target.Classes = append(target.Classes, QoSClass{ID: id, DSCPValues: append([]uint8(nil), class.DSCP...), RateKbit: uint32(class.RateBPS / 1000), CeilKbit: uint32(class.CeilingBPS / 1000), Priority: class.Priority})
		}
	}
	return out, nil
}

func effectiveAVQoSPolicies(cfg Config) []layer2.AVQoSPolicy {
	interfaceNames := make(map[string]string, len(cfg.Interfaces))
	for _, iface := range cfg.Interfaces {
		interfaceNames[iface.ID] = iface.Name
	}
	policies := make([]layer2.AVQoSPolicy, 0, len(cfg.QoS.Interfaces))
	for _, policy := range cfg.QoS.Interfaces {
		name := interfaceNames[policy.InterfaceID]
		if name == "" {
			continue
		}
		classes := make([]layer2.AVQoSClass, 0, len(policy.Classes))
		for _, class := range policy.Classes {
			classes = append(classes, layer2.AVQoSClass{DSCP: append([]uint8(nil), class.dscpValues()...), Priority: class.Priority})
		}
		policies = append(policies, layer2.AVQoSPolicy{InterfaceName: name, Classes: classes})
	}
	return policies
}
