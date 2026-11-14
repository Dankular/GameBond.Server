package gateway

import (
	"errors"
	"fmt"
	"time"

	"github.com/Dankular/GameBond.Server/gateway/layer2"
)

// RedundancyConfig coordinates health reporting for mechanisms that retain
// their own failover decisions. It does not create a second failover protocol.
type RedundancyConfig struct {
	Enabled bool              `json:"enabled"`
	Groups  []RedundancyGroup `json:"groups,omitempty"`
}

type RedundancyGroup struct {
	ID        string   `json:"id"`
	Bonds     []string `json:"bonds,omitempty"`
	Bridges   []string `json:"bridges,omitempty"`
	TrackVRRP bool     `json:"track_vrrp,omitempty"`
}

type RedundancyMechanismStatus struct {
	Mechanism string `json:"mechanism"`
	ID        string `json:"id"`
	State     string `json:"state"`
	Reason    string `json:"reason,omitempty"`
	Recovery  string `json:"recovery,omitempty"`
}

type RedundancyTransition struct {
	At        time.Time `json:"at"`
	FromState string    `json:"from_state,omitempty"`
	ToState   string    `json:"to_state"`
	FromRole  string    `json:"from_role,omitempty"`
	ToRole    string    `json:"to_role"`
	Cause     string    `json:"cause,omitempty"`
}

type RedundancyGroupStatus struct {
	ID          string                      `json:"id"`
	State       string                      `json:"state"`
	Role        string                      `json:"role"`
	Cause       string                      `json:"cause,omitempty"`
	Mechanisms  []RedundancyMechanismStatus `json:"mechanisms"`
	LastChange  time.Time                   `json:"last_change,omitempty"`
	Transitions []RedundancyTransition      `json:"transitions,omitempty"`
}

func validateRedundancy(cfg RedundancyConfig, l2cfg *layer2.Config, vrrp VRRPConfig, interfaces []Interface) error {
	if len(cfg.Groups) > 32 {
		return errors.New("redundancy.groups exceeds limit 32")
	}
	if !cfg.Enabled {
		if len(cfg.Groups) != 0 {
			return errors.New("redundancy groups require redundancy.enabled")
		}
		return nil
	}
	if len(cfg.Groups) == 0 {
		return errors.New("enabled redundancy requires at least one group")
	}
	bonds, bridges := map[string]bool{}, map[string]bool{}
	if l2cfg != nil {
		for _, bond := range l2cfg.Bonds {
			bonds[bond.ID] = true
		}
		for _, bridge := range l2cfg.Bridges {
			bridges[bridge.ID] = true
		}
	}
	groupIDs, usedBonds, usedBridges, usedResources := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]string{}
	trackedVRRP := false
	for i, group := range cfg.Groups {
		if !validID(group.ID) || groupIDs[group.ID] {
			return fmt.Errorf("redundancy.groups[%d].id is invalid or duplicated", i)
		}
		groupIDs[group.ID] = true
		if len(group.Bonds)+len(group.Bridges)+boolInt(group.TrackVRRP) == 0 {
			return fmt.Errorf("redundancy group %q must track at least one mechanism", group.ID)
		}
		for _, id := range group.Bonds {
			if !bonds[id] || usedBonds[id] {
				return fmt.Errorf("redundancy group %q references an unknown or already-owned bond %q", group.ID, id)
			}
			usedBonds[id] = true
		}
		for _, id := range group.Bridges {
			if !bridges[id] || usedBridges[id] {
				return fmt.Errorf("redundancy group %q references an unknown or already-owned bridge %q", group.ID, id)
			}
			usedBridges[id] = true
		}
		if group.TrackVRRP {
			if !vrrp.Enabled || trackedVRRP {
				return fmt.Errorf("redundancy group %q requires the enabled, unowned VRRP instance", group.ID)
			}
			trackedVRRP = true
		}
		for resource := range redundancyResources(group, l2cfg, vrrp, interfaces) {
			if owner, exists := usedResources[resource]; exists && owner != group.ID {
				return fmt.Errorf("redundancy groups %q and %q overlap on network/interface resource %q", owner, group.ID, resource)
			}
			usedResources[resource] = group.ID
		}
	}
	return nil
}

func redundancyResources(group RedundancyGroup, cfg *layer2.Config, vrrp VRRPConfig, interfaces []Interface) map[string]bool {
	resources := map[string]bool{}
	if cfg != nil {
		bonds := map[string]layer2.Bond{}
		for _, bond := range cfg.Bonds {
			bonds[bond.ID] = bond
		}
		for _, id := range group.Bonds {
			if bond, ok := bonds[id]; ok {
				resources["interface:"+bond.Interface] = true
				for _, member := range bond.Members {
					resources["interface:"+member] = true
				}
			}
		}
		for _, id := range group.Bridges {
			resources["bridge:"+id] = true
			for _, bridge := range cfg.Bridges {
				if bridge.ID != id {
					continue
				}
				for _, port := range bridge.Ports {
					resources["interface:"+port.Interface] = true
					for _, bond := range cfg.Bonds {
						if bond.Interface == port.Interface {
							for _, member := range bond.Members {
								resources["interface:"+member] = true
							}
						}
					}
				}
			}
		}
	}
	if group.TrackVRRP {
		for _, iface := range interfaces {
			if iface.ID != vrrp.InterfaceID {
				continue
			}
			resources["interface:"+iface.Name] = true
			if cfg == nil {
				continue
			}
			for _, bridge := range cfg.Bridges {
				if bridge.Name == iface.Name {
					resources["bridge:"+bridge.ID] = true
					for _, port := range bridge.Ports {
						resources["interface:"+port.Interface] = true
						for _, bond := range cfg.Bonds {
							if bond.Interface == port.Interface {
								for _, member := range bond.Members {
									resources["interface:"+member] = true
								}
							}
						}
					}
				}
			}
			for _, layerIface := range cfg.Interfaces {
				if layerIface.Name == iface.Name {
					resources["interface:"+layerIface.ID] = true
				}
			}
		}
	}
	return resources
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func evaluateRedundancy(cfg RedundancyConfig, l2cfg *layer2.Config, live *layer2.Capabilities, vrrp VRRPSnapshot) []RedundancyGroupStatus {
	if !cfg.Enabled {
		return nil
	}
	statuses := make([]RedundancyGroupStatus, 0, len(cfg.Groups))
	for _, group := range cfg.Groups {
		status := RedundancyGroupStatus{ID: group.ID, State: "healthy", Role: "active"}
		for _, id := range group.Bonds {
			mechanism := RedundancyMechanismStatus{Mechanism: "lacp", ID: id, State: "degraded", Reason: "bond status is unavailable", Recovery: "restore a member link and wait for LACP collecting/distributing state"}
			if live != nil {
				for _, bond := range live.Bonds {
					if bond.ID == id {
						mechanism.State, mechanism.Reason = "healthy", ""
						if !bond.Applied || bond.ActiveMembers < bond.MinimumActive {
							mechanism.State, mechanism.Reason = "degraded", "active LACP members are below the configured minimum"
						}
						break
					}
				}
			}
			status.Mechanisms = append(status.Mechanisms, mechanism)
		}
		for _, id := range group.Bridges {
			mechanism := RedundancyMechanismStatus{Mechanism: "stp", ID: id, State: "degraded", Reason: "bridge STP state is unavailable", Recovery: "restore the path and wait for the STP/RSTP controller to return the port to forwarding"}
			if l2cfg != nil && live != nil {
				for _, bridge := range l2cfg.Bridges {
					if bridge.ID != id {
						continue
					}
					for _, iface := range live.Interfaces {
						if iface.Name != bridge.Name {
							continue
						}
						ready := iface.STPKnown && iface.STPEnabled
						if bridge.STPMode == "rstp" {
							ready = ready && iface.STPModeKnown && iface.STPControllerKnown && iface.STPMode == "rstp"
						}
						if ready {
							mechanism.State, mechanism.Reason = "healthy", ""
						} else {
							mechanism.Reason = "configured STP controller is not active or verified"
						}
					}
				}
			}
			status.Mechanisms = append(status.Mechanisms, mechanism)
		}
		if group.TrackVRRP {
			mechanism := RedundancyMechanismStatus{Mechanism: "vrrp", ID: "gateway", State: "degraded", Reason: "VRRP service is not active", Recovery: "Keepalived peer election restores the virtual gateway; shadow mode does not preempt"}
			if vrrp.Enabled && vrrp.ServiceActive {
				switch vrrp.Role {
				case "MASTER":
					mechanism.State, mechanism.Reason, status.Role = "healthy", "", "active"
				case "BACKUP":
					mechanism.State, mechanism.Reason, status.Role = "healthy", "", "standby"
				case "FAULT":
					mechanism.Reason = "VRRP reports FAULT"
				default:
					mechanism.Reason = "VRRP role is unknown"
				}
			} else if vrrp.Error != "" {
				mechanism.Reason = vrrp.Error
			}
			status.Mechanisms = append(status.Mechanisms, mechanism)
		}
		for _, mechanism := range status.Mechanisms {
			if mechanism.State != "healthy" {
				status.State = "degraded"
				if status.Cause == "" {
					status.Cause = mechanism.Mechanism
				}
			}
		}
		if status.Cause != "" && status.Role != "standby" {
			status.Role = "degraded"
		}
		statuses = append(statuses, status)
	}
	return statuses
}
