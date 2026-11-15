package layer2

func applyPortMirrorStatus(caps *Capabilities, cfg Config) {
	interfaces := map[string]string{}
	for _, iface := range cfg.Interfaces {
		interfaces[iface.ID] = iface.Name
	}
	hostByName := map[string]HostInterface{}
	for _, iface := range caps.Interfaces {
		hostByName[iface.Name] = iface
	}
	for _, mirror := range cfg.PortMirrors {
		status := PortMirrorStatus{Source: interfaces[mirror.Source], Destination: interfaces[mirror.Destination], Direction: mirror.Direction,
			Network: mirror.Network, CaptureRateBPS: mirror.CaptureRateBPS, CaptureBurstBytes: mirror.CaptureBurstBytes}
		directions := portMirrorDirections(mirror.Direction)
		status.Applied = status.Source != "" && status.Destination != "" && len(directions) > 0
		live, exists := hostByName[status.Source]
		if !exists {
			status.Applied = false
			status.Reason = "source interface is absent from host inventory"
		}
		for _, direction := range directions {
			if !exists {
				break
			}
			priority := portMirrorPriority(direction)
			filters := live.TCFilters
			if direction == "egress" {
				filters = live.TCEgressFilters
			}
			vlan := uint16(0)
			for _, network := range cfg.Networks {
				if network.ID == mirror.Network {
					vlan = network.VLAN
					break
				}
			}
			expected := expectedPortMirrorFilter(direction, status.Destination, vlan)
			found := false
			for _, filter := range filters {
				if filter.Priority == priority && equalTCFilter(filter, expected) {
					found = true
					status.Packets += filter.Packets
					status.Bytes += filter.Bytes
					break
				}
			}
			status.Applied = status.Applied && live.TCClsact && found
		}
		if mirror.CaptureRateBPS > 0 {
			destination, ok := hostByName[status.Destination]
			status.Applied = status.Applied && ok && destination.RootQdisc == "tbf" && destination.RootQdiscRateBPS == mirror.CaptureRateBPS && destination.RootQdiscBurstBytes == mirror.CaptureBurstBytes
		}
		if !status.Applied && status.Reason == "" {
			status.Reason = "effective mirred filters do not match the requested source, destination, and direction"
		}
		caps.PortMirrors = append(caps.PortMirrors, status)
	}
}

func applyMulticastBroadcastRateStatus(caps *Capabilities, cfg Config) {
	names := map[string]string{}
	for _, iface := range cfg.Interfaces {
		names[iface.ID] = iface.Name
	}
	liveByName := map[string]HostInterface{}
	for _, iface := range caps.Interfaces {
		liveByName[iface.Name] = iface
	}
	for _, policy := range cfg.MulticastBroadcastLimits {
		name := names[policy.Interface]
		status := MulticastBroadcastRateLimitStatus{Interface: name, BroadcastRateBPS: policy.BroadcastRateBPS, MulticastRateBPS: policy.MulticastRateBPS, BurstBytes: policy.BurstBytes, Applied: name != ""}
		live, ok := liveByName[name]
		if !ok {
			status.Applied = false
			status.Reason = "interface is absent from host inventory"
		}
		for _, class := range []struct {
			rate      uint64
			multicast bool
		}{{policy.BroadcastRateBPS, false}, {policy.MulticastRateBPS, true}} {
			if class.rate == 0 || !ok {
				continue
			}
			priority := multiBroadcastPriority
			if class.multicast {
				priority = multiMulticastPriority
			}
			expected := ingressRateFilter(class.rate, policy.BurstBytes, class.multicast, priority)
			found := false
			for _, actual := range live.TCFilters {
				if equalTCFilter(actual, expected) {
					found = true
					if class.multicast {
						status.MulticastDrops = actual.Drops
					} else {
						status.BroadcastDrops = actual.Drops
					}
					break
				}
			}
			status.Applied = status.Applied && live.TCClsact && found
		}
		if status.Applied {
			status.Enforcement = "software tc ingress policer"
		} else if status.Reason == "" {
			status.Reason = "effective ingress policers do not match the requested broadcast and multicast rates"
		}
		caps.MulticastBroadcastRateLimits = append(caps.MulticastBroadcastRateLimits, status)
	}
}
