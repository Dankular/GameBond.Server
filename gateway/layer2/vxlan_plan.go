package layer2

import (
	"fmt"
	"net/netip"
)

const defaultVXLANPort = 4789

func vxlanUDPPort(device VXLANDevice) uint16 {
	if device.UDPPort == 0 {
		return defaultVXLANPort
	}
	return device.UDPPort
}

func vxlanByID(devices []VXLANDevice) map[string]VXLANDevice {
	out := make(map[string]VXLANDevice, len(devices))
	for _, device := range devices {
		out[device.ID] = device
	}
	return out
}

func managedVXLANInterfaceMatches(live HostInterface, device VXLANDevice, local netip.Addr) bool {
	return live.Kind == "vxlan" && live.VXLANKnown && live.VXLANID == device.VNI &&
		live.VXLANLocal == local.String() && live.VXLANDstPort == vxlanUDPPort(device)
}

func managedTapInterface(live HostInterface) bool {
	return live.Kind == "tun" || live.Kind == "tap"
}

// buildVXLANChanges creates only new desired devices and returns their synthetic
// live-link entries so the ordinary bridge/VLAN planner can attach them. Existing
// devices are adopted only when the previous desired config owned them.
func buildVXLANChanges(previous, desired Config, interfaces map[string]HostInterface) ([]Change, []Change, map[string]HostInterface, error) {
	previousByID := vxlanByID(previous.VXLANDevices)
	desiredByID := vxlanByID(desired.VXLANDevices)
	interfaceByID := make(map[string]Interface, len(desired.Interfaces))
	for _, iface := range desired.Interfaces {
		interfaceByID[iface.ID] = iface
	}
	networkByID := make(map[string]Network, len(desired.Networks))
	for _, network := range desired.Networks {
		networkByID[network.ID] = network
	}
	var creates, deletes []Change
	synthetic := make(map[string]HostInterface)
	for _, device := range desired.VXLANDevices {
		old, owned := previousByID[device.ID]
		tap, tapOK := interfaceByID[device.TapInterface]
		vxlan, vxlanOK := interfaceByID[device.VxlanInterface]
		underlay, underlayOK := interfaceByID[device.UnderlayInterface]
		if !tapOK || !vxlanOK || !underlayOK {
			return nil, nil, nil, fmt.Errorf("VXLAN device %q references an interface missing from desired config", device.ID)
		}
		if owned {
			oldTap, oldTapOK := findInterface(previous.Interfaces, old.TapInterface)
			oldVXLAN, oldVXLANOK := findInterface(previous.Interfaces, old.VxlanInterface)
			if !oldTapOK || !oldVXLANOK || oldTap.Name != tap.Name || oldVXLAN.Name != vxlan.Name || old.VNI != device.VNI || old.LocalAddress != device.LocalAddress || old.UnderlayInterface != device.UnderlayInterface || vxlanUDPPort(old) != vxlanUDPPort(device) {
				return nil, nil, nil, fmt.Errorf("managed VXLAN device %q VNI, underlay, and interface names are immutable; remove it in one apply before recreating", device.ID)
			}
		}
		local, _ := netip.ParseAddr(device.LocalAddress) // Config.Validate has already checked this.
		network := networkByID[device.Network]
		mtu := network.MTU
		if mtu == 0 {
			mtu = 1500
		}
		liveUnderlay, underlayExists := interfaces[underlay.Name]
		if !underlayExists || !liveUnderlay.AdminUp || liveUnderlay.MTU == 0 {
			return nil, nil, nil, fmt.Errorf("VXLAN device %q underlay %q must exist, be up, and report an MTU", device.ID, underlay.Name)
		}
		overhead := 50
		if local.Is6() {
			overhead = 70
		}
		if liveUnderlay.MTU < mtu+overhead {
			return nil, nil, nil, fmt.Errorf("VXLAN device %q underlay %q MTU %d is below inner MTU %d plus %d-byte encapsulation overhead", device.ID, underlay.Name, liveUnderlay.MTU, mtu, overhead)
		}
		liveTap, tapExists := interfaces[tap.Name]
		if tapExists {
			if !owned || !managedTapInterface(liveTap) {
				return nil, nil, nil, fmt.Errorf("TAP interface %q already exists and is not owned by a previous GameBond VXLAN config", tap.Name)
			}
		} else {
			creates = append(creates, Change{Description: "create persistent VXLAN segment TAP " + tap.Name,
				Apply:    Command{Tool: "ip", Args: []string{"tuntap", "add", "dev", tap.Name, "mode", "tap"}},
				Rollback: Command{Tool: "ip", Args: []string{"link", "del", "dev", tap.Name}}})
			creates = append(creates, Change{Description: "set VXLAN segment TAP MTU " + tap.Name,
				Apply:    Command{Tool: "ip", Args: []string{"link", "set", "dev", tap.Name, "mtu", fmt.Sprint(mtu)}},
				Rollback: Command{Tool: "ip", Args: []string{"link", "set", "dev", tap.Name, "mtu", "1500"}}})
			liveTap = HostInterface{Name: tap.Name, Kind: "tun", MTU: mtu, MaxMTU: 65535}
		}
		liveVXLAN, vxlanExists := interfaces[vxlan.Name]
		if vxlanExists {
			if !owned || !managedVXLANInterfaceMatches(liveVXLAN, device, local) {
				return nil, nil, nil, fmt.Errorf("VXLAN interface %q exists but is unmanaged or differs from the saved VNI/underlay", vxlan.Name)
			}
		} else {
			creates = append(creates, Change{Description: "create kernel VXLAN device " + device.ID,
				Apply:    Command{Tool: "ip", Args: []string{"link", "add", "name", vxlan.Name, "mtu", fmt.Sprint(mtu), "type", "vxlan", "id", fmt.Sprint(device.VNI), "local", local.String(), "dev", underlay.Name, "dstport", fmt.Sprint(vxlanUDPPort(device)), "nolearning"}},
				Rollback: Command{Tool: "ip", Args: []string{"link", "del", "dev", vxlan.Name}}})
			liveVXLAN = HostInterface{Name: vxlan.Name, Kind: "vxlan", MTU: mtu, MaxMTU: 65535,
				VXLANKnown: true, VXLANID: device.VNI, VXLANLocal: local.String(), VXLANDstPort: vxlanUDPPort(device)}
		}
		synthetic[tap.Name], synthetic[vxlan.Name] = liveTap, liveVXLAN
	}
	for id, old := range previousByID {
		if _, retained := desiredByID[id]; retained {
			continue
		}
		if _, stillConfigured := findInterface(desired.Interfaces, old.TapInterface); stillConfigured {
			return nil, nil, nil, fmt.Errorf("remove managed VXLAN device %q and its TAP interface from desired config together", id)
		}
		if _, stillConfigured := findInterface(desired.Interfaces, old.VxlanInterface); stillConfigured {
			return nil, nil, nil, fmt.Errorf("remove managed VXLAN device %q and its VXLAN interface from desired config together", id)
		}
		oldTap, tapOK := findInterface(previous.Interfaces, old.TapInterface)
		oldVXLAN, vxlanOK := findInterface(previous.Interfaces, old.VxlanInterface)
		oldUnderlay, underlayOK := findInterface(previous.Interfaces, old.UnderlayInterface)
		if !tapOK || !vxlanOK || !underlayOK {
			return nil, nil, nil, fmt.Errorf("previously managed VXLAN device %q has incomplete interface state", id)
		}
		if live, exists := interfaces[oldVXLAN.Name]; exists {
			local, _ := netip.ParseAddr(old.LocalAddress)
			if !managedVXLANInterfaceMatches(live, old, local) {
				return nil, nil, nil, fmt.Errorf("previously managed VXLAN interface %q changed outside GameBond", oldVXLAN.Name)
			}
			oldNetwork := Network{}
			for _, network := range previous.Networks {
				if network.ID == old.Network {
					oldNetwork = network
					break
				}
			}
			deletes = append(deletes, Change{Description: "delete managed VXLAN device " + id,
				Apply:    Command{Tool: "ip", Args: []string{"link", "del", "dev", oldVXLAN.Name}},
				Rollback: Command{Tool: "ip", Args: []string{"link", "add", "name", oldVXLAN.Name, "mtu", fmt.Sprint(oldNetwork.MTU), "type", "vxlan", "id", fmt.Sprint(old.VNI), "local", local.String(), "dev", oldUnderlay.Name, "dstport", fmt.Sprint(vxlanUDPPort(old)), "nolearning"}}})
		}
		if live, exists := interfaces[oldTap.Name]; exists {
			if !managedTapInterface(live) {
				return nil, nil, nil, fmt.Errorf("previously managed VXLAN TAP %q changed type outside GameBond", oldTap.Name)
			}
			deletes = append(deletes, Change{Description: "delete managed VXLAN segment TAP " + oldTap.Name,
				Apply:    Command{Tool: "ip", Args: []string{"link", "del", "dev", oldTap.Name}},
				Rollback: Command{Tool: "ip", Args: []string{"tuntap", "add", "dev", oldTap.Name, "mode", "tap"}}})
		}
	}
	return creates, deletes, synthetic, nil
}
