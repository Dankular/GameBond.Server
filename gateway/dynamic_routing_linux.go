//go:build linux

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	frrConfigDir = "/etc/frr/gamebond"
	zebraUnit    = "gamebond-zebra.service"
	ospfUnit     = "gamebond-ospfd.service"
	bgpUnit      = "gamebond-bgpd.service"
)

type DynamicRoutingSnapshot struct {
	Enabled       bool   `json:"enabled"`
	ZebraActive   bool   `json:"zebra_active"`
	OSPFActive    bool   `json:"ospf_active"`
	BGPActive     bool   `json:"bgp_active"`
	OSPFNeighbors string `json:"ospf_neighbors,omitempty"`
	BGPSummary    string `json:"bgp_summary,omitempty"`
	Error         string `json:"error,omitempty"`
}

func renderFRRConfigs(cfg DynamicRoutingConfig, interfaces []Interface) (map[string][]byte, error) {
	if !cfg.Enabled {
		return map[string][]byte{}, nil
	}
	if err := cfg.Validate(interfaces); err != nil {
		return nil, err
	}
	byID := make(map[string]string, len(interfaces))
	for _, iface := range interfaces {
		byID[iface.ID] = iface.Name
	}
	base := "! GameBond managed FRR configuration v1\nfrr defaults traditional\nhostname gamebond\n"
	configs := map[string][]byte{"zebra": []byte(base + "")}
	if cfg.OSPF.Enabled {
		var b strings.Builder
		b.WriteString(base)
		fmt.Fprintf(&b, "router ospf\n ospf router-id %s\n passive-interface default\n", cfg.RouterID)
		for _, item := range cfg.OSPF.Interfaces {
			name := byID[item.InterfaceID]
			fmt.Fprintf(&b, "interface %s\n ip ospf area %s\n", name, item.Area)
			if !item.Passive {
				fmt.Fprintf(&b, "router ospf\n no passive-interface %s\n", name)
			}
		}
		configs["ospfd"] = []byte(b.String())
	}
	if cfg.BGP.Enabled {
		var b strings.Builder
		b.WriteString(base)
		fmt.Fprintf(&b, "router bgp %d\n bgp router-id %s\n", cfg.BGP.LocalAS, cfg.RouterID)
		for _, peer := range cfg.BGP.Neighbors {
			fmt.Fprintf(&b, " neighbor %s remote-as %d\n", peer.Address, peer.RemoteAS)
			if peer.UpdateSourceInterfaceID != "" {
				fmt.Fprintf(&b, " neighbor %s update-source %s\n", peer.Address, byID[peer.UpdateSourceInterfaceID])
			}
		}
		families := map[bool][]BGPNeighbor{true: {}, false: {}}
		for _, peer := range cfg.BGP.Neighbors {
			address, _ := netip.ParseAddr(peer.Address)
			addrIs4 := address.Is4()
			families[addrIs4] = append(families[addrIs4], peer)
		}
		for _, ipv4 := range []bool{true, false} {
			peers := families[ipv4]
			if len(peers) == 0 {
				continue
			}
			family := "ipv6"
			networkCmd := "network"
			if ipv4 {
				family = "ipv4"
			}
			fmt.Fprintf(&b, " address-family %s unicast\n", family)
			for _, peer := range peers {
				fmt.Fprintf(&b, "  neighbor %s activate\n", peer.Address)
				for _, direction := range []struct {
					name     string
					prefixes []string
				}{{"IN", peer.Import}, {"OUT", peer.Export}} {
					listName := "GB_" + strings.ToUpper(strings.ReplaceAll(peer.ID, "-", "_")) + "_" + direction.name
					fmt.Fprintf(&b, "  neighbor %s prefix-list %s %s\n", peer.Address, listName, strings.ToLower(direction.name))
				}
			}
			for _, peer := range peers {
				for _, prefix := range peer.Export {
					fmt.Fprintf(&b, "  %s %s\n", networkCmd, prefix)
				}
			}
			b.WriteString(" exit-address-family\n")
		}
		// Prefix lists are global configuration and default to deny when empty.
		b.WriteString("exit\n")
		for _, peer := range cfg.BGP.Neighbors {
			for _, direction := range []struct {
				name     string
				prefixes []string
			}{{"IN", peer.Import}, {"OUT", peer.Export}} {
				name := "GB_" + strings.ToUpper(strings.ReplaceAll(peer.ID, "-", "_")) + "_" + direction.name
				prefixCmd := "ipv6 prefix-list"
				if strings.Contains(peer.Address, ".") {
					prefixCmd = "ip prefix-list"
				}
				for seq, prefix := range direction.prefixes {
					fmt.Fprintf(&b, "%s %s seq %d permit %s\n", prefixCmd, name, (seq+1)*10, prefix)
				}
				if len(direction.prefixes) == 0 {
					denyAll := "::/0"
					if strings.Contains(peer.Address, ".") {
						denyAll = "0.0.0.0/0"
					}
					fmt.Fprintf(&b, "%s %s seq 10 deny %s\n", prefixCmd, name, denyAll)
				}
			}
		}
		configs["bgpd"] = []byte(b.String())
	}
	return configs, nil
}

func validateFRRHost(ctx context.Context, runner Runner, cfg Config) error {
	if !cfg.DynamicRouting.Enabled {
		return nil
	}
	for _, tool := range []string{"zebra", "vtysh", "systemctl", "ip"} {
		if !runner.Available(tool) {
			return fmt.Errorf("dynamic routing requires FRRouting (%s) and systemctl", tool)
		}
	}
	if cfg.DynamicRouting.OSPF.Enabled && !runner.Available("ospfd") {
		return errors.New("OSPF requires the FRRouting ospfd daemon")
	}
	if cfg.DynamicRouting.BGP.Enabled && !runner.Available("bgpd") {
		return errors.New("BGP requires the FRRouting bgpd daemon")
	}
	units := []string{zebraUnit}
	if cfg.DynamicRouting.OSPF.Enabled {
		units = append(units, ospfUnit)
	}
	if cfg.DynamicRouting.BGP.Enabled {
		units = append(units, bgpUnit)
	}
	for _, unit := range units {
		result, err := runner.Run(ctx, "systemctl", "show", "--property=LoadState", "--value", unit)
		if err != nil {
			return fmt.Errorf("inspect %s: %w", unit, err)
		}
		if strings.TrimSpace(string(result.Stdout)) != "loaded" {
			return fmt.Errorf("%s is not installed; install the GameBond FRR service unit and reload systemd", unit)
		}
	}
	if _, err := user.Lookup("frr"); err != nil {
		return errors.New("dynamic routing requires the frr service account")
	}
	if _, err := user.LookupGroup("frr"); err != nil {
		return errors.New("dynamic routing requires the frr service group")
	}
	byID := make(map[string]string, len(cfg.Interfaces))
	for _, iface := range cfg.Interfaces {
		byID[iface.ID] = iface.Name
	}
	for _, item := range cfg.DynamicRouting.OSPF.Interfaces {
		result, err := runner.Run(ctx, "ip", "-j", "addr", "show", "dev", byID[item.InterfaceID])
		if err != nil {
			return fmt.Errorf("inspect OSPF interface %s: %w", byID[item.InterfaceID], err)
		}
		var rows []struct {
			AddrInfo []struct {
				Family string `json:"family"`
			} `json:"addr_info"`
		}
		if err := json.Unmarshal(result.Stdout, &rows); err != nil {
			return fmt.Errorf("decode OSPF interface %s: %w", byID[item.InterfaceID], err)
		}
		found := false
		for _, row := range rows {
			for _, address := range row.AddrInfo {
				if address.Family == "inet" {
					found = true
				}
			}
		}
		if !found {
			return fmt.Errorf("OSPF interface %s has no IPv4 address", byID[item.InterfaceID])
		}
	}
	if _, err := renderFRRConfigs(cfg.DynamicRouting, cfg.Interfaces); err != nil {
		return err
	}
	return nil
}

func writeFRRConfigs(cfg Config) error {
	configs, err := renderFRRConfigs(cfg.DynamicRouting, cfg.Interfaces)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(frrConfigDir, 0750); err != nil {
		return err
	}
	group, err := user.LookupGroup("frr")
	if err != nil {
		return fmt.Errorf("look up FRR group: %w", err)
	}
	groupID, err := strconv.Atoi(group.Gid)
	if err != nil {
		return fmt.Errorf("parse FRR group ID: %w", err)
	}
	if err := os.Chown(frrConfigDir, 0, groupID); err != nil {
		return fmt.Errorf("set FRR config directory ownership: %w", err)
	}
	for _, daemon := range []string{"zebra", "ospfd", "bgpd"} {
		path := filepath.Join(frrConfigDir, daemon+".conf")
		prior, readErr := os.ReadFile(path)
		if readErr == nil && !strings.HasPrefix(string(prior), "! GameBond managed FRR configuration v1\n") {
			return fmt.Errorf("refusing to replace unmanaged FRR config %s", path)
		}
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			return readErr
		}
		data, enabled := configs[daemon]
		if !enabled {
			if readErr == nil {
				if err := os.Remove(path); err != nil {
					return err
				}
			}
			continue
		}
		f, err := os.CreateTemp(frrConfigDir, "."+daemon+"-*.tmp")
		if err != nil {
			return err
		}
		temp := f.Name()
		if err = f.Chmod(0640); err == nil {
			err = f.Chown(0, groupID)
		}
		if err == nil {
			_, err = f.Write(data)
		}
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil {
			_ = os.Remove(temp)
			return fmt.Errorf("write %s config: %w", daemon, err)
		}
		if closeErr != nil {
			_ = os.Remove(temp)
			return closeErr
		}
		if err := os.Rename(temp, path); err != nil {
			_ = os.Remove(temp)
			return err
		}
	}
	return nil
}

func applyDynamicRoutingTransition(ctx context.Context, runner Runner, cfg Config) error {
	for _, unit := range []string{ospfUnit, bgpUnit, zebraUnit} {
		if _, err := runner.Run(ctx, "systemctl", "is-active", "--quiet", unit); err == nil {
			if _, err := runner.Run(ctx, "systemctl", "stop", unit); err != nil {
				return fmt.Errorf("stop %s: %w", unit, err)
			}
		}
	}
	if !cfg.DynamicRouting.Enabled {
		return writeFRRConfigs(cfg)
	}
	if err := writeFRRConfigs(cfg); err != nil {
		return err
	}
	if _, err := runner.Run(ctx, "systemctl", "start", zebraUnit); err != nil {
		return fmt.Errorf("start GameBond FRR zebra: %w", err)
	}
	if cfg.DynamicRouting.OSPF.Enabled {
		if _, err := runner.Run(ctx, "systemctl", "start", ospfUnit); err != nil {
			return fmt.Errorf("start GameBond OSPF: %w", err)
		}
	}
	if cfg.DynamicRouting.BGP.Enabled {
		if _, err := runner.Run(ctx, "systemctl", "start", bgpUnit); err != nil {
			return fmt.Errorf("start GameBond BGP: %w", err)
		}
	}
	return nil
}

func snapshotDynamicRouting(ctx context.Context, runner Runner, cfg DynamicRoutingConfig) DynamicRoutingSnapshot {
	out := DynamicRoutingSnapshot{Enabled: cfg.Enabled}
	if !cfg.Enabled {
		return out
	}
	for _, item := range []struct {
		unit   string
		target *bool
	}{{zebraUnit, &out.ZebraActive}, {ospfUnit, &out.OSPFActive}, {bgpUnit, &out.BGPActive}} {
		if _, err := runner.Run(ctx, "systemctl", "is-active", "--quiet", item.unit); err == nil {
			*item.target = true
		}
	}
	if cfg.OSPF.Enabled {
		if result, err := runner.Run(ctx, "vtysh", "-N", "gamebond", "-c", "show ip ospf neighbor json"); err == nil {
			out.OSPFNeighbors = strings.TrimSpace(string(result.Stdout))
		} else {
			out.Error = err.Error()
		}
	}
	if cfg.BGP.Enabled {
		if result, err := runner.Run(ctx, "vtysh", "-N", "gamebond", "-c", "show bgp summary json"); err == nil {
			out.BGPSummary = strings.TrimSpace(string(result.Stdout))
		} else if out.Error == "" {
			out.Error = err.Error()
		}
	}
	return out
}

func verifyDynamicRouting(ctx context.Context, runner Runner, cfg DynamicRoutingConfig) error {
	if !cfg.Enabled {
		for _, unit := range []string{zebraUnit, ospfUnit, bgpUnit} {
			if _, err := runner.Run(ctx, "systemctl", "is-active", "--quiet", unit); err == nil {
				return fmt.Errorf("%s remained active after dynamic routing was disabled", unit)
			}
		}
		return nil
	}
	status := snapshotDynamicRouting(ctx, runner, cfg)
	if status.Error != "" {
		return fmt.Errorf("inspect GameBond FRR: %s", status.Error)
	}
	if !status.ZebraActive || status.OSPFActive != cfg.OSPF.Enabled || status.BGPActive != cfg.BGP.Enabled {
		return errors.New("GameBond FRR service verification failed")
	}
	return nil
}

func dynamicRoutingServiceNames(cfg DynamicRoutingConfig) []string {
	names := []string{}
	if cfg.Enabled {
		names = append(names, zebraUnit)
		if cfg.OSPF.Enabled {
			names = append(names, ospfUnit)
		}
		if cfg.BGP.Enabled {
			names = append(names, bgpUnit)
		}
	}
	sort.Strings(names)
	return names
}
