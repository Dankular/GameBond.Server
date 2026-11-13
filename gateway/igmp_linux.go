//go:build linux

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	igmpUnit       = "gamebond-igmpproxy.service"
	igmpConfigPath = "/etc/gamebond/igmpproxy.conf"
)

type IGMPProxySnapshot struct {
	Enabled         bool   `json:"enabled"`
	Active          bool   `json:"active"`
	MulticastRoutes int    `json:"multicast_routes"`
	Error           string `json:"error,omitempty"`
}

func renderIGMPConfig(cfg IGMPProxyConfig, interfaces []Interface) ([]byte, error) {
	byID := make(map[string]string, len(interfaces))
	for _, iface := range interfaces {
		byID[iface.ID] = iface.Name
	}
	upstream := byID[cfg.UpstreamInterfaceID]
	if upstream == "" {
		return nil, errors.New("IGMP upstream interface is not configured")
	}
	var b strings.Builder
	if cfg.QuickLeave {
		b.WriteString("quickleave\n")
	}
	fmt.Fprintf(&b, "phyint %s upstream ratelimit 0 threshold 1\n", upstream)
	for _, prefix := range cfg.AllowedSources {
		fmt.Fprintf(&b, "altnet %s\n", prefix)
	}
	for _, id := range cfg.DownstreamInterfaceIDs {
		iface := byID[id]
		if iface == "" {
			return nil, fmt.Errorf("IGMP downstream interface %q is not configured", id)
		}
		fmt.Fprintf(&b, "phyint %s downstream ratelimit 0 threshold 1\n", iface)
	}
	return []byte(b.String()), nil
}

func validateIGMPHost(ctx context.Context, runner Runner, cfg Config) error {
	if !runner.Available("igmpproxy") || !runner.Available("systemctl") || !runner.Available("ip") {
		return errors.New("IGMP proxy requires igmpproxy, systemctl, and iproute2")
	}
	loaded, err := runner.Run(ctx, "systemctl", "show", "--property=LoadState", "--value", igmpUnit)
	if err != nil {
		return fmt.Errorf("inspect GameBond IGMP proxy service: %w", err)
	}
	if strings.TrimSpace(string(loaded.Stdout)) != "loaded" {
		return errors.New("gamebond-igmpproxy.service is not installed; install the GameBond IGMP proxy unit and reload systemd")
	}
	ids := append([]string{cfg.IGMPProxy.UpstreamInterfaceID}, cfg.IGMPProxy.DownstreamInterfaceIDs...)
	interfaces := make(map[string]Interface, len(cfg.Interfaces))
	for _, iface := range cfg.Interfaces {
		interfaces[iface.ID] = iface
	}
	var networks []netip.Prefix
	for _, id := range ids {
		iface := interfaces[id]
		result, err := runner.Run(ctx, "ip", "-j", "addr", "show", "dev", iface.Name)
		if err != nil {
			return fmt.Errorf("inspect IGMP interface %s: %w", iface.Name, err)
		}
		var rows []struct {
			AddrInfo []struct {
				Family    string `json:"family"`
				Local     string `json:"local"`
				PrefixLen int    `json:"prefixlen"`
			} `json:"addr_info"`
		}
		if err := json.Unmarshal(result.Stdout, &rows); err != nil {
			return fmt.Errorf("decode IGMP interface %s: %w", iface.Name, err)
		}
		var prefix netip.Prefix
		for _, row := range rows {
			for _, address := range row.AddrInfo {
				if address.Family != "inet" || address.PrefixLen < 0 || address.PrefixLen > 32 {
					continue
				}
				local, e := netip.ParseAddr(address.Local)
				if e == nil && local.Is4() {
					prefix = netip.PrefixFrom(local, address.PrefixLen).Masked()
					break
				}
			}
			if prefix.IsValid() {
				break
			}
		}
		if !prefix.IsValid() {
			return fmt.Errorf("IGMP interface %s has no IPv4 address", iface.Name)
		}
		for _, prior := range networks {
			if prior.Contains(prefix.Addr()) || prefix.Contains(prior.Addr()) {
				return fmt.Errorf("IGMP interfaces use overlapping subnets %s and %s", prior, prefix)
			}
		}
		networks = append(networks, prefix)
	}
	if _, err := renderIGMPConfig(cfg.IGMPProxy, cfg.Interfaces); err != nil {
		return err
	}
	return nil
}

func writeIGMPConfig(data []byte) error {
	if err := os.MkdirAll(filepath.Dir(igmpConfigPath), 0750); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(igmpConfigPath), ".igmpproxy-*.tmp")
	if err != nil {
		return fmt.Errorf("create IGMP config temp file: %w", err)
	}
	temp := f.Name()
	defer os.Remove(temp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return fmt.Errorf("write IGMP config: %w", err)
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(temp, igmpConfigPath); err != nil {
		return fmt.Errorf("replace IGMP config: %w", err)
	}
	return nil
}

func applyIGMPTransition(ctx context.Context, runner Runner, cfg Config) error {
	if cfg.IGMPProxy.Enabled {
		data, err := renderIGMPConfig(cfg.IGMPProxy, cfg.Interfaces)
		if err != nil {
			return err
		}
		if err := writeIGMPConfig(data); err != nil {
			return err
		}
		if _, err := runner.Run(ctx, "systemctl", "restart", igmpUnit); err != nil {
			return fmt.Errorf("restart GameBond IGMP proxy: %w", err)
		}
		return nil
	}
	if _, err := runner.Run(ctx, "systemctl", "stop", igmpUnit); err != nil {
		return fmt.Errorf("stop GameBond IGMP proxy: %w", err)
	}
	return nil
}

func snapshotIGMP(ctx context.Context, runner Runner, enabled bool) IGMPProxySnapshot {
	out := IGMPProxySnapshot{Enabled: enabled}
	if !enabled {
		return out
	}
	if _, err := runner.Run(ctx, "systemctl", "is-active", "--quiet", igmpUnit); err != nil {
		out.Error = err.Error()
		return out
	}
	out.Active = true
	routes, err := runner.Run(ctx, "ip", "mroute", "show")
	if err != nil {
		out.Error = err.Error()
		return out
	}
	for _, line := range strings.Split(strings.TrimSpace(string(routes.Stdout)), "\n") {
		if strings.TrimSpace(line) != "" {
			out.MulticastRoutes++
		}
	}
	return out
}

func verifyIGMP(ctx context.Context, runner Runner, enabled bool) error {
	status := snapshotIGMP(ctx, runner, enabled)
	if status.Error != "" || status.Active != enabled {
		return fmt.Errorf("IGMP proxy service verification failed: %s", status.Error)
	}
	return nil
}

func igmpInterfaceNames(cfg Config) []string {
	byID := make(map[string]string, len(cfg.Interfaces))
	for _, iface := range cfg.Interfaces {
		byID[iface.ID] = iface.Name
	}
	names := []string{}
	if cfg.IGMPProxy.Enabled {
		names = append(names, byID[cfg.IGMPProxy.UpstreamInterfaceID])
		for _, id := range cfg.IGMPProxy.DownstreamInterfaceIDs {
			names = append(names, byID[id])
		}
	}
	sort.Strings(names)
	return names
}
