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
	vrrpUnit       = "gamebond-keepalived.service"
	vrrpConfigPath = "/etc/gamebond/keepalived.conf"
)

type VRRPSnapshot struct {
	Enabled        bool     `json:"enabled"`
	ServiceActive  bool     `json:"service_active"`
	Role           string   `json:"role,omitempty"`
	OwnedAddresses []string `json:"owned_addresses,omitempty"`
	Error          string   `json:"error,omitempty"`
}

func renderKeepalivedConfig(cfg VRRPConfig, interfaces []Interface, source string) ([]byte, error) {
	name := ""
	for _, iface := range interfaces {
		if iface.ID == cfg.InterfaceID {
			name = iface.Name
			break
		}
	}
	if name == "" {
		return nil, errors.New("VRRP interface is not configured")
	}
	if addr, err := netip.ParseAddr(source); err != nil || addr.IsUnspecified() || addr.IsMulticast() {
		return nil, errors.New("VRRP source address is invalid")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "global_defs {\n  router_id GAMEBOND_SHADOW\n}\n\n")
	fmt.Fprintf(&b, "vrrp_instance GB_%d {\n  state BACKUP\n  interface %s\n  version 3\n  virtual_router_id %d\n  priority %d\n  advert_int %d\n  nopreempt\n  unicast_src_ip %s\n  unicast_peer {\n",
		cfg.VirtualRouterID, name, cfg.VirtualRouterID, cfg.Priority, cfg.AdvertisementIntervalSecs, source)
	for _, peer := range cfg.Peers {
		fmt.Fprintf(&b, "    %s\n", peer)
	}
	b.WriteString("  }\n  virtual_ipaddress {\n")
	for _, address := range cfg.VirtualAddresses {
		fmt.Fprintf(&b, "    %s dev %s\n", address, name)
	}
	b.WriteString("  }\n}\n")
	return []byte(b.String()), nil
}

func validateKeepalivedHost(ctx context.Context, runner Runner, cfg Config) error {
	if !runner.Available("keepalived") || !runner.Available("systemctl") || !runner.Available("ip") {
		return errors.New("VRRP requires keepalived, systemctl, and iproute2")
	}
	loaded, err := runner.Run(ctx, "systemctl", "show", "--property=LoadState", "--value", vrrpUnit)
	if err != nil {
		return fmt.Errorf("inspect GameBond Keepalived service: %w", err)
	}
	if strings.TrimSpace(string(loaded.Stdout)) != "loaded" {
		return errors.New("gamebond-keepalived.service is not installed; install the GameBond VRRP unit and reload systemd")
	}
	iface := ""
	for _, configured := range cfg.Interfaces {
		if configured.ID == cfg.VRRP.InterfaceID {
			iface = configured.Name
			break
		}
	}
	if iface == "" {
		return errors.New("VRRP interface is not configured")
	}
	result, err := runner.Run(ctx, "ip", "-j", "addr", "show", "dev", iface)
	if err != nil {
		return fmt.Errorf("inspect VRRP interface %s: %w", iface, err)
	}
	var rows []struct {
		AddrInfo []struct {
			Local     string `json:"local"`
			PrefixLen int    `json:"prefixlen"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal(result.Stdout, &rows); err != nil {
		return fmt.Errorf("parse VRRP interface addresses: %w", err)
	}
	family, _ := addressFamily(cfg.VRRP.VirtualAddresses[0])
	var source netip.Addr
	var subnet netip.Prefix
	for _, row := range rows {
		for _, address := range row.AddrInfo {
			local, err := netip.ParseAddr(address.Local)
			if err != nil || local.Is4() != (family == 4) || address.PrefixLen < 0 || address.PrefixLen > local.BitLen() {
				continue
			}
			source = local
			subnet = netip.PrefixFrom(local, address.PrefixLen).Masked()
			break
		}
	}
	if !source.IsValid() {
		return fmt.Errorf("VRRP interface %s has no IPv%d source address", iface, family)
	}
	for _, peer := range cfg.VRRP.Peers {
		if !subnet.Contains(netip.MustParseAddr(peer)) {
			return fmt.Errorf("VRRP peer %s is outside interface subnet %s", peer, subnet)
		}
	}
	for _, value := range cfg.VRRP.VirtualAddresses {
		vip, _ := netip.ParsePrefix(value)
		if !subnet.Contains(vip.Addr()) {
			return fmt.Errorf("VRRP virtual address %s is outside interface subnet %s", value, subnet)
		}
	}
	data, err := renderKeepalivedConfig(cfg.VRRP, cfg.Interfaces, source.String())
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp("/run/gamebond", ".keepalived-check-*.conf")
	if err != nil {
		return fmt.Errorf("create temporary Keepalived config: %w", err)
	}
	path := temp.Name()
	defer os.Remove(path)
	if err := temp.Chmod(0600); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return fmt.Errorf("write temporary Keepalived config: %w", err)
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if _, err := runner.Run(ctx, "keepalived", "-t", "-f", path); err != nil {
		return fmt.Errorf("validate Keepalived config: %w", err)
	}
	return nil
}

func writeKeepalivedConfig(data []byte) error {
	if err := os.MkdirAll(filepath.Dir(vrrpConfigPath), 0750); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(vrrpConfigPath), ".keepalived-*.tmp")
	if err != nil {
		return fmt.Errorf("create Keepalived config temp file: %w", err)
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
		return fmt.Errorf("write Keepalived config: %w", err)
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(temp, vrrpConfigPath); err != nil {
		return fmt.Errorf("replace Keepalived config: %w", err)
	}
	return nil
}

func applyVRRPTransition(ctx context.Context, runner Runner, cfg Config) error {
	if cfg.VRRP.Enabled {
		result, err := runner.Run(ctx, "ip", "-j", "addr", "show", "dev", findInterfaceName(cfg.Interfaces, cfg.VRRP.InterfaceID))
		if err != nil {
			return err
		}
		var rows []struct {
			AddrInfo []struct {
				Local string `json:"local"`
			} `json:"addr_info"`
		}
		if err := json.Unmarshal(result.Stdout, &rows); err != nil {
			return err
		}
		family, _ := addressFamily(cfg.VRRP.VirtualAddresses[0])
		source := ""
		for _, row := range rows {
			for _, address := range row.AddrInfo {
				parsed, err := netip.ParseAddr(address.Local)
				if err == nil && parsed.Is4() == (family == 4) {
					source = parsed.String()
					break
				}
			}
			if source != "" {
				break
			}
		}
		data, err := renderKeepalivedConfig(cfg.VRRP, cfg.Interfaces, source)
		if err != nil {
			return err
		}
		if err := writeKeepalivedConfig(data); err != nil {
			return err
		}
		if _, err := runner.Run(ctx, "systemctl", "restart", vrrpUnit); err != nil {
			return fmt.Errorf("restart GameBond VRRP service: %w", err)
		}
		return nil
	}
	if _, err := runner.Run(ctx, "systemctl", "stop", vrrpUnit); err != nil {
		return fmt.Errorf("stop GameBond VRRP service: %w", err)
	}
	return nil
}

func findInterfaceName(interfaces []Interface, id string) string {
	for _, iface := range interfaces {
		if iface.ID == id {
			return iface.Name
		}
	}
	return ""
}

func snapshotVRRP(ctx context.Context, runner Runner, cfg Config) VRRPSnapshot {
	out := VRRPSnapshot{Enabled: cfg.VRRP.Enabled, OwnedAddresses: []string{}}
	if !cfg.VRRP.Enabled {
		return out
	}
	_, err := runner.Run(ctx, "systemctl", "is-active", "--quiet", vrrpUnit)
	if err != nil {
		out.Role = "FAULT"
		out.Error = err.Error()
		return out
	}
	out.ServiceActive = true
	name := findInterfaceName(cfg.Interfaces, cfg.VRRP.InterfaceID)
	linkResult, err := runner.Run(ctx, "ip", "-json", "link", "show", "dev", name)
	if err != nil {
		out.Role = "FAULT"
		out.Error = err.Error()
		return out
	}
	var links []struct {
		Flags     []string `json:"flags"`
		OperState string   `json:"operstate"`
	}
	if err := json.Unmarshal(linkResult.Stdout, &links); err != nil || len(links) != 1 {
		out.Role = "FAULT"
		if err != nil {
			out.Error = err.Error()
		} else {
			out.Error = "VRRP interface state is unavailable"
		}
		return out
	}
	up := false
	for _, flag := range links[0].Flags {
		if strings.EqualFold(flag, "UP") {
			up = true
		}
	}
	if !up || strings.EqualFold(links[0].OperState, "DOWN") || strings.EqualFold(links[0].OperState, "NOTPRESENT") {
		out.Role = "FAULT"
		out.Error = "VRRP interface is down"
		return out
	}
	result, err := runner.Run(ctx, "ip", "-j", "addr", "show", "dev", name)
	if err != nil {
		out.Role = "FAULT"
		out.Error = err.Error()
		return out
	}
	var rows []struct {
		AddrInfo []struct {
			Local     string `json:"local"`
			PrefixLen int    `json:"prefixlen"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal(result.Stdout, &rows); err != nil {
		out.Role = "FAULT"
		out.Error = err.Error()
		return out
	}
	for _, wanted := range cfg.VRRP.VirtualAddresses {
		prefix, _ := netip.ParsePrefix(wanted)
		for _, row := range rows {
			for _, address := range row.AddrInfo {
				if local, err := netip.ParseAddr(address.Local); err == nil && local == prefix.Addr() && address.PrefixLen == prefix.Bits() {
					out.OwnedAddresses = append(out.OwnedAddresses, wanted)
				}
			}
		}
	}
	sort.Strings(out.OwnedAddresses)
	if len(out.OwnedAddresses) == len(cfg.VRRP.VirtualAddresses) {
		out.Role = "MASTER"
	} else if len(out.OwnedAddresses) == 0 {
		out.Role = "BACKUP"
	} else {
		out.Role = "FAULT"
		out.Error = "only part of the configured virtual address set is present"
	}
	return out
}

func verifyVRRP(ctx context.Context, runner Runner, cfg Config) error {
	status := snapshotVRRP(ctx, runner, cfg)
	if status.Error != "" || !status.ServiceActive {
		return fmt.Errorf("VRRP service verification failed: %s", status.Error)
	}
	if status.Role == "FAULT" {
		return errors.New("VRRP address state is partial")
	}
	return nil
}
