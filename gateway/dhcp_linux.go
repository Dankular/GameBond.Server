//go:build linux

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	keaUnit       = "gamebond-kea-dhcp4.service"
	keaConfigPath = "/etc/gamebond/kea-dhcp4.json"
)

type DHCPSnapshot struct {
	Enabled bool   `json:"enabled"`
	Active  bool   `json:"active"`
	Error   string `json:"error,omitempty"`
}

func snapshotDHCP(ctx context.Context, runner Runner, enabled bool) DHCPSnapshot {
	out := DHCPSnapshot{Enabled: enabled}
	if !enabled {
		return out
	}
	_, err := runner.Run(ctx, "systemctl", "is-active", "--quiet", keaUnit)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	out.Active = true
	return out
}

func renderKeaConfig(cfg DHCPConfig, interfaces []Interface) ([]byte, error) {
	byID := make(map[string]string, len(interfaces))
	for _, iface := range interfaces {
		byID[iface.ID] = iface.Name
	}
	names := make([]string, 0, len(cfg.Subnets))
	subnets := make([]map[string]any, 0, len(cfg.Subnets))
	for i, subnet := range cfg.Subnets {
		iface, ok := byID[subnet.InterfaceID]
		if !ok {
			return nil, fmt.Errorf("DHCP subnet %s references an unknown interface", subnet.ID)
		}
		names = append(names, iface)
		options := []map[string]any{
			{"name": "routers", "data": subnet.Router},
			{"name": "domain-name-servers", "data": strings.Join(subnet.DNS, ", ")},
		}
		if subnet.Domain != "" {
			options = append(options, map[string]any{"name": "domain-name", "data": subnet.Domain})
		}
		for _, option := range subnet.Options {
			options = append(options, map[string]any{"code": option.Code, "csv-format": false, "data": option.DataHex})
		}
		reservations := make([]map[string]any, 0, len(subnet.Reservations))
		for _, reservation := range subnet.Reservations {
			row := map[string]any{"hw-address": reservation.MAC, "ip-address": reservation.Address}
			if reservation.Hostname != "" {
				row["hostname"] = reservation.Hostname
			}
			reservations = append(reservations, row)
		}
		subnets = append(subnets, map[string]any{
			"id": i + 1, "subnet": subnet.Prefix, "interface": iface,
			"pools":          []map[string]string{{"pool": subnet.PoolStart + " - " + subnet.PoolEnd}},
			"valid-lifetime": subnet.LeaseSeconds, "option-data": options, "reservations": reservations,
		})
	}
	sort.Strings(names)
	unique := names[:0]
	for _, name := range names {
		if len(unique) == 0 || unique[len(unique)-1] != name {
			unique = append(unique, name)
		}
	}
	document := map[string]any{"Dhcp4": map[string]any{
		"interfaces-config": map[string]any{"interfaces": unique},
		"lease-database":    map[string]any{"type": "memfile", "persist": true, "name": "/var/lib/gamebond-kea/leases4.csv", "lfc-interval": 3600},
		"subnet4":           subnets,
	}}
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode Kea configuration: %w", err)
	}
	return append(data, '\n'), nil
}

func validateKeaHost(ctx context.Context, runner Runner, cfg Config) error {
	if !runner.Available("kea-dhcp4") || !runner.Available("systemctl") || !runner.Available("ip") {
		return errors.New("customizable DHCP requires kea-dhcp4, systemctl, and iproute2")
	}
	loaded, err := runner.Run(ctx, "systemctl", "show", "--property=LoadState", "--value", keaUnit)
	if err != nil {
		return fmt.Errorf("inspect GameBond Kea service: %w", err)
	}
	if strings.TrimSpace(string(loaded.Stdout)) != "loaded" {
		return errors.New("gamebond-kea-dhcp4.service is not installed; install the GameBond Kea unit and reload systemd")
	}
	for _, subnet := range cfg.DHCP.Subnets {
		iface := ""
		for _, configured := range cfg.Interfaces {
			if configured.ID == subnet.InterfaceID {
				iface = configured.Name
				break
			}
		}
		result, err := runner.Run(ctx, "ip", "-j", "addr", "show", "dev", iface)
		if err != nil {
			return fmt.Errorf("inspect DHCP interface %s: %w", iface, err)
		}
		var rows []struct {
			AddrInfo []struct {
				Local string `json:"local"`
			} `json:"addr_info"`
		}
		if err := json.Unmarshal(result.Stdout, &rows); err != nil {
			return fmt.Errorf("parse addresses for DHCP interface %s: %w", iface, err)
		}
		found := false
		for _, row := range rows {
			for _, address := range row.AddrInfo {
				if address.Local == subnet.Router {
					found = true
				}
			}
		}
		if !found {
			return fmt.Errorf("DHCP router %s is not assigned to interface %s", subnet.Router, iface)
		}
	}
	data, err := renderKeaConfig(cfg.DHCP, cfg.Interfaces)
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp("/run/gamebond", ".kea-check-*.json")
	if err != nil {
		return fmt.Errorf("create temporary Kea config: %w", err)
	}
	path := temp.Name()
	defer os.Remove(path)
	if err := temp.Chmod(0600); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return fmt.Errorf("write temporary Kea config: %w", err)
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if _, err := runner.Run(ctx, "kea-dhcp4", "-t", path); err != nil {
		return fmt.Errorf("validate Kea DHCP config: %w", err)
	}
	return nil
}

func writeKeaConfig(data []byte) error {
	if err := os.MkdirAll(filepath.Dir(keaConfigPath), 0750); err != nil {
		return fmt.Errorf("create GameBond config directory: %w", err)
	}
	f, err := os.CreateTemp(filepath.Dir(keaConfigPath), ".kea-*.tmp")
	if err != nil {
		return fmt.Errorf("create Kea config temp file: %w", err)
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
		return fmt.Errorf("write Kea config: %w", err)
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(temp, keaConfigPath); err != nil {
		return fmt.Errorf("replace Kea config: %w", err)
	}
	return nil
}

func applyDHCPTransition(ctx context.Context, runner Runner, cfg Config) error {
	if cfg.DHCP.Enabled {
		data, err := renderKeaConfig(cfg.DHCP, cfg.Interfaces)
		if err != nil {
			return err
		}
		if err := writeKeaConfig(data); err != nil {
			return err
		}
		if _, err := runner.Run(ctx, "systemctl", "restart", keaUnit); err != nil {
			return fmt.Errorf("restart GameBond DHCP service: %w", err)
		}
		return nil
	}
	if _, err := runner.Run(ctx, "systemctl", "stop", keaUnit); err != nil {
		return fmt.Errorf("stop GameBond DHCP service: %w", err)
	}
	return nil
}
