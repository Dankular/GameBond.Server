//go:build linux

package gateway

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Dankular/GameBond.Server/gateway/layer2"
)

const (
	keaUnit           = "gamebond-kea-dhcp4.service"
	keaConfigPath     = "/etc/gamebond/kea-dhcp4.json"
	keaLeasePath      = "/var/lib/gamebond-kea/leases4.csv"
	dhcpGuardNftTable = "gamebond_dhcp_guard"
)

type DHCPSnapshot struct {
	Enabled           bool               `json:"enabled"`
	Active            bool               `json:"active"`
	Error             string             `json:"error,omitempty"`
	LeaseBindings     []DHCPLeaseBinding `json:"lease_bindings,omitempty"`
	LeaseBindingError string             `json:"lease_binding_error,omitempty"`
}

// DHCPLeaseBinding is an active Kea IPv4 lease binding. The CSV format is
// append-only between lease-file cleanups, so callers must use the final row
// for each address before enforcing bindings.
type DHCPLeaseBinding struct {
	Address string `json:"address"`
	MAC     string `json:"mac"`
}

func hasDHCPBindingGuard(cfg *layer2.Config) bool {
	if cfg == nil {
		return false
	}
	for _, policy := range cfg.DHCPGuard {
		if !policy.Trusted && policy.ValidateBindings {
			return true
		}
	}
	return false
}

// validateDHCPBindingAuthority rejects lease-to-port enforcement until the
// managed DHCP provider supplies authenticated ingress metadata. Kea's memfile
// lease database records address and MAC but not the receiving bridge port;
// the learned bridge FDB is endpoint-influenced and cannot be an authority for
// a security decision.
func validateDHCPBindingAuthority(cfg *layer2.Config) error {
	if !hasDHCPBindingGuard(cfg) {
		return nil
	}
	return errors.New("DHCP binding guard is unavailable without authoritative DHCP ingress metadata; Kea memfile leases and the learned bridge FDB cannot securely identify the client port")
}

func syncDHCPGuardBindings(ctx context.Context, runner Runner, cfg Config, leasePath string, now time.Time) (int, int, error) {
	if !hasDHCPBindingGuard(cfg.Layer2) {
		return 0, 0, nil
	}
	return 0, 0, validateDHCPBindingAuthority(cfg.Layer2)
}

func parseKeaLeaseCSV(input io.Reader, now time.Time) ([]DHCPLeaseBinding, error) {
	const maxLeaseFileBytes = 16 << 20
	data, err := io.ReadAll(io.LimitReader(input, maxLeaseFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read Kea lease database: %w", err)
	}
	if len(data) > maxLeaseFileBytes {
		return nil, fmt.Errorf("Kea lease database exceeds %d bytes", maxLeaseFileBytes)
	}
	reader := csv.NewReader(bytes.NewReader(data))
	reader.FieldsPerRecord = -1
	reader.ReuseRecord = false
	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("read Kea lease header: %w", err)
	}
	columns := make(map[string]int, len(header))
	for i, name := range header {
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, errors.New("Kea lease file has an empty column name")
		}
		if _, exists := columns[name]; exists {
			return nil, fmt.Errorf("duplicate Kea lease column %q", name)
		}
		columns[name] = i
	}
	for _, name := range []string{"address", "hwaddr", "expire", "state"} {
		if _, exists := columns[name]; !exists {
			return nil, fmt.Errorf("Kea lease file is missing %q column", name)
		}
	}
	index := func(row []string, name string) (string, error) {
		i := columns[name]
		if i >= len(row) {
			return "", fmt.Errorf("Kea lease row is missing %q value", name)
		}
		return strings.TrimSpace(row[i]), nil
	}
	latest := make(map[string]DHCPLeaseBinding)
	for line := 2; ; line++ {
		row, readErr := reader.Read()
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("read Kea lease row %d: %w", line, readErr)
		}
		addressText, err := index(row, "address")
		if err != nil {
			return nil, fmt.Errorf("Kea lease row %d: %w", line, err)
		}
		address, err := netip.ParseAddr(addressText)
		if err != nil || !address.Is4() || address.IsUnspecified() || address.IsMulticast() {
			return nil, fmt.Errorf("Kea lease row %d has invalid IPv4 address", line)
		}
		macText, err := index(row, "hwaddr")
		if err != nil {
			return nil, fmt.Errorf("Kea lease row %d: %w", line, err)
		}
		mac, err := net.ParseMAC(macText)
		if err != nil || len(mac) != 6 || mac[0]&1 != 0 {
			return nil, fmt.Errorf("Kea lease row %d has invalid client MAC", line)
		}
		expireText, err := index(row, "expire")
		if err != nil {
			return nil, fmt.Errorf("Kea lease row %d: %w", line, err)
		}
		expire, err := time.ParseInLocation("2006-01-02 15:04:05", expireText, time.Local)
		if err != nil {
			return nil, fmt.Errorf("Kea lease row %d has invalid expiration time", line)
		}
		stateText, err := index(row, "state")
		if err != nil {
			return nil, fmt.Errorf("Kea lease row %d: %w", line, err)
		}
		state, err := strconv.ParseUint(stateText, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("Kea lease row %d has invalid state", line)
		}
		key := address.String()
		// Retain every newest record, including inactive records, so an old
		// active row cannot resurrect a released, declined, or expired lease.
		if state == 0 && expire.After(now) {
			latest[key] = DHCPLeaseBinding{Address: key, MAC: strings.ToLower(mac.String())}
		} else {
			delete(latest, key)
		}
	}
	bindings := make([]DHCPLeaseBinding, 0, len(latest))
	for _, binding := range latest {
		bindings = append(bindings, binding)
	}
	sort.Slice(bindings, func(i, j int) bool { return bindings[i].Address < bindings[j].Address })
	return bindings, nil
}

func snapshotDHCP(ctx context.Context, runner Runner, cfg DHCPConfig) DHCPSnapshot {
	out := DHCPSnapshot{Enabled: cfg.Enabled}
	if !cfg.Enabled {
		return out
	}
	_, err := runner.Run(ctx, "systemctl", "is-active", "--quiet", keaUnit)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	out.Active = true
	leaseFile, err := os.Open(keaLeasePath)
	if err != nil {
		out.LeaseBindingError = fmt.Sprintf("open Kea lease database: %v", err)
		return out
	}
	defer leaseFile.Close()
	out.LeaseBindings, err = parseKeaLeaseCSV(leaseFile, time.Now())
	if err != nil {
		out.LeaseBindingError = fmt.Sprintf("read Kea lease database: %v", err)
	}
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
