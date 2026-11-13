//go:build linux

package gateway

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	mdnsUnit       = "gamebond-avahi.service"
	mdnsConfigPath = "/etc/gamebond/avahi-daemon.conf"
)

type MDNSSnapshot struct {
	Enabled bool   `json:"enabled"`
	Active  bool   `json:"active"`
	Error   string `json:"error,omitempty"`
}

func renderMDNSConfig(cfg MDNSConfig, interfaces []Interface) ([]byte, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if err := cfg.Validate(interfaces); err != nil {
		return nil, err
	}
	byID := make(map[string]string, len(interfaces))
	for _, iface := range interfaces {
		byID[iface.ID] = iface.Name
	}
	names := make([]string, 0, len(cfg.InterfaceIDs))
	for _, id := range cfg.InterfaceIDs {
		names = append(names, byID[id])
	}
	var b strings.Builder
	b.WriteString("# GameBond managed Avahi reflector configuration v1\n")
	fmt.Fprintf(&b, "[server]\nuse-ipv4=yes\nuse-ipv6=yes\nallow-interfaces=%s\n", strings.Join(names, ","))
	b.WriteString("\n[publish]\npublish-addresses=yes\n\n[reflector]\nenable-reflector=yes\nreflect-ipv=no\n")
	if len(cfg.ReflectFilters) > 0 {
		fmt.Fprintf(&b, "reflect-filters=%s\n", strings.Join(cfg.ReflectFilters, ","))
	}
	return []byte(b.String()), nil
}

func validateMDNSHost(ctx context.Context, runner Runner, cfg Config) error {
	if !runner.Available("avahi-daemon") || !runner.Available("systemctl") || !runner.Available("ip") {
		return errors.New("mDNS reflection requires avahi-daemon, systemctl, and iproute2")
	}
	loaded, err := runner.Run(ctx, "systemctl", "show", "--property=LoadState", "--value", mdnsUnit)
	if err != nil {
		return fmt.Errorf("inspect GameBond mDNS service: %w", err)
	}
	if strings.TrimSpace(string(loaded.Stdout)) != "loaded" {
		return errors.New("gamebond-avahi.service is not installed; install the GameBond Avahi unit and reload systemd")
	}
	byID := make(map[string]string, len(cfg.Interfaces))
	for _, iface := range cfg.Interfaces {
		byID[iface.ID] = iface.Name
	}
	for _, id := range cfg.MDNS.InterfaceIDs {
		if _, err := runner.Run(ctx, "ip", "-j", "link", "show", "dev", byID[id]); err != nil {
			return fmt.Errorf("inspect mDNS interface %s: %w", byID[id], err)
		}
	}
	_, err = renderMDNSConfig(cfg.MDNS, cfg.Interfaces)
	return err
}

func writeMDNSConfig(data []byte) error {
	prior, readErr := os.ReadFile(mdnsConfigPath)
	if readErr == nil && !strings.HasPrefix(string(prior), "# GameBond managed Avahi reflector configuration v1\n") {
		return fmt.Errorf("refusing to replace unmanaged Avahi config %s", mdnsConfigPath)
	}
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return readErr
	}
	if len(data) == 0 {
		if readErr == nil {
			if err := os.Remove(mdnsConfigPath); err != nil {
				return err
			}
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(mdnsConfigPath), 0750); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(mdnsConfigPath), ".avahi-*.tmp")
	if err != nil {
		return err
	}
	temp := f.Name()
	if err = f.Chmod(0640); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		_ = os.Remove(temp)
		return err
	}
	if closeErr != nil {
		_ = os.Remove(temp)
		return closeErr
	}
	if err := os.Rename(temp, mdnsConfigPath); err != nil {
		_ = os.Remove(temp)
		return err
	}
	return nil
}

func applyMDNSTransition(ctx context.Context, runner Runner, cfg Config) error {
	if cfg.MDNS.Enabled {
		data, err := renderMDNSConfig(cfg.MDNS, cfg.Interfaces)
		if err != nil {
			return err
		}
		if err := writeMDNSConfig(data); err != nil {
			return err
		}
		if _, err := runner.Run(ctx, "systemctl", "restart", mdnsUnit); err != nil {
			return fmt.Errorf("restart GameBond mDNS reflector: %w", err)
		}
		return nil
	}
	if _, err := runner.Run(ctx, "systemctl", "stop", mdnsUnit); err != nil {
		return fmt.Errorf("stop GameBond mDNS reflector: %w", err)
	}
	return writeMDNSConfig(nil)
}

func snapshotMDNS(ctx context.Context, runner Runner, enabled bool) MDNSSnapshot {
	out := MDNSSnapshot{Enabled: enabled}
	if _, err := runner.Run(ctx, "systemctl", "is-active", "--quiet", mdnsUnit); err != nil {
		if enabled {
			out.Error = err.Error()
		}
		return out
	}
	out.Active = true
	return out
}

func verifyMDNS(ctx context.Context, runner Runner, enabled bool) error {
	status := snapshotMDNS(ctx, runner, enabled)
	if enabled && (status.Error != "" || !status.Active) {
		return fmt.Errorf("mDNS reflector service verification failed: %s", status.Error)
	}
	if !enabled {
		if _, err := runner.Run(ctx, "systemctl", "is-active", "--quiet", mdnsUnit); err == nil {
			return errors.New("mDNS reflector remained active after disable")
		}
	}
	return nil
}
