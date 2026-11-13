//go:build linux

package gateway

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Capabilities is a read-only snapshot of host support available to gateway providers.
type Capabilities struct {
	KernelRelease            string                `json:"kernel_release"`
	Tools                    map[string]bool       `json:"tools"`
	Interfaces               []InterfaceCapability `json:"interfaces"`
	ConntrackSourceAvailable bool                  `json:"conntrack_source_available"`
	BridgeFDBLimit           bool                  `json:"bridge_fdb_limit"`
	BridgeFDBVisible         bool                  `json:"bridge_fdb_visible"`
	Error                    string                `json:"error,omitempty"`
}

// InterfaceCapability reports a managed interface's current kernel identity.
type InterfaceCapability struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	IfIndex int    `json:"ifindex,omitempty"`
	Address string `json:"address,omitempty"`
	Alias   string `json:"alias,omitempty"`
	Present bool   `json:"present"`
}

// CapabilitySource collects host support without making network changes.
type CapabilitySource interface {
	Snapshot(context.Context, Config) (Capabilities, error)
}

// LinuxCapabilities inspects sysfs and fixed-argv iproute2/conntrack outputs.
type LinuxCapabilities struct {
	Runner Runner
	Sysfs  string
	Proc   string
}

func (s LinuxCapabilities) Snapshot(ctx context.Context, cfg Config) (Capabilities, error) {
	sysfs := s.Sysfs
	if sysfs == "" {
		sysfs = "/sys/class/net"
	}
	proc := s.Proc
	if proc == "" {
		proc = "/proc"
	}
	kernel, err := os.ReadFile(filepath.Join(proc, "sys/kernel/osrelease"))
	if err != nil {
		return Capabilities{}, fmt.Errorf("read kernel release: %w", err)
	}
	out := Capabilities{
		KernelRelease: strings.TrimSpace(string(kernel)),
		Tools:         map[string]bool{},
	}
	for _, tool := range []string{"ip", "bridge", "conntrack", "nft", "tc", "ethtool", "igmpproxy", "keepalived", "kea-dhcp4", "zebra", "ospfd", "bgpd", "vtysh", "avahi-daemon", "freeradius", "systemctl"} {
		out.Tools[tool] = s.Runner.Available(tool)
	}
	for _, nic := range cfg.Interfaces {
		out.Interfaces = append(out.Interfaces, inspectInterface(sysfs, nic))
	}
	for _, bridge := range cfg.Bridges {
		if out.Tools["bridge"] {
			if _, err := s.Runner.Run(ctx, "bridge", "-j", "fdb", "show", "br", bridge.InterfaceName); err == nil {
				out.BridgeFDBVisible = true
			}
		}
		if !out.Tools["ip"] {
			continue
		}
		result, err := s.Runner.Run(ctx, "ip", "-d", "-j", "link", "show", "dev", bridge.InterfaceName)
		if err != nil {
			continue
		}
		_, _, supported, err := bridgeFDBStats(result.Stdout)
		if err != nil {
			continue
		}
		// iproute2 emits these fields only when the kernel returns the corresponding bridge attributes.
		if supported {
			out.BridgeFDBLimit = true
		}
	}
	for _, name := range []string{"nf_conntrack", "ip_conntrack"} {
		f, err := os.Open(filepath.Join(proc, "net", name))
		if err == nil {
			out.ConntrackSourceAvailable = true
			_ = f.Close()
			break
		}
	}
	return out, nil
}

func inspectInterface(root string, nic Interface) InterfaceCapability {
	path := filepath.Join(root, nic.Name)
	result := InterfaceCapability{ID: nic.ID, Name: nic.Name}
	if _, err := os.Stat(path); err != nil {
		return result
	}
	result.Present = true
	if raw, err := os.ReadFile(filepath.Join(path, "ifindex")); err == nil {
		_, _ = fmt.Sscanf(strings.TrimSpace(string(raw)), "%d", &result.IfIndex)
	}
	if raw, err := os.ReadFile(filepath.Join(path, "address")); err == nil {
		result.Address = strings.TrimSpace(string(raw))
	}
	if raw, err := os.ReadFile(filepath.Join(path, "ifalias")); err == nil {
		result.Alias = strings.TrimSpace(string(raw))
	}
	return result
}
