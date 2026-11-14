//go:build linux

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Dankular/GameBond.Server/gateway/layer2"
)

const (
	gamebondLLDPMEDUnit   = "gamebond-lldpmed.service"
	gamebondLLDPMEDConfig = "/etc/gamebond/lldpmed.conf"
	gamebondLLDPMEDMarker = "# GameBond managed LLDP-MED policy v1\n"
)

type LLDPMEDPolicySnapshot struct {
	Interface   string `json:"interface"`
	Application string `json:"application"`
	Network     string `json:"network,omitempty"`
	VLAN        uint16 `json:"vlan,omitempty"`
	Tagged      bool   `json:"tagged,omitempty"`
	Priority    *uint8 `json:"priority,omitempty"`
	DSCP        *uint8 `json:"dscp,omitempty"`
}

type LLDPMEDPortSnapshot struct {
	Interface string          `json:"interface"`
	Neighbors json.RawMessage `json:"neighbors,omitempty"`
	Error     string          `json:"error,omitempty"`
}

type LLDPMEDSnapshot struct {
	Enabled    bool                    `json:"enabled"`
	Active     bool                    `json:"active"`
	Advertised []LLDPMEDPolicySnapshot `json:"advertised,omitempty"`
	Ports      []LLDPMEDPortSnapshot   `json:"ports,omitempty"`
	Error      string                  `json:"error,omitempty"`
}

func layer2ConfigOrEmpty(cfg Config) layer2.Config {
	if cfg.Layer2 != nil {
		return *cfg.Layer2
	}
	return layer2.Config{Version: 1}
}

func hasLLDPMEDPolicies(cfg layer2.Config) bool {
	for _, bridge := range cfg.Bridges {
		for _, port := range bridge.Ports {
			if port.VoiceNetwork != "" || len(port.LLDPMED) > 0 {
				return true
			}
		}
	}
	return false
}

func validateLLDPMEDHost(ctx context.Context, runner Runner, previous, desired layer2.Config) error {
	if !hasLLDPMEDPolicies(previous) && !hasLLDPMEDPolicies(desired) {
		return nil
	}
	for _, tool := range []string{"lldpd", "lldpcli", "bridge", "systemctl", "ip"} {
		if !runner.Available(tool) {
			return fmt.Errorf("Voice VLAN and LLDP-MED require %s", tool)
		}
	}
	loaded, err := runner.Run(ctx, "systemctl", "show", "--property=LoadState", "--value", gamebondLLDPMEDUnit)
	if err != nil {
		return fmt.Errorf("inspect GameBond LLDP-MED service: %w", err)
	}
	if strings.TrimSpace(string(loaded.Stdout)) != "loaded" {
		return errors.New("gamebond-lldpmed.service is not installed; install the GameBond LLDP-MED unit and reload systemd")
	}
	if _, err := layer2.RenderLLDPMEDConfig(previous, desired); err != nil {
		return err
	}
	for _, cfg := range []layer2.Config{previous, desired} {
		interfaces := make(map[string]string, len(cfg.Interfaces))
		for _, iface := range cfg.Interfaces {
			interfaces[iface.ID] = iface.Name
		}
		for _, bridge := range cfg.Bridges {
			for _, port := range bridge.Ports {
				if port.VoiceNetwork == "" && len(port.LLDPMED) == 0 {
					continue
				}
				if _, err := runner.Run(ctx, "ip", "-j", "link", "show", "dev", interfaces[port.Interface]); err != nil {
					return fmt.Errorf("inspect LLDP-MED interface %s: %w", interfaces[port.Interface], err)
				}
			}
		}
	}
	return nil
}

func writeLLDPMEDConfig(data []byte) error {
	prior, readErr := os.ReadFile(gamebondLLDPMEDConfig)
	if readErr == nil && !strings.HasPrefix(string(prior), gamebondLLDPMEDMarker) {
		return fmt.Errorf("refusing to replace unmanaged LLDP-MED config %s", gamebondLLDPMEDConfig)
	}
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return readErr
	}
	if len(data) == 0 {
		if readErr == nil {
			return os.Remove(gamebondLLDPMEDConfig)
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(gamebondLLDPMEDConfig), 0750); err != nil {
		return err
	}
	contents := append([]byte(gamebondLLDPMEDMarker), data...)
	f, err := os.CreateTemp(filepath.Dir(gamebondLLDPMEDConfig), ".lldpmed-*.tmp")
	if err != nil {
		return err
	}
	temp := f.Name()
	if err = f.Chmod(0640); err == nil {
		_, err = f.Write(contents)
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
	if err := os.Rename(temp, gamebondLLDPMEDConfig); err != nil {
		_ = os.Remove(temp)
		return err
	}
	return nil
}

func applyLLDPMEDTransition(ctx context.Context, runner Runner, previous, desired layer2.Config) error {
	data, err := layer2.RenderLLDPMEDConfig(previous, desired)
	if err != nil {
		return err
	}
	if !hasLLDPMEDPolicies(previous) && !hasLLDPMEDPolicies(desired) {
		return nil
	}
	if err := writeLLDPMEDConfig(data); err != nil {
		return err
	}
	if _, err := runner.Run(ctx, "systemctl", "restart", gamebondLLDPMEDUnit); err != nil {
		return fmt.Errorf("apply GameBond LLDP-MED policy: %w", err)
	}
	return nil
}

func verifyLLDPMED(ctx context.Context, runner Runner, desired layer2.Config) error {
	if !hasLLDPMEDPolicies(desired) {
		return nil
	}
	if _, err := runner.Run(ctx, "systemctl", "is-active", "--quiet", gamebondLLDPMEDUnit); err != nil {
		return fmt.Errorf("GameBond LLDP-MED service is not active: %w", err)
	}
	result, err := runner.Run(ctx, "lldpcli", "show", "configuration")
	if err != nil {
		return fmt.Errorf("read effective LLDP-MED configuration: %w", err)
	}
	for _, policy := range lldpMEDExpectedLines(desired) {
		if !strings.Contains(string(result.Stdout), policy) {
			return fmt.Errorf("effective LLDP-MED configuration is missing %q", policy)
		}
	}
	return nil
}

func lldpMEDExpectedLines(cfg layer2.Config) []string {
	data, err := layer2.RenderLLDPMEDConfig(layer2.Config{Version: 1}, cfg)
	if err != nil {
		return nil
	}
	var expected []string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "configure ") {
			expected = append(expected, line)
		}
	}
	return expected
}

func snapshotLLDPMED(ctx context.Context, runner Runner, cfg layer2.Config) LLDPMEDSnapshot {
	status := LLDPMEDSnapshot{Enabled: hasLLDPMEDPolicies(cfg)}
	if !status.Enabled {
		return status
	}
	if _, err := runner.Run(ctx, "systemctl", "is-active", "--quiet", gamebondLLDPMEDUnit); err != nil {
		status.Error = "GameBond LLDP-MED policy service is not active: " + err.Error()
		return status
	}
	configuration, err := runner.Run(ctx, "lldpcli", "show", "configuration")
	if err != nil {
		status.Error = "cannot read local LLDP-MED state: " + err.Error()
		return status
	}
	for _, expected := range lldpMEDExpectedLines(cfg) {
		if !strings.Contains(string(configuration.Stdout), expected) {
			status.Error = "effective LLDP-MED configuration is missing " + expected
			return status
		}
	}
	status.Active = true
	interfaces := make(map[string]string, len(cfg.Interfaces))
	networks := make(map[string]layer2.Network, len(cfg.Networks))
	for _, iface := range cfg.Interfaces {
		interfaces[iface.ID] = iface.Name
	}
	for _, network := range cfg.Networks {
		networks[network.ID] = network
	}
	seenPorts := map[string]bool{}
	for _, bridge := range cfg.Bridges {
		for _, port := range bridge.Ports {
			if port.VoiceNetwork != "" {
				vlan := networks[port.VoiceNetwork].VLAN
				status.Advertised = append(status.Advertised, LLDPMEDPolicySnapshot{Interface: interfaces[port.Interface], Application: "voice", Network: port.VoiceNetwork, VLAN: vlan, Tagged: true})
			}
			for _, policy := range port.LLDPMED {
				item := LLDPMEDPolicySnapshot{Interface: interfaces[port.Interface], Application: policy.Application, Network: policy.Network, Tagged: policy.Tagged, Priority: policy.Priority, DSCP: policy.DSCP}
				if policy.Network != "" {
					item.VLAN = networks[policy.Network].VLAN
				}
				status.Advertised = append(status.Advertised, item)
			}
			if port.VoiceNetwork == "" && len(port.LLDPMED) == 0 {
				continue
			}
			iface := interfaces[port.Interface]
			if seenPorts[iface] {
				continue
			}
			seenPorts[iface] = true
			portStatus := LLDPMEDPortSnapshot{Interface: iface}
			result, err := runner.Run(ctx, "lldpcli", "-f", "json", "show", "neighbors", "ports", iface, "details")
			if err != nil {
				portStatus.Error = err.Error()
			} else if len(result.Stdout) > 32*1024 {
				portStatus.Error = "LLDP neighbor output exceeds 32 KiB"
			} else if !json.Valid(result.Stdout) {
				portStatus.Error = "LLDP neighbor output is not valid JSON"
			} else {
				portStatus.Neighbors = append(json.RawMessage(nil), result.Stdout...)
			}
			status.Ports = append(status.Ports, portStatus)
		}
	}
	return status
}
