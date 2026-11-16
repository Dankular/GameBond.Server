//go:build linux

package edge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/Dankular/GameBond.Server/adminportal"
)

type bgpPathBinding struct {
	name             string
	neighbor         string
	recoveryHoldDown time.Duration
}

// StartBGPPathHealthMonitor subscribes gVisor egress path health to the local
// host gateway's FRR status API. The host gateway owns WireGuard and BGP; the
// container receives only the per-neighbor established state it needs for flow
// selection. No route or secret is accepted over this read-only channel.
func StartBGPPathHealthMonitor(ctx context.Context, socket string, config *L2Config) error {
	bindings, err := bgpPathBindings(config)
	if err != nil || len(bindings) == 0 {
		return err
	}
	if socket == "" {
		return errors.New("BGP-backed egress selection requires GAMEBOND_GATEWAY_SOCKET")
	}
	client, err := adminportal.NewGatewayClient(socket)
	if err != nil {
		return err
	}
	go monitorBGPPaths(ctx, client, bindings)
	return nil
}

func bgpPathBindings(config *L2Config) ([]bgpPathBinding, error) {
	if config == nil || config.Bridge == nil {
		return nil, nil
	}
	bridges := []*L2Bridge{config.Bridge}
	if len(config.Bridge.VLANs) > 0 {
		bridges = bridges[:0]
		for _, vlan := range config.Bridge.VLANs {
			if vlan.Gateway != nil {
				bridges = append(bridges, vlan.Gateway)
			}
		}
	}
	type binding struct {
		neighbor string
		holdDown time.Duration
	}
	byName := map[string]binding{}
	for _, bridge := range bridges {
		if bridge.EgressPolicy != "failover" && bridge.EgressPolicy != "weighted" {
			continue
		}
		for _, path := range bridge.EgressPaths {
			if path.BGPNeighborAddress == "" {
				return nil, fmt.Errorf("egress path %q requires bgp_neighbor_address", path.Name)
			}
			holdDownMS := bridge.RecoveryHoldDownMS
			if holdDownMS == 0 {
				holdDownMS = 3000
			}
			current := binding{neighbor: path.BGPNeighborAddress, holdDown: time.Duration(holdDownMS) * time.Millisecond}
			if previous, exists := byName[path.Name]; exists && previous != current {
				return nil, fmt.Errorf("egress path %q has conflicting BGP health settings across VLANs", path.Name)
			}
			byName[path.Name] = current
		}
	}
	bindings := make([]bgpPathBinding, 0, len(byName))
	for name, current := range byName {
		bindings = append(bindings, bgpPathBinding{name: name, neighbor: current.neighbor, recoveryHoldDown: current.holdDown})
	}
	sort.Slice(bindings, func(i, j int) bool { return bindings[i].name < bindings[j].name })
	return bindings, nil
}

func monitorBGPPaths(ctx context.Context, client *adminportal.GatewayClient, bindings []bgpPathBinding) {
	type pathState struct {
		known           bool
		healthy         bool
		recoveryStarted time.Time
	}
	pathStates := make(map[string]pathState, len(bindings))
	update := func() {
		neighborStates, err := readBGPNeighborStates(ctx, client)
		for _, binding := range bindings {
			peerUp := err == nil && neighborStates[binding.neighbor]
			reason := "BGP neighbor is not Established"
			if err != nil {
				reason = "BGP status unavailable: " + err.Error()
			} else if peerUp {
				reason = "BGP neighbor Established"
			}
			state := pathStates[binding.name]
			if !peerUp {
				state.known, state.healthy, state.recoveryStarted = true, false, time.Time{}
				_ = SetEgressPathHealth(binding.name, false, reason)
				pathStates[binding.name] = state
				continue
			}
			if !state.known {
				state.known, state.healthy = true, true
			} else if !state.healthy {
				if state.recoveryStarted.IsZero() {
					state.recoveryStarted = time.Now()
				}
				if time.Since(state.recoveryStarted) >= binding.recoveryHoldDown {
					state.healthy = true
				}
			}
			if state.healthy {
				_ = SetEgressPathHealth(binding.name, true, reason)
			}
			pathStates[binding.name] = state
		}
	}
	update()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			update()
		}
	}
}

func readBGPNeighborStates(ctx context.Context, client *adminportal.GatewayClient) (map[string]bool, error) {
	requestCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	response, err := client.Request(requestCtx, "GET", "/v1/dynamic-routing/bgp-neighbors", nil)
	if err != nil {
		return nil, err
	}
	var status struct {
		Enabled bool            `json:"enabled"`
		Summary json.RawMessage `json:"summary"`
	}
	if err := json.Unmarshal(response, &status); err != nil {
		return nil, fmt.Errorf("decode host BGP neighbor status: %w", err)
	}
	if !status.Enabled || len(status.Summary) == 0 || !json.Valid(status.Summary) {
		return nil, errors.New("host gateway BGP is disabled or has no summary")
	}
	var summary struct {
		Peers map[string]struct {
			BGPState string `json:"bgpState"`
		} `json:"peers"`
	}
	if err := json.Unmarshal(status.Summary, &summary); err != nil {
		return nil, fmt.Errorf("decode FRR BGP summary: %w", err)
	}
	states := make(map[string]bool, len(summary.Peers))
	for address, peer := range summary.Peers {
		states[address] = peer.BGPState == "Established"
	}
	return states, nil
}
