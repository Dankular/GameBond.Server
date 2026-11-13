//go:build linux

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// BridgeSnapshot reports Linux software bridge FDB use and enforcement support.
type BridgeSnapshot struct {
	ID             string    `json:"id"`
	Interface      string    `json:"interface"`
	Learned        int64     `json:"learned"`
	MaxLearned     int64     `json:"max_learned"`
	DynamicEntries int       `json:"dynamic_entries"`
	StaticEntries  int       `json:"static_entries"`
	LimitSupported bool      `json:"limit_supported"`
	LastRead       time.Time `json:"last_read"`
	Error          string    `json:"error,omitempty"`
}

// BridgeInventory provides a read-only view of configured bridge forwarding databases.
type BridgeInventory struct{ Runner Runner }

type bridgeLinkRow struct {
	LinkInfo struct {
		InfoKind string `json:"info_kind"`
		InfoData struct {
			Learned        *int64 `json:"fdb_n_learned"`
			Limit          *int64 `json:"fdb_max_learned"`
			LearnedEntries *int64 `json:"fdb_n_learned_entries"`
			LimitEntries   *int64 `json:"fdb_max_learned_entries"`
		} `json:"info_data"`
	} `json:"linkinfo"`
}

func bridgeFDBStats(data []byte) (learned, limit int64, supported bool, err error) {
	var rows []bridgeLinkRow
	if err := json.Unmarshal(data, &rows); err != nil {
		return 0, 0, false, err
	}
	if len(rows) != 1 || rows[0].LinkInfo.InfoKind != "bridge" {
		return 0, 0, false, fmt.Errorf("not a Linux bridge")
	}
	info := rows[0].LinkInfo.InfoData
	if info.Learned != nil && info.Limit != nil {
		return *info.Learned, *info.Limit, true, nil
	}
	if info.LearnedEntries != nil && info.LimitEntries != nil {
		return *info.LearnedEntries, *info.LimitEntries, true, nil
	}
	return 0, 0, false, nil
}

// Snapshot reports each configured bridge independently; one missing bridge does not hide others.
func (b BridgeInventory) Snapshot(ctx context.Context, cfg Config) []BridgeSnapshot {
	out := make([]BridgeSnapshot, 0, len(cfg.Bridges))
	for _, bridge := range cfg.Bridges {
		row := BridgeSnapshot{ID: bridge.ID, Interface: bridge.InterfaceName, Learned: -1, MaxLearned: -1, LastRead: time.Now().UTC()}
		result, err := b.Runner.Run(ctx, "ip", "-d", "-j", "link", "show", "dev", bridge.InterfaceName)
		if err != nil {
			row.Error = err.Error()
			out = append(out, row)
			continue
		}
		learned, limit, supported, err := bridgeFDBStats(result.Stdout)
		if err != nil {
			row.Error = fmt.Sprintf("%s is not a readable Linux bridge: %v", bridge.InterfaceName, err)
			out = append(out, row)
			continue
		}
		if supported {
			row.Learned, row.MaxLearned, row.LimitSupported = learned, limit, true
		}
		fdbResult, err := b.Runner.Run(ctx, "bridge", "-j", "fdb", "show", "br", bridge.InterfaceName)
		if err != nil {
			row.Error = err.Error()
			out = append(out, row)
			continue
		}
		var entries []struct {
			State string   `json:"state"`
			Flags []string `json:"flags"`
		}
		if err := json.Unmarshal(fdbResult.Stdout, &entries); err != nil {
			row.Error = fmt.Sprintf("parse bridge FDB: %v", err)
			out = append(out, row)
			continue
		}
		for _, entry := range entries {
			state := strings.ToLower(entry.State)
			if state == "permanent" || state == "static" || state == "noarp" || hasFlag(entry.Flags, "static") || hasFlag(entry.Flags, "permanent") {
				row.StaticEntries++
			} else {
				row.DynamicEntries++
			}
		}
		out = append(out, row)
	}
	return out
}

func hasFlag(flags []string, want string) bool {
	for _, flag := range flags {
		if strings.EqualFold(flag, want) {
			return true
		}
	}
	return false
}
