package edge

import (
	"encoding/json"
	"os"
	"time"

	"github.com/Dankular/GameBond.Core/bond"
	"github.com/Dankular/GameBond.Core/buildinfo"
)

// Version is reported on the admin Status page.
const Version = "0.3.1-go"

// BuildCommit is the git commit this server was built from.
func BuildCommit() string { return buildinfo.Commit }

// AdminSnapshot reshapes the Go engine's stats into the document the admin
// portal's pages read (the shape app.snapshot() produced in Python): version,
// pid, observed_at, transport.paths, packets, queues and a config summary.
// Fields the Go engine does not measure are null, not zero: the per-DSCP
// queue counters and the no-path drop counter have no Go counterpart.
func AdminSnapshot(c Config, stats map[string]any, now time.Time) map[string]any {
	paths := []any{}
	if t, ok := stats["transport"].(map[string]any); ok {
		if ps, ok := t["paths"].([]bond.PathSnapshot); ok {
			for _, p := range ps {
				paths = append(paths, map[string]any{
					"slot": p.Local, "remote": []any{p.Endpoint.Addr().String(), int(p.Endpoint.Port())},
					"healthy": p.Healthy, "available": p.Ready, "rtt_ms": p.RTTMilliseconds, "rtt_jitter_ms": p.JitterMilliseconds,
					"wire_tx_bytes": p.WireTX, "wire_rx_bytes": p.WireRX, "bfd": p.BFD,
					"errors": map[string]any{"probe_lost": p.ProbeLost}})
			}
		}
	}
	packets := map[string]any{"malformed": nil, "wrong_tunnel_address": nil, "no_path_drops": nil}
	if s, ok := stats["packets"].(bond.SessionStats); ok {
		packets = map[string]any{"malformed": s.Malformed, "wrong_tunnel_address": s.WrongSource + s.WrongDestination, "no_path_drops": nil,
			"mtu_drop": s.MTUDrops, "unsupported_ipv6": s.IPv6Unsupported, "outbound_packets": s.OutboundPackets, "inbound_packets": s.InboundPackets}
	}
	queues := map[string]any{"queued_packets": nil, "capacity_packets": nil, "per_dscp_stats": map[string]any{}, "residence_ms": map[string]any{"mean": 0}}
	if q, ok := stats["queues"].(map[string]any); ok {
		if tx, ok := q["transmit"].(bond.TransmitQueueStats); ok {
			queues["queued_packets"] = tx.QueuedPackets
			queues["transmit"] = tx
		}
	}
	bind := [][]any{}
	for _, b := range c.Bind {
		if len(b) == 2 {
			bind = append(bind, []any{rawString(b[0]), rawNumber(b[1])})
		}
	}
	return map[string]any{"version": Version, "commit": buildinfo.Commit, "pid": os.Getpid(), "observed_at": now.UTC().Format(time.RFC3339Nano),
		"transport": map[string]any{"paths": paths}, "packets": packets, "queues": queues, "qos": stats["qos"],
		"config": map[string]any{"lan_tunnel_ips": lanIPs(c), "client_tunnel_ip": c.ClientIP, "game_udp_ports": gamePorts(c),
			"queues": c.Queues, "bonding_mode": c.Bonding, "bind": bind, "mtu": c.MTU}}
}

func gamePorts(c Config) []any {
	out := []any{}
	for _, p := range c.GamePorts {
		out = append(out, int(p))
	}
	return out
}

func rawString(m json.RawMessage) string {
	var s string
	_ = json.Unmarshal(m, &s)
	return s
}

func rawNumber(m json.RawMessage) int {
	var n int
	_ = json.Unmarshal(m, &n)
	return n
}

func lanIPs(c Config) []any {
	out := []any{}
	for _, ip := range c.LanTunnelIPs {
		out = append(out, ip)
	}
	return out
}
