package adminportal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// run executes a fixed argv (no shell) with a 3 s limit and returns stdout or an error text.
func run(argv ...string) (string, string) {
	path, err := exec.LookPath(argv[0])
	if err != nil {
		return "", argv[0] + " is not installed"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, argv[1:]...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = strings.TrimSpace(out.String())
		}
		if msg == "" {
			msg = fmt.Sprintf("exit %d", cmd.ProcessState.ExitCode())
		}
		if len(msg) > 500 {
			msg = msg[:500]
		}
		return "", msg
	}
	return out.String(), ""
}

func runJSON(argv ...string) map[string]any {
	out, e := run(argv...)
	if e != "" {
		return map[string]any{"error": e}
	}
	if strings.TrimSpace(out) == "" {
		out = "[]"
	}
	var v any
	if json.Unmarshal([]byte(out), &v) != nil {
		return map[string]any{"error": "unparseable output"}
	}
	return map[string]any{"data": v}
}

func obj(v any) map[string]any { m, _ := v.(map[string]any); return m }
func list(v any) []any         { l, _ := v.([]any); return l }

func pyVal(v any) string {
	if v == nil {
		return "None"
	}
	if f, ok := v.(float64); ok && f == float64(int64(f)) {
		return fmt.Sprintf("%d", int64(f))
	}
	return fmt.Sprint(v)
}

// ShapeInterfaces is system.interfaces' reshaping of `ip -j -s addr show`.
func ShapeInterfaces(data any) []any {
	rows := []any{}
	for _, raw := range list(data) {
		i := obj(raw)
		addrs := []any{}
		for _, a := range list(i["addr_info"]) {
			am := obj(a)
			addrs = append(addrs, pyVal(am["local"])+"/"+pyVal(am["prefixlen"]))
		}
		stats := obj(i["stats64"])
		rows = append(rows, map[string]any{"name": i["ifname"], "state": i["operstate"], "mtu": i["mtu"], "mac": i["address"],
			"addresses": addrs, "rx_bytes": obj(stats["rx"])["bytes"], "tx_bytes": obj(stats["tx"])["bytes"]})
	}
	return rows
}

// ShapeRoutes is system.routes' reshaping of `ip -j -4 route show`.
func ShapeRoutes(data any) []any {
	rows := []any{}
	for _, raw := range list(data) {
		r := obj(raw)
		rows = append(rows, map[string]any{"destination": r["dst"], "gateway": r["gateway"], "device": r["dev"],
			"protocol": r["protocol"], "source": r["prefsrc"]})
	}
	return rows
}

// Interfaces is system.interfaces.
func Interfaces() map[string]any {
	r := runJSON("ip", "-j", "-s", "addr", "show")
	if d, ok := r["data"]; ok {
		r["data"] = ShapeInterfaces(d)
	}
	return r
}

// Routes is system.routes.
func Routes() map[string]any {
	r := runJSON("ip", "-j", "-4", "route", "show")
	if d, ok := r["data"]; ok {
		r["data"] = ShapeRoutes(d)
	}
	return r
}

// NATRules is system.nat_rules.
func NATRules() map[string]any {
	out, e := run("nft", "list", "table", "ip", "gamebond")
	if e != "" {
		return map[string]any{"error": e}
	}
	return map[string]any{"text": out}
}
