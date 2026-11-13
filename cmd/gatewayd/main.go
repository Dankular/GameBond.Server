//go:build linux

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Dankular/GameBond.Server/gateway"
)

func main() {
	configPath := flag.String("config", "/etc/gamebond/router.json", "gateway config file")
	checkOnly := flag.Bool("check", false, "validate config and report host capabilities without applying changes")
	flag.Parse()
	cfgFile, err := os.Open(*configPath)
	if err != nil {
		fatal("open config: %v", err)
	}
	cfg, decodeErr := gateway.DecodeConfig(cfgFile)
	closeErr := cfgFile.Close()
	if decodeErr != nil {
		fatal("decode config: %v", decodeErr)
	}
	if closeErr != nil {
		fatal("close config: %v", closeErr)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	runner, err := gateway.NewLinuxRunner()
	if err != nil {
		fatal("initialize host command runner: %v", err)
	}
	capabilities, err := (gateway.LinuxCapabilities{Runner: runner}).Snapshot(ctx, cfg)
	if err != nil {
		fatal("host capability snapshot: %v", err)
	}
	if *checkOnly {
		if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "config_valid", "capabilities": capabilities}); err != nil {
			fatal("write capability report: %v", err)
		}
		return
	}
	if os.Geteuid() != 0 {
		fatal("gateway daemon must run as root; use --check for read-only validation")
	}
	for _, iface := range capabilities.Interfaces {
		if !iface.Present {
			fatal("configured interface %s (%s) is not present", iface.ID, iface.Name)
		}
	}
	if cfg.Features.MacLimit && (!capabilities.BridgeFDBLimit || !capabilities.BridgeFDBVisible) {
		fatal("host does not report bridge FDB visibility and learning limit support")
	}
	if cfg.Features.FlowReport && !capabilities.ConntrackSourceAvailable {
		fatal("host does not expose a readable conntrack table")
	}
	manager, err := gateway.NewManager(*configPath, cfg, gateway.LinuxApplier{Runner: runner})
	if err != nil {
		fatal("initialize manager: %v", err)
	}
	if err := manager.Apply(ctx, cfg); err != nil {
		fatal("apply initial gateway config: %v", err)
	}
	runtime, err := gateway.NewRuntime(ctx, cfg, runner, "/var/lib/gamebond/outages.json")
	if err != nil {
		fatal("initialize telemetry runtime: %v", err)
	}
	defer runtime.Close()
	api := &gateway.APIServer{Manager: manager, Runtime: runtime, Runner: runner}
	apiErr := make(chan error, 1)
	go func() { apiErr <- api.Serve(ctx) }()
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{
		"status": "running", "version": 1, "capabilities": capabilities, "apply": manager.Status(),
	}); err != nil {
		fatal("write startup status: %v", err)
	}
	select {
	case <-ctx.Done():
	case err := <-apiErr:
		if err != nil {
			fatal("management API stopped: %v", err)
		}
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "gamebond-gatewayd: "+format+"\n", args...)
	os.Exit(1)
}
