//go:build linux

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/Dankular/GameBond.Server/gateway"
)

const configPath = "/etc/gamebond/router.json"

func main() {
	if os.Geteuid() != 0 {
		fatal("must run as root")
	}
	runner, err := gateway.NewLinuxRunner()
	if err != nil {
		fatal("initialize gateway runner: %v", err)
	}
	ctx := context.Background()
	if len(os.Args) == 3 && os.Args[1] == "--flush-interface" {
		if err := gateway.FlushPortAuthInterface(ctx, runner, os.Args[2]); err != nil {
			fatal("flush 802.1X authorization state: %v", err)
		}
		return
	}
	if len(os.Args) < 2 {
		fatal("expected hostapd_cli arguments: interface event station-mac")
	}
	file, err := os.Open(configPath)
	if err != nil {
		fatal("open gateway configuration: %v", err)
	}
	cfg, decodeErr := gateway.DecodeConfig(file)
	closeErr := file.Close()
	if decodeErr != nil {
		fatal("decode gateway configuration: %v", decodeErr)
	}
	if closeErr != nil {
		fatal("close gateway configuration: %v", closeErr)
	}
	if cfg.Layer2 == nil {
		fatal("gateway configuration has no Layer 2 policy")
	}
	if len(os.Args) == 3 && os.Args[1] == "--flush" {
		if err := gateway.FlushPortAuthClients(ctx, runner, *cfg.Layer2, os.Args[2]); err != nil {
			fatal("flush 802.1X authorization state: %v", err)
		}
		return
	}
	if len(os.Args) < 4 {
		fatal("expected hostapd_cli arguments: interface event station-mac")
	}
	if err := gateway.SendPortAuthEventViaAPI(ctx, cfg.SocketPath, os.Args[1], os.Args[2], os.Args[3]); err != nil {
		// An event that cannot be trusted invalidates every authorization. This
		// trades availability for the configured fail-closed policy.
		for _, policy := range cfg.Layer2.PortAuth {
			_ = gateway.FlushPortAuthClients(ctx, runner, *cfg.Layer2, policy.Interface)
		}
		fatal("process hostapd event: %v", err)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "gamebond-8021x-event: "+format+"\n", args...)
	os.Exit(1)
}
