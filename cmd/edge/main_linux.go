//go:build linux

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/Dankular/GameBond.Server/adminportal"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Dankular/GameBond.Core/hwmon"
	"github.com/Dankular/GameBond.Core/stream"
	"github.com/Dankular/GameBond.Server/edge"
	"github.com/Dankular/GameBond.Server/security"
)

func run() error {
	configPath := flag.String("config", "/run/config/server.json", "validated server config")
	keyPath := flag.String("key", "/run/secrets/gamebond.key", "read-only key file")
	flag.Parse()
	if os.Getenv("GAMEBOND_NATIVE_EDGE") != "1" {
		return fmt.Errorf("native edge requires explicit GAMEBOND_NATIVE_EDGE=1 in its container")
	}
	file, err := os.Open(*configPath)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return err
	}
	if info.Size() > 1024*1024 {
		file.Close()
		return fmt.Errorf("server config exceeds size limit")
	}
	file.Close()
	data, err := os.ReadFile(*configPath)
	if err != nil {
		return err
	}
	c, options, address, session, err := edge.DecodeConfig(data)
	if err != nil {
		return err
	}
	key, err := os.ReadFile(*keyPath)
	if err != nil {
		return err
	}
	if len(key) != 32 {
		return fmt.Errorf("key file must contain exactly 32 bytes")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	var observers []func(map[string]any)
	var restart atomic.Bool
	// Firewall, DNS filter and intrusion detection. The manager always exists so a section saved from the portal
	// takes effect at once; with no "security" key everything stays off.
	sec := security.New(security.Options{GeoDir: "/tmp/gamebond-geo", Tunnel: c.TunName, InspectionDir: "/var/lib/gamebond-inspection"})
	if err := sec.Apply(ctx, c.Security); err != nil {
		fmt.Fprintf(os.Stderr, "security settings were not applied: %v\n", err)
	}
	go sec.Run(ctx)
	edge.SetTap(sec.Tap)
	defer edge.SetTap(nil)
	if len(c.Admin) > 0 && string(c.Admin) != "null" {
		settings, err := adminportal.ParseSettings(c.Admin)
		if err != nil {
			return err
		}
		if settings.Enabled {
			hardware, err := hwmon.NewPlatform(ctx, hwmon.Options{})
			if err != nil {
				return err
			}
			defer hardware.Close()
			resources, err := hwmon.StartService(ctx, hardware.Sample, 1500*time.Millisecond)
			if err != nil {
				return err
			}
			defer resources.Close()
			var mu sync.Mutex
			var latest map[string]any
			observers = append(observers, func(stats map[string]any) {
				mu.Lock()
				latest = stats
				mu.Unlock()
			})
			portal := adminportal.New(adminportal.Options{Settings: settings, Security: securityAPI{sec}, ConfigPath: *configPath, Hardware: resources.Snapshot,
				GatewaySocketPath: os.Getenv("GAMEBOND_GATEWAY_SOCKET"),
				Snapshot: func() any {
					mu.Lock()
					defer mu.Unlock()
					return edge.AdminSnapshot(c, latest, time.Now())
				},
				Validate: func(path string) error {
					raw, err := os.ReadFile(path)
					if err != nil {
						return err
					}
					_, _, _, _, err = edge.DecodeConfig(raw)
					return err
				},
				RequestRestart: func() { restart.Store(true); stop() }})
			if err := portal.Start(); err != nil {
				return fmt.Errorf("admin portal: %w", err)
			}
			defer portal.Close()
			portal.Note("admin portal started")
			fmt.Fprintf(os.Stdout, "{\"status\":\"admin_portal\",\"bind\":[%q,%d],\"tls\":%t}\n", settings.Host, portal.Port, settings.TLSCert != "")
		}
	}
	if addr := os.Getenv("GAMEBOND_METRICS_ADDR"); addr != "" {
		metrics := &edge.MetricsHandler{}
		l, err := edge.ServeMetrics(addr, metrics)
		if err != nil {
			return err
		}
		defer l.Close()
		observers = append(observers, metrics.Observe)
		fmt.Fprintf(os.Stdout, "{\"status\":\"metrics\",\"bind\":%q}\n", l.Addr().String())
	}
	if os.Getenv("GAMEBOND_STREAM") != "0" {
		go serveStreamGateway(ctx)
	}
	err = edge.Run(ctx, c, options, address, session, key, os.Stdout, observers...)
	if restart.Load() {
		// The container entrypoint relaunches on exit status 75.
		return restartRequested{}
	}
	return err
}

// securityAPI adapts the manager to the portal, returning the normalised settings that go into the config file.
type securityAPI struct{ m *security.Manager }

func (a securityAPI) Overview(ctx context.Context) any { return a.m.Overview(ctx) }
func (a securityAPI) Catalog() any                     { return a.m.Catalog() }
func (a securityAPI) Apply(ctx context.Context, raw json.RawMessage) (json.RawMessage, error) {
	if err := a.m.Apply(ctx, raw); err != nil {
		return nil, err
	}
	return a.m.Settings().JSON(), nil
}
func (a securityAPI) Do(ctx context.Context, action string, args map[string]any) (any, error) {
	return a.m.Do(ctx, action, args)
}

// restartRequested ends the process with the admin portal's restart status.
type restartRequested struct{}

func (restartRequested) Error() string { return "restart requested from the admin portal" }
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		if _, ok := err.(restartRequested); ok {
			os.Exit(adminportal.RestartExitCode)
		}
		os.Exit(1)
	}
}

// serveStreamGateway terminates the bond-aware stream transport on the tunnel
// address: the client's userspace stack opens streams to 10.77.0.1:4436 and this
// relays them to the internet, so TCP loss recovery runs across both links
// instead of end to end.
func serveStreamGateway(ctx context.Context) {
	var pc net.PacketConn
	for pc == nil {
		var err error
		if pc, err = net.ListenPacket("udp4", "10.77.0.1:4436"); err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(250 * time.Millisecond):
			}
		}
	}
	ep := stream.NewEndpoint(pc, nil, stream.Config{ReorderHint: func() time.Duration { return 25 * time.Millisecond }})
	go func() { <-ctx.Done(); ep.Close() }()
	fmt.Fprintln(os.Stdout, `{"status":"stream_gateway","bind":"10.77.0.1:4436"}`)
	(&stream.Gateway{Ep: ep, Dial: stream.SafeDial}).Serve()
}
