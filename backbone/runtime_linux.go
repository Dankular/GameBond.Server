//go:build linux

package backbone

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const runtimeDir = "/run/gamebond-backbone"

type daemon struct {
	name string
	cmd  *exec.Cmd
	done chan struct{}
	err  error
}

// Runtime owns the isolated WireGuard interfaces and FRR processes for the
// exit container's private BGP mesh.
type Runtime struct {
	cfg          Config
	mu           sync.Mutex
	daemons      []*daemon
	createdLinks []string
	addedRoutes  []string
	closed       bool
}

func Start(ctx context.Context, cfg Config) (*Runtime, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	for _, tool := range []string{"ip", "wg", "/usr/lib/frr/zebra", "/usr/lib/frr/bgpd", "/usr/bin/vtysh"} {
		if _, err := exec.LookPath(tool); err != nil {
			return nil, fmt.Errorf("exit backbone requires %s", tool)
		}
	}
	r := &Runtime{cfg: cfg}
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		return nil, fmt.Errorf("create exit backbone runtime directory: %w", err)
	}
	if err := os.MkdirAll("/run/frr", 0755); err != nil {
		return nil, fmt.Errorf("create FRR runtime directory: %w", err)
	}
	if err := r.createInterfaces(ctx); err != nil {
		_ = r.Close()
		return nil, err
	}
	if err := r.writeFRRConfig(); err != nil {
		_ = r.Close()
		return nil, err
	}
	if err := r.startDaemon("zebra", "/usr/lib/frr/zebra", "-f", filepath.Join(runtimeDir, "zebra.conf"), "-i", filepath.Join(runtimeDir, "zebra.pid"), "-z", filepath.Join(runtimeDir, "zserv.api"), "-A", "127.0.0.1", "-u", "root", "-g", "frrvty"); err != nil {
		_ = r.Close()
		return nil, err
	}
	time.Sleep(100 * time.Millisecond)
	if err := r.daemonStatus(); err != nil {
		_ = r.Close()
		return nil, err
	}
	if err := r.startDaemon("bgpd", "/usr/lib/frr/bgpd", "-f", filepath.Join(runtimeDir, "bgpd.conf"), "-i", filepath.Join(runtimeDir, "bgpd.pid"), "-z", filepath.Join(runtimeDir, "zserv.api"), "-A", "127.0.0.1", "-u", "root", "-g", "frrvty"); err != nil {
		_ = r.Close()
		return nil, err
	}
	if err := r.daemonStatus(); err != nil {
		_ = r.Close()
		return nil, err
	}
	go func() {
		<-ctx.Done()
		_ = r.Close()
	}()
	return r, nil
}

func (r *Runtime) createInterfaces(ctx context.Context) error {
	for _, peer := range r.cfg.Peers {
		if err := checkPrivateKey(peer.PrivateKeyFile); err != nil {
			return fmt.Errorf("peer %s key: %w", peer.ID, err)
		}
		if err := r.pinEndpointRoute(ctx, peer.Endpoint); err != nil {
			return fmt.Errorf("peer %s endpoint route: %w", peer.ID, err)
		}
		if _, err := run(ctx, "ip", "link", "show", "dev", peer.Interface); err == nil {
			return fmt.Errorf("exit backbone interface %s already exists; refusing to take ownership", peer.Interface)
		}
		if _, err := run(ctx, "ip", "link", "add", "dev", peer.Interface, "type", "wireguard"); err != nil {
			return fmt.Errorf("create WireGuard interface %s: %w", peer.Interface, err)
		}
		r.createdLinks = append(r.createdLinks, peer.Interface)
		args := []string{"set", peer.Interface, "private-key", peer.PrivateKeyFile, "listen-port", fmt.Sprint(peer.ListenPort), "peer", peer.PublicKey,
			"endpoint", peer.Endpoint, "allowed-ips", strings.Join(peer.AllowedIPs, ",")}
		if peer.PersistentKeepaliveSeconds != 0 {
			args = append(args, "persistent-keepalive", fmt.Sprint(peer.PersistentKeepaliveSeconds))
		}
		if _, err := run(ctx, "wg", args...); err != nil {
			return fmt.Errorf("configure WireGuard peer %s: %w", peer.ID, err)
		}
		if _, err := run(ctx, "ip", "address", "add", peer.Address, "dev", peer.Interface); err != nil {
			return fmt.Errorf("address WireGuard interface %s: %w", peer.Interface, err)
		}
		if _, err := run(ctx, "ip", "link", "set", "dev", peer.Interface, "mtu", "1380", "up"); err != nil {
			return fmt.Errorf("bring WireGuard interface %s up: %w", peer.Interface, err)
		}
	}
	return nil
}

func (r *Runtime) pinEndpointRoute(ctx context.Context, endpointText string) error {
	endpoint, _ := netip.ParseAddrPort(endpointText)
	existing, err := run(ctx, "ip", "route", "show", "exact", endpoint.Addr().String()+"/32")
	if err == nil && len(bytes.TrimSpace(existing)) > 0 {
		return nil
	}
	if err != nil {
		return err
	}
	lookup, err := run(ctx, "ip", "route", "get", endpoint.Addr().String())
	if err != nil {
		return err
	}
	fields := strings.Fields(string(lookup))
	device, gatewayIP := "", ""
	for i := 0; i+1 < len(fields); i++ {
		switch fields[i] {
		case "dev":
			device = fields[i+1]
		case "via":
			gatewayIP = fields[i+1]
		}
	}
	if device == "" {
		return errors.New("cannot determine the underlay interface for the WireGuard endpoint")
	}
	args := []string{"route", "replace", endpoint.Addr().String() + "/32"}
	if gatewayIP != "" {
		args = append(args, "via", gatewayIP)
	}
	args = append(args, "dev", device)
	if _, err := run(ctx, "ip", args...); err != nil {
		return err
	}
	r.addedRoutes = append(r.addedRoutes, endpoint.Addr().String()+"/32")
	return nil
}

func (r *Runtime) writeFRRConfig() error {
	keepalive, hold := r.cfg.KeepaliveSeconds, r.cfg.HoldSeconds
	if keepalive == 0 {
		keepalive, hold = 1, 3
	}
	configs := renderFRRConfigs(r.cfg, keepalive, hold)
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		return err
	}
	for _, daemon := range []string{"zebra", "bgpd"} {
		data := configs[daemon]
		if len(data) == 0 {
			return fmt.Errorf("FRR renderer did not produce %s config", daemon)
		}
		path := filepath.Join(runtimeDir, daemon+".conf")
		if err := os.WriteFile(path, data, 0640); err != nil {
			return fmt.Errorf("write exit %s config: %w", daemon, err)
		}
	}
	return nil
}

func renderFRRConfigs(cfg Config, keepalive, hold uint16) map[string][]byte {
	const base = "! GameBond exit backbone\nfrr defaults traditional\nhostname gamebond-exit\n"
	var bgp strings.Builder
	bgp.WriteString(base)
	fmt.Fprintf(&bgp, "router bgp %d\n bgp router-id %s\n bgp bestpath as-path multipath-relax\n maximum-paths %d\n", cfg.LocalAS, cfg.RouterID, len(cfg.Peers))
	for _, peer := range cfg.Peers {
		fmt.Fprintf(&bgp, " neighbor %s remote-as %d\n neighbor %s update-source %s\n neighbor %s timers %d %d\n", peer.PeerAddress, peer.RemoteAS, peer.PeerAddress, peer.Interface, peer.PeerAddress, keepalive, hold)
	}
	bgp.WriteString(" address-family ipv4 unicast\n")
	for _, peer := range cfg.Peers {
		fmt.Fprintf(&bgp, "  neighbor %s activate\n  neighbor %s prefix-list GB_%s_IN in\n  neighbor %s prefix-list GB_%s_OUT out\n", peer.PeerAddress, peer.PeerAddress, peer.ID, peer.PeerAddress, peer.ID)
		for _, prefix := range peer.ExportPrefixes {
			fmt.Fprintf(&bgp, "  network %s\n", prefix)
		}
	}
	bgp.WriteString(" exit-address-family\nexit\n")
	for _, peer := range cfg.Peers {
		for _, direction := range []struct {
			name     string
			prefixes []string
		}{{"IN", peer.ImportPrefixes}, {"OUT", peer.ExportPrefixes}} {
			list := "GB_" + peer.ID + "_" + direction.name
			if len(direction.prefixes) == 0 {
				fmt.Fprintf(&bgp, "ip prefix-list %s seq 10 deny 0.0.0.0/0\n", list)
			}
			for i, prefix := range direction.prefixes {
				fmt.Fprintf(&bgp, "ip prefix-list %s seq %d permit %s\n", list, (i+1)*10, prefix)
			}
		}
	}
	return map[string][]byte{"zebra": []byte(base), "bgpd": []byte(bgp.String())}
}

func (r *Runtime) startDaemon(name, executable string, args ...string) error {
	cmd := exec.Command(executable, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start exit %s: %w", name, err)
	}
	d := &daemon{name: name, cmd: cmd, done: make(chan struct{})}
	r.mu.Lock()
	r.daemons = append(r.daemons, d)
	r.mu.Unlock()
	go func() { d.err = cmd.Wait(); close(d.done) }()
	return nil
}

func (r *Runtime) daemonStatus() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, d := range r.daemons {
		select {
		case <-d.done:
			if d.err == nil {
				d.err = errors.New("process exited")
			}
			return fmt.Errorf("exit %s stopped during startup: %w", d.name, d.err)
		default:
		}
	}
	return nil
}

// Monitor publishes BGP neighbor state at a bounded cadence. Dead peers are
// removed from new-flow selection immediately; recovered peers wait for the
// configured hold-down. Current TCP/UDP sockets remain owned by the gVisor
// gateway and are not silently moved.
func (r *Runtime) Monitor(ctx context.Context, publish func(name string, healthy bool, reason string)) {
	type state struct {
		healthy bool
		known   bool
		upSince time.Time
	}
	states := make(map[string]state, len(r.cfg.Peers))
	holdDown := time.Duration(r.cfg.RecoveryHoldDownMS) * time.Millisecond
	if holdDown == 0 {
		holdDown = 3 * time.Second
	}
	update := func() {
		neighbors, err := readNeighbors(ctx)
		for _, peer := range r.cfg.Peers {
			current := states[peer.ID]
			up := err == nil && neighbors[peer.PeerAddress]
			reason := "BGP neighbor is not Established"
			if err != nil {
				reason = "local FRR status unavailable: " + err.Error()
			} else if up {
				reason = "BGP neighbor Established"
			}
			if !up {
				current.known, current.healthy, current.upSince = true, false, time.Time{}
				publish(peer.ID, false, reason)
				states[peer.ID] = current
				continue
			}
			if !current.known {
				current.known, current.healthy = true, true
			} else if !current.healthy {
				if current.upSince.IsZero() {
					current.upSince = time.Now()
				}
				if time.Since(current.upSince) >= holdDown {
					current.healthy = true
				}
			}
			if current.healthy {
				publish(peer.ID, true, reason)
			} else {
				publish(peer.ID, false, "BGP recovered; waiting for recovery hold-down")
			}
			states[peer.ID] = current
		}
	}
	update()
	ticker := time.NewTicker(250 * time.Millisecond)
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

func readNeighbors(ctx context.Context) (map[string]bool, error) {
	cmd := exec.CommandContext(ctx, "/usr/bin/vtysh", "-c", "show bgp summary json")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("query local FRR: %w", err)
	}
	var summary struct {
		Peers map[string]struct {
			State string `json:"bgpState"`
		} `json:"peers"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(output), &summary); err != nil {
		return nil, fmt.Errorf("decode local FRR summary: %w", err)
	}
	states := make(map[string]bool, len(summary.Peers))
	for address, peer := range summary.Peers {
		states[address] = peer.State == "Established"
	}
	return states, nil
}

func (r *Runtime) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	daemons := append([]*daemon(nil), r.daemons...)
	links := append([]string(nil), r.createdLinks...)
	routes := append([]string(nil), r.addedRoutes...)
	r.mu.Unlock()
	var first error
	for i := len(daemons) - 1; i >= 0; i-- {
		d := daemons[i]
		if d.cmd.Process != nil {
			_ = d.cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-d.done:
			case <-time.After(2 * time.Second):
				_ = d.cmd.Process.Kill()
				<-d.done
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, route := range routes {
		if _, err := run(ctx, "ip", "route", "del", route); err != nil && first == nil {
			first = fmt.Errorf("remove pinned WireGuard endpoint route %s: %w", route, err)
		}
	}
	for i := len(links) - 1; i >= 0; i-- {
		if _, err := run(ctx, "ip", "link", "del", "dev", links[i]); err != nil && first == nil {
			first = fmt.Errorf("remove WireGuard interface %s: %w", links[i], err)
		}
	}
	return first
}

func checkPrivateKey(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() < 44 || info.Size() > 46 {
		return errors.New("private key file must be a regular 0600-or-stricter 32-byte WireGuard key")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	key := strings.TrimSpace(string(data))
	if !validWireGuardKey(key) {
		return errors.New("private key file does not contain one base64 32-byte key")
	}
	return nil
}

func run(ctx context.Context, executable string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, executable, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Never include arguments or tool output here: some control-plane commands contain secret file paths.
		return nil, fmt.Errorf("%s failed: %w", filepath.Base(executable), err)
	}
	return output, nil
}
