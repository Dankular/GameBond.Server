//go:build linux

// gamebond-labnode is the minimal init process in a lab node image. It waits
// for the manager to finish attaching links and installing configuration,
// then starts only the daemon names selected in node.json.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type nodeConfig struct {
	ID         string   `json:"id"`
	Role       string   `json:"role"`
	Daemons    []string `json:"daemons"`
	Interfaces []string `json:"interfaces"`
}

func main() {
	if len(os.Args) != 2 {
		fatal("usage: gamebond-labnode init|release|status|sflow")
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = run()
	case "release":
		err = os.WriteFile("/etc/gamebond-lab/ready", []byte("ready\n"), 0o600)
	case "status":
		err = status()
	case "sflow":
		err = runSFlow()
	default:
		err = errors.New("unsupported operation")
	}
	if err != nil {
		fatal(err.Error())
	}
}

func run() error {
	for {
		if _, err := os.Stat("/etc/gamebond-lab/ready"); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	data, err := os.ReadFile("/etc/gamebond-lab/node.json")
	if err != nil {
		return err
	}
	var cfg nodeConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}
	if err := configureSwitch(cfg); err != nil {
		return err
	}
	if data, err := os.ReadFile("/etc/gamebond-lab/frr.conf"); err == nil {
		if err := os.WriteFile("/etc/frr/frr.conf", data, 0o600); err != nil {
			return err
		}
		if err := exec.Command("chown", "frr:frr", "/etc/frr/frr.conf").Run(); err != nil {
			return fmt.Errorf("set FRR config owner: %w", err)
		}
		if err := os.Chmod("/etc/frr/frr.conf", 0o640); err != nil {
			return fmt.Errorf("set FRR config permissions: %w", err)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	children := make([]*exec.Cmd, 0, len(cfg.Daemons))
	for _, daemon := range cfg.Daemons {
		cmd, err := daemonCommand(daemon, cfg)
		if err != nil {
			return err
		}
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("start %s: %w", daemon, err)
		}
		children = append(children, cmd)
	}
	done := make(chan error, len(children))
	for _, child := range children {
		go func(c *exec.Cmd) { done <- c.Wait() }(child)
	}
	started := time.Now()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			if contains(cfg.Daemons, "frr") {
				_ = exec.Command("/usr/lib/frr/frrinit.sh", "stop").Run()
			}
			goto shutdown
		case err := <-done:
			// frrinit.sh and some packaged daemons fork into the background. Their
			// launcher exiting is normal while the daemon process remains alive.
			if time.Since(started) > 8*time.Second {
				if missing := missingDaemon(cfg.Daemons); missing != "" {
					return fmt.Errorf("node daemon %s exited: %v", missing, err)
				}
			}
		case <-ticker.C:
			if time.Since(started) > 8*time.Second {
				if missing := missingDaemon(cfg.Daemons); missing != "" {
					return fmt.Errorf("node daemon %s is not running", missing)
				}
			}
		}
	}

shutdown:
	for _, child := range children {
		if child.Process != nil {
			_ = child.Process.Signal(syscall.SIGTERM)
		}
	}
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for range children {
		select {
		case <-done:
		case <-deadline.C:
			for _, child := range children {
				if child.Process != nil {
					_ = child.Process.Kill()
				}
			}
			return nil
		}
	}
	return nil
}

func missingDaemon(daemons []string) string {
	processes := map[string]string{"frr": "zebra", "mstpd": "mstpd", "keepalived": "keepalived", "hostapd": "hostapd", "wpa_supplicant": "wpa_supplicant", "snmpd": "snmpd"}
	for _, daemon := range daemons {
		if daemon == "sflow" {
			if err := exec.Command("pgrep", "-f", "gamebond-labnode sflow").Run(); err != nil {
				return daemon
			}
			continue
		}
		process := processes[daemon]
		if process == "" {
			return daemon
		}
		if err := exec.Command("pgrep", "-x", process).Run(); err != nil {
			return daemon
		}
	}
	return ""
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func configureSwitch(cfg nodeConfig) error {
	if cfg.Role != "switch" {
		return nil
	}
	if _, err := exec.Command("ip", "link", "add", "name", "br-lab", "type", "bridge").CombinedOutput(); err != nil {
		return fmt.Errorf("create switch bridge: %w", err)
	}
	for _, iface := range cfg.Interfaces {
		if _, err := exec.Command("ip", "link", "set", "dev", iface, "master", "br-lab").CombinedOutput(); err != nil {
			return fmt.Errorf("attach %s to switch bridge: %w", iface, err)
		}
	}
	if _, err := exec.Command("ip", "link", "set", "dev", "br-lab", "up").CombinedOutput(); err != nil {
		return err
	}
	return nil
}

func daemonCommand(name string, cfg nodeConfig) (*exec.Cmd, error) {
	conf := filepath.Join("/etc/gamebond-lab", name+".conf")
	switch name {
	case "frr":
		return exec.Command("/usr/lib/frr/frrinit.sh", "start"), nil
	case "mstpd":
		return exec.Command("mstpd", "--foreground"), nil
	case "keepalived":
		return exec.Command("keepalived", "--dont-fork", "--use-file", conf), nil
	case "hostapd":
		return exec.Command("hostapd", conf), nil
	case "wpa_supplicant":
		if len(cfg.Interfaces) == 0 {
			return nil, errors.New("wpa_supplicant requires at least one configured interface")
		}
		return exec.Command("wpa_supplicant", "-D", "wired", "-i", cfg.Interfaces[0], "-c", conf), nil
	case "snmpd":
		if _, err := os.Stat(conf); err != nil {
			return nil, errors.New("snmpd requires daemon_config.snmpd with an explicit access policy")
		}
		return exec.Command("snmpd", "-f", "-Lo", "-C", "-c", conf), nil
	case "sflow":
		if _, err := os.Stat(filepath.Join("/etc/gamebond-lab", "sflow.conf")); err != nil {
			return nil, errors.New("sflow requires daemon_config.sflow with a collector")
		}
		return exec.Command("/usr/local/bin/gamebond-labnode", "sflow"), nil
	default:
		return nil, fmt.Errorf("unsupported daemon %q", name)
	}
}

func status() error {
	data, err := os.ReadFile("/etc/gamebond-lab/node.json")
	if err != nil {
		return err
	}
	var cfg nodeConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}
	var alive []string
	for _, daemon := range cfg.Daemons {
		if daemon == "sflow" {
			if out, _ := exec.Command("pgrep", "-af", "gamebond-labnode sflow").Output(); strings.Contains(string(out), "gamebond-labnode sflow") {
				alive = append(alive, daemon)
			}
			continue
		}
		name := map[string]string{"frr": "zebra", "mstpd": "mstpd", "keepalived": "keepalived", "hostapd": "hostapd", "wpa_supplicant": "wpa_supplicant", "snmpd": "snmpd", "sflow": "gamebond-labnode"}[daemon]
		if name == "" {
			continue
		}
		if out, _ := exec.Command("pgrep", "-x", name).Output(); len(strings.TrimSpace(string(out))) > 0 {
			alive = append(alive, daemon)
		}
	}
	_, err = fmt.Fprintf(os.Stdout, "node=%s daemons=%s", cfg.ID, strings.Join(alive, ","))
	return err
}

func fatal(message string) { fmt.Fprintln(os.Stderr, message); os.Exit(1) }
