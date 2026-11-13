//go:build linux

package gateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	maxCommandOutput    = 64 * 1024
	maxCommandArguments = 128 * 1024
	defaultCommandTime  = 5 * time.Second
)

// CommandResult separates stdout (which may be structured data) from stderr.
type CommandResult struct {
	Stdout []byte
	Stderr []byte
}

// Runner is the only process boundary used by Linux gateway providers.
type Runner interface {
	Run(ctx context.Context, tool string, args ...string) (CommandResult, error)
	Available(tool string) bool
}

type execRunner struct {
	paths   map[string]string
	timeout time.Duration
}

func newExecRunner(paths map[string]string, timeout time.Duration) *execRunner {
	copyPaths := make(map[string]string, len(paths))
	for name, path := range paths {
		copyPaths[name] = path
	}
	if timeout <= 0 {
		timeout = defaultCommandTime
	}
	return &execRunner{paths: copyPaths, timeout: timeout}
}

// NewLinuxRunner resolves a fixed allowlist once at startup. Configuration
// values can never select an executable or be interpreted by a shell.
func NewLinuxRunner() (Runner, error) {
	allowed := map[string][]string{
		"ip":         {"/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"},
		"bridge":     {"/usr/sbin/bridge", "/sbin/bridge", "/usr/bin/bridge", "/bin/bridge"},
		"tc":         {"/usr/sbin/tc", "/sbin/tc", "/usr/bin/tc", "/bin/tc"},
		"nft":        {"/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", "/bin/nft"},
		"ethtool":    {"/usr/sbin/ethtool", "/sbin/ethtool", "/usr/bin/ethtool", "/bin/ethtool"},
		"conntrack":  {"/usr/sbin/conntrack", "/sbin/conntrack", "/usr/bin/conntrack", "/bin/conntrack"},
		"keepalived": {"/usr/sbin/keepalived", "/sbin/keepalived", "/usr/bin/keepalived", "/bin/keepalived"},
		"lldpd":      {"/usr/sbin/lldpd", "/sbin/lldpd", "/usr/bin/lldpd", "/bin/lldpd"},
		"hostapd":    {"/usr/sbin/hostapd", "/sbin/hostapd", "/usr/bin/hostapd", "/bin/hostapd"},
		"mstpd":      {"/usr/sbin/mstpd", "/sbin/mstpd", "/usr/bin/mstpd", "/bin/mstpd"},
	}
	paths := make(map[string]string, len(allowed))
	for tool, candidates := range allowed {
		for _, candidate := range candidates {
			info, err := os.Stat(candidate)
			if err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
				paths[tool] = candidate
				break
			}
		}
	}
	return newExecRunner(paths, defaultCommandTime), nil
}

func (r *execRunner) Available(tool string) bool { return r.paths[tool] != "" }

func (r *execRunner) Run(ctx context.Context, tool string, args ...string) (CommandResult, error) {
	path, ok := r.paths[tool]
	if !ok || path == "" {
		return CommandResult{}, fmt.Errorf("gateway command %q is not allowlisted or unavailable", tool)
	}
	argBytes := 0
	for _, arg := range args {
		argBytes += len(arg) + 1
	}
	if argBytes > maxCommandArguments {
		return CommandResult{}, fmt.Errorf("gateway command argument limit exceeded")
	}

	cmdCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	var stdout, stderr limitedBuffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	result := CommandResult{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if stdout.exceeded || stderr.exceeded {
		return result, fmt.Errorf("gateway command %q output limit exceeded", tool)
	}
	if errors.Is(cmdCtx.Err(), context.DeadlineExceeded) {
		return result, fmt.Errorf("gateway command %q deadline exceeded", tool)
	}
	if err != nil {
		message := strings.TrimSpace(string(result.Stderr))
		if message == "" {
			return result, fmt.Errorf("gateway command %q failed: %w", tool, err)
		}
		return result, fmt.Errorf("gateway command %q failed: %s", tool, message)
	}
	return result, nil
}

type limitedBuffer struct {
	data     bytes.Buffer
	exceeded bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	remaining := maxCommandOutput - b.data.Len()
	if remaining > 0 {
		if len(p) > remaining {
			_, _ = b.data.Write(p[:remaining])
		} else {
			_, _ = b.data.Write(p)
		}
	}
	if len(p) > remaining {
		b.exceeded = true
	}
	return len(p), nil
}

func (b *limitedBuffer) Bytes() []byte { return b.data.Bytes() }
