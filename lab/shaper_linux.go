//go:build linux

package lab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type hostShapeRequest struct {
	ContainerID string     `json:"container_id"`
	Interface   string     `json:"interface"`
	Impairment  Impairment `json:"impairment"`
}

var dockerIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ServeHostShaper exposes a private Unix-socket API that applies Linux qdiscs
// outside runsc's user-space network stack. It only shapes Docker containers
// carrying the gamebond.lab label and never accepts host paths or shell text.
func ServeHostShaper(ctx context.Context, socketPath, dockerSocket, netnsDir string) error {
	if !filepath.IsAbs(socketPath) || len(socketPath) >= 100 {
		return errors.New("host-shaper socket path must be absolute and shorter than 100 bytes")
	}
	if netnsDir == "" {
		netnsDir = "/var/run/docker/netns"
	}
	if !filepath.IsAbs(netnsDir) {
		return errors.New("Docker network namespace directory must be absolute")
	}
	api, err := newDockerAPI(ctx, dockerSocket)
	if err != nil {
		return fmt.Errorf("connect host shaper to Docker Engine: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o755); err != nil {
		return err
	}
	if info, err := os.Lstat(socketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("refusing to replace a non-socket host-shaper path")
		}
		if err := os.Remove(socketPath); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	if err := os.Chmod(socketPath, 0o660); err != nil {
		listener.Close()
		os.Remove(socketPath)
		return err
	}
	server := &http.Server{Handler: hostShaperHandler(api, netnsDir), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}
	go func() { <-ctx.Done(); _ = server.Close() }()
	err = server.Serve(listener)
	_ = os.Remove(socketPath)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func hostShaperHandler(api *dockerAPI, netnsDir string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost || r.URL.Path != "/shape" {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		defer r.Body.Close()
		decoder := json.NewDecoder(io.LimitReader(r.Body, 16*1024))
		decoder.DisallowUnknownFields()
		var request hostShapeRequest
		if err := decoder.Decode(&request); err != nil {
			http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
			return
		}
		if decoder.Decode(new(any)) != io.EOF {
			http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
			return
		}
		if !dockerIDPattern.MatchString(request.ContainerID) || !interfaceNamePattern.MatchString(request.Interface) {
			http.Error(w, `{"error":"invalid container or interface"}`, http.StatusBadRequest)
			return
		}
		if err := validateShaperImpairment(request.Impairment); err != nil {
			http.Error(w, `{"error":"invalid impairment"}`, http.StatusBadRequest)
			return
		}
		var inspect struct {
			Config struct {
				Labels map[string]string `json:"Labels"`
			} `json:"Config"`
			NetworkSettings struct {
				SandboxKey string `json:"SandboxKey"`
			} `json:"NetworkSettings"`
		}
		if err := api.json(r.Context(), http.MethodGet, "/containers/"+request.ContainerID+"/json", nil, &inspect); err != nil {
			http.Error(w, `{"error":"container not found"}`, http.StatusNotFound)
			return
		}
		if inspect.Config.Labels["gamebond.lab"] != "true" {
			http.Error(w, `{"error":"container is not a lab node"}`, http.StatusForbidden)
			return
		}
		sandbox := inspect.NetworkSettings.SandboxKey
		if sandbox == "" || filepath.Base(sandbox) == "." || filepath.Base(sandbox) == string(filepath.Separator) {
			http.Error(w, `{"error":"container network namespace is unavailable"}`, http.StatusConflict)
			return
		}
		name := filepath.Join(netnsDir, filepath.Base(sandbox))
		if _, err := os.Stat(name); err != nil {
			http.Error(w, `{"error":"container network namespace is not mounted in shaper"}`, http.StatusServiceUnavailable)
			return
		}
		args := []string{"--net=" + name, "--", "tc"}
		if request.Impairment == (Impairment{}) {
			args = append(args, "qdisc", "del", "dev", request.Interface, "root")
		} else {
			args = append(args, "qdisc", "replace", "dev", request.Interface, "root", "netem")
			if request.Impairment.LatencyMS > 0 || request.Impairment.JitterMS > 0 {
				args = append(args, "delay", strconv.FormatUint(uint64(request.Impairment.LatencyMS), 10)+"ms")
				if request.Impairment.JitterMS > 0 {
					args = append(args, strconv.FormatUint(uint64(request.Impairment.JitterMS), 10)+"ms")
				}
			}
			if request.Impairment.LossPct > 0 {
				args = append(args, "loss", fmt.Sprintf("%.4g%%", request.Impairment.LossPct))
			}
			if request.Impairment.CorruptPct > 0 {
				args = append(args, "corrupt", fmt.Sprintf("%.4g%%", request.Impairment.CorruptPct))
			}
			if request.Impairment.BandwidthBPS > 0 {
				args = append(args, "rate", strconv.FormatUint(request.Impairment.BandwidthBPS, 10)+"bit")
			}
		}
		commandCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		out, err := exec.CommandContext(commandCtx, "nsenter", args...).CombinedOutput()
		if err != nil {
			message := strings.ToLower(string(out) + " " + err.Error())
			if request.Impairment == (Impairment{}) && (strings.Contains(message, "no such file") || strings.Contains(message, "cannot find qdisc")) {
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, `{"ok":true}`)
				return
			}
			http.Error(w, `{"error":"host qdisc command failed"}`, http.StatusUnprocessableEntity)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
}

func validateShaperImpairment(p Impairment) error {
	if p.LatencyMS > 60000 || p.JitterMS > 60000 || p.BandwidthBPS > 1_000_000_000_000 || !finite(p.LossPct) || !finite(p.CorruptPct) || math.IsNaN(p.LossPct) || math.IsInf(p.LossPct, 0) || math.IsNaN(p.CorruptPct) || math.IsInf(p.CorruptPct, 0) || p.LossPct < 0 || p.LossPct > 100 || p.CorruptPct < 0 || p.CorruptPct > 100 {
		return errors.New("impairment is out of range")
	}
	return nil
}
