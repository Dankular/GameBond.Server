//go:build linux

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Dankular/GameBond.Server/gateway/layer2"
)

// APIServer serves local configuration and status over a permission-protected Unix socket.
type APIServer struct {
	Manager *Manager
	Runtime *Runtime
	Runner  Runner
	applyMu sync.Mutex
}

// Serve opens the configured Unix socket and shuts down cleanly when ctx is cancelled.
func (s *APIServer) Serve(ctx context.Context) error {
	if s.Manager == nil || s.Runtime == nil {
		return errors.New("gateway API requires manager and runtime")
	}
	cfg := s.Manager.Current()
	listener, err := listenUnix(cfg.SocketPath, cfg.SocketGroup)
	if err != nil {
		return err
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(cfg.SocketPath)
	}()
	server := &http.Server{Handler: s.handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, MaxHeaderBytes: 16 << 10}
	errCh := make(chan error, 1)
	go func() { errCh <- server.Serve(listener) }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func listenUnix(path, group string) (net.Listener, error) {
	if !validSocketPath(path) {
		return nil, errors.New("invalid gateway API socket path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("create socket directory: %w", err)
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("gateway API socket path exists and is not a socket")
		}
		conn, dialErr := net.DialTimeout("unix", path, 150*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			return nil, errors.New("gateway API socket is already in use")
		}
		var opErr *net.OpError
		if !errors.As(dialErr, &opErr) || !errors.Is(opErr.Err, syscall.ECONNREFUSED) {
			return nil, fmt.Errorf("cannot determine whether existing gateway socket is stale: %w", dialErr)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale gateway socket: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on gateway socket: %w", err)
	}
	if err := os.Chmod(path, 0660); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("set gateway socket mode: %w", err)
	}
	gid := 0
	if group != "" {
		entry, err := user.LookupGroup(group)
		if err != nil {
			_ = listener.Close()
			_ = os.Remove(path)
			return nil, fmt.Errorf("lookup gateway socket group %q: %w", group, err)
		}
		gid, err = strconv.Atoi(entry.Gid)
		if err != nil {
			_ = listener.Close()
			_ = os.Remove(path)
			return nil, fmt.Errorf("invalid gid for group %q", group)
		}
	}
	if err := os.Chown(path, 0, gid); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("set gateway socket owner/group: %w", err)
	}
	return listener, nil
}

func (s *APIServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ready", "apply": s.Manager.Status(), "runtime": s.Runtime.Snapshot(r.Context())})
	})
	mux.HandleFunc("GET /v1/config", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.Manager.Current())
	})
	mux.HandleFunc("POST /v1/config/validate", func(w http.ResponseWriter, r *http.Request) {
		cfg, err := decodeRequestConfig(w, r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if _, err := s.Runtime.PrepareConfig(cfg); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		caps, err := (LinuxCapabilities{Runner: s.Runner}).Snapshot(r.Context(), cfg)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, err)
			return
		}
		for _, iface := range caps.Interfaces {
			if !iface.Present {
				writeError(w, http.StatusBadRequest, fmt.Errorf("interface %s (%s) is not present", iface.ID, iface.Name))
				return
			}
		}
		if cfg.Features.MacLimit && (!caps.BridgeFDBLimit || !caps.BridgeFDBVisible) {
			writeError(w, http.StatusBadRequest, errors.New("host does not report bridge FDB visibility and learning limit support"))
			return
		}
		if cfg.Features.FlowReport && !caps.ConntrackSourceAvailable {
			writeError(w, http.StatusBadRequest, errors.New("host does not expose a readable conntrack table"))
			return
		}
		response := map[string]any{"valid": true, "capabilities": caps}
		if cfg.Layer2 != nil {
			l2Caps, err := layer2.SnapshotCapabilities(r.Context(), layer2RunnerAdapter{runner: s.Runner})
			if err != nil {
				writeError(w, http.StatusServiceUnavailable, err)
				return
			}
			if _, err := layer2.BuildTopologyPlan(layer2.Config{Version: 1}, *cfg.Layer2, l2Caps); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			response["layer2_capabilities"] = l2Caps
		}
		writeJSON(w, http.StatusOK, response)
	})
	mux.HandleFunc("PUT /v1/config", func(w http.ResponseWriter, r *http.Request) {
		s.applyMu.Lock()
		defer s.applyMu.Unlock()
		cfg, err := decodeRequestConfig(w, r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		current := s.Manager.Current()
		if cfg.SocketPath != current.SocketPath || cfg.SocketGroup != current.SocketGroup {
			writeError(w, http.StatusConflict, errors.New("socket_path and socket_group changes require a service restart"))
			return
		}
		providers, err := s.Runtime.PrepareConfig(cfg)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		caps, err := (LinuxCapabilities{Runner: s.Runner}).Snapshot(r.Context(), cfg)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, err)
			return
		}
		for _, iface := range caps.Interfaces {
			if !iface.Present {
				writeError(w, http.StatusBadRequest, fmt.Errorf("interface %s (%s) is not present", iface.ID, iface.Name))
				return
			}
		}
		if cfg.Features.MacLimit && (!caps.BridgeFDBLimit || !caps.BridgeFDBVisible) {
			writeError(w, http.StatusBadRequest, errors.New("host does not report bridge FDB visibility and learning limit support"))
			return
		}
		if cfg.Features.FlowReport && !caps.ConntrackSourceAvailable {
			writeError(w, http.StatusBadRequest, errors.New("host does not expose a readable conntrack table"))
			return
		}
		if err := s.Manager.Apply(r.Context(), cfg); err != nil {
			writeError(w, http.StatusConflict, err)
			return
		}
		s.Runtime.Activate(providers)
		s.Runtime.SetConfig(cfg)
		writeJSON(w, http.StatusOK, map[string]any{"applied": true, "transaction": s.Manager.Status(), "config": s.Manager.Current()})
	})
	return mux
}

func decodeRequestConfig(w http.ResponseWriter, r *http.Request) (Config, error) {
	if ct := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0])); ct != "application/json" {
		return Config{}, errors.New("content type must be application/json")
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxConfigBytes+1)
	return DecodeConfig(r.Body)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]any{"error": err.Error()})
}
