package adminportal

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"runtime"
	"testing"
)

func requireUnixSocketTest(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("gateway control socket tests require Linux Unix-domain socket paths")
	}
}

func TestGatewayClientUsesOnlyAllowlistedUnixAPI(t *testing.T) {
	requireUnixSocketTest(t)
	shortDir := t.TempDir()
	socket := filepath.Join(shortDir, "c.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/config/validate" || r.Method != http.MethodPost {
			t.Errorf("unexpected gateway request %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"valid":true}`))
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	client, err := NewGatewayClient(socket)
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.Request(context.Background(), http.MethodPost, "/v1/config/validate", json.RawMessage(`{"version":1}`))
	if err != nil || string(got) != `{"valid":true}` {
		t.Fatalf("request result = %s, %v", got, err)
	}
	if _, err := client.Request(context.Background(), http.MethodPost, "/v1/exec", json.RawMessage(`{}`)); err == nil {
		t.Fatal("arbitrary gateway endpoint was accepted")
	}
}

func TestGatewayClientAllowsBoundedPlanAndBodylessRollback(t *testing.T) {
	requireUnixSocketTest(t)
	shortDir := t.TempDir()
	socket := filepath.Join(shortDir, "c.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan string, 2)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Method + " " + r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	client, err := NewGatewayClient(socket)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Request(context.Background(), http.MethodPost, "/v1/config/plan", json.RawMessage(`{"version":1}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Request(context.Background(), http.MethodPost, "/v1/config/rollback", nil); err != nil {
		t.Fatal(err)
	}
	if got := <-seen; got != "POST /v1/config/plan" {
		t.Fatalf("first request = %q", got)
	}
	if got := <-seen; got != "POST /v1/config/rollback" {
		t.Fatalf("second request = %q", got)
	}
}

func TestGatewayClientAllowsProAVProfileCatalogueRead(t *testing.T) {
	requireUnixSocketTest(t)
	shortDir := t.TempDir()
	socket := filepath.Join(shortDir, "c.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/layer2/profiles" {
			t.Errorf("unexpected gateway request %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":"dante"}]`))
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	client, err := NewGatewayClient(socket)
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.Request(context.Background(), http.MethodGet, "/v1/layer2/profiles", nil)
	if err != nil || string(got) != `[{"id":"dante"}]` {
		t.Fatalf("profile catalogue result = %s, %v", got, err)
	}
}

func TestNewGatewayClientRejectsUnsafeSocketPath(t *testing.T) {
	for _, path := range []string{"", "relative.sock", "/run/gamebond/../control.sock", "/" + string(make([]byte, 110))} {
		if _, err := NewGatewayClient(path); err == nil {
			t.Errorf("unsafe socket path %q was accepted", path)
		}
	}
}
