package adminportal

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"testing"
)

func TestGatewayClientUsesOnlyAllowlistedUnixAPI(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "control.sock")
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

func TestNewGatewayClientRejectsUnsafeSocketPath(t *testing.T) {
	for _, path := range []string{"", "relative.sock", "/run/gamebond/../control.sock", "/" + string(make([]byte, 110))} {
		if _, err := NewGatewayClient(path); err == nil {
			t.Errorf("unsafe socket path %q was accepted", path)
		}
	}
}
