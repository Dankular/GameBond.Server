package edge

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

type nested struct {
	Sent uint64 `json:"sent"`
	OK   bool   `json:"ok"`
	Name string `json:"name"`
}

func TestWritePrometheus(t *testing.T) {
	var out bytes.Buffer
	err := WritePrometheus(&out, map[string]any{
		"backend":   "native_go",
		"packets":   nested{Sent: 7, OK: true},
		"transport": map[string]any{"paths": []any{map[string]any{"rtt-ms": 21.5}, map[string]any{"rtt-ms": 40.0}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"gamebond_packets_sent 7\n", "gamebond_packets_ok 1\n",
		`gamebond_transport_paths_rtt_ms{idx="0"} 21.5`, `gamebond_transport_paths_rtt_ms{idx="1"} 40`,
		"# TYPE gamebond_packets_sent gauge",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "native_go") || strings.Contains(out.String(), "name") {
		t.Errorf("strings must be skipped:\n%s", out.String())
	}
}

func TestServeMetricsRefusesNonLoopback(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:9100", "10.0.0.1:9100", "[::1]:9100", "localhost:9100", ":9100"} {
		if _, err := ServeMetrics(addr, http.NotFoundHandler()); err == nil {
			t.Errorf("%s should be refused", addr)
		}
	}
}

func TestMetricsEndToEnd(t *testing.T) {
	m := &MetricsHandler{}
	l, err := ServeMetrics("127.0.0.1:0", m)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	m.Observe(map[string]any{"packets": map[string]any{"inbound": 3}})
	resp, err := http.Get("http://" + l.Addr().String() + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "gamebond_packets_inbound 3") {
		t.Fatalf("body: %s", body)
	}
	if r2, _ := http.Get("http://" + l.Addr().String() + "/other"); r2.StatusCode != 404 {
		t.Fatal("only /metrics is served")
	}
}
