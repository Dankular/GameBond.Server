package edge

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// WritePrometheus renders the engine's stats document in the Prometheus text format. Every
// numeric (and boolean) leaf becomes a gauge named gamebond_<path>; array elements carry
// their position in an idx label. Strings and nulls are skipped.
func WritePrometheus(w io.Writer, stats map[string]any) error {
	raw, err := json.Marshal(stats)
	if err != nil {
		return err
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	type sample struct {
		name, labels string
		value        float64
	}
	var samples []sample
	var walk func(prefix, idx string, v any)
	walk = func(prefix, idx string, v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, child := range x {
				walk(prefix+"_"+metricName(k), idx, child)
			}
		case []any:
			for i, child := range x {
				pos := fmt.Sprint(i)
				if idx != "" {
					pos = idx + "." + pos
				}
				walk(prefix, pos, child)
			}
		case float64:
			samples = append(samples, sample{prefix, idx, x})
		case bool:
			f := 0.0
			if x {
				f = 1
			}
			samples = append(samples, sample{prefix, idx, f})
		}
	}
	walk("gamebond", "", doc)
	sort.Slice(samples, func(i, j int) bool {
		if samples[i].name != samples[j].name {
			return samples[i].name < samples[j].name
		}
		return samples[i].labels < samples[j].labels
	})
	var buf bytes.Buffer
	last := ""
	for _, s := range samples {
		if s.name != last {
			fmt.Fprintf(&buf, "# TYPE %s gauge\n", s.name)
			last = s.name
		}
		if s.labels != "" {
			fmt.Fprintf(&buf, "%s{idx=%q} %v\n", s.name, s.labels, s.value)
		} else {
			fmt.Fprintf(&buf, "%s %v\n", s.name, s.value)
		}
	}
	_, err = w.Write(buf.Bytes())
	return err
}

func metricName(k string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' {
			return r
		}
		return '_'
	}, k)
}

// MetricsHandler serves the latest stats the observer saw. It is meant for a loopback listener.
type MetricsHandler struct {
	mu     sync.Mutex
	latest map[string]any
}

// Observe records the newest stats document (it is an engine observer).
func (m *MetricsHandler) Observe(stats map[string]any) {
	m.mu.Lock()
	m.latest = stats
	m.mu.Unlock()
}

func (m *MetricsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/metrics" || r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	m.mu.Lock()
	stats := m.latest
	m.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	if stats == nil {
		return
	}
	WritePrometheus(w, stats)
}

// ServeMetrics listens on addr, which must be a loopback IPv4 host:port (the endpoint has no
// authentication), and serves h until the listener is closed.
func ServeMetrics(addr string, h http.Handler) (net.Listener, error) {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil || !ap.Addr().Is4() || !ap.Addr().IsLoopback() {
		return nil, fmt.Errorf("GAMEBOND_METRICS_ADDR must be a loopback IPv4 host:port, got %q", addr)
	}
	l, err := net.Listen("tcp4", addr)
	if err != nil {
		return nil, err
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}
	go srv.Serve(l)
	return l, nil
}
