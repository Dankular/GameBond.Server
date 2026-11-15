//go:build !linux

package inspection

import (
	"context"
	"strings"
	"testing"
)

func TestProxyReportsUnsupportedPlatform(t *testing.T) {
	proxy := &Proxy{Limiter: NewLimiter(3)}
	if err := proxy.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "only supported on Linux") {
		t.Fatalf("Run error = %v, want explicit unsupported-platform error", err)
	}
	proxy.RecordError()
	status := proxy.Status()
	if status.Ready || status.Active != 0 || status.Maximum != 3 || status.Errors != 1 {
		t.Fatalf("unsupported proxy status = %+v", status)
	}
}
