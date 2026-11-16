//go:build linux

package edge

import (
	"fmt"
	"testing"

	"golang.org/x/sys/unix"
)

func TestTransientSocketError(t *testing.T) {
	for _, e := range []error{unix.ENOBUFS, unix.ENOMEM, unix.ECONNREFUSED, fmt.Errorf("wrapped: %w", unix.EHOSTUNREACH)} {
		if !transientSocketError(e) {
			t.Errorf("%v should be transient", e)
		}
	}
	for _, e := range []error{unix.EBADF, unix.EINVAL, unix.ENOTSOCK, nil} {
		if transientSocketError(e) {
			t.Errorf("%v must stay fatal", e)
		}
	}
}

func TestPathMTUDiscoveryDisablesOuterIPv4Fragmentation(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	before, err := unix.GetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER)
	if err != nil {
		t.Fatal(err)
	}
	if err := configurePathMTUDiscoverySocket(fd, false); err != nil {
		t.Fatal(err)
	}
	unchanged, err := unix.GetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER)
	if err != nil || unchanged != before {
		t.Fatalf("disabled discovery changed IP_MTU_DISCOVER: before=%d after=%d err=%v", before, unchanged, err)
	}
	if err := configurePathMTUDiscoverySocket(fd, true); err != nil {
		t.Fatal(err)
	}
	got, err := unix.GetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER)
	if err != nil || got != unix.IP_PMTUDISC_DO {
		t.Fatalf("IP_MTU_DISCOVER=%d, want IP_PMTUDISC_DO (%d): %v", got, unix.IP_PMTUDISC_DO, err)
	}
}
