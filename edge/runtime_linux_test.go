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
