//go:build linux

package l2gw

import (
	"context"
	"errors"
	"net"
	"syscall"
	"time"
)

// dialECMPPath uses the host's route table on one configured egress interface.
// This provides data-plane ECMP distribution when each member interface has a
// valid route; route health and next-hop installation remain owned by the host.
func dialECMPPath(network, address string, path ECMPPath, timeout time.Duration) (net.Conn, error) {
	if path.Interface == "" && path.Mark == 0 {
		return nil, errors.New("l2gw: ECMP route selector is empty")
	}
	dialer := net.Dialer{Timeout: timeout, Control: func(_, _ string, raw syscall.RawConn) error {
		return configureECMPSocket(raw, path)
	}}
	return dialer.DialContext(context.Background(), network, address)
}

func listenPacketECMP(path ECMPPath, family string) (net.PacketConn, error) {
	config := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		return configureECMPSocket(raw, path)
	}}
	local := "0.0.0.0:0"
	if family == "udp6" {
		local = "[::]:0"
	}
	return config.ListenPacket(context.Background(), family, local)
}

func configureECMPSocket(raw syscall.RawConn, path ECMPPath) error {
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		if path.Interface != "" {
			controlErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, 25, path.Interface)
		}
		if controlErr == nil && path.Mark != 0 {
			controlErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, 36, int(path.Mark))
		}
	}); err != nil {
		return err
	}
	return controlErr
}
