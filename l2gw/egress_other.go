//go:build !linux

package l2gw

import (
	"errors"
	"net"
	"time"
)

func dialECMPPath(_, _ string, _ ECMPPath, _ time.Duration) (net.Conn, error) {
	return nil, errors.New("l2gw: interface-bound or policy-marked ECMP is supported only on Linux")
}

func listenPacketECMP(_ ECMPPath, _ string) (net.PacketConn, error) {
	return nil, errors.New("l2gw: interface-bound or policy-marked ECMP is supported only on Linux")
}
