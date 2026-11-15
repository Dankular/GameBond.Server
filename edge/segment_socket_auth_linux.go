//go:build linux

package edge

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"time"
)

// SetRemoteSegmentMACAuthorization sends one bounded, authenticated MAC
// authorization update to a running segment broker. adminToken is a distinct
// credential; a session attachment token cannot change authorization state.
func SetRemoteSegmentMACAuthorization(ctx context.Context, socketPath, segmentID, identity, tapName string, adminToken []byte, mac [6]byte, authorized bool) error {
	if ctx == nil || !filepath.IsAbs(socketPath) || len(socketPath) >= 104 || segmentID == "" || len(segmentID) > 128 || identity == "" || len(identity) > 128 || tapName == "" || len(tapName) > 15 || len(adminToken) < 32 || len(adminToken) > 128 || !validAuthorizationMAC(mac) {
		return errors.New("segment socket: invalid MAC authorization parameters")
	}
	dialer := net.Dialer{Timeout: segmentSocketHandshakeLimit}
	conn, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return fmt.Errorf("segment socket: dial for MAC authorization: %w", err)
	}
	defer conn.Close()
	deadline := time.Now().Add(segmentSocketHandshakeLimit)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)
	hello := segmentSocketHello{Version: segmentSocketProtocolVersion, SegmentID: segmentID, Identity: identity, Token: append([]byte(nil), adminToken...), Operation: "mac_authorization"}
	if err := writeSegmentControl(conn, hello); err != nil {
		return fmt.Errorf("segment socket: send MAC authorization identity: %w", err)
	}
	if err := writeSegmentControl(conn, segmentSocketMACAuthorization{MAC: mac, Authorized: authorized, TapName: tapName}); err != nil {
		return fmt.Errorf("segment socket: send MAC authorization update: %w", err)
	}
	var result segmentSocketMACAuthorizationResult
	if err := readSegmentControl(conn, &result); err != nil {
		return fmt.Errorf("segment socket: read MAC authorization result: %w", err)
	}
	if !result.Accepted {
		if result.Error == "" {
			return errors.New("segment socket: broker rejected MAC authorization update")
		}
		return fmt.Errorf("segment socket: broker rejected MAC authorization update: %s", result.Error)
	}
	return nil
}
