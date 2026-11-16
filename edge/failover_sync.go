//go:build linux

package edge

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Dankular/GameBond.Core/bond"
	"github.com/Dankular/GameBond.Server/backbone"
)

const (
	failoverSyncPort = 51823
	failoverSyncMax  = 16 << 20
)

var failoverSyncMagic = [8]byte{'G', 'B', 'F', 'S', 'Y', 'N', 'C', 1}

type failoverStateSync struct {
	ctx       context.Context
	cancel    context.CancelFunc
	listener  net.Listener
	key       []byte
	session   [16]byte
	epoch     [16]byte
	peers     map[netip.Addr]chan []byte
	active    map[netip.Addr]bool
	lastState map[netip.Addr]peerStateRevision
	incoming  chan bond.SessionFailoverState
	mu        sync.Mutex
	closed    bool
	sent      atomic.Uint64
	sentBytes atomic.Uint64
	received  atomic.Uint64
	applied   atomic.Uint64
	rejected  atomic.Uint64
	coalesced atomic.Uint64
}

type peerStateRevision struct {
	epoch    [16]byte
	revision uint64
}

func startFailoverStateSync(parent context.Context, cfg *backbone.Config, key, session []byte) (*failoverStateSync, error) {
	if cfg == nil || len(session) != 16 || len(key) != 32 {
		return nil, errors.New("invalid failover state sync identity")
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort("0.0.0.0", strconv.Itoa(failoverSyncPort)))
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	s := &failoverStateSync{
		ctx: ctx, cancel: cancel, listener: listener, key: append([]byte(nil), key...),
		peers: make(map[netip.Addr]chan []byte, len(cfg.Peers)), active: make(map[netip.Addr]bool, len(cfg.Peers)),
		lastState: make(map[netip.Addr]peerStateRevision, len(cfg.Peers)), incoming: make(chan bond.SessionFailoverState, 8),
	}
	copy(s.session[:], session)
	if _, err := rand.Read(s.epoch[:]); err != nil {
		listener.Close()
		cancel()
		return nil, fmt.Errorf("create failover state epoch: %w", err)
	}
	for _, peer := range cfg.Peers {
		addr, parseErr := netip.ParseAddr(peer.PeerAddress)
		if parseErr != nil || !addr.Is4() {
			listener.Close()
			cancel()
			return nil, errors.New("invalid failover sync peer address")
		}
		out := make(chan []byte, 1)
		s.peers[addr] = out
		go s.peerLoop(addr, out)
	}
	go s.acceptLoop()
	return s, nil
}

func (s *failoverStateSync) Incoming() <-chan bond.SessionFailoverState { return s.incoming }

func (s *failoverStateSync) Publish(state bond.SessionFailoverState) error {
	state.Epoch = s.epoch
	payload, err := json.Marshal(state)
	if err != nil {
		s.rejected.Add(1)
		return fmt.Errorf("encode failover state: %w", err)
	}
	if len(payload) == 0 || len(payload) > failoverSyncMax {
		s.rejected.Add(1)
		return bond.ErrRecoveryState
	}
	frame := make([]byte, 8+4+sha256.Size+len(payload))
	copy(frame[:8], failoverSyncMagic[:])
	binary.BigEndian.PutUint32(frame[8:12], uint32(len(payload)))
	copy(frame[44:], payload)
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write(s.session[:])
	_, _ = mac.Write(frame[:12])
	_, _ = mac.Write(payload)
	copy(frame[12:44], mac.Sum(nil))
	for _, out := range s.peers {
		select {
		case out <- frame:
		default:
			s.coalesced.Add(1)
			select {
			case <-out:
			default:
			}
			select {
			case out <- frame:
			default:
			}
		}
	}
	s.sent.Add(1)
	s.sentBytes.Add(uint64(len(payload)))
	return nil
}

func (s *failoverStateSync) Applied() { s.applied.Add(1) }

func (s *failoverStateSync) Rejected() { s.rejected.Add(1) }

func (s *failoverStateSync) Stats() map[string]any {
	s.mu.Lock()
	connected := len(s.active)
	s.mu.Unlock()
	return map[string]any{
		"state": "running", "peer_count": len(s.peers), "connected_peers": connected,
		"snapshots_sent": s.sent.Load(), "payload_bytes_sent": s.sentBytes.Load(),
		"snapshots_received": s.received.Load(), "snapshots_applied": s.applied.Load(),
		"snapshots_rejected": s.rejected.Load(), "queued_snapshots_coalesced": s.coalesced.Load(),
	}
}

func (s *failoverStateSync) peerLoop(addr netip.Addr, updates <-chan []byte) {
	target := net.JoinHostPort(addr.String(), strconv.Itoa(failoverSyncPort))
	for {
		if s.ctx.Err() != nil {
			return
		}
		dialer := net.Dialer{Timeout: time.Second}
		conn, err := dialer.DialContext(s.ctx, "tcp4", target)
		if err != nil {
			if !waitContext(s.ctx, time.Second) {
				return
			}
			continue
		}
		for {
			select {
			case <-s.ctx.Done():
				conn.Close()
				return
			case frame := <-updates:
				_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
				if err := writeAll(conn, frame); err != nil {
					conn.Close()
					goto reconnect
				}
			}
		}
	reconnect:
		if !waitContext(s.ctx, 100*time.Millisecond) {
			return
		}
	}
}

func (s *failoverStateSync) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			continue
		}
		remote, ok := conn.RemoteAddr().(*net.TCPAddr)
		if !ok {
			conn.Close()
			continue
		}
		addr, ok := netip.AddrFromSlice(remote.IP)
		if !ok {
			conn.Close()
			continue
		}
		addr = addr.Unmap()
		if _, trusted := s.peers[addr]; !trusted {
			conn.Close()
			continue
		}
		s.mu.Lock()
		if s.active[addr] || s.closed {
			s.mu.Unlock()
			conn.Close()
			continue
		}
		s.active[addr] = true
		s.mu.Unlock()
		go s.receiveLoop(conn, addr)
	}
}

func (s *failoverStateSync) receiveLoop(conn net.Conn, addr netip.Addr) {
	defer conn.Close()
	defer func() {
		s.mu.Lock()
		delete(s.active, addr)
		s.mu.Unlock()
	}()
	var streamEpoch [16]byte
	header := make([]byte, 44)
	for s.ctx.Err() == nil {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(conn, header); err != nil {
			return
		}
		if !hmac.Equal(header[:8], failoverSyncMagic[:]) {
			return
		}
		n := binary.BigEndian.Uint32(header[8:12])
		if n == 0 || n > failoverSyncMax {
			return
		}
		payload := make([]byte, int(n))
		if _, err := io.ReadFull(conn, payload); err != nil {
			return
		}
		mac := hmac.New(sha256.New, s.key)
		_, _ = mac.Write(s.session[:])
		_, _ = mac.Write(header[:12])
		_, _ = mac.Write(payload)
		if !hmac.Equal(header[12:], mac.Sum(nil)) {
			return
		}
		var state bond.SessionFailoverState
		if err := json.Unmarshal(payload, &state); err != nil || state.Session != s.session {
			s.rejected.Add(1)
			return
		}
		if state.Epoch == ([16]byte{}) || state.Revision == 0 {
			s.rejected.Add(1)
			return
		}
		if streamEpoch == ([16]byte{}) {
			streamEpoch = state.Epoch
		} else if streamEpoch != state.Epoch {
			// A process epoch cannot change on an established TCP stream. A new
			// process must reconnect before its reset revision is accepted.
			s.rejected.Add(1)
			return
		}
		s.mu.Lock()
		previous, seen := s.lastState[addr]
		if seen && previous.epoch == state.Epoch && state.Revision <= previous.revision {
			s.mu.Unlock()
			s.rejected.Add(1)
			continue
		}
		s.lastState[addr] = peerStateRevision{epoch: state.Epoch, revision: state.Revision}
		s.mu.Unlock()
		s.received.Add(1)
		select {
		case s.incoming <- state:
		default:
			s.rejected.Add(1)
			select {
			case <-s.incoming:
			default:
			}
			select {
			case s.incoming <- state:
			default:
			}
		}
	}
}

func (s *failoverStateSync) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	s.cancel()
	return s.listener.Close()
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func waitContext(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
