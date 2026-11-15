//go:build linux

package edge

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Dankular/GameBond.Core/bond"
)

const (
	segmentSocketProtocolVersion = 1
	maxSegmentControlBytes       = 4096
	maxSegmentEthernetFrame      = 9216
	segmentSocketHandshakeLimit  = 5 * time.Second
	segmentSocketWriteLimit      = 5 * time.Second
	segmentControlWorkerLimit    = 8
)

// SegmentSocketAuthorization is a broker-owned port policy. Token must be a
// unique, randomly generated secret of at least 32 bytes for this identity.
// Port policy is taken only from this record; peers cannot choose VLANs or
// claim a different identity in their handshake.
type SegmentSocketAuthorization struct {
	Token         []byte
	EAPOLTapName  string
	Port          bond.L2PortConfig
	QueueDepth    int
	MirrorIngress bool
	MirrorEgress  bool
}

type segmentSocketHello struct {
	Version   int    `json:"version"`
	SegmentID string `json:"segment_id"`
	Identity  string `json:"identity"`
	Token     []byte `json:"token"`
	Operation string `json:"operation,omitempty"`
}

type segmentSocketMACAuthorization struct {
	MAC        [6]byte `json:"mac"`
	Authorized bool    `json:"authorized"`
	TapName    string  `json:"tap_name"`
}

type segmentSocketMACAuthorizationResult struct {
	Accepted bool   `json:"accepted"`
	Error    string `json:"error,omitempty"`
}

type segmentSocketAccept struct {
	Version   int    `json:"version"`
	SegmentID string `json:"segment_id"`
	Identity  string `json:"identity"`
	PortID    int32  `json:"port_id"`
}

// ServeSegmentSocket serves an authenticated, local-process attachment API for
// a SegmentFabric. It refuses an existing socket path and creates the socket
// with mode 0600. Each identity has a distinct secret and broker-owned port
// policy. Cancellation closes active connections and detaches all ports.
func ServeSegmentSocket(ctx context.Context, socketPath string, fabric *SegmentFabric, authorizations map[string]SegmentSocketAuthorization) error {
	return ServeSegmentSocketWithAdminToken(ctx, socketPath, fabric, authorizations, nil)
}

// ServeSegmentSocketWithAdminToken enables broker MAC authorization controls
// using a credential distinct from every session attachment token.
func ServeSegmentSocketWithAdminToken(ctx context.Context, socketPath string, fabric *SegmentFabric, authorizations map[string]SegmentSocketAuthorization, adminToken []byte) error {
	if ctx == nil || fabric == nil || fabric.Identity() == "" {
		return errors.New("segment socket: context and named fabric are required")
	}
	if !filepath.IsAbs(socketPath) || len(socketPath) == 0 || len(socketPath) >= 104 {
		return errors.New("segment socket: path must be absolute and shorter than 104 bytes")
	}
	if err := validateSegmentSocketAuthorizations(authorizations); err != nil {
		return err
	}
	if len(adminToken) != 0 && (len(adminToken) < 32 || len(adminToken) > 128) {
		return errors.New("segment socket: broker admin token must be 32..128 bytes")
	}
	if existing, err := os.Lstat(socketPath); err == nil {
		if existing.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("segment socket: refusing existing non-socket path %q", socketPath)
		}
		conn, dialErr := net.DialTimeout("unix", socketPath, 100*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			return fmt.Errorf("segment socket: another broker is already listening at %q", socketPath)
		}
		var opErr *net.OpError
		if !errors.As(dialErr, &opErr) || !errors.Is(opErr.Err, syscall.ECONNREFUSED) {
			return fmt.Errorf("segment socket: cannot safely replace existing path %q: %w", socketPath, dialErr)
		}
		current, statErr := os.Lstat(socketPath)
		if statErr != nil || !os.SameFile(existing, current) {
			return fmt.Errorf("segment socket: existing path changed during stale-socket check")
		}
		if err := os.Remove(socketPath); err != nil {
			return fmt.Errorf("segment socket: remove stale socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("segment socket: inspect path: %w", err)
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("segment socket: listen: %w", err)
	}
	pathInfo, err := os.Lstat(socketPath)
	if err != nil {
		listener.Close()
		return fmt.Errorf("segment socket: inspect listener: %w", err)
	}
	if pathInfo.Mode()&os.ModeSocket == 0 {
		listener.Close()
		return errors.New("segment socket: listener path is not a socket")
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		listener.Close()
		os.Remove(socketPath)
		return fmt.Errorf("segment socket: set socket permissions: %w", err)
	}
	if current, err := os.Lstat(socketPath); err != nil || !os.SameFile(pathInfo, current) {
		listener.Close()
		return errors.New("segment socket: listener path changed during setup")
	}
	serverAuthorizations := make(map[string]SegmentSocketAuthorization, len(authorizations))
	for identity, authorization := range authorizations {
		authorization.Token = slices.Clone(authorization.Token)
		serverAuthorizations[identity] = authorization
	}
	defer func() {
		listener.Close()
		if current, err := os.Lstat(socketPath); err == nil && os.SameFile(pathInfo, current) {
			_ = os.Remove(socketPath)
		}
	}()
	stopWatch := make(chan struct{})
	defer close(stopWatch)
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-stopWatch:
		}
	}()

	var mu sync.Mutex
	active := make(map[string]net.Conn)
	var workers sync.WaitGroup
	semaphore := make(chan struct{}, len(serverAuthorizations)+segmentControlWorkerLimit)
	defer func() {
		mu.Lock()
		for _, conn := range active {
			_ = conn.Close()
		}
		mu.Unlock()
		workers.Wait()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("segment socket: accept: %w", err)
		}
		if ctx.Err() != nil {
			conn.Close()
			return nil
		}
		select {
		case semaphore <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		workers.Add(1)
		go func() {
			defer func() { <-semaphore }()
			defer workers.Done()
			serveSegmentSocketConn(ctx, conn, fabric, serverAuthorizations, slices.Clone(adminToken), &mu, active)
		}()
	}
}

func validateSegmentSocketAuthorizations(authorizations map[string]SegmentSocketAuthorization) error {
	if len(authorizations) == 0 || len(authorizations) > 1024 {
		return errors.New("segment socket: authorization list must contain 1..1024 identities")
	}
	var tokens [][]byte
	for identity, authorization := range authorizations {
		if identity == "" || len(identity) > 128 || strings.ContainsAny(identity, "\x00\r\n") {
			return errors.New("segment socket: invalid authorized identity")
		}
		if len(authorization.Token) < 32 || len(authorization.Token) > 128 {
			return fmt.Errorf("segment socket: identity %q needs a 32..128 byte token", identity)
		}
		for _, previous := range tokens {
			if len(previous) == len(authorization.Token) && subtle.ConstantTimeCompare(previous, authorization.Token) == 1 {
				return errors.New("segment socket: each identity must have a distinct token")
			}
		}
		tokens = append(tokens, slices.Clone(authorization.Token))
		if authorization.Port.Monitor {
			return fmt.Errorf("segment socket: identity %q cannot use a monitor port", identity)
		}
		if err := authorization.Port.VLAN.Validate(); err != nil {
			return fmt.Errorf("segment socket: identity %q VLAN policy: %w", identity, err)
		}
		if authorization.Port.VLAN.AccessVLAN == 0 && len(authorization.Port.VLAN.AllowedVLANs) == 0 {
			return fmt.Errorf("segment socket: identity %q must have an explicit access VLAN or trunk allow-list", identity)
		}
		if authorization.QueueDepth < 0 || authorization.QueueDepth > maxSegmentQueue {
			return fmt.Errorf("segment socket: identity %q queue depth must be 0..%d", identity, maxSegmentQueue)
		}
	}
	return nil
}

// NewRemoteSegmentFabric constructs a SegmentFabric-compatible client adapter.
// Its first Attach opens exactly one authorized socket port; the broker's
// acceptance response supplies the authoritative port ID and attachment name.
func NewRemoteSegmentFabric(segmentID, socketPath, attachmentIdentity string, token []byte) (*SegmentFabric, error) {
	return NewRemoteSegmentFabricContext(context.Background(), segmentID, socketPath, attachmentIdentity, token)
}

// NewRemoteSegmentFabricContext builds a remote adapter whose bounded startup
// retry is canceled when its owning edge session is stopped.
func NewRemoteSegmentFabricContext(ctx context.Context, segmentID, socketPath, attachmentIdentity string, token []byte) (*SegmentFabric, error) {
	if ctx == nil || segmentID == "" || len(segmentID) > 128 || !filepath.IsAbs(socketPath) || len(socketPath) >= 104 || attachmentIdentity == "" || len(attachmentIdentity) > 128 || len(token) < 32 || len(token) > 128 {
		return nil, errors.New("segment socket: invalid remote fabric settings")
	}
	return &SegmentFabric{
		identity:       segmentID,
		ports:          make(map[bond.PortID]*SegmentPort),
		remoteSocket:   socketPath,
		remoteIdentity: attachmentIdentity,
		remoteToken:    slices.Clone(token),
		remoteCtx:      ctx,
	}, nil
}

func (f *SegmentFabric) attachRemote(_ bond.L2PortConfig, queueDepth int) (*SegmentPort, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.remoteAttach {
		return nil, errors.New("segment socket: remote fabric supports one attachment")
	}
	// Allow the broker container to start after a remote session container. Keep
	// the retry bounded so bad credentials and unavailable segments fail clearly.
	ctx := f.remoteCtx
	if ctx == nil {
		ctx = context.Background()
	}
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	var remote *SegmentSocketPort
	var err error
	for {
		remote, err = DialSegmentSocket(ctx, f.remoteSocket, f.identity, f.remoteIdentity, f.remoteToken, queueDepth)
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return nil, fmt.Errorf("segment socket: broker attachment failed after retrying: %w", err)
		case <-time.After(200 * time.Millisecond):
		}
	}
	identity := remote.Identity()
	if identity == "" {
		remote.Close()
		return nil, errors.New("segment socket: broker returned an empty identity")
	}
	port := &SegmentPort{fabric: f, id: remote.ID(), cfgName: identity, remote: remote}
	if _, exists := f.ports[port.id]; exists {
		remote.Close()
		return nil, errors.New("segment socket: broker reused an attached port ID")
	}
	f.remoteAttach = true
	f.ports[port.id] = port
	return port, nil
}

func serveSegmentSocketConn(ctx context.Context, conn net.Conn, fabric *SegmentFabric, authorizations map[string]SegmentSocketAuthorization, adminToken []byte, mu *sync.Mutex, active map[string]net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(segmentSocketHandshakeLimit))
	var hello segmentSocketHello
	if err := readSegmentControl(conn, &hello); err != nil {
		return
	}
	if hello.Version != segmentSocketProtocolVersion || hello.SegmentID != fabric.Identity() || hello.Identity == "" || len(hello.Identity) > 128 {
		return
	}
	if hello.Operation == "mac_authorization" {
		authorization, ok := authorizations[hello.Identity]
		if len(adminToken) == 0 || !ok || !authorization.Port.MACAuth || len(hello.Token) != len(adminToken) || subtle.ConstantTimeCompare(hello.Token, adminToken) != 1 {
			return
		}
		var request segmentSocketMACAuthorization
		_ = conn.SetReadDeadline(time.Now().Add(segmentSocketHandshakeLimit))
		if err := readSegmentControl(conn, &request); err != nil || !validAuthorizationMAC(request.MAC) || request.TapName == "" || request.TapName != authorization.EAPOLTapName {
			return
		}
		err := fabric.SetMACAuthorization(hello.Identity, request.MAC, request.Authorized)
		result := segmentSocketMACAuthorizationResult{Accepted: err == nil}
		if err != nil {
			result.Error = err.Error()
		}
		_ = conn.SetWriteDeadline(time.Now().Add(segmentSocketWriteLimit))
		_ = writeSegmentControl(conn, result)
		return
	}
	if hello.Operation != "" {
		return
	}
	authorization, ok := authorizations[hello.Identity]
	if !ok || len(hello.Token) != len(authorization.Token) || subtle.ConstantTimeCompare(hello.Token, authorization.Token) != 1 {
		return
	}
	mu.Lock()
	if active[hello.Identity] != nil {
		mu.Unlock()
		return
	}
	active[hello.Identity] = conn
	mu.Unlock()
	defer func() {
		mu.Lock()
		if active[hello.Identity] == conn {
			delete(active, hello.Identity)
		}
		mu.Unlock()
	}()

	portConfig := authorization.Port
	portConfig.Name = hello.Identity // never accept a peer-selected ingress identity
	port, err := fabric.AttachSession(portConfig, authorization.QueueDepth, authorization.MirrorIngress, authorization.MirrorEgress)
	if err != nil {
		return
	}
	defer port.Close()
	accept := segmentSocketAccept{Version: segmentSocketProtocolVersion, SegmentID: fabric.Identity(), Identity: hello.Identity, PortID: int32(port.ID())}
	if err := writeSegmentControl(conn, accept); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})

	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			frame, err := readSegmentFrame(conn)
			if err != nil {
				cancel()
				_ = conn.Close()
				return
			}
			port.Send(frame, time.Now())
		}
	}()
	for {
		select {
		case <-connCtx.Done():
			_ = conn.Close()
			<-readerDone
			return
		case delivery, ok := <-port.Receive():
			if !ok {
				cancel()
				_ = conn.Close()
				<-readerDone
				return
			}
			_ = conn.SetWriteDeadline(time.Now().Add(segmentSocketWriteLimit))
			err := writeSegmentDelivery(conn, delivery)
			_ = conn.SetWriteDeadline(time.Time{})
			if err != nil {
				cancel()
				_ = conn.Close()
				<-readerDone
				return
			}
		}
	}
}

func validAuthorizationMAC(mac [6]byte) bool {
	return mac != [6]byte{} && mac[0]&1 == 0
}

func readSegmentControl(reader io.Reader, value any) error {
	var length [4]byte
	if _, err := io.ReadFull(reader, length[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(length[:])
	if n == 0 || n > maxSegmentControlBytes {
		return errors.New("segment socket: invalid control message length")
	}
	data := make([]byte, int(n))
	if _, err := io.ReadFull(reader, data); err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("segment socket: trailing control data")
	}
	return nil
}

func writeSegmentControl(writer io.Writer, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(data) == 0 || len(data) > maxSegmentControlBytes {
		return errors.New("segment socket: control message too large")
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(data)))
	if err := writeSegmentFull(writer, length[:]); err != nil {
		return err
	}
	return writeSegmentFull(writer, data)
}

func readSegmentFrame(reader io.Reader) ([]byte, error) {
	var length [4]byte
	if _, err := io.ReadFull(reader, length[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(length[:])
	if n < bond.EthHeaderLen || n > maxSegmentEthernetFrame {
		return nil, errors.New("segment socket: invalid Ethernet frame length")
	}
	frame := make([]byte, int(n))
	if _, err := io.ReadFull(reader, frame); err != nil {
		return nil, err
	}
	return frame, nil
}

func writeSegmentFrame(writer io.Writer, frame []byte) error {
	if len(frame) < bond.EthHeaderLen || len(frame) > maxSegmentEthernetFrame {
		return errors.New("segment socket: invalid Ethernet frame length")
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(frame)))
	if err := writeSegmentFull(writer, length[:]); err != nil {
		return err
	}
	return writeSegmentFull(writer, frame)
}

func writeSegmentDelivery(writer io.Writer, delivery SegmentFrame) error {
	if len(delivery.IngressIdentity) == 0 || len(delivery.IngressIdentity) > 128 || strings.ContainsAny(delivery.IngressIdentity, "\x00\r\n") {
		return errors.New("segment socket: invalid ingress identity")
	}
	if len(delivery.Frame) < bond.EthHeaderLen || len(delivery.Frame) > maxSegmentEthernetFrame {
		return errors.New("segment socket: invalid Ethernet frame length")
	}
	identity := []byte(delivery.IngressIdentity)
	var header [10]byte
	binary.BigEndian.PutUint32(header[0:4], uint32(delivery.IngressPort))
	binary.BigEndian.PutUint16(header[4:6], uint16(len(identity)))
	binary.BigEndian.PutUint32(header[6:10], uint32(len(delivery.Frame)))
	if err := writeSegmentFull(writer, header[:]); err != nil {
		return err
	}
	if err := writeSegmentFull(writer, identity); err != nil {
		return err
	}
	return writeSegmentFull(writer, delivery.Frame)
}

func writeSegmentFull(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
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

func readSegmentDelivery(reader io.Reader) (SegmentFrame, error) {
	var header [10]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return SegmentFrame{}, err
	}
	port := int32(binary.BigEndian.Uint32(header[0:4]))
	identityLen := binary.BigEndian.Uint16(header[4:6])
	frameLen := binary.BigEndian.Uint32(header[6:10])
	if port <= 0 || identityLen == 0 || identityLen > 128 || frameLen < bond.EthHeaderLen || frameLen > maxSegmentEthernetFrame {
		return SegmentFrame{}, errors.New("segment socket: invalid delivery metadata")
	}
	identity := make([]byte, int(identityLen))
	frame := make([]byte, int(frameLen))
	if _, err := io.ReadFull(reader, identity); err != nil {
		return SegmentFrame{}, err
	}
	if strings.ContainsAny(string(identity), "\x00\r\n") {
		return SegmentFrame{}, errors.New("segment socket: invalid ingress identity")
	}
	if _, err := io.ReadFull(reader, frame); err != nil {
		return SegmentFrame{}, err
	}
	return SegmentFrame{Frame: frame, IngressPort: bond.PortID(port), IngressIdentity: string(identity)}, nil
}

// SegmentSocketPort is one remote attachment to a SegmentFabric. Send is
// nonblocking and reports queue saturation as a storm-control drop. Receive is
// bounded by the queue depth authorized for this attachment.
type SegmentSocketPort struct {
	conn       net.Conn
	id         bond.PortID
	identity   string
	out        chan []byte
	in         chan SegmentFrame
	done       chan struct{}
	mu         sync.Mutex
	closed     bool
	wg         sync.WaitGroup
	droppedIn  atomic.Uint64
	droppedOut atomic.Uint64
}

// DialSegmentSocket authenticates one remote attachment to a local Linux
// segment broker. VLAN and other port policy are selected by the broker's
// authorization record, not by this client.
func DialSegmentSocket(ctx context.Context, socketPath, segmentID, identity string, token []byte, queueDepth int) (*SegmentSocketPort, error) {
	if ctx == nil || !filepath.IsAbs(socketPath) || len(socketPath) >= 104 || segmentID == "" || len(segmentID) > 128 || identity == "" || len(identity) > 128 || len(token) < 32 || len(token) > 128 {
		return nil, errors.New("segment socket: invalid dial parameters")
	}
	if queueDepth == 0 {
		queueDepth = defaultSegmentQueue
	}
	if queueDepth < 1 || queueDepth > maxSegmentQueue {
		return nil, fmt.Errorf("segment socket: queue depth must be 1..%d", maxSegmentQueue)
	}
	dialer := net.Dialer{Timeout: segmentSocketHandshakeLimit}
	conn, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("segment socket: dial: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(segmentSocketHandshakeLimit))
	hello := segmentSocketHello{Version: segmentSocketProtocolVersion, SegmentID: segmentID, Identity: identity, Token: slices.Clone(token)}
	if err := writeSegmentControl(conn, hello); err != nil {
		conn.Close()
		return nil, err
	}
	var accept segmentSocketAccept
	if err := readSegmentControl(conn, &accept); err != nil {
		conn.Close()
		return nil, fmt.Errorf("segment socket: attach rejected: %w", err)
	}
	if accept.Version != segmentSocketProtocolVersion || accept.SegmentID != segmentID || accept.Identity != identity || accept.PortID <= 0 {
		conn.Close()
		return nil, errors.New("segment socket: invalid broker acceptance")
	}
	_ = conn.SetDeadline(time.Time{})
	port := &SegmentSocketPort{conn: conn, id: bond.PortID(accept.PortID), identity: accept.Identity, out: make(chan []byte, queueDepth), in: make(chan SegmentFrame, queueDepth), done: make(chan struct{})}
	port.wg.Add(2)
	go port.writeLoop()
	go port.readLoop()
	go func() {
		port.wg.Wait()
		port.mu.Lock()
		port.closed = true
		port.mu.Unlock()
		_ = port.conn.Close()
		close(port.in)
	}()
	return port, nil
}

func (p *SegmentSocketPort) ID() bond.PortID {
	if p == nil {
		return 0
	}
	return p.id
}

// Identity is the broker-accepted attachment identity, not a peer-provided name.
func (p *SegmentSocketPort) Identity() string {
	if p == nil {
		return ""
	}
	return p.identity
}

func (p *SegmentSocketPort) Receive() <-chan SegmentFrame {
	if p == nil {
		return nil
	}
	return p.in
}

func (p *SegmentSocketPort) Send(frame []byte, _ time.Time) bond.L2Verdict {
	if p == nil || len(frame) < bond.EthHeaderLen || len(frame) > maxSegmentEthernetFrame {
		return bond.L2Verdict{Drop: bond.L2DropMalform}
	}
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return bond.L2Verdict{Drop: bond.L2DropNoPort}
	}
	copyFrame := slices.Clone(frame)
	select {
	case p.out <- copyFrame:
		return bond.L2Verdict{Drop: bond.L2Forward}
	default:
		p.droppedOut.Add(1)
		return bond.L2Verdict{Drop: bond.L2DropStorm}
	}
}

func (p *SegmentSocketPort) Close() {
	if p == nil {
		return
	}
	p.stop()
	p.wg.Wait()
}

// QueueDrops reports frames discarded because either bounded local queue filled.
func (p *SegmentSocketPort) QueueDrops() (incoming, outgoing uint64) {
	if p == nil {
		return 0, 0
	}
	return p.droppedIn.Load(), p.droppedOut.Load()
}

func (p *SegmentSocketPort) stop() {
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		close(p.done)
		_ = p.conn.Close()
	}
	p.mu.Unlock()
}

func (p *SegmentSocketPort) writeLoop() {
	defer p.wg.Done()
	for {
		select {
		case <-p.done:
			return
		case frame := <-p.out:
			if err := writeSegmentFrame(p.conn, frame); err != nil {
				p.stop()
				return
			}
		}
	}
}

func (p *SegmentSocketPort) readLoop() {
	defer p.wg.Done()
	for {
		delivery, err := readSegmentDelivery(p.conn)
		if err != nil {
			p.stop()
			return
		}
		select {
		case <-p.done:
			return
		case p.in <- delivery:
		default:
			// A slow local session must not block the socket reader or broker.
			p.droppedIn.Add(1)
		}
	}
}
