//go:build linux

package inspection

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const DefaultProxyPort = 9445

type URLPolicy func(device netip.Addr, host, path string) (ruleID, action string, matched bool)
type policyHolder struct{ fn URLPolicy }
type exhaustionHolder struct{ action string }

type ProxyStatus struct {
	Ready         bool   `json:"ready"`
	Active        int    `json:"active_sessions"`
	Maximum       int    `json:"max_sessions"`
	Rejected      uint64 `json:"rejected"`
	Bypassed      uint64 `json:"bypassed"`
	Errors        uint64 `json:"errors"`
	PolicyMatches uint64 `json:"policy_matches"`
	PolicyDenied  uint64 `json:"policy_denied"`
}

// Proxy terminates supported TCP/TLS flows redirected from the tunnel interface.
type Proxy struct {
	CA            *CA
	Limiter       *Limiter
	Port          int
	policy        atomic.Pointer[policyHolder]
	exhaustion    atomic.Pointer[exhaustionHolder]
	ready         atomic.Bool
	bypassed      atomic.Uint64
	errors        atomic.Uint64
	policyMatches atomic.Uint64
	policyDenied  atomic.Uint64
	mu            sync.Mutex
	connections   map[net.Conn]struct{}
	workers       sync.WaitGroup
}

func (p *Proxy) SetPolicy(fn URLPolicy) {
	if fn == nil {
		p.policy.Store(nil)
		return
	}
	p.policy.Store(&policyHolder{fn: fn})
}

func (p *Proxy) SetExhaustionAction(action string) {
	p.exhaustion.Store(&exhaustionHolder{action: action})
}

func (p *Proxy) Status() ProxyStatus {
	st := ProxyStatus{Ready: p.ready.Load(), Bypassed: p.bypassed.Load(), Errors: p.errors.Load(), PolicyMatches: p.policyMatches.Load(), PolicyDenied: p.policyDenied.Load()}
	if p.Limiter != nil {
		st.Active, st.Maximum, st.Rejected = p.Limiter.Active(), p.Limiter.Limit(), p.Limiter.Rejected()
	}
	return st
}

func (p *Proxy) RecordError() { p.errors.Add(1) }

// Run accepts redirected traffic until ctx ends. Callers should invoke only when inspection is enabled.
func (p *Proxy) Run(ctx context.Context) error {
	if p.CA == nil || p.Limiter == nil {
		return errors.New("inspection: CA and session limiter are required")
	}
	port := p.Port
	if port == 0 {
		port = DefaultProxyPort
	}
	ln, err := net.Listen("tcp4", net.JoinHostPort("0.0.0.0", strconv.Itoa(port)))
	if err != nil {
		return fmt.Errorf("inspection: listen: %w", err)
	}
	p.ready.Store(true)
	go func() {
		<-ctx.Done()
		_ = ln.Close()
		p.closeConnections()
	}()
	defer p.ready.Store(false)
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			p.closeConnections()
			p.workers.Wait()
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		p.mu.Lock()
		if p.connections == nil {
			p.connections = map[net.Conn]struct{}{}
		}
		p.connections[conn] = struct{}{}
		p.workers.Add(1)
		p.mu.Unlock()
		go func() {
			defer p.workers.Done()
			defer func() {
				p.mu.Lock()
				delete(p.connections, conn)
				p.mu.Unlock()
			}()
			p.handle(ctx, conn)
		}()
	}
}

func (p *Proxy) closeConnections() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for conn := range p.connections {
		_ = conn.Close()
	}
}

func (p *Proxy) handle(ctx context.Context, client net.Conn) {
	defer client.Close()
	original, err := originalDestination(client)
	if err != nil {
		p.errors.Add(1)
		return
	}
	release, ok := p.Limiter.Acquire(ctx)
	if !ok {
		action := p.exhaustion.Load()
		if action != nil && action.action == "bypass" {
			p.bypassed.Add(1)
			p.relay(client, original)
		}
		return
	}
	defer release()

	var serverName string
	front := tls.Server(&idleDeadlineConn{Conn: client, idle: 5 * time.Minute}, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			serverName = info.ServerName
			certPEM, keyPEM, err := p.CA.Leaf(serverName)
			if err != nil {
				return nil, err
			}
			cert, err := tls.X509KeyPair(certPEM, keyPEM)
			if err != nil {
				return nil, err
			}
			return &cert, nil
		},
	})
	if err := front.HandshakeContext(ctx); err != nil {
		p.errors.Add(1)
		return
	}
	if front.ConnectionState().NegotiatedProtocol != "" && front.ConnectionState().NegotiatedProtocol != "http/1.1" {
		p.errors.Add(1)
		return
	}
	reader := bufio.NewReaderSize(front, 32*1024)
	request, err := http.ReadRequest(reader)
	if err != nil {
		p.errors.Add(1)
		return
	}
	defer request.Body.Close()
	if request.Method == http.MethodConnect || request.Header.Get("Upgrade") != "" {
		p.errors.Add(1)
		writeInspectionError(front, http.StatusNotImplemented)
		return
	}
	host := request.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if serverName == "" || !strings.EqualFold(host, strings.TrimSuffix(serverName, ".")) {
		p.errors.Add(1)
		writeInspectionError(front, http.StatusMisdirectedRequest)
		return
	}
	if policy := p.policy.Load(); policy != nil {
		device := netip.Addr{}
		if peer, ok := client.RemoteAddr().(*net.TCPAddr); ok {
			if addr, valid := netip.AddrFromSlice(peer.IP); valid {
				device = addr.Unmap()
			}
		}
		if _, action, matched := policy.fn(device, host, request.URL.EscapedPath()); matched {
			p.policyMatches.Add(1)
			if action == "deny" {
				p.policyDenied.Add(1)
				writeInspectionError(front, http.StatusForbidden)
				return
			}
		}
	}
	request.URL.Scheme = "https"
	request.URL.Host = request.Host
	request.RequestURI = ""
	request.Close = true
	request.Header.Del("Proxy-Connection")
	request.Header.Set("Connection", "close")

	upstream, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", original.String())
	if err != nil {
		p.errors.Add(1)
		writeInspectionError(front, http.StatusBadGateway)
		return
	}
	defer upstream.Close()
	secure := tls.Client(&idleDeadlineConn{Conn: upstream, idle: 5 * time.Minute}, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName})
	if err := secure.HandshakeContext(ctx); err != nil {
		p.errors.Add(1)
		writeInspectionError(front, http.StatusBadGateway)
		return
	}
	if err := request.Write(secure); err != nil {
		p.errors.Add(1)
		return
	}
	response, err := http.ReadResponse(bufio.NewReaderSize(secure, 32*1024), request)
	if err != nil {
		p.errors.Add(1)
		writeInspectionError(front, http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	response.Close = true
	if err := response.Write(front); err != nil {
		p.errors.Add(1)
	}
}

func writeInspectionError(w io.Writer, code int) {
	status := http.StatusText(code)
	_, _ = fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", code, status)
}

func (p *Proxy) relay(client net.Conn, original netip.AddrPort) {
	remote, err := net.DialTimeout("tcp", original.String(), 10*time.Second)
	if err != nil {
		return
	}
	defer remote.Close()
	done := make(chan struct{}, 2)
	clientIdle := &idleDeadlineConn{Conn: client, idle: 5 * time.Minute}
	remoteIdle := &idleDeadlineConn{Conn: remote, idle: 5 * time.Minute}
	go func() { _, _ = io.Copy(remoteIdle, clientIdle); done <- struct{}{} }()
	go func() { _, _ = io.Copy(clientIdle, remoteIdle); done <- struct{}{} }()
	<-done
}

type idleDeadlineConn struct {
	net.Conn
	idle time.Duration
}

func (c *idleDeadlineConn) Read(p []byte) (int, error) {
	_ = c.Conn.SetReadDeadline(time.Now().Add(c.idle))
	return c.Conn.Read(p)
}

func (c *idleDeadlineConn) Write(p []byte) (int, error) {
	_ = c.Conn.SetWriteDeadline(time.Now().Add(c.idle))
	return c.Conn.Write(p)
}

type sockaddrIn struct {
	Family uint16
	Port   uint16
	Addr   [4]byte
	Zero   [8]byte
}

func originalDestination(conn net.Conn) (netip.AddrPort, error) {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return netip.AddrPort{}, errors.New("inspection: accepted connection is not TCP")
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}
	var addr sockaddrIn
	var callErr error
	err = raw.Control(func(fd uintptr) {
		length := uint32(unsafe.Sizeof(addr))
		_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, fd, uintptr(unix.SOL_IP), 80, uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&length)), 0)
		if errno != 0 {
			callErr = errno
			return
		}
		if addr.Family != unix.AF_INET {
			callErr = errors.New("inspection: original destination is not IPv4")
		}
	})
	if err != nil {
		return netip.AddrPort{}, err
	}
	if callErr != nil {
		return netip.AddrPort{}, callErr
	}
	portBytes := (*[2]byte)(unsafe.Pointer(&addr.Port))
	port := uint16(portBytes[0])<<8 | uint16(portBytes[1])
	return netip.AddrPortFrom(netip.AddrFrom4(addr.Addr), port), nil
}
