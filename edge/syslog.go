package edge

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	remoteSyslogQueue = 256
	maxSyslogMessage  = 4096
	syslogDialTimeout = 5 * time.Second
)

// RemoteSyslog exports informational RFC 5424 messages. UDP messages are
// best-effort datagrams. A tls:// endpoint uses RFC 5425 octet counting over
// TLS with certificate verification. Writes are queued so collector latency
// never blocks the caller; a full queue drops the message and increments Drops.
type RemoteSyslog struct {
	conn      net.Conn
	address   string
	tlsConfig *tls.Config
	stream    bool
	appName   string
	host      string
	pid       int
	queue     chan []byte
	mu        sync.Mutex
	closed    bool
	wg        sync.WaitGroup
	drops     atomic.Uint64
}

// OpenRemoteSyslog starts an RFC 5424 exporter. A host:port address uses UDP;
// tls://host:port uses RFC 5425 over TLS and the system trust roots.
func OpenRemoteSyslog(address, appName string) (*RemoteSyslog, error) {
	return OpenRemoteSyslogWithTLS(address, appName, nil)
}

// OpenRemoteSyslogWithCAFile uses system trust roots plus certificates in
// caFile to verify a tls:// collector. It is useful for private collector PKI.
func OpenRemoteSyslogWithCAFile(address, appName, caFile string) (*RemoteSyslog, error) {
	if caFile == "" {
		return OpenRemoteSyslog(address, appName)
	}
	if !strings.HasPrefix(address, "tls://") {
		return nil, fmt.Errorf("syslog CA file requires a tls:// address")
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read syslog CA file: %w", err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("syslog CA file contains no valid certificates")
	}
	return OpenRemoteSyslogWithTLS(address, appName, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots})
}

// OpenRemoteSyslogWithTLS starts an exporter with an optional TLS client
// configuration. address must be tls://host:port when tlsConfig is non-nil.
// Certificate verification cannot be disabled. The caller may provide RootCAs
// and ClientCertificates for private PKI or mutual TLS.
func OpenRemoteSyslogWithTLS(address, appName string, tlsConfig *tls.Config) (*RemoteSyslog, error) {
	if strings.TrimSpace(appName) == "" || len(appName) > 48 || strings.ContainsAny(appName, " \t\r\n\x00") {
		return nil, fmt.Errorf("syslog app name must be an RFC 5424 token of 1..48 bytes")
	}
	if strings.HasPrefix(address, "tls://") {
		u, err := url.Parse(address)
		if err != nil || u.Scheme != "tls" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("TLS syslog address must be tls://host:port")
		}
		if _, _, err := net.SplitHostPort(u.Host); err != nil {
			return nil, fmt.Errorf("TLS syslog address must include a valid port: %w", err)
		}
		config := &tls.Config{MinVersion: tls.VersionTLS12}
		if tlsConfig != nil {
			config = tlsConfig.Clone()
			if config.InsecureSkipVerify {
				return nil, fmt.Errorf("TLS syslog certificate verification cannot be disabled")
			}
			if config.MinVersion < tls.VersionTLS12 {
				config.MinVersion = tls.VersionTLS12
			}
			if config.MaxVersion != 0 && config.MaxVersion < tls.VersionTLS12 {
				return nil, fmt.Errorf("TLS syslog requires TLS 1.2 or newer")
			}
		}
		conn, err := dialSyslogTLS(u.Host, config)
		if err != nil {
			return nil, fmt.Errorf("connect TLS syslog collector: %w", err)
		}
		return newRemoteSyslog(conn, u.Host, config, true, appName), nil
	}
	if tlsConfig != nil {
		return nil, fmt.Errorf("TLS syslog configuration requires a tls:// address")
	}
	remote, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, fmt.Errorf("resolve syslog collector: %w", err)
	}
	conn, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		return nil, fmt.Errorf("connect syslog collector: %w", err)
	}
	return newRemoteSyslog(conn, remote.String(), nil, false, appName), nil
}

func newRemoteSyslog(conn net.Conn, address string, tlsConfig *tls.Config, stream bool, appName string) *RemoteSyslog {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "-"
	}
	exporter := &RemoteSyslog{conn: conn, address: address, tlsConfig: tlsConfig, stream: stream, appName: appName, host: syslogToken(host), pid: os.Getpid(), queue: make(chan []byte, remoteSyslogQueue)}
	exporter.wg.Add(1)
	go exporter.run()
	return exporter
}

func dialSyslogTLS(address string, config *tls.Config) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: syslogDialTimeout}
	return tls.DialWithDialer(dialer, "tcp", address, config)
}

func (s *RemoteSyslog) Write(p []byte) (int, error) {
	if s == nil {
		return len(p), nil
	}
	count := len(p)
	for _, line := range strings.Split(strings.TrimRight(string(p), "\r\n"), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			continue
		}
		if len(line) > maxSyslogMessage {
			line = line[:maxSyslogMessage]
		}
		message := []byte(fmt.Sprintf("<134>1 %s %s %s %d APP - %s", time.Now().UTC().Format(time.RFC3339Nano), s.host, s.appName, s.pid, line))
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return count, nil
		}
		select {
		case s.queue <- message:
		default:
			s.drops.Add(1)
		}
		s.mu.Unlock()
	}
	return count, nil
}

func (s *RemoteSyslog) run() {
	defer s.wg.Done()
	for message := range s.queue {
		if s.conn == nil && s.stream {
			conn, err := dialSyslogTLS(s.address, s.tlsConfig)
			if err != nil {
				s.drops.Add(1)
				continue
			}
			s.conn = conn
		}
		_ = s.conn.SetWriteDeadline(time.Now().Add(250 * time.Millisecond))
		payload := message
		if s.stream {
			payload = append([]byte(strconv.Itoa(len(message))+" "), message...)
		}
		if err := writeSyslogPayload(s.conn, payload, s.stream); err != nil {
			s.drops.Add(1)
			if s.stream {
				_ = s.conn.Close()
				s.conn = nil
			}
		}
	}
}

func writeSyslogPayload(conn net.Conn, payload []byte, stream bool) error {
	if stream {
		for len(payload) > 0 {
			n, err := conn.Write(payload)
			if err != nil {
				return err
			}
			if n == 0 {
				return fmt.Errorf("short TLS syslog write")
			}
			payload = payload[n:]
		}
		return nil
	}
	n, err := conn.Write(payload)
	if err != nil {
		return err
	}
	if n != len(payload) {
		return fmt.Errorf("short UDP syslog write: %d of %d bytes", n, len(payload))
	}
	return nil
}

// Drops returns the count of messages dropped because the queue filled, a
// connection failed, or a collector write failed.
func (s *RemoteSyslog) Drops() uint64 {
	if s == nil {
		return 0
	}
	return s.drops.Load()
}

func (s *RemoteSyslog) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.queue)
	s.mu.Unlock()
	s.wg.Wait()
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

func syslogToken(value string) string {
	value = strings.Map(func(r rune) rune {
		if r <= 0x20 || r >= 0x7f || strings.ContainsRune("\\]", r) {
			return '_'
		}
		return r
	}, value)
	if value == "" {
		return "-"
	}
	return value
}
