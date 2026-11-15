package edge

import (
	"bufio"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRemoteSyslogExportsRFC5424OverUDP(t *testing.T) {
	collector, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Close()
	if err := collector.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	exporter, err := OpenRemoteSyslog(collector.LocalAddr().String(), "gamebond-edge")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exporter.Write([]byte("gateway transaction committed\n")); err != nil {
		t.Fatal(err)
	}
	var packet [maxSyslogMessage + 256]byte
	n, _, err := collector.ReadFromUDP(packet[:])
	if err != nil {
		t.Fatal(err)
	}
	message := string(packet[:n])
	if !strings.HasPrefix(message, "<134>1 ") || !strings.Contains(message, " gamebond-edge ") || !strings.HasSuffix(message, " gateway transaction committed") {
		t.Fatalf("unexpected RFC 5424 message: %q", message)
	}
	if err := exporter.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRemoteSyslogRejectsInvalidAppName(t *testing.T) {
	if _, err := OpenRemoteSyslog("127.0.0.1:514", "bad app"); err == nil {
		t.Fatal("invalid RFC 5424 app name was accepted")
	}
}

func TestRemoteSyslogTLSUsesVerifiedRFC5425OctetCounting(t *testing.T) {
	certSource := httptest.NewTLSServer(nil)
	certificate := certSource.TLS.Certificates[0]
	certSource.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]})
	caFile := filepath.Join(t.TempDir(), "collector-ca.pem")
	if err := os.WriteFile(caFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	address := "tls://" + listener.Addr().String()
	messageCh := make(chan string, 1)
	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			serverErr <- err
			return
		}
		reader := bufio.NewReader(conn)
		lengthText, err := reader.ReadString(' ')
		if err != nil {
			serverErr <- err
			return
		}
		length, err := strconv.Atoi(strings.TrimSuffix(lengthText, " "))
		if err != nil || length <= 0 || length > maxSyslogMessage+256 {
			serverErr <- errors.New("invalid RFC 5425 frame length")
			return
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(reader, payload); err != nil {
			serverErr <- err
			return
		}
		messageCh <- string(payload)
	}()

	exporter, err := OpenRemoteSyslogWithCAFile(address, "gamebond-edge", caFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exporter.Write([]byte("TLS collector transaction committed\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case message := <-messageCh:
		if !strings.HasPrefix(message, "<134>1 ") || !strings.Contains(message, " gamebond-edge ") || !strings.HasSuffix(message, " TLS collector transaction committed") {
			t.Fatalf("unexpected RFC 5424 TLS message: %q", message)
		}
	case err := <-serverErr:
		t.Fatal(err)
	case <-time.After(3 * time.Second):
		t.Fatal("TLS syslog collector did not receive a message")
	}
	if err := exporter.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRemoteSyslogTLSRejectsUntrustedCollector(t *testing.T) {
	certSource := httptest.NewTLSServer(nil)
	certificate := certSource.TLS.Certificates[0]
	certSource.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			defer conn.Close()
			_ = conn.(*tls.Conn).Handshake()
		}
	}()
	if _, err := OpenRemoteSyslog("tls://"+listener.Addr().String(), "gamebond-edge"); err == nil {
		t.Fatal("TLS syslog accepted an untrusted collector certificate")
	}
}

func TestRemoteSyslogTLSReconnectsAfterCollectorDisconnect(t *testing.T) {
	certSource := httptest.NewTLSServer(nil)
	certificate := certSource.TLS.Certificates[0]
	certSource.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	caFile := filepath.Join(t.TempDir(), "collector-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}), 0o600); err != nil {
		t.Fatal(err)
	}
	firstMessage := make(chan string, 1)
	secondMessage := make(chan string, 1)
	disconnected := make(chan struct{})
	serverErr := make(chan error, 1)
	go func() {
		first, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		firstTLS := first.(*tls.Conn)
		message, err := readSyslogTLSMessage(firstTLS)
		if err != nil {
			serverErr <- err
			firstTLS.Close()
			return
		}
		firstMessage <- message
		if tcp, ok := firstTLS.NetConn().(*net.TCPConn); ok {
			_ = tcp.SetLinger(0)
		}
		_ = firstTLS.Close()
		close(disconnected)

		second, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer second.Close()
		message, err = readSyslogTLSMessage(second)
		if err != nil {
			serverErr <- err
			return
		}
		secondMessage <- message
	}()

	exporter, err := OpenRemoteSyslogWithCAFile("tls://"+listener.Addr().String(), "gamebond-edge", caFile)
	if err != nil {
		t.Fatal(err)
	}
	defer exporter.Close()
	if _, err := exporter.Write([]byte("before disconnect\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case message := <-firstMessage:
		if !strings.HasSuffix(message, " before disconnect") {
			t.Fatalf("first TLS message = %q", message)
		}
	case err := <-serverErr:
		t.Fatal(err)
	case <-time.After(3 * time.Second):
		t.Fatal("collector did not receive initial TLS message")
	}
	select {
	case <-disconnected:
	case err := <-serverErr:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("collector did not close the first connection")
	}

	var got string
	for attempt := 0; attempt < 20; attempt++ {
		if _, err := exporter.Write([]byte(fmt.Sprintf("reconnect probe %d\n", attempt))); err != nil {
			t.Fatal(err)
		}
		select {
		case got = <-secondMessage:
			attempt = 20
		case err := <-serverErr:
			t.Fatal(err)
		case <-time.After(50 * time.Millisecond):
		}
	}
	if got == "" || !strings.Contains(got, " reconnect probe ") {
		t.Fatal("syslog exporter did not reconnect after a failed TLS stream write")
	}
}

func readSyslogTLSMessage(conn net.Conn) (string, error) {
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return "", err
	}
	reader := bufio.NewReader(conn)
	lengthText, err := reader.ReadString(' ')
	if err != nil {
		return "", err
	}
	length, err := strconv.Atoi(strings.TrimSuffix(lengthText, " "))
	if err != nil || length <= 0 || length > maxSyslogMessage+256 {
		return "", errors.New("invalid RFC 5425 frame length")
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return "", err
	}
	return string(payload), nil
}
