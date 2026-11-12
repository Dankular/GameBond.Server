package stream

import (
	"fmt"
	"io"
	"net"
	"time"
)

var errEOF = io.EOF

// Gateway accepts streams from an Endpoint, dials the requested TCP target
// and relays bytes both ways.
type Gateway struct {
	Ep      *Endpoint
	Dial    func(network, address string, timeout time.Duration) (net.Conn, error)
	Allowed func(address string) bool // nil allows everything
}

// Serve runs until the endpoint closes.
func (g *Gateway) Serve() error {
	dial := g.Dial
	if dial == nil {
		dial = func(n, a string, d time.Duration) (net.Conn, error) { return net.DialTimeout(n, a, d) }
	}
	for {
		s, err := g.Ep.Accept()
		if err != nil {
			return err
		}
		go g.handle(s, dial)
	}
}

func (g *Gateway) handle(s *Stream, dial func(string, string, time.Duration) (net.Conn, error)) {
	defer s.Close()
	s.SetReadDeadline(time.Now().Add(10 * time.Second))
	var l [1]byte
	if _, err := io.ReadFull(s, l[:]); err != nil || l[0] == 0 {
		s.abort()
		return
	}
	target := make([]byte, l[0])
	if _, err := io.ReadFull(s, target); err != nil {
		s.abort()
		return
	}
	s.SetReadDeadline(time.Time{})
	addr := string(target)
	if g.Allowed != nil && !g.Allowed(addr) {
		s.Write([]byte{1})
		return
	}
	up, err := dial("tcp4", addr, 8*time.Second)
	if err != nil {
		s.Write([]byte{1})
		return
	}
	defer up.Close()
	if _, err := s.Write([]byte{0}); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() {
		for t := time.NewTicker(2 * time.Second); ; <-t.C {
			st, cwnd, rtt := s.Stats()
			if st.PacketsSent == 0 && st.BytesAcked == 0 {
				continue
			}
			fmt.Printf("{\"status\":\"stream\",\"cwnd\":%d,\"srtt_ms\":%d,\"retx\":%d,\"spurious\":%d,\"acked\":%d}\n", cwnd, rtt.Milliseconds(), st.Retransmits, st.SpuriousRetx, st.BytesAcked)
			if s.closedNow() {
				return
			}
		}
	}()
	go func() { // stream -> upstream
		io.Copy(up, s)
		if tc, ok := up.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() { // upstream -> stream
		io.Copy(s, up)
		s.CloseWrite()
		done <- struct{}{}
	}()
	<-done
	<-done
	if st, cwnd, rtt := s.Stats(); st.BytesAcked > 1<<20 {
		fmt.Printf("{\"status\":\"stream_done\",\"cwnd\":%d,\"srtt_ms\":%d,\"sent\":%d,\"retx\":%d,\"spurious\":%d,\"timeouts\":%d,\"acked\":%d}\n", cwnd, rtt.Milliseconds(), st.PacketsSent, st.Retransmits, st.SpuriousRetx, st.Timeouts, st.BytesAcked)
	}
}
