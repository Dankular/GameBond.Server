package l2gw

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"
)

const dhcpv6RelayPendingLimit = 4096

type dhcpv6RelayPending struct {
	peer      netip.Addr
	mac       []byte
	ethernet  []byte
	circuitID string
	clientID  []byte
	expires   time.Time
}

type dhcpv6Relay struct {
	conn       *net.UDPConn
	server     netip.AddrPort
	link       netip.Addr
	serverLink netip.Addr
	gatewayMAC []byte
	out        func([]byte)
	mu         sync.Mutex
	pending    map[[3]byte]dhcpv6RelayPending
}

func newDHCPv6Relay(server netip.AddrPort, link netip.Addr, gatewayMAC net.HardwareAddr, serverLink netip.Addr, out func([]byte)) (*dhcpv6Relay, error) {
	if !server.IsValid() || !server.Addr().Is6() || server.Addr().Is4In6() || server.Port() == 0 || !link.Is6() || link.Is4In6() || !serverLink.Is6() || serverLink.Is4In6() || len(gatewayMAC) != 6 || out == nil {
		return nil, errors.New("l2gw: invalid DHCPv6 relay configuration")
	}
	conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6unspecified})
	if err != nil {
		return nil, err
	}
	return &dhcpv6Relay{conn: conn, server: server, link: link, serverLink: serverLink, gatewayMAC: append([]byte(nil), gatewayMAC...), out: out, pending: make(map[[3]byte]dhcpv6RelayPending)}, nil
}

func (r *dhcpv6Relay) Close() {
	if r != nil && r.conn != nil {
		_ = r.conn.Close()
	}
}

func (r *dhcpv6Relay) HandleFrame(frame []byte, ingress string) bool {
	if r == nil || len(frame) < 14+40+8 {
		return false
	}
	offset := 14
	etherType := binary.BigEndian.Uint16(frame[12:14])
	for tags := 0; tags < 2 && (etherType == 0x8100 || etherType == 0x88a8 || etherType == 0x9100); tags++ {
		if len(frame) < offset+4 {
			return false
		}
		etherType = binary.BigEndian.Uint16(frame[offset+2 : offset+4])
		offset += 4
	}
	if etherType != 0x86dd || len(frame) < offset+48 {
		return false
	}
	ip := frame[offset:]
	if ip[0]>>4 != 6 || ip[6] != 17 || ip[7] != 1 || binary.BigEndian.Uint16(ip[40:42]) != 546 || binary.BigEndian.Uint16(ip[42:44]) != 547 {
		return false
	}
	ipLen := int(binary.BigEndian.Uint16(ip[4:6]))
	if ipLen != len(ip)-40 || ipLen < 8 || int(binary.BigEndian.Uint16(ip[44:46])) != ipLen || binary.BigEndian.Uint16(ip[46:48]) == 0 || dhcpv6UDPChecksum(ip[8:24], ip[24:40], ip[40:]) != 0 {
		return true
	}
	payload := ip[48:]
	req, ok := parseDHCPv6(payload)
	if !ok || len(req.clientID) == 0 {
		return true
	}
	if ingress == "" {
		ingress = "local"
	}
	if len(ingress) > 255 {
		return true
	}
	peer := netip.AddrFrom16([16]byte(ip[8:24]))
	forward, err := makeDHCPv6RelayForward(payload, r.link, peer, ingress)
	if err != nil {
		return true
	}
	var xid [3]byte
	copy(xid[:], payload[1:4])
	r.mu.Lock()
	now := time.Now()
	for id, pending := range r.pending {
		if !now.Before(pending.expires) {
			delete(r.pending, id)
		}
	}
	prior, exists := r.pending[xid]
	if exists && (prior.circuitID != ingress || string(prior.clientID) != string(req.clientID) || prior.peer != peer || string(prior.mac) != string(frame[6:12])) {
		r.mu.Unlock()
		return true
	}
	if !exists && len(r.pending) >= dhcpv6RelayPendingLimit {
		r.mu.Unlock()
		return true
	}
	r.pending[xid] = dhcpv6RelayPending{peer: peer, mac: append([]byte(nil), frame[6:12]...), ethernet: append([]byte(nil), frame[:offset]...), circuitID: ingress, clientID: append([]byte(nil), req.clientID...), expires: now.Add(30 * time.Second)}
	r.mu.Unlock()
	if _, err := r.conn.WriteToUDP(forward, net.UDPAddrFromAddrPort(r.server)); err != nil {
		r.mu.Lock()
		delete(r.pending, xid)
		r.mu.Unlock()
	}
	return true
}

func (r *dhcpv6Relay) readLoop(ctxDone <-chan struct{}) {
	buf := make([]byte, 65535)
	for {
		_ = r.conn.SetReadDeadline(time.Now().Add(time.Second))
		n, from, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-ctxDone:
					return
				default:
					continue
				}
			}
			return
		}
		if !from.AddrPort().Addr().Unmap().Is6() || from.AddrPort().Addr().Unmap() != r.server.Addr() || from.Port != int(r.server.Port()) {
			continue
		}
		peer, inner, circuit, ok := dhcpv6RelayReplyEnvelope(buf[:n])
		if !ok {
			continue
		}
		req, ok := parseDHCPv6(inner)
		if !ok {
			continue
		}
		var xid [3]byte
		copy(xid[:], inner[1:4])
		r.mu.Lock()
		pending, exists := r.pending[xid]
		if exists {
			delete(r.pending, xid)
		}
		r.mu.Unlock()
		if !exists || pending.peer != peer || pending.circuitID != circuit || string(req.clientID) != string(pending.clientID) {
			continue
		}
		payload, err := parseDHCPv6RelayReply(buf[:n], r.link, pending.peer, pending.circuitID)
		if err != nil {
			continue
		}
		frame := buildDHCPv6Frame(pending.ethernet, pending.mac, r.gatewayMAC, pending.peer, r.serverLink, payload)
		r.out(frame)
	}
}

func dhcpv6RelayReplyEnvelope(payload []byte) (netip.Addr, []byte, string, bool) {
	if len(payload) < 34 || payload[0] != dhcpv6RelayReply || payload[1] != 0 {
		return netip.Addr{}, nil, "", false
	}
	peer := netip.AddrFrom16([16]byte(payload[18:34]))
	var inner []byte
	circuit := ""
	for off := 34; off < len(payload); {
		if len(payload)-off < 4 {
			return netip.Addr{}, nil, "", false
		}
		code, n := binary.BigEndian.Uint16(payload[off:off+2]), int(binary.BigEndian.Uint16(payload[off+2:off+4]))
		off += 4
		if n > len(payload)-off {
			return netip.Addr{}, nil, "", false
		}
		switch code {
		case dhcpv6OptRelayMsg:
			if inner != nil {
				return netip.Addr{}, nil, "", false
			}
			inner = payload[off : off+n]
		case 18:
			if circuit != "" {
				return netip.Addr{}, nil, "", false
			}
			circuit = string(payload[off : off+n])
		}
		off += n
	}
	return peer, inner, circuit, peer.Is6() && inner != nil && circuit != ""
}
