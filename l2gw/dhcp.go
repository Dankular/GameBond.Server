package l2gw

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// DHCP message types (option 53).
const (
	dhcpDiscover = 1
	dhcpOffer    = 2
	dhcpRequest  = 3
	dhcpDecline  = 4
	dhcpAck      = 5
	dhcpNak      = 6
	dhcpRelease  = 7
	dhcpInform   = 8

	dhcpMagic     = 0x63825363
	dhcpFixedSize = 236
)

type lease struct {
	ip      netip.Addr
	mac     [6]byte
	expires time.Time
	offered bool // only offered so far, held briefly
	ingress string
}

type dhcpCounters struct {
	discover, request, ack, nak uint64
	leases                      int
}

// dhcpServer hands out addresses from a pool, honouring fixed hosts. It is authoritative: a client
// asking to renew an address it does not hold, or one outside the pool, is refused so it starts over.
// That is what lets the two exits use different pools and the same gateway address.
type dhcpServer struct {
	mu      sync.Mutex
	cfg     *Config
	byMAC   map[[6]byte]*lease
	byIP    map[netip.Addr]*lease
	static  map[[6]byte]netip.Addr
	staticI map[netip.Addr]bool
	ingress map[[6]byte]string
	banned  map[netip.Addr]time.Time // declined addresses
	count   dhcpCounters
}

func (d *dhcpServer) init(cfg *Config) error {
	d.cfg = cfg
	pfx := cfg.Address
	gw := pfx.Addr()
	network := pfx.Masked().Addr()
	broadcast := network.As4()
	mask := net.CIDRMask(pfx.Bits(), 32)
	for i := range broadcast {
		broadcast[i] |= ^mask[i]
	}
	broadcastIP := netip.AddrFrom4(broadcast)
	if !cfg.DHCPStart.IsValid() || !cfg.DHCPEnd.IsValid() {
		return errors.New("l2gw: DHCP range required")
	}
	if !pfx.Contains(cfg.DHCPStart) || !pfx.Contains(cfg.DHCPEnd) || cfg.DHCPEnd.Less(cfg.DHCPStart) ||
		(cfg.DHCPStart.Compare(gw) <= 0 && gw.Compare(cfg.DHCPEnd) <= 0) ||
		(cfg.DHCPStart.Compare(network) <= 0 && network.Compare(cfg.DHCPEnd) <= 0) ||
		(cfg.DHCPStart.Compare(broadcastIP) <= 0 && broadcastIP.Compare(cfg.DHCPEnd) <= 0) {
		return errors.New("l2gw: DHCP range must contain only usable host addresses in the subnet")
	}
	d.byMAC = map[[6]byte]*lease{}
	d.byIP = map[netip.Addr]*lease{}
	d.static = map[[6]byte]netip.Addr{}
	d.staticI = map[netip.Addr]bool{}
	d.ingress = map[[6]byte]string{}
	d.banned = map[netip.Addr]time.Time{}
	if err := d.setHosts(cfg.Hosts); err != nil {
		return err
	}
	return nil
}

func (d *dhcpServer) stats() dhcpCounters {
	d.mu.Lock()
	defer d.mu.Unlock()
	c := d.count
	now := time.Now()
	for _, l := range d.byMAC {
		if !l.offered && now.Before(l.expires) {
			c.leases++
		}
	}
	return c
}

func (d *dhcpServer) setIngress(mac [6]byte, identity string) {
	d.mu.Lock()
	d.ingress[mac] = identity
	d.mu.Unlock()
}

func (d *dhcpServer) ingressFor(mac [6]byte) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.ingress[mac]
}

func (d *dhcpServer) bindings() []DHCPBinding {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	bindings := make([]DHCPBinding, 0, len(d.byMAC))
	for mac, lease := range d.byMAC {
		if lease.offered || !now.Before(lease.expires) || lease.ingress == "" {
			continue
		}
		bindings = append(bindings, DHCPBinding{MAC: net.HardwareAddr(mac[:]).String(), IP: lease.ip, SessionPort: lease.ingress, Expires: lease.expires})
	}
	return bindings
}

// dhcpMessage is the part of a BOOTP/DHCP packet the server needs.
type dhcpMessage struct {
	xid       uint32
	flags     uint16
	ciaddr    netip.Addr
	chaddr    [6]byte
	msgType   byte
	reqIP     netip.Addr
	serverID  netip.Addr
	hostname  string
	rawHeader []byte // first 236 bytes, echoed in replies
}

func parseDHCP(p []byte) (dhcpMessage, bool) {
	var m dhcpMessage
	if len(p) < dhcpFixedSize+4 || p[0] != 1 || p[1] != 1 || p[2] != 6 {
		return m, false
	}
	if binary.BigEndian.Uint32(p[dhcpFixedSize:]) != dhcpMagic {
		return m, false
	}
	m.xid = binary.BigEndian.Uint32(p[4:])
	m.flags = binary.BigEndian.Uint16(p[10:])
	m.ciaddr = netip.AddrFrom4([4]byte(p[12:16]))
	copy(m.chaddr[:], p[28:34])
	m.rawHeader = p[:dhcpFixedSize]
	opts := p[dhcpFixedSize+4:]
	ended := false
	for len(opts) > 0 {
		code := opts[0]
		if code == 0 {
			opts = opts[1:]
			continue
		}
		if code == 255 {
			ended = true
			break
		}
		if len(opts) < 2 || len(opts) < 2+int(opts[1]) {
			return m, false
		}
		val := opts[2 : 2+int(opts[1])]
		switch code {
		case 53:
			if len(val) == 1 {
				m.msgType = val[0]
			}
		case 50:
			if len(val) == 4 {
				m.reqIP = netip.AddrFrom4([4]byte(val))
			}
		case 54:
			if len(val) == 4 {
				m.serverID = netip.AddrFrom4([4]byte(val))
			}
		case 12:
			m.hostname = string(bytes.TrimRight(val, "\x00"))
		}
		opts = opts[2+int(opts[1]):]
	}
	// This server only supports Ethernet clients. Refuse malformed or missing end markers
	// instead of acting on a partially parsed request.
	zeroMAC := m.chaddr == [6]byte{}
	return m, ended && m.msgType != 0 && !zeroMAC && m.chaddr[0]&1 == 0
}

// handle returns the reply for one client message, or nil.
func (d *dhcpServer) handle(m dhcpMessage, now time.Time) []byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	gw := d.cfg.Address.Addr()
	if m.serverID.IsValid() && m.serverID != gw {
		return nil // the client chose another server
	}
	switch m.msgType {
	case dhcpDiscover:
		d.count.discover++
		ip, ok := d.pick(m, now, netip.Addr{})
		if !ok {
			return nil
		}
		d.hold(m.chaddr, ip, now.Add(60*time.Second), true)
		return d.reply(m, dhcpOffer, ip, d.cfg.Lease)
	case dhcpRequest:
		d.count.request++
		want := m.reqIP
		if !want.IsValid() {
			want = m.ciaddr
		}
		ip, ok := d.pick(m, now, want)
		if !ok || (want.IsValid() && ip != want) {
			d.count.nak++
			return d.reply(m, dhcpNak, netip.Addr{}, 0)
		}
		d.hold(m.chaddr, ip, now.Add(d.cfg.Lease), false)
		if lease := d.byMAC[m.chaddr]; lease != nil {
			lease.ingress = d.ingress[m.chaddr]
		}
		d.count.ack++
		return d.reply(m, dhcpAck, ip, d.cfg.Lease)
	case dhcpDecline:
		if m.reqIP.IsValid() {
			d.banned[m.reqIP] = now.Add(10 * time.Minute)
			d.drop(m.chaddr)
		}
	case dhcpRelease:
		d.drop(m.chaddr)
	case dhcpInform:
		return d.reply(m, dhcpAck, netip.Addr{}, 0)
	}
	return nil
}

func (d *dhcpServer) inPool(ip netip.Addr) bool {
	return ip.Compare(d.cfg.DHCPStart) >= 0 && ip.Compare(d.cfg.DHCPEnd) <= 0
}

// pick chooses the address for a client. With want set it only confirms that address (or returns a
// different one so the caller can refuse); without it, it allocates.
func (d *dhcpServer) pick(m dhcpMessage, now time.Time, want netip.Addr) (netip.Addr, bool) {
	if fixed, ok := d.static[m.chaddr]; ok {
		return fixed, true
	}
	free := func(ip netip.Addr) bool {
		if d.staticI[ip] || !d.inPool(ip) {
			return false
		}
		if until, ok := d.banned[ip]; ok && now.Before(until) {
			return false
		}
		if l, ok := d.byIP[ip]; ok && l.mac != m.chaddr && now.Before(l.expires) {
			return false
		}
		return true
	}
	if want.IsValid() {
		if free(want) {
			return want, true
		}
		return netip.Addr{}, false
	}
	if l, ok := d.byMAC[m.chaddr]; ok && free(l.ip) {
		return l.ip, true
	}
	for ip := d.cfg.DHCPStart; ip.Compare(d.cfg.DHCPEnd) <= 0; ip = ip.Next() {
		if free(ip) {
			return ip, true
		}
	}
	return netip.Addr{}, false
}

func (d *dhcpServer) hold(mac [6]byte, ip netip.Addr, until time.Time, offered bool) {
	if old, ok := d.byMAC[mac]; ok && old.ip != ip {
		delete(d.byIP, old.ip)
	}
	l := &lease{ip: ip, mac: mac, expires: until, offered: offered}
	d.byMAC[mac] = l
	d.byIP[ip] = l
}

func (d *dhcpServer) drop(mac [6]byte) {
	if l, ok := d.byMAC[mac]; ok {
		delete(d.byIP, l.ip)
		delete(d.byMAC, mac)
	}
}

// reply builds an OFFER, ACK or NAK.
func (d *dhcpServer) reply(m dhcpMessage, typ byte, ip netip.Addr, lease time.Duration) []byte {
	gw := d.cfg.Address.Addr()
	b := make([]byte, dhcpFixedSize+4, 320)
	b[0], b[1], b[2] = 2, 1, 6
	binary.BigEndian.PutUint32(b[4:], m.xid)
	binary.BigEndian.PutUint16(b[10:], m.flags)
	if typ == dhcpAck && !ip.IsValid() { // INFORM answer carries the client's own address
		copy(b[12:16], m.ciaddr.AsSlice())
	}
	if ip.IsValid() {
		copy(b[16:20], ip.AsSlice())
	}
	copy(b[20:24], gw.AsSlice())
	copy(b[28:34], m.chaddr[:])
	binary.BigEndian.PutUint32(b[dhcpFixedSize:], dhcpMagic)
	opt := func(code byte, v ...byte) { b = append(append(b, code, byte(len(v))), v...) }
	opt(53, typ)
	opt(54, gw.AsSlice()...)
	if typ != dhcpNak {
		if lease > 0 {
			secs := uint32(lease / time.Second)
			var t [4]byte
			binary.BigEndian.PutUint32(t[:], secs)
			opt(51, t[:]...)
			binary.BigEndian.PutUint32(t[:], secs/2)
			opt(58, t[:]...)
			binary.BigEndian.PutUint32(t[:], secs/8*7)
			opt(59, t[:]...)
		}
		mask := net.CIDRMask(d.cfg.Address.Bits(), 32)
		opt(1, mask...)
		opt(3, gw.AsSlice()...)
		var dns []byte
		for _, a := range d.cfg.DNS {
			dns = append(dns, a.AsSlice()...)
		}
		opt(6, dns...)
		var mtu [2]byte
		binary.BigEndian.PutUint16(mtu[:], uint16(d.cfg.MTU))
		opt(26, mtu[:]...)
		bc := d.cfg.Address.Masked().Addr().As4()
		hostBits := 32 - d.cfg.Address.Bits()
		v := binary.BigEndian.Uint32(bc[:]) | (1<<hostBits - 1)
		binary.BigEndian.PutUint32(bc[:], v)
		opt(28, bc[:]...)
	}
	b = append(b, 255)
	for len(b) < 300 {
		b = append(b, 0)
	}
	return b
}

// startDHCP binds UDP port 67 on the stack and serves until ctx ends. Two endpoints share the port:
// a wildcard one that receives the clients' broadcasts, and one bound to the gateway address that
// every reply leaves from. Replies from the wildcard socket take whatever source address the stack
// picks, and once forwarded flows have created temporary spoofed addresses on the NIC that is no
// longer the gateway; devices then ignore the offer.
func (g *Gateway) startDHCP(ctx context.Context) error {
	open := func(addr tcpip.Address) (*gonet.UDPConn, error) {
		var wq waiter.Queue
		ep, err := g.stack.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
		if err != nil {
			return nil, errors.New("l2gw: dhcp endpoint: " + err.String())
		}
		ep.SocketOptions().SetBroadcast(true)
		ep.SocketOptions().SetReuseAddress(true)
		if err := ep.Bind(tcpip.FullAddress{NIC: nicID, Addr: addr, Port: 67}); err != nil {
			ep.Close()
			return nil, errors.New("l2gw: dhcp bind: " + err.String())
		}
		return gonet.NewUDPConn(&wq, ep), nil
	}
	recv, err := open(tcpip.Address{})
	if err != nil {
		return err
	}
	send, err := open(tcpip.AddrFrom4(g.cfg.Address.Addr().As4()))
	if err != nil {
		recv.Close()
		return err
	}
	if g.cfg.DHCPRelay4.IsValid() {
		return g.startDHCPRelay(ctx, recv, send)
	}
	bcast := &net.UDPAddr{IP: net.IPv4bcast.To4(), Port: 68}
	serve := func(conn *gonet.UDPConn) {
		defer g.done.Done()
		defer conn.Close()
		go func() { <-ctx.Done(); conn.Close() }()
		buf := make([]byte, 2048)
		for {
			n, _, rerr := conn.ReadFrom(buf)
			if rerr != nil {
				return
			}
			m, ok := parseDHCP(buf[:n])
			if !ok {
				continue
			}
			if reply := g.dhcp.handle(m, time.Now()); reply != nil {
				// Always broadcast: the client may not have an address yet, and a broadcast
				// reply is accepted by clients that do.
				send.WriteTo(reply, bcast)
			}
		}
	}
	g.done.Add(2)
	go serve(recv)
	go serve(send)
	return nil
}

func (g *Gateway) startDHCPRelay(ctx context.Context, recv, send *gonet.UDPConn) error {
	upstream := net.UDPAddrFromAddrPort(g.cfg.DHCPRelay4)
	broadcast := &net.UDPAddr{IP: net.IPv4bcast.To4(), Port: 68}
	type relayState struct {
		circuitID string
		expires   time.Time
	}
	var pendingMu sync.Mutex
	pending := make(map[dhcpv4RelayKey]relayState)
	g.done.Add(2)
	go func() {
		defer g.done.Done()
		defer recv.Close()
		go func() { <-ctx.Done(); recv.Close() }()
		buf := make([]byte, 4096)
		for {
			n, _, err := recv.ReadFrom(buf)
			if err != nil {
				return
			}
			message, ok := parseDHCP(buf[:n])
			if !ok || message.msgType == dhcpOffer || message.msgType == dhcpAck || message.msgType == dhcpNak {
				continue
			}
			identity := g.dhcp.ingressFor(message.chaddr)
			if identity == "" {
				identity = "l2gw"
			}
			forward, ok := makeDHCPv4RelayForward(buf[:n], g.cfg.Address.Addr(), identity)
			if !ok {
				continue
			}
			key := dhcpv4RelayKey{xid: message.xid, chaddr: message.chaddr}
			pendingMu.Lock()
			now := time.Now()
			for current, state := range pending {
				if !now.Before(state.expires) {
					delete(pending, current)
				}
			}
			if len(pending) >= 4096 && pending[key].expires.IsZero() {
				pendingMu.Unlock()
				continue
			}
			pending[key] = relayState{circuitID: identity, expires: now.Add(2 * time.Minute)}
			pendingMu.Unlock()
			if _, err := send.WriteTo(forward, upstream); err != nil {
				pendingMu.Lock()
				delete(pending, key)
				pendingMu.Unlock()
				if ctx.Err() != nil {
					return
				}
			}
		}
	}()
	go func() {
		defer g.done.Done()
		defer send.Close()
		go func() { <-ctx.Done(); send.Close() }()
		buf := make([]byte, 4096)
		for {
			n, peerAddr, err := send.ReadFrom(buf)
			if err != nil {
				return
			}
			peer, ok := peerAddr.(*net.UDPAddr)
			if !ok || peer.Port != int(g.cfg.DHCPRelay4.Port()) || !peer.IP.Equal(net.IP(g.cfg.DHCPRelay4.Addr().AsSlice())) {
				continue
			}
			key, ok := dhcpv4RelayReplyKey(buf[:n], g.cfg.Address.Addr())
			if !ok {
				continue
			}
			pendingMu.Lock()
			state, exists := pending[key]
			if exists && !time.Now().Before(state.expires) {
				delete(pending, key)
				exists = false
			}
			pendingMu.Unlock()
			if !exists {
				continue
			}
			reply, ok := parseDHCPv4RelayReply(buf[:n], g.cfg.Address.Addr(), state.circuitID)
			if !ok {
				continue
			}
			if _, err := send.WriteTo(reply, broadcast); err != nil && ctx.Err() != nil {
				return
			}
		}
	}()
	return nil
}

func makeDHCPv4RelayForward(payload []byte, giaddr netip.Addr, circuitID string) ([]byte, bool) {
	if len(payload) < dhcpFixedSize+4 || !giaddr.Is4() || giaddr.IsUnspecified() || len(circuitID) == 0 || len(circuitID) > 128 {
		return nil, false
	}
	message, ok := parseDHCP(payload)
	if !ok || message.msgType < dhcpDiscover || message.msgType > dhcpInform || payload[3] >= 16 || payload[24] != 0 || payload[25] != 0 || payload[26] != 0 || payload[27] != 0 {
		return nil, false
	}
	end, ok := dhcpOptionEnd(payload)
	if !ok {
		return nil, false
	}
	for off := dhcpFixedSize + 4; off < end; {
		code := payload[off]
		if code == 0 {
			off++
			continue
		}
		if code == 82 {
			return nil, false // never trust a client-supplied relay-agent identity
		}
		off += 2 + int(payload[off+1])
	}
	value := make([]byte, 2+len(circuitID))
	value[0], value[1] = 1, byte(len(circuitID)) // Circuit-ID suboption.
	copy(value[2:], circuitID)
	out := make([]byte, 0, end+2+len(value))
	out = append(out, payload[:end]...)
	out = append(out, 82, byte(len(value)))
	out = append(out, value...)
	out = append(out, 255)
	out[3]++
	copy(out[24:28], giaddr.AsSlice())
	return out, true
}

type dhcpv4RelayKey struct {
	xid    uint32
	chaddr [6]byte
}

func dhcpv4RelayReplyKey(payload []byte, giaddr netip.Addr) (dhcpv4RelayKey, bool) {
	var key dhcpv4RelayKey
	if len(payload) < dhcpFixedSize+4 || payload[0] != 2 || payload[1] != 1 || payload[2] != 6 || binary.BigEndian.Uint32(payload[dhcpFixedSize:]) != dhcpMagic || !giaddr.Is4() || !bytes.Equal(payload[24:28], giaddr.AsSlice()) {
		return key, false
	}
	copy(key.chaddr[:], payload[28:34])
	if key.chaddr == [6]byte{} || key.chaddr[0]&1 != 0 {
		return dhcpv4RelayKey{}, false
	}
	key.xid = binary.BigEndian.Uint32(payload[4:8])
	return key, true
}

func parseDHCPv4RelayReply(payload []byte, giaddr netip.Addr, circuitID string) ([]byte, bool) {
	if _, ok := dhcpv4RelayReplyKey(payload, giaddr); !ok || circuitID == "" {
		return nil, false
	}
	end, ok := dhcpOptionEnd(payload)
	if !ok {
		return nil, false
	}
	var found bool
	var optionType byte
	out := append([]byte(nil), payload[:dhcpFixedSize+4]...)
	for off := dhcpFixedSize + 4; off < end; {
		code := payload[off]
		if code == 0 {
			out = append(out, 0)
			off++
			continue
		}
		n := int(payload[off+1])
		value := payload[off+2 : off+2+n]
		if code == 53 && n == 1 {
			optionType = value[0]
		}
		if code == 82 {
			if found || !dhcpRelayCircuitIDMatches(value, circuitID) {
				return nil, false
			}
			found = true
		} else {
			out = append(out, code, byte(n))
			out = append(out, value...)
		}
		off += 2 + n
	}
	if !found || (optionType != dhcpOffer && optionType != dhcpAck && optionType != dhcpNak) {
		return nil, false
	}
	out = append(out, 255)
	out[3] = 0
	clear(out[24:28]) // Relay-agent hop address is not forwarded to the client.
	return out, true
}

func dhcpRelayCircuitIDMatches(option []byte, circuitID string) bool {
	var found bool
	for off := 0; off < len(option); {
		if len(option)-off < 2 {
			return false
		}
		code, n := option[off], int(option[off+1])
		off += 2
		if n > len(option)-off {
			return false
		}
		if code == 1 {
			if found || string(option[off:off+n]) != circuitID {
				return false
			}
			found = true
		}
		off += n
	}
	return found
}

func dhcpOptionEnd(payload []byte) (int, bool) {
	if len(payload) < dhcpFixedSize+4 || binary.BigEndian.Uint32(payload[dhcpFixedSize:]) != dhcpMagic {
		return 0, false
	}
	for off := dhcpFixedSize + 4; off < len(payload); {
		code := payload[off]
		if code == 0 {
			off++
			continue
		}
		if code == 255 {
			return off, true
		}
		if len(payload)-off < 2 || int(payload[off+1]) > len(payload)-off-2 {
			return 0, false
		}
		off += 2 + int(payload[off+1])
	}
	return 0, false
}

func validDHCPRelayGateway(prefix netip.Prefix, gateway netip.Addr) bool {
	if !prefix.IsValid() || !prefix.Addr().Is4() || !gateway.Is4() || gateway.IsUnspecified() || gateway.IsMulticast() || !prefix.Contains(gateway) || gateway == prefix.Addr() {
		return false
	}
	network := prefix.Masked().Addr().As4()
	broadcast := network
	mask := net.CIDRMask(prefix.Bits(), 32)
	for i := range broadcast {
		broadcast[i] |= ^mask[i]
	}
	return gateway.As4() != network && gateway.As4() != broadcast
}

// setHosts replaces the fixed leases. A held lease that now conflicts with a fixed address is dropped,
// so the device that owned it re-requests and is told to use the right one.
func (d *dhcpServer) setHosts(hosts []Host) error {
	pfx, gw := d.cfg.Address, d.cfg.Address.Addr()
	broadcast := pfx.Masked().Addr().As4()
	mask := net.CIDRMask(pfx.Bits(), 32)
	for i := range broadcast {
		broadcast[i] |= ^mask[i]
	}
	broadcastIP := netip.AddrFrom4(broadcast)
	static := map[[6]byte]netip.Addr{}
	staticI := map[netip.Addr]bool{}
	for _, h := range hosts {
		if len(h.MAC) != 6 || h.MAC[0]&1 != 0 || !pfx.Contains(h.IP) || h.IP == gw || h.IP == pfx.Masked().Addr() || h.IP == broadcastIP {
			return errors.New("l2gw: fixed host outside the subnet")
		}
		var m [6]byte
		copy(m[:], h.MAC)
		if previous, exists := static[m]; exists && previous != h.IP {
			return errors.New("l2gw: one fixed host has multiple addresses")
		}
		if staticI[h.IP] {
			return errors.New("l2gw: two fixed hosts share an address")
		}
		static[m] = h.IP
		staticI[h.IP] = true
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.static, d.staticI = static, staticI
	for mac, l := range d.byMAC {
		if fixed, ok := static[mac]; ok && fixed != l.ip {
			delete(d.byIP, l.ip)
			delete(d.byMAC, mac)
		} else if _, isFixed := static[mac]; !isFixed && staticI[l.ip] {
			delete(d.byIP, l.ip)
			delete(d.byMAC, mac)
		}
	}
	return nil
}

// macFor says which device holds ip: a live lease, or a fixed host.
func (d *dhcpServer) macFor(ip netip.Addr) ([6]byte, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if l, ok := d.byIP[ip]; ok && time.Now().Before(l.expires) {
		return l.mac, true
	}
	for mac, a := range d.static {
		if a == ip {
			return mac, true
		}
	}
	return [6]byte{}, false
}

// ipFor is the address a device holds.
func (d *dhcpServer) ipFor(mac [6]byte) (netip.Addr, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if l, ok := d.byMAC[mac]; ok && time.Now().Before(l.expires) {
		return l.ip, true
	}
	a, ok := d.static[mac]
	return a, ok
}
