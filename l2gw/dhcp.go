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
	banned  map[netip.Addr]time.Time // declined addresses
	count   dhcpCounters
}

func (d *dhcpServer) init(cfg *Config) error {
	d.cfg = cfg
	pfx := cfg.Address
	gw := pfx.Addr()
	if !cfg.DHCPStart.IsValid() || !cfg.DHCPEnd.IsValid() {
		return errors.New("l2gw: DHCP range required")
	}
	if !pfx.Contains(cfg.DHCPStart) || !pfx.Contains(cfg.DHCPEnd) || cfg.DHCPEnd.Less(cfg.DHCPStart) ||
		(cfg.DHCPStart.Compare(gw) <= 0 && gw.Compare(cfg.DHCPEnd) <= 0) {
		return errors.New("l2gw: DHCP range must lie inside the subnet and not include the gateway")
	}
	d.byMAC = map[[6]byte]*lease{}
	d.byIP = map[netip.Addr]*lease{}
	d.static = map[[6]byte]netip.Addr{}
	d.staticI = map[netip.Addr]bool{}
	d.banned = map[netip.Addr]time.Time{}
	for _, h := range cfg.Hosts {
		if len(h.MAC) != 6 || !pfx.Contains(h.IP) || h.IP == gw {
			return errors.New("l2gw: fixed host outside the subnet")
		}
		var m [6]byte
		copy(m[:], h.MAC)
		d.static[m] = h.IP
		d.staticI[h.IP] = true
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
	for len(opts) > 0 {
		code := opts[0]
		if code == 0 {
			opts = opts[1:]
			continue
		}
		if code == 255 || len(opts) < 2 || len(opts) < 2+int(opts[1]) {
			break
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
	return m, m.msgType != 0
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

// startDHCP binds UDP port 67 on the stack and serves until ctx ends.
func (g *Gateway) startDHCP(ctx context.Context) error {
	var wq waiter.Queue
	ep, err := g.stack.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if err != nil {
		return errors.New("l2gw: dhcp endpoint: " + err.String())
	}
	ep.SocketOptions().SetBroadcast(true)
	if err := ep.Bind(tcpip.FullAddress{Port: 67}); err != nil {
		return errors.New("l2gw: dhcp bind: " + err.String())
	}
	conn := gonet.NewUDPConn(&wq, ep)
	g.done.Add(1)
	go func() {
		defer g.done.Done()
		defer conn.Close()
		go func() { <-ctx.Done(); conn.Close() }()
		buf := make([]byte, 2048)
		bcast := &net.UDPAddr{IP: net.IPv4bcast.To4(), Port: 68}
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
				conn.WriteTo(reply, bcast)
			}
		}
	}()
	return nil
}
