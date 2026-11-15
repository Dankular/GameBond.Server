package l2gw

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const (
	dhcpv6Solicit   = 1
	dhcpv6Advertise = 2
	dhcpv6Request   = 3
	dhcpv6Confirm   = 4
	dhcpv6Renew     = 5
	dhcpv6Rebind    = 6
	dhcpv6Reply     = 7
	dhcpv6Release   = 8
	dhcpv6Decline   = 9

	dhcpv6OptClientID = 1
	dhcpv6OptServerID = 2
	dhcpv6OptIANA     = 3
	dhcpv6OptIAAddr   = 5
	dhcpv6OptIAPD     = 25
	dhcpv6OptIAPrefix = 26
	dhcpv6OptDNS      = 23
	dhcpv6OptStatus   = 13
	dhcpv6OptRapid    = 14
	dhcpv6OptORO      = 6
	dhcpv6Success     = 0
	dhcpv6NoAddrs     = 2
	dhcpv6NoBinding   = 3
	dhcpv6NotOnLink   = 4
)

// dhcpv6Request is the validated IA_NA subset used by the stateful server.
type dhcpv6Message struct {
	typ          byte
	xid          [3]byte
	clientID     []byte
	serverID     []byte
	iaid         uint32
	requestedIP  netip.Addr
	hasIANA      bool
	rapidCommit  bool
	requestedDNS bool
	hasIAPD      bool
	pdIAID       uint32
	requestedPD  netip.Prefix
}

type dhcpv6Lease struct {
	ip      netip.Addr
	expires time.Time
	offered bool
	mac     [6]byte
	ingress string
}

type dhcpv6PDLease struct {
	prefix  netip.Prefix
	expires time.Time
	offered bool
	mac     [6]byte
	ingress string
	nextHop netip.Addr
}

// DHCPv6Host pins a lease to the raw Client Identifier option payload and IAID.
type DHCPv6Host struct {
	ClientID []byte
	IAID     uint32
	MAC      net.HardwareAddr
	IP       netip.Addr
}

// dhcpv6Server handles stateful DHCPv6 IA_NA leases inside one configured
// gateway prefix. Identity is recorded from the authenticated frame ingress.
type dhcpv6Server struct {
	mu          sync.Mutex
	prefix      netip.Prefix
	gateway     netip.Addr
	serverID    []byte
	dns         []netip.Addr
	leaseTime   time.Duration
	byClient    map[string]*dhcpv6Lease
	byIP        map[netip.Addr]string
	reserved    map[string]netip.Addr
	reservedIP  map[netip.Addr]string
	reservedMAC map[string][6]byte
	pdPool      netip.Prefix
	pdBits      uint8
	pdByClient  map[string]*dhcpv6PDLease
	pdByPrefix  map[netip.Prefix]string
}

func (d *dhcpv6Server) bindings() []DHCPBinding {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	out := make([]DHCPBinding, 0, len(d.byClient))
	for _, lease := range d.byClient {
		if lease.offered || !now.Before(lease.expires) {
			continue
		}
		out = append(out, DHCPBinding{MAC: net.HardwareAddr(lease.mac[:]).String(), IP: lease.ip, SessionPort: lease.ingress, Expires: lease.expires})
	}
	return out
}

func newDHCPv6Server(prefix netip.Prefix, gatewayMAC net.HardwareAddr, dns []netip.Addr, leaseTime time.Duration, hosts ...DHCPv6Host) (*dhcpv6Server, error) {
	if !prefix.IsValid() || !prefix.Addr().Is6() || prefix.Addr().Is4In6() || prefix.Bits() < 48 || prefix.Bits() > 120 {
		return nil, errors.New("l2gw: DHCPv6 requires a native IPv6 prefix between /48 and /120")
	}
	if len(gatewayMAC) != 6 || gatewayMAC[0]&1 != 0 {
		return nil, errors.New("l2gw: DHCPv6 server requires a six-byte unicast gateway MAC")
	}
	if leaseTime <= 0 {
		leaseTime = 12 * time.Hour
	}
	for _, addr := range dns {
		if !addr.Is6() || addr.Is4In6() || addr.IsUnspecified() || addr.IsMulticast() {
			return nil, errors.New("l2gw: DHCPv6 DNS address must be native IPv6 unicast")
		}
	}
	duid := []byte{0, 3, 0, 1}
	duid = append(duid, gatewayMAC...)
	d := &dhcpv6Server{prefix: prefix.Masked(), gateway: prefix.Addr(), serverID: duid, dns: slices.Clone(dns), leaseTime: leaseTime,
		byClient: make(map[string]*dhcpv6Lease), byIP: make(map[netip.Addr]string), reserved: make(map[string]netip.Addr), reservedIP: make(map[netip.Addr]string), reservedMAC: make(map[string][6]byte), pdByClient: make(map[string]*dhcpv6PDLease), pdByPrefix: make(map[netip.Prefix]string)}
	for _, host := range hosts {
		if len(host.ClientID) < 2 || len(host.ClientID) > 128 || len(host.MAC) != 6 || host.MAC[0]&1 != 0 || !host.IP.Is6() || host.IP.Is4In6() || !d.prefix.Contains(host.IP) || host.IP == d.gateway || host.IP.IsUnspecified() || host.IP.IsMulticast() {
			return nil, errors.New("l2gw: invalid DHCPv6 static reservation")
		}
		key := string(host.ClientID) + fmt.Sprintf("/%08x", host.IAID)
		if _, exists := d.reserved[key]; exists {
			return nil, errors.New("l2gw: duplicate DHCPv6 client DUID and IAID reservation")
		}
		if _, exists := d.reservedIP[host.IP]; exists {
			return nil, errors.New("l2gw: duplicate DHCPv6 reserved address")
		}
		var mac [6]byte
		copy(mac[:], host.MAC)
		d.reserved[key], d.reservedIP[host.IP], d.reservedMAC[key] = host.IP, key, mac
	}
	return d, nil
}

// ConfigurePrefixDelegation enables IA_PD from a delegated-prefix pool. Pool
// must be larger than each delegation; delegatedBits is the resulting prefix
// length (for example /60 delegations from a /48 pool).
func (d *dhcpv6Server) ConfigurePrefixDelegation(pool netip.Prefix, delegatedBits uint8) error {
	if d == nil || !pool.IsValid() || !pool.Addr().Is6() || pool.Addr().Is4In6() || pool != pool.Masked() || int(delegatedBits) < pool.Bits() || delegatedBits > 120 {
		return errors.New("l2gw: invalid DHCPv6 prefix delegation pool")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pdPool, d.pdBits = pool, delegatedBits
	d.pdByClient, d.pdByPrefix = make(map[string]*dhcpv6PDLease), make(map[netip.Prefix]string)
	return nil
}

func parseDHCPv6(p []byte) (dhcpv6Message, bool) {
	var req dhcpv6Message
	if len(p) < 4 {
		return req, false
	}
	req.typ = p[0]
	copy(req.xid[:], p[1:4])
	if req.typ < dhcpv6Solicit || req.typ > dhcpv6Decline {
		return req, false
	}
	seen := map[uint16]bool{}
	for off := 4; off < len(p); {
		if len(p)-off < 4 {
			return req, false
		}
		code, n := binary.BigEndian.Uint16(p[off:off+2]), int(binary.BigEndian.Uint16(p[off+2:off+4]))
		off += 4
		if n > len(p)-off || seen[code] {
			return req, false
		}
		seen[code] = true
		value := p[off : off+n]
		off += n
		switch code {
		case dhcpv6OptClientID:
			if n < 2 {
				return req, false
			}
			req.clientID = slices.Clone(value)
		case dhcpv6OptServerID:
			if n < 2 {
				return req, false
			}
			req.serverID = slices.Clone(value)
		case dhcpv6OptIANA:
			if n < 12 {
				return req, false
			}
			req.hasIANA = true
			req.iaid = binary.BigEndian.Uint32(value[:4])
			for inner := 12; inner < len(value); {
				if len(value)-inner < 4 {
					return req, false
				}
				innerCode, innerLen := binary.BigEndian.Uint16(value[inner:inner+2]), int(binary.BigEndian.Uint16(value[inner+2:inner+4]))
				inner += 4
				if innerLen > len(value)-inner {
					return req, false
				}
				if innerCode == dhcpv6OptIAAddr {
					if innerLen < 24 || req.requestedIP.IsValid() {
						return req, false
					}
					var raw [16]byte
					copy(raw[:], value[inner:inner+16])
					req.requestedIP = netip.AddrFrom16(raw)
				}
				inner += innerLen
			}
		case dhcpv6OptIAPD:
			if n < 12 || req.hasIAPD {
				return req, false
			}
			req.hasIAPD = true
			req.pdIAID = binary.BigEndian.Uint32(value[:4])
			for inner := 12; inner < len(value); {
				if len(value)-inner < 4 {
					return req, false
				}
				code := binary.BigEndian.Uint16(value[inner : inner+2])
				innerLen := int(binary.BigEndian.Uint16(value[inner+2 : inner+4]))
				inner += 4
				if innerLen > len(value)-inner {
					return req, false
				}
				if code == dhcpv6OptIAPrefix {
					if innerLen < 25 || req.requestedPD.IsValid() {
						return req, false
					}
					bits := int(value[inner+8])
					var raw [16]byte
					copy(raw[:], value[inner+9:inner+25])
					req.requestedPD = netip.PrefixFrom(netip.AddrFrom16(raw), bits)
					if !req.requestedPD.IsValid() || req.requestedPD != req.requestedPD.Masked() {
						return req, false
					}
				}
				inner += innerLen
			}
		case dhcpv6OptRapid:
			if n != 0 {
				return req, false
			}
			req.rapidCommit = true
		case dhcpv6OptORO:
			if n%2 != 0 {
				return req, false
			}
			for i := 0; i < n; i += 2 {
				if binary.BigEndian.Uint16(value[i:i+2]) == dhcpv6OptDNS {
					req.requestedDNS = true
				}
			}
		}
	}
	if len(req.clientID) == 0 {
		return req, false
	}
	if req.typ == dhcpv6Solicit {
		return req, req.hasIANA || req.hasIAPD
	}
	return req, req.hasIANA || req.hasIAPD
}

// handle processes one validated message and returns a DHCPv6 response payload.
// The caller supplies the Ethernet source and authenticated ingress identity.
func (d *dhcpv6Server) handle(payload []byte, mac [6]byte, ingress string, now time.Time) []byte {
	return d.handleFrom(payload, mac, ingress, netip.Addr{}, now)
}

// handleFrom records the client link-local source used to reach an IA_PD router.
// The source is empty for direct unit callers that only exercise lease allocation.
func (d *dhcpv6Server) handleFrom(payload []byte, mac [6]byte, ingress string, source netip.Addr, now time.Time) []byte {
	if d == nil {
		return nil
	}
	req, ok := parseDHCPv6(payload)
	if !ok || (len(req.serverID) != 0 && !bytes.Equal(req.serverID, d.serverID)) {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.expire(now)
	if req.hasIAPD && !req.hasIANA {
		return d.handlePD(req, mac, ingress, source, now)
	}
	var pdOption []byte
	if req.hasIAPD {
		pdReply := d.handlePD(req, mac, ingress, source, now)
		pdOption = dhcpv6OptionValue(pdReply, dhcpv6OptIAPD)
	}
	respond := func(typ byte, lease *dhcpv6Lease, status uint16) []byte {
		out := d.reply(req, typ, lease, status)
		if len(pdOption) != 0 {
			appendDHCPv6Option(&out, dhcpv6OptIAPD, pdOption)
		}
		return out
	}
	if (req.typ == dhcpv6Request || req.typ == dhcpv6Renew || req.typ == dhcpv6Release || req.typ == dhcpv6Decline) && len(req.serverID) == 0 {
		return nil
	}
	key := string(req.clientID) + fmt.Sprintf("/%08x", req.iaid)
	if reservedMAC, reserved := d.reservedMAC[key]; reserved && reservedMAC != mac {
		return respond(dhcpv6Reply, nil, dhcpv6NoBinding)
	}
	if current := d.byClient[key]; current != nil && (current.mac != mac || current.ingress != ingress) && req.typ != dhcpv6Confirm {
		return respond(dhcpv6Reply, nil, dhcpv6NoBinding)
	}
	if req.typ == dhcpv6Confirm {
		status := uint16(dhcpv6Success)
		if req.requestedIP.IsValid() && !d.prefix.Contains(req.requestedIP) {
			status = dhcpv6NotOnLink
		}
		return respond(dhcpv6Reply, nil, status)
	}
	if req.typ == dhcpv6Release || req.typ == dhcpv6Decline {
		if lease := d.byClient[key]; lease != nil {
			if d.byIP[lease.ip] == key {
				delete(d.byIP, lease.ip)
			}
			delete(d.byClient, key)
		}
		return respond(dhcpv6Reply, nil, dhcpv6Success)
	}
	if req.typ != dhcpv6Solicit && req.typ != dhcpv6Request && req.typ != dhcpv6Renew && req.typ != dhcpv6Rebind {
		return nil
	}
	if req.typ == dhcpv6Solicit && !req.rapidCommit {
		ip, found := d.allocate(key, req.requestedIP, now)
		if !found {
			return respond(dhcpv6Advertise, nil, dhcpv6NoAddrs)
		}
		lease := d.hold(key, ip, mac, ingress, now.Add(60*time.Second), true)
		return respond(dhcpv6Advertise, lease, dhcpv6Success)
	}
	if req.typ == dhcpv6Renew || req.typ == dhcpv6Rebind {
		if current := d.byClient[key]; current == nil || !now.Before(current.expires) {
			return respond(dhcpv6Reply, nil, dhcpv6NoBinding)
		}
	}
	want := req.requestedIP
	if current := d.byClient[key]; current != nil && !want.IsValid() {
		want = current.ip
	}
	ip, found := d.allocate(key, want, now)
	if !found {
		return respond(dhcpv6Reply, nil, dhcpv6NoAddrs)
	}
	lease := d.hold(key, ip, mac, ingress, now.Add(d.leaseTime), false)
	typ := byte(dhcpv6Reply)
	if req.typ == dhcpv6Solicit && !req.rapidCommit {
		typ = dhcpv6Advertise
		lease.offered = true
		lease.expires = now.Add(60 * time.Second)
	}
	return respond(typ, lease, dhcpv6Success)
}

func appendDHCPv6Option(out *[]byte, code uint16, value []byte) {
	var h [4]byte
	binary.BigEndian.PutUint16(h[:2], code)
	binary.BigEndian.PutUint16(h[2:], uint16(len(value)))
	*out = append(*out, h[:]...)
	*out = append(*out, value...)
}

func dhcpv6OptionValue(payload []byte, wanted uint16) []byte {
	if len(payload) < 4 {
		return nil
	}
	for off := 4; off+4 <= len(payload); {
		code, n := binary.BigEndian.Uint16(payload[off:off+2]), int(binary.BigEndian.Uint16(payload[off+2:off+4]))
		off += 4
		if n > len(payload)-off {
			return nil
		}
		if code == wanted {
			return slices.Clone(payload[off : off+n])
		}
		off += n
	}
	return nil
}

func (d *dhcpv6Server) handlePD(req dhcpv6Message, mac [6]byte, ingress string, source netip.Addr, now time.Time) []byte {
	if (req.typ == dhcpv6Request || req.typ == dhcpv6Renew || req.typ == dhcpv6Release || req.typ == dhcpv6Decline) && len(req.serverID) == 0 {
		return nil
	}
	if !d.pdPool.IsValid() {
		return d.replyPD(req, dhcpv6Reply, nil, dhcpv6NoAddrs)
	}
	key := string(req.clientID) + fmt.Sprintf("/pd/%08x", req.pdIAID)
	current := d.pdByClient[key]
	if current != nil && (current.mac != mac || current.ingress != ingress) && req.typ != dhcpv6Confirm {
		return d.replyPD(req, dhcpv6Reply, nil, dhcpv6NoBinding)
	}
	if req.typ == dhcpv6Release || req.typ == dhcpv6Decline {
		if current != nil {
			delete(d.pdByPrefix, current.prefix)
			delete(d.pdByClient, key)
		}
		return d.replyPD(req, dhcpv6Reply, nil, dhcpv6Success)
	}
	if req.typ == dhcpv6Renew || req.typ == dhcpv6Rebind {
		if current == nil || !now.Before(current.expires) {
			return d.replyPD(req, dhcpv6Reply, nil, dhcpv6NoBinding)
		}
	}
	if req.typ != dhcpv6Solicit && req.typ != dhcpv6Request && req.typ != dhcpv6Renew && req.typ != dhcpv6Rebind {
		return nil
	}
	want := req.requestedPD
	if current != nil && !want.IsValid() {
		want = current.prefix
	}
	delegated, ok := d.allocatePD(key, want)
	if !ok {
		typ := byte(dhcpv6Reply)
		if req.typ == dhcpv6Solicit && !req.rapidCommit {
			typ = dhcpv6Advertise
		}
		return d.replyPD(req, typ, nil, dhcpv6NoAddrs)
	}
	typ, lifetime, offered := byte(dhcpv6Reply), d.leaseTime, false
	if req.typ == dhcpv6Solicit && !req.rapidCommit {
		typ, lifetime, offered = dhcpv6Advertise, 60*time.Second, true
	}
	lease := &dhcpv6PDLease{prefix: delegated, expires: now.Add(lifetime), offered: offered, mac: mac, ingress: ingress, nextHop: source}
	if current != nil && current.prefix != delegated {
		delete(d.pdByPrefix, current.prefix)
	}
	d.pdByClient[key], d.pdByPrefix[delegated] = lease, key
	return d.replyPD(req, typ, lease, dhcpv6Success)
}

// activePDLeases returns committed, unexpired delegations with a usable router
// next hop. Offers are intentionally excluded until the client Requests them.
func (d *dhcpv6Server) activePDLeases(now time.Time) []dhcpv6PDLease {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.expire(now)
	out := make([]dhcpv6PDLease, 0, len(d.pdByClient))
	for _, lease := range d.pdByClient {
		if lease.offered || !now.Before(lease.expires) || !lease.nextHop.Is6() || !lease.nextHop.IsLinkLocalUnicast() {
			continue
		}
		out = append(out, *lease)
	}
	return out
}

func (d *dhcpv6Server) allocatePD(key string, want netip.Prefix) (netip.Prefix, bool) {
	valid := func(p netip.Prefix) bool {
		if !p.IsValid() || p.Bits() != int(d.pdBits) || p != p.Masked() || !d.pdPool.Contains(p.Addr()) {
			return false
		}
		last := p.Addr().As16()
		poolLast := d.pdPool.Addr().As16()
		for bit := 0; bit < d.pdPool.Bits(); bit++ {
			mask := byte(1 << (7 - bit%8))
			if last[bit/8]&mask != poolLast[bit/8]&mask {
				return false
			}
		}
		owner := d.pdByPrefix[p]
		return owner == "" || owner == key
	}
	if want.IsValid() {
		return want, valid(want)
	}
	if current := d.pdByClient[key]; current != nil && valid(current.prefix) {
		return current.prefix, true
	}
	addr := d.pdPool.Addr().As16()
	for tries := 0; tries <= len(d.pdByPrefix); tries++ {
		p := netip.PrefixFrom(netip.AddrFrom16(addr), int(d.pdBits))
		if valid(p) {
			return p, true
		}
		if !incrementPDIndex(&addr, d.pdPool.Bits(), int(d.pdBits)) {
			break
		}
	}
	return netip.Prefix{}, false
}

func incrementPDIndex(addr *[16]byte, firstBit, lastBit int) bool {
	for bit := lastBit - 1; bit >= firstBit; bit-- {
		mask := byte(1 << (7 - bit%8))
		if addr[bit/8]&mask == 0 {
			addr[bit/8] |= mask
			return true
		}
		addr[bit/8] &^= mask
	}
	return false
}

func (d *dhcpv6Server) replyPD(req dhcpv6Message, typ byte, lease *dhcpv6PDLease, status uint16) []byte {
	out := []byte{typ, req.xid[0], req.xid[1], req.xid[2]}
	appendOption := func(code uint16, value []byte) {
		var h [4]byte
		binary.BigEndian.PutUint16(h[:2], code)
		binary.BigEndian.PutUint16(h[2:], uint16(len(value)))
		out = append(out, h[:]...)
		out = append(out, value...)
	}
	appendOption(dhcpv6OptServerID, d.serverID)
	appendOption(dhcpv6OptClientID, req.clientID)
	ia := make([]byte, 12)
	binary.BigEndian.PutUint32(ia[:4], req.pdIAID)
	if lease != nil {
		value := make([]byte, 25)
		seconds := uint32(d.leaseTime / time.Second)
		if lease.offered {
			seconds = 60
		}
		binary.BigEndian.PutUint32(value[:4], seconds)
		binary.BigEndian.PutUint32(value[4:8], seconds)
		value[8] = byte(lease.prefix.Bits())
		addr := lease.prefix.Addr().As16()
		copy(value[9:25], addr[:])
		var h [4]byte
		binary.BigEndian.PutUint16(h[:2], dhcpv6OptIAPrefix)
		binary.BigEndian.PutUint16(h[2:], uint16(len(value)))
		ia = append(ia, h[:]...)
		ia = append(ia, value...)
	}
	if status != dhcpv6Success {
		value := make([]byte, 2)
		binary.BigEndian.PutUint16(value, status)
		var h [4]byte
		binary.BigEndian.PutUint16(h[:2], dhcpv6OptStatus)
		binary.BigEndian.PutUint16(h[2:], uint16(len(value)))
		ia = append(ia, h[:]...)
		ia = append(ia, value...)
	}
	appendOption(dhcpv6OptIAPD, ia)
	if req.rapidCommit && typ == dhcpv6Reply {
		appendOption(dhcpv6OptRapid, nil)
	}
	return out
}

func (d *dhcpv6Server) allocate(key string, want netip.Addr, now time.Time) (netip.Addr, bool) {
	free := func(ip netip.Addr) bool {
		if !ip.IsValid() || !d.prefix.Contains(ip) || ip == d.gateway || ip.IsUnspecified() || ip.IsMulticast() {
			return false
		}
		if reservation, exists := d.reservedIP[ip]; exists && reservation != key {
			return false
		}
		owner, exists := d.byIP[ip]
		if exists && owner != key {
			lease := d.byClient[owner]
			return lease == nil || !now.Before(lease.expires)
		}
		return true
	}
	if reserved, exists := d.reserved[key]; exists {
		if want.IsValid() && want != reserved {
			return netip.Addr{}, false
		}
		return reserved, free(reserved)
	}
	if want.IsValid() {
		return want, free(want)
	}
	if existing := d.byClient[key]; existing != nil && now.Before(existing.expires) {
		return existing.ip, true
	}
	ip := d.prefix.Masked().Addr().Next()
	for i := 0; i < 65536 && d.prefix.Contains(ip); i++ {
		if free(ip) {
			return ip, true
		}
		ip = ip.Next()
	}
	return netip.Addr{}, false
}

func (d *dhcpv6Server) expire(now time.Time) {
	for key, lease := range d.byClient {
		if now.Before(lease.expires) {
			continue
		}
		if d.byIP[lease.ip] == key {
			delete(d.byIP, lease.ip)
		}
		delete(d.byClient, key)
	}
	for key, lease := range d.pdByClient {
		if now.Before(lease.expires) {
			continue
		}
		if d.pdByPrefix[lease.prefix] == key {
			delete(d.pdByPrefix, lease.prefix)
		}
		delete(d.pdByClient, key)
	}
}

func (d *dhcpv6Server) hold(key string, ip netip.Addr, mac [6]byte, ingress string, expires time.Time, offered bool) *dhcpv6Lease {
	if old := d.byClient[key]; old != nil && old.ip != ip {
		if d.byIP[old.ip] == key {
			delete(d.byIP, old.ip)
		}
	}
	lease := &dhcpv6Lease{ip: ip, mac: mac, ingress: ingress, expires: expires, offered: offered}
	d.byClient[key] = lease
	d.byIP[ip] = key
	return lease
}

func (d *dhcpv6Server) reply(req dhcpv6Message, typ byte, lease *dhcpv6Lease, status uint16) []byte {
	out := []byte{typ, req.xid[0], req.xid[1], req.xid[2]}
	appendOption := func(code uint16, value []byte) {
		var h [4]byte
		binary.BigEndian.PutUint16(h[:2], code)
		binary.BigEndian.PutUint16(h[2:], uint16(len(value)))
		out = append(out, h[:]...)
		out = append(out, value...)
	}
	appendOption(dhcpv6OptServerID, d.serverID)
	appendOption(dhcpv6OptClientID, req.clientID)
	ia := make([]byte, 12)
	binary.BigEndian.PutUint32(ia[:4], req.iaid)
	if lease != nil {
		addr := lease.ip.As16()
		iaAddr := make([]byte, 24)
		copy(iaAddr[:16], addr[:])
		seconds := uint32(d.leaseTime / time.Second)
		if lease.offered {
			seconds = 60
		}
		binary.BigEndian.PutUint32(iaAddr[16:20], seconds)
		binary.BigEndian.PutUint32(iaAddr[20:24], seconds)
		var hdr [4]byte
		binary.BigEndian.PutUint16(hdr[:2], dhcpv6OptIAAddr)
		binary.BigEndian.PutUint16(hdr[2:], uint16(len(iaAddr)))
		ia = append(ia, hdr[:]...)
		ia = append(ia, iaAddr...)
	}
	if status != dhcpv6Success {
		st := make([]byte, 2, 22)
		binary.BigEndian.PutUint16(st, status)
		st = append(st, []byte("address unavailable")...)
		var hdr [4]byte
		binary.BigEndian.PutUint16(hdr[:2], dhcpv6OptStatus)
		binary.BigEndian.PutUint16(hdr[2:], uint16(len(st)))
		ia = append(ia, hdr[:]...)
		ia = append(ia, st...)
	}
	appendOption(dhcpv6OptIANA, ia)
	if req.requestedDNS && len(d.dns) > 0 {
		dns := make([]byte, 0, 16*len(d.dns))
		for _, addr := range d.dns {
			bytes := addr.As16()
			dns = append(dns, bytes[:]...)
		}
		appendOption(dhcpv6OptDNS, dns)
	}
	if req.rapidCommit && typ == dhcpv6Reply {
		appendOption(dhcpv6OptRapid, nil)
	}
	return out
}

var dhcpv6AllServersAndRelays = netip.MustParseAddr("ff02::1:2")

const (
	dhcpv6RelayForward = 12
	dhcpv6RelayReply   = 13
	dhcpv6OptRelayMsg  = 9
)

// makeDHCPv6RelayForward wraps a client message in a single-hop relay-forward
// and adds a Circuit-ID option carrying the authenticated session identity.
func makeDHCPv6RelayForward(payload []byte, linkAddr, peerAddr netip.Addr, circuitID string) ([]byte, error) {
	if len(payload) < 4 || payload[0] == dhcpv6RelayForward || payload[0] == dhcpv6RelayReply || !linkAddr.Is6() || !peerAddr.Is6() || linkAddr.Is4In6() || peerAddr.Is4In6() || circuitID == "" || len(circuitID) > 255 {
		return nil, errors.New("l2gw: invalid DHCPv6 relay-forward input")
	}
	out := make([]byte, 34)
	out[0], out[1] = dhcpv6RelayForward, 0
	link, peer := linkAddr.As16(), peerAddr.As16()
	copy(out[2:18], link[:])
	copy(out[18:34], peer[:])
	appendOption := func(code uint16, value []byte) {
		var h [4]byte
		binary.BigEndian.PutUint16(h[:2], code)
		binary.BigEndian.PutUint16(h[2:], uint16(len(value)))
		out = append(out, h[:]...)
		out = append(out, value...)
	}
	appendOption(dhcpv6OptRelayMsg, payload)
	appendOption(18, []byte(circuitID)) // Interface-ID (RFC 8415)
	return out, nil
}

// parseDHCPv6RelayReply validates a Relay-reply and extracts its encapsulated
// client response, requiring the configured local relay address and peer.
func parseDHCPv6RelayReply(payload []byte, linkAddr, peerAddr netip.Addr, circuitID string) ([]byte, error) {
	if len(payload) < 34 || payload[0] != dhcpv6RelayReply || !linkAddr.Is6() || !peerAddr.Is6() || circuitID == "" {
		return nil, errors.New("l2gw: invalid DHCPv6 relay-reply")
	}
	link := netip.AddrFrom16([16]byte(payload[2:18]))
	peer := netip.AddrFrom16([16]byte(payload[18:34]))
	if link != linkAddr || peer != peerAddr {
		return nil, errors.New("l2gw: DHCPv6 relay-reply address mismatch")
	}
	var inner []byte
	gotCircuit := false
	for off := 34; off < len(payload); {
		if len(payload)-off < 4 {
			return nil, errors.New("l2gw: malformed DHCPv6 relay option")
		}
		code, n := binary.BigEndian.Uint16(payload[off:off+2]), int(binary.BigEndian.Uint16(payload[off+2:off+4]))
		off += 4
		if n > len(payload)-off {
			return nil, errors.New("l2gw: truncated DHCPv6 relay option")
		}
		switch code {
		case dhcpv6OptRelayMsg:
			if inner != nil {
				return nil, errors.New("l2gw: duplicate DHCPv6 Relay Message")
			}
			inner = payload[off : off+n]
		case 18:
			if gotCircuit || string(payload[off:off+n]) != circuitID {
				return nil, errors.New("l2gw: DHCPv6 relay Interface-ID mismatch")
			}
			gotCircuit = true
		}
		off += n
	}
	if !gotCircuit || len(inner) < 4 || inner[0] == dhcpv6RelayForward || inner[0] == dhcpv6RelayReply {
		return nil, errors.New("l2gw: incomplete DHCPv6 relay-reply")
	}
	return slices.Clone(inner), nil
}

// handleDHCPv6Frame validates direct client DHCPv6 frames and builds the
// Ethernet reply. Relay messages are handled by the relay helper API above.
func (d *dhcpv6Server) handleFrame(frame []byte, gatewayMAC net.HardwareAddr, serverLinkLocal netip.Addr, ingress string, now time.Time) ([]byte, bool) {
	if d == nil || len(frame) < header.EthernetMinimumSize+40+8 || len(gatewayMAC) != 6 || !serverLinkLocal.Is6() || !serverLinkLocal.IsLinkLocalUnicast() {
		return nil, false
	}
	offset := 14
	etherType := binary.BigEndian.Uint16(frame[12:14])
	for tags := 0; tags < 2 && (etherType == 0x8100 || etherType == 0x88a8 || etherType == 0x9100); tags++ {
		if len(frame) < offset+4 {
			return nil, false
		}
		etherType = binary.BigEndian.Uint16(frame[offset+2 : offset+4])
		offset += 4
	}
	if etherType != uint16(header.IPv6ProtocolNumber) || len(frame) < offset+48 {
		return nil, false
	}
	ip := frame[offset:]
	if ip[0]>>4 != 6 || ip[6] != 17 || ip[7] != 1 {
		return nil, false
	}
	ipLen := int(binary.BigEndian.Uint16(ip[4:6]))
	if ipLen < 8 || ipLen != len(ip)-40 {
		return nil, false
	}
	udp := ip[40 : 40+ipLen]
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLen < 8 || udpLen != len(udp) || binary.BigEndian.Uint16(udp[:2]) != 546 || binary.BigEndian.Uint16(udp[2:4]) != 547 || binary.BigEndian.Uint16(udp[6:8]) == 0 {
		return nil, false
	}
	source := netip.AddrFrom16([16]byte(ip[8:24]))
	destination := netip.AddrFrom16([16]byte(ip[24:40]))
	if !(destination == dhcpv6AllServersAndRelays || destination == d.gateway) ||
		(!source.IsUnspecified() && (source.IsMulticast() || (!source.IsLinkLocalUnicast() && !d.prefix.Contains(source)))) {
		return nil, false
	}
	if dhcpv6UDPChecksum(ip[8:24], ip[24:40], udp) != 0 {
		return nil, false
	}
	var mac [6]byte
	copy(mac[:], frame[6:12])
	if mac == [6]byte{} || mac[0]&1 != 0 {
		return nil, false
	}
	payload := udp[8:]
	if req, ok := parseDHCPv6(payload); ok && req.hasIAPD && !source.IsLinkLocalUnicast() {
		return nil, true
	}
	reply := d.handleFrom(payload, mac, ingress, source, now)
	if len(reply) == 0 {
		return nil, true
	}
	return buildDHCPv6Frame(frame[:offset], frame[6:12], gatewayMAC, source, serverLinkLocal, reply), true
}

func buildDHCPv6Frame(ethernetHeader, clientMAC, gatewayMAC []byte, clientIP, serverIP netip.Addr, payload []byte) []byte {
	dstIP, dstMAC := clientIP, clientMAC
	if clientIP.IsUnspecified() {
		dstIP = dhcpv6AllServersAndRelays
		dstMAC = []byte{0x33, 0x33, 0x00, 0x01, 0x00, 0x02}
	}
	udpLen := 8 + len(payload)
	out := make([]byte, len(ethernetHeader)+40+udpLen)
	copy(out[:6], dstMAC)
	copy(out[6:12], gatewayMAC)
	copy(out[12:len(ethernetHeader)], ethernetHeader[12:])
	ip := out[len(ethernetHeader):]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(udpLen))
	ip[6], ip[7] = 17, 1
	src := serverIP.As16()
	dst := dstIP.As16()
	copy(ip[8:24], src[:])
	copy(ip[24:40], dst[:])
	udp := ip[40:]
	binary.BigEndian.PutUint16(udp[:2], 547)
	binary.BigEndian.PutUint16(udp[2:4], 546)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(udp[8:], payload)
	checksum := dhcpv6UDPChecksum(ip[8:24], ip[24:40], udp)
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], checksum)
	return out
}

func dhcpv6UDPChecksum(source, destination, udp []byte) uint16 {
	var sum uint32
	add := func(data []byte) {
		for len(data) >= 2 {
			sum += uint32(binary.BigEndian.Uint16(data[:2]))
			data = data[2:]
		}
		if len(data) == 1 {
			sum += uint32(data[0]) << 8
		}
	}
	add(source)
	add(destination)
	var tail [8]byte
	binary.BigEndian.PutUint32(tail[:4], uint32(len(udp)))
	tail[7] = 17
	add(tail[:])
	add(udp)
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
