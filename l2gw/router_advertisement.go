package l2gw

import (
	"encoding/binary"
	"net/netip"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

var allNodesIPv6 = netip.MustParseAddr("ff02::1").As16()

const routerAdvertisementInterval = 200 * time.Second

// routerAdvertisement answers a valid IPv6 Router Solicitation on the bridged
// segment. A small per-source limit prevents a client from filling the gateway
// output queue with repeated solicitations.
func (g *Gateway) routerAdvertisement(frame []byte, now time.Time) []byte {
	if !g.cfg.IPv6Address.IsValid() || len(frame) < header.EthernetMinimumSize+48 ||
		header.Ethernet(frame).Type() != header.IPv6ProtocolNumber || frame[6]&1 != 0 {
		return nil
	}
	ip := frame[header.EthernetMinimumSize:]
	payloadLen := int(binary.BigEndian.Uint16(ip[4:6]))
	if ip[0]>>4 != 6 || ip[6] != 58 || ip[7] != 255 || payloadLen < 8 || payloadLen > len(ip)-40 {
		return nil
	}
	rs := ip[40 : 40+payloadLen]
	if rs[0] != 133 || rs[1] != 0 || icmpv6Checksum(ip[8:24], ip[24:40], rs) != 0 {
		return nil
	}
	requester := netip.AddrFrom16([16]byte(ip[8:24]))
	if !requester.IsUnspecified() && !requester.IsLinkLocalUnicast() {
		return nil
	}
	var mac [6]byte
	copy(mac[:], frame[6:12])
	g.raMu.Lock()
	if g.raLast == nil {
		g.raLast = make(map[[6]byte]time.Time)
	}
	if last, exists := g.raLast[mac]; exists && now.Before(last.Add(time.Second)) {
		g.raMu.Unlock()
		return nil
	}
	if _, exists := g.raLast[mac]; !exists && len(g.raLast) >= 4096 {
		for source, seen := range g.raLast {
			if now.Sub(seen) > 10*time.Minute {
				delete(g.raLast, source)
			}
		}
		if len(g.raLast) >= 4096 {
			g.raMu.Unlock()
			return nil
		}
	}
	g.raLast[mac] = now
	g.raMu.Unlock()

	var destinationMAC [6]byte
	copy(destinationMAC[:], frame[:6])
	return g.buildRouterAdvertisement(destinationMAC, requester)
}

func (g *Gateway) unsolicitedRouterAdvertisement() []byte {
	return g.buildRouterAdvertisement([6]byte{0x33, 0x33, 0, 0, 0, 1}, netip.AddrFrom16(allNodesIPv6))
}

func (g *Gateway) withdrawRouterAdvertisement() []byte {
	return g.buildRouterAdvertisementWithLifetimes([6]byte{0x33, 0x33, 0, 0, 0, 1}, netip.AddrFrom16(allNodesIPv6), 0, 0, 0)
}

func (g *Gateway) sendRouterAdvertisement(frame []byte) bool {
	g.raSendMu.Lock()
	defer g.raSendMu.Unlock()
	if g.closed.Load() {
		return false
	}
	g.raAdvertised.Store(true)
	g.framesOut.Add(1)
	g.tap(false, frame)
	g.cfg.Out(frame)
	return true
}

func (g *Gateway) buildRouterAdvertisement(destinationMAC [6]byte, dst netip.Addr) []byte {
	return g.buildRouterAdvertisementWithLifetimes(destinationMAC, dst, 1800, 86400, 14400)
}

func (g *Gateway) buildRouterAdvertisementWithLifetimes(destinationMAC [6]byte, dst netip.Addr, routerLifetime uint16, validLifetime, preferredLifetime uint32) []byte {
	if !g.cfg.IPv6Address.IsValid() {
		return nil
	}
	src := g.routerLinkLocal()
	raLen := 48
	if len(g.cfg.DNS6) > 0 {
		raLen += 8 + 16*len(g.cfg.DNS6)
	}
	out := make([]byte, header.EthernetMinimumSize+40+raLen)
	copy(out[:6], destinationMAC[:])
	copy(out[6:12], g.cfg.MAC)
	binary.BigEndian.PutUint16(out[12:14], uint16(header.IPv6ProtocolNumber))
	if dst.IsUnspecified() {
		copy(out[:6], []byte{0x33, 0x33, 0, 0, 0, 1})
		copy(out[6:12], g.cfg.MAC)
		dst = netip.AddrFrom16(allNodesIPv6)
	}
	v6 := out[header.EthernetMinimumSize:]
	v6[0] = 0x60
	binary.BigEndian.PutUint16(v6[4:6], uint16(raLen))
	v6[6], v6[7] = 58, 255
	copy(v6[8:24], src[:])
	destination := dst.As16()
	copy(v6[24:40], destination[:])
	ra := v6[40:]
	ra[0], ra[1], ra[4] = 134, 0, 64
	binary.BigEndian.PutUint16(ra[6:8], routerLifetime)
	ra[16], ra[17], ra[18], ra[19] = 3, 4, byte(g.cfg.IPv6Address.Bits()), 0x80 // prefix info, on-link
	if g.cfg.IPv6Address.Bits() == 64 {
		ra[19] |= 0x40 // autonomous address configuration is defined for /64 prefixes
	}
	binary.BigEndian.PutUint32(ra[20:24], validLifetime)
	binary.BigEndian.PutUint32(ra[24:28], preferredLifetime)
	prefix := g.cfg.IPv6Address.Masked().Addr().As16()
	copy(ra[32:48], prefix[:])
	if len(g.cfg.DNS6) > 0 {
		offset := 48
		ra[offset], ra[offset+1] = 25, byte(1+2*len(g.cfg.DNS6))
		dnsLifetime := uint32(routerLifetime)
		binary.BigEndian.PutUint32(ra[offset+4:offset+8], dnsLifetime)
		for _, dns := range g.cfg.DNS6 {
			address := dns.As16()
			copy(ra[offset+8:offset+24], address[:])
			offset += 16
		}
	}
	binary.BigEndian.PutUint16(ra[2:4], icmpv6Checksum(v6[8:24], v6[24:40], ra))
	return out
}

// periodicRouterAdvertisements refreshes router and SLAAC prefix lifetimes for
// clients after their initial solicitation. The 200-second interval stays
// below the IPv6 Router Advertisement maximum interval.
func (g *Gateway) periodicRouterAdvertisements(done <-chan struct{}) {
	defer g.done.Done()
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	for {
		select {
		case <-done:
			return
		case <-timer.C:
			if frame := g.unsolicitedRouterAdvertisement(); frame != nil {
				g.sendRouterAdvertisement(frame)
			}
			timer.Reset(routerAdvertisementInterval)
		}
	}
}

// routerLinkLocal derives a stable modified-EUI-64 address from the gateway MAC.
// Router Advertisements must use a link-local source even when the advertised
// prefix and configured gateway address are global.
func (g *Gateway) routerLinkLocal() [16]byte {
	var address [16]byte
	address[0], address[1] = 0xfe, 0x80
	mac := g.cfg.MAC
	address[8] = mac[0] ^ 0x02
	address[9], address[10] = mac[1], mac[2]
	address[11], address[12] = 0xff, 0xfe
	address[13], address[14], address[15] = mac[3], mac[4], mac[5]
	return address
}

func icmpv6Checksum(src, dst, message []byte) uint16 {
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
	add(src)
	add(dst)
	var pseudo [8]byte
	binary.BigEndian.PutUint32(pseudo[:4], uint32(len(message)))
	pseudo[7] = 58
	add(pseudo[:])
	add(message)
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
