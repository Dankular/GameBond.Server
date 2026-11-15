package edge

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"time"
)

var (
	mdnsIPv4Group = netip.MustParseAddr("224.0.0.251").As4()
	mdnsIPv6Group = netip.MustParseAddr("ff02::fb").As16()
	mdnsRelayMAC  = [6]byte{0x02, 0x47, 0x42, 0xff, 0xff, 0xfe}
)

const (
	mdnsUnicastLifetime = 5 * time.Second
	mdnsUnicastCapacity = 4096
	mdnsUnicastFanout   = 16
)

type mdnsUnicastKey struct {
	vlan   uint16
	family uint8
	addr   netip.Addr
	port   uint16
	id     uint16
}

type mdnsUnicastOrigin struct {
	vlan    uint16
	mac     [6]byte
	expires time.Time
}

type mdnsUnicastDelivery struct {
	vlan  uint16
	frame []byte
}

// mdnsUnicastTracker remembers the VLAN and Ethernet destination of queries
// reflected into another VLAN. Most mDNS answers are multicast, but legacy
// queries and QU behavior can produce a unicast answer addressed to the relay
// MAC; this state returns that answer only to the authorized query origins.
type mdnsUnicastTracker struct {
	entries   map[mdnsUnicastKey][]mdnsUnicastOrigin
	nextSweep time.Time
}

func newMDNSUnicastTracker() *mdnsUnicastTracker {
	return &mdnsUnicastTracker{entries: make(map[mdnsUnicastKey][]mdnsUnicastOrigin)}
}

func (t *mdnsUnicastTracker) rememberQuery(frame []byte, sourceVLAN, targetVLAN uint16, now time.Time) bool {
	key, sourceMAC, ok := mdnsUnicastQueryKey(frame, targetVLAN)
	if !ok {
		return mdnsIsResponseMessage(frame) // multicast responses need no return-path state.
	}
	t.sweep(now)
	origins := t.entries[key]
	for i := range origins {
		if origins[i].vlan == sourceVLAN && origins[i].mac == sourceMAC {
			origins[i].expires = now.Add(mdnsUnicastLifetime)
			t.entries[key] = origins
			return true
		}
	}
	if len(origins) >= mdnsUnicastFanout || len(origins) == 0 && len(t.entries) >= mdnsUnicastCapacity {
		return false
	}
	t.entries[key] = append(origins, mdnsUnicastOrigin{vlan: sourceVLAN, mac: sourceMAC, expires: now.Add(mdnsUnicastLifetime)})
	return true
}

func mdnsIsResponseMessage(frame []byte) bool {
	_, _, _, _, udp, end, ok := mdnsUDPBounds(frame)
	return ok && validMDNSMessage(frame[udp+8:end]) && binary.BigEndian.Uint16(frame[udp+10:udp+12])&0x8000 != 0
}

func (t *mdnsUnicastTracker) reflectResponse(frame []byte, responseVLAN uint16, now time.Time) ([]mdnsUnicastDelivery, bool) {
	key, ok := mdnsUnicastResponseKey(frame, responseVLAN)
	if !ok {
		return nil, false
	}
	t.sweep(now)
	origins, ok := t.entries[key]
	if !ok {
		return nil, true // consume valid but unsolicited or expired answers at the relay MAC.
	}
	deliveries := make([]mdnsUnicastDelivery, 0, len(origins))
	for _, origin := range origins {
		if !now.Before(origin.expires) {
			continue
		}
		copyFrame := append([]byte(nil), frame...)
		copy(copyFrame[:6], origin.mac[:])
		copy(copyFrame[6:12], mdnsRelayMAC[:])
		deliveries = append(deliveries, mdnsUnicastDelivery{vlan: origin.vlan, frame: copyFrame})
	}
	return deliveries, true
}

func (t *mdnsUnicastTracker) sweep(now time.Time) {
	if now.Before(t.nextSweep) {
		return
	}
	for key, origins := range t.entries {
		alive := origins[:0]
		for _, origin := range origins {
			if now.Before(origin.expires) {
				alive = append(alive, origin)
			}
		}
		if len(alive) == 0 {
			delete(t.entries, key)
		} else {
			t.entries[key] = alive
		}
	}
	t.nextSweep = now.Add(time.Second)
}

func mdnsUnicastQueryKey(frame []byte, targetVLAN uint16) (mdnsUnicastKey, [6]byte, bool) {
	var mac [6]byte
	if len(frame) < 14 {
		return mdnsUnicastKey{}, mac, false
	}
	copy(mac[:], frame[6:12])
	_, family, src, _, udp, end, ok := mdnsUDPBounds(frame)
	if !ok || binary.BigEndian.Uint16(frame[udp+2:udp+4]) != 5353 {
		return mdnsUnicastKey{}, mac, false
	}
	dns := frame[udp+8 : end]
	if !validMDNSPacket(dns, binary.BigEndian.Uint16(frame[udp:udp+2])) || binary.BigEndian.Uint16(dns[2:4])&0x8000 != 0 {
		return mdnsUnicastKey{}, mac, false
	}
	return mdnsUnicastKey{vlan: targetVLAN, family: family, addr: src, port: binary.BigEndian.Uint16(frame[udp : udp+2]), id: binary.BigEndian.Uint16(dns[:2])}, mac, true
}

func mdnsUnicastResponseKey(frame []byte, responseVLAN uint16) (mdnsUnicastKey, bool) {
	if len(frame) < 14 || !bytes.Equal(frame[:6], mdnsRelayMAC[:]) {
		return mdnsUnicastKey{}, false
	}
	_, family, src, dst, udp, end, ok := mdnsUDPBounds(frame)
	if !ok || !src.IsLinkLocalUnicast() || !dst.IsLinkLocalUnicast() || binary.BigEndian.Uint16(frame[udp:udp+2]) != 5353 {
		return mdnsUnicastKey{}, false
	}
	dns := frame[udp+8 : end]
	if !validMDNSMessage(dns) || binary.BigEndian.Uint16(dns[2:4])&0x8000 == 0 {
		return mdnsUnicastKey{}, false
	}
	return mdnsUnicastKey{vlan: responseVLAN, family: family, addr: dst, port: binary.BigEndian.Uint16(frame[udp+2 : udp+4]), id: binary.BigEndian.Uint16(dns[:2])}, true
}

// mdnsUDPBounds returns the network and UDP ranges for a complete, unfragmented
// link-local mDNS frame. Both IP families require hop-limit 255 and a valid
// transport checksum (IPv4 retains its permitted zero-checksum form).
func mdnsUDPBounds(frame []byte) (ip int, family uint8, src, dst netip.Addr, udp, end int, ok bool) {
	if len(frame) < 14 {
		return 0, 0, netip.Addr{}, netip.Addr{}, 0, 0, false
	}
	etherType := binary.BigEndian.Uint16(frame[12:14])
	ip = 14
	for tags := 0; tags < 2 && (etherType == 0x8100 || etherType == 0x88a8 || etherType == 0x9100); tags++ {
		if len(frame) < ip+4 {
			return 0, 0, netip.Addr{}, netip.Addr{}, 0, 0, false
		}
		etherType = binary.BigEndian.Uint16(frame[ip+2 : ip+4])
		ip += 4
	}
	switch etherType {
	case 0x0800:
		if len(frame) < ip+20 || frame[ip]>>4 != 4 {
			break
		}
		ihl := int(frame[ip]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(frame[ip+2 : ip+4]))
		if ihl < 20 || total < ihl+8+12 || total > len(frame)-ip || frame[ip+8] != 255 || frame[ip+9] != 17 || frame[ip+6]&0x3f != 0 || frame[ip+7] != 0 || internetChecksum(frame[ip:ip+ihl]) != 0 {
			break
		}
		src = netip.AddrFrom4([4]byte(frame[ip+12 : ip+16]))
		dst = netip.AddrFrom4([4]byte(frame[ip+16 : ip+20]))
		udp, end, family = ip+ihl, ip+total, 4
		udpLen := int(binary.BigEndian.Uint16(frame[udp+4 : udp+6]))
		if udpLen != total-ihl || udpLen < 8+12 || binary.BigEndian.Uint16(frame[udp+6:udp+8]) != 0 && !validIPv4UDPChecksum(frame[ip+12:ip+20], frame[udp:udp+udpLen]) {
			break
		}
		return ip, family, src, dst, udp, udp + udpLen, true
	case 0x86dd:
		if len(frame) < ip+40 || frame[ip]>>4 != 6 || frame[ip+6] != 17 || frame[ip+7] != 255 {
			break
		}
		payload := int(binary.BigEndian.Uint16(frame[ip+4 : ip+6]))
		if payload < 8+12 || payload > len(frame)-ip-40 {
			break
		}
		src = netip.AddrFrom16([16]byte(frame[ip+8 : ip+24]))
		dst = netip.AddrFrom16([16]byte(frame[ip+24 : ip+40]))
		udp, end, family = ip+40, ip+40+payload, 16
		udpLen := int(binary.BigEndian.Uint16(frame[udp+4 : udp+6]))
		if udpLen != payload || udpLen < 8+12 || !validIPv6UDPChecksum(frame[ip+8:ip+40], frame[udp:udp+udpLen]) {
			break
		}
		return ip, family, src, dst, udp, udp + udpLen, true
	}
	return 0, 0, netip.Addr{}, netip.Addr{}, 0, 0, false
}

func isMDNSRelayFrame(frame []byte) bool {
	return len(frame) >= 12 && bytes.Equal(frame[6:12], mdnsRelayMAC[:])
}

// prepareMDNSRelayFrame accepts valid link-local multicast DNS queries and
// responses. It converts QU questions to QM so answers return through the
// multicast path and can be reflected to the original VLAN. Returned frames
// are marked with a relay source MAC to prevent reflection loops.
func prepareMDNSRelayFrame(frame []byte) ([]byte, bool) {
	if len(frame) < 14 || len(frame) > 9216 {
		return nil, false
	}
	offset := 12
	etherType := binary.BigEndian.Uint16(frame[offset : offset+2])
	offset += 2
	for tags := 0; tags < 2 && (etherType == 0x8100 || etherType == 0x88a8 || etherType == 0x9100); tags++ {
		if len(frame) < offset+4 {
			return nil, false
		}
		etherType = binary.BigEndian.Uint16(frame[offset+2 : offset+4])
		offset += 4
	}
	if etherType == 0x0800 {
		if !bytes.Equal(frame[:6], []byte{0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb}) {
			return nil, false
		}
		return prepareMDNSIPv4(frame, offset)
	}
	if etherType == 0x86dd {
		if !bytes.Equal(frame[:6], []byte{0x33, 0x33, 0x00, 0x00, 0x00, 0xfb}) {
			return nil, false
		}
		return prepareMDNSIPv6(frame, offset)
	}
	return nil, false
}

func prepareMDNSIPv4(frame []byte, ip int) ([]byte, bool) {
	if len(frame) < ip+20 || frame[ip]>>4 != 4 {
		return nil, false
	}
	ihl := int(frame[ip]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(frame[ip+2 : ip+4]))
	if ihl < 20 || total < ihl+8+12 || total > len(frame)-ip || frame[ip+8] != 255 || frame[ip+9] != 17 || frame[ip+6]&0x3f != 0 || frame[ip+7] != 0 {
		return nil, false
	}
	if internetChecksum(frame[ip:ip+ihl]) != 0 {
		return nil, false
	}
	src := netip.AddrFrom4([4]byte(frame[ip+12 : ip+16]))
	dst := [4]byte(frame[ip+16 : ip+20])
	if !src.IsLinkLocalUnicast() || dst != mdnsIPv4Group || frame[ip+12] == 0 {
		return nil, false
	}
	udp := ip + ihl
	if binary.BigEndian.Uint16(frame[udp+2:udp+4]) != 5353 {
		return nil, false
	}
	udpLen := int(binary.BigEndian.Uint16(frame[udp+4 : udp+6]))
	if udpLen < 8+12 || udpLen != total-ihl {
		return nil, false
	}
	if binary.BigEndian.Uint16(frame[udp+6:udp+8]) != 0 && !validIPv4UDPChecksum(frame[ip+12:ip+20], frame[udp:udp+udpLen]) {
		return nil, false
	}
	dns := frame[udp+8 : udp+udpLen]
	if !validMDNSPacket(dns, binary.BigEndian.Uint16(frame[udp:udp+2])) {
		return nil, false
	}
	out := append([]byte(nil), frame[:ip+total]...)
	copy(out[6:12], mdnsRelayMAC[:])
	if clearMDNSQU(out[udp+8 : udp+udpLen]) {
		if binary.BigEndian.Uint16(out[udp+6:udp+8]) != 0 {
			binary.BigEndian.PutUint16(out[udp+6:udp+8], 0)
			checksum := internetChecksumValue(ipv4UDPPseudoHeader(out[ip+12:ip+20], out[udp:udp+udpLen]))
			if checksum == 0 {
				checksum = 0xffff
			}
			binary.BigEndian.PutUint16(out[udp+6:udp+8], checksum)
		}
	}
	// mDNS is link-local and receivers require a hop limit of 255. Reject
	// anything else above; recompute the IPv4 header checksum for the copy.
	out[ip+8] = 255
	out[ip+10], out[ip+11] = 0, 0
	binary.BigEndian.PutUint16(out[ip+10:ip+12], internetChecksumValue(out[ip:ip+ihl]))
	return out, true
}

func prepareMDNSIPv6(frame []byte, ip int) ([]byte, bool) {
	if len(frame) < ip+40 || frame[ip]>>4 != 6 || frame[ip+6] != 17 || frame[ip+7] != 255 {
		return nil, false
	}
	payload := int(binary.BigEndian.Uint16(frame[ip+4 : ip+6]))
	if payload < 8+12 || payload > len(frame)-ip-40 {
		return nil, false
	}
	src := netip.AddrFrom16([16]byte(frame[ip+8 : ip+24]))
	dst := [16]byte(frame[ip+24 : ip+40])
	if !src.IsLinkLocalUnicast() || dst != mdnsIPv6Group {
		return nil, false
	}
	udp := ip + 40
	if binary.BigEndian.Uint16(frame[udp+2:udp+4]) != 5353 || binary.BigEndian.Uint16(frame[udp+6:udp+8]) == 0 {
		return nil, false
	}
	udpLen := int(binary.BigEndian.Uint16(frame[udp+4 : udp+6]))
	if udpLen < 8+12 || udpLen != payload {
		return nil, false
	}
	if !validIPv6UDPChecksum(frame[ip+8:ip+40], frame[udp:udp+udpLen]) {
		return nil, false
	}
	if !validMDNSPacket(frame[udp+8:udp+udpLen], binary.BigEndian.Uint16(frame[udp:udp+2])) {
		return nil, false
	}
	out := append([]byte(nil), frame[:ip+40+payload]...)
	copy(out[6:12], mdnsRelayMAC[:])
	if clearMDNSQU(out[udp+8 : udp+udpLen]) {
		binary.BigEndian.PutUint16(out[udp+6:udp+8], 0)
		binary.BigEndian.PutUint16(out[udp+6:udp+8], ipv6UDPChecksum(out[ip+8:ip+40], out[udp:udp+udpLen]))
	}
	return out, true
}

func validMDNSMessage(message []byte) bool {
	if len(message) < 12 {
		return false
	}
	flags := binary.BigEndian.Uint16(message[2:4])
	if flags&0x7800 != 0 {
		return false
	}
	questions := int(binary.BigEndian.Uint16(message[4:6]))
	answers := int(binary.BigEndian.Uint16(message[6:8]))
	authorities := int(binary.BigEndian.Uint16(message[8:10]))
	additionals := int(binary.BigEndian.Uint16(message[10:12]))
	if questions+answers+authorities+additionals > 1024 {
		return false
	}
	offset := 12
	for i := 0; i < questions; i++ {
		var ok bool
		offset, ok = skipDNSName(message, offset)
		if !ok || offset+4 > len(message) {
			return false
		}
		offset += 4
	}
	for i := 0; i < answers+authorities+additionals; i++ {
		var ok bool
		offset, ok = skipDNSName(message, offset)
		if !ok || offset+10 > len(message) {
			return false
		}
		rdlength := int(binary.BigEndian.Uint16(message[offset+8 : offset+10]))
		offset += 10
		if rdlength > len(message)-offset {
			return false
		}
		offset += rdlength
	}
	return offset == len(message)
}

func validMDNSPacket(message []byte, sourcePort uint16) bool {
	if sourcePort == 0 || !validMDNSMessage(message) {
		return false
	}
	id := binary.BigEndian.Uint16(message[:2])
	response := binary.BigEndian.Uint16(message[2:4])&0x8000 != 0
	// Ordinary multicast mDNS messages use ID zero. Legacy unicast queries may
	// carry a DNS transaction ID, which their unicast response must preserve.
	if response {
		return id == 0 && sourcePort == 5353
	}
	return id == 0 || sourcePort != 5353
}

func clearMDNSQU(message []byte) bool {
	if len(message) < 12 || binary.BigEndian.Uint16(message[2:4])&0x8000 != 0 {
		return false // responses do not carry question unicast-response requests.
	}
	questions := int(binary.BigEndian.Uint16(message[4:6]))
	offset := 12
	changed := false
	for i := 0; i < questions; i++ {
		next, ok := skipDNSName(message, offset)
		if !ok || next+4 > len(message) {
			return false
		}
		qclass := binary.BigEndian.Uint16(message[next+2 : next+4])
		if qclass&0x8000 != 0 {
			binary.BigEndian.PutUint16(message[next+2:next+4], qclass&0x7fff)
			changed = true
		}
		offset = next + 4
	}
	return changed
}

func ipv4UDPPseudoHeader(addresses, datagram []byte) []byte {
	pseudo := make([]byte, 12+len(datagram))
	copy(pseudo[:8], addresses)
	pseudo[9] = 17
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(datagram)))
	copy(pseudo[12:], datagram)
	return pseudo
}

func ipv6UDPChecksum(addresses, datagram []byte) uint16 {
	pseudo := make([]byte, 40+len(datagram))
	copy(pseudo[:32], addresses)
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(datagram)))
	pseudo[39] = 17
	copy(pseudo[40:], datagram)
	checksum := internetChecksumValue(pseudo)
	if checksum == 0 {
		return 0xffff
	}
	return checksum
}

func skipDNSName(message []byte, offset int) (int, bool) {
	if offset < 0 || offset >= len(message) {
		return 0, false
	}
	consumed := -1
	position := offset
	steps := 0
	nameLength := 0
	for steps < 128 {
		steps++
		if position >= len(message) {
			return 0, false
		}
		length := int(message[position])
		if length&0xc0 == 0xc0 {
			if position+1 >= len(message) {
				return 0, false
			}
			pointer := ((length & 0x3f) << 8) | int(message[position+1])
			if pointer >= len(message) {
				return 0, false
			}
			if consumed < 0 {
				consumed = position + 2
			}
			position = pointer
			continue
		}
		if length&0xc0 != 0 {
			return 0, false
		}
		position++
		if length == 0 {
			if consumed >= 0 {
				return consumed, true
			}
			return position, true
		}
		if length > 63 || position+length > len(message) {
			return 0, false
		}
		nameLength += length + 1
		if nameLength > 255 {
			return 0, false
		}
		position += length
	}
	return 0, false
}

func internetChecksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func internetChecksumValue(data []byte) uint16 { return internetChecksum(data) }

func validIPv6UDPChecksum(addresses, datagram []byte) bool {
	if len(addresses) != 32 || len(datagram) < 8 {
		return false
	}
	pseudo := make([]byte, 40+len(datagram))
	copy(pseudo[:32], addresses)
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(datagram)))
	pseudo[39] = 17
	copy(pseudo[40:], datagram)
	return internetChecksum(pseudo) == 0
}

func validIPv4UDPChecksum(addresses, datagram []byte) bool {
	if len(addresses) != 8 || len(datagram) < 8 || len(datagram) > 65535 {
		return false
	}
	pseudo := make([]byte, 12+len(datagram))
	copy(pseudo[:8], addresses)
	pseudo[9] = 17
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(datagram)))
	copy(pseudo[12:], datagram)
	return internetChecksum(pseudo) == 0
}
