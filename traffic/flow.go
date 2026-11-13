package traffic

import (
	"encoding/binary"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxFlowEntries = 65536
	flowTTL        = 2 * time.Minute
	maxDNSIPs      = 32768
)

type flowKey struct {
	src, dst netip.Addr
	proto    uint8
	sport    uint16
	dport    uint16
}

type flowEntry struct {
	result  Result
	seen    time.Time
	packets uint64
	bytes   uint64
}

type domainEntry struct {
	name    string
	expires time.Time
}

// Result describes what was visible in packet metadata. Port-only classifications have low confidence.
type Result struct {
	Application string    `json:"application"`
	Protocol    string    `json:"protocol"`
	Domain      string    `json:"domain,omitempty"`
	Confidence  string    `json:"confidence"`
	Evidence    string    `json:"evidence"`
	Packets     uint64    `json:"packets"`
	Bytes       uint64    `json:"bytes"`
	LastSeen    time.Time `json:"last_seen"`
}

type Status struct {
	Flows       int    `json:"flows"`
	DNSMappings int    `json:"dns_mappings"`
	Unknown     uint64 `json:"unknown"`
	Evicted     uint64 `json:"evicted"`
}

// Classifier keeps a bounded, payload-free summary of recent IPv4 flows and DNS-to-address hints.
type Classifier struct {
	mu        sync.Mutex
	flows     map[flowKey]flowEntry
	domains   map[netip.Addr]domainEntry
	now       func() time.Time
	lastPrune time.Time
	unknown   uint64
	evicted   uint64
	enabled   atomic.Bool
}

func NewClassifier() *Classifier {
	return &Classifier{flows: make(map[flowKey]flowEntry), domains: make(map[netip.Addr]domainEntry), now: time.Now}
}

func (c *Classifier) SetEnabled(enabled bool) { c.enabled.Store(enabled) }

// ObservePacket records IPv4 headers and transiently reads visible HTTP/TLS host metadata. It retains no payloads.
func (c *Classifier) ObservePacket(fromDevice bool, packet []byte) {
	if !c.enabled.Load() {
		return
	}
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return
	}
	hlen := int(packet[0]&0x0f) * 4
	if hlen < 20 || len(packet) < hlen || binary.BigEndian.Uint16(packet[6:])&0x1fff != 0 {
		return
	}
	proto := packet[9]
	src := netip.AddrFrom4([4]byte(packet[12:16]))
	dst := netip.AddrFrom4([4]byte(packet[16:20]))
	var sport, dport uint16
	if (proto == 6 || proto == 17) && len(packet) >= hlen+4 {
		sport, dport = binary.BigEndian.Uint16(packet[hlen:]), binary.BigEndian.Uint16(packet[hlen+2:])
	}
	if !fromDevice {
		src, dst, sport, dport = dst, src, dport, sport
	}
	observedDomain, evidence := packetDomain(packet, hlen, proto)
	k := flowKey{src, dst, proto, sport, dport}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.flows[k]
	if ok && now.Sub(e.seen) > flowTTL {
		delete(c.flows, k)
		ok = false
	}
	if !ok {
		if len(c.flows) >= maxFlowEntries {
			c.evictOldestLocked()
		}
		name := "unknown"
		protocol := "unknown"
		confidence := "low"
		evidence := "port"
		if proto == 6 {
			protocol = "tcp"
		} else if proto == 17 {
			protocol = "udp"
		}
		name = applicationFor(proto, dport)
		if name == "unknown" {
			c.unknown++
		}
		if domain, found := c.domains[dst]; found && now.Before(domain.expires) {
			name = "web"
			evidence = "dns_ip_correlation"
		}
		e = flowEntry{result: Result{Application: name, Protocol: protocol, Confidence: confidence, Evidence: evidence}}
	}
	e.seen = now
	e.packets++
	e.bytes += uint64(len(packet))
	e.result.Packets, e.result.Bytes, e.result.LastSeen = e.packets, e.bytes, now
	if observedDomain != "" {
		e.result.Domain = observedDomain
		e.result.Application = "web"
		e.result.Evidence = evidence
		e.result.Confidence = "high"
	} else if domain, found := c.domains[dst]; found && now.Before(domain.expires) {
		e.result.Domain = domain.name
		e.result.Application = "web"
		e.result.Evidence = "dns_ip_correlation"
		e.result.Confidence = "low"
	}
	c.flows[k] = e
}

func packetDomain(packet []byte, ipHeader int, proto uint8) (string, string) {
	if proto != 6 || len(packet) < ipHeader+20 {
		return "", ""
	}
	tcpHeader := int(packet[ipHeader+12]>>4) * 4
	if tcpHeader < 20 || len(packet) < ipHeader+tcpHeader {
		return "", ""
	}
	payload := packet[ipHeader+tcpHeader:]
	if len(payload) >= 5 && payload[0] == 0x16 && payload[1] == 0x03 {
		if name := tlsServerName(payload); name != "" {
			return name, "tls_sni"
		}
	}
	if len(payload) > 4 && len(payload) <= 4096 {
		if name := httpHost(payload); name != "" {
			return name, "http_host"
		}
	}
	return "", ""
}

func tlsServerName(record []byte) string {
	if len(record) < 9 || record[0] != 0x16 || record[5] != 0x01 {
		return ""
	}
	recordLen := int(binary.BigEndian.Uint16(record[3:5]))
	if recordLen+5 > len(record) {
		return ""
	}
	b := record[5 : 5+recordLen]
	if len(b) < 42 || b[0] != 0x01 {
		return ""
	}
	i := 4 + 2 + 32
	if i >= len(b) {
		return ""
	}
	sidLen := int(b[i])
	i++
	i += sidLen
	if i+2 > len(b) {
		return ""
	}
	cipherLen := int(binary.BigEndian.Uint16(b[i : i+2]))
	i += 2 + cipherLen
	if i >= len(b) {
		return ""
	}
	compressionLen := int(b[i])
	i++
	i += compressionLen
	if i+2 > len(b) {
		return ""
	}
	extLen := int(binary.BigEndian.Uint16(b[i : i+2]))
	i += 2
	end := i + extLen
	if end > len(b) {
		return ""
	}
	for i+4 <= end {
		typ := binary.BigEndian.Uint16(b[i : i+2])
		n := int(binary.BigEndian.Uint16(b[i+2 : i+4]))
		i += 4
		if i+n > end {
			return ""
		}
		if typ == 0 && n >= 5 {
			listLen := int(binary.BigEndian.Uint16(b[i : i+2]))
			j, listEnd := i+2, i+2+listLen
			if listEnd > i+n {
				return ""
			}
			for j+3 <= listEnd {
				nameType, nameLen := b[j], int(binary.BigEndian.Uint16(b[j+1:j+3]))
				j += 3
				if j+nameLen > listEnd {
					return ""
				}
				if nameType == 0 && nameLen > 0 && nameLen <= 253 {
					name := strings.ToLower(string(b[j : j+nameLen]))
					if net.ParseIP(name) == nil && !strings.ContainsAny(name, "/:@ ") {
						return name
					}
				}
				j += nameLen
			}
		}
		i += n
	}
	return ""
}

func httpHost(payload []byte) string {
	lineEnd := strings.Index(string(payload), "\r\n")
	if lineEnd <= 0 || lineEnd > 16 {
		return ""
	}
	requestLine := strings.Fields(string(payload[:lineEnd]))
	if len(requestLine) != 3 || !strings.HasPrefix(requestLine[2], "HTTP/") {
		return ""
	}
	for _, line := range strings.Split(string(payload[lineEnd+2:]), "\r\n") {
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), "host") {
			host := strings.TrimSpace(value)
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			host = strings.TrimSuffix(strings.ToLower(host), ".")
			if host != "" && len(host) <= 253 && net.ParseIP(host) == nil && !strings.ContainsAny(host, "/:@ ") {
				return host
			}
		}
	}
	return ""
}

// ObserveDNS associates answer addresses with a domain for a short-lived, explicitly uncertain hint.
func (c *Classifier) ObserveDNS(name string, answers []netip.Addr) {
	if !c.enabled.Load() {
		return
	}
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if name == "" || len(name) > 253 {
		return
	}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, ip := range answers {
		if !ip.IsValid() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
			continue
		}
		if _, exists := c.domains[ip]; !exists && len(c.domains) >= maxDNSIPs {
			c.evictOldestDomainLocked()
		}
		c.domains[ip] = domainEntry{name, now.Add(5 * time.Minute)}
	}
}

func applicationFor(proto uint8, port uint16) string {
	if proto == 17 && port == 443 {
		return "quic"
	}
	if proto == 17 && port == 53 || proto == 6 && port == 53 {
		return "dns"
	}
	if proto == 6 {
		switch port {
		case 80, 8080:
			return "http"
		case 443, 8443:
			return "tls"
		case 22:
			return "ssh"
		case 25, 465, 587:
			return "mail"
		}
	}
	return "unknown"
}

func (c *Classifier) pruneLocked(now time.Time) {
	if !c.lastPrune.IsZero() && now.Sub(c.lastPrune) < time.Second {
		return
	}
	c.lastPrune = now
	for k, e := range c.flows {
		if now.Sub(e.seen) > flowTTL {
			delete(c.flows, k)
		}
	}
	for ip, e := range c.domains {
		if !now.Before(e.expires) {
			delete(c.domains, ip)
		}
	}
}

func (c *Classifier) evictOldestLocked() {
	for k := range c.flows {
		delete(c.flows, k)
		c.evicted++
		return
	}
}

func (c *Classifier) evictOldestDomainLocked() {
	for ip := range c.domains {
		delete(c.domains, ip)
		c.evicted++
		return
	}
}

func (c *Classifier) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(c.now())
	return Status{Flows: len(c.flows), DNSMappings: len(c.domains), Unknown: c.unknown, Evicted: c.evicted}
}

func (c *Classifier) Recent(limit int) []Result {
	if limit < 1 || limit > 1000 {
		limit = 100
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(c.now())
	out := make([]Result, 0, len(c.flows))
	for _, e := range c.flows {
		out = append(out, e.result)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	if len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}
