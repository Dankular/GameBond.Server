package l2gw

import (
	"bytes"
	"encoding/binary"
	"time"
)

const (
	lldpEtherType        = 0x88cc
	lldpMEDOUI0          = 0x00
	lldpMEDOUI1          = 0x12
	lldpMEDOUI2          = 0xbb
	lldpMEDNetworkPolicy = 2
)

var lldpNearestBridge = [6]byte{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e}

// LLDPMEDNetworkPolicy is the single network policy advertised by this
// gateway. VLAN membership itself is enforced by the L2 switch; this value
// must be populated from that gateway port's configured VLAN.
type LLDPMEDNetworkPolicy struct {
	ApplicationType uint8
	VLANID          uint16
	Tagged          bool
	L2Priority      uint8
	DSCP            uint8
}

// BuildLLDPMEDResponse validates a peer LLDP-MED advertisement and builds a
// standard nearest-bridge multicast LLDP-MED advertisement for the gateway.
// LLDP is not a request/reply protocol; this helper lets the L2 ingress path
// answer a device's initial discovery immediately, in addition to any
// periodic host advertisements. Malformed or non-LLDP-MED frames return nil.
//
// The gateway identity is stable: its chassis ID is its configured MAC, and
// its port ID is the fixed ASCII name "gamebond-gateway".
func (g *Gateway) BuildLLDPMEDResponse(frame []byte) []byte {
	if g == nil || len(g.cfg.MAC) != 6 || len(frame) < 16 || len(frame) > 9216 {
		return nil
	}
	if !bytes.Equal(frame[:6], lldpNearestBridge[:]) {
		return nil
	}
	etherTypeOffset := 12
	offset := 14
	etherType := binary.BigEndian.Uint16(frame[etherTypeOffset : etherTypeOffset+2])
	for tags := 0; tags < 2 && (etherType == 0x8100 || etherType == 0x88a8 || etherType == 0x9100); tags++ {
		if len(frame) < offset+4 {
			return nil
		}
		etherTypeOffset = offset + 2
		offset += 4
		etherType = binary.BigEndian.Uint16(frame[etherTypeOffset : etherTypeOffset+2])
	}
	if etherType != lldpEtherType {
		return nil
	}
	src := frame[6:12]
	if src[0]&1 != 0 || bytes.Equal(src, g.cfg.MAC) || bytes.Equal(src, []byte{0, 0, 0, 0, 0, 0}) {
		return nil
	}

	seen := [4]bool{}
	hasMED := false
	ended := false
	for offset+2 <= len(frame) {
		header := binary.BigEndian.Uint16(frame[offset : offset+2])
		typ, size := header>>9, int(header&0x1ff)
		offset += 2
		if size > len(frame)-offset {
			return nil
		}
		value := frame[offset : offset+size]
		offset += size
		if typ == 0 {
			if size != 0 {
				return nil
			}
			ended = true
			for _, padding := range frame[offset:] {
				if padding != 0 {
					return nil
				}
			}
			break
		}
		if typ <= 3 {
			if seen[typ] || size < 2 {
				return nil
			}
			seen[typ] = true
			if typ == 3 && size != 2 {
				return nil
			}
			if (typ == 1 || typ == 2) && (value[0] < 1 || value[0] > 7 || size < 2) {
				return nil
			}
		}
		if typ == 127 && size >= 4 && value[0] == lldpMEDOUI0 && value[1] == lldpMEDOUI1 && value[2] == lldpMEDOUI2 && value[3] == 1 {
			if size != 7 {
				return nil
			}
			hasMED = true
		}
	}
	if !ended || !seen[1] || !seen[2] || !seen[3] || !hasMED {
		return nil
	}

	return g.buildLLDPMEDFrame(120, frame[12:etherTypeOffset])
}

func (g *Gateway) buildLLDPMEDFrame(ttl uint16, tags []byte) []byte {
	if g == nil || len(g.cfg.MAC) != 6 {
		return nil
	}
	out := make([]byte, 0, 128)
	out = append(out, lldpNearestBridge[:]...)
	out = append(out, g.cfg.MAC...)
	out = append(out, tags...)
	out = append(out, 0x88, 0xcc)
	out = appendLLDPTLV(out, 1, append([]byte{4}, g.cfg.MAC...)) // chassis ID: MAC address
	out = appendLLDPTLV(out, 2, append([]byte{5}, []byte("gamebond-gateway")...))
	var ttlBytes [2]byte
	binary.BigEndian.PutUint16(ttlBytes[:], ttl)
	out = appendLLDPTLV(out, 3, ttlBytes[:])
	out = appendLLDPTLV(out, 6, []byte("GameBond userspace Layer 2 gateway"))
	// Bridge and router system capabilities; LLDP-MED network policy is supported.
	out = appendLLDPTLV(out, 7, []byte{0x00, 0x14, 0x00, 0x14})
	out = appendLLDPTLV(out, 127, []byte{lldpMEDOUI0, lldpMEDOUI1, lldpMEDOUI2, 1, 0, 0x03, 4})
	if policy := g.cfg.LLDPMEDPolicy; policy != nil {
		var bits uint32
		bits |= uint32(policy.ApplicationType) << 24
		if policy.Tagged {
			bits |= 1 << 22
		}
		bits |= uint32(policy.VLANID&0x0fff) << 9
		bits |= uint32(policy.L2Priority&7) << 6
		bits |= uint32(policy.DSCP & 0x3f)
		value := []byte{lldpMEDOUI0, lldpMEDOUI1, lldpMEDOUI2, lldpMEDNetworkPolicy,
			byte(bits >> 24), byte(bits >> 16), byte(bits >> 8), byte(bits)}
		out = appendLLDPTLV(out, 127, value)
	}
	out = append(out, 0, 0) // End of LLDPDU
	return out
}

func (g *Gateway) sendLLDPMED(ttl uint16, tags []byte) {
	if frame := g.buildLLDPMEDFrame(ttl, tags); frame != nil {
		g.framesOut.Add(1)
		g.tap(false, frame)
		g.cfg.Out(frame)
	}
}

func (g *Gateway) periodicLLDPMED(ctxDone <-chan struct{}) {
	defer g.done.Done()
	ticker := time.NewTicker(g.cfg.LLDPMEDInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctxDone:
			return
		case <-ticker.C:
			g.sendLLDPMED(120, nil)
		}
	}
}

func appendLLDPTLV(frame []byte, typ uint16, value []byte) []byte {
	header := (typ << 9) | uint16(len(value))
	frame = append(frame, byte(header>>8), byte(header))
	return append(frame, value...)
}
