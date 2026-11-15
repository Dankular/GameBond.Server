package edge

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Dankular/GameBond.Core/bond"
)

const (
	vxlanUDPPort      = 4789
	vxlanHeaderLen    = 8
	vxlanMaxVNI       = 1<<24 - 1
	vxlanDefaultMTU   = 1400
	vxlanPeerIdentity = "vxlan-vni-"
	vxlanMaxPeers     = 64
)

// VXLANPeer is a statically configured remote VTEP. For secure deployment,
// Remote must be reachable through a trusted or encrypted underlay (for
// example WireGuard or IPsec); VXLAN itself does not authenticate peers.
type VXLANPeer struct {
	Remote netip.AddrPort `json:"remote"`
}

// VXLANConfig attaches one VNI to a named local segment. The peer set must be
// a full mesh: remote-origin frames are not re-encapsulated, which provides
// split horizon and prevents BUM loops without an EVPN control plane.
type VXLANConfig struct {
	VNI         uint32            `json:"vni"`
	Listen      netip.AddrPort    `json:"listen"`
	Peers       []VXLANPeer       `json:"peers"`
	Port        bond.L2PortConfig `json:"port"`
	FrameMTU    int               `json:"frame_mtu,omitempty"`
	UnderlayMTU int               `json:"underlay_mtu,omitempty"`
}

// VXLANStats reports encapsulation and validation outcomes.
type VXLANStats struct {
	Encapsulated uint64
	Decapsulated uint64
	Invalid      uint64
	SendErrors   uint64
	SwitchDrops  uint64
	SplitHorizon uint64
}

// VXLANOverlay is a static-peer RFC 7348 data plane over UDP. It does not
// implement EVPN route exchange, VTEP discovery, or peer authentication.
type VXLANOverlay struct {
	conn         *net.UDPConn
	ports        map[netip.AddrPort]*SegmentPort
	mtu          int
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	close        sync.Once
	encapsulated atomic.Uint64
	decapsulated atomic.Uint64
	invalid      atomic.Uint64
	sendErrors   atomic.Uint64
	switchDrops  atomic.Uint64
	splitHorizon atomic.Uint64
}

// AttachVXLAN binds a UDP VTEP and attaches one switch port per remote peer.
// Incoming datagrams are accepted only from the configured endpoint carrying
// the configured VNI. The caller must place this UDP path on a trusted or
// encrypted underlay because VXLAN provides no cryptographic protection.
func AttachVXLAN(ctx context.Context, fabric *SegmentFabric, cfg VXLANConfig) (*VXLANOverlay, error) {
	if ctx == nil || fabric == nil || fabric.Identity() == "" {
		return nil, errors.New("vxlan: context and named segment fabric are required")
	}
	if cfg.VNI == 0 || cfg.VNI > vxlanMaxVNI {
		return nil, errors.New("vxlan: VNI must be in range 1..16777215")
	}
	if !cfg.Listen.IsValid() || (!cfg.Listen.Addr().Is4() && !cfg.Listen.Addr().Is6()) {
		return nil, errors.New("vxlan: listen address must be a valid IP endpoint")
	}
	if len(cfg.Peers) == 0 || len(cfg.Peers) > vxlanMaxPeers {
		return nil, fmt.Errorf("vxlan: peer list must contain 1..%d endpoints", vxlanMaxPeers)
	}
	if cfg.FrameMTU == 0 {
		cfg.FrameMTU = vxlanDefaultMTU
	}
	if cfg.UnderlayMTU == 0 {
		cfg.UnderlayMTU = 1500
	}
	if cfg.FrameMTU < bond.EthHeaderLen || cfg.FrameMTU > 65507-vxlanHeaderLen {
		return nil, errors.New("vxlan: frame MTU must be 14..65499 bytes")
	}
	outerIPHeader := 20
	if cfg.Listen.Addr().Is6() {
		outerIPHeader = 40
	}
	if cfg.FrameMTU+outerIPHeader+8+vxlanHeaderLen > cfg.UnderlayMTU {
		return nil, fmt.Errorf("vxlan: inner frame MTU %d plus encapsulation headers exceeds underlay MTU %d", cfg.FrameMTU, cfg.UnderlayMTU)
	}
	if cfg.Port.VLAN.AccessVLAN == 0 && len(cfg.Port.VLAN.AllowedVLANs) == 0 {
		return nil, errors.New("vxlan: peer port requires an explicit access VLAN or trunk allow-list")
	}
	if err := cfg.Port.VLAN.Validate(); err != nil {
		return nil, fmt.Errorf("vxlan: port VLAN policy: %w", err)
	}
	peers := make(map[netip.AddrPort]bool, len(cfg.Peers))
	for _, peer := range cfg.Peers {
		remote := peer.Remote
		if !remote.IsValid() || remote.Port() == 0 || remote.Addr().IsUnspecified() || remote.Addr().IsMulticast() || remote.Addr().Is4In6() {
			return nil, fmt.Errorf("vxlan: invalid remote VTEP %q", remote)
		}
		if peers[remote] {
			return nil, fmt.Errorf("vxlan: duplicate remote VTEP %q", remote)
		}
		if remote.Addr().Is4() != cfg.Listen.Addr().Is4() {
			return nil, fmt.Errorf("vxlan: remote VTEP %q address family does not match the listen endpoint", remote)
		}
		peers[remote] = true
	}
	localPort := cfg.Listen.Port()
	if localPort == 0 {
		localPort = vxlanUDPPort
	}
	conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(cfg.Listen.Addr(), localPort)))
	if err != nil {
		return nil, fmt.Errorf("vxlan: listen: %w", err)
	}
	return attachVXLANConn(ctx, fabric, cfg, conn)
}

func attachVXLANConn(ctx context.Context, fabric *SegmentFabric, cfg VXLANConfig, conn *net.UDPConn) (*VXLANOverlay, error) {
	overlayCtx, cancel := context.WithCancel(ctx)
	overlay := &VXLANOverlay{conn: conn, ports: make(map[netip.AddrPort]*SegmentPort), mtu: cfg.FrameMTU, cancel: cancel}
	for _, peer := range cfg.Peers {
		remote := peer.Remote
		portCfg := cfg.Port
		// A remote VTEP may have the only listener for a snooped group on this
		// fabric. Always send multicast to the overlay; the remote switch applies
		// its own membership filters before delivering to local ports.
		portCfg.MulticastRouter = true
		portCfg.Name = fmt.Sprintf("vxlan-vni-%d-%s", cfg.VNI, remote.String())
		port, err := fabric.AttachService(portCfg, 256, false, false)
		if err != nil {
			overlay.Close()
			return nil, fmt.Errorf("vxlan: attach VTEP %q: %w", remote, err)
		}
		overlay.ports[remote] = port
		overlay.wg.Add(1)
		go overlay.encapsulateToPeer(overlayCtx, cfg.VNI, remote, port)
	}
	overlay.wg.Add(1)
	go overlay.decapsulateFromPeers(overlayCtx, cfg.VNI)
	return overlay, nil
}

func (v *VXLANOverlay) encapsulateToPeer(ctx context.Context, vni uint32, remote netip.AddrPort, port *SegmentPort) {
	defer v.wg.Done()
	peer := net.UDPAddrFromAddrPort(remote)
	for {
		select {
		case <-ctx.Done():
			return
		case delivery, ok := <-port.Receive():
			if !ok {
				return
			}
			if len(delivery.IngressIdentity) >= len(vxlanPeerIdentity) && delivery.IngressIdentity[:len(vxlanPeerIdentity)] == vxlanPeerIdentity {
				v.splitHorizon.Add(1)
				continue
			}
			packet, ok := encodeVXLAN(vni, delivery.Frame, v.mtu)
			if !ok {
				v.invalid.Add(1)
				continue
			}
			if _, err := v.conn.WriteToUDP(packet, peer); err != nil {
				v.sendErrors.Add(1)
				continue
			}
			v.encapsulated.Add(1)
		}
	}
}

func (v *VXLANOverlay) decapsulateFromPeers(ctx context.Context, vni uint32) {
	defer v.wg.Done()
	// Read one byte beyond the configured limit so oversized datagrams cannot
	// be mistaken for a valid truncated packet by UDP's bounded read buffer.
	buf := make([]byte, v.mtu+vxlanHeaderLen+1)
	for {
		_ = v.conn.SetReadDeadline(time.Now().Add(time.Second))
		n, source, err := v.conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			v.invalid.Add(1)
			continue
		}
		remote := source.AddrPort()
		port := v.ports[remote]
		if port == nil {
			v.invalid.Add(1)
			continue
		}
		frame, ok := decodeVXLAN(buf[:n], vni, v.mtu)
		if !ok {
			v.invalid.Add(1)
			continue
		}
		if verdict := port.Send(frame, time.Now()); verdict.Drop != bond.L2Forward {
			v.switchDrops.Add(1)
			continue
		}
		v.decapsulated.Add(1)
	}
}

// encodeVXLAN builds the standard 8-byte VXLAN header followed by an inner
// Ethernet frame. Security must be supplied by the underlay.
func encodeVXLAN(vni uint32, frame []byte, mtu int) ([]byte, bool) {
	if vni == 0 || vni > vxlanMaxVNI || len(frame) < bond.EthHeaderLen || len(frame) > mtu || mtu > 65507-vxlanHeaderLen {
		return nil, false
	}
	out := make([]byte, vxlanHeaderLen+len(frame))
	out[0] = 0x08 // I flag; all reserved bits and fields are zero.
	out[4], out[5], out[6] = byte(vni>>16), byte(vni>>8), byte(vni)
	copy(out[vxlanHeaderLen:], frame)
	return out, true
}

func decodeVXLAN(packet []byte, vni uint32, mtu int) ([]byte, bool) {
	if len(packet) < vxlanHeaderLen+bond.EthHeaderLen || len(packet)-vxlanHeaderLen > mtu || packet[0] != 0x08 || packet[1] != 0 || packet[2] != 0 || packet[3] != 0 || packet[7] != 0 {
		return nil, false
	}
	gotVNI := uint32(packet[4])<<16 | uint32(packet[5])<<8 | uint32(packet[6])
	if gotVNI != vni {
		return nil, false
	}
	return append([]byte(nil), packet[vxlanHeaderLen:]...), true
}

// Addr returns the local UDP endpoint selected by the operating system.
func (v *VXLANOverlay) Addr() netip.AddrPort {
	if v == nil || v.conn == nil {
		return netip.AddrPort{}
	}
	addr, ok := v.conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}
	}
	return addr.AddrPort()
}

// Stats snapshots the current VXLAN transport counters.
func (v *VXLANOverlay) Stats() VXLANStats {
	if v == nil {
		return VXLANStats{}
	}
	return VXLANStats{Encapsulated: v.encapsulated.Load(), Decapsulated: v.decapsulated.Load(), Invalid: v.invalid.Load(), SendErrors: v.sendErrors.Load(), SwitchDrops: v.switchDrops.Load(), SplitHorizon: v.splitHorizon.Load()}
}

// Close stops transport workers and removes their service ports.
func (v *VXLANOverlay) Close() error {
	if v == nil {
		return nil
	}
	var closeErr error
	v.close.Do(func() {
		v.cancel()
		closeErr = v.conn.Close()
		v.wg.Wait()
		for _, port := range v.ports {
			port.Close()
		}
	})
	return closeErr
}

// buildVXLANHeader writes the RFC 7348 header for tests and shared codecs.
func buildVXLANHeader(vni uint32) []byte {
	header := make([]byte, vxlanHeaderLen)
	header[0] = 0x08
	binary.BigEndian.PutUint32(header[4:8], vni<<8)
	return header
}
