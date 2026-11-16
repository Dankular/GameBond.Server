//go:build linux

package edge

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/Dankular/GameBond.Core/bond"
	"github.com/Dankular/GameBond.Core/buildinfo"
	"github.com/Dankular/GameBond.Server/l2gw"
	"golang.org/x/sys/unix"
)

func openTun(name string) (int, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	request, err := unix.NewIfreq(name)
	if err != nil {
		unix.Close(fd)
		return -1, err
	}
	request.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_TUN_EXCL)
	if err = unix.IoctlIfreq(fd, unix.TUNSETIFF, request); err != nil {
		unix.Close(fd)
		return -1, err
	}
	if request.Name() != name {
		unix.Close(fd)
		return -1, fmt.Errorf("unexpected TUN interface")
	}
	return fd, nil
}

// tap, when set, sees every IPv4 packet crossing the TUN: fromDevice is the leg a device sent toward the internet
// (after it was written to the TUN), false the leg read from the TUN toward a device. It runs on the packet loop, so
// it must only parse and count.
var tap atomic.Pointer[func(fromDevice bool, packet []byte)]

// SetTap installs (or, with nil, removes) the packet observer.
func SetTap(f func(fromDevice bool, packet []byte)) {
	if f == nil {
		tap.Store(nil)
		return
	}
	tap.Store(&f)
}

// dnsFilter is the filtering resolver the userspace L2 gateway hands bridged devices' DNS to.
var dnsFilter atomic.Pointer[l2gw.DNSHook]

// SetDNSFilter installs (or, with nil, removes) the filtering resolver for bridged devices.
func SetDNSFilter(h *l2gw.DNSHook) { dnsFilter.Store(h) }

// Run owns the packet state on one epoll actor. All UDP/TUN I/O is nonblocking;
// neither a bulk pacing wait nor device backpressure can stop control/priority.
// Address, link-up and NAT setup belong to the container's existing entrypoint.
func Run(ctx context.Context, c Config, options bond.SessionOptions, address netip.AddrPort, session, key []byte, output io.Writer, observers ...func(map[string]any)) error {
	return run(ctx, c, options, address, session, key, output, nil, observers...)
}

// RunWithSegmentFabric runs one Layer 2 session as an attachment to an in-process
// shared segment. Multiple callers in the same process can pass the same fabric.
// Each authenticated session is one port identified by its session ID. The segment
// supervisor attaches one shared gateway/service port separately.
// This API does not connect separate processes or hosts.
func RunWithSegmentFabric(ctx context.Context, c Config, options bond.SessionOptions, address netip.AddrPort, session, key []byte, output io.Writer, fabric *SegmentFabric, observers ...func(map[string]any)) error {
	if fabric == nil {
		return errors.New("shared Layer 2 fabric is required")
	}
	if c.L2 == nil || !c.L2.Enabled {
		return errors.New("shared Layer 2 fabric requires l2.enabled")
	}
	if c.L2.Bridge != nil {
		return errors.New("shared Layer 2 fabric requires a single separately attached gateway service; per-session gVisor gateways are unsupported")
	}
	if c.L2.SegmentID == "" || c.L2.SegmentID != fabric.Identity() {
		return errors.New("shared Layer 2 fabric identity must match l2.segment_id")
	}
	return run(ctx, c, options, address, session, key, output, fabric, observers...)
}

// RunWithSegmentGateway attaches one gVisor router and DHCP service to a named
// in-process segment. Start exactly one gateway per segment; session attachments
// use RunWithSegmentFabric and frames are switched before reaching this router.
func RunWithSegmentGateway(ctx context.Context, c Config, output io.Writer, fabric *SegmentFabric, observers ...func(map[string]any)) error {
	if fabric == nil {
		return errors.New("shared Layer 2 fabric is required")
	}
	if c.L2 == nil || !c.L2.Enabled || c.L2.Bridge == nil {
		return errors.New("shared segment gateway requires l2.bridge")
	}
	if err := c.L2.validate(); err != nil {
		return err
	}
	if c.L2.SegmentID == "" || c.L2.SegmentID != fabric.Identity() {
		return errors.New("shared gateway fabric identity must match l2.segment_id")
	}
	type gatewayInput struct {
		edge     *l2Edge
		delivery SegmentFrame
	}
	var gateways []*l2Edge
	open := func(l2 *L2Config) error {
		e, err := openGateway(l2, fabric)
		if err != nil {
			return err
		}
		gateways = append(gateways, e)
		return nil
	}
	if len(c.L2.Bridge.VLANs) == 0 {
		if err := open(c.L2); err != nil {
			return err
		}
	} else {
		for _, entry := range c.L2.Bridge.VLANs {
			l2 := *c.L2
			gateway := *entry.Gateway
			gateway.LLDPMEDPolicy = entry.LLDPMEDPolicy
			l2.Bridge = &gateway
			l2.ExitVLAN = bond.L2VLANPolicy{AccessVLAN: entry.VLANID}
			if err := open(&l2); err != nil {
				for _, e := range gateways {
					e.close()
				}
				return err
			}
		}
	}
	defer func() {
		for _, e := range gateways {
			e.close()
		}
	}()
	if len(gateways) == 0 {
		return errors.New("shared segment has no gateway VLANs")
	}
	var vxlan *VXLANOverlay
	if c.L2.VXLAN != nil {
		var err error
		vxlan, err = AttachVXLAN(ctx, fabric, *c.L2.VXLAN)
		if err != nil {
			for _, e := range gateways {
				e.close()
			}
			return fmt.Errorf("start static VXLAN overlay: %w", err)
		}
		defer vxlan.Close()
	}
	kernelVXLAN, err := startKernelVXLANAttachments(ctx, c.L2, fabric)
	if err != nil {
		return fmt.Errorf("start kernel VXLAN segment attachments: %w", err)
	}
	defer kernelVXLAN.Close()
	if c.L2.Monitor != nil {
		monitorFD, err := openMonitorTap(c.L2)
		if err != nil {
			for _, e := range gateways {
				e.close()
			}
			return fmt.Errorf("open segment monitor TAP: %w", err)
		}
		monitorPort, err := fabric.AttachMonitor(c.L2.Monitor.TapName, 0)
		if err != nil {
			unix.Close(monitorFD)
			for _, e := range gateways {
				e.close()
			}
			return fmt.Errorf("attach segment monitor port: %w", err)
		}
		defer func() {
			monitorPort.Close()
			unix.Close(monitorFD)
		}()
		go func() {
			for delivery := range monitorPort.Receive() {
				if n, err := unix.Write(monitorFD, delivery.Frame); err != nil || n != len(delivery.Frame) {
					fabric.RecordMonitorTAPDrop()
				}
			}
		}()
	}
	// The Core switch keeps link-local multicast inside one VLAN. The only
	// cross-VLAN mDNS path is this explicit, mutual pair allow-list, and each
	// destination gateway's access port applies the destination VLAN policy.
	mdnsTargets := make(map[uint16][]*l2Edge)
	mdnsByVLAN := make(map[uint16]*l2Edge, len(gateways))
	var mdnsRelayDrops uint64
	for _, gateway := range gateways {
		mdnsByVLAN[gateway.config.ExitVLAN.AccessVLAN] = gateway
	}
	mdnsUnicast := newMDNSUnicastTracker()
	if len(c.L2.Bridge.VLANs) > 0 {
		for _, entry := range c.L2.Bridge.VLANs {
			for _, targetID := range entry.MDNSRelayTo {
				if target := mdnsByVLAN[targetID]; target != nil {
					mdnsTargets[entry.VLANID] = append(mdnsTargets[entry.VLANID], target)
				}
			}
		}
	}
	activeSnapshot := append([]*l2Edge(nil), gateways...)
	activeSegmentL2.Store(&activeSnapshot)
	defer activeSegmentL2.CompareAndSwap(&activeSnapshot, nil)
	if output != nil {
		ports := make([]int, 0, len(gateways))
		for _, e := range gateways {
			ports = append(ports, int(e.servicePort.ID()))
		}
		status := map[string]any{"status": "segment_gateway_running", "segment_id": fabric.Identity(), "service_ports": ports}
		if vxlan != nil {
			status["vxlan"] = map[string]any{"state": "running", "vni": c.L2.VXLAN.VNI, "local": vxlan.Addr().String(), "peer_count": len(c.L2.VXLAN.Peers)}
		}
		if len(c.L2.KernelVXLANAttachments) > 0 {
			status["kernel_vxlan_attachments"] = map[string]any{"state": "running", "attachments": kernelVXLAN.Stats()}
		}
		if err := json.NewEncoder(output).Encode(status); err != nil {
			return err
		}
	}
	incoming := make(chan gatewayInput, 1024)
	for _, gateway := range gateways {
		go func(e *l2Edge) {
			for delivery := range e.servicePort.Receive() {
				select {
				case incoming <- gatewayInput{edge: e, delivery: delivery}:
				case <-ctx.Done():
					return
				}
			}
		}(gateway)
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case item := <-incoming:
			now := time.Now()
			if responses, matched := mdnsUnicast.reflectResponse(item.delivery.Frame, item.edge.config.ExitVLAN.AccessVLAN, now); matched {
				if len(responses) == 0 {
					mdnsRelayDrops++
					item.edge.switchDrops.Add(1)
				}
				for _, response := range responses {
					if origin := mdnsByVLAN[response.vlan]; origin != nil && origin.servicePort.Send(response.frame, now).Drop != bond.L2Forward {
						mdnsRelayDrops++
						origin.switchDrops.Add(1)
					}
				}
				continue // consume the relayed unicast answer instead of routing it through the gateway.
			}
			if !isMDNSRelayFrame(item.delivery.Frame) {
				if relayFrame, ok := prepareMDNSRelayFrame(item.delivery.Frame); ok {
					for _, target := range mdnsTargets[item.edge.config.ExitVLAN.AccessVLAN] {
						if !mdnsUnicast.rememberQuery(item.delivery.Frame, item.edge.config.ExitVLAN.AccessVLAN, target.config.ExitVLAN.AccessVLAN, now) {
							mdnsRelayDrops++
							item.edge.switchDrops.Add(1)
							continue // fail closed if a reply cannot be mapped to its authorized query origin.
						}
						if target.servicePort.Send(relayFrame, now).Drop != bond.L2Forward {
							mdnsRelayDrops++
							target.switchDrops.Add(1)
						}
					}
				}
			}
			item.edge.gw.InboundFrom(item.delivery.Frame, item.delivery.IngressIdentity)
			if isDHCPv4LeaseFrame(item.delivery.Frame) {
				if err := refreshDHCPSourceGuardBindings(fabric, gateways); err != nil {
					return err
				}
			}
		case now := <-tick.C:
			fabric.Sweep(now)
			fabric.EmitMulticastQueries(now)
			fabric.EmitRSTPBPDUs(now) // Queue pressure is visible in segment queue-drop counters.
			if err := refreshDHCPSourceGuardBindings(fabric, gateways); err != nil {
				return err
			}
			var layer2 any
			if len(gateways) == 1 {
				layer2 = gateways[0].Stats(now)
			} else {
				rows := make([]any, 0, len(gateways))
				for _, e := range gateways {
					rows = append(rows, e.Stats(now))
				}
				layer2 = map[string]any{"segment_id": fabric.Identity(), "gateways": rows}
			}
			observation := map[string]any{"observed_at": now.UTC().Format(time.RFC3339Nano), "l2": layer2}
			observation["mdns_relay"] = map[string]any{"relay_drops": mdnsRelayDrops}
			if vxlan != nil {
				observation["vxlan"] = vxlan.Stats()
			}
			if len(c.L2.KernelVXLANAttachments) > 0 {
				observation["kernel_vxlan_attachments"] = kernelVXLAN.Stats()
			}
			for _, observe := range observers {
				observe(observation)
			}
		}
	}
}

func refreshDHCPSourceGuardBindings(fabric *SegmentFabric, gateways []*l2Edge) error {
	byIdentity := make(map[string][]bond.L2SourceBinding)
	for _, gateway := range gateways {
		if gateway == nil || gateway.gw == nil || gateway.config == nil {
			continue
		}
		vlan := gateway.config.ExitVLAN.AccessVLAN
		for _, lease := range gateway.gw.DHCPBindings() {
			if lease.SessionPort == "" || (!lease.IP.Is4() && !lease.IP.Is6()) {
				continue
			}
			mac, err := net.ParseMAC(lease.MAC)
			if err != nil || len(mac) != 6 {
				continue
			}
			var address [6]byte
			copy(address[:], mac)
			byIdentity[lease.SessionPort] = append(byIdentity[lease.SessionPort], bond.L2SourceBinding{VLAN: vlan, IP: lease.IP, MAC: address})
		}
	}
	return fabric.ReplaceDHCPSourceBindings(byIdentity)
}

func run(ctx context.Context, c Config, options bond.SessionOptions, address netip.AddrPort, session, key []byte, output io.Writer, fabric *SegmentFabric, observers ...func(map[string]any)) error {
	options.Version = buildinfo.Commit
	// ECN decapsulation is unavailable in the published Core dependency yet.
	// Keep it unnegotiated until the Core release containing UDPWithOuterECN lands.
	// The update probe drops this file just before it replaces the container, so clients can
	// tell a planned restart from an outage.
	options.State = func() string {
		if _, err := os.Stat("/tmp/gamebond-updating"); err == nil {
			return "updating"
		}
		// A draining exit says so, with how many flows it still carries, so clients steer new flows elsewhere.
		if flows, draining := l2Draining(); draining {
			return "draining:" + strconv.Itoa(flows)
		}
		return ""
	}
	engine, err := bond.NewSession(key, session, options)
	if err != nil {
		return err
	}
	var stateSync *failoverStateSync
	if c.ExitBackbone != nil {
		stateSync, err = startFailoverStateSync(ctx, c.ExitBackbone, key, session)
		if err != nil {
			return fmt.Errorf("start private exit failover state sync: %w", err)
		}
		defer stateSync.Close()
	}
	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(sock)
	if err = unix.SetsockoptInt(sock, unix.SOL_SOCKET, unix.SO_SNDBUF, 65536); err != nil {
		return err
	}
	if err = unix.SetsockoptInt(sock, unix.SOL_SOCKET, unix.SO_RCVBUF, 4*1024*1024); err != nil {
		return err
	}
	if err = configurePathMTUDiscoverySocket(sock, options.PathMTUDiscovery); err != nil {
		return err
	}
	forceErr := unix.SetsockoptInt(sock, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, 4*1024*1024)
	local := &unix.SockaddrInet4{Port: int(address.Port()), Addr: address.Addr().As4()}
	if err = unix.Bind(sock, local); err != nil {
		return err
	}
	tun, err := openTun(c.TunName)
	if err != nil {
		return err
	}
	defer unix.Close(tun)
	var l2 *l2Edge
	if c.L2 != nil && c.L2.Enabled {
		if l2, err = openL2WithFabric(c.L2, fabric, hex.EncodeToString(session)); err != nil {
			return err
		}
		if err = l2.startFabric(ctx); err != nil {
			l2.close()
			return err
		}
		defer l2.close()
	}
	poller, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return err
	}
	defer unix.Close(poller)
	watched := []int{sock, tun}
	if l2 != nil {
		if l2.fd >= 0 {
			watched = append(watched, l2.fd)
		}
		if l2.notifyFD >= 0 && l2.notifyFD != l2.fd {
			watched = append(watched, l2.notifyFD)
		}
	}
	for _, fd := range watched {
		if err = unix.EpollCtl(poller, unix.EPOLL_CTL_ADD, fd, &unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(fd)}); err != nil {
			return err
		}
	}
	write := func(d bond.Datagram) error {
		if !d.Endpoint.Addr().Is4() {
			return bond.ErrFrame
		}
		return unix.Sendto(sock, d.Frame, unix.MSG_DONTWAIT, &unix.SockaddrInet4{Port: int(d.Endpoint.Port()), Addr: d.Endpoint.Addr().As4()})
	}
	inject := func(packet []byte) error {
		if len(packet) > 0 && packet[0] == bond.L2Marker {
			if l2 == nil {
				return bond.ErrPacketRejected
			}
			return l2.deliver(packet, time.Now())
		}
		n, err := unix.Write(tun, packet)
		if err == unix.EAGAIN || err == unix.ENOBUFS || err == unix.ENETDOWN {
			return bond.ErrWouldBlock
		}
		if err == unix.EINVAL || err == unix.EMSGSIZE {
			return bond.ErrPacketRejected
		}
		if err != nil {
			return err
		}
		if n != len(packet) {
			return io.ErrShortWrite
		}
		if t := tap.Load(); t != nil {
			(*t)(true, packet)
		}
		return nil
	}
	encoder := json.NewEncoder(output)
	receiveBuffer, _ := unix.GetsockoptInt(sock, unix.SOL_SOCKET, unix.SO_RCVBUF)
	sendBuffer, _ := unix.GetsockoptInt(sock, unix.SOL_SOCKET, unix.SO_SNDBUF)
	if err = encoder.Encode(map[string]any{"status": "running", "backend": "native_go", "tun": c.TunName, "bind": address.String(), "actual_receive_buffer_bytes": receiveBuffer, "actual_send_buffer_bytes": sendBuffer, "receive_buffer_force_succeeded": forceErr == nil}); err != nil {
		return err
	}
	buffer := make([]byte, 65536)
	events := make([]unix.EpollEvent, 4)
	next := time.Now()
	nextStateSync := next
	var lastData bond.SessionStats
	var lastDataAt time.Time
	stateReplicated := false
	var stateRevision uint64
	reportAt := next.Add(time.Second)
	for ctx.Err() == nil {
		now := time.Now()
		wait := int((next.Sub(now) + time.Millisecond - 1) / time.Millisecond)
		if wait < 0 {
			wait = 0
		}
		if wait > 2 {
			wait = 2
		}
		n, err := unix.EpollWait(poller, events, wait)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		for _, event := range events[:n] {
			fd := int(event.Fd)
			for batch := 0; batch < 64; batch++ {
				if fd == sock {
					size, from, err := unix.Recvfrom(sock, buffer, unix.MSG_DONTWAIT)
					if err == unix.EAGAIN {
						break
					}
					if err == unix.EINTR {
						continue
					}
					if transientSocketError(err) {
						break // a passing resource or ICMP condition; the next epoll wake retries
					}
					if err != nil {
						return err
					}
					peer, ok := from.(*unix.SockaddrInet4)
					if !ok {
						continue
					}
					if err = engine.UDP(buffer[:size], netip.AddrPortFrom(netip.AddrFrom4(peer.Addr), uint16(peer.Port)), time.Now(), write); err != nil {
						return err
					}
				} else if l2 != nil && l2.gw != nil && fd == l2.fd {
					l2.drainGateway(engine, time.Now())
					break
				} else if l2 != nil && fd == l2.notifyFD {
					l2.drainFabric(engine, time.Now())
					break
				} else if l2 != nil && fd == l2.fd {
					size, err := unix.Read(l2.fd, buffer)
					if err == unix.EAGAIN {
						break
					}
					if err == unix.EINTR {
						continue
					}
					if err != nil {
						return err
					}
					if size > 0 {
						l2.fromTapFrame(buffer[:size], engine, time.Now())
					}
				} else if fd == tun {
					size, err := unix.Read(tun, buffer)
					if err == unix.EAGAIN {
						break
					}
					if err == unix.EINTR {
						continue
					}
					if err != nil {
						return err
					}
					if size == 0 {
						return io.EOF
					}
					if t := tap.Load(); t != nil {
						(*t)(false, buffer[:size])
					}
					engine.TUN(buffer[:size], time.Now())
				}
			}
		}
		now = time.Now()
		next, err = engine.Pump(now, write, inject)
		if err != nil {
			return err
		}
		if stateSync != nil {
			for {
				select {
				case state := <-stateSync.Incoming():
					// A warmed exit can receive snapshots before its own client
					// handshake is ready; a later active snapshot will retry.
					// Once this exit has handled local user data, it is the new
					// authority and must not be rolled back by a delayed old-exit copy.
					if lastDataAt.IsZero() && state.Revision > stateRevision && engine.RestoreFailoverState(state) == nil {
						lastData, lastDataAt = state.Stats, time.Time{}
						stateReplicated = true
						stateRevision = state.Revision
						stateSync.Applied()
					} else {
						stateSync.Rejected()
					}
				default:
					goto stateSyncDrained
				}
			}
		stateSyncDrained:
			packets := engine.PacketStats()
			if packets.InboundPackets != lastData.InboundPackets || packets.OutboundPackets != lastData.OutboundPackets || packets.L2Frames != lastData.L2Frames {
				if stateReplicated {
					engine.ActivateFailoverState()
					stateReplicated = false
				}
				lastData, lastDataAt = packets, now
			}
			if !lastDataAt.IsZero() && now.Sub(lastDataAt) <= 250*time.Millisecond && !now.Before(nextStateSync) {
				stateRevision++
				state, snapshotErr := engine.SnapshotFailoverState(now, stateRevision)
				if snapshotErr == nil {
					_ = stateSync.Publish(state)
				}
				nextStateSync = now.Add(100 * time.Millisecond)
			}
		}
		if !now.Before(reportAt) {
			if l2 != nil {
				l2.emitMulticastQueries(engine, now)
				l2.emitRSTPBPDUs(engine, now)
			}
			stats := engine.Stats(now)
			stats["observed_at"] = now.UTC().Format(time.RFC3339Nano)
			if stateSync != nil {
				stats["failover_state_sync"] = stateSync.Stats()
			}
			if l2 != nil {
				stats["l2"] = l2.Stats(now)
			}
			for _, observe := range observers {
				observe(stats)
			}
			if err = encoder.Encode(stats); err != nil {
				return err
			}
			reportAt = now.Add(time.Second)
		}
	}
	if err = encoder.Encode(map[string]any{"status": "stopped", "backend": "native_go"}); err != nil && !errors.Is(err, io.ErrClosedPipe) {
		return err
	}
	return nil
}

// configurePathMTUDiscoverySocket prevents IPv4 fragmentation on the outer
// UDP path so authenticated DPLPMTUD probes confirm an unfragmented packet size.
func configurePathMTUDiscoverySocket(fd int, enabled bool) error {
	if !enabled {
		return nil
	}
	return unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO)
}

// transientSocketError reports receive errors that say nothing about the socket's health
// (buffer or memory pressure, or an ICMP error surfaced on read) and must not stop the server.
func transientSocketError(err error) bool {
	for _, e := range []error{unix.ENOBUFS, unix.ENOMEM, unix.ECONNREFUSED, unix.ECONNRESET, unix.EHOSTUNREACH, unix.ENETUNREACH, unix.EMSGSIZE} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}
