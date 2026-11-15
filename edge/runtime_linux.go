//go:build linux

package edge

import (
	"github.com/Dankular/GameBond.Server/l2gw"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/Dankular/GameBond.Core/bond"
	"github.com/Dankular/GameBond.Core/buildinfo"
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
	options.Version = buildinfo.Commit
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
		if l2, err = openL2(c.L2); err != nil {
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
		watched = append(watched, l2.fd)
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
		if !now.Before(reportAt) {
			stats := engine.Stats(now)
			stats["observed_at"] = now.UTC().Format(time.RFC3339Nano)
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
