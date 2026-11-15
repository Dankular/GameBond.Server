//go:build linux

package gateway

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// rtnetlinkLinkAddressReader is the native read boundary used by local Linux
// host management. Remote and test runners can keep using their command adapter.
type rtnetlinkLinkAddressReader interface {
	LinkAddresses(context.Context, string) ([]netip.Addr, error)
}

// Rtnetlink is the local Linux link-control foundation for a GameBond-owned
// gateway. It intentionally exposes link primitives rather than shell syntax.
type Rtnetlink struct{}

var rtnetlinkSequence atomic.Uint32

func (Rtnetlink) SetLinkUp(ctx context.Context, interfaceName string, up bool) error {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return err
	}
	flags := uint32(0)
	if up {
		flags = syscall.IFF_UP
	}
	return rtnetlinkChangeLink(ctx, iface.Index, flags, syscall.IFF_UP, nil)
}

func (Rtnetlink) SetMaster(ctx context.Context, interfaceName, masterName string) error {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return err
	}
	master := uint32(0)
	if masterName != "" {
		masterInterface, err := net.InterfaceByName(masterName)
		if err != nil {
			return err
		}
		master = uint32(masterInterface.Index)
	}
	var attrs []byte
	attrs = appendRtnetlinkAttribute(attrs, syscall.IFLA_MASTER, nativeUint32(master))
	return rtnetlinkChangeLink(ctx, iface.Index, 0, 0, attrs)
}

func (Rtnetlink) SetMTU(ctx context.Context, interfaceName string, mtu int) error {
	if mtu < 68 || mtu > 1<<20 {
		return fmt.Errorf("invalid interface MTU %d", mtu)
	}
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return err
	}
	attrs := appendRtnetlinkAttribute(nil, syscall.IFLA_MTU, nativeUint32(uint32(mtu)))
	return rtnetlinkChangeLink(ctx, iface.Index, 0, 0, attrs)
}

func rtnetlinkChangeLink(ctx context.Context, index int, flags, change uint32, attrs []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if index <= 0 {
		return fmt.Errorf("invalid rtnetlink interface index %d", index)
	}
	seq := rtnetlinkSequence.Add(1)
	request := buildRtnetlinkLinkRequest(index, flags, change, attrs, seq)
	return sendRtnetlinkRequest(ctx, request, seq)
}

func buildRtnetlinkLinkRequest(index int, flags, change uint32, attrs []byte, sequence uint32) []byte {
	body := make([]byte, syscall.SizeofIfInfomsg)
	body[0] = syscall.AF_UNSPEC
	binary.NativeEndian.PutUint32(body[4:8], uint32(int32(index)))
	binary.NativeEndian.PutUint32(body[8:12], flags)
	binary.NativeEndian.PutUint32(body[12:16], change)
	body = append(body, attrs...)
	request := make([]byte, syscall.NLMSG_HDRLEN+len(body))
	binary.NativeEndian.PutUint32(request[0:4], uint32(len(request)))
	binary.NativeEndian.PutUint16(request[4:6], syscall.RTM_NEWLINK)
	binary.NativeEndian.PutUint16(request[6:8], syscall.NLM_F_REQUEST|syscall.NLM_F_ACK)
	binary.NativeEndian.PutUint32(request[8:12], sequence)
	copy(request[syscall.NLMSG_HDRLEN:], body)
	return request
}

func sendRtnetlinkRequest(ctx context.Context, request []byte, sequence uint32) error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}
	timeout := syscall.NsecToTimeval(100 * int64(time.Millisecond))
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &timeout); err != nil {
		return err
	}
	if err := syscall.Sendto(fd, request, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}
	buffer := make([]byte, 16*1024)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, from, err := syscall.Recvfrom(fd, buffer, 0)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK || err == syscall.EINTR {
				continue
			}
			return err
		}
		sender, ok := from.(*syscall.SockaddrNetlink)
		if !ok || sender.Pid != 0 {
			return fmt.Errorf("rtnetlink acknowledgement did not come from the kernel")
		}
		messages, err := syscall.ParseNetlinkMessage(buffer[:n])
		if err != nil {
			return err
		}
		for _, message := range messages {
			if message.Header.Seq != sequence || message.Header.Type != syscall.NLMSG_ERROR || len(message.Data) < 4 {
				continue
			}
			code := int32(binary.NativeEndian.Uint32(message.Data[:4]))
			if code == 0 {
				return nil
			}
			return syscall.Errno(-code)
		}
	}
}

func appendRtnetlinkAttribute(dst []byte, kind uint16, value []byte) []byte {
	length := 4 + len(value)
	aligned := (length + 3) &^ 3
	start := len(dst)
	dst = append(dst, make([]byte, aligned)...)
	binary.NativeEndian.PutUint16(dst[start:start+2], uint16(length))
	binary.NativeEndian.PutUint16(dst[start+2:start+4], kind)
	copy(dst[start+4:start+length], value)
	return dst
}

func nativeUint32(value uint32) []byte {
	var out [4]byte
	binary.NativeEndian.PutUint32(out[:], value)
	return out[:]
}

func rtnetlinkInterfaceAddresses(ctx context.Context, interfaceName string) ([]netip.Addr, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("lookup interface %s: %w", interfaceName, err)
	}
	raw, err := syscall.NetlinkRIB(syscall.RTM_GETADDR, syscall.AF_UNSPEC)
	if err != nil {
		return nil, fmt.Errorf("dump interface addresses over rtnetlink: %w", err)
	}
	messages, err := syscall.ParseNetlinkMessage(raw)
	if err != nil {
		return nil, fmt.Errorf("parse rtnetlink address dump: %w", err)
	}
	addresses := make([]netip.Addr, 0, 4)
	seen := make(map[netip.Addr]struct{})
	for _, message := range messages {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if message.Header.Type != syscall.RTM_NEWADDR || len(message.Data) < syscall.SizeofIfAddrmsg {
			continue
		}
		addressMessage := *(*syscall.IfAddrmsg)(unsafe.Pointer(&message.Data[0]))
		if int(addressMessage.Index) != iface.Index {
			continue
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(&message)
		if err != nil {
			return nil, fmt.Errorf("parse address attributes for %s: %w", interfaceName, err)
		}
		var local netip.Addr
		for _, attr := range attrs {
			if attr.Attr.Type != syscall.IFA_LOCAL && attr.Attr.Type != syscall.IFA_ADDRESS {
				continue
			}
			var candidate netip.Addr
			switch addressMessage.Family {
			case syscall.AF_INET:
				if len(attr.Value) == 4 {
					var bytes [4]byte
					copy(bytes[:], attr.Value)
					candidate = netip.AddrFrom4(bytes)
				}
			case syscall.AF_INET6:
				if len(attr.Value) == 16 {
					var bytes [16]byte
					copy(bytes[:], attr.Value)
					candidate = netip.AddrFrom16(bytes)
				}
			}
			if !candidate.IsValid() {
				continue
			}
			if attr.Attr.Type == syscall.IFA_LOCAL || !local.IsValid() {
				local = candidate
			}
		}
		if local.IsValid() {
			if _, exists := seen[local]; !exists {
				seen[local] = struct{}{}
				addresses = append(addresses, local)
			}
		}
	}
	return addresses, nil
}
