//go:build linux

package edge

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Dankular/GameBond.Core/bond"
	"golang.org/x/sys/unix"
)

// SegmentEAPOLTaps owns one hostapd-facing TAP per MACAuth session identity.
// Core pairs each TAP with exactly one broker-authorized session port.
type SegmentEAPOLTaps struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	taps   []segmentEAPOLTap
	drops  atomic.Uint64
}

type segmentEAPOLTap struct {
	name string
	fd   int
	port *SegmentPort
}

// StartSegmentEAPOLTaps creates dedicated TAP/service pairs for all member
// authorizations that enable MACAuth. Every member must use one access VLAN
// and a unique interface name; trunked MACAuth ports are rejected.
func StartSegmentEAPOLTaps(fabric *SegmentFabric, authorizations map[string]SegmentSocketAuthorization, frameMTU int) (*SegmentEAPOLTaps, error) {
	if fabric == nil || frameMTU < 600 || frameMTU > 1600 {
		return nil, errors.New("segment EAPOL TAPs require a fabric and valid frame MTU")
	}
	taps := &SegmentEAPOLTaps{}
	identities := make([]string, 0, len(authorizations))
	for identity := range authorizations {
		identities = append(identities, identity)
	}
	sort.Strings(identities)
	seenNames := make(map[string]bool)
	for _, identity := range identities {
		authorization := authorizations[identity]
		if !authorization.Port.MACAuth {
			if authorization.EAPOLTapName != "" {
				taps.Close()
				return nil, fmt.Errorf("segment EAPOL TAP %q is configured for non-MACAuth identity %q", authorization.EAPOLTapName, identity)
			}
			continue
		}
		name := authorization.EAPOLTapName
		if len(name) == 0 || len(name) > 15 || strings.ContainsAny(name, " /\t\r\n\x00") || seenNames[name] || authorization.Port.VLAN.AccessVLAN == 0 || len(authorization.Port.VLAN.AllowedVLANs) != 0 || authorization.Port.VLAN.NativeVLAN != 0 {
			taps.Close()
			return nil, fmt.Errorf("segment EAPOL TAP for %q requires a unique interface name and an access VLAN", identity)
		}
		seenNames[name] = true
		fd, err := openTap(name, frameMTU-bond.EthHeaderLen)
		if err != nil {
			taps.Close()
			return nil, fmt.Errorf("open hostapd TAP %s for %q: %w", name, identity, err)
		}
		tapPortConfig := bond.L2PortConfig{
			Name: "eapol-" + identity, VLAN: bond.L2VLANPolicy{AccessVLAN: authorization.Port.VLAN.AccessVLAN},
			EAPOLAuthenticator: true, EAPOLAuthenticatorFor: identity,
		}
		if authorization.Port.PVLANPrimaryVLAN != 0 {
			tapPortConfig.VLAN.AccessVLAN = authorization.Port.PVLANPrimaryVLAN
			tapPortConfig.PrivateVLAN = authorization.Port.PrivateVLAN
			tapPortConfig.PrivateVLANRole = bond.L2PVLANPromiscuous
			tapPortConfig.PVLANPrimaryVLAN = authorization.Port.PVLANPrimaryVLAN
		}
		port, err := fabric.AttachService(tapPortConfig, 0, false, false)
		if err != nil {
			unix.Close(fd)
			taps.Close()
			return nil, fmt.Errorf("attach hostapd TAP %s for %q: %w", name, identity, err)
		}
		taps.taps = append(taps.taps, segmentEAPOLTap{name: name, fd: fd, port: port})
	}
	if len(taps.taps) == 0 {
		return taps, nil
	}
	taps.ctx, taps.cancel = context.WithCancel(context.Background())
	for _, tap := range taps.taps {
		taps.start(tap)
	}
	return taps, nil
}

func (t *SegmentEAPOLTaps) start(tap segmentEAPOLTap) {
	t.wg.Add(2)
	go func() {
		defer t.wg.Done()
		poll := []unix.PollFd{{Fd: int32(tap.fd), Events: unix.POLLIN}}
		buffer := make([]byte, 1600)
		for {
			select {
			case <-t.ctx.Done():
				return
			default:
			}
			poll[0].Revents = 0
			n, err := unix.Poll(poll, 250)
			if err == unix.EINTR {
				continue
			}
			if err != nil {
				return
			}
			if n == 0 || poll[0].Revents&unix.POLLIN == 0 {
				continue
			}
			read, err := unix.Read(tap.fd, buffer)
			if err == unix.EAGAIN || err == unix.EINTR {
				continue
			}
			if err != nil {
				return
			}
			frame := buffer[:read]
			if !hasEAPOLFrame(frame) {
				continue
			}
			if tap.port.Send(frame, time.Now()).Drop != bond.L2Forward {
				t.drops.Add(1)
			}
		}
	}()
	go func() {
		defer t.wg.Done()
		for {
			select {
			case <-t.ctx.Done():
				return
			case delivery, ok := <-tap.port.Receive():
				if !ok {
					return
				}
				if !hasEAPOLFrame(delivery.Frame) {
					continue
				}
				n, err := unix.Write(tap.fd, delivery.Frame)
				if err != nil || n != len(delivery.Frame) {
					t.drops.Add(1)
				}
			}
		}
	}()
}

// Close tears down all broker authenticator attachments and TAP workers.
func (t *SegmentEAPOLTaps) Close() {
	if t == nil {
		return
	}
	if t.cancel != nil {
		t.cancel()
	}
	for _, tap := range t.taps {
		tap.port.Close()
	}
	t.wg.Wait()
	for _, tap := range t.taps {
		if tap.fd >= 0 {
			_ = unix.Close(tap.fd)
		}
	}
	t.taps = nil
}

func hasEAPOLFrame(frame []byte) bool {
	if len(frame) < bond.EthHeaderLen {
		return false
	}
	offset := 12
	typ := binary.BigEndian.Uint16(frame[offset : offset+2])
	for tags := 0; tags < 2 && (typ == 0x8100 || typ == 0x88a8 || typ == 0x9100); tags++ {
		if len(frame) < offset+6 {
			return false
		}
		typ = binary.BigEndian.Uint16(frame[offset+4 : offset+6])
		offset += 4
	}
	return typ == 0x888e
}
