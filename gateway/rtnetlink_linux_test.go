//go:build linux

package gateway

import (
	"context"
	"encoding/binary"
	"net/netip"
	"syscall"
	"testing"
	"unsafe"
)

func TestRtnetlinkInterfaceAddressesReadsLoopback(t *testing.T) {
	addresses, err := rtnetlinkInterfaceAddresses(context.Background(), "lo")
	if err != nil {
		t.Fatal(err)
	}
	want := netip.MustParseAddr("127.0.0.1")
	for _, address := range addresses {
		if address == want {
			return
		}
	}
	t.Fatalf("rtnetlink omitted loopback address %s from %v", want, addresses)
}

func TestBuildRtnetlinkLinkRequestUsesTypedLinkAndMasterAttributes(t *testing.T) {
	attrs := appendRtnetlinkAttribute(nil, syscall.IFLA_MASTER, nativeUint32(9))
	request := buildRtnetlinkLinkRequest(7, 0, 0, attrs, 42)
	messages, err := syscall.ParseNetlinkMessage(request)
	if err != nil || len(messages) != 1 {
		t.Fatalf("parse request: messages=%d err=%v", len(messages), err)
	}
	message := messages[0]
	if message.Header.Type != syscall.RTM_NEWLINK || message.Header.Seq != 42 || len(message.Data) != syscall.SizeofIfInfomsg+8 {
		t.Fatalf("request header = %+v data_len=%d", message.Header, len(message.Data))
	}
	info := *(*syscall.IfInfomsg)(unsafe.Pointer(&message.Data[0]))
	if info.Index != 7 || info.Flags != 0 || info.Change != 0 {
		t.Fatalf("link info = %+v", info)
	}
	attrOffset := syscall.SizeofIfInfomsg
	attrLen := int(binary.NativeEndian.Uint16(message.Data[attrOffset : attrOffset+2]))
	attrType := binary.NativeEndian.Uint16(message.Data[attrOffset+2 : attrOffset+4])
	master := binary.NativeEndian.Uint32(message.Data[attrOffset+4 : attrOffset+8])
	if attrLen != 8 || attrType != syscall.IFLA_MASTER || master != 9 {
		t.Fatalf("master attr len=%d type=%d index=%d", attrLen, attrType, master)
	}
}
