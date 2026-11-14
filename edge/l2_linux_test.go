//go:build linux

package edge

import (
	"testing"
	"time"

	"github.com/Dankular/GameBond.Core/bond"
	"golang.org/x/sys/unix"
)

// htons for the AF_PACKET protocol field.
func htons(v uint16) uint16 { return v<<8 | v>>8 }

func TestL2EdgeDeliversFramesToTheTapAndEnforcesPortPolicy(t *testing.T) {
	e, err := openL2(&L2Config{Enabled: true, TapName: "gbtest-tap0", FrameMTU: 1394, MACLimit: 2})
	if err != nil {
		t.Skip("cannot open a TAP here (needs root and /dev/net/tun):", err)
	}
	defer e.close()
	idx, err := unix.NewIfreq("gbtest-tap0")
	if err != nil {
		t.Fatal(err)
	}
	s, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(s)
	if err = unix.IoctlIfreq(s, unix.SIOCGIFINDEX, idx); err != nil {
		t.Fatal(err)
	}
	raw, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		t.Skip("no AF_PACKET:", err)
	}
	defer unix.Close(raw)
	if err = unix.Bind(raw, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: int(idx.Uint32())}); err != nil {
		t.Fatal(err)
	}
	unix.SetsockoptTimeval(raw, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 2})

	frame := func(src byte) []byte {
		f := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2, 0, 0, 0, 0, src, 0x88, 0xb5}
		return append(f, make([]byte, 50)...)
	}
	now := time.Now()
	if err = e.deliver(bond.WrapFrame(frame(1)), now); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	for {
		n, _, err := unix.Recvfrom(raw, buf, 0)
		if err != nil {
			t.Fatal("frame never reached the TAP:", err)
		}
		if n == len(frame(1)) && buf[11] == 1 {
			break
		}
	}
	e.deliver(bond.WrapFrame(frame(2)), now)
	e.deliver(bond.WrapFrame(frame(3)), now) // third source MAC exceeds the cap of 2
	st := e.Stats(now)
	if st["to_tap"].(uint64) != 2 || st["drop_mac_limit"].(uint64) != 1 || st["fdb_size"].(int) != 2 {
		t.Fatalf("unexpected counters: %v", st)
	}
}
