//go:build linux

package edge

import (
	"testing"
	"time"

	"github.com/Dankular/GameBond.Core/bond"
	"golang.org/x/sys/unix"
)

func TestHasEAPOLFrameAcceptsUntaggedAndTaggedOnly(t *testing.T) {
	untagged := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x88, 0x8e}
	tagged := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x81, 0x00, 0, 10, 0x88, 0x8e}
	nonEAPOL := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00}
	if !hasEAPOLFrame(untagged) || !hasEAPOLFrame(tagged) || hasEAPOLFrame(nonEAPOL) || hasEAPOLFrame([]byte{1, 2}) {
		t.Fatal("EAPOL TAP filter did not distinguish EAPOL frames")
	}
}

func TestGatewayQuerierPortBecomesPromiscuousPVLANPrimary(t *testing.T) {
	port := gatewayQuerierPort(bond.L2PortConfig{VLAN: bond.L2VLANPolicy{AccessVLAN: 100}}, &L2Bridge{PrivateVLAN: 7}, [4]byte{10, 0, 0, 1})
	if port.PrivateVLAN != 7 || port.PrivateVLANRole != bond.L2PVLANPromiscuous || port.PVLANPrimaryVLAN != 100 {
		t.Fatalf("gateway service port PVLAN mapping = %+v", port)
	}
}

func TestStandalonePVLANConfigAppliesTunnelToGatewayTagRewrite(t *testing.T) {
	config := &L2Config{
		Enabled:    true,
		TunnelVLAN: bond.L2VLANPolicy{AccessVLAN: 20},
		ExitVLAN:   bond.L2VLANPolicy{AccessVLAN: 10},
		TunnelPrivateVLAN: &L2PrivateVLANPortConfig{
			GroupID: 7, Role: "isolated", PrimaryVLAN: 10, SecondaryVLAN: 20,
		},
		Bridge: &L2Bridge{Address: "10.78.0.1/24", PrivateVLAN: 7},
	}
	switcher := l2Switch(config, "gbpvlan0")
	frame := []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x02, 0, 0, 0, 0, 1,
		0x81, 0x00, 0, 20, 0x08, 0x00,
	}
	frame = append(frame, make([]byte, 46)...)
	verdict := switcher.Forward(l2PortTunnel, frame, time.Unix(1, 0))
	if verdict.Drop != bond.L2Forward || len(verdict.Out) != 1 || verdict.Out[0] != l2PortTap {
		t.Fatalf("isolated PVLAN broadcast should reach only the promiscuous gateway: %+v", verdict)
	}
	egress := verdict.FrameFor(l2PortTap, frame)
	if len(egress) < 18 || egress[14] != 0 || egress[15] != 10 {
		t.Fatalf("gateway egress tag = %v, want primary VLAN 10", egress[12:16])
	}
}

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
