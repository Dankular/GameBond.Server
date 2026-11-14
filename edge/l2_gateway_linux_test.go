//go:build linux

package edge

import (
	"bytes"
	"testing"
	"time"

	"github.com/Dankular/GameBond.Core/bond"
)

// An ARP request for the gateway address, carried over the bond, must come back as an ARP reply
// from the userspace gateway: no TAP, bridge or kernel networking is involved.
func TestL2GatewayAnswersARPOverTheBond(t *testing.T) {
	cfg := &L2Config{Enabled: true, FrameMTU: 1394, Bridge: &L2Bridge{DHCPStart: "10.78.0.100", DHCPEnd: "10.78.0.149"}}
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	e, err := openL2(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer e.close()

	device := [6]byte{0x02, 0, 0, 0, 0, 0x77}
	arp := []byte{0, 1, 8, 0, 6, 4, 0, 1}
	arp = append(arp, device[:]...)
	arp = append(arp, 10, 78, 0, 50)
	arp = append(arp, 0, 0, 0, 0, 0, 0)
	arp = append(arp, 10, 78, 0, 1)
	frame := append([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, device[:]...)
	frame = append(frame, 0x08, 0x06)
	frame = append(frame, arp...)

	if err := e.deliver(bond.WrapFrame(frame), time.Now()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		e.qmu.Lock()
		q := e.q
		e.qmu.Unlock()
		for _, f := range q {
			if len(f) >= 42 && f[12] == 0x08 && f[13] == 0x06 && f[21] == 2 && bytes.Equal(f[38:42], []byte{10, 78, 0, 50}) && bytes.Equal(f[28:32], []byte{10, 78, 0, 1}) {
				if st := e.Stats(time.Now()); st["gateway"] == nil {
					t.Fatal("gateway stats missing")
				}
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no ARP reply from the gateway")
}
