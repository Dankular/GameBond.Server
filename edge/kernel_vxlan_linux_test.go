//go:build linux

package edge

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Dankular/GameBond.Core/bond"
)

func validKernelVXLANAttachmentConfig() *L2Config {
	return &L2Config{
		Enabled:                true,
		SegmentSocketPath:      "/run/gamebond/segment.sock",
		SegmentID:              "venue-east",
		TapName:                "gamebond-tap0",
		FrameMTU:               1394,
		ExitVLAN:               bond.L2VLANPolicy{AccessVLAN: 10},
		Bridge:                 &L2Bridge{Address: "10.78.0.1/24"},
		KernelVXLANAttachments: []KernelVXLANAttachment{{ID: "vni-east", TapName: "gbvx-east", VLAN: 10}},
	}
}

func TestKernelVXLANPumpAccountingHelpers(t *testing.T) {
	frame := []byte{1, 2, 3}
	if !forwardKernelVXLANIngress(func(got []byte, _ time.Time) bond.L2Verdict {
		if string(got) != string(frame) {
			t.Fatalf("ingress frame %v", got)
		}
		return bond.L2Verdict{Drop: bond.L2Forward}
	}, frame, time.Now()) {
		t.Fatal("forward verdict counted as reject")
	}
	if forwardKernelVXLANIngress(func([]byte, time.Time) bond.L2Verdict { return bond.L2Verdict{Drop: bond.L2DropVLAN} }, frame, time.Now()) {
		t.Fatal("switch-rejected frame counted as forwarded")
	}
	if !writeKernelVXLANFrame(func(got []byte) (int, error) { return len(got), nil }, frame) {
		t.Fatal("complete TAP write counted as drop")
	}
	if writeKernelVXLANFrame(func(got []byte) (int, error) { return len(got) - 1, nil }, frame) {
		t.Fatal("short TAP write was not counted as drop")
	}
	if writeKernelVXLANFrame(func([]byte) (int, error) { return 0, errors.New("tap failure") }, frame) {
		t.Fatal("TAP write error was not counted as drop")
	}
}

func TestValidateKernelVXLANAttachment(t *testing.T) {
	if err := validKernelVXLANAttachmentConfig().validateKernelVXLANAttachments(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateKernelVXLANAttachmentsRequiresBrokerGatewayAndConfiguredVLAN(t *testing.T) {
	c := validKernelVXLANAttachmentConfig()
	c.Bridge = nil
	if err := c.validateKernelVXLANAttachments(); err == nil || !strings.Contains(err.Error(), "broker segment gateway") {
		t.Fatalf("expected gateway error, got %v", err)
	}
	c = validKernelVXLANAttachmentConfig()
	c.KernelVXLANAttachments[0].VLAN = 20
	if err := c.validateKernelVXLANAttachments(); err == nil || !strings.Contains(err.Error(), "match the configured gateway access VLAN") {
		t.Fatalf("expected VLAN error, got %v", err)
	}
}

func TestValidateKernelVXLANAttachmentsRejectsStaticOverlayCombination(t *testing.T) {
	c := validKernelVXLANAttachmentConfig()
	c.VXLAN = &VXLANConfig{VNI: 10010}
	if err := c.validateKernelVXLANAttachments(); err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("static and kernel VXLAN transports were combined: %v", err)
	}
}

func TestValidateKernelVXLANAttachmentsRejectsDuplicateTAPAndBadVLAN(t *testing.T) {
	c := validKernelVXLANAttachmentConfig()
	c.KernelVXLANAttachments = append(c.KernelVXLANAttachments, KernelVXLANAttachment{ID: "vni-west", TapName: "gbvx-east", VLAN: 10})
	if err := c.validateKernelVXLANAttachments(); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("expected duplicate TAP error, got %v", err)
	}
	c = validKernelVXLANAttachmentConfig()
	c.KernelVXLANAttachments[0].VLAN = 4095
	if err := c.validateKernelVXLANAttachments(); err == nil || !strings.Contains(err.Error(), "range 1..4094") {
		t.Fatalf("expected VLAN range error, got %v", err)
	}
}

func TestValidateKernelVXLANAttachmentsMapsConfiguredVLANSet(t *testing.T) {
	c := validKernelVXLANAttachmentConfig()
	c.Bridge.VLANs = []L2BridgeVLAN{{VLANID: 10, Gateway: &L2Bridge{Address: "10.78.0.1/24"}}, {VLANID: 20, Gateway: &L2Bridge{Address: "10.79.0.1/24"}}}
	c.ExitVLAN = bond.L2VLANPolicy{}
	c.KernelVXLANAttachments = []KernelVXLANAttachment{{ID: "east", TapName: "gbvx-east", VLAN: 10}, {ID: "west", TapName: "gbvx-west", VLAN: 20}}
	if err := c.validateKernelVXLANAttachments(); err != nil {
		t.Fatal(err)
	}
}
