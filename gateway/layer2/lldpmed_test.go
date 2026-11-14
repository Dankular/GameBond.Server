package layer2

import (
	"strings"
	"testing"
)

func TestRenderLLDPMEDConfigRemovesOldPoliciesBeforeAdvertisingNew(t *testing.T) {
	previous, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	previous.Bridges[0].Ports[0].VoiceNetwork = "voice"
	desired := previous
	desired.Bridges = append([]Bridge(nil), previous.Bridges...)
	desired.Bridges[0].Ports = append([]BridgePort(nil), previous.Bridges[0].Ports...)
	desired.Bridges[0].Ports[0].LLDPMED = []LLDPMEDPolicy{{Application: "voice-signaling", Network: "voice", Tagged: true}}
	got, err := RenderLLDPMEDConfig(previous, desired)
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	remove := "unconfigure ports enp2s0 med policy application voice"
	voice := "configure ports enp2s0 med policy application voice tagged vlan 20"
	signal := "configure ports enp2s0 med policy application voice-signaling tagged vlan 20"
	if !strings.Contains(text, remove) || !strings.Contains(text, voice) || !strings.Contains(text, signal) {
		t.Fatalf("missing managed LLDP-MED policy commands:\n%s", text)
	}
	if strings.Index(text, remove) > strings.Index(text, voice) {
		t.Fatalf("previous policies must be removed before new policies are configured:\n%s", text)
	}
}

func TestRenderLLDPMEDConfigRejectsInvalidConfig(t *testing.T) {
	desired, err := DecodeConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	desired.Bridges[0].Ports[0].VoiceNetwork = "missing"
	if _, err := RenderLLDPMEDConfig(Config{}, desired); err == nil {
		t.Fatal("invalid voice network reached LLDP-MED renderer")
	}
}
