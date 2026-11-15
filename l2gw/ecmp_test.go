package l2gw

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func TestSelectECMPPathIsFlowStableAndWeighted(t *testing.T) {
	paths := []ECMPPath{{Name: "wan-a", Interface: "eth0", Weight: 1}, {Name: "wan-b", Interface: "eth1", Weight: 3}}
	counts := map[string]int{}
	for i := 0; i < 4000; i++ {
		key := []byte(fmt.Sprintf("tcp:10.0.0.2:%d->203.0.113.9:443", i+1000))
		got, err := SelectECMPPath(paths, key)
		if err != nil {
			t.Fatal(err)
		}
		again, err := SelectECMPPath(paths, key)
		if err != nil || again.Name != got.Name {
			t.Fatalf("flow path changed for the same tuple: first=%+v second=%+v err=%v", got, again, err)
		}
		counts[got.Name]++
	}
	if counts["wan-a"] < 850 || counts["wan-a"] > 1150 || counts["wan-b"] < 2850 || counts["wan-b"] > 3150 {
		t.Fatalf("weighted distribution is outside tolerance: %v", counts)
	}
}

func TestDialWithECMPKeepsSinglePathFallback(t *testing.T) {
	called := false
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	conn, path, err := DialWithECMP(func(network, address string, timeout time.Duration) (net.Conn, error) {
		called = network == "tcp" && address == "example.invalid:443" && timeout == time.Second
		return left, nil
	}, "tcp", "example.invalid:443", time.Second, nil, nil)
	if err != nil || conn != left || path != (ECMPPath{}) || !called {
		t.Fatalf("single-path fallback changed: conn=%v path=%+v called=%v err=%v", conn, path, called, err)
	}
}

func TestValidateECMPPathsRejectsInvalidOrDuplicateMembers(t *testing.T) {
	for name, paths := range map[string][]ECMPPath{
		"empty interface":    {{Name: "wan-a"}},
		"duplicate selector": {{Name: "wan-a", Interface: "eth0", Mark: 10}, {Name: "wan-b", Interface: "eth0", Mark: 10}},
		"invalid weight":     {{Name: "wan-a", Interface: "eth0", Weight: 1001}},
		"invalid interface":  {{Name: "wan-a", Interface: "ethernet-interface-long"}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateECMPPaths(paths); err == nil {
				t.Fatalf("invalid paths accepted: %+v", paths)
			}
		})
	}
	if err := ValidateECMPPaths([]ECMPPath{{Name: "table-a", Interface: "eth0", Mark: 10}, {Name: "table-b", Interface: "eth0", Mark: 20}}); err != nil {
		t.Fatalf("distinct policy-routing marks on one interface rejected: %v", err)
	}
}
