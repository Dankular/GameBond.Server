package l2gw

import (
	"net"
	"net/netip"
	"testing"
)

func TestUDPMappingAndDeviceEndpointUseIPv6(t *testing.T) {
	g, _ := newTestGateway(t, func(cfg *Config) {
		cfg.IPv6Address = netip.MustParsePrefix("2001:db8:1::1/64")
	})

	device := netip.MustParseAddrPort("[2001:db8:1::20]:40000")
	public, err := g.listenUDP(device)
	if err != nil {
		t.Fatal(err)
	}
	defer public.Close()
	if addr, ok := public.LocalAddr().(*net.UDPAddr); !ok || addr.IP.To4() != nil {
		t.Fatalf("IPv6 mapping got non-IPv6 public socket: %#v", public.LocalAddr())
	}

	remote := netip.MustParseAddrPort("[2001:db8:2::99]:50000")
	endpoint, err := g.deviceEndpoint(remote, device)
	if err != nil {
		t.Fatalf("create IPv6 device-facing UDP endpoint: %v", err)
	}
	endpoint.Close()
}
