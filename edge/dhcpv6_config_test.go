package edge

import "testing"

func TestL2BridgeValidatesDHCPv6RelayAndPrefixDelegation(t *testing.T) {
	base := func() L2Bridge {
		return L2Bridge{Address: "10.78.0.1/24", DHCPStart: "10.78.0.100", DHCPEnd: "10.78.0.120", IPv6Address: "fd78:78::1/64"}
	}
	t.Run("relay", func(t *testing.T) {
		b := base(); b.DHCPRelay6 = "[2001:db8::53]:547"
		if err := b.validate(); err != nil { t.Fatal(err) }
	})
	t.Run("relay link address", func(t *testing.T) {
		b := base(); b.DHCPRelay6 = "[2001:db8::53]:547"; b.DHCPRelayLink6 = "fd78:78::1"
		if err := b.validate(); err != nil { t.Fatal(err) }
	})
	t.Run("local prefix delegation", func(t *testing.T) {
		b := base(); b.DHCPv6PDPool = "fd78:1::/48"; b.DHCPv6PDBits = 60
		if err := b.validate(); err != nil { t.Fatal(err) }
	})
	t.Run("relay and local reservation conflict", func(t *testing.T) {
		b := base(); b.DHCPRelay6 = "[2001:db8::53]:547"; b.Hosts6 = []L2Host6{{ClientIDHex: "0001", MAC: "02:00:00:00:00:01", IP: "fd78:78::10"}}
		if err := b.validate(); err == nil { t.Fatal("relay accepted a local DHCPv6 reservation") }
	})
	t.Run("delegation pool overlaps client prefix", func(t *testing.T) {
		b := base(); b.DHCPv6PDPool = "fd78:78::/48"; b.DHCPv6PDBits = 60
		if err := b.validate(); err == nil { t.Fatal("overlapping delegated prefix pool accepted") }
	})
}
