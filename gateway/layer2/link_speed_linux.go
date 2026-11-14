//go:build linux

package layer2

import (
	"fmt"
	"regexp"
)

var ethtoolSpeedPattern = regexp.MustCompile(`(?m)^\s*Speed:\s*([0-9]+(?:\.[0-9]+)?)\s*(Mb/s|Gb/s|Tb/s)\s*$`)

func parseEthtoolLinkSpeed(data []byte) (uint64, error) {
	match := ethtoolSpeedPattern.FindSubmatch(data)
	if len(match) != 3 {
		return 0, fmt.Errorf("ethtool did not report a known link speed")
	}
	rateUnit := map[string]string{"Mb/s": "Mbit", "Gb/s": "Gbit", "Tb/s": "Tbit"}[string(match[2])]
	rate, err := parseTCQuantity(string(match[1]), rateUnit, true)
	if err != nil || rate < 8_000 || rate > 100_000_000_000 {
		return 0, fmt.Errorf("ethtool reported an unsupported link speed")
	}
	return rate, nil
}
