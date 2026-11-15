package layer2

import (
	"sort"
	"strings"
)

func mapKeys(values map[string][2]uint64) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func exactStringSet(actual, expected []string) bool {
	actual = append([]string(nil), actual...)
	expected = append([]string(nil), expected...)
	sort.Strings(actual)
	sort.Strings(expected)
	return strings.Join(actual, "\x00") == strings.Join(expected, "\x00")
}

func interfaceByID(interfaces []Interface, id string) Interface {
	for _, iface := range interfaces {
		if iface.ID == id {
			return iface
		}
	}
	return Interface{}
}
