package dnsfilter

import (
	"bufio"
	"io"
	"net/netip"
	"sort"
	"strings"
)

// ParseStats says what a list contained.
type ParseStats struct {
	Lines    int `json:"lines"`
	Domains  int `json:"domains"`   // after removing duplicates
	Skipped  int `json:"skipped"`   // rules that cannot apply to DNS (paths, patterns, options) or are not domains
	Excepted int `json:"exception"` // adblock @@ exceptions, not applied
}

// MaxDomainsPerList refuses a list with more domains than any real one has (the biggest, 1Hosts Xtra, has a few million).
const MaxDomainsPerList = 6_000_000

const maxDomainLen = 253

// hash64 is FNV-1a over the lowercase domain. Domains are stored only as hashes: eight bytes each instead of
// tens, and with 64 bits two different domains colliding is vanishingly unlikely.
func hash64(s string) uint64 {
	h := uint64(14695981039346656037)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

// NormalizeDomain lowercases, strips a trailing dot, and reports whether s is a usable blocklist domain: at least two
// labels (a bare TLD would block a whole zone), valid characters, not an address.
func NormalizeDomain(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if s == "" || len(s) > maxDomainLen || !strings.Contains(s, ".") {
		return "", false
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return "", false
	}
	start := true
	dots := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '.':
			if start || s[i-1] == '-' { // an empty label, or one ending in a hyphen
				return "", false
			}
			start = true
			dots++
			continue
		case c == '-':
			if start { // a label may not begin with a hyphen
				return "", false
			}
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_':
		default:
			return "", false
		}
		start = false
	}
	if start || dots < 1 || s[len(s)-1] == '-' { // start is still set when the name ends with a dot
		return "", false
	}
	switch s {
	case "localhost.localdomain", "local.host":
		return "", false
	}
	return s, true
}

var hostsAddresses = map[string]bool{"0.0.0.0": true, "127.0.0.1": true, "::": true, "::1": true, "0": true}

// parseRule extracts the domain a line blocks. ok is false for blank lines, comments and rules that do not apply.
// kind is "skip" for a rule that is real but cannot be applied to DNS, "except" for an adblock exception, "" otherwise.
func parseRule(line string) (domain, kind string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || line[0] == '#' || line[0] == '!' || line[0] == '[' {
		return "", "", false
	}
	if strings.HasPrefix(line, "@@") {
		return "", "except", false
	}
	if strings.HasPrefix(line, "||") { // adblock: ||domain^ with optional options after $
		rest := line[2:]
		opts := ""
		if i := strings.IndexByte(rest, '$'); i >= 0 {
			rest, opts = rest[:i], rest[i+1:]
		}
		if !strings.HasSuffix(rest, "^") || strings.ContainsAny(rest[:len(rest)-1], "/*?|^:") {
			return "", "skip", false // a path, a pattern, a port: not a whole domain
		}
		for _, o := range strings.Split(opts, ",") {
			switch strings.TrimSpace(o) {
			case "", "third-party", "3p", "important", "all":
			default:
				return "", "skip", false // restricted to a page, a type of request, ...: browser-only
			}
		}
		d, good := NormalizeDomain(rest[:len(rest)-1])
		if !good {
			return "", "skip", false
		}
		return d, "", true
	}
	// Cosmetic (element hiding) rules such as example.com##.ad are browser-only, and must not be read as the domain.
	for _, m := range []string{"##", "#@#", "#?#", "#$#", "#%#"} {
		if strings.Contains(line, m) {
			return "", "skip", false
		}
	}
	for i := 1; i < len(line); i++ { // a trailing comment starts at a # that follows whitespace
		if line[i] == '#' && (line[i-1] == ' ' || line[i-1] == '\t') {
			line = strings.TrimSpace(line[:i])
			break
		}
	}
	fields := strings.Fields(line)
	switch {
	case len(fields) == 0:
		return "", "", false
	case len(fields) >= 2 && hostsAddresses[fields[0]]: // hosts: 0.0.0.0 domain [more domains]
		d, good := NormalizeDomain(fields[1])
		if !good {
			return "", "skip", false
		}
		return d, "", true
	case len(fields) == 1:
		f := strings.TrimPrefix(fields[0], "*.") // wildcard lists: *.domain
		if strings.ContainsAny(f, "*/?|^:$@") {
			return "", "skip", false
		}
		d, good := NormalizeDomain(f)
		if !good {
			return "", "skip", false
		}
		return d, "", true
	}
	return "", "skip", false
}

// ParseList reads a list in any of the supported formats (hosts, domain per line, wildcard, adblock) and returns the
// sorted unique hashes of its domains. At most limit domains are accepted; beyond that the list is refused.
func ParseList(r io.Reader, limit int) ([]uint64, ParseStats, error) {
	var st ParseStats
	var out []uint64
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		st.Lines++
		d, kind, ok := parseRule(sc.Text())
		switch {
		case ok:
			out = append(out, hash64(d))
			if len(out) > limit {
				return nil, st, errTooManyDomains
			}
		case kind == "skip":
			st.Skipped++
		case kind == "except":
			st.Excepted++
		}
	}
	if err := sc.Err(); err != nil {
		return nil, st, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	n := 0
	for i, h := range out {
		if i == 0 || h != out[i-1] {
			out[n] = h
			n++
		}
	}
	out = out[:n]
	st.Domains = n
	return out, st, nil
}

type parseError string

func (e parseError) Error() string { return string(e) }

const errTooManyDomains = parseError("the list has more domains than the filter accepts")

// contains reports whether the sorted hash slice has h.
func contains(sorted []uint64, h uint64) bool {
	i := sort.Search(len(sorted), func(i int) bool { return sorted[i] >= h })
	return i < len(sorted) && sorted[i] == h
}

// suffixes returns name and its parent domains, longest first, down to two labels: "a.b.example.com" gives
// a.b.example.com, b.example.com, example.com. Blocking a domain blocks everything under it.
func suffixes(name string) []string {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	var out []string
	for {
		if strings.Count(name, ".") < 1 {
			return out
		}
		out = append(out, name)
		i := strings.IndexByte(name, '.')
		name = name[i+1:]
		if len(out) >= 12 {
			return out
		}
	}
}
