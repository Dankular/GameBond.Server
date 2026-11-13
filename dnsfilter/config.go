package dnsfilter

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
)

const (
	MaxCustomLists = 10
	MaxCustomRules = 2000
)

// MaxActiveDomain bounds the domains held in memory across all active lists (eight bytes each).
var MaxActiveDomain = 8_000_000

// Config is the "dns_filter" part of the security settings.
type Config struct {
	Enabled bool `json:"enabled"`
	// Upstreams are the resolvers questions are forwarded to, host:port (default 1.1.1.1:53 and 9.9.9.9:53).
	Upstreams []string `json:"upstreams"`
	// BlockMode is the answer for a blocked name: "nxdomain" (default) or "null" (0.0.0.0 and ::).
	BlockMode string `json:"block_mode"`
	// Categories switched on: every default list of a category is used.
	Categories []string `json:"categories"`
	// EnableLists adds lists on top of the defaults; DisableLists removes some.
	EnableLists  []string     `json:"enable_lists"`
	DisableLists []string     `json:"disable_lists"`
	CustomLists  []CustomList `json:"custom_lists"`
	Block        []string     `json:"block"`  // domains (and subdomains) always blocked
	Allow        []string     `json:"allow"`  // domains (and subdomains) never blocked, whatever the lists say
	Exempt       []string     `json:"exempt"` // tunnel device addresses that are not filtered
	// RefreshHours is how often the lists are checked for a newer version (default 12).
	RefreshHours int `json:"refresh_hours"`
}

// CustomList is a list the user adds by URL.
type CustomList struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	URL      string `json:"url"`
	Category string `json:"category"`
}

var customID = regexp.MustCompile(`^custom-[a-z0-9][a-z0-9-]{0,30}$`)

// Parse decodes and validates the configuration. Unknown fields are refused.
func Parse(raw json.RawMessage) (Config, error) {
	var c Config
	if t := bytes.TrimSpace(raw); len(t) == 0 || string(t) == "null" {
		return c.normalised(), nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("dns_filter: %w", err)
	}
	c = c.normalised()
	return c, c.Validate()
}

func (c Config) normalised() Config {
	if len(c.Upstreams) == 0 {
		c.Upstreams = []string{"1.1.1.1:53", "9.9.9.9:53"}
	}
	if c.BlockMode == "" {
		c.BlockMode = "nxdomain"
	}
	if c.RefreshHours == 0 {
		c.RefreshHours = 12
	}
	return c
}

func validUpstream(s string) error {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return fmt.Errorf("%q is not host:port", s)
	}
	a, err := netip.ParseAddr(host)
	if err != nil || !a.Is4() {
		return fmt.Errorf("%q: the upstream must be an IPv4 address", s)
	}
	if a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() || a == netip.MustParseAddr("10.77.0.1") {
		return fmt.Errorf("%q cannot be an upstream (that would loop back into the filter)", s)
	}
	if p, err := net.LookupPort("udp", port); err != nil || p == 0 {
		return fmt.Errorf("%q has a bad port", s)
	}
	return nil
}

// allowedListURL refuses addresses on the server's own networks: the server fetches these on a user's behalf.
func allowedListURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return errors.New("a list URL must be https://host/path")
	}
	if a, err := netip.ParseAddr(u.Hostname()); err == nil && !publicAddr(a) {
		return errors.New("a list URL cannot point at a private or local address")
	}
	if len(raw) > 300 {
		return errors.New("the URL is too long")
	}
	return nil
}

func publicAddr(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsValid() && !a.IsPrivate() && !a.IsLoopback() && !a.IsLinkLocalUnicast() && !a.IsLinkLocalMulticast() && !a.IsMulticast() && !a.IsUnspecified() &&
		!(a.Is4() && (a.As4()[0] == 100 && a.As4()[1]&0xc0 == 64)) // CGNAT
}

// Validate checks every field.
func (c Config) Validate() error {
	if c.BlockMode != "nxdomain" && c.BlockMode != "null" {
		return errors.New("dns_filter: block_mode must be nxdomain or null")
	}
	if c.RefreshHours < 1 || c.RefreshHours > 168 {
		return errors.New("dns_filter: refresh_hours must be between 1 and 168")
	}
	if len(c.Upstreams) > 4 {
		return errors.New("dns_filter: at most 4 upstreams")
	}
	for _, u := range c.Upstreams {
		if err := validUpstream(u); err != nil {
			return fmt.Errorf("dns_filter: %w", err)
		}
	}
	seen := map[string]bool{}
	for _, cat := range c.Categories {
		if !categoryKnown(cat) {
			return fmt.Errorf("dns_filter: unknown category %q", cat)
		}
		if seen[cat] {
			return fmt.Errorf("dns_filter: category %q is listed twice", cat)
		}
		seen[cat] = true
	}
	custom := map[string]bool{}
	for _, l := range c.CustomLists {
		if !customID.MatchString(l.ID) || custom[l.ID] {
			return fmt.Errorf("dns_filter: custom list id %q must be unique and look like custom-name", l.ID)
		}
		custom[l.ID] = true
		if l.Name == "" || len(l.Name) > 60 {
			return fmt.Errorf("dns_filter: custom list %s needs a name of up to 60 characters", l.ID)
		}
		if err := allowedListURL(l.URL); err != nil {
			return fmt.Errorf("dns_filter: custom list %s: %w", l.ID, err)
		}
		if l.Category != "" && !categoryKnown(l.Category) {
			return fmt.Errorf("dns_filter: custom list %s: unknown category %q", l.ID, l.Category)
		}
	}
	if len(c.CustomLists) > MaxCustomLists {
		return fmt.Errorf("dns_filter: at most %d custom lists", MaxCustomLists)
	}
	for _, group := range []struct {
		name string
		ids  []string
	}{{"enable_lists", c.EnableLists}, {"disable_lists", c.DisableLists}} {
		for _, id := range group.ids {
			if _, ok := listByID(id); !ok {
				return fmt.Errorf("dns_filter: %s names %q, which is not in the catalog", group.name, id)
			}
		}
	}
	for _, group := range []struct {
		name  string
		items []string
	}{{"block", c.Block}, {"allow", c.Allow}} {
		if len(group.items) > MaxCustomRules {
			return fmt.Errorf("dns_filter: at most %d %s entries", MaxCustomRules, group.name)
		}
		for _, d := range group.items {
			if _, ok := NormalizeDomain(d); !ok {
				return fmt.Errorf("dns_filter: %s: %q is not a domain such as example.com", group.name, d)
			}
		}
	}
	for _, e := range c.Exempt {
		a, err := netip.ParseAddr(e)
		if err != nil || !a.Is4() || a.String() != e {
			return fmt.Errorf("dns_filter: exempt: %q is not an IPv4 address", e)
		}
	}
	return nil
}

// ActiveLists is the lists the configuration uses: the defaults of each enabled category, plus extras, minus
// disabled ones, plus custom lists.
func (c Config) ActiveLists() []List {
	enabled := map[string]bool{}
	for _, cat := range c.Categories {
		enabled[cat] = true
	}
	extra, off := map[string]bool{}, map[string]bool{}
	for _, id := range c.EnableLists {
		extra[id] = true
	}
	for _, id := range c.DisableLists {
		off[id] = true
	}
	var out []List
	for _, l := range Lists {
		if off[l.ID] {
			continue
		}
		if (l.Default && enabled[l.Category]) || extra[l.ID] {
			out = append(out, l)
		}
	}
	for _, cl := range c.CustomLists {
		cat := cl.Category
		if cat == "" {
			cat = "ads"
		}
		out = append(out, List{ID: cl.ID, Source: "custom", Name: cl.Name, Category: cat, URL: cl.URL, Format: "any"})
	}
	return out
}

func normalisedSet(items []string) map[string]bool {
	out := map[string]bool{}
	for _, d := range items {
		if n, ok := NormalizeDomain(d); ok {
			out[n] = true
		}
	}
	return out
}
