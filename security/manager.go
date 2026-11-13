package security

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/Dankular/GameBond.Server/dnsfilter"
	"github.com/Dankular/GameBond.Server/firewall"
	"github.com/Dankular/GameBond.Server/geoip"
	"github.com/Dankular/GameBond.Server/ids"
)

// DNSAddr is where the filtering resolver listens: the server's address on the tunnel.
const DNSAddr = "10.77.0.1:53"

// Manager owns the engines and applies settings to them.
type Manager struct {
	FW   *firewall.Manager
	Geo  *geoip.Store
	DNS  *dnsfilter.Server
	IDS  *ids.Engine
	List *dnsfilter.Filter

	mu       sync.Mutex
	settings Settings
	loaded   bool
}

// Options configure New.
type Options struct {
	Runner firewall.Runner // nft and conntrack; nil runs the real ones
	GeoDir string          // where country lists are cached
	Tunnel string          // the TUN interface name
}

// New builds the engines and wires them together; nothing runs until Run.
func New(o Options) *Manager {
	fw := firewall.NewManager(o.Runner)
	fw.Tunnel = o.Tunnel
	geo := geoip.New(o.GeoDir)
	fw.Geo = geo.Prefixes
	filter := dnsfilter.NewFilter()
	srv := dnsfilter.NewServer(filter)
	engine := ids.New(fw)
	srv.Observer = func(q dnsfilter.Query) {
		engine.ObserveDNS(ids.DNSQuery{Client: q.Client, Name: q.Name, RCode: q.RCode})
	}
	return &Manager{FW: fw, Geo: geo, DNS: srv, IDS: engine, List: filter}
}

// Tap receives every packet the edge forwards (see edge.SetTap).
func (m *Manager) Tap(fromDevice bool, packet []byte) { m.IDS.Observe(fromDevice, packet) }

// Settings returns the settings in force.
func (m *Manager) Settings() Settings {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.settings
}

// Apply validates and installs settings. The detector and DNS filter cannot fail, the firewall can (nftables may
// refuse a script), so the firewall goes last and, if it is refused, the others return to what they were: either all
// of it applies or none of it does.
func (m *Manager) Apply(ctx context.Context, raw json.RawMessage) error {
	s, err := Parse(raw)
	if err != nil {
		return err
	}
	return m.ApplySettings(ctx, s)
}

// ApplySettings installs already validated settings.
func (m *Manager) ApplySettings(ctx context.Context, s Settings) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	prev := m.settings
	hadPrev := m.loaded
	// Country lists first, so the firewall is rendered with data when there is any. A failure is not fatal: the
	// firewall reports that the lists are not loaded and the background refresh keeps trying.
	if s.Firewall.Enabled && s.Firewall.Countries.Mode != "off" {
		gctx, cancel := context.WithTimeout(ctx, 25*time.Second)
		_, _ = m.Geo.Ensure(gctx, s.Firewall.Countries.Codes)
		cancel()
	}
	m.IDS.Apply(s.IDS)
	m.List.Apply(s.DNSFilter)
	if err := m.FW.Apply(ctx, s.Firewall); err != nil {
		if hadPrev {
			m.IDS.Apply(prev.IDS)
			m.List.Apply(prev.DNSFilter)
		}
		return err
	}
	m.DNS.ClearCache()
	m.settings, m.loaded = s, true
	if s.DNSFilter.Enabled { // fetch what is missing in the background; the call does not wait for the lists
		go m.List.Refresh(context.Background(), false)
	}
	return nil
}

// Run starts the background work: the resolver, the blocklist and country list refresh, and the detector. It returns
// when ctx ends.
func (m *Manager) Run(ctx context.Context) {
	var wg sync.WaitGroup
	start := func(f func()) {
		wg.Add(1)
		go func() { defer wg.Done(); f() }()
	}
	start(func() { _ = m.DNS.ListenAndServe(ctx, DNSAddr) })
	start(func() { m.List.Run(ctx, func([]string) { m.DNS.ClearCache() }) })
	start(func() {
		m.Geo.Run(ctx, func() []string { return m.Settings().Firewall.Countries.Codes }, func() { _ = m.FW.Reapply(ctx) })
	})
	start(func() { m.IDS.Run(ctx) })
	wg.Wait()
}

// Catalog is the static information the GUI needs to build its forms.
func (m *Manager) Catalog() any {
	return map[string]any{
		"categories": dnsfilter.Categories, "sources": dnsfilter.Sources, "lists": dnsfilter.Lists,
		"detectors": ids.Specs, "countries": CountryCodes,
		"limits": map[string]any{"rules": firewall.MaxRules, "zones": firewall.MaxZones, "custom_lists": dnsfilter.MaxCustomLists},
	}
}

// Overview is what the GUI shows: the settings and the live state of every engine.
func (m *Manager) Overview(ctx context.Context) any {
	s := m.Settings()
	return map[string]any{
		"settings":  json.RawMessage(s.JSON()),
		"firewall":  m.FW.Status(ctx),
		"countries": m.Geo.Status(s.Firewall.Countries.Codes),
		"dns":       map[string]any{"filter": m.List.Status(), "server": m.DNS.Stats(), "listen": DNSAddr},
		"ids":       m.IDS.Status(),
	}
}

// Do runs an action from the GUI.
func (m *Manager) Do(ctx context.Context, action string, args map[string]any) (any, error) {
	str := func(k string) string { v, _ := args[k].(string); return v }
	switch action {
	case "unblock":
		ip := str("ip")
		if err := m.IDS.Unblock(ctx, ip); err != nil {
			return nil, err
		}
		return map[string]any{"ok": true}, nil
	case "block":
		ip := str("ip")
		secs, _ := args["seconds"].(float64)
		if secs == 0 {
			secs = 3600
		}
		if err := m.FW.BlockAddress(ctx, ip, time.Duration(secs)*time.Second); err != nil {
			return nil, err
		}
		return map[string]any{"ok": true}, nil
	case "refresh_lists":
		changed := m.List.Refresh(ctx, true)
		m.DNS.ClearCache()
		return map[string]any{"ok": true, "changed": changed}, nil
	case "refresh_countries":
		_, err := m.Geo.Ensure(ctx, m.Settings().Firewall.Countries.Codes)
		if err != nil {
			return nil, err
		}
		return map[string]any{"ok": true}, m.FW.Reapply(ctx)
	case "clear_events":
		m.IDS.ClearEvents()
		return map[string]any{"ok": true}, nil
	case "flush_connections":
		if err := m.FW.FlushConnections(ctx); err != nil {
			return nil, err
		}
		return map[string]any{"ok": true}, nil
	case "check_domain":
		d := str("domain")
		if d == "" {
			return nil, errors.New("give a domain to check")
		}
		return m.List.Match(d), nil
	case "test_address": // would the firewall's country filter and the detector's block list touch this address?
		a, err := netip.ParseAddr(str("ip"))
		if err != nil || !a.Is4() {
			return nil, fmt.Errorf("%q is not an IPv4 address", str("ip"))
		}
		cc := m.Settings().Firewall.Countries.Codes
		in := []string{}
		for _, c := range cc {
			for _, p := range m.Geo.Prefixes([]string{c}) {
				if p.Contains(a) {
					in = append(in, c)
					break
				}
			}
		}
		return map[string]any{"countries": in}, nil
	}
	return nil, fmt.Errorf("unknown action %q", action)
}
