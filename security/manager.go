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
	"github.com/Dankular/GameBond.Server/inspection"
	"github.com/Dankular/GameBond.Server/traffic"
)

// DNSAddr is where the filtering resolver listens: the server's address on the tunnel.
const DNSAddr = "10.77.0.1:53"

// Manager owns the engines and applies settings to them.
type Manager struct {
	FW      *firewall.Manager
	Geo     *geoip.Store
	DNS     *dnsfilter.Server
	IDS     *ids.Engine
	List    *dnsfilter.Filter
	Traffic *traffic.Classifier

	inspectionMu     sync.Mutex
	inspectionCA     *inspection.CA
	inspectionProxy  *inspection.Proxy
	inspectionCancel context.CancelFunc
	inspectionDone   chan struct{}
	runtimeCtx       context.Context
	inspectionDir    string

	mu       sync.Mutex
	settings Settings
	loaded   bool
}

// Options configure New.
type Options struct {
	Runner        firewall.Runner // nft and conntrack; nil runs the real ones
	GeoDir        string          // where country lists are cached
	Tunnel        string          // the TUN interface name
	InspectionDir string          // persistent private storage for the TLS inspection CA
}

// New builds the engines and wires them together; nothing runs until Run.
func New(o Options) *Manager {
	fw := firewall.NewManager(o.Runner)
	fw.Tunnel = o.Tunnel
	geo := geoip.New(o.GeoDir)
	fw.Geo = geo.Prefixes
	fw.GeoByCode = func(code string) []netip.Prefix { return geo.Prefixes([]string{code}) }
	filter := dnsfilter.NewFilter()
	srv := dnsfilter.NewServer(filter)
	engine := ids.New(fw)
	classifier := traffic.NewClassifier()
	srv.Observer = func(q dnsfilter.Query) {
		engine.ObserveDNS(ids.DNSQuery{Client: q.Client, Name: q.Name, RCode: q.RCode})
		classifier.ObserveDNS(q.Name, q.Answers)
	}
	return &Manager{FW: fw, Geo: geo, DNS: srv, IDS: engine, List: filter, Traffic: classifier, inspectionDir: o.InspectionDir}
}

// Tap receives every packet the edge forwards (see edge.SetTap).
func (m *Manager) Tap(fromDevice bool, packet []byte) {
	m.IDS.Observe(fromDevice, packet)
	m.Traffic.ObservePacket(fromDevice, packet)
}

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
	prevZones := zoneMembers(prev.Firewall.Zones)
	var prevPolicy dnsfilter.DomainPolicy
	if hadPrev && m.settings.Traffic.Enabled {
		prevConfig := m.settings.Traffic
		prevPolicy = func(device netip.Addr, name string) (string, string, bool) {
			return prevConfig.MatchDomainFor(device, name, prevZones)
		}
	}
	// Country lists first, so the firewall is rendered with data when there is any. A failure is not fatal: the
	// firewall reports that the lists are not loaded and the background refresh keeps trying.
	if s.Firewall.Enabled && len(geoCodes(s)) > 0 {
		gctx, cancel := context.WithTimeout(ctx, 25*time.Second)
		_, _ = m.Geo.Ensure(gctx, geoCodes(s))
		cancel()
	}
	var ca *inspection.CA
	if s.Inspection.Enabled {
		loadedCA, err := inspection.LoadOrCreate(m.inspectionDir)
		if err != nil {
			return err
		}
		ca = loadedCA
	}
	m.inspectionMu.Lock()
	currentProxy, previousCA := m.inspectionProxy, m.inspectionCA
	m.inspectionMu.Unlock()
	previousLimit := 0
	if s.Inspection.Enabled && currentProxy != nil && currentProxy.Status().Ready {
		previousLimit = currentProxy.Limiter.Limit()
		if !currentProxy.Limiter.SetLimit(s.Inspection.MaxSessions) {
			return fmt.Errorf("inspection: cannot lower max_sessions below the %d active sessions", currentProxy.Limiter.Active())
		}
	}
	prestarted := false
	if s.Inspection.Enabled && (currentProxy == nil || !currentProxy.Status().Ready) {
		if err := m.configureInspection(s, ca, ctx); err != nil {
			return err
		}
		prestarted = true
	}
	m.IDS.Apply(s.IDS)
	m.List.Apply(s.DNSFilter)
	m.Traffic.SetEnabled(s.Traffic.Enabled || s.Inspection.Enabled)
	zones := zoneMembers(s.Firewall.Zones)
	m.DNS.SetPolicy(func(device netip.Addr, name string) (string, string, bool) {
		return s.Traffic.MatchDomainFor(device, name, zones)
	})
	fwConfig := s.Firewall
	fwConfig.InspectTLS = s.Inspection.Enabled
	if err := m.FW.Apply(ctx, fwConfig); err != nil {
		if previousLimit > 0 && currentProxy != nil {
			currentProxy.Limiter.SetLimit(previousLimit)
		}
		if hadPrev {
			m.IDS.Apply(prev.IDS)
			m.List.Apply(prev.DNSFilter)
			m.Traffic.SetEnabled(prev.Traffic.Enabled || prev.Inspection.Enabled)
			m.DNS.SetPolicy(prevPolicy)
		} else {
			m.Traffic.SetEnabled(false)
			m.DNS.SetPolicy(nil)
		}
		if prestarted {
			_ = m.configureInspection(prev, previousCA, ctx)
		}
		return err
	}
	m.DNS.ClearCache()
	m.settings, m.loaded = s, true
	if err := m.configureInspection(s, ca, ctx); err != nil {
		return err
	}
	if s.DNSFilter.Enabled { // fetch what is missing in the background; the call does not wait for the lists
		go m.List.Refresh(context.Background(), false)
	}
	return nil
}

// Run starts the background work: the resolver, the blocklist and country list refresh, and the detector. It returns
// when ctx ends.
func (m *Manager) Run(ctx context.Context) {
	m.inspectionMu.Lock()
	m.runtimeCtx = ctx
	ca := m.inspectionCA
	m.inspectionMu.Unlock()
	if s := m.Settings(); s.Inspection.Enabled {
		_ = m.configureInspection(s, ca, ctx)
	}
	var wg sync.WaitGroup
	start := func(f func()) {
		wg.Add(1)
		go func() { defer wg.Done(); f() }()
	}
	start(func() { _ = m.DNS.ListenAndServe(ctx, DNSAddr) })
	start(func() { m.List.Run(ctx, func([]string) { m.DNS.ClearCache() }) })
	start(func() {
		m.Geo.Run(ctx, func() []string { return geoCodes(m.Settings()) }, func() { _ = m.FW.Reapply(ctx) })
	})
	start(func() { m.IDS.Run(ctx) })
	wg.Wait()
}

func geoCodes(s Settings) []string {
	seen := make(map[string]bool)
	codes := make([]string, 0, len(s.Firewall.Countries.Codes))
	add := func(code string) {
		if !seen[code] {
			seen[code] = true
			codes = append(codes, code)
		}
	}
	if s.Firewall.Countries.Mode != "off" {
		for _, code := range s.Firewall.Countries.Codes {
			add(code)
		}
	}
	for _, r := range s.Firewall.Rules {
		for _, code := range r.Regions {
			add(code)
		}
	}
	return codes
}

func zoneMembers(zones []firewall.Zone) map[string]map[netip.Addr]bool {
	members := make(map[string]map[netip.Addr]bool, len(zones))
	for _, zone := range zones {
		set := make(map[netip.Addr]bool, len(zone.Members))
		for _, raw := range zone.Members {
			if addr, err := netip.ParseAddr(raw); err == nil {
				set[addr.Unmap()] = true
			}
		}
		members[zone.Name] = set
	}
	return members
}

func (m *Manager) configureInspection(s Settings, ca *inspection.CA, fallback context.Context) error {
	m.inspectionMu.Lock()
	if m.runtimeCtx == nil {
		m.runtimeCtx = fallback
	}
	runtimeCtx := m.runtimeCtx
	if s.Inspection.Enabled && ca != nil && m.inspectionProxy != nil && m.inspectionCA != nil && m.inspectionCA.Fingerprint() == ca.Fingerprint() && m.inspectionProxy.Status().Ready {
		if !m.inspectionProxy.Limiter.SetLimit(s.Inspection.MaxSessions) {
			m.inspectionMu.Unlock()
			return errors.New("inspection: active sessions exceed the new max_sessions")
		}
		m.inspectionProxy.SetExhaustionAction(s.Inspection.ExhaustionAction)
		zones := zoneMembers(s.Firewall.Zones)
		m.inspectionProxy.SetPolicy(func(device netip.Addr, host, path string) (string, string, bool) {
			return s.Traffic.MatchURLFor(device, host, path, zones)
		})
		m.inspectionMu.Unlock()
		return nil
	}
	oldCancel, oldDone := m.inspectionCancel, m.inspectionDone
	if oldCancel != nil {
		oldCancel()
	}
	m.inspectionCancel, m.inspectionDone = nil, nil
	m.inspectionProxy, m.inspectionCA = nil, ca
	m.inspectionMu.Unlock()
	if oldDone != nil {
		<-oldDone
	}
	if !s.Inspection.Enabled || ca == nil {
		return nil
	}
	if runtimeCtx == nil {
		return errors.New("inspection: runtime context is not available")
	}
	p := &inspection.Proxy{CA: ca, Limiter: inspection.NewLimiter(s.Inspection.MaxSessions)}
	p.SetExhaustionAction(s.Inspection.ExhaustionAction)
	zones := zoneMembers(s.Firewall.Zones)
	p.SetPolicy(func(device netip.Addr, host, path string) (string, string, bool) {
		return s.Traffic.MatchURLFor(device, host, path, zones)
	})
	var done chan struct{}
	m.inspectionMu.Lock()
	m.inspectionProxy = p
	if runtimeCtx != nil {
		child, cancel := context.WithCancel(runtimeCtx)
		done = make(chan struct{})
		m.inspectionCancel, m.inspectionDone = cancel, done
		go func() {
			defer close(done)
			if err := p.Run(child); err != nil {
				p.RecordError()
			}
		}()
	}
	m.inspectionMu.Unlock()
	deadline := time.NewTimer(5 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer deadline.Stop()
	defer ticker.Stop()
	for {
		if p.Status().Ready {
			return nil
		}
		select {
		case <-done:
			return errors.New("inspection: proxy stopped before becoming ready")
		case <-runtimeCtx.Done():
			return errors.New("inspection: runtime stopped before proxy became ready")
		case <-deadline.C:
			return errors.New("inspection: proxy did not become ready within five seconds")
		case <-ticker.C:
		}
	}
}

func (m *Manager) inspectionStatus(s Settings) any {
	m.inspectionMu.Lock()
	ca, proxy := m.inspectionCA, m.inspectionProxy
	m.inspectionMu.Unlock()
	var status inspection.ProxyStatus
	status.Maximum = s.Inspection.MaxSessions
	if proxy != nil {
		status = proxy.Status()
	}
	return map[string]any{"enabled": s.Inspection.Enabled, "ready": status.Ready, "active_sessions": status.Active,
		"max_sessions": status.Maximum, "rejected": status.Rejected, "bypassed": status.Bypassed, "errors": status.Errors,
		"policy_matches": status.PolicyMatches, "policy_denied": status.PolicyDenied,
		"ca_ready": ca != nil, "ca_sha256": func() string {
			if ca == nil {
				return ""
			}
			return ca.Fingerprint()
		}()}
}

// Catalog is the static information the GUI needs to build its forms.
func (m *Manager) Catalog() any {
	return map[string]any{
		"categories": dnsfilter.Categories, "sources": dnsfilter.Sources, "lists": dnsfilter.Lists,
		"detectors": ids.Specs, "countries": CountryCodes,
		"applications": []string{"dns", "http", "tls", "quic", "ssh", "mail", "unknown"},
		"protocols":    []string{"tcp", "udp", "unknown"},
		"limits":       map[string]any{"rules": firewall.MaxRules, "zones": firewall.MaxZones, "custom_lists": dnsfilter.MaxCustomLists},
	}
}

// Overview is what the GUI shows: the settings and the live state of every engine.
func (m *Manager) Overview(ctx context.Context) any {
	s := m.Settings()
	return map[string]any{
		"settings":   json.RawMessage(s.JSON()),
		"firewall":   m.FW.Status(ctx),
		"countries":  m.Geo.Status(s.Firewall.Countries.Codes),
		"dns":        map[string]any{"filter": m.List.Status(), "server": m.DNS.Stats(), "listen": DNSAddr},
		"ids":        m.IDS.Status(),
		"traffic":    map[string]any{"classifier": m.Traffic.Status(), "recent": m.Traffic.Recent(100)},
		"inspection": m.inspectionStatus(s),
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
	case "export_inspection_ca":
		m.inspectionMu.Lock()
		ca := m.inspectionCA
		m.inspectionMu.Unlock()
		if ca == nil {
			return nil, errors.New("TLS inspection CA is not ready")
		}
		return map[string]any{"certificate_pem": string(ca.CertificatePEM()), "sha256": ca.Fingerprint()}, nil
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
