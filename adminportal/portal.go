package adminportal

import (
	"bytes"
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Dankular/GameBond.Server/adminauth"
	"github.com/Dankular/GameBond.Server/lab"
	"golang.org/x/net/websocket"
)

//go:embed static/*
var staticFiles embed.FS

// RestartExitCode is the status the container entrypoint treats as "restart".
const RestartExitCode = 75

const maxBody = 1 << 20

// maxHashing is how many password hashes may run at the same time.
const maxHashing = 2

var contentTypes = map[string]string{".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8"}

var securityHeaders = [][2]string{
	{"Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self' ws: wss:; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"},
	{"X-Content-Type-Options", "nosniff"}, {"X-Frame-Options", "DENY"}, {"Referrer-Policy", "no-referrer"},
	{"Cache-Control", "no-store"}, {"Strict-Transport-Security", "max-age=31536000"},
}

// Options wires the portal to its host process.
type Options struct {
	Settings *Settings
	// Snapshot is the live status document for /api/status.
	Snapshot func() any
	// Hardware reads a background cache; it must not sample in the HTTP handler.
	Hardware func() map[string]any
	// ConfigPath is the server config the portal reads and rewrites in place.
	ConfigPath string
	// Validate checks a candidate config file (load_config); nil accepts anything.
	Validate func(path string) error
	// RequestRestart is called 0.5 s after a confirmed restart request.
	RequestRestart func()
	// Clock is monotonic seconds (tests); nil uses the real clock.
	Clock func() float64
	// TempDir overrides os.TempDir (tests).
	TempDir string
	// Security, when set, serves the firewall, DNS filter and intrusion detection pages.
	Security SecurityAPI
	// GatewaySocketPath is optional; when configured, only the gateway's allowlisted Unix API is used.
	GatewaySocketPath string
	// LabManager is nil when this process has no configured single-host sandbox backend.
	LabManager *lab.Manager
	// LabManagerFactory creates an isolated in-memory orchestrator for a team.
	LabManagerFactory func(team string) (*lab.Manager, error)
	LabDirectory      string
}

// SecurityAPI is what the portal needs from the security manager.
type SecurityAPI interface {
	Overview(ctx context.Context) any
	Catalog() any
	// Apply installs settings live and returns them normalised, ready to be stored in the config file.
	Apply(ctx context.Context, raw json.RawMessage) (json.RawMessage, error)
	Do(ctx context.Context, action string, args map[string]any) (any, error)
}

// Portal is AdminPortal.
type Portal struct {
	o        Options
	Sessions *adminauth.Sessions
	Throttle *adminauth.Throttle

	// hashing bounds concurrent scrypt work: each verification needs about 32 MiB, and the
	// throttle only counts failures after they finish, so a parallel burst would otherwise
	// all run at once and exhaust the container's memory.
	hashing      chan struct{}
	mu           sync.Mutex // configuration writes and the password hash
	labMu        sync.Mutex
	labManagers  map[string]*lab.Manager
	passwordHash string
	gateway      *GatewayClient
	logMu        sync.Mutex
	log          []string
	server       *http.Server
	Port         int
}

// New builds a portal; Start serves it.
func New(o Options) *Portal {
	if o.Validate == nil {
		o.Validate = func(string) error { return nil }
	}
	if o.RequestRestart == nil {
		o.RequestRestart = func() {}
	}
	p := &Portal{o: o, hashing: make(chan struct{}, maxHashing), Sessions: adminauth.NewSessions(o.Clock), Throttle: adminauth.NewThrottle(o.Clock), passwordHash: o.Settings.PasswordHash, labManagers: make(map[string]*lab.Manager)}
	if o.GatewaySocketPath != "" {
		p.gateway, _ = NewGatewayClient(o.GatewaySocketPath)
	}
	return p
}

func (p *Portal) labManager(team string) (*lab.Manager, error) {
	if p.o.LabManager != nil {
		return p.o.LabManager, nil
	}
	if p.o.LabManagerFactory == nil {
		return nil, nil
	}
	if team == "" {
		return nil, errors.New("session has no team scope")
	}
	p.labMu.Lock()
	defer p.labMu.Unlock()
	if manager := p.labManagers[team]; manager != nil {
		return manager, nil
	}
	manager, err := p.o.LabManagerFactory(team)
	if err != nil {
		return nil, err
	}
	p.labManagers[team] = manager
	return manager, nil
}

func (p *Portal) legacyAdmin() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.o.Settings.Users) == 0
}

// Note appends a timestamped line to the portal's log ring.
func (p *Portal) Note(line string) {
	p.logMu.Lock()
	defer p.logMu.Unlock()
	p.log = append(p.log, time.Now().Format("2006-01-02 15:04:05")+" "+line)
	if n := len(p.log) - p.o.Settings.LogLines; n > 0 {
		p.log = append([]string(nil), p.log[n:]...)
	}
}

func (p *Portal) logLines() []string {
	p.logMu.Lock()
	defer p.logMu.Unlock()
	return append([]string{}, p.log...)
}

// Start listens on the configured address (TLS when a certificate is set).
func (p *Portal) Start() error {
	s := p.o.Settings
	l, err := net.Listen("tcp4", net.JoinHostPort(s.Host, strconv.Itoa(s.Port)))
	if err != nil {
		return err
	}
	p.Port = l.Addr().(*net.TCPAddr).Port
	if s.TLSCert != "" {
		cert, err := tls.LoadX509KeyPair(s.TLSCert, s.TLSKey)
		if err != nil {
			l.Close()
			return err
		}
		l = tls.NewListener(l, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}})
	}
	p.server = &http.Server{Handler: http.HandlerFunc(p.serve), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second}
	go p.server.Serve(l)
	return nil
}

// Close stops the listener.
func (p *Portal) Close() {
	if p.server != nil {
		p.server.Close()
	}
	p.labMu.Lock()
	managers := make([]*lab.Manager, 0, len(p.labManagers))
	for _, manager := range p.labManagers {
		managers = append(managers, manager)
	}
	p.labManagers = make(map[string]*lab.Manager)
	p.labMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, manager := range managers {
		if err := manager.Close(ctx); err != nil {
			p.Note("lab runtime cleanup failed: " + err.Error())
		}
	}
}

// ReadConfig is the config file text.
func (p *Portal) ReadConfig() (string, error) {
	raw, err := os.ReadFile(p.o.ConfigPath)
	return string(raw), err
}

func parseObject(text string) (map[string]any, error) {
	var v any
	if err := json.Unmarshal([]byte(text), &v); err != nil {
		return nil, fmt.Errorf("ValueError: %v", err)
	}
	m, _ := v.(map[string]any)
	return m, nil
}

// CheckConfig is check_config: the error text (empty when valid). The admin
// block can only change through the password flow, never here.
func (p *Portal) CheckConfig(text string) string {
	fresh, err := parseObject(text)
	if err != nil {
		return err.Error()
	}
	if fresh == nil {
		return "config must be a JSON object"
	}
	current, err := p.ReadConfig()
	if err != nil {
		return "OSError: " + err.Error()
	}
	old, err := parseObject(current)
	if err != nil {
		return err.Error()
	}
	if !reflect.DeepEqual(fresh["admin"], old["admin"]) {
		return "the admin block cannot be edited here; use the Administration page"
	}
	dir, err := os.MkdirTemp(p.o.TempDir, "gamebond-check-")
	if err != nil {
		return "OSError: " + err.Error()
	}
	defer os.RemoveAll(dir)
	probe := filepath.Join(dir, "server.json")
	if err := os.WriteFile(probe, []byte(text), 0o600); err != nil {
		return "OSError: " + err.Error()
	}
	if err := p.o.Validate(probe); err != nil {
		return "ValueError: " + err.Error()
	}
	return ""
}

// writeInPlace rewrites the file's contents without replacing it: the compose
// file bind-mounts the single file, so rename-over would fail.
func writeInPlace(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// ApplyConfig validates and writes the config; the error text is empty on success.
func (p *Portal) ApplyConfig(text string) string {
	if e := p.CheckConfig(text); e != "" {
		return e
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	previous, err := p.ReadConfig()
	if err != nil {
		return "OSError: " + err.Error()
	}
	tmp := p.o.TempDir
	if tmp == "" {
		tmp = os.TempDir()
	}
	if err := os.WriteFile(filepath.Join(tmp, "gamebond-config.previous.json"), []byte(previous), 0o600); err != nil {
		return "OSError: " + err.Error()
	}
	if err := writeInPlace(p.o.ConfigPath, []byte(text)); err != nil {
		p.restoreConfig(previous)
		return "OSError: " + err.Error()
	}
	// The file is rewritten in place, so a short write or a full disk could leave it truncated and
	// the entrypoint would then refuse to start. Read it back and put the old text back if it differs.
	if written, err := os.ReadFile(p.o.ConfigPath); err != nil || string(written) != text {
		p.restoreConfig(previous)
		return "OSError: configuration was not written correctly; the previous configuration was restored"
	}
	p.Note("configuration written; restart required to apply")
	return ""
}

// persistSecurity stores the security section in the config file, leaving every other key and the file's layout as
// it was. The error text is empty on success.
func (p *Portal) persistSecurity(section json.RawMessage) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	previous, err := p.ReadConfig()
	if err != nil {
		return "OSError: " + err.Error()
	}
	doc, err := parseOrdered(previous)
	if err != nil || doc.kind != 'o' {
		return "the configuration file is not a JSON object"
	}
	fresh, err := parseOrdered(string(section))
	if err != nil {
		return err.Error()
	}
	doc.set("security", fresh)
	var out bytes.Buffer
	doc.encode(&out, 0)
	out.WriteByte('\n')
	text := out.String()
	if e := p.CheckConfig(text); e != "" {
		return e
	}
	if err := writeInPlace(p.o.ConfigPath, []byte(text)); err != nil {
		p.restoreConfig(previous)
		return "OSError: " + err.Error()
	}
	if written, err := os.ReadFile(p.o.ConfigPath); err != nil || string(written) != text {
		p.restoreConfig(previous)
		return "the file was not written correctly; the previous configuration was restored"
	}
	return ""
}

// restoreConfig puts earlier configuration text back after a failed save.
func (p *Portal) restoreConfig(previous string) {
	if err := writeInPlace(p.o.ConfigPath, []byte(previous)); err != nil {
		p.Note("restoring the previous configuration failed: " + err.Error())
		return
	}
	p.Note("save failed; previous configuration restored")
}

func (p *Portal) acquireHash() bool {
	select {
	case p.hashing <- struct{}{}:
		return true
	default:
		return false
	}
}

func (p *Portal) releaseHash() { <-p.hashing }

// SetPassword changes the admin password; the error text is empty on success.
func (p *Portal) SetPassword(current, fresh string) string {
	if !p.acquireHash() {
		return "the server is busy; try again shortly"
	}
	defer p.releaseHash()
	p.mu.Lock()
	defer p.mu.Unlock()
	if !adminauth.VerifyPassword(current, p.passwordHash) {
		return "current password is wrong"
	}
	hashed, err := adminauth.HashPassword(fresh, adminauth.ScryptN)
	if err != nil {
		return err.Error()
	}
	text, err := p.ReadConfig()
	if err != nil {
		return "OSError: " + err.Error()
	}
	doc, err := parseOrdered(text)
	if err != nil || doc.kind != 'o' {
		return "ValueError: configuration is not a JSON object"
	}
	admin := doc.get("admin")
	if admin == nil {
		admin = &node{kind: 'o'}
		doc.set("admin", admin)
	}
	if admin.kind != 'o' {
		return "TypeError: admin is not an object"
	}
	admin.set("password_hash", &node{kind: 's', raw: pyString(hashed)})
	var buf bytes.Buffer
	doc.encode(&buf, 0)
	out := buf.Bytes()
	if err := writeInPlace(p.o.ConfigPath, out); err != nil {
		return "OSError: " + err.Error()
	}
	p.passwordHash = hashed
	p.Sessions.DropAll()
	p.Note("admin password changed; all sessions ended")
	return ""
}

// ---- HTTP

func (p *Portal) send(w http.ResponseWriter, code int, body []byte, ctype string, extra ...[2]string) {
	h := w.Header()
	for _, kv := range securityHeaders {
		h.Set(kv[0], kv[1])
	}
	h.Set("Content-Type", ctype)
	h.Set("Content-Length", strconv.Itoa(len(body)))
	for _, kv := range extra {
		h.Add(kv[0], kv[1])
	}
	w.WriteHeader(code)
	w.Write(body)
}

func (p *Portal) json(w http.ResponseWriter, code int, v any, extra ...[2]string) {
	b, err := json.Marshal(v)
	if err != nil {
		b, code = []byte(`{"error":"internal error"}`), 500
	}
	p.send(w, code, b, "application/json", extra...)
}

func sessionToken(r *http.Request) string {
	for _, part := range strings.Split(r.Header.Get("Cookie"), ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 && kv[0] == "gb_session" {
			return strings.Trim(kv[1], `"`)
		}
	}
	return ""
}

func (p *Portal) serve(w http.ResponseWriter, r *http.Request) {
	path := r.RequestURI
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	if path == "/api/labs/console" {
		if r.Method != http.MethodGet {
			p.json(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		p.labConsole(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		p.get(w, r, path)
	case http.MethodPost:
		p.post(w, r, path)
	default:
		p.json(w, 501, map[string]any{"error": "unsupported method"})
	}
}

func (p *Portal) labConsole(w http.ResponseWriter, r *http.Request) {
	session := p.Sessions.Get(sessionToken(r))
	if session == nil {
		p.json(w, http.StatusUnauthorized, map[string]any{"error": "login required"})
		return
	}
	origin, err := url.Parse(r.Header.Get("Origin"))
	if err != nil || origin.Host != r.Host || origin.User != nil || (origin.Scheme != "http" && origin.Scheme != "https") {
		p.json(w, http.StatusForbidden, map[string]any{"error": "same-origin console connection required"})
		return
	}
	if session.Role == "viewer" {
		p.json(w, http.StatusForbidden, map[string]any{"error": "editor role is required for node consoles"})
		return
	}
	team := session.Team
	if session.Role == "system-admin" && r.URL.Query().Get("team") != "" {
		team = r.URL.Query().Get("team")
	}
	if !teamPattern.MatchString(team) {
		p.json(w, 400, map[string]any{"error": "invalid team scope"})
		return
	}
	manager, managerErr := p.labManager(team)
	if managerErr != nil || manager == nil {
		p.json(w, http.StatusServiceUnavailable, map[string]any{"error": "lab runtime is not configured"})
		return
	}
	node := r.URL.Query().Get("node")
	if node == "" || len(node) > 32 {
		p.json(w, http.StatusBadRequest, map[string]any{"error": "node id is required"})
		return
	}
	console, err := manager.NodeConsole(r.Context(), node)
	if err != nil {
		p.json(w, http.StatusNotFound, map[string]any{"error": err.Error()})
		return
	}
	handler := websocket.Handler(func(ws *websocket.Conn) {
		defer console.Close()
		defer ws.Close()
		ws.MaxPayloadBytes = 64 * 1024
		done := make(chan struct{}, 2)
		go func() { _, _ = io.Copy(console, ws); done <- struct{}{} }()
		go func() { _, _ = io.Copy(ws, console); done <- struct{}{} }()
		<-done
	})
	handler.ServeHTTP(w, r)
	_ = console.Close()
}

func (p *Portal) get(w http.ResponseWriter, r *http.Request, path string) {
	if strings.HasPrefix(path, "/api/") {
		p.apiGet(w, r, path)
		return
	}
	name := ""
	switch {
	case path == "/":
		name = "index.html"
	case strings.HasPrefix(path, "/static/"):
		name = strings.TrimPrefix(path, "/static/")
	}
	if name != "" && !strings.Contains(name, "/") && !strings.HasPrefix(name, ".") {
		if ctype, ok := contentTypes[filepath.Ext(name)]; ok {
			if data, err := staticFiles.ReadFile("static/" + name); err == nil {
				p.send(w, 200, data, ctype)
				return
			}
		}
	}
	p.json(w, 404, map[string]any{"error": "not found"})
}

func (p *Portal) apiGet(w http.ResponseWriter, r *http.Request, path string) {
	s := p.Sessions.Get(sessionToken(r))
	if path == "/api/session" {
		var csrf any
		var identity any
		if s != nil {
			csrf = s.CSRF
			identity = map[string]any{"username": s.Username, "team": s.Team, "role": s.Role, "legacy_admin": p.legacyAdmin()}
		}
		p.json(w, 200, map[string]any{"authenticated": s != nil, "csrf": csrf, "identity": identity})
		return
	}
	if s == nil {
		p.json(w, 401, map[string]any{"error": "login required"})
		return
	}
	if s.Role != "system-admin" && !strings.HasPrefix(path, "/api/labs/") {
		p.json(w, http.StatusForbidden, map[string]any{"error": "team role cannot access this endpoint"})
		return
	}
	team := s.Team
	if s.Role == "system-admin" && r.URL.Query().Get("team") != "" {
		team = r.URL.Query().Get("team")
	}
	if !teamPattern.MatchString(team) {
		p.json(w, 400, map[string]any{"error": "invalid team scope"})
		return
	}
	if path == "/api/labs/users" {
		if s.Role != "system-admin" && s.Role != "team-admin" {
			p.json(w, http.StatusForbidden, map[string]any{"error": "team admin role required"})
			return
		}
		if s.Role != "system-admin" && team != s.Team {
			p.json(w, 403, map[string]any{"error": "team admins may only manage their own team"})
			return
		}
		p.json(w, http.StatusOK, map[string]any{"team": team, "users": p.teamUsers(team)})
		return
	}
	if path == "/api/labs/topologies" {
		topologies, err := p.listLabTopologies(team)
		if err != nil {
			p.json(w, 500, map[string]any{"error": "could not read saved lab topologies"})
			return
		}
		p.json(w, 200, map[string]any{"version": lab.TopologyVersion, "topologies": topologies})
		return
	}
	if path == "/api/labs/status" {
		manager, managerErr := p.labManager(team)
		if managerErr != nil {
			p.json(w, 503, map[string]any{"error": managerErr.Error()})
			return
		}
		if manager == nil {
			p.json(w, 200, map[string]any{"available": false})
			return
		}
		status, err := manager.Observe(r.Context())
		if err != nil {
			p.json(w, 503, map[string]any{"error": err.Error()})
			return
		}
		status["available"] = true
		p.json(w, 200, status)
		return
	}
	if p.o.Security != nil && (path == "/api/security" || path == "/api/security/catalog") {
		if path == "/api/security" {
			p.json(w, 200, p.o.Security.Overview(r.Context()))
		} else {
			p.json(w, 200, p.o.Security.Catalog())
		}
		return
	}
	if path == "/api/gateway/status" {
		if p.gateway == nil {
			p.json(w, 200, map[string]any{"available": false})
			return
		}
		out, err := p.gateway.Request(r.Context(), http.MethodGet, "/v1/status", nil)
		if err != nil {
			p.json(w, 200, map[string]any{"available": false, "error": err.Error()})
			return
		}
		p.send(w, 200, out, "application/json; charset=utf-8")
		return
	}
	if path == "/api/gateway/config" {
		if p.gateway == nil {
			p.json(w, 200, map[string]any{"available": false})
			return
		}
		out, err := p.gateway.Request(r.Context(), http.MethodGet, "/v1/config", nil)
		if err != nil {
			p.json(w, 200, map[string]any{"available": false, "error": err.Error()})
			return
		}
		p.send(w, 200, out, "application/json; charset=utf-8")
		return
	}
	if path == "/api/gateway/layer2/profiles" {
		if p.gateway == nil {
			p.json(w, 200, map[string]any{"available": false})
			return
		}
		out, err := p.gateway.Request(r.Context(), http.MethodGet, "/v1/layer2/profiles", nil)
		if err != nil {
			p.json(w, 200, map[string]any{"available": false, "error": err.Error()})
			return
		}
		p.send(w, 200, out, "application/json; charset=utf-8")
		return
	}
	routes := map[string]func() any{
		"/api/hardware": func() any {
			if p.o.Hardware == nil {
				return map[string]any{"available": false, "errors": []string{"Hardware monitoring is unavailable"}}
			}
			return p.o.Hardware()
		},
		"/api/status": func() any {
			if p.o.Snapshot == nil {
				return map[string]any{}
			}
			return p.o.Snapshot()
		},
		"/api/interfaces": func() any { return Interfaces() },
		"/api/routes":     func() any { return Routes() },
		"/api/nat":        func() any { return NATRules() },
		"/api/log":        func() any { return map[string]any{"lines": p.logLines()} },
		"/api/config": func() any {
			text, err := p.ReadConfig()
			if err != nil {
				return map[string]any{"error": err.Error()}
			}
			return map[string]any{"text": text}
		},
	}
	if fn, ok := routes[path]; ok {
		p.json(w, 200, fn())
		return
	}
	p.json(w, 404, map[string]any{"error": "not found"})
}

// body is _body: nil when missing/oversized/invalid/not an object.
func body(r *http.Request) map[string]any {
	length := 0
	if h := r.Header.Get("Content-Length"); h != "" {
		n, err := strconv.Atoi(strings.TrimSpace(h))
		if err != nil {
			return nil
		}
		length = n
	}
	if length < 0 || length > maxBody {
		return nil
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, int64(length)))
	if err != nil || len(raw) != length {
		return nil
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		raw = []byte("{}")
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return nil
	}
	m, _ := v.(map[string]any)
	return m
}

// text is str(body.get(key, "")).
func text(m map[string]any, key string) string {
	switch x := m[key].(type) {
	case nil:
		if _, present := m[key]; present {
			return "None"
		}
		return ""
	case string:
		return x
	case bool:
		if x {
			return "True"
		}
		return "False"
	case float64:
		return strconv.FormatFloat(x, 'g', -1, 64)
	default:
		b, _ := json.Marshal(x)
		return string(b)
	}
}

func (p *Portal) post(w http.ResponseWriter, r *http.Request, path string) {
	b := body(r)
	if b == nil {
		p.json(w, 400, map[string]any{"error": "invalid request body"})
		return
	}
	if path == "/api/login" {
		p.login(w, r, b)
		return
	}
	token := sessionToken(r)
	s := p.Sessions.Get(token)
	if s == nil {
		p.json(w, 401, map[string]any{"error": "login required"})
		return
	}
	if h := r.Header.Get("X-CSRF-Token"); h == "" || h != s.CSRF {
		p.json(w, 403, map[string]any{"error": "bad CSRF token"})
		return
	}
	isLabPath := strings.HasPrefix(path, "/api/labs/")
	if s.Role != "system-admin" && !isLabPath && path != "/api/logout" && path != "/api/account/password" {
		p.json(w, http.StatusForbidden, map[string]any{"error": "team role cannot modify this endpoint"})
		return
	}
	if s.Role == "viewer" && path != "/api/logout" && path != "/api/labs/check" && path != "/api/labs/capture" && path != "/api/account/password" {
		p.json(w, http.StatusForbidden, map[string]any{"error": "editor role is required for lab changes"})
		return
	}
	if path == "/api/labs/users" && s.Role != "system-admin" && s.Role != "team-admin" {
		p.json(w, http.StatusForbidden, map[string]any{"error": "team admin role required"})
		return
	}
	team := s.Team
	if s.Role == "system-admin" {
		if requested := text(b, "team"); requested != "" {
			team = requested
		}
	}
	if !teamPattern.MatchString(team) {
		p.json(w, 400, map[string]any{"error": "invalid team scope"})
		return
	}
	var labManager *lab.Manager
	if isLabPath {
		var managerErr error
		labManager, managerErr = p.labManager(team)
		if managerErr != nil {
			p.json(w, http.StatusServiceUnavailable, map[string]any{"error": managerErr.Error()})
			return
		}
	}
	result := func(e string) {
		code := 200
		var msg any
		if e != "" {
			code, msg = 422, e
		}
		p.json(w, code, map[string]any{"ok": e == "", "error": msg})
	}
	switch path {
	case "/api/account/password":
		if p.legacyAdmin() {
			result(p.SetPassword(text(b, "current"), text(b, "new")))
			return
		}
		_, err := p.changeTeamUser(s.Team, "password", s.Username, text(b, "current"), text(b, "new"), s.Role)
		if err != nil {
			p.json(w, 422, map[string]any{"error": err.Error()})
			return
		}
		p.Sessions.DropUser(s.Team, s.Username)
		p.json(w, 200, map[string]any{"ok": true})
	case "/api/labs/users":
		newRole := text(b, "role")
		if s.Role == "system-admin" && newRole == "team-admin" {
			// A system admin can bootstrap another team's first scoped administrator;
			// ordinary team admins can only add editors and viewers to their own team.
		} else if newRole == "team-admin" {
			p.json(w, 403, map[string]any{"error": "only a system admin can provision team admins"})
			return
		}
		users, err := p.changeTeamUser(team, text(b, "action"), text(b, "username"), "", text(b, "password"), newRole)
		if err != nil {
			p.json(w, 422, map[string]any{"error": err.Error()})
			return
		}
		p.json(w, 200, map[string]any{"ok": true, "users": users})
	case "/api/labs/topologies":
		topologyValue, ok := b["topology"]
		if !ok {
			p.json(w, 400, map[string]any{"error": "topology required"})
			return
		}
		raw, err := json.Marshal(topologyValue)
		if err != nil {
			p.json(w, 400, map[string]any{"error": "invalid topology"})
			return
		}
		if err := p.saveLabTopology(team, raw); err != nil {
			p.json(w, 422, map[string]any{"error": err.Error()})
			return
		}
		p.Note("lab topology saved")
		p.json(w, 200, map[string]any{"ok": true})
	case "/api/labs/apply":
		if labManager == nil {
			p.json(w, 503, map[string]any{"ok": false, "error": "lab runtime is not configured"})
			return
		}
		topologyValue, ok := b["topology"]
		if !ok {
			p.json(w, 400, map[string]any{"error": "topology required"})
			return
		}
		raw, err := json.Marshal(topologyValue)
		if err != nil {
			p.json(w, 400, map[string]any{"error": "invalid topology"})
			return
		}
		topology, err := lab.DecodeTopology(raw)
		if err != nil {
			p.json(w, 422, map[string]any{"error": err.Error()})
			return
		}
		state, err := labManager.Apply(r.Context(), topology)
		if err != nil {
			p.json(w, 422, map[string]any{"error": err.Error()})
			return
		}
		p.Note("lab topology applied: " + topology.ID)
		p.json(w, 200, map[string]any{"ok": true, "state": state})
	case "/api/labs/action":
		if labManager == nil {
			p.json(w, 503, map[string]any{"error": "lab runtime is not configured"})
			return
		}
		var err error
		switch text(b, "action") {
		case "pause":
			err = labManager.Pause(r.Context())
		case "resume":
			err = labManager.Resume(r.Context())
		case "rollback":
			var state lab.State
			state, err = labManager.Rollback(r.Context())
			if err == nil {
				p.json(w, 200, map[string]any{"ok": true, "state": state})
				return
			}
		case "restart-node":
			err = labManager.RestartNode(r.Context(), text(b, "node"))
		case "link-down":
			err = labManager.SetLinkUp(r.Context(), text(b, "link"), false)
		case "link-up":
			err = labManager.SetLinkUp(r.Context(), text(b, "link"), true)
		case "link-flap":
			ms, parseErr := strconv.Atoi(text(b, "duration_ms"))
			if parseErr != nil {
				p.json(w, 400, map[string]any{"error": "duration_ms must be an integer"})
				return
			}
			err = labManager.FlapLink(r.Context(), text(b, "link"), time.Duration(ms)*time.Millisecond)
		case "set-impairment":
			var impairment lab.Impairment
			raw, marshalErr := json.Marshal(b["impairment"])
			if marshalErr != nil || json.Unmarshal(raw, &impairment) != nil {
				p.json(w, 400, map[string]any{"error": "invalid impairment"})
				return
			}
			err = labManager.SetImpairment(r.Context(), text(b, "link"), impairment)
		case "interface-errors":
			var fault lab.Impairment
			raw, marshalErr := json.Marshal(b["impairment"])
			if marshalErr != nil || json.Unmarshal(raw, &fault) != nil {
				p.json(w, 400, map[string]any{"error": "invalid interface fault"})
				return
			}
			err = labManager.SetInterfaceFault(r.Context(), text(b, "node"), text(b, "interface"), fault)
		default:
			p.json(w, 400, map[string]any{"error": "unsupported lab action"})
			return
		}
		if err != nil {
			p.json(w, 422, map[string]any{"error": err.Error()})
			return
		}
		p.json(w, 200, map[string]any{"ok": true})
	case "/api/labs/check":
		if labManager == nil {
			p.json(w, 503, map[string]any{"error": "lab runtime is not configured"})
			return
		}
		results, err := labManager.RunAssertions(r.Context())
		if err != nil {
			p.json(w, 422, map[string]any{"error": err.Error(), "results": results})
			return
		}
		passed := 0
		for _, result := range results {
			if result.Passed {
				passed++
			}
		}
		p.json(w, 200, map[string]any{"ok": passed == len(results), "passed": passed, "total": len(results), "results": results})
	case "/api/labs/capture":
		if labManager == nil {
			p.json(w, 503, map[string]any{"error": "lab runtime is not configured"})
			return
		}
		ms, parseErr := strconv.Atoi(text(b, "duration_ms"))
		if parseErr != nil {
			p.json(w, 400, map[string]any{"error": "duration_ms must be an integer"})
			return
		}
		data, err := labManager.CaptureLink(r.Context(), text(b, "link"), time.Duration(ms)*time.Millisecond)
		if err != nil {
			p.json(w, 422, map[string]any{"error": err.Error()})
			return
		}
		p.json(w, 200, map[string]any{"link": text(b, "link"), "pcap_base64": data})
	case "/api/logout":
		p.Sessions.Drop(token)
		p.json(w, 200, map[string]any{"ok": true}, [2]string{"Set-Cookie", "gb_session=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict"})
	case "/api/config/validate":
		e := p.CheckConfig(text(b, "text"))
		var msg any
		if e != "" {
			msg = e
		}
		p.json(w, 200, map[string]any{"ok": e == "", "error": msg})
	case "/api/config":
		result(p.ApplyConfig(text(b, "text")))
	case "/api/security":
		if p.o.Security == nil {
			p.json(w, 404, map[string]any{"error": "not found"})
			return
		}
		settings, ok := b["settings"]
		if !ok {
			p.json(w, 400, map[string]any{"error": "settings required"})
			return
		}
		raw, _ := json.Marshal(settings)
		// Live first: a refused configuration must never reach the file, and a file that cannot be written
		// is reported even though the settings are already in force.
		applied, err := p.o.Security.Apply(r.Context(), raw)
		if err != nil {
			result(err.Error())
			return
		}
		if e := p.persistSecurity(applied); e != "" {
			p.json(w, 500, map[string]any{"ok": false, "applied": true, "error": "applied, but not saved to the configuration file (it will revert at the next restart): " + e})
			return
		}
		p.Note("security settings applied and saved")
		p.json(w, 200, map[string]any{"ok": true, "error": nil})
	case "/api/security/action":
		if p.o.Security == nil {
			p.json(w, 404, map[string]any{"error": "not found"})
			return
		}
		args, _ := b["args"].(map[string]any)
		out, err := p.o.Security.Do(r.Context(), text(b, "action"), args)
		if err != nil {
			p.json(w, 422, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		p.json(w, 200, map[string]any{"ok": true, "error": nil, "result": out})
	case "/api/gateway/validate", "/api/gateway/plan", "/api/gateway/config", "/api/gateway/rollback":
		if p.gateway == nil {
			p.json(w, 503, map[string]any{"ok": false, "error": "gateway daemon is not configured"})
			return
		}
		if path == "/api/gateway/rollback" {
			out, err := p.gateway.Request(r.Context(), http.MethodPost, "/v1/config/rollback", nil)
			if err != nil {
				p.json(w, 422, map[string]any{"ok": false, "error": err.Error()})
				return
			}
			p.send(w, 200, out, "application/json; charset=utf-8")
			return
		}
		config, ok := b["config"]
		if !ok {
			p.json(w, 400, map[string]any{"ok": false, "error": "config required"})
			return
		}
		raw, err := json.Marshal(config)
		if err != nil {
			p.json(w, 400, map[string]any{"ok": false, "error": "invalid config"})
			return
		}
		method, endpoint := http.MethodPost, "/v1/config/validate"
		if path == "/api/gateway/plan" {
			endpoint = "/v1/config/plan"
		} else if path == "/api/gateway/config" {
			method, endpoint = http.MethodPut, "/v1/config"
		}
		out, err := p.gateway.Request(r.Context(), method, endpoint, raw)
		if err != nil {
			p.json(w, 422, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		p.send(w, 200, out, "application/json; charset=utf-8")
	case "/api/password":
		if !p.legacyAdmin() {
			result("Use Account password on the Labs page to change this account's password.")
			return
		}
		result(p.SetPassword(text(b, "current"), text(b, "new")))
	case "/api/restart":
		if v, _ := b["confirm"].(bool); !v {
			p.json(w, 400, map[string]any{"error": "confirmation required"})
			return
		}
		p.Note("restart requested from the portal")
		p.json(w, 202, map[string]any{"ok": true})
		time.AfterFunc(500*time.Millisecond, p.o.RequestRestart)
	default:
		p.json(w, 404, map[string]any{"error": "not found"})
	}
}

func (p *Portal) login(w http.ResponseWriter, r *http.Request, b map[string]any) {
	addr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		addr = r.RemoteAddr
	}
	if wait := p.Throttle.RetryAfter(addr); wait > 0 {
		after := strconv.Itoa(int(wait) + 1)
		p.json(w, 429, map[string]any{"error": "too many attempts; retry in " + after + "s"}, [2]string{"Retry-After", after})
		return
	}
	password, ok := b["password"].(string)
	username, _ := b["username"].(string)
	if username == "" {
		username = "admin"
	}
	p.mu.Lock()
	users := append([]AdminUser(nil), p.o.Settings.Users...)
	hash := p.passwordHash
	p.mu.Unlock()
	team, role := "", ""
	if len(users) > 0 {
		for _, user := range users {
			if strings.EqualFold(user.Username, username) {
				hash, team, role = user.PasswordHash, user.Team, user.Role
				username = user.Username
				break
			}
		}
	} else if username == "admin" {
		team, role = "default", "system-admin"
	}
	if !p.acquireHash() {
		p.json(w, 503, map[string]any{"error": "server busy; retry shortly"}, [2]string{"Retry-After", "1"})
		return
	}
	verified := ok && hash != "" && adminauth.VerifyPassword(password, hash)
	p.releaseHash()
	if !verified {
		p.Throttle.Fail(addr)
		p.Note("failed login from " + addr)
		p.json(w, 401, map[string]any{"error": "invalid password"})
		return
	}
	p.Throttle.Success(addr)
	token, csrf := p.Sessions.CreateFor(username, team, role)
	p.Note("login from " + addr + " as " + username + " (team " + team + ")")
	p.json(w, 200, map[string]any{"ok": true, "csrf": csrf, "identity": map[string]any{"username": username, "team": team, "role": role, "legacy_admin": len(users) == 0}},
		[2]string{"Set-Cookie", "gb_session=" + token + "; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=28800"})
}
