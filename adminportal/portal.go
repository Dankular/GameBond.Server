package adminportal

import (
	"bytes"
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Dankular/GameBond.Server/adminauth"
)

//go:embed static/*
var staticFiles embed.FS

// RestartExitCode is the status the container entrypoint treats as "restart".
const RestartExitCode = 75

const maxBody = 256 * 1024

// maxHashing is how many password hashes may run at the same time.
const maxHashing = 2

var contentTypes = map[string]string{".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8"}

var securityHeaders = [][2]string{
	{"Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"},
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
	passwordHash string
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
	return &Portal{o: o, hashing: make(chan struct{}, maxHashing), Sessions: adminauth.NewSessions(o.Clock), Throttle: adminauth.NewThrottle(o.Clock), passwordHash: o.Settings.PasswordHash}
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
	switch r.Method {
	case http.MethodGet:
		p.get(w, r, path)
	case http.MethodPost:
		p.post(w, r, path)
	default:
		p.json(w, 501, map[string]any{"error": "unsupported method"})
	}
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
		if s != nil {
			csrf = s.CSRF
		}
		p.json(w, 200, map[string]any{"authenticated": s != nil, "csrf": csrf})
		return
	}
	if s == nil {
		p.json(w, 401, map[string]any{"error": "login required"})
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
	result := func(e string) {
		code := 200
		var msg any
		if e != "" {
			code, msg = 422, e
		}
		p.json(w, code, map[string]any{"ok": e == "", "error": msg})
	}
	switch path {
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
	case "/api/password":
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
	p.mu.Lock()
	hash := p.passwordHash
	p.mu.Unlock()
	if !p.acquireHash() {
		p.json(w, 503, map[string]any{"error": "server busy; retry shortly"}, [2]string{"Retry-After", "1"})
		return
	}
	verified := ok && adminauth.VerifyPassword(password, hash)
	p.releaseHash()
	if !verified {
		p.Throttle.Fail(addr)
		p.Note("failed login from " + addr)
		p.json(w, 401, map[string]any{"error": "invalid password"})
		return
	}
	p.Throttle.Success(addr)
	token, csrf := p.Sessions.Create()
	p.Note("login from " + addr)
	p.json(w, 200, map[string]any{"ok": true, "csrf": csrf},
		[2]string{"Set-Cookie", "gb_session=" + token + "; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=28800"})
}
