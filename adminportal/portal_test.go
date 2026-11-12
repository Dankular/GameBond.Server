package adminportal

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Dankular/GameBond.Server/adminauth"
)

const password = "correct horse battery"

type rig struct {
	t        *testing.T
	portal   *Portal
	base     string
	client   *http.Client
	config   string
	restarts atomic.Int32
	now      float64
	validate func(string) error
}

func newRig(t *testing.T) *rig {
	t.Helper()
	hash, err := adminauth.HashPassword(password, 1<<10)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	r := &rig{t: t, config: filepath.Join(dir, "server.json"), now: 1000, client: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	cfg := map[string]any{"role": "server", "mtu": 1280, "admin": map[string]any{"enabled": true, "password_hash": hash, "bind": []any{"127.0.0.1", 8443}}}
	raw, _ := json.Marshal(cfg)
	if err := os.WriteFile(r.config, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	s := &Settings{Enabled: true, Host: "127.0.0.1", Port: 0, PasswordHash: hash, LogLines: 50}
	r.portal = New(Options{Settings: s, ConfigPath: r.config, TempDir: dir, Snapshot: func() any { return map[string]any{"state": "up"} },
		Validate: func(path string) error {
			if r.validate != nil {
				return r.validate(path)
			}
			return nil
		}, RequestRestart: func() { r.restarts.Add(1) }, Clock: func() float64 { return r.now }})
	if err := r.portal.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.portal.Close)
	r.base = "http://127.0.0.1:" + itoa(r.portal.Port)
	return r
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

type reply struct {
	code   int
	header http.Header
	body   map[string]any
	raw    []byte
}

func (r *rig) do(method, path string, body any, cookie, csrf string) reply {
	r.t.Helper()
	var rd io.Reader
	if s, ok := body.(string); ok {
		rd = strings.NewReader(s)
	} else if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, r.base+path, rd)
	if cookie != "" {
		req.Header.Set("Cookie", "gb_session="+cookie)
	}
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := reply{code: resp.StatusCode, header: resp.Header, raw: raw}
	_ = json.Unmarshal(raw, &out.body)
	return out
}

func (r *rig) login() (token, csrf string) {
	r.t.Helper()
	rep := r.do("POST", "/api/login", map[string]any{"password": password}, "", "")
	if rep.code != 200 {
		r.t.Fatalf("login: %d %s", rep.code, rep.raw)
	}
	c := rep.header.Get("Set-Cookie")
	token = strings.TrimPrefix(strings.SplitN(c, ";", 2)[0], "gb_session=")
	return token, rep.body["csrf"].(string)
}

func TestStaticFilesAndSecurityHeaders(t *testing.T) {
	r := newRig(t)
	for path, ctype := range map[string]string{"/": "text/html; charset=utf-8", "/static/app.js": "text/javascript; charset=utf-8", "/static/style.css": "text/css; charset=utf-8"} {
		rep := r.do("GET", path, nil, "", "")
		if rep.code != 200 || rep.header.Get("Content-Type") != ctype || len(rep.raw) == 0 {
			t.Fatalf("%s: %d %q", path, rep.code, rep.header.Get("Content-Type"))
		}
		for _, h := range []string{"Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Strict-Transport-Security"} {
			if rep.header.Get(h) == "" {
				t.Fatalf("%s lacks %s", path, h)
			}
		}
		if rep.header.Get("Cache-Control") != "no-store" {
			t.Fatalf("%s cache control %q", path, rep.header.Get("Cache-Control"))
		}
	}
	for _, path := range []string{"/static/../x", "/static/.hidden", "/static/sub/app.js", "/static/nope.js", "/static/app.txt", "/static/", "/index.html", "/nothing"} {
		if rep := r.do("GET", path, nil, "", ""); rep.code != 404 || rep.body["error"] != "not found" {
			t.Fatalf("%s: %d %s", path, rep.code, rep.raw)
		}
	}
	if rep := r.do("GET", "/?x=1", nil, "", ""); rep.code != 200 {
		t.Fatalf("query string not stripped: %d", rep.code)
	}
}

func TestEmbeddedAssetsMatchPython(t *testing.T) {
	for _, name := range []string{"index.html", "app.js", "style.css"} {
		python, err := os.ReadFile(filepath.Join("..", "..", "gamebond", "admin", "static", name))
		if err != nil {
			t.Skip("the Python portal is gone, so there is nothing to compare against")
		}
		embedded, _ := staticFiles.ReadFile("static/" + name)
		if !bytes.Equal(python, embedded) {
			t.Fatalf("static/%s differs from gamebond/admin/static/%s: copy it again", name, name)
		}
	}
}

func TestSessionAndLoginFlow(t *testing.T) {
	r := newRig(t)
	if rep := r.do("GET", "/api/session", nil, "", ""); rep.body["authenticated"] != false || rep.body["csrf"] != nil {
		t.Fatalf("anonymous session: %s", rep.raw)
	}
	for _, path := range []string{"/api/status", "/api/config", "/api/log", "/api/interfaces", "/api/routes", "/api/nat"} {
		if rep := r.do("GET", path, nil, "", ""); rep.code != 401 || rep.body["error"] != "login required" {
			t.Fatalf("%s anonymous: %d %s", path, rep.code, rep.raw)
		}
	}
	token, csrf := r.login()
	cookie := r.do("POST", "/api/login", map[string]any{"password": password}, "", "").header.Get("Set-Cookie")
	for _, want := range []string{"Path=/", "Secure", "HttpOnly", "SameSite=Strict", "Max-Age=28800"} {
		if !strings.Contains(cookie, want) {
			t.Fatalf("cookie %q lacks %s", cookie, want)
		}
	}
	if rep := r.do("GET", "/api/session", nil, token, ""); rep.body["authenticated"] != true || rep.body["csrf"] != csrf {
		t.Fatalf("session: %s", rep.raw)
	}
	if rep := r.do("GET", "/api/status", nil, token, ""); rep.code != 200 || rep.body["state"] != "up" {
		t.Fatalf("status: %d %s", rep.code, rep.raw)
	}
	if rep := r.do("GET", "/api/config", nil, token, ""); rep.code != 200 || !strings.Contains(rep.body["text"].(string), `"role"`) {
		t.Fatalf("config: %s", rep.raw)
	}
	if rep := r.do("GET", "/api/unknown", nil, token, ""); rep.code != 404 {
		t.Fatalf("unknown api: %d", rep.code)
	}
	if rep := r.do("GET", "/api/log", nil, token, ""); rep.code != 200 || len(rep.body["lines"].([]any)) == 0 {
		t.Fatalf("log: %s", rep.raw)
	}
	// logout needs the CSRF token, then ends the session
	if rep := r.do("POST", "/api/logout", map[string]any{}, token, "wrong"); rep.code != 403 || rep.body["error"] != "bad CSRF token" {
		t.Fatalf("logout without csrf: %d %s", rep.code, rep.raw)
	}
	rep := r.do("POST", "/api/logout", map[string]any{}, token, csrf)
	if rep.code != 200 || !strings.Contains(rep.header.Get("Set-Cookie"), "Max-Age=0") {
		t.Fatalf("logout: %d %v", rep.code, rep.header)
	}
	if rep := r.do("GET", "/api/session", nil, token, ""); rep.body["authenticated"] != false {
		t.Fatal("session survived logout")
	}
}

func TestLoginRejectionAndThrottle(t *testing.T) {
	r := newRig(t)
	for i := 0; i < 20; i++ {
		rep := r.do("POST", "/api/login", map[string]any{"password": "wrong"}, "", "")
		if rep.code == 429 {
			if rep.header.Get("Retry-After") == "" || !strings.HasPrefix(rep.body["error"].(string), "too many attempts; retry in ") {
				t.Fatalf("429 shape: %v %s", rep.header, rep.raw)
			}
			// even the right password is refused during the lockout
			if r.do("POST", "/api/login", map[string]any{"password": password}, "", "").code != 429 {
				t.Fatal("lockout did not hold for the right password")
			}
			r.now += 100000 // far past any backoff
			if r.do("POST", "/api/login", map[string]any{"password": password}, "", "").code != 200 {
				t.Fatal("lockout never ended")
			}
			return
		}
		if rep.code != 401 || rep.body["error"] != "invalid password" {
			t.Fatalf("attempt %d: %d %s", i, rep.code, rep.raw)
		}
	}
	t.Fatal("no throttle after 20 failures")
}

func TestPostBodyValidation(t *testing.T) {
	r := newRig(t)
	for name, body := range map[string]any{"not json": "{", "array": "[1]", "string": `"x"`, "oversized": `{"x":"` + strings.Repeat("a", maxBody) + `"}`} {
		if rep := r.do("POST", "/api/login", body, "", ""); rep.code != 400 || rep.body["error"] != "invalid request body" {
			t.Fatalf("%s: %d %s", name, rep.code, rep.raw)
		}
	}
	// an empty body is {}: it reaches the handler and fails as a wrong password
	if rep := r.do("POST", "/api/login", nil, "", ""); rep.code != 401 {
		t.Fatalf("empty body: %d", rep.code)
	}
	if rep := r.do("POST", "/api/login", map[string]any{"password": 5}, "", ""); rep.code != 401 {
		t.Fatalf("non-string password: %d", rep.code)
	}
	if rep := r.do("POST", "/api/nothing", map[string]any{}, "", ""); rep.code != 401 {
		t.Fatalf("unauthenticated unknown POST: %d", rep.code)
	}
	token, csrf := r.login()
	if rep := r.do("POST", "/api/nothing", map[string]any{}, token, csrf); rep.code != 404 {
		t.Fatalf("unknown POST: %d", rep.code)
	}
	if rep := r.do("PUT", "/api/config", map[string]any{}, token, csrf); rep.code != 501 {
		t.Fatalf("PUT: %d", rep.code)
	}
}

func TestConfigValidateAndApply(t *testing.T) {
	r := newRig(t)
	token, csrf := r.login()
	current := func() map[string]any {
		rep := r.do("GET", "/api/config", nil, token, "")
		var m map[string]any
		json.Unmarshal([]byte(rep.body["text"].(string)), &m)
		return m
	}
	valid := current()
	valid["mtu"] = 1300
	good, _ := json.Marshal(valid)
	check := func(text string) reply {
		return r.do("POST", "/api/config/validate", map[string]any{"text": text}, token, csrf)
	}
	if rep := check(string(good)); rep.code != 200 || rep.body["ok"] != true || rep.body["error"] != nil {
		t.Fatalf("valid: %s", rep.raw)
	}
	if rep := check("{"); rep.body["ok"] != false || !strings.HasPrefix(rep.body["error"].(string), "ValueError: ") {
		t.Fatalf("bad json: %s", rep.raw)
	}
	if rep := check("[1]"); rep.body["error"] != "config must be a JSON object" {
		t.Fatalf("array: %s", rep.raw)
	}
	tampered := current()
	tampered["admin"].(map[string]any)["enabled"] = false
	bad, _ := json.Marshal(tampered)
	if rep := check(string(bad)); rep.body["error"] != "the admin block cannot be edited here; use the Administration page" {
		t.Fatalf("admin edit: %s", rep.raw)
	}
	delete(tampered, "admin")
	gone, _ := json.Marshal(tampered)
	if rep := check(string(gone)); rep.body["ok"] != false {
		t.Fatalf("removing the admin block accepted: %s", rep.raw)
	}
	r.validate = func(path string) error {
		raw, _ := os.ReadFile(path)
		if bytes.Contains(raw, []byte("1300")) {
			return errors.New("mtu must be 1280")
		}
		return nil
	}
	if rep := check(string(good)); rep.body["error"] != "ValueError: mtu must be 1280" {
		t.Fatalf("validator error: %s", rep.raw)
	}
	// apply: validation failure leaves the file alone with 422
	before, _ := os.ReadFile(r.config)
	if rep := r.do("POST", "/api/config", map[string]any{"text": string(good)}, token, csrf); rep.code != 422 || rep.body["ok"] != false {
		t.Fatalf("apply invalid: %d %s", rep.code, rep.raw)
	}
	if after, _ := os.ReadFile(r.config); !bytes.Equal(before, after) {
		t.Fatal("a rejected apply changed the file")
	}
	r.validate = nil
	if rep := r.do("POST", "/api/config", map[string]any{"text": string(good)}, token, csrf); rep.code != 200 || rep.body["ok"] != true {
		t.Fatalf("apply: %d %s", rep.code, rep.raw)
	}
	if after, _ := os.ReadFile(r.config); string(after) != string(good) {
		t.Fatal("apply did not write the text")
	}
	if prev, _ := os.ReadFile(filepath.Join(filepath.Dir(r.config), "gamebond-config.previous.json")); !bytes.Equal(prev, before) {
		t.Fatal("previous configuration not kept")
	}
	// A shorter document must replace, not overlay, the longer one.
	shorter := current()
	delete(shorter, "mtu")
	short, _ := json.Marshal(shorter)
	if rep := r.do("POST", "/api/config", map[string]any{"text": string(short)}, token, csrf); rep.code != 200 {
		t.Fatalf("apply shorter: %d %s", rep.code, rep.raw)
	}
	if after, _ := os.ReadFile(r.config); string(after) != string(short) {
		t.Fatalf("shorter config left old bytes behind: %q", after)
	}
	if rep := r.do("GET", "/api/log", nil, token, ""); !strings.Contains(string(rep.raw), "configuration written; restart required to apply") {
		t.Fatalf("log: %s", rep.raw)
	}
}

func TestPasswordChange(t *testing.T) {
	r := newRig(t)
	token, csrf := r.login()
	set := func(cur, fresh string) reply {
		return r.do("POST", "/api/password", map[string]any{"current": cur, "new": fresh}, token, csrf)
	}
	if rep := set("nope", "another long password"); rep.code != 422 || rep.body["error"] != "current password is wrong" {
		t.Fatalf("wrong current: %d %s", rep.code, rep.raw)
	}
	if rep := set(password, "short"); rep.code != 422 || rep.body["error"] != "password must be at least 10 characters" {
		t.Fatalf("short: %d %s", rep.code, rep.raw)
	}
	if rep := set(password, "another long password"); rep.code != 200 || rep.body["ok"] != true {
		t.Fatalf("change: %d %s", rep.code, rep.raw)
	}
	if rep := r.do("GET", "/api/session", nil, token, ""); rep.body["authenticated"] != false {
		t.Fatal("old session survived a password change")
	}
	raw, _ := os.ReadFile(r.config)
	var cfg map[string]any
	json.Unmarshal(raw, &cfg)
	hash := cfg["admin"].(map[string]any)["password_hash"].(string)
	if !adminauth.VerifyPassword("another long password", hash) || cfg["role"] != "server" {
		t.Fatalf("config after change: %s", raw)
	}
	if rep := r.do("POST", "/api/login", map[string]any{"password": password}, "", ""); rep.code != 401 {
		t.Fatal("old password still works")
	}
	if rep := r.do("POST", "/api/login", map[string]any{"password": "another long password"}, "", ""); rep.code != 200 {
		t.Fatal("new password rejected")
	}
}

func TestRestartNeedsConfirmation(t *testing.T) {
	r := newRig(t)
	token, csrf := r.login()
	for _, body := range []any{map[string]any{}, map[string]any{"confirm": "true"}, map[string]any{"confirm": 1}, map[string]any{"confirm": false}} {
		if rep := r.do("POST", "/api/restart", body, token, csrf); rep.code != 400 || rep.body["error"] != "confirmation required" {
			t.Fatalf("%v: %d %s", body, rep.code, rep.raw)
		}
	}
	if r.restarts.Load() != 0 {
		t.Fatal("restart ran without confirmation")
	}
	if rep := r.do("POST", "/api/restart", map[string]any{"confirm": true}, token, csrf); rep.code != 202 || rep.body["ok"] != true {
		t.Fatalf("restart: %d %s", rep.code, rep.raw)
	}
	if r.restarts.Load() != 0 {
		t.Fatal("restart did not wait for the reply to be sent")
	}
	deadline := time.Now().Add(3 * time.Second)
	for r.restarts.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if r.restarts.Load() != 1 {
		t.Fatalf("restart callbacks: %d", r.restarts.Load())
	}
}

func TestLogRingKeepsOnlyLogLines(t *testing.T) {
	r := newRig(t)
	for i := 0; i < 80; i++ {
		r.portal.Note("line")
	}
	if n := len(r.portal.logLines()); n != 50 {
		t.Fatalf("ring holds %d lines, want 50", n)
	}
}

func TestSelfSignedCertificateServesTLS(t *testing.T) {
	dir := t.TempDir()
	info, err := WriteSelfSigned(dir, []string{"127.0.0.1", "admin.example"}, 30)
	if err != nil || info["self_signed"] != true || info["days"] != 30 {
		t.Fatalf("%v %v", info, err)
	}
	if _, err := WriteSelfSigned(dir, nil, 30); err == nil {
		t.Fatal("an existing key was overwritten")
	}
	certPEM, _ := os.ReadFile(info["cert"].(string))
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("certificate not PEM")
	}
	hash, _ := adminauth.HashPassword(password, 1<<10)
	s := &Settings{Enabled: true, Host: "127.0.0.1", Port: 0, PasswordHash: hash, LogLines: 50, TLSCert: info["cert"].(string), TLSKey: info["key"].(string)}
	p := New(Options{Settings: s, ConfigPath: filepath.Join(dir, "none.json")})
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	resp, err := client.Get("https://127.0.0.1:" + itoa(p.Port) + "/api/session")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	old := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11}}}
	if _, err := old.Get("https://127.0.0.1:" + itoa(p.Port) + "/"); err == nil {
		t.Fatal("TLS 1.1 accepted")
	}
	cert, _ := x509.ParseCertificate(mustDecode(t, certPEM))
	if cert.Subject.CommonName != "gamebond-admin" || len(cert.IPAddresses) != 1 || len(cert.DNSNames) != 1 {
		t.Fatalf("certificate fields: %+v", cert)
	}
	if st, _ := os.Stat(info["key"].(string)); st.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Fatalf("key mode %v", st.Mode())
	}
}

func mustDecode(t *testing.T, pemBytes []byte) []byte {
	t.Helper()
	i := bytes.Index(pemBytes, []byte("-----BEGIN"))
	if i < 0 {
		t.Fatal("no PEM block")
	}
	block, _ := pemDecode(pemBytes)
	return block
}

func TestSuccessfulLoginClearsTheFailureCount(t *testing.T) {
	r := newRig(t)
	fail := func() int { return r.do("POST", "/api/login", map[string]any{"password": "wrong"}, "", "").code }
	for round := 0; round < 3; round++ {
		for i := 0; i < 4; i++ { // four failures are free
			if code := fail(); code != 401 {
				t.Fatalf("round %d failure %d answered %d", round, i, code)
			}
		}
		if r.do("POST", "/api/login", map[string]any{"password": password}, "", "").code != 200 {
			t.Fatalf("round %d: right password refused", round)
		}
	}
}

// Password verification needs tens of MiB each, so only a couple may run at once; a burst of
// parallel logins is turned away instead of exhausting the container's memory.
func TestLoginIsBoundedWhileHashingSlotsAreBusy(t *testing.T) {
	r := newRig(t)
	for i := 0; i < maxHashing; i++ {
		if !r.portal.acquireHash() {
			t.Fatal("slot should be free")
		}
	}
	rep := r.do("POST", "/api/login", map[string]any{"password": password}, "", "")
	if rep.code != 503 || rep.header.Get("Retry-After") == "" {
		t.Fatalf("busy login: %d %s", rep.code, rep.raw)
	}
	if got := r.portal.Throttle.RetryAfter("127.0.0.1"); got != 0 {
		t.Fatalf("a refused attempt must not count as a failed login (wait %v)", got)
	}
	r.portal.releaseHash()
	r.portal.releaseHash()
	r.login()
	if len(r.portal.hashing) != 0 {
		t.Fatal("hashing slot leaked")
	}
}

func TestLoginAndPasswordChangeShareTheLimit(t *testing.T) {
	r := newRig(t)
	for i := 0; i < maxHashing; i++ {
		r.portal.acquireHash()
	}
	if msg := r.portal.SetPassword(password, "another long password"); !strings.Contains(msg, "busy") {
		t.Fatalf("SetPassword while busy: %q", msg)
	}
}

func TestRestoreConfigPutsPreviousTextBack(t *testing.T) {
	r := newRig(t)
	before, _ := r.portal.ReadConfig()
	if err := writeInPlace(r.config, []byte(`{"trunc`)); err != nil {
		t.Fatal(err)
	}
	r.portal.restoreConfig(before)
	if after, _ := r.portal.ReadConfig(); after != before {
		t.Fatalf("not restored: %q", after)
	}
}
