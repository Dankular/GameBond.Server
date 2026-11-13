package adminportal

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

type fakeSecurity struct {
	applied json.RawMessage
	fail    error
	actions []string
}

func (f *fakeSecurity) Overview(context.Context) any {
	return map[string]any{"ids": map[string]any{"mode": "detect"}}
}
func (f *fakeSecurity) Catalog() any { return map[string]any{"categories": []string{"ads"}} }
func (f *fakeSecurity) Apply(_ context.Context, raw json.RawMessage) (json.RawMessage, error) {
	if f.fail != nil {
		return nil, f.fail
	}
	f.applied = raw
	return raw, nil
}
func (f *fakeSecurity) Do(_ context.Context, action string, args map[string]any) (any, error) {
	f.actions = append(f.actions, action)
	if action == "bad" {
		return nil, errors.New("no such action")
	}
	return map[string]any{"echo": args["ip"]}, nil
}

func TestSecurityEndpoints(t *testing.T) {
	r := newRig(t)
	fake := &fakeSecurity{}
	r.portal.o.Security = fake
	if got := r.do("GET", "/api/security", nil, "", ""); got.code != 401 {
		t.Fatalf("login is required to read security: %d", got.code)
	}
	token, csrf := r.login()
	if got := r.do("GET", "/api/security", nil, token, ""); got.code != 200 || !strings.Contains(string(got.raw), "detect") {
		t.Fatalf("%d %s", got.code, got.raw)
	}
	if got := r.do("GET", "/api/security/catalog", nil, token, ""); got.code != 200 || !strings.Contains(string(got.raw), "ads") {
		t.Fatalf("%d %s", got.code, got.raw)
	}
	if got := r.do("POST", "/api/security", map[string]any{"settings": map[string]any{"ids": map[string]any{"mode": "prevent"}}}, token, ""); got.code != 403 {
		t.Fatalf("a missing CSRF token must be refused: %d", got.code)
	}
	if got := r.do("POST", "/api/security", map[string]any{}, token, csrf); got.code != 400 {
		t.Fatalf("%d", got.code)
	}

	got := r.do("POST", "/api/security", map[string]any{"settings": map[string]any{"ids": map[string]any{"mode": "prevent"}}}, token, csrf)
	if got.code != 200 || got.body["ok"] != true {
		t.Fatalf("%d %s", got.code, got.raw)
	}
	saved, _ := os.ReadFile(r.config)
	var doc map[string]any
	if err := json.Unmarshal(saved, &doc); err != nil {
		t.Fatalf("the config file must stay valid JSON: %v\n%s", err, saved)
	}
	if doc["security"].(map[string]any)["ids"].(map[string]any)["mode"] != "prevent" {
		t.Fatalf("the settings must be stored: %s", saved)
	}
	if doc["role"] != "server" || doc["admin"] == nil || doc["mtu"].(float64) != 1280 {
		t.Fatalf("every other key must survive: %s", saved)
	}
	if strings.Index(string(saved), `"admin"`) > strings.Index(string(saved), `"mtu"`) || strings.Index(string(saved), `"mtu"`) > strings.Index(string(saved), `"role"`) || strings.Index(string(saved), `"role"`) > strings.Index(string(saved), `"security"`) {
		t.Fatalf("the existing key order (the test file is written sorted) must be kept and the new section appended: %s", saved)
	}

	before, _ := os.ReadFile(r.config)
	fake.fail = errors.New("nft refused")
	got = r.do("POST", "/api/security", map[string]any{"settings": map[string]any{}}, token, csrf)
	if got.code != 422 || !strings.Contains(string(got.raw), "nft refused") {
		t.Fatalf("%d %s", got.code, got.raw)
	}
	after, _ := os.ReadFile(r.config)
	if string(before) != string(after) {
		t.Fatal("a refused configuration must not reach the file")
	}
	fake.fail = nil

	r.validate = func(string) error { return errors.New("rejected by the edge") }
	got = r.do("POST", "/api/security", map[string]any{"settings": map[string]any{"ids": map[string]any{"mode": "off"}}}, token, csrf)
	if got.code != 500 || got.body["applied"] != true || !strings.Contains(string(got.raw), "revert at the next restart") {
		t.Fatalf("an unsaved change must be reported as such: %d %s", got.code, got.raw)
	}
	if again, _ := os.ReadFile(r.config); string(again) != string(before) {
		t.Fatal("and the file must be unchanged")
	}
	r.validate = nil

	got = r.do("POST", "/api/security/action", map[string]any{"action": "unblock", "args": map[string]any{"ip": "10.77.0.9"}}, token, csrf)
	if got.code != 200 || !strings.Contains(string(got.raw), "10.77.0.9") || fake.actions[0] != "unblock" {
		t.Fatalf("%d %s", got.code, got.raw)
	}
	if got = r.do("POST", "/api/security/action", map[string]any{"action": "bad"}, token, csrf); got.code != 422 {
		t.Fatalf("%d", got.code)
	}
}

func TestSecurityRoutesAbsentWithoutAManager(t *testing.T) {
	r := newRig(t)
	token, csrf := r.login()
	if got := r.do("POST", "/api/security", map[string]any{"settings": map[string]any{}}, token, csrf); got.code != 404 {
		t.Fatalf("%d", got.code)
	}
	if got := r.do("POST", "/api/security/action", map[string]any{"action": "x"}, token, csrf); got.code != 404 {
		t.Fatalf("%d", got.code)
	}
}
