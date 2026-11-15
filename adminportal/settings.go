// Package adminportal is gamebond/admin/{server,cert,system}.py: the HTTPS
// admin portal (login, live status, config edit/validate/apply, restart), the
// self-signed certificate writer and the read-only system views. Password
// hashing, sessions and throttling are package adminauth.
package adminportal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

// Settings is AdminSettings.
type Settings struct {
	Enabled      bool
	Host         string
	Port         int
	PasswordHash string
	TLSCert      string
	TLSKey       string
	LogLines     int
	Users        []AdminUser
}

// AdminUser is a team-scoped portal identity. Passwords are stored only as
// the same scrypt hashes used by the legacy single-admin login.
type AdminUser struct {
	Username     string `json:"username"`
	Team         string `json:"team"`
	Role         string `json:"role"`
	PasswordHash string `json:"password_hash"`
}

var adminKeys = map[string]bool{"enabled": true, "bind": true, "password_hash": true, "tls_cert": true, "tls_key": true, "log_lines": true, "users": true}
var usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)
var teamPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// pyInt reports whether v is a JSON integer in Python's sense (type(v) is int:
// no bools, no floats, even 1.0).
func pyInt(v any) (int, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	s := n.String()
	if strings.ContainsAny(s, ".eE") {
		return 0, false
	}
	i, err := n.Int64()
	if err != nil || i > 1<<53 || i < -(1<<53) {
		return 0, false
	}
	return int(i), true
}

// validIPv4 is ipaddress.IPv4Address(str): strict dotted quad, no leading zeros.
func validIPv4(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() || a.Zone() != "" {
		return netip.Addr{}, false
	}
	return a, true
}

// ParseSettings decodes the "admin" object with AdminSettings' rules.
func ParseSettings(raw json.RawMessage) (*Settings, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("admin must be an object")
	}
	var unknown []string
	for k := range m {
		if !adminKeys[k] {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return nil, fmt.Errorf("unknown admin keys: %v", unknown)
	}
	s := &Settings{Enabled: true, Host: "127.0.0.1", Port: 8443, LogLines: 200}
	if x, present := m["enabled"]; present {
		b, isBool := x.(bool)
		if !isBool {
			return nil, errors.New("invalid admin settings")
		}
		s.Enabled = b
	}
	if x, present := m["bind"]; present {
		pair, isList := x.([]any)
		if !isList || len(pair) != 2 {
			return nil, errors.New("invalid admin bind")
		}
		host, isStr := pair[0].(string)
		if !isStr {
			return nil, errors.New("invalid admin bind host")
		}
		s.Host = host
		port, okp := pyInt(pair[1])
		if _, good := validIPv4(host); !good {
			return nil, fmt.Errorf("Expected 4 octets or invalid IPv4 address %q", host)
		}
		if !okp || port < 1 || port > 65535 {
			return nil, errors.New("invalid admin port")
		}
		s.Port = port
	}
	if x, present := m["password_hash"]; present {
		if str, isStr := x.(string); isStr {
			s.PasswordHash = str
		} else if x == nil {
			s.PasswordHash = "None" // str(None), as the Python settings store it
		} else if b, isBool := x.(bool); isBool && b {
			s.PasswordHash = "True"
		} else if isBool {
			s.PasswordHash = "False"
		} else {
			s.PasswordHash = fmt.Sprint(x)
		}
	}
	for key, into := range map[string]*string{"tls_cert": &s.TLSCert, "tls_key": &s.TLSKey} {
		if x, present := m[key]; present && x != nil {
			str, isStr := x.(string)
			if !isStr {
				return nil, fmt.Errorf("admin.%s must be a path", key)
			}
			*into = str
		}
	}
	if x, present := m["log_lines"]; present {
		n, okn := pyInt(x)
		if !okn {
			return nil, errors.New("invalid admin settings")
		}
		s.LogLines = n
	}
	if x, present := m["users"]; present {
		rows, ok := x.([]any)
		if !ok || len(rows) > 256 {
			return nil, errors.New("admin.users must be an array of at most 256 users")
		}
		seen := map[string]bool{}
		admins := map[string]bool{}
		systemAdmin := false
		for i, raw := range rows {
			row, ok := raw.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("admin.users[%d] must be an object", i)
			}
			for key := range row {
				if key != "username" && key != "team" && key != "role" && key != "password_hash" {
					return nil, fmt.Errorf("admin.users[%d] has unknown field %q", i, key)
				}
			}
			user := AdminUser{}
			user.Username, _ = row["username"].(string)
			user.Team, _ = row["team"].(string)
			user.Role, _ = row["role"].(string)
			user.PasswordHash, _ = row["password_hash"].(string)
			key := strings.ToLower(user.Username)
			if !usernamePattern.MatchString(user.Username) || !teamPattern.MatchString(user.Team) || (user.Role != "system-admin" && user.Role != "team-admin" && user.Role != "editor" && user.Role != "viewer") || !strings.HasPrefix(user.PasswordHash, "scrypt$") || seen[key] {
				return nil, fmt.Errorf("admin.users[%d] has an invalid or duplicate username, team, role, or password_hash", i)
			}
			seen[key] = true
			if user.Role == "system-admin" || user.Role == "team-admin" { admins[user.Team] = true }
			if user.Role == "system-admin" { systemAdmin = true }
			s.Users = append(s.Users, user)
		}
		for _, user := range s.Users { if !admins[user.Team] { return nil,fmt.Errorf("team %q must have a system-admin or team-admin account",user.Team) } }
		if len(s.Users)>0 && !systemAdmin { return nil,errors.New("admin.users must include at least one system-admin") }
	}
	if s.LogLines < 10 || s.LogLines > 2000 {
		return nil, errors.New("invalid admin settings")
	}
	if s.Enabled {
		if len(s.Users) == 0 && !strings.HasPrefix(s.PasswordHash, "scrypt$") {
			return nil, errors.New("admin.password_hash is required (python -m gamebond admin-passwd)")
		}
		host, _ := validIPv4(s.Host)
		if (s.TLSCert == "" || s.TLSKey == "") && !host.IsLoopback() {
			return nil, errors.New("admin.tls_cert and admin.tls_key are required unless the portal binds loopback")
		}
	}
	return s, nil
}
