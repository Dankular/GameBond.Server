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
}

var adminKeys = map[string]bool{"enabled": true, "bind": true, "password_hash": true, "tls_cert": true, "tls_key": true, "log_lines": true}

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
	if s.LogLines < 10 || s.LogLines > 2000 {
		return nil, errors.New("invalid admin settings")
	}
	if s.Enabled {
		if !strings.HasPrefix(s.PasswordHash, "scrypt$") {
			return nil, errors.New("admin.password_hash is required (python -m gamebond admin-passwd)")
		}
		host, _ := validIPv4(s.Host)
		if (s.TLSCert == "" || s.TLSKey == "") && !host.IsLoopback() {
			return nil, errors.New("admin.tls_cert and admin.tls_key are required unless the portal binds loopback")
		}
	}
	return s, nil
}
