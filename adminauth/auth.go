// Package adminauth is gamebond/admin/auth.py: scrypt password hashes, sessions
// with CSRF tokens, and failed-login throttling.
package adminauth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/crypto/scrypt"
)

const (
	ScryptN      = 1 << 15
	scryptR      = 8
	scryptP      = 1
	maxMem       = 128 * 1024 * 1024
	IdleSeconds  = 30 * 60
	AbsoluteSecs = 8 * 3600
	MaxSessions  = 16
)

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// HashPassword is hash_password(password, n=n).
func HashPassword(password string, n int) (string, error) {
	if len([]rune(password)) < 10 {
		return "", errors.New("password must be at least 10 characters")
	}
	if err := checkMemory(n); err != nil {
		return "", err
	}
	salt := randomBytes(16)
	digest, err := scrypt.Key([]byte(password), salt, n, scryptR, scryptP, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("scrypt$%d$%s$%s", n, base64.StdEncoding.EncodeToString(salt), base64.StdEncoding.EncodeToString(digest)), nil
}

// checkMemory is OpenSSL's maxmem test as hashlib.scrypt applies it.
func checkMemory(n int) error {
	if n < 2 || n&(n-1) != 0 {
		return errors.New("invalid scrypt n")
	}
	need := 128*scryptR*scryptP + 128*scryptR*(n+2)
	if need > maxMem {
		return errors.New("scrypt memory limit exceeded")
	}
	return nil
}

// pyInt is int(text) for the characters a stored hash can reasonably hold:
// surrounding whitespace, one sign, digits with single underscores.
func pyInt(s string) (int, bool) {
	s = strings.TrimFunc(s, func(r rune) bool { return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f) })
	neg := false
	if s != "" && (s[0] == '+' || s[0] == '-') {
		neg = s[0] == '-'
		s = s[1:]
	}
	if s == "" || s[0] == '_' || s[len(s)-1] == '_' || strings.Contains(s, "__") {
		return 0, false
	}
	v := 0
	for _, r := range s {
		if r == '_' {
			continue
		}
		if r < '0' || r > '9' {
			return 0, false
		}
		v = v*10 + int(r-'0')
		if v > 1<<40 {
			return 0, false
		}
	}
	if neg {
		v = -v
	}
	return v, true
}

// pyB64Decode is base64.b64decode(s) (non-strict): characters outside the
// alphabet are skipped and missing padding is an error.
func pyB64Decode(s string) ([]byte, bool) {
	var data []byte
	pads := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '=':
			pads++
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '+', c == '/':
			if pads > 0 && len(data)%4 == 0 {
				pads = 0 // a new quad starts after complete padding
			}
			data = append(data, c)
		}
	}
	need := (4 - len(data)%4) % 4
	if len(data)%4 == 1 || pads < need {
		return nil, false
	}
	out, err := base64.RawStdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, false
	}
	return out, true
}

// VerifyPassword is verify_password(password, stored).
func VerifyPassword(password, stored string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != "scrypt" {
		return false
	}
	expected, ok := pyB64Decode(parts[3])
	if !ok {
		return false
	}
	n, ok := pyInt(parts[1])
	if !ok || len(expected) == 0 || len(expected) > 1<<20 {
		return false
	}
	salt, ok := pyB64Decode(parts[2])
	if !ok || checkMemory(n) != nil {
		return false
	}
	actual, err := scrypt.Key([]byte(password), salt, n, scryptR, scryptP, len(expected))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

// Throttle is the per-address and global failed-login lockout.
type Throttle struct {
	Clock       func() float64
	Free        int
	Base, Cap   float64
	GlobalLimit int
	Window      float64

	mu           sync.Mutex
	failures     map[string]int
	blockedUntil map[string]float64
	recent       []float64
}

func monotonic() float64 { return float64(time.Now().UnixNano()) / 1e9 }

// NewThrottle uses Python's defaults (4 free, 2 s base, 900 s cap, 40 per 300 s).
func NewThrottle(clock func() float64) *Throttle {
	if clock == nil {
		clock = monotonic
	}
	return &Throttle{Clock: clock, Free: 4, Base: 2, Cap: 900, GlobalLimit: 40, Window: 300,
		failures: map[string]int{}, blockedUntil: map[string]float64{}}
}

// RetryAfter is how many seconds the address must still wait.
func (t *Throttle) RetryAfter(addr string) float64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.Clock()
	kept := t.recent[:0]
	for _, at := range t.recent {
		if now-at < t.Window {
			kept = append(kept, at)
		}
	}
	t.recent = kept
	wait := t.blockedUntil[addr] - now
	if wait < 0 {
		wait = 0
	}
	if len(t.recent) >= t.GlobalLimit {
		if w := t.Window - (now - t.recent[0]); w > wait {
			wait = w
		}
	}
	return wait
}

// Fail records a failed login.
func (t *Throttle) Fail(addr string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.Clock()
	t.failures[addr]++
	count := t.failures[addr]
	t.recent = append(t.recent, now)
	if count > t.Free {
		d := t.Base
		for i := 0; i < count-t.Free-1 && d < t.Cap; i++ {
			d *= 2
		}
		if d > t.Cap {
			d = t.Cap
		}
		t.blockedUntil[addr] = now + d
	}
	if len(t.failures) > 4096 {
		t.failures = map[string]int{}
		t.blockedUntil = map[string]float64{}
	}
}

// Success clears an address.
func (t *Throttle) Success(addr string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.failures, addr)
	delete(t.blockedUntil, addr)
}

// Session is one login.
type Session struct {
	CSRF       string
	Born, Seen float64
}

// Sessions holds at most MaxSessions logins with idle and absolute expiry.
type Sessions struct {
	Clock func() float64
	mu    sync.Mutex
	items map[string]*Session
}

func NewSessions(clock func() float64) *Sessions {
	if clock == nil {
		clock = monotonic
	}
	return &Sessions{Clock: clock, items: map[string]*Session{}}
}

func urlsafe(n int) string { return base64.RawURLEncoding.EncodeToString(randomBytes(n)) }

func (s *Sessions) expire(now float64) {
	for token, it := range s.items {
		if now-it.Seen > IdleSeconds || now-it.Born > AbsoluteSecs {
			delete(s.items, token)
		}
	}
}

// Create returns a new session token and CSRF token.
func (s *Sessions) Create() (token, csrf string) {
	now := s.Clock()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire(now)
	for len(s.items) >= MaxSessions {
		oldest, first := "", true
		for k, it := range s.items {
			if first || it.Seen < s.items[oldest].Seen {
				oldest, first = k, false
			}
		}
		delete(s.items, oldest)
	}
	token, csrf = urlsafe(32), urlsafe(24)
	s.items[token] = &Session{CSRF: csrf, Born: now, Seen: now}
	return
}

// Get refreshes and returns a copy of the session, or nil.
func (s *Sessions) Get(token string) *Session {
	if token == "" {
		return nil
	}
	now := s.Clock()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire(now)
	it := s.items[token]
	if it == nil {
		return nil
	}
	it.Seen = now
	cp := *it
	return &cp
}

func (s *Sessions) Drop(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, token)
}

func (s *Sessions) DropAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = map[string]*Session{}
}

// Len is the number of live sessions (test helper).
func (s *Sessions) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items)
}
