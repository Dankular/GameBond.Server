package adminauth

import (
	"compress/gzip"
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"
)

type vectors struct {
	Verify []struct {
		Password string          `json:"password"`
		Stored   string          `json:"stored"`
		HashLen  *int            `json:"hash_len"`
		OK       json.RawMessage `json:"ok"`
	} `json:"verify"`
	KAT []struct {
		Password string `json:"password"`
		Stored   string `json:"stored"`
	} `json:"kat"`
	Throttle []struct {
		Kwargs struct {
			Free        *int     `json:"free"`
			Base        *float64 `json:"base"`
			Cap         *float64 `json:"cap"`
			GlobalLimit *int     `json:"global_limit"`
			Window      *float64 `json:"window"`
		} `json:"kwargs"`
		Steps []struct {
			Op   string  `json:"op"`
			Addr string  `json:"addr"`
			DT   float64 `json:"dt"`
			Want float64 `json:"want"`
		} `json:"steps"`
	} `json:"throttle"`
	Evict struct {
		Count     int     `json:"count"`
		WantFirst float64 `json:"want_first"`
		WantLast  float64 `json:"want_last"`
	} `json:"evict"`
}

func load(t *testing.T) vectors {
	f, err := os.Open("testdata/vectors.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.NewDecoder(zr).Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestVerifyMatchesPython(t *testing.T) {
	v := load(t)
	accepted := 0
	for i, c := range v.Verify {
		if c.HashLen != nil {
			_, err := HashPassword(strings.Repeat("x", *c.HashLen), 2)
			if want := string(c.OK) == "true"; (err == nil) != want {
				t.Errorf("hash length %d: go ok=%v python ok=%v", *c.HashLen, err == nil, want)
			}
			continue
		}
		want := string(c.OK) == "true"
		if string(c.OK) != "true" && string(c.OK) != "false" {
			t.Fatalf("case %d: python raised %s", i, c.OK)
		}
		got := VerifyPassword(c.Password, c.Stored)
		if got != want {
			t.Errorf("case %d stored=%.60q: go=%v python=%v", i, c.Stored, got, want)
		}
		if want {
			accepted++
		}
	}
	if accepted < 100 {
		t.Fatalf("only %d accepted cases", accepted)
	}
}

func TestKnownAnswerAndRoundTrip(t *testing.T) {
	for _, k := range load(t).KAT {
		if !VerifyPassword(k.Password, k.Stored) {
			t.Errorf("Python-made hash rejected for %q", k.Password)
		}
	}
	h, err := HashPassword("a long enough secret", 1024)
	if err != nil || !strings.HasPrefix(h, "scrypt$1024$") {
		t.Fatal(h, err)
	}
	if !VerifyPassword("a long enough secret", h) || VerifyPassword("a long enough secreT", h) {
		t.Fatal("round trip")
	}
	h2, _ := HashPassword("a long enough secret", 1024)
	if h == h2 {
		t.Fatal("salt not random")
	}
}

func TestThrottleMatchesPython(t *testing.T) {
	v := load(t)
	checks := 0
	for ri, run := range v.Throttle {
		clock := 0.0
		th := NewThrottle(func() float64 { return clock })
		k := run.Kwargs
		if k.Free != nil {
			th.Free = *k.Free
		}
		if k.Base != nil {
			th.Base = *k.Base
		}
		if k.Cap != nil {
			th.Cap = *k.Cap
		}
		if k.GlobalLimit != nil {
			th.GlobalLimit = *k.GlobalLimit
		}
		if k.Window != nil {
			th.Window = *k.Window
		}
		for si, s := range run.Steps {
			switch s.Op {
			case "wait":
				clock += s.DT
			case "fail":
				th.Fail(s.Addr)
			case "success":
				th.Success(s.Addr)
			case "retry":
				checks++
				if got := th.RetryAfter(s.Addr); math.Abs(got-s.Want) > 1e-9 {
					t.Fatalf("run %d step %d: retry_after(%s)=%v, python %v", ri, si, s.Addr, got, s.Want)
				}
			}
		}
	}
	th := NewThrottle(func() float64 { return 0 })
	th.Free, th.GlobalLimit = 0, 1<<30
	for i := 0; i < v.Evict.Count; i++ {
		th.Fail("h" + itoa(i))
	}
	if a, b := th.RetryAfter("h0"), th.RetryAfter("h4097"); a != v.Evict.WantFirst || b != v.Evict.WantLast {
		t.Fatalf("eviction: %v %v, python %v %v", a, b, v.Evict.WantFirst, v.Evict.WantLast)
	}
	t.Logf("%d throttle checks", checks)
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

func TestSessions(t *testing.T) {
	clock := 0.0
	s := NewSessions(func() float64 { return clock })
	tok, csrf := s.Create()
	if got := s.Get(tok); got == nil || got.CSRF != csrf {
		t.Fatalf("%+v", got)
	}
	if s.Get("") != nil || s.Get("nope") != nil {
		t.Fatal("unknown token accepted")
	}
	clock = IdleSeconds - 1
	if s.Get(tok) == nil {
		t.Fatal("expired too early")
	}
	clock += IdleSeconds - 1 // refreshed by the Get above
	if s.Get(tok) == nil {
		t.Fatal("idle timer not refreshed")
	}
	clock += IdleSeconds + 1
	if s.Get(tok) != nil {
		t.Fatal("idle session survived")
	}
	// absolute lifetime
	clock = 0
	s = NewSessions(func() float64 { return clock })
	tok, _ = s.Create()
	for clock < AbsoluteSecs {
		clock += IdleSeconds - 10
		if clock > AbsoluteSecs {
			break
		}
		if s.Get(tok) == nil {
			t.Fatal("died before the absolute limit")
		}
	}
	clock = AbsoluteSecs + 1
	if s.Get(tok) != nil {
		t.Fatal("absolute lifetime not enforced")
	}
	// capacity: the least recently used is evicted
	clock = 0
	s = NewSessions(func() float64 { return clock })
	var toks []string
	for i := 0; i < MaxSessions; i++ {
		clock = float64(i)
		tk, _ := s.Create()
		toks = append(toks, tk)
	}
	clock = 100
	s.Get(toks[0])
	clock = 101
	s.Create()
	if s.Len() != MaxSessions || s.Get(toks[1]) != nil || s.Get(toks[0]) == nil {
		t.Fatalf("len=%d; wrong session evicted", s.Len())
	}
	s.Drop(toks[0])
	if s.Get(toks[0]) != nil {
		t.Fatal("drop")
	}
	s.DropAll()
	if s.Len() != 0 {
		t.Fatal("drop all")
	}
}
