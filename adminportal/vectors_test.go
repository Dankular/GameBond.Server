package adminportal

import (
	"compress/gzip"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

type vectorFile struct {
	Settings []struct {
		Raw json.RawMessage `json:"raw"`
		Out struct {
			OK *struct {
				Enabled      bool   `json:"enabled"`
				Host         string `json:"host"`
				Port         int    `json:"port"`
				PasswordHash string `json:"password_hash"`
				TLSCert      string `json:"tls_cert"`
				TLSKey       string `json:"tls_key"`
				LogLines     int    `json:"log_lines"`
			} `json:"ok"`
			Error string `json:"error"`
		} `json:"out"`
	} `json:"settings"`
	Shapes []struct {
		Kind        string `json:"kind"`
		Input       any    `json:"input"`
		EmptyOutput bool   `json:"empty_output"`
		Out         any    `json:"out"`
	} `json:"shapes"`
}

func loadVectors(t *testing.T) vectorFile {
	f, err := os.Open("testdata/vectors.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var v vectorFile
	if err := json.NewDecoder(z).Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestSettingsReplayPython(t *testing.T) {
	accepted := 0
	for i, c := range loadVectors(t).Settings {
		s, err := ParseSettings(c.Raw)
		if c.Out.OK == nil {
			if err == nil {
				t.Fatalf("case %d %s: accepted %+v, Python rejected (%s)", i, c.Raw, s, c.Out.Error)
			}
			continue
		}
		accepted++
		want := c.Out.OK
		if err != nil {
			t.Fatalf("case %d %s: rejected (%v), Python accepted", i, c.Raw, err)
		}
		if s.Enabled != want.Enabled || s.Host != want.Host || s.Port != want.Port || s.PasswordHash != want.PasswordHash ||
			s.TLSCert != want.TLSCert || s.TLSKey != want.TLSKey || s.LogLines != want.LogLines {
			t.Fatalf("case %d %s: %+v, Python %+v", i, c.Raw, s, want)
		}
	}
	if accepted < 300 {
		t.Fatalf("only %d accepted cases", accepted)
	}
}

func TestSystemShapingReplaysPython(t *testing.T) {
	for i, c := range loadVectors(t).Shapes {
		var got any
		switch c.Kind {
		case "interfaces":
			got = map[string]any{"data": ShapeInterfaces(c.Input)}
		case "routes":
			if c.EmptyOutput {
				got = map[string]any{"data": ShapeRoutes([]any{})}
			} else {
				got = map[string]any{"data": ShapeRoutes(c.Input)}
			}
		}
		if !reflect.DeepEqual(got, c.Out) {
			gj, _ := json.Marshal(got)
			wj, _ := json.Marshal(c.Out)
			t.Fatalf("shape %d (%s):\n go     %s\n python %s", i, c.Kind, gj, wj)
		}
	}
}
