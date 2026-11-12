package adminportal

import (
	"bytes"
	"testing"
)

func TestOrderedRewriteKeepsKeyOrderAndPythonEscaping(t *testing.T) {
	n, err := parseOrdered(`{"z":1,"a":[1,2.50,{"k":"é\u0001"}],"e":{},"l":[],"z":3,"n":null,"t":true}`)
	if err != nil {
		t.Fatal(err)
	}
	n.set("admin", &node{kind: 'o'})
	var b bytes.Buffer
	n.encode(&b, 0)
	want := "{\n  \"z\": 3,\n  \"a\": [\n    1,\n    2.5,\n    {\n      \"k\": \"\\u00e9\\u0001\"\n    }\n  ],\n  \"e\": {},\n  \"l\": [],\n  \"n\": null,\n  \"t\": true,\n  \"admin\": {}\n}"
	if b.String() != want {
		t.Fatalf("got\n%s\nwant\n%s", b.String(), want)
	}
	for _, bad := range []string{`{} x`, `{"a":`, ``} {
		if _, err := parseOrdered(bad); err == nil {
			t.Fatal("accepted", bad)
		}
	}
}

func TestPyNumber(t *testing.T) {
	for in, want := range map[string]string{"12": "12", "2.50": "2.5", "1e3": "1000.0", "1e16": "1e+16", "1.5e-5": "1.5e-05", "0.0": "0.0", "-3.0": "-3.0", "123456789012345678901234567890": "123456789012345678901234567890"} {
		if got := pyNumber(in); got != want {
			t.Errorf("%s: %s want %s", in, got, want)
		}
	}
}
