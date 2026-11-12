package adminportal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf16"
)

// A JSON document that keeps object key order, so rewriting the config to
// change one field leaves the operator's layout alone (Python's dict does the
// same; encoding/json would sort keys).
type node struct {
	kind   byte // 'o' object, 'a' array, 's' scalar (raw JSON text)
	keys   []string
	values []*node
	raw    string
}

func parseOrdered(text string) (*node, error) {
	d := json.NewDecoder(strings.NewReader(text))
	d.UseNumber()
	n, err := readNode(d)
	if err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("trailing data")
	}
	return n, nil
}

func readNode(d *json.Decoder) (*node, error) {
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch v := t.(type) {
	case json.Delim:
		if v == '{' {
			n := &node{kind: 'o'}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return nil, err
				}
				child, err := readNode(d)
				if err != nil {
					return nil, err
				}
				key := k.(string)
				replaced := false
				for i := range n.keys {
					if n.keys[i] == key { // duplicate key: last value wins, first position stays (dict semantics)
						n.values[i], replaced = child, true
					}
				}
				if !replaced {
					n.keys, n.values = append(n.keys, key), append(n.values, child)
				}
			}
			_, err := d.Token()
			return n, err
		}
		n := &node{kind: 'a'}
		for d.More() {
			child, err := readNode(d)
			if err != nil {
				return nil, err
			}
			n.values = append(n.values, child)
		}
		_, err := d.Token()
		return n, err
	case string:
		return &node{kind: 's', raw: pyString(v)}, nil
	case json.Number:
		return &node{kind: 's', raw: pyNumber(v.String())}, nil
	case bool:
		return &node{kind: 's', raw: fmt.Sprint(v)}, nil
	case nil:
		return &node{kind: 's', raw: "null"}, nil
	}
	return nil, errors.New("unexpected token")
}

// pyString quotes like json.dumps(ensure_ascii=True).
func pyString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r < 0x20 || r >= 0x80:
			if r >= 0x10000 {
				a, c := utf16.EncodeRune(r)
				fmt.Fprintf(&b, `\u%04x\u%04x`, a, c)
			} else {
				fmt.Fprintf(&b, `\u%04x`, r)
			}
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func (n *node) get(key string) *node {
	for i, k := range n.keys {
		if k == key {
			return n.values[i]
		}
	}
	return nil
}

func (n *node) set(key string, v *node) {
	for i, k := range n.keys {
		if k == key {
			n.values[i] = v
			return
		}
	}
	n.keys, n.values = append(n.keys, key), append(n.values, v)
}

// encode writes json.dump(indent=2) formatting.
func (n *node) encode(b *bytes.Buffer, depth int) {
	pad := strings.Repeat("  ", depth+1)
	switch n.kind {
	case 's':
		b.WriteString(n.raw)
	case 'a':
		if len(n.values) == 0 {
			b.WriteString("[]")
			return
		}
		b.WriteString("[\n")
		for i, v := range n.values {
			b.WriteString(pad)
			v.encode(b, depth+1)
			if i < len(n.values)-1 {
				b.WriteByte(',')
			}
			b.WriteByte('\n')
		}
		b.WriteString(strings.Repeat("  ", depth) + "]")
	case 'o':
		if len(n.values) == 0 {
			b.WriteString("{}")
			return
		}
		b.WriteString("{\n")
		for i, v := range n.values {
			b.WriteString(pad + pyString(n.keys[i]) + ": ")
			v.encode(b, depth+1)
			if i < len(n.values)-1 {
				b.WriteByte(',')
			}
			b.WriteByte('\n')
		}
		b.WriteString(strings.Repeat("  ", depth) + "}")
	}
}

// pyNumber re-spells a JSON number the way json.dumps would after json.loads:
// integers keep their digits, floats take Python's repr.
func pyNumber(lit string) string {
	if !strings.ContainsAny(lit, ".eE") {
		return lit
	}
	f, err := strconv.ParseFloat(lit, 64)
	if err != nil {
		return lit
	}
	a := f
	if a < 0 {
		a = -a
	}
	if a != 0 && (a >= 1e16 || a < 1e-4) {
		s := strconv.FormatFloat(f, 'e', -1, 64) // 1e+16, 1.5e-05
		if i := strings.IndexByte(s, 'e'); i >= 0 && !strings.Contains(s[:i], ".") {
			return s
		}
		return s
	}
	s := strconv.FormatFloat(f, 'f', -1, 64)
	if !strings.Contains(s, ".") {
		s += ".0"
	}
	return s
}
