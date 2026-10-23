package scrub

import (
	"encoding/json"
	"strings"
	"testing"
)

// FuzzScrub feeds arbitrary text through String, Bytes and Any (as raw
// JSON and, when it decodes, as a tree): nothing panics and the raw value
// never survives. The value has no '[' or ']', so no match can span a
// Mask, and nothing JSON would escape.
func FuzzScrub(f *testing.F) {
	const value = "hunter2!pw"
	for _, s := range []string{
		``, `null`, `{"a":"hunter2!pw"}`, `["hunter2!pw",1]`, `{"hunter2!pw":{"x":[1,2,"aGh1bnRlcjIhcHc="]}}`,
		`{"a":"\u0068unter2!pw"}`, `hunter2!pwhunter2!pw`, `{"a":`, `1e999`, `"x" "y"`,
	} {
		f.Add([]byte(s))
	}
	sc := New(value)
	f.Fuzz(func(t *testing.T, data []byte) {
		check := func(where, out string) {
			if strings.Contains(out, value) {
				t.Fatalf("%s leaks the value for input %q: %q", where, data, out)
			}
		}
		check("String", sc.String(string(data)))
		check("Bytes", string(sc.Bytes(data)))
		raw, _ := sc.Any(json.RawMessage(data)).(json.RawMessage)
		check("Any(raw)", string(raw))
		var tree any
		if json.Unmarshal(data, &tree) == nil {
			b, err := json.Marshal(sc.Any(tree))
			if err != nil {
				t.Fatalf("scrubbed tree does not marshal: %v", err)
			}
			check("Any(tree)", string(b))
			if json.Valid(data) && !json.Valid(raw) {
				t.Fatalf("valid JSON became invalid: %q -> %q", data, raw)
			}
		}
	})
}
