package approvals_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/huynle/mcp-gateway/internal/approvals"
)

func decode(t *testing.T, raw string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// TestCanonicalIsStableAcrossKeyOrderAndWhitespace: the digest depends on
// the argument values alone, not on how the harness serialised them.
func TestCanonicalIsStableAcrossKeyOrderAndWhitespace(t *testing.T) {
	a := decode(t, `{"repo": "acme/web", "title": "Bug", "labels": ["b", "a"], "meta": {"z": 1, "a": {"y": true, "x": null}}}`)
	b := decode(t, `{"meta":{"a":{"x":null,"y":true},"z":1},"labels":["b","a"],"title":"Bug","repo":"acme/web"}`)
	ca, err := approvals.Canonical(a)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := approvals.Canonical(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ca, cb) {
		t.Errorf("canonical forms differ:\n%s\n%s", ca, cb)
	}
	want := `{"labels":["b","a"],"meta":{"a":{"x":null,"y":true},"z":1},"repo":"acme/web","title":"Bug"}`
	if string(ca) != want {
		t.Errorf("canonical = %s, want %s", ca, want)
	}
	da, db := approvals.Digest(a), approvals.Digest(b)
	if !bytes.Equal(da, db) || len(da) != 32 {
		t.Errorf("digests differ or wrong size: %x %x", da, db)
	}
}

// TestCanonicalDoesNotEscapeHTMLAndNilIsEmptyObject: "<" in a body is
// kept as is (escaping would be another source of drift), and a nil map is
// the empty object.
func TestCanonicalDoesNotEscapeHTMLAndNilIsEmptyObject(t *testing.T) {
	c, err := approvals.Canonical(map[string]any{"body": "a <b> & c"})
	if err != nil {
		t.Fatal(err)
	}
	if string(c) != `{"body":"a <b> & c"}` {
		t.Errorf("canonical = %s", c)
	}
	c, err = approvals.Canonical(nil)
	if err != nil || string(c) != "{}" {
		t.Errorf("nil canonical = %s, %v", c, err)
	}
}

// TestDigestDistinguishesValues: a changed value, an added key and a
// changed nesting all give a different digest.
func TestDigestDistinguishesValues(t *testing.T) {
	base := approvals.Digest(map[string]any{"a": "1", "b": map[string]any{"c": 2.0}})
	for name, args := range map[string]map[string]any{
		"value":   {"a": "2", "b": map[string]any{"c": 2.0}},
		"added":   {"a": "1", "b": map[string]any{"c": 2.0}, "d": true},
		"nesting": {"a": "1", "b": map[string]any{"c": 2.0, "d": map[string]any{}}},
		"type":    {"a": 1.0, "b": map[string]any{"c": 2.0}},
	} {
		if bytes.Equal(approvals.Digest(args), base) {
			t.Errorf("%s: digest collides with the base", name)
		}
	}
}
