package tooldigest

import (
	"encoding/json"
	"strings"
	"testing"
)

const schema = `{"type":"object","properties":{"host":{"type":"string","pattern":"^[a-z]+$"},"n":{"type":"integer","maximum":100}},"required":["host"],"additionalProperties":false}`

func TestDigestIgnoresKeyOrderWhitespaceAndNumberFormatting(t *testing.T) {
	base := Digest("stash", "Runs tee", json.RawMessage(schema))
	if !strings.HasPrefix(base, Prefix) || len(base) != len(Prefix)+64 {
		t.Fatalf("digest %q", base)
	}
	for _, same := range []string{
		`{"additionalProperties":false,"required":["host"],"properties":{"n":{"maximum":100,"type":"integer"},"host":{"pattern":"^[a-z]+$","type":"string"}},"type":"object"}`,
		"{\n  \"type\": \"object\",\n  \"properties\": {\"host\": {\"type\": \"string\", \"pattern\": \"^[a-z]+$\"}, \"n\": {\"type\": \"integer\", \"maximum\": 1e2}},\n  \"required\": [\"host\"], \"additionalProperties\": false\n}",
		`{"type":"object","properties":{"host":{"type":"string","pattern":"^[a-z]+$"},"n":{"type":"integer","maximum":100.00}},"required":["host"],"additionalProperties":false}`,
		`{"type":"object","properties":{"host":{"type":"string","pattern":"^[a-z]+$"},"n":{"type":"integer","maximum":1000E-1}},"required":["host"],"additionalProperties":false}`,
		`{"type":"object","properties":{"host":{"type":"string","pattern":"\u005e[a-z]+$"},"n":{"type":"integer","maximum":100}},"required":["host"],"additionalProperties":false}`,
	} {
		if got := Digest("stash", "Runs tee", json.RawMessage(same)); got != base {
			t.Errorf("digest of %s = %s, want %s", same, got, base)
		}
	}
}

func TestDigestChangesWithEveryField(t *testing.T) {
	base := Digest("stash", "Runs tee", json.RawMessage(schema))
	for name, got := range map[string]string{
		"name":        Digest("stash2", "Runs tee", json.RawMessage(schema)),
		"description": Digest("stash", "Runs tee -a", json.RawMessage(schema)),
		"schema":      Digest("stash", "Runs tee", json.RawMessage(strings.Replace(schema, "^[a-z]+$", "^[a-z0-9]+$", 1))),
		"number":      Digest("stash", "Runs tee", json.RawMessage(strings.Replace(schema, "100", "101", 1))),
		"no schema":   Digest("stash", "Runs tee", nil),
	} {
		if got == base {
			t.Errorf("changing the %s keeps the digest", name)
		}
	}
	// Field boundaries: moving text between name and description matters.
	if Digest("ab", "c", nil) == Digest("a", "bc", nil) {
		t.Error("name and description are not separated")
	}
}

func TestDigestMissingSchemaIsNull(t *testing.T) {
	want := Digest("t", "d", nil)
	for _, raw := range []string{"", "null", "  null "} {
		if got := Digest("t", "d", json.RawMessage(raw)); got != want {
			t.Errorf("schema %q: %s, want %s", raw, got, want)
		}
	}
}

func TestDigestInvalidSchemaIsStableAndDistinct(t *testing.T) {
	a := Digest("t", "d", json.RawMessage(`{"type":`))
	if a != Digest("t", "d", json.RawMessage(`{"type":`)) {
		t.Fatal("unstable digest for an invalid schema")
	}
	if a == Digest("t", "d", nil) || a == Digest("t", "d", json.RawMessage(`"{\"type\":"`)) {
		t.Fatal("an invalid schema collides with a valid one")
	}
}

func TestCanonicalNumber(t *testing.T) {
	for in, want := range map[string]string{
		"0": "0", "-0": "0", "0.000": "0", "7": "7", "100": "1e2", "1e2": "1e2", "1E+2": "1e2", "100.00": "1e2",
		"1.5": "15e-1", "0.15e1": "15e-1", "-2.50": "-25e-1", "0.001": "1e-3", "12345678901234567890": "1234567890123456789e1",
		"1e400": "1e400", "-1000000000": "-1e9",
	} {
		if got := canonicalNumber(in); got != want {
			t.Errorf("canonicalNumber(%s) = %s, want %s", in, got, want)
		}
	}
}
