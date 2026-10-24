// Package tooldigest fingerprints an MCP tool definition: its name,
// description and input schema. The gateway sends the digest of the tool
// it approved with every federated tools/call (CallToolParams._meta
// MetaKey), so that a server that runs what its definition says (the
// machine actions server, internal/machineclient) can refuse a call whose
// reviewed definition is not the one it serves now.
//
// Both sides must agree for an unchanged tool although the gateway reads
// the definition back from its snapshot (PostgreSQL jsonb reorders keys,
// drops whitespace and may rewrite numbers) while the server hashes the
// tool it lists. Digest therefore hashes a canonical encoding: the schema
// is decoded and re-encoded with sorted keys, no insignificant whitespace,
// strings in one escaping, and every number in one form for its value
// (canonicalNumber). The package is a leaf: standard library only.
package tooldigest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
)

// MetaKey is the tools/call _meta key that carries the digest.
const MetaKey = "mcp-gateway/tool-digest"

// Prefix starts every digest; it names the algorithm and leaves room for
// another encoding later.
const Prefix = "sha256:"

// Digest is Prefix and the hex SHA-256 of the canonical JSON object
// {"description":…, "inputSchema":…, "name":…}. A missing or null schema
// is null. A schema that is not valid JSON is hashed by its bytes under a
// different key, so it never equals a valid schema's digest.
func Digest(name, description string, inputSchema json.RawMessage) string {
	doc := map[string]any{"name": name, "description": description, "inputSchema": nil}
	if raw := bytes.TrimSpace(inputSchema); len(raw) > 0 && !bytes.Equal(raw, []byte("null")) {
		if v, ok := canonicalValue(raw); ok {
			doc["inputSchema"] = v
		} else {
			delete(doc, "inputSchema")
			doc["inputSchemaInvalid"] = hex.EncodeToString(raw)
		}
	}
	b, err := json.Marshal(doc) // sorted keys
	if err != nil {
		// Unreachable: doc holds only decoded JSON values and strings.
		b = []byte(err.Error())
	}
	sum := sha256.Sum256(b)
	return Prefix + hex.EncodeToString(sum[:])
}

// canonicalValue decodes raw (exactly one JSON value) with every number
// rewritten by canonicalNumber.
func canonicalValue(raw []byte) (any, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, false
	}
	if _, err := dec.Token(); err == nil {
		return nil, false // trailing data
	}
	return normalize(v), true
}

func normalize(v any) any {
	switch x := v.(type) {
	case json.Number:
		return json.Number(canonicalNumber(string(x)))
	case []any:
		for i := range x {
			x[i] = normalize(x[i])
		}
	case map[string]any:
		for k, e := range x {
			x[k] = normalize(e)
		}
	}
	return v
}

// maxExp bounds the exponents canonicalNumber rewrites, so the exponent
// arithmetic cannot overflow.
const maxExp = 1 << 40

// canonicalNumber writes a JSON number literal as its significant digits
// without trailing zeros and a decimal exponent when not zero: 100, 1e2
// and 100.0 are all "1e2", 1.50 is "15e-1", -0 is "0". The value is kept
// exactly (no float conversion). A literal it cannot parse (or with an
// exponent beyond maxExp) is returned as is.
func canonicalNumber(s string) string {
	neg := strings.HasPrefix(s, "-")
	m := strings.TrimPrefix(s, "-")
	var exp int64
	if i := strings.IndexAny(m, "eE"); i >= 0 {
		e, err := strconv.ParseInt(strings.TrimPrefix(m[i+1:], "+"), 10, 64)
		if err != nil || e > maxExp || e < -maxExp {
			return s
		}
		m, exp = m[:i], e
	}
	intPart, frac, _ := strings.Cut(m, ".")
	digits := intPart + frac
	if digits == "" || strings.Trim(digits, "0123456789") != "" {
		return s
	}
	exp -= int64(len(frac))
	digits = strings.TrimLeft(digits, "0")
	if digits == "" {
		return "0"
	}
	trimmed := strings.TrimRight(digits, "0")
	exp += int64(len(digits) - len(trimmed))
	out := trimmed
	if exp != 0 {
		out += "e" + strconv.FormatInt(exp, 10)
	}
	if neg {
		out = "-" + out
	}
	return out
}
