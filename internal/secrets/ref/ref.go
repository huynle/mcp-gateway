// Package ref defines ephemeral secret handles and the secret references
// agents put into tool arguments (design: docs/plans/2026-10-23-ephemeral-
// secrets-design.md).
//
// A handle is Prefix followed by 32 random bytes in fixed-width base62:
//
//	sec_<43 base62 chars>
//
// The model only ever holds a handle. Inside tool arguments it passes a ref,
// a JSON object with exactly one key "$secret" whose value is a valid
// handle string:
//
//	{"password": {"$secret": "sec_…"}}
//
// Objects with extra keys, a non-string value or a string that is not a
// valid handle are not refs and are left alone. The helpers here are pure:
// they find refs, report where they sit, and build deep copies with each
// ref replaced by its plaintext (dispatch) or by its handle string (schema
// precheck). They never mutate their input.
package ref

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sort"
	"strconv"
	"strings"
)

const (
	// Prefix starts every handle.
	Prefix = "sec_"
	// HandleBytes is the entropy of a handle.
	HandleBytes = 32
	// HandleLen is the length of the encoded part of a handle:
	// ceil(256 / log2(62)) = 43.
	HandleLen = 43
	// Key is the only key of a ref object.
	Key = "$secret"
	// ScanPattern is a regular expression matching exactly one handle, for
	// secret-scanning rules.
	ScanPattern = `sec_[0-9A-Za-z]{43}`
)

var (
	// ErrUnknownHandle reports a ref whose handle has no value in the map
	// given to Replace. The error never carries a value.
	ErrUnknownHandle = errors.New("ref: unknown secret handle")
	// ErrRootRef reports an arguments object that is itself a ref, so it
	// cannot be replaced by a string and still be an arguments object.
	ErrRootRef = errors.New("ref: arguments object is itself a secret ref")
)

const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// Generate returns a new handle from the operating system's CSPRNG.
func Generate() (string, error) {
	raw := make([]byte, HandleBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("ref: generate handle: %w", err)
	}
	return Prefix + encodeBase62(raw, HandleLen), nil
}

// Valid reports whether s has exactly the shape Generate produces: the
// prefix, then HandleLen base62 characters, nothing else.
func Valid(s string) bool {
	rest, ok := strings.CutPrefix(s, Prefix)
	if !ok || len(rest) != HandleLen {
		return false
	}
	for i := 0; i < len(rest); i++ {
		if strings.IndexByte(alphabet, rest[i]) < 0 {
			return false
		}
	}
	return true
}

// encodeBase62 renders b as a big-endian base62 number, left-padded with
// '0' to width characters (as internal/tokens does).
func encodeBase62(b []byte, width int) string {
	n := new(big.Int).SetBytes(b)
	base, rem := big.NewInt(62), new(big.Int)
	out := make([]byte, width)
	for i := width - 1; i >= 0; i-- {
		n.DivMod(n, base, rem)
		out[i] = alphabet[rem.Int64()]
	}
	return string(out)
}

// IsRef reports whether v is a ref and returns its handle: a
// map[string]any with exactly the key Key whose value is a valid handle.
func IsRef(v any) (string, bool) {
	m, ok := v.(map[string]any)
	if !ok || len(m) != 1 {
		return "", false
	}
	h, ok := m[Key].(string)
	if !ok || !Valid(h) {
		return "", false
	}
	return h, true
}

// Location is where one ref sits in an arguments tree.
type Location struct {
	// Handle is the ref's handle.
	Handle string
	// Arg is the top-level argument the ref sits under ("" when the root
	// is not an object, or the root itself is the ref).
	Arg string
	// Pointer is the RFC 6901 JSON pointer to the ref object ("" for the
	// root).
	Pointer string
}

// TopLevel reports whether the ref is the value of a top-level argument
// (not nested inside one).
func (l Location) TopLevel() bool {
	return l.Pointer != "" && l.Pointer == "/"+escapeToken(l.Arg)
}

// BoundTo reports whether the ref is exactly the value of the top-level
// argument arg, which is what a secret bound to that argument requires.
func (l Location) BoundTo(arg string) bool {
	return arg != "" && l.Arg == arg && l.TopLevel()
}

// Find returns the distinct handles of all refs in args, in a
// deterministic order (depth first, object keys sorted). args is a decoded
// JSON tree (map[string]any, []any, scalars), or json.RawMessage / []byte
// holding JSON; invalid JSON yields no handles (use FindRaw to see the
// error). Values of other types are not traversed.
func Find(args any) []string {
	var out []string
	seen := map[string]bool{}
	for _, l := range FindWithPaths(args) {
		if !seen[l.Handle] {
			seen[l.Handle] = true
			out = append(out, l.Handle)
		}
	}
	return out
}

// FindRaw is Find over raw JSON, reporting a decode error. Empty input and
// JSON null hold no refs.
func FindRaw(raw json.RawMessage) ([]string, error) {
	v, err := decode(raw)
	if err != nil {
		return nil, err
	}
	return Find(v), nil
}

// FindWithPaths returns every ref in args (one entry per occurrence, so a
// handle used twice appears twice) with its location, in the same order as
// Find. It accepts the same inputs as Find.
func FindWithPaths(args any) []Location {
	root, _, err := normalize(args)
	if err != nil {
		return nil
	}
	var out []Location
	walk(root, "", "", true, &out)
	return out
}

func walk(v any, arg, ptr string, root bool, out *[]Location) {
	if h, ok := IsRef(v); ok {
		*out = append(*out, Location{Handle: h, Arg: arg, Pointer: ptr})
		return
	}
	switch t := v.(type) {
	case map[string]any:
		for _, k := range sortedKeys(t) {
			a := arg
			if root {
				a = k
			}
			walk(t[k], a, ptr+"/"+escapeToken(k), false, out)
		}
	case []any:
		for i, e := range t {
			walk(e, arg, ptr+"/"+strconv.Itoa(i), false, out)
		}
	}
}

// Replace returns a deep copy of args with every ref replaced by
// values[handle]. A ref whose handle is not in values is ErrUnknownHandle.
// args is a decoded JSON tree, or json.RawMessage / []byte, in which case
// the result is json.RawMessage (numbers keep their exact text). The input
// is never mutated, and the result shares no maps or slices with it.
func Replace(args any, values map[string]string) (any, error) {
	return transform(args, func(h string) (any, error) {
		v, ok := values[h]
		if !ok {
			return nil, ErrUnknownHandle
		}
		return v, nil
	})
}

// ReplaceArgs is Replace for an arguments object (the type of
// connectors.Call.Args). An arguments object that is itself a ref is
// ErrRootRef; nil stays nil.
func ReplaceArgs(args map[string]any, values map[string]string) (map[string]any, error) {
	if args == nil {
		return nil, nil
	}
	if _, ok := IsRef(args); ok {
		return nil, ErrRootRef
	}
	out, err := Replace(args, values)
	if err != nil {
		return nil, err
	}
	return out.(map[string]any), nil
}

// ReplaceWithHandle returns a deep copy of args with every ref replaced by
// its handle string, so a schema expecting a string accepts the arguments
// (the precheck). It accepts the same inputs as Replace; raw JSON that does
// not decode is returned as an unchanged copy.
func ReplaceWithHandle(args any) any {
	out, err := transform(args, func(h string) (any, error) { return h, nil })
	if err != nil {
		switch t := args.(type) {
		case json.RawMessage:
			return append(json.RawMessage(nil), t...)
		case []byte:
			return append([]byte(nil), t...)
		}
		return args
	}
	return out
}

// ReplaceArgsWithHandle is ReplaceWithHandle for an arguments object. An
// arguments object that is itself a ref is copied unchanged (the handle is
// not a secret); nil stays nil.
func ReplaceArgsWithHandle(args map[string]any) map[string]any {
	if args == nil {
		return nil
	}
	if _, ok := IsRef(args); ok {
		return copyTree(args, nil).(map[string]any)
	}
	return ReplaceWithHandle(args).(map[string]any)
}

// transform deep-copies args (normalizing raw JSON first) with each ref
// replaced by sub(handle).
func transform(args any, sub func(string) (any, error)) (any, error) {
	root, raw, err := normalize(args)
	if err != nil {
		return nil, err
	}
	var firstErr error
	out := copyTree(root, func(h string) any {
		v, err := sub(h)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		return v
	})
	if firstErr != nil {
		return nil, firstErr
	}
	if !raw {
		return out, nil
	}
	b, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("ref: encode arguments: %w", err)
	}
	return json.RawMessage(b), nil
}

// copyTree deep-copies maps and slices; with sub set, each ref becomes
// sub(handle). Other values are returned as they are.
func copyTree(v any, sub func(string) any) any {
	if sub != nil {
		if h, ok := IsRef(v); ok {
			return sub(h)
		}
	}
	switch t := v.(type) {
	case map[string]any:
		if t == nil {
			return t
		}
		m := make(map[string]any, len(t))
		for k, e := range t {
			m[k] = copyTree(e, sub)
		}
		return m
	case []any:
		if t == nil {
			return t
		}
		s := make([]any, len(t))
		for i, e := range t {
			s[i] = copyTree(e, sub)
		}
		return s
	}
	return v
}

// normalize decodes raw JSON inputs (json.RawMessage, []byte); raw
// reports that it did.
func normalize(args any) (v any, raw bool, err error) {
	switch t := args.(type) {
	case json.RawMessage:
		v, err = decode(t)
		return v, true, err
	case []byte:
		v, err = decode(t)
		return v, true, err
	}
	return args, false, nil
}

// decode parses one JSON value with numbers kept as json.Number; empty
// input decodes to nil.
func decode(raw []byte) (any, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("ref: decode arguments: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("ref: decode arguments: trailing data")
	}
	return v, nil
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// escapeToken escapes one RFC 6901 reference token.
func escapeToken(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}
