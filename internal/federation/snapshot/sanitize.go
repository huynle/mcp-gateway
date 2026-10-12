package snapshot

import (
	"bytes"
	"cmp"
	"encoding/json"
	"slices"
	"strings"
	"unicode"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Upstream text policy (Brain task jsb8470s). PostgreSQL jsonb cannot
// store U+0000, so a single NUL anywhere in a server's answer used to make
// every refresh of that server fail. Discovery now cleans what it can and
// leaves out what it cannot:
//
//   - a tool, prompt, resource or resource template whose key (tool or
//     prompt name, URI, URI template) contains NUL or any other control
//     character (C0, DEL, C1) is left out: keys are matched against calls,
//     so they are never rewritten;
//   - a prompt with such a character in an argument name is left out
//     (dropping the argument would change the prompt's signature);
//   - a tool with NUL in a key of its input or output schema is left out;
//   - NUL is removed from every other string: titles, descriptions,
//     resource names and MIME types, annotation titles, prompt argument
//     titles and descriptions, and the string values of schemas.
//
// Everything left out is listed in Snapshot.Skipped with a display-safe
// name and a reason. Other text is still stored as discovered and
// sanitized for display (Display*).

// Reasons a discovered item is skipped.
const (
	// ReasonInvalidName: the item's key has NUL or a control character.
	ReasonInvalidName = "invalid name"
	// ReasonInvalidSchema: a key of the tool's schema has NUL.
	ReasonInvalidSchema = "invalid schema"
	// ReasonInvalidArgument: a prompt argument name has NUL or a control
	// character.
	ReasonInvalidArgument = "invalid argument"
)

// Kinds of skipped items.
const (
	SkippedTool     = "tool"
	SkippedResource = "resource"
	SkippedTemplate = "resource template"
	SkippedPrompt   = "prompt"
)

// Skipped is an upstream item discovery left out of the snapshot. Name is
// the item's key passed through DisplayName (never the raw upstream text);
// Kind is one of the Skipped* kinds and Reason one of the Reason*
// constants. Skipped items are not stored: they are reported by the
// refresh that met them (Record.Skipped).
type Skipped struct {
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// skips collects skipped items.
type skips []Skipped

func (s *skips) add(kind, key, reason string) {
	name := DisplayName(key)
	if name == "" {
		name = "(unnamed)"
	}
	*s = append(*s, Skipped{Kind: kind, Name: name, Reason: reason})
}

// sorted returns the items by kind, name and reason (nil when empty).
func (s skips) sorted() []Skipped {
	if len(s) == 0 {
		return nil
	}
	out := slices.Clone([]Skipped(s))
	slices.SortFunc(out, func(a, b Skipped) int {
		return cmp.Or(cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Name, b.Name), cmp.Compare(a.Reason, b.Reason))
	})
	return out
}

// invalidKey reports whether an upstream key has NUL or another control
// character.
func invalidKey(s string) bool {
	return strings.IndexFunc(s, unicode.IsControl) >= 0
}

// clean removes NUL from upstream text.
func clean(s string) string {
	if !strings.ContainsRune(s, 0) {
		return s
	}
	return strings.ReplaceAll(s, "\x00", "")
}

// keep filters a list, recording what reject refuses (reason "" keeps).
func keep[T any](in []*T, s *skips, kind string, reject func(*T) (key, reason string)) []*T {
	out := in[:0:0]
	for _, x := range in {
		if x != nil {
			if key, reason := reject(x); reason != "" {
				s.add(kind, key, reason)
				continue
			}
		}
		out = append(out, x)
	}
	return out
}

// nulEscape is how encoding/json writes U+0000.
var nulEscape = []byte(`\u0000`)

// cleanSchema removes NUL from a schema's string values. It reports false
// when a key of the schema (at any depth) has NUL.
func cleanSchema(raw json.RawMessage) (json.RawMessage, bool) {
	if !bytes.Contains(raw, nulEscape) {
		return raw, true
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, false
	}
	v, ok := cleanValue(v)
	if !ok {
		return nil, false
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, false
	}
	return b, true
}

func cleanValue(v any) (any, bool) {
	switch x := v.(type) {
	case string:
		return clean(x), true
	case []any:
		for i := range x {
			var ok bool
			if x[i], ok = cleanValue(x[i]); !ok {
				return nil, false
			}
		}
		return x, true
	case map[string]any:
		for k, e := range x {
			if strings.ContainsRune(k, 0) {
				return nil, false
			}
			c, ok := cleanValue(e)
			if !ok {
				return nil, false
			}
			x[k] = c
		}
		return x, true
	}
	return v, true
}

// cleanTools removes NUL from converted tools' text and schemas and drops
// tools with NUL in a schema key.
func cleanTools(in []Tool, s *skips) []Tool {
	out := in[:0]
	for _, t := range in {
		var okIn, okOut bool
		t.InputSchema, okIn = cleanOptionalSchema(t.InputSchema)
		t.OutputSchema, okOut = cleanOptionalSchema(t.OutputSchema)
		if !okIn || !okOut {
			s.add(SkippedTool, t.Name, ReasonInvalidSchema)
			continue
		}
		t.Title, t.Description = clean(t.Title), clean(t.Description)
		if t.Annotations != nil {
			t.Annotations.Title = clean(t.Annotations.Title)
		}
		out = append(out, t)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func cleanOptionalSchema(raw json.RawMessage) (json.RawMessage, bool) {
	if raw == nil {
		return nil, true
	}
	return cleanSchema(raw)
}

func rejectKey(key string) (string, string) {
	if invalidKey(key) {
		return key, ReasonInvalidName
	}
	return "", ""
}

func rejectTool(t *mcp.Tool) (string, string) {
	if invalidKey(t.Name) {
		return t.Name, ReasonInvalidName
	}
	return "", ""
}

func rejectPrompt(p *mcp.Prompt) (string, string) {
	if invalidKey(p.Name) {
		return p.Name, ReasonInvalidName
	}
	for _, a := range p.Arguments {
		if a != nil && invalidKey(a.Name) {
			return p.Name, ReasonInvalidArgument
		}
	}
	return "", ""
}

func cleanResource(r Resource) Resource {
	r.Name, r.Title, r.Description, r.MIMEType = clean(r.Name), clean(r.Title), clean(r.Description), clean(r.MIMEType)
	return r
}

func cleanTemplate(r ResourceTemplate) ResourceTemplate {
	r.Name, r.Title, r.Description, r.MIMEType = clean(r.Name), clean(r.Title), clean(r.Description), clean(r.MIMEType)
	return r
}

func cleanPrompt(p Prompt) Prompt {
	p.Title, p.Description = clean(p.Title), clean(p.Description)
	for i := range p.Arguments {
		a := &p.Arguments[i]
		a.Title, a.Description = clean(a.Title), clean(a.Description)
	}
	return p
}
