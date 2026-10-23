// Package scrub removes ephemeral secret values from tool results and
// error text before anything outside the secret stage sees them (design:
// docs/plans/2026-10-23-ephemeral-secrets-design.md, correction 4).
//
// A Scrubber is built once per call from the plaintext values substituted
// into it. For each value it removes the raw text and the encodings a
// target is likely to echo it in:
//
//   - raw;
//   - base64: standard, URL-safe, and both without padding;
//   - url.QueryEscape and url.PathEscape;
//   - the JSON string-escaped form (with and without HTML escaping);
//   - hex, lower and upper case.
//
// Each occurrence becomes Mask. Longer forms are matched first, so a value
// that contains another value is removed whole. Empty values and duplicate
// forms are skipped. Values shorter than 8 bytes are refused by the caller
// (they would match unrelated text); the scrubber still removes whatever it
// is given.
//
// Limits: an encoding of the value inside a larger encoded blob (base64 of
// a longer string at an unaligned offset, gzip, ...) is not detected; nor
// are encodings other than those above.
//
// A Scrubber is immutable after New and safe for concurrent use. A nil
// Scrubber, or one without values, returns its input unchanged.
package scrub

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// Mask replaces every removed form.
const Mask = "[secret]"

// Scrubber removes a fixed set of secret values in all their forms.
type Scrubber struct {
	forms []string
	r     *strings.Replacer
}

// New returns a Scrubber for values.
func New(values ...string) *Scrubber {
	seen := map[string]bool{}
	var forms []string
	for _, v := range values {
		for _, f := range formsOf(v) {
			if f != "" && !seen[f] {
				seen[f] = true
				forms = append(forms, f)
			}
		}
	}
	// Longest first: strings.Replacer tries its pairs in argument order at
	// each position.
	sort.Slice(forms, func(i, j int) bool {
		if len(forms[i]) != len(forms[j]) {
			return len(forms[i]) > len(forms[j])
		}
		return forms[i] < forms[j]
	})
	s := &Scrubber{forms: forms}
	if len(forms) > 0 {
		pairs := make([]string, 0, 2*len(forms))
		for _, f := range forms {
			pairs = append(pairs, f, Mask)
		}
		s.r = strings.NewReplacer(pairs...)
	}
	return s
}

// formsOf lists the forms of one value (possibly with duplicates).
func formsOf(v string) []string {
	if v == "" {
		return nil
	}
	b := []byte(v)
	h := hex.EncodeToString(b)
	return []string{
		v,
		base64.StdEncoding.EncodeToString(b),
		base64.URLEncoding.EncodeToString(b),
		base64.RawStdEncoding.EncodeToString(b),
		base64.RawURLEncoding.EncodeToString(b),
		url.QueryEscape(v),
		url.PathEscape(v),
		jsonEscaped(v, true),
		jsonEscaped(v, false),
		h,
		strings.ToUpper(h),
	}
}

// jsonEscaped is v as the body of a JSON string, without the quotes.
func jsonEscaped(v string, escapeHTML bool) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(escapeHTML)
	if err := enc.Encode(v); err != nil {
		return ""
	}
	out := strings.TrimSuffix(buf.String(), "\n")
	return out[1 : len(out)-1]
}

func (s *Scrubber) active() bool { return s != nil && s.r != nil }

// String returns v with every form of every value replaced by Mask.
func (s *Scrubber) String(v string) string {
	if !s.active() {
		return v
	}
	return s.r.Replace(v)
}

// Bytes returns a scrubbed copy of b; nil stays nil. b is not modified.
func (s *Scrubber) Bytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	if !s.active() {
		return b
	}
	return []byte(s.r.Replace(string(b)))
}

// Any returns a scrubbed deep copy of v; v is never modified. It handles
// every shape a tool result takes (internal/mcp toCallResult):
//
//   - string, []byte;
//   - json.RawMessage: decoded, scrubbed as a tree and re-encoded (numbers
//     keep their text); invalid JSON is scrubbed as bytes;
//   - decoded JSON trees (map[string]any, []any, json.Number, float64,
//     bool, nil); object keys are scrubbed too, and a number that matches
//     becomes a scrubbed string;
//   - SDK content (*TextContent, *ImageContent, *AudioContent,
//     *ResourceLink, *EmbeddedResource; binary data is scrubbed as bytes;
//     any other content type is kept when clean and otherwise becomes a
//     *TextContent holding its scrubbed wire form), []sdk.Content and
//     *sdk.CallToolResult (content, structured content, meta);
//   - an error: see Error.
//
// Anything else is marshalled to JSON, scrubbed and returned decoded (as
// map[string]any, []any, ...); if it cannot be marshalled, its scrubbed %v
// text is returned.
func (s *Scrubber) Any(v any) any {
	if !s.active() {
		return v
	}
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		return s.String(t)
	case []byte:
		return s.Bytes(t)
	case json.RawMessage:
		return s.raw(t)
	case bool:
		return t
	case json.Number:
		return s.number(string(t), t)
	case float64:
		return s.float(t)
	case map[string]any:
		return s.object(t)
	case []any:
		return s.array(t)
	case sdk.Meta:
		return s.meta(t)
	case *sdk.CallToolResult:
		return s.callToolResult(t)
	case []sdk.Content:
		return s.contents(t)
	case sdk.Content:
		return s.content(t)
	case error:
		return s.Error(t)
	}
	return s.marshalled(v)
}

func (s *Scrubber) marshalled(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return s.String(fmt.Sprintf("%v", v))
	}
	tree, err := decode(b)
	if err != nil {
		return s.String(string(b))
	}
	return s.Any(tree)
}

// raw scrubs JSON text, keeping it valid JSON where possible.
func (s *Scrubber) raw(b json.RawMessage) json.RawMessage {
	if b == nil {
		return nil
	}
	tree, err := decode(b)
	if err != nil {
		return json.RawMessage(s.Bytes(b))
	}
	out, err := json.Marshal(s.Any(tree))
	if err != nil {
		return json.RawMessage(s.Bytes(b))
	}
	// Defensive second pass over the encoded text (forms spanning JSON
	// structure); if that breaks the JSON, return the scrubbed original
	// text as one JSON string.
	out = s.Bytes(out)
	if !json.Valid(out) {
		str, _ := json.Marshal(s.String(string(b)))
		return json.RawMessage(s.Bytes(str))
	}
	return json.RawMessage(out)
}

// number scrubs a number's text; a match turns it into a string.
func (s *Scrubber) number(text string, orig any) any {
	if c := s.String(text); c != text {
		return c
	}
	return orig
}

func (s *Scrubber) float(f float64) any {
	for _, text := range []string{
		strconv.FormatFloat(f, 'f', -1, 64),
		strconv.FormatFloat(f, 'g', -1, 64),
	} {
		if c := s.String(text); c != text {
			return c
		}
	}
	if b, err := json.Marshal(f); err == nil {
		return s.number(string(b), f)
	}
	return f
}

func (s *Scrubber) object(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[s.String(k)] = s.Any(v)
	}
	return out
}

func (s *Scrubber) array(a []any) []any {
	if a == nil {
		return nil
	}
	out := make([]any, len(a))
	for i, v := range a {
		out[i] = s.Any(v)
	}
	return out
}

func (s *Scrubber) meta(m sdk.Meta) sdk.Meta {
	if m == nil {
		return nil
	}
	return sdk.Meta(s.object(m))
}

func (s *Scrubber) strings(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = s.String(v)
	}
	return out
}

func (s *Scrubber) callToolResult(r *sdk.CallToolResult) *sdk.CallToolResult {
	if r == nil {
		return nil
	}
	cp := *r
	cp.Meta = s.meta(r.Meta)
	cp.Content = s.contents(r.Content)
	cp.StructuredContent = s.Any(r.StructuredContent)
	cp.RequestState = s.String(r.RequestState)
	return &cp
}

func (s *Scrubber) contents(cs []sdk.Content) []sdk.Content {
	if cs == nil {
		return nil
	}
	out := make([]sdk.Content, len(cs))
	for i, c := range cs {
		out[i] = s.content(c)
	}
	return out
}

func (s *Scrubber) content(c sdk.Content) sdk.Content {
	switch t := c.(type) {
	case nil:
		return nil
	case *sdk.TextContent:
		if t == nil {
			return t
		}
		cp := *t
		cp.Text = s.String(t.Text)
		cp.Meta = s.meta(t.Meta)
		return &cp
	case *sdk.ImageContent:
		if t == nil {
			return t
		}
		cp := *t
		cp.Data = s.Bytes(t.Data)
		cp.MIMEType = s.String(t.MIMEType)
		cp.Meta = s.meta(t.Meta)
		return &cp
	case *sdk.AudioContent:
		if t == nil {
			return t
		}
		cp := *t
		cp.Data = s.Bytes(t.Data)
		cp.MIMEType = s.String(t.MIMEType)
		cp.Meta = s.meta(t.Meta)
		return &cp
	case *sdk.ResourceLink:
		if t == nil {
			return t
		}
		cp := *t
		cp.URI = s.String(t.URI)
		cp.Name = s.String(t.Name)
		cp.Title = s.String(t.Title)
		cp.Description = s.String(t.Description)
		cp.MIMEType = s.String(t.MIMEType)
		cp.Meta = s.meta(t.Meta)
		if t.Icons != nil {
			cp.Icons = make([]sdk.Icon, len(t.Icons))
			for i, ic := range t.Icons {
				ic.Source = s.String(ic.Source)
				ic.MIMEType = s.String(ic.MIMEType)
				ic.Sizes = s.strings(ic.Sizes)
				cp.Icons[i] = ic
			}
		}
		return &cp
	case *sdk.EmbeddedResource:
		if t == nil {
			return t
		}
		cp := *t
		cp.Meta = s.meta(t.Meta)
		if t.Resource != nil {
			rc := *t.Resource
			rc.URI = s.String(rc.URI)
			rc.MIMEType = s.String(rc.MIMEType)
			rc.Text = s.String(rc.Text)
			rc.Blob = s.Bytes(rc.Blob)
			rc.Meta = s.meta(rc.Meta)
			cp.Resource = &rc
		}
		return &cp
	}
	// Any other content (the deprecated sampling types ToolUseContent and
	// ToolResultContent, or a type from a newer SDK): keep it when its
	// wire form is clean, otherwise replace it by its scrubbed wire form
	// as text.
	b, err := c.MarshalJSON()
	if err != nil {
		return &sdk.TextContent{Text: s.String(fmt.Sprintf("%v", c))}
	}
	if clean := s.String(string(b)); clean != string(b) {
		return &sdk.TextContent{Text: clean}
	}
	return c
}

// Error returns err with its message scrubbed; nil stays nil. An error
// whose message holds no form is returned as it is. Otherwise the result's
// Error() is the scrubbed message and Unwrap returns err, so errors.Is and
// errors.As keep working.
//
// errors.As (and Unwrap) reach the original error and its fields, which
// may still hold the value: a caller that extracts a typed error from the
// chain and renders its fields (internal/mcp.ToolError's Message and Data,
// for one) must scrub those fields itself. This package cannot import
// internal/mcp; the pipeline's secret stage does that.
func (s *Scrubber) Error(err error) error {
	if err == nil || !s.active() {
		return err
	}
	msg := err.Error()
	clean := s.String(msg)
	if clean == msg {
		return err
	}
	return &scrubbedError{msg: clean, err: err}
}

type scrubbedError struct {
	msg string
	err error
}

func (e *scrubbedError) Error() string { return e.msg }
func (e *scrubbedError) Unwrap() error { return e.err }

// errInvalidJSON reports text that is not exactly one JSON value.
var errInvalidJSON = errors.New("scrub: invalid JSON")

// decode parses exactly one JSON value with numbers kept as json.Number.
func decode(b []byte) (any, error) {
	if !json.Valid(b) {
		return nil, errInvalidJSON
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}
