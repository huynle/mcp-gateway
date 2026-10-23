package scrub

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// secret has characters that make every encoded form distinct: space,
// slash, quote, backslash, HTML-escaped characters, '+', '?', '=' and a
// non-ASCII rune; its base64 forms contain "/" or "_", "+" or "-" and padding.
const secret = `p@ss w/rd"\<&>+?=é!???~~~`

// allForms computes every form the scrubber must remove, independently of
// the implementation.
func allForms(v string) map[string]string {
	jsonEsc, _ := json.Marshal(v)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	plainEsc := strings.TrimSuffix(buf.String(), "\n")
	return map[string]string{
		"raw":         v,
		"b64std":      base64.StdEncoding.EncodeToString([]byte(v)),
		"b64url":      base64.URLEncoding.EncodeToString([]byte(v)),
		"b64rawstd":   base64.RawStdEncoding.EncodeToString([]byte(v)),
		"b64rawurl":   base64.RawURLEncoding.EncodeToString([]byte(v)),
		"query":       url.QueryEscape(v),
		"path":        url.PathEscape(v),
		"json":        string(jsonEsc[1 : len(jsonEsc)-1]),
		"json-nohtml": plainEsc[1 : len(plainEsc)-1],
		"hex":         hex.EncodeToString([]byte(v)),
		"HEX":         strings.ToUpper(hex.EncodeToString([]byte(v))),
	}
}

// assertClean fails when any form of secret appears in s.
func assertClean(t *testing.T, s string) {
	t.Helper()
	for name, f := range allForms(secret) {
		if strings.Contains(s, f) {
			t.Errorf("output contains %s form %q:\n%s", name, f, s)
		}
	}
}

// marshal renders any value as JSON (falling back to %v) for assertions.
func marshal(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %T: %v", v, err)
	}
	return string(b)
}

func TestFormsAreDistinct(t *testing.T) {
	seen := map[string]string{}
	for name, f := range allForms(secret) {
		if other, ok := seen[f]; ok && name != other {
			// json and json-nohtml differ for this value; everything else
			// must too, or the test would not cover each form.
			t.Fatalf("forms %s and %s are equal", name, other)
		}
		seen[f] = name
	}
}

func TestStringEveryForm(t *testing.T) {
	s := New(secret)
	for name, f := range allForms(secret) {
		t.Run(name, func(t *testing.T) {
			in := "before " + f + " middle " + f + " after"
			got := s.String(in)
			assertClean(t, got)
			if want := "before [secret] middle [secret] after"; got != want {
				t.Fatalf("String = %q, want %q", got, want)
			}
		})
	}
}

func TestBytesEveryForm(t *testing.T) {
	s := New(secret)
	for name, f := range allForms(secret) {
		t.Run(name, func(t *testing.T) {
			in := []byte("x" + f + "y")
			orig := append([]byte(nil), in...)
			got := s.Bytes(in)
			if string(got) != "x[secret]y" {
				t.Fatalf("Bytes = %q", got)
			}
			if !bytes.Equal(in, orig) {
				t.Fatal("Bytes mutated input")
			}
		})
	}
	if s.Bytes(nil) != nil {
		t.Fatal("Bytes(nil) != nil")
	}
}

func TestLongestFirstAndMultipleValues(t *testing.T) {
	s := New("abcdefgh", "abcdefghijkl", "abcdefgh", "")
	if got := s.String("[abcdefghijkl] [abcdefgh]"); got != "[[secret]] [[secret]]" {
		t.Fatalf("String = %q", got)
	}
	// The base64 form of the longer value is not split by the shorter one.
	b := base64.StdEncoding.EncodeToString([]byte("abcdefghijkl"))
	if got := s.String(b); got != "[secret]" {
		t.Fatalf("String(%q) = %q", b, got)
	}
}

func TestNoValues(t *testing.T) {
	for _, s := range []*Scrubber{New(), New(""), nil} {
		if got := s.String("anything " + secret); got != "anything "+secret {
			t.Fatalf("String = %q", got)
		}
		m := map[string]any{"a": "b"}
		if got := s.Any(m); !reflect.DeepEqual(got, m) {
			t.Fatalf("Any = %v", got)
		}
		if s.Error(nil) != nil {
			t.Fatal("Error(nil) != nil")
		}
	}
}

func TestShortValueStillScrubbed(t *testing.T) {
	// Callers refuse values shorter than 8 bytes; the scrubber itself
	// removes whatever it is given.
	s := New("abc")
	if got := s.String("xabcx"); got != "x[secret]x" {
		t.Fatalf("String = %q", got)
	}
}

type payload struct {
	Password string `json:"password"`
	Nested   struct {
		Token string `json:"token"`
	} `json:"nested"`
}

func TestAny(t *testing.T) {
	f := allForms(secret)
	s := New(secret)
	typed := payload{Password: secret}
	typed.Nested.Token = f["b64std"]

	tests := []struct {
		name  string
		in    any
		check func(t *testing.T, out any)
	}{
		{"nil", nil, func(t *testing.T, out any) {
			if out != nil {
				t.Fatalf("out = %v", out)
			}
		}},
		{"bool", true, func(t *testing.T, out any) {
			if out != true {
				t.Fatalf("out = %v", out)
			}
		}},
		{"string", "pw=" + secret, func(t *testing.T, out any) {
			if out != "pw=[secret]" {
				t.Fatalf("out = %v", out)
			}
		}},
		{"bytes", []byte("pw=" + f["hex"]), func(t *testing.T, out any) {
			if b, ok := out.([]byte); !ok || string(b) != "pw=[secret]" {
				t.Fatalf("out = %#v", out)
			}
		}},
		{"raw message", json.RawMessage(`{"a":"` + f["json"] + `","` + f["json"] + `":["` + f["b64url"] + `"],"n":12345678901234567890}`),
			func(t *testing.T, out any) {
				raw, ok := out.(json.RawMessage)
				if !ok || !json.Valid(raw) {
					t.Fatalf("out = %T %s", out, out)
				}
				if !strings.Contains(string(raw), "12345678901234567890") {
					t.Fatalf("number lost: %s", raw)
				}
			}},
		{"invalid raw message", json.RawMessage(`{"a":"` + secret + `", `), func(t *testing.T, out any) {
			if _, ok := out.(json.RawMessage); !ok {
				t.Fatalf("out = %T", out)
			}
		}},
		{"map", map[string]any{
			"pw":    secret,
			secret:  "key",
			"deep":  map[string]any{"list": []any{f["query"], 1.0, nil, map[string]any{"x": f["path"]}}},
			"bytes": []byte(secret),
		}, nil},
		{"slice", []any{secret, []any{f["b64rawstd"]}, map[string]any{"k": f["b64rawurl"]}}, nil},
		{"text content", &sdk.TextContent{Text: "out: " + secret, Meta: sdk.Meta{"m": secret}}, func(t *testing.T, out any) {
			if _, ok := out.(*sdk.TextContent); !ok {
				t.Fatalf("out = %T", out)
			}
		}},
		{"image content", &sdk.ImageContent{Data: []byte(secret + "\x00\x01binary"), MIMEType: "image/png"}, func(t *testing.T, out any) {
			c, ok := out.(*sdk.ImageContent)
			if !ok || c.MIMEType != "image/png" || !bytes.HasSuffix(c.Data, []byte("\x00\x01binary")) {
				t.Fatalf("out = %#v", out)
			}
		}},
		{"audio content", &sdk.AudioContent{Data: []byte(secret), MIMEType: "audio/wav"}, nil},
		{"resource link", &sdk.ResourceLink{
			URI:         "https://example.com/x?pw=" + f["query"],
			Name:        secret,
			Title:       f["hex"],
			Description: "d " + secret,
			MIMEType:    "text/plain",
			Icons:       []sdk.Icon{{Source: "https://example.com/" + f["path"] + ".png"}},
		}, nil},
		{"embedded resource", &sdk.EmbeddedResource{Resource: &sdk.ResourceContents{
			URI:  "file:///" + f["path"],
			Text: "t " + secret,
			Blob: []byte(secret),
			Meta: sdk.Meta{"k": secret},
		}}, nil},
		{"embedded resource nil", &sdk.EmbeddedResource{}, nil},
		// Deprecated sampling content exercises the unknown-content fallback.
		{"tool use", &sdk.ToolUseContent{ //nolint:staticcheck // fallback path
			ID: "1", Name: "n", Input: map[string]any{"pw": secret},
		}, func(t *testing.T, out any) {
			if _, ok := out.(*sdk.TextContent); !ok {
				t.Fatalf("out = %T, want *TextContent", out)
			}
		}},
		{"tool result", &sdk.ToolResultContent{ //nolint:staticcheck // fallback path
			ToolUseID:         "1",
			Content:           []sdk.Content{&sdk.TextContent{Text: secret}},
			StructuredContent: map[string]any{"pw": secret},
		}, nil},
		{"content slice", []sdk.Content{
			&sdk.TextContent{Text: secret},
			&sdk.ImageContent{Data: []byte(secret), MIMEType: "image/png"},
			&sdk.TextContent{Text: f["b64std"]},
		}, func(t *testing.T, out any) {
			if c, ok := out.([]sdk.Content); !ok || len(c) != 3 {
				t.Fatalf("out = %#v", out)
			}
		}},
		{"call tool result", &sdk.CallToolResult{
			Content:           []sdk.Content{&sdk.TextContent{Text: "a " + secret}},
			StructuredContent: map[string]any{"pw": secret, "list": []any{f["json"]}},
			IsError:           true,
			Meta:              sdk.Meta{"m": f["hex"]},
		}, func(t *testing.T, out any) {
			r, ok := out.(*sdk.CallToolResult)
			if !ok || !r.IsError {
				t.Fatalf("out = %#v", out)
			}
		}},
		{"call tool result raw structured", &sdk.CallToolResult{
			Content:           []sdk.Content{&sdk.TextContent{Text: `{"pw":"` + f["json"] + `"}`}},
			StructuredContent: json.RawMessage(`{"pw":"` + f["json"] + `"}`),
		}, nil},
		{"call tool result typed structured", &sdk.CallToolResult{StructuredContent: typed}, nil},
		{"typed struct", typed, func(t *testing.T, out any) {
			m, ok := out.(map[string]any)
			if !ok || m["password"] != "[secret]" {
				t.Fatalf("out = %#v", out)
			}
		}},
		{"typed pointer", &typed, nil},
		{"string map", map[string]string{"pw": secret}, nil},
		{"error value", fmt.Errorf("boom %s", secret), func(t *testing.T, out any) {
			if !strings.Contains(fmt.Sprint(out), "[secret]") {
				t.Fatalf("out = %v", out)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := fmt.Sprintf("%#v", tt.in)
			beforeJSON, _ := json.Marshal(tt.in)
			out := s.Any(tt.in)
			if b, err := json.Marshal(out); err == nil {
				assertClean(t, string(b))
			}
			assertClean(t, fmt.Sprintf("%v", out))
			if tt.check != nil {
				tt.check(t, out)
			}
			if after := fmt.Sprintf("%#v", tt.in); after != before {
				t.Fatalf("input mutated:\n%s\n%s", before, after)
			}
			if afterJSON, _ := json.Marshal(tt.in); !bytes.Equal(afterJSON, beforeJSON) {
				t.Fatalf("input mutated:\n%s\n%s", beforeJSON, afterJSON)
			}
		})
	}
}

func TestAnyNumbers(t *testing.T) {
	s := New("12345678")
	in := map[string]any{"f": 12345678.0, "n": json.Number("912345678"), "i": 12345678, "ok": 42.0}
	out := s.Any(in).(map[string]any)
	b := marshal(t, out)
	if strings.Contains(b, "12345678") {
		t.Fatalf("number not scrubbed: %s", b)
	}
	if out["ok"] != 42.0 {
		t.Fatalf("clean number changed: %v", out["ok"])
	}
}

func TestAnyCallToolResultIsCopy(t *testing.T) {
	s := New(secret)
	text := &sdk.TextContent{Text: secret}
	structured := map[string]any{"pw": secret}
	in := &sdk.CallToolResult{Content: []sdk.Content{text}, StructuredContent: structured}
	out := s.Any(in).(*sdk.CallToolResult)
	if out == in || out.Content[0] == sdk.Content(text) {
		t.Fatal("Any returned shared result or content")
	}
	if text.Text != secret || structured["pw"] != secret {
		t.Fatal("input mutated")
	}
	if s.Any((*sdk.CallToolResult)(nil)) != (*sdk.CallToolResult)(nil) {
		t.Fatal("typed nil result changed")
	}
}

var errSentinel = errors.New("sentinel")

type codedError struct{ Code int }

func (e *codedError) Error() string { return fmt.Sprintf("code %d: %s", e.Code, secret) }

func TestError(t *testing.T) {
	s := New(secret)
	if s.Error(nil) != nil {
		t.Fatal("Error(nil) != nil")
	}

	orig := fmt.Errorf("login with %q failed: %w", secret, errSentinel)
	got := s.Error(orig)
	assertClean(t, got.Error())
	if !strings.Contains(got.Error(), "[secret]") {
		t.Fatalf("Error() = %q", got.Error())
	}
	if !errors.Is(got, errSentinel) {
		t.Fatal("errors.Is lost the sentinel")
	}
	if errors.Unwrap(got) != orig { //nolint:errorlint // identity, not a match
		t.Fatal("Unwrap does not return the original")
	}
	if got := fmt.Sprintf("%v|%s|%+v", got, got, got); strings.Contains(got, secret) {
		t.Fatalf("formatted error leaks: %s", got)
	}

	ce := s.Error(&codedError{Code: 7})
	assertClean(t, ce.Error())
	var target *codedError
	if !errors.As(ce, &target) || target.Code != 7 {
		t.Fatal("errors.As lost the typed error")
	}

	clean := errors.New("nothing to see")
	if s.Error(clean) != clean { //nolint:errorlint // identity, not a match
		t.Fatal("clean error should be returned unchanged")
	}

	wrapped := fmt.Errorf("open: %w", fs.ErrNotExist)
	if !errors.Is(s.Error(fmt.Errorf("%s: %w", secret, wrapped)), fs.ErrNotExist) {
		t.Fatal("errors.Is through two levels")
	}
}

func TestConcurrent(t *testing.T) {
	s := New(secret, "another-secret-value")
	in := &sdk.CallToolResult{
		Content:           []sdk.Content{&sdk.TextContent{Text: secret}},
		StructuredContent: map[string]any{"pw": secret, "b": base64.StdEncoding.EncodeToString([]byte("another-secret-value"))},
	}
	other := allForms("another-secret-value")
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 50 {
				out := s.Any(in)
				b, _ := json.Marshal(out)
				if strings.Contains(string(b), secret) || strings.Contains(s.String(secret), secret) {
					t.Error("leak under concurrency")
				}
				for name, f := range other {
					if strings.Contains(string(b), f) {
						t.Errorf("second value's %s form leaks under concurrency", name)
					}
				}
				_ = s.Error(errors.New(secret))
			}
		})
	}
	wg.Wait()
}
