package snapshot

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const strictSchema = `{
	"type": "object",
	"properties": {
		"query": {"type": "string"},
		"limit": {"type": "integer", "minimum": 1},
		"opts": {"type": "object", "properties": {"deep": {"type": "boolean"}}, "additionalProperties": false}
	},
	"required": ["query"],
	"additionalProperties": false
}`

func checkFixture() (*Snapshot, Review) {
	s := &Snapshot{Tools: []Tool{
		{Name: "search", InputSchema: json.RawMessage(strictSchema), Annotations: &Annotations{ReadOnlyHint: true}},
		{Name: "send", InputSchema: json.RawMessage(`{"type":"object","properties":{"to":{"type":"string"}}}`)},
		{Name: "noschema"},
		{Name: "remote", InputSchema: json.RawMessage(`{"$ref":"https://evil.example.com/schema.json"}`)},
		{Name: "draft7", InputSchema: json.RawMessage(`{"$schema":"http://json-schema.org/draft-07/schema#","type":"object","properties":{"n":{"type":"number"}},"required":["n"]}`)},
		{Name: "unreviewed", InputSchema: json.RawMessage(`{"type":"object"}`)},
	}}
	r := Review{
		"search":   {Enabled: true, Kind: KindRead},
		"send":     {Enabled: false, Kind: KindWrite},
		"noschema": {Enabled: true, Kind: KindWrite},
		"remote":   {Enabled: true, Kind: KindWrite},
		"draft7":   {Enabled: true, Kind: KindWrite},
	}
	return s, r
}

func args(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestCheckAllowsValidCall(t *testing.T) {
	s, r := checkFixture()
	tl, kind, err := Check(s, r, "search", args(t, `{"query":"x","limit":3,"opts":{"deep":true}}`))
	if err != nil {
		t.Fatalf("Check = %v", err)
	}
	if tl.Name != "search" || kind != KindRead {
		t.Errorf("tool %q kind %q", tl.Name, kind)
	}
	// Go-typed args (not from JSON) are normalised before validation.
	if _, _, err := Check(s, r, "search", map[string]any{"query": "x", "limit": 2}); err != nil {
		t.Errorf("Go-typed args = %v", err)
	}
	if _, _, err := Check(s, r, "draft7", map[string]any{"n": 1.5}); err != nil {
		t.Errorf("draft-07 schema = %v", err)
	}
}

func TestCheckRefusesUnknownAndDisabledTools(t *testing.T) {
	s, r := checkFixture()
	if _, _, err := Check(s, r, "nope", nil); !errors.Is(err, ErrToolNotReviewed) {
		t.Errorf("unknown tool = %v, want ErrToolNotReviewed", err)
	}
	if _, _, err := Check(nil, nil, "search", nil); !errors.Is(err, ErrToolNotReviewed) {
		t.Errorf("no approved snapshot = %v, want ErrToolNotReviewed", err)
	}
	if _, _, err := Check(s, r, "send", map[string]any{"to": "x"}); !errors.Is(err, ErrToolDisabled) {
		t.Errorf("disabled tool = %v, want ErrToolDisabled", err)
	}
	if _, _, err := Check(s, r, "unreviewed", nil); !errors.Is(err, ErrToolDisabled) {
		t.Errorf("tool without review entry = %v, want ErrToolDisabled", err)
	}
}

func TestCheckRefusesSchemaViolations(t *testing.T) {
	s, r := checkFixture()
	cases := map[string]string{
		"extra property":        `{"query":"x","smuggled":"rm -rf /"}`,
		"nested extra property": `{"query":"x","opts":{"deep":true,"exec":"SECRET-VALUE"}}`,
		"wrong type":            `{"query":42}`,
		"wrong nested type":     `{"query":"x","opts":{"deep":"yes"}}`,
		"missing required":      `{"limit":3}`,
		"below minimum":         `{"query":"x","limit":0}`,
		"non-integer":           `{"query":"x","limit":1.5}`,
	}
	for name, a := range cases {
		_, _, err := Check(s, r, "search", args(t, a))
		if !errors.Is(err, ErrArgsInvalid) {
			t.Errorf("%s: Check = %v, want ErrArgsInvalid", name, err)
			continue
		}
		for _, leak := range []string{"rm -rf", "SECRET-VALUE", "smuggled", "exec", "yes", "42"} {
			if strings.Contains(err.Error(), leak) {
				t.Errorf("%s: error %q echoes argument data %q", name, err, leak)
			}
		}
	}
}

func TestCheckMissingSchemaAllowsOnlyEmptyArgs(t *testing.T) {
	s, r := checkFixture()
	if _, _, err := Check(s, r, "noschema", nil); err != nil {
		t.Errorf("no args = %v", err)
	}
	if _, _, err := Check(s, r, "noschema", map[string]any{"a": 1}); !errors.Is(err, ErrArgsInvalid) {
		t.Errorf("args without schema = %v, want ErrArgsInvalid", err)
	}
}

func TestCheckRefusesUnusableSchema(t *testing.T) {
	s, r := checkFixture()
	if _, _, err := Check(s, r, "remote", map[string]any{}); !errors.Is(err, ErrArgsInvalid) {
		t.Errorf("remote $ref schema = %v, want ErrArgsInvalid (never fetched)", err)
	}
}

func TestCheckUsesReviewKind(t *testing.T) {
	s, r := checkFixture()
	tr := r["search"]
	tr.Kind = KindWrite
	r["search"] = tr
	if _, kind, err := Check(s, r, "search", map[string]any{"query": "q"}); err != nil || kind != KindWrite {
		t.Errorf("kind = %q, %v; want write from the review", kind, err)
	}
	// A review entry with an empty kind falls back to write.
	r["search"] = ToolReview{Enabled: true}
	if _, kind, _ := Check(s, r, "search", map[string]any{"query": "q"}); kind != KindWrite {
		t.Errorf("empty review kind = %q, want write", kind)
	}
}
