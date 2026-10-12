package snapshot

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// hostileSession lists NUL and control characters in every kind of
// upstream string (Brain task jsb8470s): PostgreSQL jsonb refuses
// U+0000, so none may reach the stored snapshot.
func hostileSession(t *testing.T) *fakeSession {
	t.Helper()
	return &fakeSession{
		caps: allCaps(),
		tools: []*mcp.Tool{
			{Name: "search", Title: "Se\x00arch", Description: "finds\x00 notes",
				InputSchema: objSchema(t, `{"type":"object","properties":{"q":{"type":"string","description":"query\u0000 text"}}}`),
				Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, Title: "t\x00"}},
			{Name: "ev\x00il", Description: "nul in the name", InputSchema: objSchema(t, `{"type":"object"}`)},
			{Name: "ctl\x01tool", Description: "control in the name", InputSchema: objSchema(t, `{"type":"object"}`)},
			{Name: "c1\u0085tool", Description: "C1 control in the name", InputSchema: objSchema(t, `{"type":"object"}`)},
			{Name: "badkey", Description: "nul in a schema key",
				InputSchema: objSchema(t, `{"type":"object","properties":{"a\u0000b":{"type":"string"}}}`)},
			{Name: "badout", Description: "nul in an output schema key", InputSchema: objSchema(t, `{"type":"object"}`),
				OutputSchema: objSchema(t, `{"type":"object","properties":{"x\u0000":{}}}`)},
		},
		resources: []*mcp.Resource{
			{URI: "notes://good", Name: "go\x00od", Description: "d\x00", MIMEType: "text/plain\x00"},
			{URI: "notes://bad\x00", Name: "bad"},
		},
		templates: []*mcp.ResourceTemplate{
			{URITemplate: "notes://{id}", Name: "by id", Title: "T\x00"},
			{URITemplate: "notes://{id}\x00", Name: "bad"},
		},
		prompts: []*mcp.Prompt{
			{Name: "summarize", Description: "sum\x00", Arguments: []*mcp.PromptArgument{{Name: "topic", Description: "about\x00"}}},
			{Name: "pr\x00ompt"},
			{Name: "badarg", Arguments: []*mcp.PromptArgument{{Name: "a\x00", Required: true}}},
		},
	}
}

func TestDiscoverSanitizesHostileText(t *testing.T) {
	snap, err := Discover(t.Context(), hostileSession(t))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	var tools []string
	for _, tl := range snap.Tools {
		tools = append(tools, tl.Name)
	}
	if strings.Join(tools, ",") != "search" {
		t.Errorf("tools = %v, want only search", tools)
	}
	search, _ := snap.Tool("search")
	if search.Title != "Search" || search.Description != "finds notes" || search.Annotations.Title != "t" {
		t.Errorf("search text = %q %q %q, want NUL removed", search.Title, search.Description, search.Annotations.Title)
	}
	if !strings.Contains(string(search.InputSchema), `"query text"`) {
		t.Errorf("schema = %s, want NUL removed from string values", search.InputSchema)
	}
	if len(snap.Resources) != 1 || snap.Resources[0].URI != "notes://good" || snap.Resources[0].Name != "good" ||
		snap.Resources[0].Description != "d" || snap.Resources[0].MIMEType != "text/plain" {
		t.Errorf("resources = %+v", snap.Resources)
	}
	if len(snap.ResourceTemplates) != 1 || snap.ResourceTemplates[0].URITemplate != "notes://{id}" || snap.ResourceTemplates[0].Title != "T" {
		t.Errorf("templates = %+v", snap.ResourceTemplates)
	}
	if len(snap.Prompts) != 1 || snap.Prompts[0].Name != "summarize" || snap.Prompts[0].Description != "sum" ||
		snap.Prompts[0].Arguments[0].Description != "about" {
		t.Errorf("prompts = %+v", snap.Prompts)
	}

	want := map[string]string{
		"tool evil":                      ReasonInvalidName,
		"tool ctltool":                   ReasonInvalidName,
		"tool c1 tool":                   ReasonInvalidName,
		"tool badkey":                    ReasonInvalidSchema,
		"tool badout":                    ReasonInvalidSchema,
		"resource notes://bad":           ReasonInvalidName,
		"resource template notes://{id}": ReasonInvalidName,
		"prompt prompt":                  ReasonInvalidName,
		"prompt badarg":                  ReasonInvalidArgument,
	}
	got := map[string]string{}
	for _, s := range snap.Skipped {
		for _, r := range s.Name {
			if r == 0 || unicode.IsControl(r) {
				t.Errorf("skipped name %q carries a control character", s.Name)
			}
		}
		got[s.Kind+" "+s.Name] = s.Reason
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("skipped[%s] = %q, want %q (all: %v)", k, got[k], v, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("skipped = %v, want %d items", got, len(want))
	}

	// Nothing that is stored carries a NUL.
	row, err := encodeSnapshot("srv", snap)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []json.RawMessage{row.Tools, row.Resources, row.ResourceTemplates, row.Prompts} {
		if strings.Contains(string(raw), `\u0000`) || strings.ContainsRune(string(raw), 0) {
			t.Errorf("stored list carries a NUL: %s", raw)
		}
	}
}

func TestDiscoverSkippedNotPartOfComparison(t *testing.T) {
	a, err := Discover(t.Context(), hostileSession(t))
	if err != nil {
		t.Fatal(err)
	}
	b := *a
	b.Skipped = nil
	if !Compare(a, &b).Empty() {
		t.Error("skipped items must not count as a change")
	}
}

func TestDiscoverCleanUpstreamSkipsNothing(t *testing.T) {
	sess := &fakeSession{caps: allCaps(), tools: []*mcp.Tool{{Name: "search", Description: "line one\nline two\ttab",
		InputSchema: objSchema(t, `{"type":"object"}`)}}}
	snap, err := Discover(t.Context(), sess)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Skipped) != 0 || len(snap.Tools) != 1 || snap.Tools[0].Description != "line one\nline two\ttab" {
		t.Errorf("clean upstream: %+v", snap)
	}
}
