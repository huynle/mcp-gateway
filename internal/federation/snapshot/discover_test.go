package snapshot

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// fakeSession is an in-memory Session.
type fakeSession struct {
	caps      *mcp.ServerCapabilities
	tools     []*mcp.Tool
	resources []*mcp.Resource
	templates []*mcp.ResourceTemplate
	prompts   []*mcp.Prompt
	err       error
	calls     []string
}

func (f *fakeSession) Capabilities() *mcp.ServerCapabilities { return f.caps }

func (f *fakeSession) ListTools(context.Context) ([]*mcp.Tool, error) {
	f.calls = append(f.calls, "tools")
	return f.tools, f.err
}

func (f *fakeSession) ListResources(context.Context) ([]*mcp.Resource, error) {
	f.calls = append(f.calls, "resources")
	return f.resources, f.err
}

func (f *fakeSession) ListResourceTemplates(context.Context) ([]*mcp.ResourceTemplate, error) {
	f.calls = append(f.calls, "templates")
	return f.templates, f.err
}

func (f *fakeSession) ListPrompts(context.Context) ([]*mcp.Prompt, error) {
	f.calls = append(f.calls, "prompts")
	return f.prompts, f.err
}

func allCaps() *mcp.ServerCapabilities {
	return &mcp.ServerCapabilities{
		Tools:     &mcp.ToolCapabilities{},
		Resources: &mcp.ResourceCapabilities{},
		Prompts:   &mcp.PromptCapabilities{},
	}
}

func boolPtr(b bool) *bool { return &b }

// objSchema is what a go-sdk client hands back for a tool schema.
func objSchema(t *testing.T, s string) any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("schema: %v", err)
	}
	return m
}

func TestDiscoverMapsEverything(t *testing.T) {
	sess := &fakeSession{
		caps: allCaps(),
		tools: []*mcp.Tool{
			{
				Name: "write_note", Title: "Write", Description: "writes a note",
				InputSchema:  objSchema(t, `{"type":"object","properties":{"text":{"type":"string"}}}`),
				OutputSchema: objSchema(t, `{"type":"object"}`),
				Annotations:  &mcp.ToolAnnotations{DestructiveHint: boolPtr(true), OpenWorldHint: boolPtr(false), Title: "W"},
			},
			{
				Name: "search", Description: "searches",
				InputSchema: objSchema(t, `{"type":"object"}`),
				Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
			},
		},
		resources: []*mcp.Resource{{URI: "file:///b", Name: "b"}, {URI: "file:///a", Name: "a", MIMEType: "text/plain"}},
		templates: []*mcp.ResourceTemplate{{URITemplate: "note://{id}", Name: "note"}},
		prompts: []*mcp.Prompt{{Name: "summarize", Description: "sum", Arguments: []*mcp.PromptArgument{
			{Name: "topic", Required: true},
		}}},
	}
	snap, err := Discover(t.Context(), sess)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(snap.Tools) != 2 || snap.Tools[0].Name != "search" || snap.Tools[1].Name != "write_note" {
		t.Fatalf("tools = %+v, want sorted search, write_note", snap.Tools)
	}
	w := snap.Tools[1]
	if w.Title != "Write" || w.Description != "writes a note" {
		t.Errorf("write_note title/description = %q / %q", w.Title, w.Description)
	}
	if !EqualJSON(w.InputSchema, []byte(`{"properties":{"text":{"type":"string"}},"type":"object"}`)) {
		t.Errorf("input schema = %s", w.InputSchema)
	}
	if !EqualJSON(w.OutputSchema, []byte(`{"type":"object"}`)) {
		t.Errorf("output schema = %s", w.OutputSchema)
	}
	if w.Annotations == nil || w.Annotations.DestructiveHint == nil || !*w.Annotations.DestructiveHint ||
		w.Annotations.OpenWorldHint == nil || *w.Annotations.OpenWorldHint || w.Annotations.Title != "W" {
		t.Errorf("annotations = %+v", w.Annotations)
	}
	if snap.Tools[0].OutputSchema != nil {
		t.Errorf("search output schema = %s, want none", snap.Tools[0].OutputSchema)
	}
	if len(snap.Resources) != 2 || snap.Resources[0].URI != "file:///a" || snap.Resources[0].MIMEType != "text/plain" {
		t.Errorf("resources = %+v", snap.Resources)
	}
	if len(snap.ResourceTemplates) != 1 || snap.ResourceTemplates[0].URITemplate != "note://{id}" {
		t.Errorf("templates = %+v", snap.ResourceTemplates)
	}
	if len(snap.Prompts) != 1 || len(snap.Prompts[0].Arguments) != 1 || !snap.Prompts[0].Arguments[0].Required {
		t.Errorf("prompts = %+v", snap.Prompts)
	}
}

func TestHintKind(t *testing.T) {
	cases := []struct {
		name string
		ann  *Annotations
		want Kind
	}{
		{"missing annotations", nil, KindWrite},
		{"readOnlyHint false", &Annotations{}, KindWrite},
		{"readOnlyHint false but not destructive", &Annotations{DestructiveHint: boolPtr(false)}, KindWrite},
		{"readOnlyHint true", &Annotations{ReadOnlyHint: true}, KindRead},
	}
	for _, c := range cases {
		if got := (Tool{Name: "x", Annotations: c.ann}).HintKind(); got != c.want {
			t.Errorf("%s: HintKind = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestDiscoverReadOnlyHintSurvivesDiscovery(t *testing.T) {
	sess := &fakeSession{caps: allCaps(), tools: []*mcp.Tool{
		{Name: "r", InputSchema: objSchema(t, `{"type":"object"}`), Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		{Name: "w", InputSchema: objSchema(t, `{"type":"object"}`)},
	}}
	snap, err := Discover(t.Context(), sess)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Tools[0].HintKind() != KindRead || snap.Tools[1].HintKind() != KindWrite {
		t.Errorf("kinds = %s, %s; want read, write", snap.Tools[0].HintKind(), snap.Tools[1].HintKind())
	}
}

func TestDiscoverOnlyListsAdvertisedCapabilities(t *testing.T) {
	sess := &fakeSession{caps: &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{}},
		tools: []*mcp.Tool{{Name: "t", InputSchema: objSchema(t, `{"type":"object"}`)}}}
	snap, err := Discover(t.Context(), sess)
	if err != nil {
		t.Fatal(err)
	}
	if len(sess.calls) != 1 || sess.calls[0] != "tools" {
		t.Errorf("calls = %v, want only tools", sess.calls)
	}
	if len(snap.Tools) != 1 || snap.Resources != nil || snap.Prompts != nil {
		t.Errorf("snapshot = %+v", snap)
	}

	none := &fakeSession{}
	snap, err = Discover(t.Context(), none)
	if err != nil {
		t.Fatal(err)
	}
	if len(none.calls) != 0 || len(snap.Tools) != 0 {
		t.Errorf("nil capabilities: calls %v, tools %d", none.calls, len(snap.Tools))
	}
}

func TestDiscoverPropagatesListErrors(t *testing.T) {
	boom := errors.New("boom")
	sess := &fakeSession{caps: allCaps(), err: boom}
	if _, err := Discover(t.Context(), sess); !errors.Is(err, boom) {
		t.Errorf("Discover = %v, want wrapped list error", err)
	}
}

func TestDiscoverRejectsDuplicateOrEmptyNames(t *testing.T) {
	cases := map[string]*fakeSession{
		"duplicate tool":   {caps: allCaps(), tools: []*mcp.Tool{{Name: "a"}, {Name: "a"}}},
		"empty tool":       {caps: allCaps(), tools: []*mcp.Tool{{Name: ""}}},
		"duplicate prompt": {caps: allCaps(), prompts: []*mcp.Prompt{{Name: "p"}, {Name: "p"}}},
		"duplicate resource": {caps: allCaps(), resources: []*mcp.Resource{
			{URI: "u", Name: "a"}, {URI: "u", Name: "b"}}},
		"nil tool": {caps: allCaps(), tools: []*mcp.Tool{nil}},
	}
	for name, sess := range cases {
		if _, err := Discover(t.Context(), sess); !errors.Is(err, ErrInvalidSnapshot) {
			t.Errorf("%s: Discover = %v, want ErrInvalidSnapshot", name, err)
		}
	}
}
