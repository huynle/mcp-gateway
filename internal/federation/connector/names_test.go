package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/store"
)

func TestValidateServerName(t *testing.T) {
	for _, name := range []string{"notes", "brain", "my-server_2", strings.Repeat("a", 63)} {
		if err := ValidateServerName(name); err != nil {
			t.Errorf("ValidateServerName(%q) = %v, want nil", name, err)
		}
	}
	for _, name := range []string{"", "Notes", "a.b", "a b", strings.Repeat("a", 64)} {
		if err := ValidateServerName(name); !errors.Is(err, ErrInvalidServerName) {
			t.Errorf("ValidateServerName(%q) = %v, want ErrInvalidServerName", name, err)
		}
	}
	for _, name := range ReservedNames() {
		if err := ValidateServerName(name); !errors.Is(err, ErrReservedServerName) {
			t.Errorf("ValidateServerName(%q) = %v, want ErrReservedServerName", name, err)
		}
	}
	want := []string{"atlassian", "calendar", "chat", "confluence", "contacts", "docs", "drive", "fake", "gateway", "github", "gmail", "google", "jira", "mcp", "microsoft", "secrets", "sheets", "slack", "slides", "tasks"}
	if got := fmt.Sprint(ReservedNames()); got != fmt.Sprint(want) {
		t.Errorf("ReservedNames = %s, want %s", got, want)
	}
}

func TestToolName(t *testing.T) {
	for in, want := range map[string]string{
		"search":                "search",
		"getUser":               "get_user",
		"get-user":              "get-user",
		"Create Note!":          "create_note",
		"ns/tool.v2":            "ns_tool_v2",
		"__x__":                 "x",
		"HTTPGet":               "httpget",
		"ünïcode":               "n_code",
		strings.Repeat("a", 80): strings.Repeat("a", 64),
	} {
		got, ok := ToolName(in)
		if !ok || got != want {
			t.Errorf("ToolName(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "!!!", "ü"} {
		if got, ok := ToolName(in); ok {
			t.Errorf("ToolName(%q) = %q, want refusal", in, got)
		}
	}
}

func record(tools []snapshot.Tool, review snapshot.Review) *snapshot.Record {
	return &snapshot.Record{ID: "snap-1", ServerID: "srv-1", Version: 1, Status: store.MCPSnapshotApproved,
		Snapshot: &snapshot.Snapshot{Tools: tools}, Review: review}
}

func TestBuildTools(t *testing.T) {
	server := &store.MCPServer{ID: "srv-1", Name: "notes"}
	tools := []snapshot.Tool{
		{Name: "search", Description: "Find notes.\u202e evil", InputSchema: json.RawMessage(`{"type":"object","properties":{"q":{"type":"string"}}}`)},
		{Name: "createNote", Title: "Create", InputSchema: json.RawMessage(`{"type":"object"}`)},
		{Name: "disabled_one", InputSchema: json.RawMessage(`{"type":"object"}`)},
		{Name: "no_schema"},
		{Name: "array_schema", InputSchema: json.RawMessage(`{"type":"array"}`)},
		{Name: "dup_a", InputSchema: json.RawMessage(`{"type":"object"}`)},
		{Name: "dupA", InputSchema: json.RawMessage(`{"type":"object"}`)},
		{Name: "not_reviewed", InputSchema: json.RawMessage(`{"type":"object"}`)},
	}
	review := snapshot.Review{
		"search":       {Enabled: true, Kind: snapshot.KindRead},
		"createNote":   {Enabled: true, Kind: snapshot.KindWrite},
		"disabled_one": {Enabled: false, Kind: snapshot.KindRead},
		"no_schema":    {Enabled: true, Kind: snapshot.KindRead},
		"array_schema": {Enabled: true, Kind: snapshot.KindRead},
		"dup_a":        {Enabled: true, Kind: snapshot.KindRead},
		"dupA":         {Enabled: true, Kind: snapshot.KindRead},
	}
	var calls []string
	handler := func(upstream string, kind connectors.Kind) connectors.Handler {
		calls = append(calls, upstream+":"+string(kind))
		return func(ctx context.Context, call connectors.Call) (connectors.Result, error) {
			return connectors.Result{}, nil
		}
	}
	got, skipped := buildTools(server, record(tools, review), handler)

	byName := map[string]connectors.Tool{}
	for _, tool := range got {
		byName[tool.FullName()] = tool
	}
	if len(byName) != 3 {
		t.Fatalf("tools = %v, want notes.search, notes.create_note, notes.no_schema", names(got))
	}
	s := byName["notes.search"]
	if s.Kind != connectors.KindRead || s.Reconcile.Kind != "" {
		t.Errorf("search kind/reconcile = %s/%s", s.Kind, s.Reconcile.Kind)
	}
	if !strings.HasPrefix(s.Description, "[notes] ") || strings.ContainsRune(s.Description, '\u202e') {
		t.Errorf("description = %q, want provenance prefix and no bidi controls", s.Description)
	}
	if id := s.ResourceIdentity(map[string]any{"q": "secret"}); fmt.Sprint(id) != "map[server:notes]" {
		t.Errorf("resource identity = %v", id)
	}
	if err := connectors.NewRegistry().AddServerTools("notes", got); err != nil {
		t.Errorf("built tools do not register: %v", err)
	}
	c := byName["notes.create_note"]
	if c.Kind != connectors.KindWrite || c.Reconcile.Kind != connectors.ReconcileNone || c.ResultIDs != nil {
		t.Errorf("write tool kind/reconcile/resultIDs = %s/%s/%v", c.Kind, c.Reconcile.Kind, c.ResultIDs != nil)
	}
	// Quirk 47ab9sk7: upstream tools are never deduplicated by arguments
	// (a write is often an unannotated read); every call runs.
	for _, tool := range got {
		if tool.Idempotency != connectors.IdempotencyPerCall {
			t.Errorf("%s idempotency = %q, want per_call", tool.FullName(), tool.Idempotency)
		}
	}
	if string(byName["notes.no_schema"].InputSchema) != `{"type":"object","properties":{},"additionalProperties":false}` {
		t.Errorf("no-schema tool schema = %s", byName["notes.no_schema"].InputSchema)
	}
	if fmt.Sprint(calls) != "[createNote:write no_schema:read search:read]" {
		t.Errorf("handlers bound for %v (upstream names and kinds)", calls)
	}
	if fmt.Sprint(skipped) != "[array_schema dupA dup_a]" {
		t.Errorf("skipped = %v", skipped)
	}
}

func names(tools []connectors.Tool) []string {
	out := []string{}
	for _, t := range tools {
		out = append(out, t.FullName())
	}
	return out
}
