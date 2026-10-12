//go:build integration

package snapshot_test

import (
	"context"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/store"
)

// hostile is an upstream with NUL in every kind of string (Brain task
// jsb8470s).
type hostile struct{}

func (hostile) Capabilities() *mcp.ServerCapabilities {
	return &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{}, Resources: &mcp.ResourceCapabilities{}, Prompts: &mcp.PromptCapabilities{}}
}

func (hostile) ListTools(context.Context) ([]*mcp.Tool, error) {
	return []*mcp.Tool{
		{Name: "search", Description: "finds\x00 notes", InputSchema: map[string]any{"type": "object",
			"properties": map[string]any{"q": map[string]any{"type": "string", "description": "q\x00"}}},
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		{Name: "ev\x00il", InputSchema: map[string]any{"type": "object"}},
		{Name: "badkey", InputSchema: map[string]any{"type": "object", "properties": map[string]any{"a\x00": map[string]any{}}}},
	}, nil
}

func (hostile) ListResources(context.Context) ([]*mcp.Resource, error) {
	return []*mcp.Resource{{URI: "notes://a", Name: "a\x00"}, {URI: "notes://b\x00", Name: "b"}}, nil
}

func (hostile) ListResourceTemplates(context.Context) ([]*mcp.ResourceTemplate, error) {
	return []*mcp.ResourceTemplate{{URITemplate: "notes://{id}", Name: "id\x00"}}, nil
}

func (hostile) ListPrompts(context.Context) ([]*mcp.Prompt, error) {
	return []*mcp.Prompt{
		{Name: "summarize", Arguments: []*mcp.PromptArgument{{Name: "topic", Description: "t\x00"}}},
		{Name: "badarg", Arguments: []*mcp.PromptArgument{{Name: "x\x00"}}},
	}, nil
}

func TestIntegrationRefreshStoresSanitizedSnapshot(t *testing.T) {
	st := openTestStore(t)
	ctx := t.Context()
	owner := newUser(t, st, "owner")
	srv := newServer(t, st, owner, "nulhost")
	svc := snapshot.NewService(st)
	actor := snapshot.Actor{UserID: owner}

	rec, _, err := svc.Refresh(ctx, actor, srv, hostile{})
	if err != nil {
		t.Fatalf("Refresh with NUL upstream text: %v", err)
	}
	var skipped []string
	for _, s := range rec.Skipped {
		skipped = append(skipped, s.Kind+":"+s.Name+":"+s.Reason)
	}
	want := "prompt:badarg:invalid argument,resource:notes://b:invalid name,tool:badkey:invalid schema,tool:evil:invalid name"
	if strings.Join(skipped, ",") != want {
		t.Errorf("skipped = %v, want %s", skipped, want)
	}

	// The stored row decodes to the clean items.
	latest, err := svc.Latest(ctx, actor, srv)
	if err != nil {
		t.Fatal(err)
	}
	if len(latest.Snapshot.Tools) != 1 || latest.Snapshot.Tools[0].Description != "finds notes" {
		t.Errorf("stored tools = %+v", latest.Snapshot.Tools)
	}
	if len(latest.Snapshot.Resources) != 1 || latest.Snapshot.Resources[0].Name != "a" ||
		len(latest.Snapshot.ResourceTemplates) != 1 || latest.Snapshot.ResourceTemplates[0].Name != "id" ||
		len(latest.Snapshot.Prompts) != 1 || latest.Snapshot.Prompts[0].Arguments[0].Description != "t" {
		t.Errorf("stored snapshot = %+v", latest.Snapshot)
	}
	var raw string
	if err := st.WithJobs(ctx, func(tx store.Tx) error {
		return tx.QueryRow(ctx, `SELECT tools::text || resources::text || resource_templates::text || prompts::text
			FROM mcp_server_snapshots WHERE server_id = $1`, srv).Scan(&raw)
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, `\u0000`) {
		t.Errorf("stored snapshot carries a NUL: %s", raw)
	}

	// The tool can be approved and called like any other.
	if _, err := svc.Approve(ctx, actor, srv, rec.Version, snapshot.ReviewDecisions{EnableReads: true}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Allowed(ctx, actor, srv, "search", map[string]any{"q": "x"}); err != nil {
		t.Errorf("Allowed(search) after approval: %v", err)
	}
	// A second refresh of the same upstream adds no version and still
	// reports what it skipped.
	again, _, err := svc.Refresh(ctx, actor, srv, hostile{})
	if err != nil {
		t.Fatal(err)
	}
	if again.Version != rec.Version || len(again.Skipped) != 4 {
		t.Errorf("second refresh: version %d (want %d), skipped %d (want 4)", again.Version, rec.Version, len(again.Skipped))
	}
}
