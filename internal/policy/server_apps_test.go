package policy_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/policy"
)

// A published user-added MCP server's tools are a server app in the
// registry (federation connector). The role editor lists them like any
// app, an admin can grant `<server>.<tool>` or `<server>.*`, and the
// compiled policy then allows them for the role's members (task 1d9i8b07:
// publishing alone keeps them hidden for the role until a role grants
// them; the owner keeps the owner layer, task fekckdrt).
func TestRoleEditorGrantsServerAppTools(t *testing.T) {
	p := newPages(t)
	handler := func(context.Context, connectors.Call) (connectors.Result, error) { return connectors.Result{}, nil }
	err := p.reg.AddServerTools("wiki", []connectors.Tool{
		{App: "wiki", Name: "search", Description: "[wiki] search", InputSchema: json.RawMessage(`{"type":"object"}`),
			Kind: connectors.KindRead, Handler: handler},
		{App: "wiki", Name: "create_page", Description: "[wiki] create", InputSchema: json.RawMessage(`{"type":"object"}`),
			Kind: connectors.KindWrite, Reconcile: connectors.Reconciliation{Kind: connectors.ReconcileNone}, Handler: handler},
	})
	if err != nil {
		t.Fatalf("AddServerTools: %v", err)
	}
	search, _ := p.reg.Get("wiki.search")
	create, _ := p.reg.Get("wiki.create_page")
	ctx := context.Background()
	if d, err := p.svc.Decide(ctx, policy.Input{UserID: memberUser, Tool: search}); err != nil || d.Outcome != policy.OutcomeHidden {
		t.Fatalf("before the grant: %v, %v; want hidden", d.Outcome, err)
	}

	body := p.do(t, http.MethodGet, "/admin/roles/member", nil, true).Body.String()
	for _, want := range []string{`name="outcome.wiki.*"`, `name="outcome.wiki.search"`, `name="outcome.wiki.create_page"`} {
		if !strings.Contains(body, want) {
			t.Errorf("role editor lacks %s", want)
		}
	}

	form := url.Values{
		"description":              {"Default"},
		"outcome.fake.list_items":  {"allow"},
		"outcome.wiki.search":      {"allow"},
		"outcome.wiki.create_page": {"confirm"},
	}
	if rec := p.do(t, http.MethodPost, "/admin/roles/member", form, true); rec.Code != http.StatusSeeOther {
		t.Fatalf("save role = %d:\n%s", rec.Code, rec.Body)
	}
	if d, err := p.svc.Decide(ctx, policy.Input{UserID: memberUser, Tool: search}); err != nil || d.Outcome != policy.OutcomeAllow {
		t.Errorf("wiki.search after the grant: %v, %v; want allow", d.Outcome, err)
	}
	if d, err := p.svc.Decide(ctx, policy.Input{UserID: memberUser, Tool: create}); err != nil || d.Outcome != policy.OutcomeConfirm {
		t.Errorf("wiki.create_page after the grant: %v, %v; want confirm", d.Outcome, err)
	}
}

// The role editor lists a server app's resources/read and prompts/get
// actions next to its tools (task bdb5zcud) and saves grants of them.
func TestRoleEditorGrantsServerResourcesAndPrompts(t *testing.T) {
	p := newPages(t)
	handler := func(context.Context, connectors.Call) (connectors.Result, error) { return connectors.Result{}, nil }
	if err := p.reg.AddServerTools("wiki", []connectors.Tool{
		{App: "wiki", Name: "search", Description: "[wiki] search", InputSchema: json.RawMessage(`{"type":"object"}`),
			Kind: connectors.KindRead, Handler: handler},
	}); err != nil {
		t.Fatal(err)
	}
	body := p.do(t, http.MethodGet, "/admin/roles/member", nil, true).Body.String()
	for _, want := range []string{`name="outcome.wiki.resources/read"`, `name="outcome.wiki.prompts/get"`} {
		if !strings.Contains(body, want) {
			t.Errorf("role editor lacks %s", want)
		}
	}
	// Built-in apps get no such rows.
	if strings.Contains(body, `name="outcome.fake.resources/read"`) {
		t.Error("role editor offers resources/read for a built-in app")
	}
	res := policy.ServerAccessTool("wiki", policy.ResourcesReadTool)
	ctx := context.Background()
	if ok, _ := p.svc.Permits(ctx, policy.Input{UserID: memberUser, Tool: res}); ok {
		t.Fatal("resources permitted before the grant")
	}
	form := url.Values{"description": {"Default"}, "outcome.fake.list_items": {"allow"}, "outcome.wiki.resources/read": {"allow"}}
	if rec := p.do(t, http.MethodPost, "/admin/roles/member", form, true); rec.Code != http.StatusSeeOther {
		t.Fatalf("save role = %d:\n%s", rec.Code, rec.Body)
	}
	if ok, err := p.svc.Permits(ctx, policy.Input{UserID: memberUser, Tool: res}); err != nil || !ok {
		t.Errorf("resources after the grant: %v, %v", ok, err)
	}
	if ok, _ := p.svc.Permits(ctx, policy.Input{UserID: memberUser, Tool: policy.ServerAccessTool("wiki", policy.PromptsGetTool)}); ok {
		t.Error("prompts permitted by a resources grant")
	}
}
