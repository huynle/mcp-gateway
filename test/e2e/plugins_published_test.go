//go:build integration || e2e

package e2e

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/policy"
)

const (
	crmOwnerKey = "crm-owner-shared-key-e2e"
	crmAdminKey = "crm-admin-shared-key-e2e"
)

// TestE2EPluginsSharedKeyPublishedByAdmin is the shared-credential
// scenario (task w2cd39bc): alice adds a server with a shared API key on
// the portal; an admin publishes it to the restricted role and replaces
// the shared key on the admin pages; once the role grants the tool, bob
// and carol (both restricted) call it with the shared key, never their
// own. The owner keeps the tool after it is published (the owner layer
// covers published servers too, task fekckdrt / decision q7vbxlyk) and
// calls it with the server's shared credential, now the admin's key.
func TestE2EPluginsSharedKeyPublishedByAdmin(t *testing.T) {
	w := newWorld(t, options{federation: true})
	w.forbid(crmOwnerKey, "shared API key (owner)")
	w.forbid(crmAdminKey, "shared API key (admin)")
	w.allowLoopback()
	up := newKeyUpstream(t, "crm", "X-Crm-Key", map[string]string{crmOwnerKey: "owner-key", crmAdminKey: "admin-key"})
	carol := w.signInAs("carol-subject", "Carol", roleRestricted)

	// Alice adds it with a shared key; the key is never rendered again.
	id := w.addServer(w.alice, url.Values{"name": {"crm"}, "url_mode": {"https"}, "url": {up.srv.URL + "/mcp"},
		"auth_kind": {"api_key"}, "credential_mode": {"shared"}, "api_key_in": {"header"}, "api_key_name": {"X-Crm-Key"},
		"shared_api_key": {crmOwnerKey}})
	p := w.page(w.alice, "/servers/"+id)
	if !strings.Contains(p.body, "a secret is stored") || !strings.Contains(p.body, "shared credential") || strings.Contains(p.body, crmOwnerKey) {
		t.Errorf("owner's server page:\n%s", snippet(p.body))
	}
	w.approve(w.alice, id, w.refresh(w.alice, id), "lookup")
	alice := w.client(w.alice)
	if got := w.toolText(alice, "crm.lookup", map[string]any{"q": "a"}); got != "lookup a with owner-key" {
		t.Errorf("alice (private, owner layer) = %q", got)
	}

	// The admin publishes it to the restricted role and replaces the key.
	if p := w.page(w.admin, "/admin/servers/"+id); p.status != http.StatusOK || strings.Contains(p.body, crmOwnerKey) {
		t.Fatalf("admin server page = %d", p.status)
	}
	if p := w.page(w.alice, "/admin/servers/"+id); p.status != http.StatusNotFound {
		t.Errorf("non-admin GET admin server page = %d, want 404", p.status)
	}
	mustRedirect(t, "publish", w.submit(w.admin, "/admin/servers/"+id+"/publish", url.Values{"roles": {w.roleID(roleRestricted)}}),
		"/admin/servers/"+id+"?done=")
	mustRedirect(t, "shared credential", w.submit(w.admin, "/admin/servers/"+id+"/shared-credential", url.Values{"api_key": {crmAdminKey}}),
		"/admin/servers/"+id+"?done=")
	if p := w.page(w.admin, "/admin/servers/"+id); strings.Contains(p.body, crmAdminKey) {
		t.Error("the admin page renders the shared key")
	}
	// The owner may no longer approve a published server's review.
	rp := w.page(w.alice, "/servers/"+id+"/review")
	if !strings.Contains(rp.body, "an admin must review") || strings.Contains(rp.body, `name="enable"`) {
		t.Errorf("owner's review page of a published server:\n%s", snippet(rp.body))
	}
	version := regexp.MustCompile(`Version (\d+) is`).FindStringSubmatch(rp.body)
	if version == nil {
		t.Fatalf("review page without a version:\n%s", snippet(rp.body))
	}
	if p := w.submit(w.alice, "/servers/"+id+"/review", url.Values{"version": {version[1]}}); p.status != http.StatusForbidden {
		t.Errorf("owner review of a published server = %d, want 403", p.status)
	}

	// Published tools are hidden until a role grants them.
	bob, carolCS := w.client(w.bob), w.client(carol)
	if contains(toolNames(t, bob), "crm.lookup") {
		t.Error("published tool visible before any role grants it")
	}
	w.grant(roleRestricted, policy.ToolRule{App: "crm", Tool: "lookup", Outcome: policy.OutcomeAllow})
	for name, cs := range map[string]*sdk.ClientSession{"bob": bob, "carol": carolCS} {
		if !contains(toolNames(t, cs), "crm.lookup") {
			t.Errorf("%s does not see the granted tool", name)
			continue
		}
		if got := w.toolText(cs, "crm.lookup", map[string]any{"q": name}); got != "lookup "+name+" with admin-key" {
			t.Errorf("%s's call = %q, want the shared (admin-set) key", name, got)
		}
	}
	if p := w.page(w.bob, "/servers/"+id); p.status != http.StatusOK || !strings.Contains(p.body, ">shared credential<") || !strings.Contains(p.body, "published") {
		t.Errorf("bob's server page = %d:\n%s", p.status, snippet(p.body))
	}

	// The owner keeps the tool without any grant to her role (member).
	alice = w.client(w.alice)
	if !contains(toolNames(t, alice), "crm.lookup") {
		t.Error("owner lost the published tool (the owner layer covers published servers)")
	}
	if got := w.toolText(alice, "crm.lookup", map[string]any{"q": "a"}); got != "lookup a with admin-key" {
		t.Errorf("owner after publish = %q", got)
	}

	// The upstream only ever saw the shared key.
	for _, h := range up.headers() {
		if h.Get("Authorization") != "" || h.Get("Cookie") != "" {
			t.Errorf("upstream received gateway credentials: %v", h)
		}
		if k := h.Get("X-Crm-Key"); k != crmOwnerKey && k != crmAdminKey {
			t.Errorf("upstream request without the shared key (X-Crm-Key %q)", k)
		}
	}
	// The admin's changes are audited, without the key.
	actions := map[string]bool{}
	for _, ev := range w.events(w.admin) {
		if ev.ResourceIdentity["server_id"] == id {
			actions[ev.ResourceIdentity["action"]] = true
		}
	}
	if !actions["mcp_server.published"] || !actions["mcp_server.shared_credential_set"] {
		t.Errorf("admin audit actions = %v", actions)
	}
	if !w.hasAudit(w.bob, "crm.lookup", "succeeded", "") || !w.hasAudit(carol, "crm.lookup", "succeeded", "") {
		t.Error("no succeeded audit rows for bob's and carol's calls")
	}
}

type docsSearchIn struct {
	Q string `json:"q"`
}

// newDocsUpstream is a server without auth with a tool, a resource, a
// resource template and a prompt.
func newDocsUpstream(t *testing.T) string {
	t.Helper()
	s := sdk.NewServer(&sdk.Implementation{Name: "docs", Version: "1"}, nil)
	sdk.AddTool(s, &sdk.Tool{Name: "search", Description: "Search the docs.", Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true}},
		func(_ context.Context, _ *sdk.CallToolRequest, in docsSearchIn) (*sdk.CallToolResult, any, error) {
			return textResult("docs about " + in.Q), nil, nil
		})
	s.AddResource(&sdk.Resource{URI: "docs://index", Name: "index", MIMEType: "text/plain"},
		func(_ context.Context, req *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error) {
			return &sdk.ReadResourceResult{Contents: []*sdk.ResourceContents{{URI: req.Params.URI, MIMEType: "text/plain", Text: "the index"}}}, nil
		})
	s.AddResourceTemplate(&sdk.ResourceTemplate{URITemplate: "docs://page/{slug}", Name: "page"},
		func(_ context.Context, req *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error) {
			return &sdk.ReadResourceResult{Contents: []*sdk.ResourceContents{{URI: req.Params.URI, MIMEType: "text/plain", Text: "page " + strings.TrimPrefix(req.Params.URI, "docs://page/")}}}, nil
		})
	s.AddPrompt(&sdk.Prompt{Name: "summarize", Description: "Summarize a page", Arguments: []*sdk.PromptArgument{{Name: "page", Required: true}}},
		func(_ context.Context, req *sdk.GetPromptRequest) (*sdk.GetPromptResult, error) {
			return &sdk.GetPromptResult{Messages: []*sdk.PromptMessage{{Role: "user", Content: &sdk.TextContent{Text: "Summarize " + req.Params.Arguments["page"]}}}}, nil
		})
	return newOpenUpstream(t, s).URL
}

// surface is what one user sees of the docs server through /mcp.
type surface struct{ tool, resource, template, prompt bool }

func docsSurface(t *testing.T, cs *sdk.ClientSession) surface {
	t.Helper()
	ctx := t.Context()
	var s surface
	s.tool = contains(toolNames(t, cs), "handbook.search")
	rs, err := cs.ListResources(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs.Resources {
		s.resource = s.resource || r.URI == "mcpgw://handbook/docs://index"
	}
	ts, err := cs.ListResourceTemplates(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range ts.ResourceTemplates {
		s.template = s.template || r.URITemplate == "mcpgw://handbook/docs://page/{slug}"
	}
	ps, err := cs.ListPrompts(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range ps.Prompts {
		s.prompt = s.prompt || p.Name == "handbook.summarize"
	}
	return s
}

// TestE2EPluginsPrivateVsPublishedVisibility checks, in one scenario,
// who sees a server's tools, resources, templates and prompts (task
// w2cd39bc): private → only the owner; published to a role → that role's
// users get the resources, templates and prompts at once (server-level
// policy) and the tool once the role grants it, including a templated
// read through the published server; the owner keeps everything (task
// fekckdrt); a user of another role sees nothing;
// unpublishing restores the private view.
func TestE2EPluginsPrivateVsPublishedVisibility(t *testing.T) {
	w := newWorld(t, options{federation: true})
	ctx := t.Context()
	w.allowLoopback()
	docsURL := newDocsUpstream(t)
	carol := w.signIn("carol-subject", "Carol") // member, like alice; not the owner
	id := w.addServer(w.alice, url.Values{"name": {"handbook"}, "url_mode": {"https"}, "url": {docsURL},
		"auth_kind": {"none"}, "credential_mode": {"per_user"}})
	review := w.refresh(w.alice, id)
	if !strings.Contains(review, "docs://index") || !strings.Contains(review, "docs://page/{slug}") || !strings.Contains(review, "summarize") {
		t.Errorf("review lacks the resource, template or prompt:\n%s", snippet(review))
	}
	w.approve(w.alice, id, review, "search")

	all, none := surface{true, true, true, true}, surface{}
	check := func(step string, want map[string]surface, clients map[string]*sdk.ClientSession) {
		t.Helper()
		for name, cs := range clients {
			if got := docsSurface(t, cs); got != want[name] {
				t.Errorf("%s: %s sees %+v, want %+v", step, name, got, want[name])
			}
		}
	}
	clients := func() map[string]*sdk.ClientSession {
		return map[string]*sdk.ClientSession{"alice": w.client(w.alice), "bob": w.client(w.bob), "carol": w.client(carol)}
	}

	// 1. Private: only the owner.
	cs := clients()
	check("private", map[string]surface{"alice": all, "bob": none, "carol": none}, cs)
	_, err := cs["bob"].ReadResource(ctx, &sdk.ReadResourceParams{URI: "mcpgw://handbook/docs://page/intro"})
	if we := rpcError(t, err, mcp.CodeInvalidParams); we.Message != "Resource not found" {
		t.Errorf("bob's templated read of a private server: %+v", we)
	}
	_, err = cs["bob"].GetPrompt(ctx, &sdk.GetPromptParams{Name: "handbook.summarize", Arguments: map[string]string{"page": "x"}})
	_ = rpcError(t, err, mcp.CodeInvalidParams)
	_, err = w.call(cs["bob"], "handbook.search", map[string]any{"q": "x"})
	_ = rpcError(t, err, mcp.CodeToolNotFound)

	// 2. Published to the restricted role (bob), no tool grant yet.
	mustRedirect(t, "publish", w.submit(w.admin, "/admin/servers/"+id+"/publish", url.Values{"roles": {w.roleID(roleRestricted)}}),
		"/admin/servers/"+id+"?done=")
	cs = clients()
	resourcesOnly := surface{resource: true, template: true, prompt: true}
	check("published, not granted", map[string]surface{"alice": all, "bob": resourcesOnly, "carol": none}, cs)
	page, err := cs["bob"].ReadResource(ctx, &sdk.ReadResourceParams{URI: "mcpgw://handbook/docs://page/intro"})
	if err != nil || len(page.Contents) != 1 || page.Contents[0].Text != "page intro" || page.Contents[0].URI != "mcpgw://handbook/docs://page/intro" {
		t.Fatalf("bob's templated read through the published server = %+v, %v", page, err)
	}
	got, err := cs["bob"].GetPrompt(ctx, &sdk.GetPromptParams{Name: "handbook.summarize", Arguments: map[string]string{"page": "intro"}})
	if err != nil || len(got.Messages) != 1 || got.Messages[0].Content.(*sdk.TextContent).Text != "Summarize intro" {
		t.Fatalf("bob's prompt = %+v, %v", got, err)
	}
	_, err = cs["carol"].ReadResource(ctx, &sdk.ReadResourceParams{URI: "mcpgw://handbook/docs://index"})
	_ = rpcError(t, err, mcp.CodeInvalidParams)

	// 3. The role grants the tool.
	w.grant(roleRestricted, policy.ToolRule{App: "handbook", Tool: "search", Outcome: policy.OutcomeAllow})
	cs = clients()
	check("published, granted", map[string]surface{"alice": all, "bob": all, "carol": none}, cs)
	if got := w.toolText(cs["bob"], "handbook.search", map[string]any{"q": "tunnels"}); got != "docs about tunnels" {
		t.Errorf("bob's call = %q", got)
	}

	// 4. Unpublished: private again.
	mustRedirect(t, "unpublish", w.submit(w.admin, "/admin/servers/"+id+"/unpublish", url.Values{}), "/admin/servers/"+id+"?done=")
	cs = clients()
	check("unpublished", map[string]surface{"alice": all, "bob": none, "carol": none}, cs)
	if got := w.toolText(cs["alice"], "handbook.search", map[string]any{"q": "x"}); got != "docs about x" {
		t.Errorf("alice after unpublish = %q", got)
	}
}
