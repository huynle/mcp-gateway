//go:build integration || e2e

package e2e

import (
	"context"
	"net/url"
	"slices"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/mcp"
)

// newLinkedDocsUpstream is a docs server (search, docs://index,
// docs://private, docs://page/{slug}, summarize) whose prompt points at
// resources: a resource link and an embedded resource.
func newLinkedDocsUpstream(t *testing.T) string {
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
	s.AddResource(&sdk.Resource{URI: "docs://private", Name: "private", MIMEType: "text/plain"},
		func(_ context.Context, req *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error) {
			return &sdk.ReadResourceResult{Contents: []*sdk.ResourceContents{{URI: req.Params.URI, MIMEType: "text/plain", Text: "private"}}}, nil
		})
	s.AddResourceTemplate(&sdk.ResourceTemplate{URITemplate: "docs://page/{slug}", Name: "page"},
		func(_ context.Context, req *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error) {
			return &sdk.ReadResourceResult{Contents: []*sdk.ResourceContents{{URI: req.Params.URI, MIMEType: "text/plain", Text: "page " + strings.TrimPrefix(req.Params.URI, "docs://page/")}}}, nil
		})
	s.AddPrompt(&sdk.Prompt{Name: "summarize", Description: "Summarize the index"},
		func(context.Context, *sdk.GetPromptRequest) (*sdk.GetPromptResult, error) {
			return &sdk.GetPromptResult{Messages: []*sdk.PromptMessage{
				{Role: "user", Content: &sdk.TextContent{Text: "Summarize this:"}},
				{Role: "user", Content: &sdk.ResourceLink{URI: "docs://index", Name: "index"}},
				{Role: "user", Content: &sdk.EmbeddedResource{Resource: &sdk.ResourceContents{URI: "docs://page/intro", MIMEType: "text/plain", Text: "page intro"}}},
			}}, nil
		})
	return newOpenUpstream(t, s).URL
}

// listedKeys is what a client sees of the resources, templates and
// prompts through /mcp (resources sorted).
func listedKeys(t *testing.T, cs *sdk.ClientSession) (res, tpl, prm []string) {
	t.Helper()
	ctx := t.Context()
	rs, err := cs.ListResources(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs.Resources {
		res = append(res, r.URI)
	}
	ts, err := cs.ListResourceTemplates(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range ts.ResourceTemplates {
		tpl = append(tpl, x.URITemplate)
	}
	ps, err := cs.ListPrompts(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range ps.Prompts {
		prm = append(prm, p.Name)
	}
	slices.Sort(res)
	return res, tpl, prm
}

// TestE2EPluginsResourceReviewAndGrants (Brain task bdb5zcud): the review
// page has toggles for resources, templates and prompts; only enabled
// ones are listed and served on /mcp (a disabled one answers "not found");
// approve_all enables them all; a snapshot approved before the toggles
// (legacy review column) keeps serving everything without a new review;
// prompt results name resources by gateway URI.
func TestE2EPluginsResourceReviewAndGrants(t *testing.T) {
	w := newWorld(t, options{federation: true})
	ctx := t.Context()
	w.allowLoopback()
	id := w.addServer(w.alice, url.Values{"name": {"manual"}, "url_mode": {"https"}, "url": {newLinkedDocsUpstream(t)},
		"auth_kind": {"none"}, "credential_mode": {"per_user"}})
	review := w.refresh(w.alice, id)
	items, checked := reviewItems(review)
	if len(items) != 4 || len(checked) != 0 {
		t.Fatalf("review page items = %v, pre-checked %v (want 4, none checked)", items, checked)
	}
	for _, want := range []string{`data-group="resources"`, `data-group="resource-templates"`, `data-group="prompts"`} {
		if !strings.Contains(review, want) {
			t.Errorf("review page lacks %s", want)
		}
	}

	// 1. Only the index resource and the prompt enabled.
	w.approve(w.alice, id, review, "search", "docs://index", "summarize")
	alice := w.client(w.alice)
	res, tpl, prm := listedKeys(t, alice)
	if !slices.Equal(res, []string{"mcpgw://manual/docs://index"}) || len(tpl) != 0 || !slices.Equal(prm, []string{"manual.summarize"}) {
		t.Fatalf("listed after a partial review = %v %v %v", res, tpl, prm)
	}
	for _, uri := range []string{"mcpgw://manual/docs://private", "mcpgw://manual/docs://page/intro"} {
		_, err := alice.ReadResource(ctx, &sdk.ReadResourceParams{URI: uri})
		if we := rpcError(t, err, mcp.CodeInvalidParams); we.Message != "Resource not found" {
			t.Errorf("read of disabled %s: %+v", uri, we)
		}
	}
	if r, err := alice.ReadResource(ctx, &sdk.ReadResourceParams{URI: "mcpgw://manual/docs://index"}); err != nil || r.Contents[0].Text != "the index" {
		t.Errorf("read of the enabled resource = %+v, %v", r, err)
	}

	// 2. Prompt results point at gateway URIs.
	got, err := alice.GetPrompt(ctx, &sdk.GetPromptParams{Name: "manual.summarize"})
	if err != nil || len(got.Messages) != 3 {
		t.Fatalf("prompt = %+v, %v", got, err)
	}
	if link, ok := got.Messages[1].Content.(*sdk.ResourceLink); !ok || link.URI != "mcpgw://manual/docs://index" {
		t.Errorf("resource link = %#v", got.Messages[1].Content)
	}
	if emb, ok := got.Messages[2].Content.(*sdk.EmbeddedResource); !ok || emb.Resource == nil || emb.Resource.URI != "mcpgw://manual/docs://page/intro" {
		t.Errorf("embedded resource = %#v", got.Messages[2].Content)
	}

	// 3. The review page pre-checks what is enabled; approve_all enables
	// the rest.
	review = w.page(w.alice, "/servers/"+id+"/review").body
	if _, checked := reviewItems(review); !slices.Equal(sortedCopy(checked), []string{"docs://index", "summarize"}) {
		t.Errorf("pre-checked items = %v", checked)
	}
	w.approveAll(w.alice, id, review)
	res, tpl, prm = listedKeys(t, alice)
	if len(res) != 2 || len(tpl) != 1 || len(prm) != 1 {
		t.Fatalf("listed after approve_all = %v %v %v", res, tpl, prm)
	}

	// 4. A snapshot approved before the toggles: the review column holds
	// only the flat tool map. Everything stays served, unreviewed.
	w.exec(`UPDATE mcp_server_snapshots SET review = '{"search":{"enabled":true,"kind":"read"}}'::jsonb WHERE server_id = $1 AND status = 'approved'`, id)
	if err := w.fed.Manager.ServerChanged(ctx, id); err != nil {
		t.Fatal(err)
	}
	alice = w.client(w.alice)
	res, tpl, prm = listedKeys(t, alice)
	if len(res) != 2 || len(tpl) != 1 || len(prm) != 1 {
		t.Fatalf("legacy approved snapshot lists %v %v %v, want everything", res, tpl, prm)
	}
	if r, err := alice.ReadResource(ctx, &sdk.ReadResourceParams{URI: "mcpgw://manual/docs://page/legacy"}); err != nil || r.Contents[0].Text != "page legacy" {
		t.Errorf("legacy templated read = %+v, %v", r, err)
	}
	if got := w.toolText(alice, "manual.search", map[string]any{"q": "x"}); got != "docs about x" {
		t.Errorf("legacy tool call = %q", got)
	}
	// Its review page shows the legacy items enabled (pre-checked).
	review = w.page(w.alice, "/servers/"+id+"/review").body
	if _, checked := reviewItems(review); len(checked) != 4 {
		t.Errorf("legacy review page pre-checks %v, want all 4", checked)
	}
}

func sortedCopy(xs []string) []string {
	out := slices.Clone(xs)
	slices.Sort(out)
	return out
}
