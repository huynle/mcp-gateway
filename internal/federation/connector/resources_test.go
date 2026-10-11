package connector

import (
	"context"
	"errors"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/federation/auth"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// addResources gives the test upstream two resources (text and blob), a
// template and a prompt; the snapshot the fixture approves pins them.
func addResources(s *sdk.Server) {
	s.AddResource(&sdk.Resource{URI: "notes://readme", Name: "readme", Title: "Readme", Description: "The\u202e readme", MIMEType: "text/markdown"},
		func(_ context.Context, req *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error) {
			return &sdk.ReadResourceResult{Contents: []*sdk.ResourceContents{{URI: req.Params.URI, MIMEType: "text/markdown", Text: "# Readme"}}}, nil
		})
	s.AddResource(&sdk.Resource{URI: "notes://logo", Name: "logo", MIMEType: "image/png"},
		func(_ context.Context, req *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error) {
			return &sdk.ReadResourceResult{Contents: []*sdk.ResourceContents{{URI: req.Params.URI, MIMEType: "image/png", Blob: []byte{0x89, 'P', 'N', 'G'}}}}, nil
		})
	s.AddResourceTemplate(&sdk.ResourceTemplate{URITemplate: "notes://note/{id}", Name: "note", Description: "One note"},
		func(_ context.Context, req *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error) {
			id := strings.TrimPrefix(req.Params.URI, "notes://note/")
			return &sdk.ReadResourceResult{Contents: []*sdk.ResourceContents{{URI: req.Params.URI, MIMEType: "text/plain", Text: "note " + id}}}, nil
		})
	s.AddPrompt(&sdk.Prompt{Name: "summarize", Title: "Summarize", Description: "Summarize a topic", Arguments: []*sdk.PromptArgument{{Name: "topic", Required: true}}},
		func(_ context.Context, req *sdk.GetPromptRequest) (*sdk.GetPromptResult, error) {
			return &sdk.GetPromptResult{Description: "summary", Messages: []*sdk.PromptMessage{
				{Role: "user", Content: &sdk.TextContent{Text: "Summarize " + req.Params.Arguments["topic"]}},
			}}, nil
		})
}

// admits records every Admit call.
type admits struct{ got []mcp.Access }

func (a *admits) hook() mcp.Admit {
	return func(_ context.Context, acc mcp.Access) error {
		a.got = append(a.got, acc)
		return nil
	}
}

func principal(user string) *tokens.Principal {
	return &tokens.Principal{UserID: user, TokenID: "tok-" + user}
}

func errClass(err error) string {
	var te *mcp.ToolError
	if errors.As(err, &te) {
		return te.Class()
	}
	var ce mcp.ClassedError
	if errors.As(err, &ce) {
		return ce.ErrorClass()
	}
	if err != nil {
		return "other:" + err.Error()
	}
	return ""
}

func TestResourceProviderListsApprovedSnapshotForVisibleServersOnly(t *testing.T) {
	f := newFixture(t)
	rp := f.m.ResourceProvider()
	ctx := t.Context()

	rs, err := rp.ListResources(ctx, principal(alice))
	if err != nil {
		t.Fatal(err)
	}
	byURI := map[string]*sdk.Resource{}
	for _, r := range rs {
		byURI[r.URI] = r
	}
	readme := byURI["mcpgw://notes/notes://readme"]
	if len(rs) != 2 || readme == nil || byURI["mcpgw://notes/notes://logo"] == nil {
		t.Fatalf("alice's resources = %v", byURI)
	}
	if readme.Name != "notes.readme" || readme.Title != "[notes] Readme" || readme.Description != "[notes] The readme" || readme.MIMEType != "text/markdown" {
		t.Errorf("readme = %+v", readme)
	}
	if logo := byURI["mcpgw://notes/notes://logo"]; logo.Title != "[notes] logo" {
		t.Errorf("logo title = %q (the name stands in for a missing title)", logo.Title)
	}
	ts, err := rp.ListResourceTemplates(ctx, principal(alice))
	if err != nil || len(ts) != 1 || ts[0].URITemplate != "mcpgw://notes/notes://note/{id}" || ts[0].Name != "notes.note" || ts[0].Description != "[notes] One note" {
		t.Fatalf("templates = %+v, %v", ts, err)
	}
	ps, err := rp.ListPrompts(ctx, principal(alice))
	if err != nil || len(ps) != 1 || ps[0].Name != "notes.summarize" || ps[0].Title != "[notes] Summarize" ||
		ps[0].Description != "[notes] Summarize a topic" || len(ps[0].Arguments) != 1 || ps[0].Arguments[0].Name != "topic" || !ps[0].Arguments[0].Required {
		t.Fatalf("prompts = %+v, %v", ps, err)
	}

	// Bob may not use alice's private server: nothing at all.
	for name, n := range map[string]func() (int, error){
		"resources": func() (int, error) { r, err := rp.ListResources(ctx, principal(bob)); return len(r), err },
		"templates": func() (int, error) { r, err := rp.ListResourceTemplates(ctx, principal(bob)); return len(r), err },
		"prompts":   func() (int, error) { r, err := rp.ListPrompts(ctx, principal(bob)); return len(r), err },
	} {
		if got, err := n(); err != nil || got != 0 {
			t.Errorf("bob's %s = %d, %v; want none", name, got, err)
		}
	}
	// A token narrowed to other apps sees nothing; one naming the server does.
	narrowed := principal(alice)
	narrowed.Scope = tokens.Scope{Apps: []string{"github"}}
	if r, _ := rp.ListResources(ctx, narrowed); len(r) != 0 {
		t.Errorf("token restricted to github lists %d resources", len(r))
	}
	narrowed.Scope = tokens.Scope{Apps: []string{"notes"}, ReadOnly: true}
	if r, _ := rp.ListResources(ctx, narrowed); len(r) != 2 {
		t.Errorf("read-only token for notes lists %d resources, want 2", len(r))
	}
}

func TestResourceProviderSkipsUnsafePromptNames(t *testing.T) {
	f := newFixture(t)
	rec := *f.snaps.records[srvID]
	snap := *rec.Snapshot
	snap.Prompts = append(append([]snapshot.Prompt(nil), snap.Prompts...), snapshot.Prompt{Name: "evil\u202eprompt"}, snapshot.Prompt{Name: ""})
	rec.Snapshot = &snap
	f.snaps.records[srvID] = &rec
	if err := f.m.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	ps, err := f.m.ResourceProvider().ListPrompts(t.Context(), principal(alice))
	if err != nil || len(ps) != 1 || ps[0].Name != "notes.summarize" {
		t.Fatalf("prompts = %+v, %v", ps, err)
	}
}

func TestResourceProviderReadsLiveWithTheCallersCredential(t *testing.T) {
	f := newFixture(t)
	rp := f.m.ResourceProvider()
	a := &admits{}
	f.up.reset()
	res, err := rp.ReadResource(t.Context(), principal(alice), "mcpgw://notes/notes://readme", a.hook())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Contents) != 1 || res.Contents[0].Text != "# Readme" || res.Contents[0].MIMEType != "text/markdown" ||
		res.Contents[0].URI != "mcpgw://notes/notes://readme" {
		t.Fatalf("contents = %+v", res.Contents[0])
	}
	if len(a.got) != 1 || a.got[0].Name != "notes.resources/read" || a.got[0].ResourceIdentity["server"] != "notes" ||
		a.got[0].ResourceIdentity["uri"] != "notes://readme" {
		t.Errorf("admitted = %+v", a.got)
	}
	seen := f.up.seen()
	if len(seen) == 0 {
		t.Fatal("upstream not called")
	}
	for _, h := range seen {
		if h.Get("X-Upstream-Key") != alice+"-key" || h.Get("X-Tenant") != "acme" || h.Get("Authorization") != "" {
			t.Errorf("upstream headers = %v", h)
		}
	}

	// Blob contents keep their bytes and type.
	res, err = rp.ReadResource(t.Context(), principal(alice), "mcpgw://notes/notes://logo", a.hook())
	if err != nil || string(res.Contents[0].Blob) != "\x89PNG" || res.Contents[0].MIMEType != "image/png" {
		t.Fatalf("logo = %+v, %v", res, err)
	}
	// A filled-in template of the approved snapshot.
	res, err = rp.ReadResource(t.Context(), principal(alice), "mcpgw://notes/notes://note/42", a.hook())
	if err != nil || res.Contents[0].Text != "note 42" || res.Contents[0].URI != "mcpgw://notes/notes://note/42" {
		t.Fatalf("templated read = %+v, %v", res, err)
	}
}

func TestResourceProviderRefusesWhatIsNotVisibleOrApproved(t *testing.T) {
	f := newFixture(t)
	// The upstream has a resource the approved snapshot does not.
	f.up.sdk.AddResource(&sdk.Resource{URI: "notes://secret", Name: "secret"},
		func(_ context.Context, req *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error) {
			return &sdk.ReadResourceResult{Contents: []*sdk.ResourceContents{{URI: req.Params.URI, Text: "secret"}}}, nil
		})
	rp := f.m.ResourceProvider()
	ctx := t.Context()
	for _, c := range []struct {
		user, uri string
	}{
		{bob, "mcpgw://notes/notes://readme"},      // not bob's server
		{alice, "mcpgw://notes/notes://secret"},    // not in the approved snapshot
		{alice, "mcpgw://notes/notes://note/42/x"}, // the template does not match
		{alice, "notes://readme"},                  // not a gateway URI
		{alice, "mcpgw://other/notes://readme"},    // no such server
		{alice, "mcpgw://github/github://x"},       // a built-in app is no server
		{"", "mcpgw://notes/notes://readme"},       // nobody
	} {
		a := &admits{}
		f.up.reset()
		_, err := rp.ReadResource(ctx, principal(c.user), c.uri, a.hook())
		if errClass(err) != "resource_not_found" {
			t.Errorf("%s reading %s: %v (%s), want resource_not_found", c.user, c.uri, err, errClass(err))
		}
		var te *mcp.ToolError
		if errors.As(err, &te) && te.Data["uri"] != c.uri {
			t.Errorf("not-found data = %v, want the requested uri", te.Data)
		}
		if len(a.got) != 0 || len(f.up.seen()) != 0 {
			t.Errorf("%s reading %s: admitted %v, upstream calls %d", c.user, c.uri, a.got, len(f.up.seen()))
		}
	}
	// A narrowed token is refused like a hidden server.
	narrowed := principal(alice)
	narrowed.Scope = tokens.Scope{Apps: []string{"github"}}
	if _, err := rp.ReadResource(ctx, narrowed, "mcpgw://notes/notes://readme", (&admits{}).hook()); errClass(err) != "resource_not_found" {
		t.Errorf("narrowed token read: %v", err)
	}
	// A server disabled since the last load.
	s, _ := f.st.GetServer(ctx, srvID)
	s.Status = store.MCPServerDisabled
	f.st.put(*s)
	if _, err := rp.ReadResource(ctx, principal(alice), "mcpgw://notes/notes://readme", (&admits{}).hook()); errClass(err) != "resource_not_found" {
		t.Errorf("disabled server read: %v", err)
	}
}

func TestResourceProviderAdmitRefusalStopsBeforeUpstream(t *testing.T) {
	f := newFixture(t)
	f.up.reset()
	refuse := mcp.NewToolError(mcp.CodeRateLimited, "rate_limited", "slow down")
	_, err := f.m.ResourceProvider().ReadResource(t.Context(), principal(alice), "mcpgw://notes/notes://readme",
		func(context.Context, mcp.Access) error { return refuse })
	if !errors.Is(err, refuse) {
		t.Fatalf("err = %v, want the admit error as is", err)
	}
	if len(f.up.seen()) != 0 {
		t.Error("upstream called after admit refused")
	}
}

func TestResourceProviderUpstreamAndCredentialErrorsAreClassLevel(t *testing.T) {
	f := newFixture(t)
	rp := f.m.ResourceProvider()
	ctx := t.Context()
	f.creds.errs[alice] = auth.ErrNeedsReconnect
	_, err := rp.ReadResource(ctx, principal(alice), "mcpgw://notes/notes://readme", (&admits{}).hook())
	if errClass(err) != "needs_reconnect" || !strings.Contains(err.Error(), "https://gw.example/servers/"+srvID) {
		t.Errorf("needs reconnect: %v (%s)", err, errClass(err))
	}
	_, err = rp.GetPrompt(ctx, principal(alice), "notes.summarize", nil, (&admits{}).hook())
	if errClass(err) != "needs_reconnect" {
		t.Errorf("prompt needs reconnect: %v", err)
	}
	delete(f.creds.errs, alice)

	// The upstream is gone: unreachable, never its text or URL.
	s, _ := f.st.GetServer(ctx, srvID)
	s.URL = "http://127.0.0.1:1/mcp"
	f.st.put(*s)
	_, err = rp.ReadResource(ctx, principal(alice), "mcpgw://notes/notes://readme", (&admits{}).hook())
	if errClass(err) != "upstream_unreachable" || strings.Contains(err.Error(), "127.0.0.1") {
		t.Errorf("unreachable: %v (%s)", err, errClass(err))
	}
	if errors.Is(err, connectors.ErrOutcomeUnknown) {
		t.Error("a read is never an unknown outcome")
	}
}

func TestResourceProviderGetsApprovedPromptsWithArguments(t *testing.T) {
	f := newFixture(t)
	rp := f.m.ResourceProvider()
	a := &admits{}
	res, err := rp.GetPrompt(t.Context(), principal(alice), "notes.summarize", map[string]string{"topic": "plans"}, a.hook())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Messages) != 1 || res.Messages[0].Content.(*sdk.TextContent).Text != "Summarize plans" {
		t.Fatalf("prompt = %+v", res)
	}
	if len(a.got) != 1 || a.got[0].Name != "notes.prompts/get" || a.got[0].ResourceIdentity["prompt"] != "summarize" || a.got[0].ResourceIdentity["server"] != "notes" {
		t.Errorf("admitted = %+v", a.got)
	}
	f.up.sdk.AddPrompt(&sdk.Prompt{Name: "unreviewed"}, func(context.Context, *sdk.GetPromptRequest) (*sdk.GetPromptResult, error) {
		return &sdk.GetPromptResult{}, nil
	})
	for _, c := range []struct{ user, name string }{
		{bob, "notes.summarize"},
		{alice, "notes.unreviewed"},
		{alice, "summarize"},
		{alice, "other.summarize"},
	} {
		a := &admits{}
		_, err := rp.GetPrompt(t.Context(), principal(c.user), c.name, nil, a.hook())
		if errClass(err) != "prompt_not_found" || len(a.got) != 0 {
			t.Errorf("%s getting %s: %v, admitted %v", c.user, c.name, err, a.got)
		}
	}
}

// A resource the approved snapshot lists but the upstream no longer has:
// the upstream's JSON-RPC error is a class, never its text.
func TestResourceProviderUpstreamRefusalIsClassLevel(t *testing.T) {
	f := newFixture(t)
	rec := *f.snaps.records[srvID]
	snap := *rec.Snapshot
	snap.Resources = append(append([]snapshot.Resource(nil), snap.Resources...), snapshot.Resource{URI: "notes://gone", Name: "gone"})
	rec.Snapshot = &snap
	f.snaps.records[srvID] = &rec
	if err := f.m.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	_, err := f.m.ResourceProvider().ReadResource(t.Context(), principal(alice), "mcpgw://notes/notes://gone", (&admits{}).hook())
	if errClass(err) != "upstream_refused" || err.Error() != "notes: the server refused the request" {
		t.Errorf("err = %v (%s)", err, errClass(err))
	}
}
