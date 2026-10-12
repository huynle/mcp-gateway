package connector

import (
	"context"
	"errors"
	"sync"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// fakePolicy permits every per-server action except the denied
// "<user> <app>.<action>" keys, and records what it was asked.
type fakePolicy struct {
	mu     sync.Mutex
	denied map[string]bool
	err    error
	asked  []policy.Input
}

func (p *fakePolicy) Permits(_ context.Context, in policy.Input) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.asked = append(p.asked, in)
	if p.err != nil {
		return false, p.err
	}
	return !p.denied[in.UserID+" "+in.Tool.FullName()], nil
}

func (p *fakePolicy) deny(user, action string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.denied[user+" "+action] = true
}

// setContent replaces the approved snapshot's content review and reloads.
func (f *fixture) setContent(t *testing.T, c *snapshot.ContentReview) {
	t.Helper()
	f.snaps.mu.Lock()
	rec := *f.snaps.records[srvID]
	rec.Content = c
	f.snaps.records[srvID] = &rec
	f.snaps.mu.Unlock()
	if err := f.m.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func listed(t *testing.T, rp interface {
	ListResources(context.Context, *tokens.Principal) ([]*sdk.Resource, error)
	ListResourceTemplates(context.Context, *tokens.Principal) ([]*sdk.ResourceTemplate, error)
	ListPrompts(context.Context, *tokens.Principal) ([]*sdk.Prompt, error)
}, p *tokens.Principal) (res, tpl, pr []string) {
	t.Helper()
	rs, err := rp.ListResources(t.Context(), p)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs {
		res = append(res, r.URI)
	}
	ts, err := rp.ListResourceTemplates(t.Context(), p)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range ts {
		tpl = append(tpl, x.URITemplate)
	}
	ps, err := rp.ListPrompts(t.Context(), p)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range ps {
		pr = append(pr, x.Name)
	}
	return res, tpl, pr
}

// Items the review disabled are neither listed nor served: reading or
// getting one answers like not found, before admit and upstream (task
// bdb5zcud).
func TestResourceProviderServesOnlyEnabledItems(t *testing.T) {
	f := newFixture(t)
	f.setContent(t, &snapshot.ContentReview{
		Resources:         map[string]snapshot.ItemReview{"notes://readme": {Enabled: true}, "notes://logo": {Enabled: false}},
		ResourceTemplates: map[string]snapshot.ItemReview{"notes://note/{id}": {Enabled: false}},
		Prompts:           map[string]snapshot.ItemReview{},
	})
	rp := f.m.ResourceProvider(f.pol)
	res, tpl, pr := listed(t, rp, principal(alice))
	if len(res) != 1 || res[0] != "mcpgw://notes/notes://readme" || len(tpl) != 0 || len(pr) != 0 {
		t.Fatalf("listed = %v %v %v", res, tpl, pr)
	}
	for _, uri := range []string{"mcpgw://notes/notes://logo", "mcpgw://notes/notes://note/42"} {
		a := &admits{}
		f.up.reset()
		if _, err := rp.ReadResource(t.Context(), principal(alice), uri, a.hook()); errClass(err) != "resource_not_found" {
			t.Errorf("disabled %s: %v", uri, err)
		}
		if len(a.got) != 0 || len(f.up.seen()) != 0 {
			t.Errorf("disabled %s reached admit (%v) or the upstream (%d)", uri, a.got, len(f.up.seen()))
		}
	}
	if _, err := rp.GetPrompt(t.Context(), principal(alice), "notes.summarize", map[string]string{"topic": "x"}, (&admits{}).hook()); errClass(err) != "prompt_not_found" {
		t.Errorf("disabled prompt: %v", err)
	}
	if _, err := rp.ReadResource(t.Context(), principal(alice), "mcpgw://notes/notes://readme", (&admits{}).hook()); err != nil {
		t.Errorf("enabled resource: %v", err)
	}
}

// A snapshot approved before the toggles (nil content review) serves
// everything it lists: the live Brain server keeps working unreviewed.
func TestResourceProviderLegacySnapshotServesEverything(t *testing.T) {
	f := newFixture(t)
	f.setContent(t, nil)
	res, tpl, pr := listed(t, f.m.ResourceProvider(f.pol), principal(alice))
	if len(res) != 2 || len(tpl) != 1 || len(pr) != 1 {
		t.Fatalf("legacy snapshot listed = %v %v %v", res, tpl, pr)
	}
	if _, err := f.m.ResourceProvider(f.pol).ReadResource(t.Context(), principal(alice), "mcpgw://notes/notes://note/7", (&admits{}).hook()); err != nil {
		t.Errorf("legacy templated read: %v", err)
	}
}

// Policy decides resources/read and prompts/get per server: without the
// grant nothing is listed and reads answer not found.
func TestResourceProviderAsksPolicyPerServerAction(t *testing.T) {
	f := newFixture(t)
	rp := f.m.ResourceProvider(f.pol)
	p := principal(alice)
	p.Scope = tokens.Scope{ReadOnly: true}
	f.pol.deny(alice, "notes.resources/read")
	res, tpl, pr := listed(t, rp, p)
	if len(res) != 0 || len(tpl) != 0 || len(pr) != 1 {
		t.Fatalf("resources denied: listed = %v %v %v", res, tpl, pr)
	}
	a := &admits{}
	if _, err := rp.ReadResource(t.Context(), p, "mcpgw://notes/notes://readme", a.hook()); errClass(err) != "resource_not_found" || len(a.got) != 0 {
		t.Errorf("denied read: %v, admitted %v", err, a.got)
	}
	if _, err := rp.GetPrompt(t.Context(), p, "notes.summarize", map[string]string{"topic": "x"}, (&admits{}).hook()); err != nil {
		t.Errorf("prompt still granted: %v", err)
	}
	var sawScope bool
	for _, in := range f.pol.asked {
		if in.UserID != alice || in.Tool.App != "notes" || !policy.IsServerAccessTool(in.Tool.Name) {
			t.Errorf("policy asked %+v", in)
		}
		sawScope = sawScope || (in.TokenScope.ReadOnly && in.TokenID == p.TokenID)
	}
	if !sawScope {
		t.Error("policy not given the token")
	}
	f.pol.deny(alice, "notes.prompts/get")
	if _, err := rp.GetPrompt(t.Context(), p, "notes.summarize", nil, (&admits{}).hook()); errClass(err) != "prompt_not_found" {
		t.Errorf("denied prompt: %v", err)
	}

	// A policy failure fails closed; so does a missing policy.
	f.pol.err = errors.New("db down")
	if res, _, pr := listed(t, rp, principal(alice)); len(res)+len(pr) != 0 {
		t.Errorf("policy error lists %v %v", res, pr)
	}
	if res, tpl, pr := listed(t, f.m.ResourceProvider(nil), principal(alice)); len(res)+len(tpl)+len(pr) != 0 {
		t.Errorf("nil policy lists %v %v %v", res, tpl, pr)
	}
}

// Resource links and embedded resources in a prompt result name gateway
// URIs (mcpgw://<server>/<upstream URI>), like resources/read contents.
func TestRewritePromptResult(t *testing.T) {
	res := &sdk.GetPromptResult{Messages: []*sdk.PromptMessage{
		{Role: "user", Content: &sdk.TextContent{Text: "see notes://a"}},
		{Role: "user", Content: &sdk.ResourceLink{URI: "notes://a", Name: "a"}},
		{Role: "assistant", Content: &sdk.EmbeddedResource{Resource: &sdk.ResourceContents{URI: "notes://b?x=1#y", Text: "b"}}},
		{Role: "user", Content: &sdk.ResourceLink{URI: "", Name: "empty"}},
		{Role: "user", Content: &sdk.EmbeddedResource{}},
		nil,
	}}
	rewritePromptResult("notes", res)
	if got := res.Messages[0].Content.(*sdk.TextContent).Text; got != "see notes://a" {
		t.Errorf("text changed: %q", got)
	}
	if got := res.Messages[1].Content.(*sdk.ResourceLink).URI; got != "mcpgw://notes/notes://a" {
		t.Errorf("link = %q", got)
	}
	if got := res.Messages[2].Content.(*sdk.EmbeddedResource).Resource.URI; got != "mcpgw://notes/notes://b?x=1#y" {
		t.Errorf("embedded = %q", got)
	}
	if got := res.Messages[3].Content.(*sdk.ResourceLink).URI; got != "" {
		t.Errorf("empty link = %q", got)
	}
	rewritePromptResult("notes", nil)
}

func TestResourceProviderPromptResultLinksAreGatewayURIs(t *testing.T) {
	f := newFixture(t)
	f.up.sdk.AddPrompt(&sdk.Prompt{Name: "linked"}, func(context.Context, *sdk.GetPromptRequest) (*sdk.GetPromptResult, error) {
		return &sdk.GetPromptResult{Messages: []*sdk.PromptMessage{
			{Role: "user", Content: &sdk.ResourceLink{URI: "notes://readme", Name: "readme"}},
			{Role: "user", Content: &sdk.EmbeddedResource{Resource: &sdk.ResourceContents{URI: "notes://logo", MIMEType: "text/plain", Text: "x"}}},
		}}, nil
	})
	f.snaps.mu.Lock()
	rec := *f.snaps.records[srvID]
	snap := *rec.Snapshot
	snap.Prompts = append(append([]snapshot.Prompt(nil), snap.Prompts...), snapshot.Prompt{Name: "linked"})
	rec.Snapshot = &snap
	f.snaps.records[srvID] = &rec
	f.snaps.mu.Unlock()
	if err := f.m.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	res, err := f.m.ResourceProvider(f.pol).GetPrompt(t.Context(), principal(alice), "notes.linked", nil, (&admits{}).hook())
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Messages[0].Content.(*sdk.ResourceLink).URI; got != "mcpgw://notes/notes://readme" {
		t.Errorf("link = %q", got)
	}
	if got := res.Messages[1].Content.(*sdk.EmbeddedResource).Resource.URI; got != "mcpgw://notes/notes://logo" {
		t.Errorf("embedded = %q", got)
	}
}
