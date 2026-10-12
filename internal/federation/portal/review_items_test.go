package portal

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/store"
)

// fakePolicy permits everything but the denied "<user> <app>.<action>".
type fakePolicy struct {
	mu     sync.Mutex
	denied map[string]bool
}

func (p *fakePolicy) Permits(_ context.Context, in policy.Input) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.denied[in.UserID+" "+in.Tool.FullName()], nil
}

func itemsSnapshot() *snapshot.Snapshot {
	return &snapshot.Snapshot{
		Tools:             []snapshot.Tool{{Name: "search", Annotations: &snapshot.Annotations{ReadOnlyHint: true}}},
		Resources:         []snapshot.Resource{{URI: "docs://a", Name: "a", Description: "First doc. More text."}, {URI: "docs://b", Name: "b"}},
		ResourceTemplates: []snapshot.ResourceTemplate{{URITemplate: "docs://page/{slug}", Name: "page"}},
		Prompts:           []snapshot.Prompt{{Name: "summarize", Description: "Summarize"}},
	}
}

// The review page lists resources, templates and prompts in their own
// groups with the tools' compact rows (task bdb5zcud); new ones start
// unchecked.
func TestReviewPageListsResourcesTemplatesAndPrompts(t *testing.T) {
	e := newEnv(t)
	s := e.st.add(store.MCPServer{Name: "docs", URL: "https://docs.example/mcp", OwnerUserID: alice, AuthKind: store.MCPAuthNone})
	e.snap.pending(s.ID, itemsSnapshot())
	r := e.get("/servers/"+s.ID+"/review", alice)
	if r.code != 200 {
		t.Fatalf("review %d", r.code)
	}
	mustContain(t, r.body,
		`data-group="resources"`, `data-group="resource-templates"`, `data-group="prompts"`,
		`name="enable_resource" value="0"`, `name="enable_resource" value="1"`, `name="enable_template" value="0"`, `name="enable_prompt" value="0"`,
		`aria-label="Enable docs://a"`, `aria-label="Enable summarize"`, `<span class="tool-summary">First doc.</span>`,
		"0 of 5 selected", `data-item`)
	mustNotContain(t, r.body, `name="enable_resource" value="0" checked`)
}

func TestReviewFormDecidesResourcesTemplatesAndPrompts(t *testing.T) {
	e := newEnv(t)
	s := e.st.add(store.MCPServer{Name: "docs", URL: "https://docs.example/mcp", OwnerUserID: alice, AuthKind: store.MCPAuthNone})
	e.snap.pending(s.ID, itemsSnapshot())
	r := e.post("/servers/"+s.ID+"/review", alice, url.Values{"version": {"1"}, "action": {"approve"},
		"enable": {"0"}, "enable_resource": {"1"}, "enable_prompt": {"0"}})
	if r.code != 303 {
		t.Fatalf("approve: %d %s", r.code, r.body)
	}
	d := e.snap.approvals[0].d
	if d.Resources["docs://a"] || !d.Resources["docs://b"] || len(d.Resources) != 2 {
		t.Errorf("resources = %v", d.Resources)
	}
	if v, ok := d.ResourceTemplates["docs://page/{slug}"]; !ok || v {
		t.Errorf("templates = %v", d.ResourceTemplates)
	}
	if !d.Prompts["summarize"] {
		t.Errorf("prompts = %v", d.Prompts)
	}

	// approve_all enables every item too.
	e.snap.approvals = nil
	r = e.post("/servers/"+s.ID+"/review", alice, url.Values{"version": {"1"}, "action": {"approve_all"}})
	if r.code != 303 {
		t.Fatalf("approve all: %d %s", r.code, r.body)
	}
	d = e.snap.approvals[0].d
	if !d.Resources["docs://a"] || !d.Resources["docs://b"] || !d.ResourceTemplates["docs://page/{slug}"] || !d.Prompts["summarize"] {
		t.Errorf("approve_all decisions = %+v", d)
	}
}

// An approved snapshot from before the toggles (no content review) shows
// its unchanged items enabled and pre-checked; a content review that
// disables an item leaves it unchecked.
func TestReviewPrechecksLegacyAndEnabledItems(t *testing.T) {
	e := newEnv(t)
	s := e.st.add(store.MCPServer{Name: "docs", URL: "https://docs.example/mcp", OwnerUserID: alice, AuthKind: store.MCPAuthNone})
	e.snap.approved(s.ID, itemsSnapshot(), snapshot.Review{"search": {Enabled: true, Kind: snapshot.KindRead}})
	r := e.get("/servers/"+s.ID+"/review", alice)
	mustContain(t, r.body, `name="enable_resource" value="0" checked`, `name="enable_resource" value="1" checked`,
		`name="enable_template" value="0" checked`, `name="enable_prompt" value="0" checked`, "5 of 5 selected")

	e.snap.current[s.ID].Content = &snapshot.ContentReview{
		Resources: map[string]snapshot.ItemReview{"docs://a": {Enabled: true}},
		Prompts:   map[string]snapshot.ItemReview{"summarize": {Enabled: false}},
	}
	r = e.get("/servers/"+s.ID+"/review", alice)
	mustContain(t, r.body, `name="enable_resource" value="0" checked`, "2 of 5 selected")
	mustNotContain(t, r.body, `name="enable_resource" value="1" checked`, `name="enable_template" value="0" checked`, `name="enable_prompt" value="0" checked`)
}

// The browse pages show and serve only enabled items, and only when the
// policy grants the per-server action.
func TestBrowseShowsOnlyEnabledPermittedItems(t *testing.T) {
	e, s := browseEnv(t)
	e.snap.current[s.ID].Content = &snapshot.ContentReview{
		Resources: map[string]snapshot.ItemReview{"file:///a.txt": {Enabled: true}},
		Prompts:   map[string]snapshot.ItemReview{},
	}
	r := e.get("/servers/"+s.ID+"/resources", alice)
	mustContain(t, r.body, "file:///a.txt")
	mustNotContain(t, r.body, "blob://img", "file:///{path}", `href="/servers/`+s.ID+`/prompts/summarize"`)
	if r := e.post("/servers/"+s.ID+"/resources/read", alice, url.Values{"uri": {"blob://img"}}); r.code != 422 {
		t.Errorf("read of a disabled resource = %d, want 422", r.code)
	}
	if r := e.get("/servers/"+s.ID+"/prompts/summarize", alice); r.code != 404 {
		t.Errorf("disabled prompt page = %d, want 404", r.code)
	}

	// Policy: resources not granted.
	e.pol.denied[alice+" notes.resources/read"] = true
	r = e.get("/servers/"+s.ID+"/resources", alice)
	if strings.Contains(r.body, "file:///a.txt") {
		t.Error("resources listed without the policy grant")
	}
	if r := e.post("/servers/"+s.ID+"/resources/read", alice, url.Values{"uri": {"file:///a.txt"}}); r.code != 422 {
		t.Errorf("read without the grant = %d, want 422", r.code)
	}
	e.snap.current[s.ID].Content = nil
	e.pol.denied[alice+" notes.prompts/get"] = true
	if r := e.get("/servers/"+s.ID+"/prompts/summarize", alice); r.code != 404 {
		t.Errorf("prompt page without the grant = %d, want 404", r.code)
	}
}
