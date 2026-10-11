//go:build integration || e2e

package e2e

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/federation/auth"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/store"
)

const (
	wikiAliceKey = "alice-wiki-key-e2e"
	wikiHomeBody = "wiki-home-body-must-not-be-audited"
	wikiTopic    = "zebra-topic-e2e"
)

// wikiUpstream is a user-added MCP server with resources (text and blob),
// a resource template and a prompt behind an API key. It records which
// URIs were read.
type wikiUpstream struct {
	srv   *httptest.Server
	sdk   *sdk.Server
	mu    sync.Mutex
	reads []string
}

func newWikiUpstream(t *testing.T) *wikiUpstream {
	t.Helper()
	u := &wikiUpstream{}
	s := sdk.NewServer(&sdk.Implementation{Name: "wiki", Version: "1"}, nil)
	record := func(uri string) {
		u.mu.Lock()
		u.reads = append(u.reads, uri)
		u.mu.Unlock()
	}
	s.AddResource(&sdk.Resource{URI: "wiki://home", Name: "home", Title: "Home", Description: "The home page", MIMEType: "text/markdown"},
		func(_ context.Context, req *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error) {
			record(req.Params.URI)
			return &sdk.ReadResourceResult{Contents: []*sdk.ResourceContents{{URI: req.Params.URI, MIMEType: "text/markdown", Text: wikiHomeBody}}}, nil
		})
	s.AddResource(&sdk.Resource{URI: "wiki://logo", Name: "logo", MIMEType: "image/png"},
		func(_ context.Context, req *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error) {
			record(req.Params.URI)
			return &sdk.ReadResourceResult{Contents: []*sdk.ResourceContents{{URI: req.Params.URI, MIMEType: "image/png", Blob: []byte{0x89, 'P', 'N', 'G'}}}}, nil
		})
	s.AddResourceTemplate(&sdk.ResourceTemplate{URITemplate: "wiki://page/{name}", Name: "page"},
		func(_ context.Context, req *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error) {
			record(req.Params.URI)
			return &sdk.ReadResourceResult{Contents: []*sdk.ResourceContents{{URI: req.Params.URI, MIMEType: "text/plain", Text: "page " + strings.TrimPrefix(req.Params.URI, "wiki://page/")}}}, nil
		})
	s.AddPrompt(&sdk.Prompt{Name: "draft", Description: "Draft a page", Arguments: []*sdk.PromptArgument{{Name: "topic", Required: true}}},
		func(_ context.Context, req *sdk.GetPromptRequest) (*sdk.GetPromptResult, error) {
			return &sdk.GetPromptResult{Messages: []*sdk.PromptMessage{{Role: "user", Content: &sdk.TextContent{Text: "Draft about " + req.Params.Arguments["topic"]}}}}, nil
		})
	u.sdk = s
	h := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return s }, &sdk.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Wiki-Key") != wikiAliceKey {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *wikiUpstream) readURIs() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.reads...)
}

// TestE2EFederatedResourcesAndPrompts is the resources/prompts acceptance
// scenario (task isdrqc6a), through the official MCP client against the
// in-process gateway: alice's private server's approved resources,
// template and prompt are listed, read and got through /mcp with her
// credential; bob sees none of them and reading alice's URI is "not
// found"; a resource the upstream has but the approved snapshot does not
// is refused without reaching the upstream; audit rows name the server
// and never the content.
func TestE2EFederatedResourcesAndPrompts(t *testing.T) {
	w := newWorld(t, options{federation: true})
	ctx := t.Context()
	w.forbid(wikiAliceKey, "upstream API key")
	w.forbid(wikiHomeBody, "resource content")
	w.forbid(wikiTopic, "prompt argument")
	up := newWikiUpstream(t)
	err := w.st.WithJobs(ctx, func(tx store.Tx) error {
		return store.CreateNetguardAllowHost(ctx, tx, &store.NetguardAllowHost{Pattern: "127.0.0.1", Note: "e2e upstream"})
	})
	if err != nil {
		t.Fatal(err)
	}
	server := &store.MCPServer{
		Name: "wiki", URL: up.srv.URL, OwnerUserID: w.alice.id,
		CredentialMode: store.MCPCredentialPerUser, AuthKind: store.MCPAuthAPIKey,
		AuthConfig: []byte(`{"api_key":{"header":"X-Wiki-Key"}}`),
	}
	if err := w.fed.Manager.CreateServer(ctx, server); err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	if err := w.fed.Auth.SetUserCredential(ctx, w.alice.id, server.ID, auth.Credential{APIKey: wikiAliceKey}); err != nil {
		t.Fatalf("SetUserCredential: %v", err)
	}
	review(t, w, w.alice, server, false, nil)
	// Added upstream after the review: not in the approved snapshot.
	up.sdk.AddResource(&sdk.Resource{URI: "wiki://secret", Name: "secret"},
		func(_ context.Context, req *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error) {
			return &sdk.ReadResourceResult{Contents: []*sdk.ResourceContents{{URI: req.Params.URI, Text: "secret"}}}, nil
		})

	alice, bob := w.client(w.alice), w.client(w.bob)
	caps := alice.InitializeResult().Capabilities
	if caps.Resources == nil || caps.Prompts == nil || caps.Resources.Subscribe || caps.Resources.ListChanged {
		t.Fatalf("capabilities = resources %+v prompts %+v", caps.Resources, caps.Prompts)
	}

	// 1. Alice lists, reads and gets.
	list, err := alice.ListResources(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	uris := map[string]*sdk.Resource{}
	for _, r := range list.Resources {
		uris[r.URI] = r
	}
	home := uris["mcpgw://wiki/wiki://home"]
	if home == nil || uris["mcpgw://wiki/wiki://logo"] == nil || uris["mcpgw://wiki/wiki://secret"] != nil {
		t.Fatalf("alice's resources = %v", uris)
	}
	if home.Title != "[wiki] Home" || home.Description != "[wiki] The home page" || home.MIMEType != "text/markdown" {
		t.Errorf("home = %+v", home)
	}
	read, err := alice.ReadResource(ctx, &sdk.ReadResourceParams{URI: home.URI})
	if err != nil || len(read.Contents) != 1 || read.Contents[0].Text != wikiHomeBody || read.Contents[0].MIMEType != "text/markdown" {
		t.Fatalf("read home = %+v, %v", read, err)
	}
	logo, err := alice.ReadResource(ctx, &sdk.ReadResourceParams{URI: "mcpgw://wiki/wiki://logo"})
	if err != nil || string(logo.Contents[0].Blob) != "\x89PNG" || logo.Contents[0].MIMEType != "image/png" {
		t.Fatalf("read logo = %+v, %v", logo, err)
	}
	templates, err := alice.ListResourceTemplates(ctx, nil)
	if err != nil || len(templates.ResourceTemplates) != 1 || templates.ResourceTemplates[0].URITemplate != "mcpgw://wiki/wiki://page/{name}" {
		t.Fatalf("templates = %+v, %v", templates, err)
	}
	page, err := alice.ReadResource(ctx, &sdk.ReadResourceParams{URI: "mcpgw://wiki/wiki://page/intro"})
	if err != nil || page.Contents[0].Text != "page intro" {
		t.Fatalf("templated read = %+v, %v", page, err)
	}
	prompts, err := alice.ListPrompts(ctx, nil)
	if err != nil || len(prompts.Prompts) != 1 || prompts.Prompts[0].Name != "wiki.draft" {
		t.Fatalf("prompts = %+v, %v", prompts, err)
	}
	got, err := alice.GetPrompt(ctx, &sdk.GetPromptParams{Name: "wiki.draft", Arguments: map[string]string{"topic": wikiTopic}})
	if err != nil || len(got.Messages) != 1 || got.Messages[0].Content.(*sdk.TextContent).Text != "Draft about "+wikiTopic {
		t.Fatalf("get prompt = %+v, %v", got, err)
	}

	// 2. A resource the upstream has but the review never saw.
	before := len(up.readURIs())
	_, err = alice.ReadResource(ctx, &sdk.ReadResourceParams{URI: "mcpgw://wiki/wiki://secret"})
	if we := rpcError(t, err, mcp.CodeInvalidParams); we.Message != "Resource not found" {
		t.Errorf("unreviewed resource: %+v", we)
	}
	if after := up.readURIs(); len(after) != before {
		t.Errorf("the upstream was asked for an unreviewed resource: %v", after[before:])
	}

	// 3. Bob may not use alice's private server.
	bobList, err := bob.ListResources(ctx, nil)
	if err != nil || len(bobList.Resources) != 0 {
		t.Errorf("bob's resources = %+v, %v", bobList, err)
	}
	bobTemplates, err := bob.ListResourceTemplates(ctx, nil)
	if err != nil || len(bobTemplates.ResourceTemplates) != 0 {
		t.Errorf("bob's templates = %+v, %v", bobTemplates, err)
	}
	bobPrompts, err := bob.ListPrompts(ctx, nil)
	if err != nil || len(bobPrompts.Prompts) != 0 {
		t.Errorf("bob's prompts = %+v, %v", bobPrompts, err)
	}
	_, err = bob.ReadResource(ctx, &sdk.ReadResourceParams{URI: home.URI})
	hidden := rpcError(t, err, mcp.CodeInvalidParams)
	_, err = bob.ReadResource(ctx, &sdk.ReadResourceParams{URI: "mcpgw://nosuch/wiki://home"})
	unknown := rpcError(t, err, mcp.CodeInvalidParams)
	if hidden.Message != unknown.Message || hidden.Message != "Resource not found" {
		t.Errorf("hidden %q vs unknown %q: must be the same answer", hidden.Message, unknown.Message)
	}
	_, err = bob.GetPrompt(ctx, &sdk.GetPromptParams{Name: "wiki.draft", Arguments: map[string]string{"topic": "x"}})
	if we := rpcError(t, err, mcp.CodeInvalidParams); we.Message != `unknown prompt "wiki.draft"` {
		t.Errorf("bob's prompt: %+v", we)
	}

	// 4. Audit: one row per read/get, naming the server, never content.
	var reads, gets int
	for _, ev := range w.events(w.alice) {
		switch ev.Tool {
		case "wiki.resources/read":
			if ev.ResourceIdentity["server"] != "wiki" || ev.ResourceIdentity["uri"] == "" || ev.ResourceIdentity["uri_sha256"] == "" {
				t.Errorf("read row identity = %v", ev.ResourceIdentity)
			}
			if ev.Outcome == "succeeded" {
				reads++
			}
		case "wiki.prompts/get":
			if ev.ResourceIdentity["prompt"] != "draft" || ev.Outcome != "succeeded" {
				t.Errorf("get row = %+v", ev.Event)
			}
			gets++
		}
	}
	if reads != 3 || gets != 1 {
		t.Errorf("audited reads %d (want 3), gets %d (want 1)", reads, gets)
	}
	denied := false
	for _, ev := range w.events(w.bob) {
		if ev.Tool == "resources/read" && ev.Outcome == "denied" && ev.ErrorClass == "resource_not_found" {
			denied = true
		}
	}
	if !denied {
		t.Error("bob's refused read has no audit row")
	}
}
