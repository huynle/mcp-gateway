//go:build integration || e2e

package e2e

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/federation/auth"
	"github.com/huynle/mcp-gateway/internal/federation/client"
	"github.com/huynle/mcp-gateway/internal/federation/connector"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/store"
)

// Upstream API keys: each maps to whose key it is. They must never reach
// the gateway log or the audit rows.
var notesKeys = map[string]string{
	"alice-notes-key-e2e":  "alice",
	"bob-notes-key-e2e":    "bob",
	"shared-notes-key-e2e": "shared",
}

type notesSearch struct {
	Q string `json:"q"`
}

type notesSearchV2 struct {
	Q     string `json:"q"`
	Limit int    `json:"limit"`
}

type notesCreate struct {
	Title string `json:"title"`
}

// notesUpstream is a user-added MCP server ("notes"): API key auth on
// every request, a read (search), a write (create_note) and a write
// nobody enables (purge). Version 2 changes search's input schema. It
// records every request's headers.
type notesUpstream struct {
	srv     *httptest.Server
	v2      atomic.Bool
	mu      sync.Mutex
	headers []http.Header
	created []string
}

func newNotesUpstream(t *testing.T) *notesUpstream {
	t.Helper()
	u := &notesUpstream{}
	who := func(req *sdk.CallToolRequest) string { return notesKeys[req.Extra.Header.Get("X-Notes-Key")] }
	build := func(v2 bool) *sdk.Server {
		s := sdk.NewServer(&sdk.Implementation{Name: "notes", Version: "1"}, nil)
		if v2 {
			sdk.AddTool(s, &sdk.Tool{Name: "search", Description: "Search notes.", Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true}},
				func(_ context.Context, req *sdk.CallToolRequest, in notesSearchV2) (*sdk.CallToolResult, any, error) {
					return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "v2 results for " + who(req)}}}, nil, nil
				})
		} else {
			sdk.AddTool(s, &sdk.Tool{Name: "search", Description: "Search notes.", Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true}},
				func(_ context.Context, req *sdk.CallToolRequest, in notesSearch) (*sdk.CallToolResult, any, error) {
					return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "results for " + who(req)}}}, nil, nil
				})
		}
		sdk.AddTool(s, &sdk.Tool{Name: "create_note", Description: "Create a note."},
			func(_ context.Context, req *sdk.CallToolRequest, in notesCreate) (*sdk.CallToolResult, any, error) {
				u.mu.Lock()
				u.created = append(u.created, who(req)+":"+in.Title)
				u.mu.Unlock()
				return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "created"}}}, nil, nil
			})
		sdk.AddTool(s, &sdk.Tool{Name: "purge", Description: "Delete every note."},
			func(context.Context, *sdk.CallToolRequest, notesCreate) (*sdk.CallToolResult, any, error) {
				return &sdk.CallToolResult{}, nil, nil
			})
		return s
	}
	v1, v2 := build(false), build(true)
	h := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server {
		if u.v2.Load() {
			return v2
		}
		return v1
	}, &sdk.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.headers = append(u.headers, r.Header.Clone())
		u.mu.Unlock()
		if _, ok := notesKeys[r.Header.Get("X-Notes-Key")]; !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="notes"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *notesUpstream) allHeaders() []http.Header {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]http.Header(nil), u.headers...)
}

// review discovers the server as the owner (with the owner's credential)
// and approves the given version with decisions; version 0 means a new
// snapshot (Create, or Refresh when one exists).
func review(t *testing.T, w *world, owner user, server *store.MCPServer, refresh bool, enable map[string]bool) {
	t.Helper()
	ctx := t.Context()
	az, err := w.fed.Auth.ForUser(ctx, server, owner.id)
	if err != nil {
		t.Fatalf("ForUser: %v", err)
	}
	c, err := client.New(client.Options{HTTPClient: w.fed.Guard.Client(), Authorizer: az})
	if err != nil {
		t.Fatal(err)
	}
	sess, err := c.Connect(ctx, client.Endpoint{URL: server.URL})
	if err != nil {
		t.Fatalf("connect upstream: %v", err)
	}
	defer func() { _ = sess.Close() }()
	actor := snapshot.Actor{UserID: owner.id}
	var rec *snapshot.Record
	if refresh {
		rec, _, err = w.fed.Snapshots.Refresh(ctx, actor, server.ID, sess)
	} else {
		rec, err = w.fed.Snapshots.Create(ctx, actor, server.ID, sess)
	}
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	decisions := snapshot.ReviewDecisions{Tools: map[string]snapshot.Decision{}}
	for name, on := range enable {
		decisions.Tools[name] = snapshot.Decision{Enabled: &on}
	}
	// Every resource, template and prompt enabled (their review toggles
	// have their own scenario, TestE2EPluginsResourceReviewAndGrants).
	decisions.Resources, decisions.ResourceTemplates, decisions.Prompts = map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, r := range rec.Snapshot.Resources {
		decisions.Resources[r.URI] = true
	}
	for _, x := range rec.Snapshot.ResourceTemplates {
		decisions.ResourceTemplates[x.URITemplate] = true
	}
	for _, p := range rec.Snapshot.Prompts {
		decisions.Prompts[p.Name] = true
	}
	if _, err := w.fed.Snapshots.Approve(ctx, actor, server.ID, rec.Version, decisions); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if err := w.fed.Manager.ServerChanged(ctx, server.ID); err != nil {
		t.Fatalf("ServerChanged: %v", err)
	}
}

// TestE2EFederatedServerVisibilityApprovalAndCredentials is the
// federation acceptance scenario (task fybs78bs), through the official
// MCP client against the in-process gateway:
//
//  1. alice adds a private server (allow-listed in netguard's store-backed
//     list) and approves its snapshot: her tools/list shows notes.search
//     and notes.create_note, bob's does not; a reserved name is refused;
//  2. alice's read is allowed, her write needs an approval and then runs
//     once (ledgered); a tool nobody enabled does not exist;
//  3. a changed upstream schema is refused after the refresh until it is
//     re-reviewed;
//  4. an admin publishes the server to bob's role: still hidden until the
//     role grants the tools; then bob calls with his own credential
//     (per_user: none yet = no_account), and after a switch to a shared
//     credential with the shared one; his write needs an approval;
//  5. the upstream never saw a gateway token; audit rows name the server.
func TestE2EFederatedServerVisibilityApprovalAndCredentials(t *testing.T) {
	w := newWorld(t, options{federation: true})
	ctx := t.Context()
	for k := range notesKeys {
		w.forbid(k, "upstream API key")
	}
	up := newNotesUpstream(t)
	// The test upstream listens on 127.0.0.1: an admin allow-lists it.
	err := w.st.WithJobs(ctx, func(tx store.Tx) error {
		return store.CreateNetguardAllowHost(ctx, tx, &store.NetguardAllowHost{Pattern: "127.0.0.1", Note: "e2e upstream"})
	})
	if err != nil {
		t.Fatal(err)
	}

	// 1. Alice adds the server; reserved names are refused.
	if err := w.fed.Manager.CreateServer(ctx, &store.MCPServer{Name: "github", URL: up.srv.URL, OwnerUserID: w.alice.id}); !errors.Is(err, connector.ErrReservedServerName) {
		t.Errorf("CreateServer(github) = %v, want ErrReservedServerName", err)
	}
	server := &store.MCPServer{
		Name: "notes", URL: up.srv.URL, OwnerUserID: w.alice.id,
		CredentialMode: store.MCPCredentialPerUser, AuthKind: store.MCPAuthAPIKey,
		AuthConfig: []byte(`{"api_key":{"header":"X-Notes-Key"}}`),
	}
	if err := w.fed.Manager.CreateServer(ctx, server); err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	if err := w.fed.Auth.SetUserCredential(ctx, w.alice.id, server.ID, auth.Credential{APIKey: "alice-notes-key-e2e"}); err != nil {
		t.Fatalf("SetUserCredential alice: %v", err)
	}
	review(t, w, w.alice, server, false, map[string]bool{"search": true, "create_note": true})

	alice, bob := w.client(w.alice), w.client(w.bob)
	aliceTools, bobTools := toolNames(t, alice), toolNames(t, bob)
	if !contains(aliceTools, "notes.search") || !contains(aliceTools, "notes.create_note") || contains(aliceTools, "notes.purge") {
		t.Fatalf("alice's tools = %v", aliceTools)
	}
	for _, name := range bobTools {
		if strings.HasPrefix(name, "notes.") {
			t.Fatalf("bob sees alice's private server: %v", bobTools)
		}
	}
	// Bob calling it gets exactly the unknown-tool answer.
	_, err = w.call(bob, "notes.search", map[string]any{"q": "x"})
	_ = rpcError(t, err, mcp.CodeToolNotFound)

	// 2. Alice's read is allowed with her own credential.
	res, err := w.call(alice, "notes.search", map[string]any{"q": "plans"})
	if err != nil || res.IsError || text(t, res) != "results for alice" {
		t.Fatalf("alice search: %v %+v", err, res)
	}
	// Her write needs an approval, then runs once with the stored args.
	_, err = w.call(alice, "notes.create_note", map[string]any{"title": "first"})
	id := approvalRequired(t, err)
	if code, _ := w.post(w.alice, "/approvals/"+id+"/approve", true); code != 303 {
		t.Fatalf("approve = %d", code)
	}
	res, err = w.call(alice, "notes.create_note", map[string]any{"title": "drifted", "approval_id": id})
	if err != nil || res.IsError {
		t.Fatalf("approved write: %v %+v", err, res)
	}
	up.mu.Lock()
	created := strings.Join(up.created, ",")
	up.mu.Unlock()
	if created != "alice:first" {
		t.Errorf("upstream writes = %q, want alice:first", created)
	}
	if op := w.opFor(w.alice, "notes.create_note", store.LedgerSucceeded); op == nil {
		t.Error("the federated write has no succeeded ledger operation")
	}
	// A tool nobody enabled does not exist.
	_, err = w.call(alice, "notes.purge", map[string]any{"title": "x"})
	_ = rpcError(t, err, mcp.CodeToolNotFound)
	// Arguments outside the pinned schema are refused.
	_, err = w.call(alice, "notes.search", map[string]any{"q": 7})
	_ = rpcError(t, err, mcp.CodeInvalidParams)

	// 3. The upstream changes search's schema; after the refresh the
	// changed tool is disabled until re-reviewed.
	up.v2.Store(true)
	review(t, w, w.alice, server, true, nil)
	_, err = w.call(alice, "notes.search", map[string]any{"q": "plans", "limit": 2})
	_ = rpcError(t, err, mcp.CodeToolNotFound)
	review(t, w, w.alice, server, false, map[string]bool{"search": true}) // re-approve the same version with search on
	res, err = w.call(alice, "notes.search", map[string]any{"q": "plans", "limit": 2})
	if err != nil || text(t, res) != "v2 results for alice" {
		t.Fatalf("re-reviewed search: %v %+v", err, res)
	}

	// 4. An admin publishes the server to bob's role.
	err = w.st.WithJobs(ctx, func(tx store.Tx) error {
		role, err := store.FindRoleByName(ctx, tx, roleRestricted)
		if err != nil {
			return err
		}
		return store.PublishMCPServer(ctx, tx, server.ID, []string{role.ID})
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.fed.Manager.ServerChanged(ctx, server.ID); err != nil {
		t.Fatal(err)
	}
	if contains(toolNames(t, bob), "notes.search") {
		t.Error("published tools visible before the role grants them (default must be hidden)")
	}
	restricted, err := w.policy.Role(ctx, roleRestricted)
	if err != nil {
		t.Fatal(err)
	}
	restricted.Rules = append(restricted.Rules,
		policy.ToolRule{App: "notes", Tool: "search", Outcome: policy.OutcomeAllow},
		policy.ToolRule{App: "notes", Tool: "create_note", Outcome: policy.OutcomeConfirm})
	if err := w.policy.SaveRole(ctx, w.admin.id, restricted); err != nil {
		t.Fatal(err)
	}
	if !contains(toolNames(t, bob), "notes.search") {
		t.Fatal("bob does not see the published, granted tool")
	}
	// per_user: bob has not connected yet.
	_, err = w.call(bob, "notes.search", map[string]any{"q": "x", "limit": 1})
	_ = rpcError(t, err, mcp.CodeNoAccount)
	if err := w.fed.Auth.SetUserCredential(ctx, w.bob.id, server.ID, auth.Credential{APIKey: "bob-notes-key-e2e"}); err != nil {
		t.Fatalf("SetUserCredential bob: %v", err)
	}
	res, err = w.call(bob, "notes.search", map[string]any{"q": "x", "limit": 1})
	if err != nil || text(t, res) != "v2 results for bob" {
		t.Fatalf("bob search with his own credential: %v %+v", err, res)
	}
	_, err = w.call(bob, "notes.create_note", map[string]any{"title": "bobs"})
	approvalRequired(t, err)

	// shared: the owner switches to a shared credential.
	server.CredentialMode = store.MCPCredentialShared
	if err := w.fed.Manager.UpdateServer(ctx, w.alice.id, server); err != nil {
		t.Fatalf("UpdateServer: %v", err)
	}
	if err := w.fed.Auth.SetSharedCredential(ctx, auth.Actor{UserID: w.alice.id}, server.ID, auth.Credential{APIKey: "shared-notes-key-e2e"}); err != nil {
		t.Fatalf("SetSharedCredential: %v", err)
	}
	res, err = w.call(bob, "notes.search", map[string]any{"q": "x", "limit": 1})
	if err != nil || text(t, res) != "v2 results for shared" {
		t.Fatalf("bob search with the shared credential: %v %+v", err, res)
	}

	// 5. No gateway token ever reached the upstream.
	for _, h := range up.allHeaders() {
		if h.Get("Authorization") != "" || h.Get("Cookie") != "" {
			t.Errorf("upstream received gateway credentials: %v", h)
		}
		for _, raws := range w.tokensByUser {
			for _, raw := range raws {
				for name, vals := range h {
					for _, v := range vals {
						if strings.Contains(v, raw) {
							t.Errorf("upstream header %s carries a harness token", name)
						}
					}
				}
			}
		}
	}
	// Audit rows name the server as the resource.
	found := false
	for _, ev := range w.events(w.bob) {
		if ev.Tool == "notes.search" && ev.ResourceIdentity["server"] == "notes" && ev.Outcome == "succeeded" {
			found = true
		}
	}
	if !found {
		t.Error("no audit row for bob's notes.search naming the server")
	}
}
