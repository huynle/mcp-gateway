package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/federation/auth"
	"github.com/huynle/mcp-gateway/internal/federation/client"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/federation/tunnel"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/netguard"
	"github.com/huynle/mcp-gateway/internal/permissions"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

const (
	alice = "11111111-1111-4111-8111-111111111111"
	bob   = "22222222-2222-4222-8222-222222222222"
)

// --- fakes -------------------------------------------------------------------

type fakeStore struct {
	mu           sync.Mutex
	servers      map[string]*store.MCPServer
	visible      map[string][]string
	conns        map[string]*store.MCPUserConnection // user|server
	anchors      map[string]string                   // user|server|label -> id
	visibleCalls int
	created      []string
}

func newFakeStore() *fakeStore {
	return &fakeStore{servers: map[string]*store.MCPServer{}, visible: map[string][]string{}, conns: map[string]*store.MCPUserConnection{}, anchors: map[string]string{}}
}

func (f *fakeStore) put(s store.MCPServer) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.servers[s.ID] = &s
}

func (f *fakeStore) ListServers(context.Context) ([]store.MCPServer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []store.MCPServer
	for _, s := range f.servers {
		out = append(out, *s)
	}
	return out, nil
}

func (f *fakeStore) GetServer(_ context.Context, id string) (*store.MCPServer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.servers[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	c := *s
	return &c, nil
}

func (f *fakeStore) VisibleServerIDs(_ context.Context, userID string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.visibleCalls++
	return append([]string(nil), f.visible[userID]...), nil
}

func (f *fakeStore) UserConnection(_ context.Context, userID, serverID string) (*store.MCPUserConnection, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.conns[userID+"|"+serverID]
	if !ok {
		return nil, store.ErrNotFound
	}
	return c, nil
}

func (f *fakeStore) AnchorAccount(_ context.Context, userID string, s *store.MCPServer, label string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := userID + "|" + s.ID + "|" + label
	if id, ok := f.anchors[key]; ok {
		return id, nil
	}
	id := connectors.NewAccountID()
	f.anchors[key] = id
	return id, nil
}

func (f *fakeStore) CreateServer(_ context.Context, s *store.MCPServer) error {
	f.mu.Lock()
	f.created = append(f.created, s.Name)
	f.mu.Unlock()
	if s.ID == "" {
		s.ID = connectors.NewAccountID()
	}
	f.put(*s)
	return nil
}

func (f *fakeStore) UpdateServer(_ context.Context, _ string, s *store.MCPServer) error {
	f.put(*s)
	return nil
}

func (f *fakeStore) visibleCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.visibleCalls
}

// fakeSnaps serves approved records and answers Allowed with the real
// snapshot.Check, refusing users who cannot see the server like RLS.
type fakeSnaps struct {
	mu      sync.Mutex
	records map[string]*snapshot.Record
	st      *fakeStore
	actors  []snapshot.Actor
}

func (f *fakeSnaps) Current(_ context.Context, a snapshot.Actor, serverID string) (*snapshot.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.actors = append(f.actors, a)
	r, ok := f.records[serverID]
	if !ok {
		return nil, snapshot.ErrNoSnapshot
	}
	return r, nil
}

func (f *fakeSnaps) Allowed(ctx context.Context, a snapshot.Actor, serverID, tool string, args map[string]any) (snapshot.Tool, snapshot.Kind, error) {
	f.mu.Lock()
	f.actors = append(f.actors, a)
	r, ok := f.records[serverID]
	f.mu.Unlock()
	if !a.Admin {
		ids, _ := f.st.VisibleServerIDs(ctx, a.UserID)
		seen := false
		for _, id := range ids {
			seen = seen || id == serverID
		}
		if !seen {
			return snapshot.Tool{}, "", snapshot.ErrNoSnapshot
		}
	}
	if !ok {
		return snapshot.Tool{}, "", snapshot.ErrNoSnapshot
	}
	return snapshot.Check(r.Snapshot, r.Review, tool, args)
}

func (f *fakeSnaps) setReview(tool string, rv snapshot.ToolReview) {
	const serverID = srvID
	f.mu.Lock()
	defer f.mu.Unlock()
	r := *f.records[serverID]
	review := snapshot.Review{}
	for k, v := range r.Review {
		review[k] = v
	}
	review[tool] = rv
	r.Review = review
	f.records[serverID] = &r
}

// headerAuth is an auth.Authorizer that sets one header.
type headerAuth struct{ name, value string }

func (h headerAuth) Authorize(_ context.Context, r *http.Request) error {
	r.Header.Set(h.name, h.value)
	return nil
}
func (h headerAuth) Unauthorized(context.Context) error { return auth.ErrNeedsReconnect }

type fakeCreds struct {
	mu   sync.Mutex
	errs map[string]error // user -> error
}

func (f *fakeCreds) ForUser(_ context.Context, s *store.MCPServer, userID string) (auth.Authorizer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.errs[userID]; err != nil {
		return nil, err
	}
	return headerAuth{"X-Upstream-Key", userID + "-key"}, nil
}

type fakeTunnels struct {
	authErr   error
	transport http.RoundTripper
	owners    []string
}

func (f *fakeTunnels) Authorize(_ context.Context, owner, id string) error {
	f.owners = append(f.owners, owner+"/"+id)
	return f.authErr
}

func (f *fakeTunnels) HTTPClient(base *http.Client) *http.Client {
	c := *base
	c.Transport = f.transport
	return &c
}

// allVisible is the base visibility (policy stand-in): everything.
type allVisible struct{}

func (allVisible) Visible(context.Context, *tokens.Principal, connectors.Tool) bool { return true }

// --- upstream ------------------------------------------------------------------

type searchIn struct {
	Q string `json:"q"`
}
type searchOut struct {
	Hits []string `json:"hits"`
}
type createIn struct {
	Title string `json:"title"`
}

// upstream is a go-sdk MCP server that records the headers of every
// request.
type upstream struct {
	srv     *httptest.Server
	sdk     *sdk.Server
	mu      sync.Mutex
	headers []http.Header
	block   chan struct{}
}

func newUpstream(t *testing.T) *upstream {
	t.Helper()
	u := &upstream{block: make(chan struct{})}
	s := sdk.NewServer(&sdk.Implementation{Name: "notes", Version: "1"}, nil)
	sdk.AddTool(s, &sdk.Tool{Name: "search", Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true}},
		func(_ context.Context, _ *sdk.CallToolRequest, in searchIn) (*sdk.CallToolResult, searchOut, error) {
			return nil, searchOut{Hits: []string{"hit for " + in.Q}}, nil
		})
	sdk.AddTool(s, &sdk.Tool{Name: "create_note"},
		func(_ context.Context, _ *sdk.CallToolRequest, in createIn) (*sdk.CallToolResult, any, error) {
			return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "created " + in.Title}}}, nil, nil
		})
	sdk.AddTool(s, &sdk.Tool{Name: "slow_write"},
		func(ctx context.Context, _ *sdk.CallToolRequest, _ createIn) (*sdk.CallToolResult, any, error) {
			select {
			case <-u.block:
			case <-ctx.Done():
			}
			return &sdk.CallToolResult{}, nil, nil
		})
	sdk.AddTool(s, &sdk.Tool{Name: "broken", Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true}},
		func(context.Context, *sdk.CallToolRequest, searchIn) (*sdk.CallToolResult, any, error) {
			return nil, nil, errors.New("upstream detail that must not leak")
		})
	addResources(s)
	u.sdk = s
	h := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return s }, &sdk.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.headers = append(u.headers, r.Header.Clone())
		u.mu.Unlock()
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(func() { close(u.block); u.srv.Close() })
	return u
}

func (u *upstream) reset() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.headers = nil
}

func (u *upstream) seen() []http.Header {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]http.Header(nil), u.headers...)
}

// discovered lists the upstream's tools as a snapshot (what the review
// pinned).
func discovered(t *testing.T, u *upstream) *snapshot.Snapshot {
	t.Helper()
	allow, _ := netguard.NewStaticAllowList("127.0.0.1")
	c, err := client.New(client.Options{HTTPClient: netguard.New(netguard.Options{AllowList: allow}).Client()})
	if err != nil {
		t.Fatal(err)
	}
	cs, err := c.Connect(t.Context(), client.Endpoint{URL: u.srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cs.Close() }()
	snap, err := snapshot.Discover(t.Context(), cs)
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

// --- fixture ---------------------------------------------------------------------

type fixture struct {
	m        *Manager
	reg      *connectors.Registry
	st       *fakeStore
	snaps    *fakeSnaps
	creds    *fakeCreds
	tunnels  *fakeTunnels
	perms    *fakePerms
	up       *upstream
	changes  int
	changeMu sync.Mutex
}

const srvID = "33333333-3333-4333-8333-333333333333"

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{reg: connectors.NewRegistry(), st: newFakeStore(), creds: &fakeCreds{errs: map[string]error{}}, tunnels: &fakeTunnels{},
		perms: &fakePerms{denied: map[string]bool{}}}
	if err := f.reg.Register(stubTool("github", "list_issues", connectors.KindRead)); err != nil {
		t.Fatal(err)
	}
	f.up = newUpstream(t)
	f.st.put(store.MCPServer{
		ID: srvID, Name: "notes", URL: f.up.srv.URL, OwnerUserID: alice, Audience: store.MCPAudiencePrivate,
		CredentialMode: store.MCPCredentialPerUser, AuthKind: store.MCPAuthAPIKey, Status: store.MCPServerActive,
		HeaderConfig: json.RawMessage(`{"static":{"X-Tenant":"acme"}}`),
	})
	f.st.visible[alice] = []string{srvID}
	f.snaps = &fakeSnaps{st: f.st, records: map[string]*snapshot.Record{srvID: {
		ID: "snap-1", ServerID: srvID, Version: 1, Status: store.MCPSnapshotApproved, Snapshot: discovered(t, f.up),
		Review: snapshot.Review{
			"search":      {Enabled: true, Kind: snapshot.KindRead},
			"create_note": {Enabled: true, Kind: snapshot.KindWrite},
			"slow_write":  {Enabled: true, Kind: snapshot.KindWrite},
			"broken":      {Enabled: true, Kind: snapshot.KindRead},
		},
	}}}
	allow, err := netguard.NewStaticAllowList("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	guard := netguard.New(netguard.Options{AllowList: allow})
	f.m, err = New(Options{
		Registry: f.reg, Store: f.st, Snapshots: f.snaps, Credentials: f.creds, Tunnels: f.tunnels, Permissions: f.perms,
		HTTPClient: guard.Client(), BaseURL: "https://gw.example", Timeout: 2 * time.Second,
		OnChange: func() { f.changeMu.Lock(); f.changes++; f.changeMu.Unlock() },
		Log:      slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.m.Load(t.Context()); err != nil {
		t.Fatalf("Load: %v", err)
	}
	return f
}

func stubTool(app, name string, kind connectors.Kind) connectors.Tool {
	return connectors.Tool{App: app, Name: name, Kind: kind, InputSchema: json.RawMessage(`{"type":"object"}`),
		Handler: func(context.Context, connectors.Call) (connectors.Result, error) {
			return connectors.Result{Content: "builtin"}, nil
		}}
}

// call runs a registered tool's handler as the pipeline's dispatch would.
func (f *fixture) call(t *testing.T, user, name string, args map[string]any) (connectors.Result, error) {
	t.Helper()
	tool, ok := f.reg.Get(name)
	if !ok {
		t.Fatalf("%s not registered (have %v)", name, names(f.reg.List()))
	}
	return tool.Handler(t.Context(), connectors.Call{Principal: connectors.Principal{UserID: user}, Tool: name, Args: args})
}

func toolErrClass(err error) string {
	var te *mcp.ToolError
	if errors.As(err, &te) {
		return "tool:" + te.Class()
	}
	var ce mcp.ClassedError
	if errors.As(err, &ce) {
		return "handler:" + ce.ErrorClass()
	}
	if err == nil {
		return ""
	}
	return "other:" + err.Error()
}

// --- tests ---------------------------------------------------------------------

func TestManagerLoadRegistersApprovedEnabledTools(t *testing.T) {
	f := newFixture(t)
	// Servers that must not appear: disabled, reserved name, no approved
	// snapshot.
	f.st.put(store.MCPServer{ID: "s-off", Name: "off", Status: store.MCPServerDisabled, OwnerUserID: alice})
	f.st.put(store.MCPServer{ID: "s-gh", Name: "github", Status: store.MCPServerActive, OwnerUserID: alice})
	f.st.put(store.MCPServer{ID: "s-new", Name: "fresh", Status: store.MCPServerActive, OwnerUserID: alice})
	f.snaps.records["s-off"] = f.snaps.records[srvID]
	f.snaps.records["s-gh"] = f.snaps.records[srvID]
	f.snaps.setReview("broken", snapshot.ToolReview{Enabled: false, Kind: snapshot.KindRead})
	if err := f.m.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	got := fmt.Sprint(names(f.reg.List()))
	if got != "[github.list_issues notes.create_note notes.search notes.slow_write]" {
		t.Errorf("registry = %s", got)
	}
	if fmt.Sprint(f.reg.ServerApps()) != "[notes]" {
		t.Errorf("server apps = %v", f.reg.ServerApps())
	}
	for _, a := range f.snaps.actors {
		if !a.Admin || a.UserID != "" {
			t.Errorf("loader read snapshots as %+v, want the system actor", a)
		}
	}
}

func TestManagerServerChangedReloads(t *testing.T) {
	f := newFixture(t)
	f.snaps.setReview("search", snapshot.ToolReview{Enabled: false, Kind: snapshot.KindRead})
	if err := f.m.ServerChanged(t.Context(), srvID); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.reg.Get("notes.search"); ok {
		t.Error("disabled tool still registered after ServerChanged")
	}
	if f.changes != 1 {
		t.Errorf("OnChange calls = %d, want 1", f.changes)
	}
	// Disabled server: every tool goes.
	s, _ := f.st.GetServer(t.Context(), srvID)
	s.Status = store.MCPServerDisabled
	f.st.put(*s)
	if err := f.m.ServerChanged(t.Context(), srvID); err != nil {
		t.Fatal(err)
	}
	if f.reg.IsServerApp("notes") {
		t.Error("disabled server still has an app")
	}
	// Re-enabled then deleted.
	s.Status = store.MCPServerActive
	f.st.put(*s)
	_ = f.m.ServerChanged(t.Context(), srvID)
	if !f.reg.IsServerApp("notes") {
		t.Fatal("re-enabled server not loaded")
	}
	f.st.mu.Lock()
	delete(f.st.servers, srvID)
	f.st.mu.Unlock()
	_ = f.m.ServerChanged(t.Context(), srvID)
	if f.reg.IsServerApp("notes") {
		t.Error("deleted server still has an app")
	}
}

func TestManagerVisibility(t *testing.T) {
	f := newFixture(t)
	vis := f.m.Visibility(allVisible{})
	search, _ := f.reg.Get("notes.search")
	builtin, _ := f.reg.Get("github.list_issues")
	pa, pb := &tokens.Principal{UserID: alice}, &tokens.Principal{UserID: bob}
	if !vis.Visible(t.Context(), pa, search) {
		t.Error("owner cannot see the server's tool")
	}
	if vis.Visible(t.Context(), pb, search) {
		t.Error("another user sees a private server's tool")
	}
	if !vis.Visible(t.Context(), pb, builtin) {
		t.Error("built-in tool visibility not delegated to the base")
	}
	if vis.Visible(t.Context(), nil, search) {
		t.Error("no principal sees a server tool")
	}
	// Cached per user for the TTL: one lookup per user so far.
	calls := f.st.visibleCount()
	_ = vis.Visible(t.Context(), pa, search)
	if f.st.visibleCount() != calls {
		t.Error("visible servers not cached")
	}
	// Publishing to bob (the portal calls ServerChanged) shows it at once.
	f.st.mu.Lock()
	f.st.visible[bob] = []string{srvID}
	f.st.mu.Unlock()
	_ = f.m.ServerChanged(t.Context(), srvID)
	if !vis.Visible(t.Context(), pb, search) {
		t.Error("ServerChanged did not drop the visibility cache")
	}
	// A policy that hides the tool still hides it.
	deny := f.m.Visibility(mcp.ScopeVisibility{})
	if deny.Visible(t.Context(), &tokens.Principal{UserID: alice, Scope: tokens.Scope{Apps: []string{"github"}}}, search) {
		t.Error("base visibility ignored for a server tool")
	}
}

func TestManagerAccounts(t *testing.T) {
	f := newFixture(t)
	fallback := connectors.NewStaticAccountSource()
	fallback.Add(alice, connectors.Account{ID: "gh-1", App: "github"})
	src := f.m.Accounts(fallback)

	// per_user api_key without a connection: no account.
	if got, err := src.ListAccounts(t.Context(), alice, "notes"); err != nil || len(got) != 0 {
		t.Errorf("unconnected per_user accounts = %v, %v", got, err)
	}
	f.st.conns[alice+"|"+srvID] = &store.MCPUserConnection{ServerID: srvID, UserID: alice, Status: store.MCPConnectionActive}
	got, err := src.ListAccounts(t.Context(), alice, "notes")
	if err != nil || len(got) != 1 || got[0].Label != connectors.LabelPersonal || got[0].App != "notes" || got[0].DisplayName != "notes" {
		t.Fatalf("connected accounts = %+v, %v", got, err)
	}
	again, _ := src.ListAccounts(t.Context(), alice, "notes")
	if again[0].ID != got[0].ID {
		t.Error("anchor account id not stable")
	}
	// A connection needing reconnect still yields the account (the call
	// then says "reconnect"); a revoked one does not.
	f.st.conns[alice+"|"+srvID].Status = store.MCPConnectionNeedsReconnect
	if got, _ := src.ListAccounts(t.Context(), alice, "notes"); len(got) != 1 {
		t.Error("needs_reconnect connection hid the account")
	}
	f.st.conns[alice+"|"+srvID].Status = store.MCPConnectionRevoked
	if got, _ := src.ListAccounts(t.Context(), alice, "notes"); len(got) != 0 {
		t.Error("revoked connection still yields an account")
	}
	// Shared credential: the synthetic company account.
	s, _ := f.st.GetServer(t.Context(), srvID)
	s.CredentialMode = store.MCPCredentialShared
	f.st.put(*s)
	_ = f.m.ServerChanged(t.Context(), srvID)
	got, _ = src.ListAccounts(t.Context(), alice, "notes")
	if len(got) != 1 || got[0].Label != connectors.LabelCompany {
		t.Errorf("shared accounts = %+v", got)
	}
	// Someone who cannot see the server has none; other apps fall back.
	if got, _ := src.ListAccounts(t.Context(), bob, "notes"); len(got) != 0 {
		t.Errorf("invisible server accounts = %+v", got)
	}
	if got, _ := src.ListAccounts(t.Context(), alice, "github"); len(got) != 1 || got[0].ID != "gh-1" {
		t.Errorf("fallback accounts = %+v", got)
	}
}

func TestManagerCallReadPassesThrough(t *testing.T) {
	f := newFixture(t)
	f.up.reset() // drop the fixture's own discovery requests
	res, err := f.call(t, alice, "notes.search", map[string]any{"q": "plans"})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	out, ok := res.Content.(*sdk.CallToolResult)
	if !ok {
		t.Fatalf("content is %T, want the upstream *CallToolResult", res.Content)
	}
	sc, _ := json.Marshal(out.StructuredContent)
	if string(sc) != `{"hits":["hit for plans"]}` {
		t.Errorf("structured content = %s", sc)
	}
	// The upstream saw the user's credential and the static header, and
	// nothing else of ours.
	if len(f.up.seen()) == 0 {
		t.Fatal("no upstream requests recorded")
	}
	for _, h := range f.up.seen() {
		if h.Get("X-Upstream-Key") != alice+"-key" || h.Get("X-Tenant") != "acme" {
			t.Errorf("upstream headers = %v", h)
		}
		if h.Get("Authorization") != "" || h.Get("Cookie") != "" {
			t.Errorf("upstream got gateway credentials: %v", h)
		}
	}
	// Snapshot checks ran as the caller (RLS visibility as defence in depth).
	last := f.snaps.actors[len(f.snaps.actors)-1]
	if last.Admin || last.UserID != alice {
		t.Errorf("Allowed actor = %+v, want the caller", last)
	}
}

func TestManagerCallRefusals(t *testing.T) {
	f := newFixture(t)
	cases := []struct {
		name  string
		user  string
		tool  string
		args  map[string]any
		setup func()
		want  string
	}{
		{"args not matching the pinned schema", alice, "notes.search", map[string]any{"q": 5}, nil, "tool:args_invalid"},
		{"user cannot see the server", bob, "notes.search", map[string]any{"q": "x"}, nil, "tool:tool_not_found"},
		{"tool disabled since listing", alice, "notes.search", map[string]any{"q": "x"}, func() {
			f.snaps.setReview("search", snapshot.ToolReview{Enabled: false, Kind: snapshot.KindRead})
		}, "tool:tool_disabled"},
		{"read became write since listing", alice, "notes.broken", map[string]any{"q": "x"}, func() {
			f.snaps.setReview("broken", snapshot.ToolReview{Enabled: true, Kind: snapshot.KindWrite})
		}, "tool:tool_changed"},
		{"not connected", alice, "notes.create_note", map[string]any{"title": "t"}, func() {
			f.creds.errs[alice] = auth.ErrNotConnected
		}, "tool:auth_required"},
		{"needs reconnect", alice, "notes.create_note", map[string]any{"title": "t"}, func() {
			f.creds.errs[alice] = auth.ErrNeedsReconnect
		}, "tool:needs_reconnect"},
		{"not configured", alice, "notes.create_note", map[string]any{"title": "t"}, func() {
			f.creds.errs[alice] = auth.ErrNotConfigured
		}, "tool:server_not_configured"},
		{"server disabled", alice, "notes.create_note", map[string]any{"title": "t"}, func() {
			s, _ := f.st.GetServer(t.Context(), srvID)
			s.Status = store.MCPServerDisabled
			f.st.put(*s)
		}, "tool:tool_not_found"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setup != nil {
				tc.setup()
			}
			_, err := f.call(t, tc.user, tc.tool, tc.args)
			if got := toolErrClass(err); got != tc.want {
				t.Errorf("error class = %s, want %s (err %v)", got, tc.want, err)
			}
			if err != nil && strings.Contains(err.Error(), "5") && tc.want == "tool:args_invalid" {
				t.Errorf("message echoes the argument: %v", err)
			}
		})
	}
	// The connect hint points at the portal page of the server.
	f2 := newFixture(t)
	f2.creds.errs[alice] = auth.ErrNotConnected
	_, err := f2.call(t, alice, "notes.create_note", map[string]any{"title": "t"})
	if err == nil || !strings.Contains(err.Error(), "https://gw.example/servers/"+srvID) {
		t.Errorf("not-connected message = %v, want the portal URL", err)
	}
}

func TestManagerCallUpstreamFailures(t *testing.T) {
	f := newFixture(t)
	// The upstream's own tool error is a result, passed through.
	res, err := f.call(t, alice, "notes.broken", map[string]any{"q": "x"})
	if err != nil {
		t.Fatalf("tool error became a Go error: %v", err)
	}
	if out := res.Content.(*sdk.CallToolResult); !out.IsError {
		t.Error("upstream isError lost")
	}

	// A slow write: the outcome is unknown (the ledger reconciles none:
	// unresolved, the user checks).
	_, err = f.call(t, alice, "notes.slow_write", map[string]any{"title": "t"})
	if !errors.Is(err, connectors.ErrOutcomeUnknown) || toolErrClass(err) != "handler:upstream_timeout" {
		t.Errorf("slow write err = %v (%s), want outcome unknown, upstream_timeout", err, toolErrClass(err))
	}

	// Unreachable before anything was sent: a plain, definite failure.
	s, _ := f.st.GetServer(t.Context(), srvID)
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()
	s.URL = deadURL
	f.st.put(*s)
	_, err = f.call(t, alice, "notes.create_note", map[string]any{"title": "t"})
	if errors.Is(err, connectors.ErrOutcomeUnknown) || toolErrClass(err) != "handler:upstream_unreachable" {
		t.Errorf("unreachable err = %v (%s)", err, toolErrClass(err))
	}
	if strings.Contains(err.Error(), "127.0.0.1") {
		t.Errorf("error leaks the URL: %v", err)
	}
}

func TestManagerCallThroughTunnel(t *testing.T) {
	f := newFixture(t)
	tunnelID := "44444444-4444-4444-8444-444444444444"
	s, _ := f.st.GetServer(t.Context(), srvID)
	s.URL = tunnel.URL(tunnelID, "/")
	f.st.put(*s)
	target, _ := url.Parse(f.up.srv.URL)
	f.tunnels.transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != tunnelID+".tunnel.invalid" {
			return nil, fmt.Errorf("unexpected host %s", r.URL.Host)
		}
		r2 := r.Clone(r.Context())
		r2.URL.Scheme, r2.URL.Host, r2.Host = target.Scheme, target.Host, ""
		return http.DefaultTransport.RoundTrip(r2)
	})
	if _, err := f.call(t, alice, "notes.search", map[string]any{"q": "x"}); err != nil {
		t.Fatalf("tunnel call: %v", err)
	}
	if fmt.Sprint(f.tunnels.owners) != "["+alice+"/"+tunnelID+"]" {
		t.Errorf("Authorize calls = %v, want the server owner and tunnel", f.tunnels.owners)
	}

	f.tunnels.transport = roundTrip(func(*http.Request) (*http.Response, error) {
		return nil, &tunnel.Error{Class: tunnel.ClassOffline}
	})
	if _, err := f.call(t, alice, "notes.search", map[string]any{"q": "x"}); toolErrClass(err) != "handler:tunnel_offline" {
		t.Errorf("offline tunnel err = %v (%s)", err, toolErrClass(err))
	}
	f.tunnels.authErr = tunnel.ErrForbidden
	if _, err := f.call(t, alice, "notes.search", map[string]any{"q": "x"}); toolErrClass(err) != "handler:tunnel_unavailable" {
		t.Errorf("forbidden tunnel err = %v (%s)", err, toolErrClass(err))
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// fakePerms: everyone but the denied users may add servers.
type fakePerms struct {
	mu     sync.Mutex
	denied map[string]bool
}

func (p *fakePerms) CanAddServers(_ context.Context, userID string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return userID != "" && !p.denied[userID]
}

// Defense in depth behind the portal (decision bnneszc1): the Manager
// refuses to create a server for an owner who may not add servers.
func TestManagerCreateServerNeedsPermission(t *testing.T) {
	f := newFixture(t)
	f.perms.mu.Lock()
	f.perms.denied[bob] = true
	f.perms.mu.Unlock()
	changes := f.changes
	err := f.m.CreateServer(t.Context(), &store.MCPServer{Name: "sneaky", OwnerUserID: bob, URL: "https://x.example"})
	if !errors.Is(err, permissions.ErrNotPermitted) {
		t.Fatalf("CreateServer without permission = %v, want ErrNotPermitted", err)
	}
	if err := f.m.CreateServer(t.Context(), &store.MCPServer{Name: "noowner", URL: "https://x.example"}); !errors.Is(err, permissions.ErrNotPermitted) {
		t.Errorf("CreateServer without an owner = %v, want ErrNotPermitted", err)
	}
	if len(f.st.created) != 0 {
		t.Errorf("refused servers reached the store: %v", f.st.created)
	}
	if f.changes != changes {
		t.Error("a refused create reloaded the registry")
	}
	// Servers bob already owns keep working: updates are not gated here.
	if err := f.m.CreateServer(t.Context(), &store.MCPServer{Name: "fine", OwnerUserID: alice, URL: "https://x.example"}); err != nil {
		t.Fatalf("permitted CreateServer: %v", err)
	}
}

func TestNewRequiresPermissions(t *testing.T) {
	_, err := New(Options{Registry: connectors.NewRegistry(), Store: newFakeStore(), Snapshots: &fakeSnaps{}, Credentials: &fakeCreds{},
		HTTPClient: http.DefaultClient})
	if err == nil {
		t.Error("New without Permissions succeeded")
	}
}

func TestManagerCreateServerRefusesReservedNames(t *testing.T) {
	f := newFixture(t)
	for _, name := range []string{"github", "jira", "Bad Name"} {
		if err := f.m.CreateServer(t.Context(), &store.MCPServer{Name: name, OwnerUserID: alice, URL: "https://x.example"}); err == nil {
			t.Errorf("CreateServer(%q) accepted", name)
		}
	}
	if len(f.st.created) != 0 {
		t.Errorf("refused names reached the store: %v", f.st.created)
	}
	if err := f.m.CreateServer(t.Context(), &store.MCPServer{Name: "brain", OwnerUserID: alice, URL: "https://x.example"}); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(f.m.UpdateServer(t.Context(), alice, &store.MCPServer{ID: srvID, Name: "slack"}), ErrReservedServerName) {
		t.Error("rename to a reserved name accepted")
	}
}
