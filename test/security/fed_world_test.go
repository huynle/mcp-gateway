//go:build integration || e2e || security

package security

// The federated world: user-added MCP servers (Brain plan 0omkv2e1,
// feature mcp-server-plugins) wired into the security world exactly as
// cmd/gateway does (newFederation, withFederationRoutes,
// withFederationPages, withFederationAdmin), plus hostile upstream
// servers whose every request the tests can inspect. Task rvrfpzzj (the
// adversarial gate before deploy).

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/crypto"
	fedadmin "github.com/huynle/mcp-gateway/internal/federation/admin"
	"github.com/huynle/mcp-gateway/internal/federation/auth"
	"github.com/huynle/mcp-gateway/internal/federation/connector"
	"github.com/huynle/mcp-gateway/internal/federation/gatewaytools"
	fedportal "github.com/huynle/mcp-gateway/internal/federation/portal"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/federation/tunnel"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/machines"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/portal"
	"github.com/huynle/mcp-gateway/internal/store"
)

// wireFederation builds the federation over the world's store and keys
// (connector.Wire, the store-backed allow list) and returns the decider
// and account source the pipeline must use.
func (w *world) wireFederation(keys crypto.KeyProvider, log *slog.Logger, opts options) (mcp.Decider, connectors.AccountSource) {
	w.t.Helper()
	wopts := connector.WireOptions{
		Store: w.st, Keys: keys, Registry: w.reg, BaseURL: baseURL, Version: "security",
		OnChange: w.policy.Invalidate, Log: log, Timeout: opts.fedTimeout,
	}
	var relayHandler atomic.Value
	if opts.tunnelRelay {
		// The relay listener is its own server, never the public mux.
		w.relay = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			relayHandler.Load().(http.Handler).ServeHTTP(rw, r)
		}))
		w.t.Cleanup(w.relay.Close)
		w.forbid(relaySecret, "tunnel relay secret")
		wopts.TunnelRelay = &tunnel.RelayOptions{Advertise: w.relay.URL, Secret: []byte(relaySecret), HTTPClient: &http.Client{}}
	}
	fed, err := connector.Wire(wopts)
	if err != nil {
		w.t.Fatal(err)
	}
	if opts.tunnelRelay {
		relayHandler.Store(fed.Tunnels.RelayHandler())
	}
	fed.Start(w.t.Context())
	w.fed = fed
	// Adding MCP servers needs permission (decision bnneszc1): the
	// cross-user cases need both alice and bob able to add servers.
	w.grantAddServers(w.alice)
	w.grantAddServers(w.bob)
	// The gateway.* management tools, as cmd/gateway's newGatewayTools
	// wires them (off until a user switches them on).
	w.gw, err = gatewaytools.Wire(gatewaytools.WireOptions{
		Federation: fed, Store: w.st, Registry: w.reg, Activity: w.perms, BaseURL: baseURL, Log: log, Timeout: opts.fedTimeout,
	})
	if err != nil {
		w.t.Fatal(err)
	}
	// Enrolled machines, as cmd/gateway's newMachines wires them.
	factory, err := fedportal.NewClientFactory(fedportal.FactoryOptions{
		Credentials: fed.Auth, Tunnels: fed.Tunnels, HTTPClient: fed.Guard.Client(), Log: log,
	})
	if err != nil {
		w.t.Fatal(err)
	}
	w.machines, err = machines.New(machines.Options{
		Store:   machines.NewStore(w.st, nil),
		Servers: machines.NewServers(machines.ServersOptions{Store: w.st, Manager: fed.Manager, Snapshots: fed.Snapshots, Clients: factory}),
		Tunnels: fed.Tunnels, BaseURL: baseURL, Audit: w.rec, Log: log,
	})
	if err != nil {
		w.t.Fatal(err)
	}
	return w.gw.Decider(fed.Manager.Decider(w.policy)), w.gw.Accounts(fed.Manager.Accounts(w.conn))
}

// roleServerBuilders may add MCP servers (and nothing else).
const roleServerBuilders = "server_builders"

// grantAddServers gives u, besides their roles, one an admin marked "May
// add MCP servers" (policy service saves it, the bypass scope assigns it).
func (w *world) grantAddServers(u user) {
	w.t.Helper()
	ctx := w.t.Context()
	if err := w.policy.SaveRole(ctx, w.admin.id, policy.Role{Name: roleServerBuilders, Description: "May add MCP servers", MayAddServers: true}); err != nil {
		w.t.Fatalf("SaveRole %s: %v", roleServerBuilders, err)
	}
	err := w.st.WithJobs(ctx, func(tx store.Tx) error {
		r, err := store.FindRoleByName(ctx, tx, roleServerBuilders)
		if err != nil {
			return err
		}
		return store.AssignRoleIfMissing(ctx, tx, u.id, r.ID, nil)
	})
	if err != nil {
		w.t.Fatalf("assign %s: %v", roleServerBuilders, err)
	}
}

// mountFederationPages mounts the upstream OAuth connect pages, the
// servers portal and the admin pages behind the portal's session and
// admin checks, as cmd/gateway's withFederationPages and
// withFederationAdmin do.
func (w *world) mountFederationPages(p *portal.Portal, session func(*http.Request) (string, string), log *slog.Logger) {
	w.t.Helper()
	fed := w.fed
	user := func(r *http.Request) (string, bool) {
		id, _ := session(r)
		return id, id != ""
	}
	p.MountUser("GET /servers/{id}/connect", fed.Auth.StartConnect(user))
	p.MountUser("GET "+auth.CallbackPath, fed.Auth.Callback(user))
	factory, err := fedportal.NewClientFactory(fedportal.FactoryOptions{
		Credentials: fed.Auth, Tunnels: fed.Tunnels, HTTPClient: fed.Guard.Client(), Log: log,
	})
	if err != nil {
		w.t.Fatal(err)
	}
	identityFn := func(r *http.Request) (string, string, bool) {
		id, csrf := session(r)
		return id, csrf, identity.PrincipalFrom(r.Context()).IsAdmin()
	}
	fedportal.NewPortal(fedportal.Deps{
		Store: fedportal.NewStore(w.st), Snapshots: fed.Snapshots, Auth: fed.Auth, Tunnels: fed.Tunnels,
		ClientFactory: factory, Hook: hookFunc(func(ctx context.Context, id string) { _ = fed.Manager.ServerChanged(ctx, id) }),
		Permissions: fed.Permissions, Policy: w.policy, Identity: identityFn, Audit: w.rec, Log: log, BaseURL: baseURL,
	}).Mount(p.MountUser)
	as := fedadmin.NewStore(w.st)
	fedadmin.NewAdmin(fedadmin.Deps{
		Store: as, Roles: as, Snapshots: fed.Snapshots, Auth: fed.Auth, Tunnels: fed.Tunnels, ClientFactory: factory,
		Hook: fed.Manager, AllowList: fed.AllowList, Identity: identityFn, Audit: w.rec, Log: log,
	}).Mount(p.MountAdmin)
	machines.NewPortal(w.machines, identityFn, log).Mount(func(pattern string, h http.Handler) {
		if strings.Contains(pattern, " /admin/") {
			p.MountAdmin(pattern, h)
			return
		}
		p.MountUser(pattern, h)
	})
}

// mountFederationRoutes mounts the public federation routes (client
// metadata document, tunnel endpoint) like withFederationRoutes.
func (w *world) mountFederationRoutes(mux *http.ServeMux) {
	mux.Handle("GET "+auth.ClientMetadataPath, w.fed.Auth.ClientMetadataDocument())
	mux.Handle(tunnel.ConnectPath, w.fed.Tunnels.Handler())
	w.machines.Mount(mux)
}

type hookFunc func(ctx context.Context, serverID string)

func (f hookFunc) ServerChanged(ctx context.Context, serverID string) { f(ctx, serverID) }

// allowLoopback lets the federation reach the test upstreams (they listen
// on 127.0.0.1): the admin allow-list entry for exactly that address.
func (w *world) allowLoopback() {
	w.t.Helper()
	w.allowHost("127.0.0.1")
}

// allowHost adds an admin allow-list entry and drops the cached list.
func (w *world) allowHost(pattern string) {
	w.t.Helper()
	ctx := w.t.Context()
	err := w.st.WithJobs(ctx, func(tx store.Tx) error {
		return store.CreateNetguardAllowHost(ctx, tx, &store.NetguardAllowHost{Pattern: pattern, Note: "security test"})
	})
	if err != nil {
		w.t.Fatal(err)
	}
	w.fed.AllowList.Invalidate()
}

// addServer creates a private server for owner through the Manager (the
// service-layer path the portal uses), with optional changes first.
func (w *world) addServer(owner user, name, rawURL string, mutate func(*store.MCPServer)) *store.MCPServer {
	w.t.Helper()
	s := &store.MCPServer{
		Name: name, URL: rawURL, OwnerUserID: owner.id,
		CredentialMode: store.MCPCredentialPerUser, AuthKind: store.MCPAuthNone,
	}
	if mutate != nil {
		mutate(s)
	}
	if err := w.fed.Manager.CreateServer(w.t.Context(), s); err != nil {
		w.t.Fatalf("CreateServer %s: %v", name, err)
	}
	return s
}

// factory is the portal's default client factory over the world's
// federation (credentials, netguard, tunnels).
func (w *world) factory() fedportal.ClientFactory {
	w.t.Helper()
	f, err := fedportal.NewClientFactory(fedportal.FactoryOptions{
		Credentials: w.fed.Auth, Tunnels: w.fed.Tunnels, HTTPClient: w.fed.Guard.Client(),
	})
	if err != nil {
		w.t.Fatal(err)
	}
	return f
}

// reviewAs discovers the server as who (the owner, or an admin when
// admin is set; the session uses who's credential) and approves the new
// snapshot with the tools in enable switched on (none when empty), then
// reloads the registry.
func (w *world) reviewAs(who user, admin bool, server *store.MCPServer, enable ...string) {
	w.t.Helper()
	ctx := w.t.Context()
	sess, err := w.factory().Open(ctx, server, who.id)
	if err != nil {
		w.t.Fatalf("open upstream %s: %v", server.Name, err)
	}
	defer func() { _ = sess.Close() }()
	actor := snapshot.Actor{UserID: who.id, Admin: admin}
	rec, _, err := w.fed.Snapshots.Refresh(ctx, actor, server.ID, sess)
	if err != nil {
		w.t.Fatalf("discover %s: %v", server.Name, err)
	}
	d := snapshot.ReviewDecisions{Tools: map[string]snapshot.Decision{}}
	for _, name := range enable {
		on := true
		d.Tools[name] = snapshot.Decision{Enabled: &on}
	}
	// Every resource, template and prompt of the snapshot is enabled
	// (their review toggles, task bdb5zcud, are covered by the e2e and
	// unit tests); the suites here probe what is enabled.
	d.Resources, d.ResourceTemplates, d.Prompts = map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, r := range rec.Snapshot.Resources {
		d.Resources[r.URI] = true
	}
	for _, t := range rec.Snapshot.ResourceTemplates {
		d.ResourceTemplates[t.URITemplate] = true
	}
	for _, p := range rec.Snapshot.Prompts {
		d.Prompts[p.Name] = true
	}
	if _, err := w.fed.Snapshots.Approve(ctx, actor, server.ID, rec.Version, d); err != nil {
		w.t.Fatalf("approve %s: %v", server.Name, err)
	}
	if err := w.fed.Manager.ServerChanged(ctx, server.ID); err != nil {
		w.t.Fatal(err)
	}
}

// review is reviewAs by the owner.
func (w *world) review(owner user, server *store.MCPServer, enable ...string) {
	w.t.Helper()
	w.reviewAs(owner, false, server, enable...)
}

// publish publishes the server to the named roles (an admin action) and
// adds the rules to each role.
func (w *world) publish(server *store.MCPServer, rules []policy.ToolRule, roleNames ...string) {
	w.t.Helper()
	ctx := w.t.Context()
	var ids []string
	err := w.st.WithJobs(ctx, func(tx store.Tx) error {
		for _, n := range roleNames {
			role, err := store.FindRoleByName(ctx, tx, n)
			if err != nil {
				return err
			}
			ids = append(ids, role.ID)
		}
		return store.PublishMCPServer(ctx, tx, server.ID, ids)
	})
	if err != nil {
		w.t.Fatal(err)
	}
	for _, n := range roleNames {
		role, err := w.policy.Role(ctx, n)
		if err != nil {
			w.t.Fatal(err)
		}
		role.Rules = append(role.Rules, rules...)
		if err := w.policy.SaveRole(ctx, w.admin.id, role); err != nil {
			w.t.Fatal(err)
		}
	}
	w.policy.Invalidate()
	if err := w.fed.Manager.ServerChanged(ctx, server.ID); err != nil {
		w.t.Fatal(err)
	}
}

// --- hostile upstreams -------------------------------------------------------------

// captured is one request an upstream received.
type captured struct {
	Method, Path, RawQuery string
	Header                 http.Header
	Body                   string
}

// upstream is an MCP server under test control. build returns the SDK
// server to serve (called per request, so tests can swap behaviour); gate,
// when set, runs first and may answer instead (auth checks, hostile raw
// answers). Every request is captured.
type upstream struct {
	srv   *httptest.Server
	mu    sync.Mutex
	reqs  []captured
	build func(r *http.Request) *sdk.Server
	gate  func(w http.ResponseWriter, r *http.Request) bool
}

func newUpstream(t *testing.T, build func(r *http.Request) *sdk.Server) *upstream {
	t.Helper()
	u := &upstream{build: build}
	h := sdk.NewStreamableHTTPHandler(func(r *http.Request) *sdk.Server {
		u.mu.Lock()
		b := u.build
		u.mu.Unlock()
		return b(r)
	}, &sdk.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(body))
		u.mu.Lock()
		u.reqs = append(u.reqs, captured{Method: r.Method, Path: r.URL.Path, RawQuery: r.URL.RawQuery, Header: r.Header.Clone(), Body: string(body)})
		gate := u.gate
		u.mu.Unlock()
		if gate != nil && gate(w, r) {
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *upstream) URL() string { return u.srv.URL }

func (u *upstream) setGate(g func(w http.ResponseWriter, r *http.Request) bool) {
	u.mu.Lock()
	u.gate = g
	u.mu.Unlock()
}

func (u *upstream) setBuild(b func(r *http.Request) *sdk.Server) {
	u.mu.Lock()
	u.build = b
	u.mu.Unlock()
}

func (u *upstream) reset() {
	u.mu.Lock()
	u.reqs = nil
	u.mu.Unlock()
}

func (u *upstream) requests() []captured {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]captured(nil), u.reqs...)
}

// sawValue reports whether any captured request carries v in a header
// value, the query or the body.
func (u *upstream) sawValue(v string) bool {
	for _, r := range u.requests() {
		if strings.Contains(r.Body, v) || strings.Contains(r.RawQuery, v) {
			return true
		}
		for _, vals := range r.Header {
			for _, hv := range vals {
				if strings.Contains(hv, v) {
					return true
				}
			}
		}
	}
	return false
}

type searchIn struct {
	Q string `json:"q"`
}

type noteIn struct {
	Title string `json:"title"`
}

// notesServer is a plain server: search (read), create_note (write),
// purge (write nobody enables), a resource and a template, a prompt. The
// text answers name the caller's X-Notes-Key.
func notesServer(r *http.Request) *sdk.Server {
	key := r.Header.Get("X-Notes-Key")
	s := sdk.NewServer(&sdk.Implementation{Name: "notes", Version: "1"}, nil)
	sdk.AddTool(s, &sdk.Tool{Name: "search", Description: "Search notes.", Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true}},
		func(context.Context, *sdk.CallToolRequest, searchIn) (*sdk.CallToolResult, any, error) {
			return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "results for " + key}}}, nil, nil
		})
	sdk.AddTool(s, &sdk.Tool{Name: "create_note", Description: "Create a note."},
		func(context.Context, *sdk.CallToolRequest, noteIn) (*sdk.CallToolResult, any, error) {
			return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "created"}}}, nil, nil
		})
	sdk.AddTool(s, &sdk.Tool{Name: "purge", Description: "Delete every note."},
		func(context.Context, *sdk.CallToolRequest, noteIn) (*sdk.CallToolResult, any, error) {
			return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "purged"}}}, nil, nil
		})
	s.AddResource(&sdk.Resource{URI: "notes://readme", Name: "readme", MIMEType: "text/plain"},
		func(_ context.Context, req *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error) {
			return &sdk.ReadResourceResult{Contents: []*sdk.ResourceContents{{URI: req.Params.URI, MIMEType: "text/plain", Text: "readme text"}}}, nil
		})
	s.AddResourceTemplate(&sdk.ResourceTemplate{URITemplate: "notes://note/{id}", Name: "note"},
		func(_ context.Context, req *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error) {
			return &sdk.ReadResourceResult{Contents: []*sdk.ResourceContents{{URI: req.Params.URI, MIMEType: "text/plain", Text: "note " + req.Params.URI}}}, nil
		})
	s.AddPrompt(&sdk.Prompt{Name: "summarize", Description: "Summarize notes."},
		func(context.Context, *sdk.GetPromptRequest) (*sdk.GetPromptResult, error) {
			return &sdk.GetPromptResult{Messages: []*sdk.PromptMessage{{Role: "user", Content: &sdk.TextContent{Text: "summarize"}}}}, nil
		})
	return s
}

// requireKey is a gate answering 401 unless X-Notes-Key is one of keys.
func requireKey(keys ...string) func(w http.ResponseWriter, r *http.Request) bool {
	return func(w http.ResponseWriter, r *http.Request) bool {
		got := r.Header.Get("X-Notes-Key")
		for _, k := range keys {
			if got == k {
				return false
			}
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="notes"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return true
	}
}

// apiKeyServer sets the server to per-user API key auth in X-Notes-Key.
func apiKeyServer(s *store.MCPServer) {
	s.CredentialMode, s.AuthKind = store.MCPCredentialPerUser, store.MCPAuthAPIKey
	s.AuthConfig = []byte(`{"api_key":{"header":"X-Notes-Key"}}`)
}

// rawBody posts one JSON-RPC message to /mcp with the token and returns
// the wire answer.
func (w *world) rawBody(token string, msg any) (int, http.Header, []byte) {
	w.t.Helper()
	body, _ := json.Marshal(msg)
	req, _ := http.NewRequestWithContext(w.t.Context(), http.MethodPost, w.srv.URL+"/mcp", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		w.t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	out, _ := io.ReadAll(res.Body)
	return res.StatusCode, res.Header, out
}
