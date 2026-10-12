package gatewaytools

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/federation/auth"
	"github.com/huynle/mcp-gateway/internal/federation/client"
	fedportal "github.com/huynle/mcp-gateway/internal/federation/portal"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/permissions"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/store"
)

type world struct {
	t       *testing.T
	servers *fakeServers
	mgr     *fakeManager
	snaps   *fakeSnapshots
	det     *fakeDetector
	clients *fakeClients
	perms   *fakePermStore
	gate    *Gate
	conn    *Connector
	reg     *connectors.Registry
}

// newWorld: alice and bob may add servers and switched the tools on.
func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{t: t, servers: newFakeServers(), snaps: newFakeSnapshots(), det: &fakeDetector{results: map[string]*auth.DetectResult{}, errs: map[string]error{}},
		clients: &fakeClients{}, perms: newFakePermStore()}
	w.mgr = &fakeManager{servers: w.servers, permitted: map[string]bool{alice: true, bob: true}}
	w.perms.set(alice, true, true)
	w.perms.set(bob, true, true)
	w.gate = NewGate(permissions.New(w.perms, permissions.Options{}), GateOptions{TTL: time.Nanosecond})
	var err error
	w.conn, err = New(Deps{
		Servers: w.servers, Snapshots: w.snaps, Detector: w.det, Manager: w.mgr, Clients: w.clients,
		URLCheck: fakeChecker{allow: []string{"127.0.0.1"}}, Gate: w.gate, BaseURL: base + "/",
	})
	if err != nil {
		t.Fatal(err)
	}
	w.reg = connectors.NewRegistry()
	if err := w.conn.Register(w.reg); err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *world) call(user, tool string, args map[string]any) (connectors.Result, error) {
	w.t.Helper()
	t, ok := w.reg.Get(App + "." + tool)
	if !ok {
		w.t.Fatalf("tool %s not registered", tool)
	}
	if args == nil {
		args = map[string]any{}
	}
	return t.Handler(w.t.Context(), connectors.Call{Principal: connectors.Principal{UserID: user}, Tool: t.FullName(), Args: args})
}

// ok calls a tool that must succeed and returns its content as JSON.
func (w *world) ok(user, tool string, args map[string]any) map[string]any {
	w.t.Helper()
	res, err := w.call(user, tool, args)
	if err != nil {
		w.t.Fatalf("%s: %v", tool, err)
	}
	b, err := json.Marshal(res.Content)
	if err != nil {
		w.t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		w.t.Fatalf("%s content %s: %v", tool, b, err)
	}
	return out
}

// fail calls a tool that must fail with a classed error and returns it.
func (w *world) fail(user, tool string, args map[string]any) (class, msg string) {
	w.t.Helper()
	_, err := w.call(user, tool, args)
	if err == nil {
		w.t.Fatalf("%s succeeded, want an error", tool)
	}
	var ce mcp.ClassedError
	if !errors.As(err, &ce) {
		w.t.Fatalf("%s error %v is not classed", tool, err)
	}
	if len(err.Error()) > 200 {
		w.t.Errorf("%s error longer than the 200 characters the pipeline keeps: %q", tool, err.Error())
	}
	return ce.ErrorClass(), err.Error()
}

func jsonString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestRegisterTools(t *testing.T) {
	w := newWorld(t)
	want := map[string]connectors.Kind{
		ToolListServers: connectors.KindRead, ToolGetServer: connectors.KindRead, ToolDetectAuth: connectors.KindRead,
		ToolConnectLink: connectors.KindRead, ToolRefreshServer: connectors.KindRead,
		ToolAddServer: connectors.KindWrite, ToolDeleteServer: connectors.KindWrite,
	}
	var got []string
	for _, tool := range w.reg.List() {
		if tool.App != App {
			continue
		}
		got = append(got, tool.Name)
		kind, ok := want[tool.Name]
		if !ok {
			t.Errorf("unexpected tool %s (no list_accounts, approve, publish, allow-list or tunnel tools)", tool.FullName())
			continue
		}
		if tool.Kind != kind {
			t.Errorf("%s kind = %s, want %s", tool.FullName(), tool.Kind, kind)
		}
		if tool.Kind == connectors.KindWrite && tool.Reconcile.Kind != connectors.ReconcileNone {
			t.Errorf("%s reconcile = %q", tool.FullName(), tool.Reconcile.Kind)
		}
		var schema map[string]any
		if err := json.Unmarshal(tool.InputSchema, &schema); err != nil || schema["additionalProperties"] != false {
			t.Errorf("%s schema %s must close additionalProperties", tool.FullName(), tool.InputSchema)
		}
		if !strings.Contains(tool.Description, "browser") {
			t.Errorf("%s description does not send the model to the browser: %q", tool.FullName(), tool.Description)
		}
	}
	if len(got) != len(want) {
		t.Errorf("registered %v, want %d tools", got, len(want))
	}
	add, _ := w.reg.Get(App + "." + ToolAddServer)
	for _, s := range []string{"secret", "never", "review"} {
		if !strings.Contains(strings.ToLower(add.Description), s) {
			t.Errorf("add_server description lacks %q: %q", s, add.Description)
		}
	}
	del, _ := w.reg.Get(App + "." + ToolDeleteServer)
	if !strings.Contains(strings.ToLower(del.Description), "approv") {
		t.Errorf("delete_server description does not mention the approval: %q", del.Description)
	}
	refresh, _ := w.reg.Get(App + "." + ToolRefreshServer)
	if !strings.Contains(strings.ToLower(refresh.Description), "never approves") {
		t.Errorf("refresh_server description: %q", refresh.Description)
	}
}

// The compiled policy (gateway layer) over the registered tools: reads and
// add_server allow, delete_server needs an approval, for a user without
// any role.
func TestPolicyDefaultsForRegisteredTools(t *testing.T) {
	w := newWorld(t)
	c, err := policy.Compile(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range w.reg.List() {
		want := policy.OutcomeAllow
		if tool.Name == ToolDeleteServer {
			want = policy.OutcomeConfirm
		}
		if got := c.Decide(policy.Input{UserID: alice, Tool: tool}).Outcome; got != want {
			t.Errorf("%s = %s, want %s", tool.FullName(), got, want)
		}
	}
}

// With the gate closed a call is answered exactly like an unknown tool,
// even if something reached the handler (defense in depth).
func TestClosedGateCallIsUnknownTool(t *testing.T) {
	w := newWorld(t)
	w.perms.set(alice, true, false)
	for _, name := range []string{ToolListServers, ToolAddServer, ToolDeleteServer} {
		_, err := w.call(alice, name, nil)
		var te *mcp.ToolError
		if !errors.As(err, &te) || te.Message != mcp.ErrToolNotFound(App+"."+name).Message || te.Code != mcp.CodeToolNotFound {
			t.Errorf("%s with the tools off = %v, want the unknown-tool error", name, err)
		}
	}
}

func TestListServers(t *testing.T) {
	w := newWorld(t)
	notes := w.servers.add(store.MCPServer{Name: "notes", URL: "https://notes.example.com/mcp", OwnerUserID: alice,
		AuthKind: store.MCPAuthOAuth, CredentialMode: store.MCPCredentialPerUser})
	w.snaps.approved(notes.ID, 1, []string{"a", "b", "c"}, 2)
	w.snaps.latest[notes.ID] = &snapshot.Record{ServerID: notes.ID, Version: 2}
	team := w.servers.add(store.MCPServer{Name: "team", URL: "https://team.example.com/mcp", OwnerUserID: bob, Audience: store.MCPAudiencePublished,
		AuthKind: store.MCPAuthNone, CredentialMode: store.MCPCredentialPerUser})
	w.servers.sharedWith[team.ID] = []string{alice}
	w.servers.add(store.MCPServer{Name: "bobs", URL: "https://bobs.example.com/mcp", OwnerUserID: bob, AuthKind: store.MCPAuthNone})

	out := w.ok(alice, ToolListServers, nil)
	list, _ := out["servers"].([]any)
	if len(list) != 2 {
		t.Fatalf("alice sees %d servers, want 2: %s", len(list), jsonString(out))
	}
	byName := map[string]map[string]any{}
	for _, s := range list {
		m := s.(map[string]any)
		byName[m["name"].(string)] = m
	}
	if _, ok := byName["bobs"]; ok {
		t.Fatal("alice sees bob's private server")
	}
	n := byName["notes"]
	for k, v := range map[string]any{
		"id": notes.ID, "url_host": "notes.example.com", "audience": "private", "status": "active", "auth_kind": "oauth",
		"credential_mode": "per_user", "connection": "needs connect", "pending_review": true, "approved_tools": float64(2), "owner": true,
	} {
		if n[k] != v {
			t.Errorf("notes.%s = %v, want %v", k, n[k], v)
		}
	}
	links, _ := n["links"].(map[string]any)
	if links["server"] != base+"/servers/"+notes.ID || links["review"] != base+"/servers/"+notes.ID+"/review" ||
		links["connect"] != base+"/servers/"+notes.ID+"/connect" {
		t.Errorf("notes links = %v", links)
	}
	tm := byName["team"]
	if tm["owner"] != false || tm["audience"] != "published" || tm["connection"] != "no connection needed" || tm["approved_tools"] != float64(0) {
		t.Errorf("team = %v", tm)
	}
	if l, _ := tm["links"].(map[string]any); l["review"] != nil || l["connect"] != nil {
		t.Errorf("team (not mine, no connection) links = %v", l)
	}

	// Bob sees his two servers, not alice's private one.
	bobsList, _ := w.ok(bob, ToolListServers, nil)["servers"].([]any)
	if text := jsonString(bobsList); len(bobsList) != 2 || strings.Contains(text, notes.ID) {
		t.Errorf("bob's list = %s", text)
	}
	if class, _ := w.fail(bob, ToolGetServer, map[string]any{"server": notes.ID}); class != "server_not_found" {
		t.Errorf("bob reads alice's server: %s", class)
	}
}

func TestGetServerNextSteps(t *testing.T) {
	w := newWorld(t)
	oauth := w.servers.add(store.MCPServer{Name: "oauthy", URL: "https://o.example.com/mcp", OwnerUserID: alice, AuthKind: store.MCPAuthOAuth, CredentialMode: store.MCPCredentialPerUser})
	key := w.servers.add(store.MCPServer{Name: "keyed", URL: "https://k.example.com/mcp", OwnerUserID: alice, AuthKind: store.MCPAuthAPIKey, CredentialMode: store.MCPCredentialPerUser,
		AuthConfig: json.RawMessage(`{"api_key":{"header":"X-Key"}}`)})
	shared := w.servers.add(store.MCPServer{Name: "shared", URL: "https://s.example.com/mcp", OwnerUserID: alice, AuthKind: store.MCPAuthBearer, CredentialMode: store.MCPCredentialShared})
	pending := w.servers.add(store.MCPServer{Name: "pending", URL: "https://p.example.com/mcp", OwnerUserID: alice, AuthKind: store.MCPAuthNone, CredentialMode: store.MCPCredentialPerUser})
	w.snaps.latest[pending.ID] = &snapshot.Record{ServerID: pending.ID, Version: 1}

	steps := func(server string) string {
		out := w.ok(alice, ToolGetServer, map[string]any{"server": server})
		return jsonString(out["next_steps"])
	}
	if s := steps("oauthy"); !strings.Contains(s, base+"/servers/"+oauth.ID+"/connect") || !strings.Contains(s, "refresh_server") {
		t.Errorf("oauth next steps = %s", s)
	}
	if s := steps(key.ID); !strings.Contains(s, base+"/servers/"+key.ID+"#connection") || !strings.Contains(s, "browser") {
		t.Errorf("api key next steps = %s", s)
	}
	if s := steps("shared"); !strings.Contains(s, base+"/servers/"+shared.ID+"/edit") || !strings.Contains(strings.ToLower(s), "shared") {
		t.Errorf("shared next steps = %s", s)
	}
	if s := steps("pending"); !strings.Contains(s, base+"/servers/"+pending.ID+"/review") {
		t.Errorf("pending next steps = %s", s)
	}
	out := w.ok(alice, ToolGetServer, map[string]any{"server": "keyed"})
	if out["api_key_placement"] != "header X-Key" {
		t.Errorf("api key placement = %v", out["api_key_placement"])
	}
}

// Another user's private server is "not found" by name and by id, worded
// exactly like a server that does not exist.
func TestOtherUsersServerNotFound(t *testing.T) {
	w := newWorld(t)
	bobs := w.servers.add(store.MCPServer{Name: "bobs", URL: "https://bobs.example.com/mcp", OwnerUserID: bob, AuthKind: store.MCPAuthNone})
	missingID := connectors.NewAccountID()
	for _, tool := range []string{ToolGetServer, ToolConnectLink, ToolRefreshServer, ToolDeleteServer} {
		for _, pair := range [][2]string{{"bobs", "nosuch"}, {bobs.ID, missingID}} {
			c1, m1 := w.fail(alice, tool, map[string]any{"server": pair[0]})
			c2, m2 := w.fail(alice, tool, map[string]any{"server": pair[1]})
			if c1 != "server_not_found" || c1 != c2 || strings.ReplaceAll(m1, pair[0], "X") != strings.ReplaceAll(m2, pair[1], "X") {
				t.Errorf("%s: bob's %q = %s %q; missing %q = %s %q", tool, pair[0], c1, m1, pair[1], c2, m2)
			}
		}
	}
	if len(w.servers.deleted) != 0 || len(w.clients.opened) != 0 {
		t.Error("something happened to bob's server")
	}
}

// Owner-only tools refuse a server that is visible but not owned
// (published to the caller) like one that does not exist.
func TestOwnerOnlyTools(t *testing.T) {
	w := newWorld(t)
	team := w.servers.add(store.MCPServer{Name: "team", URL: "https://team.example.com/mcp", OwnerUserID: bob, Audience: store.MCPAudiencePublished, AuthKind: store.MCPAuthNone})
	w.servers.sharedWith[team.ID] = []string{alice}
	for _, tool := range []string{ToolRefreshServer, ToolDeleteServer} {
		if class, _ := w.fail(alice, tool, map[string]any{"server": "team"}); class != "server_not_found" {
			t.Errorf("%s on a published server I do not own = %s", tool, class)
		}
	}
	// Reading it is fine.
	w.ok(alice, ToolGetServer, map[string]any{"server": "team"})
	if len(w.servers.deleted) != 0 || len(w.snaps.refreshes) != 0 {
		t.Error("owner-only tool acted on someone else's server")
	}
}

func TestDetectAuth(t *testing.T) {
	w := newWorld(t)
	u := "https://mcp.example.com/mcp"
	w.det.results[u] = &auth.DetectResult{AuthKinds: []string{store.MCPAuthOAuth, store.MCPAuthAPIKey}, SupportsDCR: true, SupportsCIMD: false,
		SupportsS256: true, Scopes: []string{"read", "write"}}
	out := w.ok(alice, ToolDetectAuth, map[string]any{"url": u})
	if jsonString(out["auth_kinds"]) != `["oauth","api_key"]` || out["dcr"] != true || out["cimd"] != false || jsonString(out["scopes"]) != `["read","write"]` {
		t.Errorf("detect = %s", jsonString(out))
	}

	// Failures are class-level messages, as on the portal.
	w.det.errs["https://blocked.example.com/mcp"] = &client.Error{Class: client.ClassBlocked, Op: "connect"}
	class, msg := w.fail(alice, ToolDetectAuth, map[string]any{"url": "https://blocked.example.com/mcp"})
	if class != "upstream_blocked" || !strings.Contains(msg, "SSRF") {
		t.Errorf("blocked detect = %s %q", class, msg)
	}
	w.det.errs["https://bad.example.com/mcp"] = fmt.Errorf("wrapped: %w", auth.ErrInvalidServerURL)
	if _, msg := w.fail(alice, ToolDetectAuth, map[string]any{"url": "https://bad.example.com/mcp"}); msg != fedportal.DetectMessage(auth.ErrInvalidServerURL) {
		t.Errorf("invalid URL detect = %q", msg)
	}

	// Refused before any request: not https, credentials in the URL, a
	// blocked literal address (SSRF), a secret in the query.
	calls := len(w.det.calls)
	for _, bad := range []string{"http://mcp.example.com/mcp", "https://u:p@mcp.example.com/", "https://169.254.169.254/latest/meta-data",
		"https://[::1]/mcp", "https://mcp.example.com/mcp?api_key=abc123"} {
		w.fail(alice, ToolDetectAuth, map[string]any{"url": bad})
	}
	if len(w.det.calls) != calls {
		t.Errorf("detector called for refused URLs: %v", w.det.calls[calls:])
	}
}

func TestAddServer(t *testing.T) {
	w := newWorld(t)
	out := w.ok(alice, ToolAddServer, map[string]any{"name": "notes", "url": "https://notes.example.com/mcp", "auth_kind": "oauth", "credential_mode": "per_user"})
	if len(w.mgr.created) != 1 {
		t.Fatalf("created %d servers", len(w.mgr.created))
	}
	s := w.mgr.created[0]
	if s.OwnerUserID != alice || s.Name != "notes" || s.AuthKind != store.MCPAuthOAuth || s.CredentialMode != store.MCPCredentialPerUser || s.Transport != store.MCPTransportAuto {
		t.Errorf("created %+v", s)
	}
	srv, _ := out["server"].(map[string]any)
	if srv["id"] != s.ID || srv["audience"] != "private" {
		t.Errorf("result server = %v", srv)
	}
	text := jsonString(out)
	for _, want := range []string{base + "/servers/" + s.ID + "/connect", "refresh_server", base + "/servers/" + s.ID + "/review"} {
		if !strings.Contains(text, want) {
			t.Errorf("add result lacks %q: %s", want, text)
		}
	}

	// API key per user, placed in a header, plus per-user header names.
	out = w.ok(alice, ToolAddServer, map[string]any{"name": "keyed", "url": "https://k.example.com/mcp", "auth_kind": "api_key", "credential_mode": "per_user",
		"api_key_in": "header", "api_key_name": "X-Key", "static_header_names": []any{"X-Tenant"}})
	s = w.mgr.created[1]
	if string(s.AuthConfig) != `{"api_key":{"header":"X-Key"}}` || string(s.HeaderConfig) != `{"per_user":["X-Tenant"]}` {
		t.Errorf("keyed config = %s %s", s.AuthConfig, s.HeaderConfig)
	}
	if !strings.Contains(jsonString(out), base+"/servers/"+s.ID+"#connection") {
		t.Errorf("api key result lacks the credential page: %s", jsonString(out))
	}
	// API key in a query parameter.
	w.ok(alice, ToolAddServer, map[string]any{"name": "queried", "url": "https://q.example.com/mcp", "auth_kind": "api_key", "credential_mode": "per_user",
		"api_key_in": "query", "api_key_name": "apikey"})
	if s = w.mgr.created[2]; string(s.AuthConfig) != `{"api_key":{"query":"apikey"}}` {
		t.Errorf("query config = %s", s.AuthConfig)
	}

	// Shared bearer: the secret is set on the portal.
	out = w.ok(alice, ToolAddServer, map[string]any{"name": "sharedb", "url": "https://s.example.com/mcp", "auth_kind": "bearer", "credential_mode": "shared"})
	s = w.mgr.created[3]
	if text := jsonString(out); !strings.Contains(text, base+"/servers/"+s.ID+"/edit") || !strings.Contains(strings.ToLower(text), "shared credential") {
		t.Errorf("shared result = %s", text)
	}
	// none: per_user whatever was asked.
	w.ok(alice, ToolAddServer, map[string]any{"name": "open", "url": "https://open.example.com/mcp", "auth_kind": "none", "credential_mode": "shared"})
	if s = w.mgr.created[4]; s.CredentialMode != store.MCPCredentialPerUser {
		t.Errorf("auth none credential mode = %s", s.CredentialMode)
	}
	if w.snaps.approves != 0 {
		t.Error("adding a server approved something")
	}
}

// No argument may carry a secret: secret-looking names, Authorization
// headers, tokens in values or in the URL are refused before anything is
// created, with a pointer to the browser.
func TestAddServerRejectsSecrets(t *testing.T) {
	w := newWorld(t)
	good := func(extra map[string]any) map[string]any {
		args := map[string]any{"name": "notes", "url": "https://notes.example.com/mcp", "auth_kind": "api_key", "credential_mode": "per_user"}
		for k, v := range extra {
			args[k] = v
		}
		return args
	}
	for _, tc := range []map[string]any{
		{"api_key": "abc123"},
		{"key": "abc123"},
		{"token": "abc123"},
		{"access_token": "abc"},
		{"secret": "abc"},
		{"client_secret": "abc"},
		{"password": "hunter2"},
		{"authorization": "Bearer abc"},
		{"headers": map[string]any{"Authorization": "Bearer abc"}},
		{"Authorization": "Bearer abc"},
		{"bearer": "abc"},
		{"credential": "abc"},
		{"url": "https://notes.example.com/mcp?api_key=abc123"},
		{"url": "https://notes.example.com/mcp?token=abc123"},
		{"url": "https://alice:pw@notes.example.com/mcp"},
		{"static_header_names": []any{"Authorization: Bearer abc"}},
		{"static_header_names": []any{"X-Api-Key=abc"}},
		{"api_key_name": "ghp_abcdefghijklmnopqrstuvwxyz0123"},
		{"name": "ghp_abcdefghijklmnopqrstuvwxyz0123"},
	} {
		class, msg := w.fail(alice, ToolAddServer, good(tc))
		if class != "secret_refused" || !strings.Contains(msg, "browser") {
			t.Errorf("%v = %s %q, want secret_refused pointing to the browser", tc, class, msg)
		}
		if strings.Contains(msg, "abc123") || strings.Contains(msg, "hunter2") {
			t.Errorf("%v: the error echoes the secret: %q", tc, msg)
		}
	}
	// An unknown, harmless argument is an argument error, not a secret.
	if class, _ := w.fail(alice, ToolAddServer, good(map[string]any{"colour": "blue"})); class != "args_invalid" {
		t.Errorf("unknown argument = %s", class)
	}
	if len(w.mgr.created) != 0 {
		t.Errorf("servers created despite refused arguments: %d", len(w.mgr.created))
	}
}

func TestAddServerValidation(t *testing.T) {
	w := newWorld(t)
	tunnelID, bobsTunnel, revoked := connectors.NewAccountID(), connectors.NewAccountID(), connectors.NewAccountID()
	now := time.Now()
	w.servers.tunnels[alice] = []store.MCPTunnel{{ID: tunnelID, Name: "laptop"}, {ID: revoked, Name: "old", RevokedAt: &now}}
	w.servers.tunnels[bob] = []store.MCPTunnel{{ID: bobsTunnel, Name: "bobs"}}
	args := func(name, u, kind, mode string) map[string]any {
		return map[string]any{"name": name, "url": u, "auth_kind": kind, "credential_mode": mode}
	}
	for _, tc := range []struct {
		args  map[string]any
		class string
	}{
		{args("gateway", "https://x.example.com/mcp", "none", "per_user"), "name_invalid"},
		{args("github", "https://x.example.com/mcp", "none", "per_user"), "name_invalid"},
		{args("mcp", "https://x.example.com/mcp", "none", "per_user"), "name_invalid"},
		{args("Bad Name", "https://x.example.com/mcp", "none", "per_user"), "name_invalid"},
		{args("plain", "http://x.example.com/mcp", "none", "per_user"), "url_invalid"},
		{args("meta", "https://169.254.169.254/latest", "none", "per_user"), "upstream_blocked"},
		{args("local", "https://localhost/mcp", "none", "per_user"), "upstream_blocked"},
		{args("bobtun", "tunnel://"+bobsTunnel+"/mcp", "none", "per_user"), "url_invalid"},
		{args("oldtun", "tunnel://"+revoked+"/mcp", "none", "per_user"), "url_invalid"},
		{args("kinds", "https://x.example.com/mcp", "magic", "per_user"), "args_invalid"},
		{args("modes", "https://x.example.com/mcp", "api_key", "everyone"), "args_invalid"},
		{args("soauth", "https://x.example.com/mcp", "oauth", "shared"), "args_invalid"},
		{map[string]any{"name": "missing", "auth_kind": "none", "credential_mode": "per_user"}, "args_invalid"},
		{map[string]any{"name": "keyplace", "url": "https://x.example.com/mcp", "auth_kind": "bearer", "credential_mode": "per_user", "api_key_in": "header", "api_key_name": "X-Key"}, "args_invalid"},
		{map[string]any{"name": "keyhdr", "url": "https://x.example.com/mcp", "auth_kind": "api_key", "credential_mode": "per_user", "api_key_in": "header", "api_key_name": "Content-Type"}, "args_invalid"},
		{map[string]any{"name": "hdrs", "url": "https://x.example.com/mcp", "auth_kind": "none", "credential_mode": "per_user", "static_header_names": []any{"Host"}}, "args_invalid"},
	} {
		if class, msg := w.fail(alice, ToolAddServer, tc.args); class != tc.class {
			t.Errorf("%v = %s %q, want %s", tc.args, class, msg, tc.class)
		}
	}
	if len(w.mgr.created) != 0 {
		t.Fatalf("invalid servers created: %d", len(w.mgr.created))
	}
	// Own live tunnel; an allow-listed loopback host.
	w.ok(alice, ToolAddServer, args("laptop", "tunnel://"+tunnelID+"/mcp", "none", "per_user"))
	w.ok(alice, ToolAddServer, args("loop", "https://127.0.0.1:8443/mcp", "none", "per_user"))
	if len(w.mgr.created) != 2 || w.mgr.created[0].URL != "tunnel://"+tunnelID+"/mcp" {
		t.Errorf("created = %+v", w.mgr.created)
	}
	// Name taken; not permitted.
	if class, _ := w.fail(alice, ToolAddServer, args("laptop", "https://y.example.com/mcp", "none", "per_user")); class != "name_taken" {
		t.Errorf("duplicate name = %s", class)
	}
	w.mgr.permitted[alice] = false
	if class, _ := w.fail(alice, ToolAddServer, args("later", "https://y.example.com/mcp", "none", "per_user")); class != "not_permitted" {
		t.Errorf("not permitted = %s", class)
	}
}

func TestRefreshServer(t *testing.T) {
	w := newWorld(t)
	s := w.servers.add(store.MCPServer{Name: "notes", URL: "https://notes.example.com/mcp", OwnerUserID: alice, AuthKind: store.MCPAuthNone})
	w.snaps.approved(s.ID, 1, []string{"keep"}, 1)
	var added []string
	for i := range 30 {
		added = append(added, fmt.Sprintf("tool_%02d", i))
	}
	w.snaps.nextDiff = snapshot.Diff{FromVersion: 1, Added: added, Removed: []string{"gone"},
		Changed: []snapshot.ToolChange{{Name: "keep", Fields: []string{"description"}}}}
	out := w.ok(alice, ToolRefreshServer, map[string]any{"server": "notes"})
	if len(w.clients.opened) != 1 || w.clients.as[0] != alice {
		t.Errorf("session opened %v as %v, want once as alice", w.clients.opened, w.clients.as)
	}
	if len(w.snaps.refreshBy) != 1 || w.snaps.refreshBy[0].UserID != alice || w.snaps.refreshBy[0].Admin {
		t.Errorf("refresh actor = %+v", w.snaps.refreshBy)
	}
	addedOut, _ := out["added"].(map[string]any)
	if addedOut["count"] != float64(30) || len(addedOut["names"].([]any)) != maxDiffNames || addedOut["truncated"] != true {
		t.Errorf("added = %v", addedOut)
	}
	if ch, _ := out["changed"].(map[string]any); ch["count"] != float64(1) || jsonString(ch["names"]) != `["keep"]` {
		t.Errorf("changed = %v", ch)
	}
	if rm, _ := out["removed"].(map[string]any); rm["count"] != float64(1) {
		t.Errorf("removed = %v", rm)
	}
	if out["review_link"] != base+"/servers/"+s.ID+"/review" || out["to_version"] != float64(2) {
		t.Errorf("refresh = %s", jsonString(out))
	}
	// It never approves: nothing approved, the approved version stays.
	if w.snaps.approves != 0 {
		t.Error("refresh approved")
	}
	if cur, _ := w.snaps.Current(t.Context(), snapshot.Actor{UserID: alice}, s.ID); cur.Version != 1 {
		t.Errorf("approved version = %d after refresh", cur.Version)
	}

	// A refresh that needs a connection first says so, with the link.
	w.clients.err = auth.ErrNotConnected
	class, msg := w.fail(alice, ToolRefreshServer, map[string]any{"server": s.ID})
	if class != "refresh_failed" || !strings.Contains(msg, "Connect to the server first") || !strings.Contains(msg, base+"/servers/"+s.ID) {
		t.Errorf("not connected = %s %q", class, msg)
	}
}

func TestConnectLink(t *testing.T) {
	w := newWorld(t)
	o := w.servers.add(store.MCPServer{Name: "o", URL: "https://o.example.com/mcp", OwnerUserID: alice, AuthKind: store.MCPAuthOAuth, CredentialMode: store.MCPCredentialPerUser})
	k := w.servers.add(store.MCPServer{Name: "k", URL: "https://k.example.com/mcp", OwnerUserID: alice, AuthKind: store.MCPAuthBearer, CredentialMode: store.MCPCredentialPerUser})
	n := w.servers.add(store.MCPServer{Name: "n", URL: "https://n.example.com/mcp", OwnerUserID: alice, AuthKind: store.MCPAuthNone, CredentialMode: store.MCPCredentialPerUser})
	w.servers.conns[alice] = []store.MCPUserConnection{{ServerID: o.ID, UserID: alice, Status: store.MCPConnectionNeedsReconnect}}
	if out := w.ok(alice, ToolConnectLink, map[string]any{"server": "o"}); out["link"] != base+"/servers/"+o.ID+"/connect" || out["connection"] != "needs reconnect" {
		t.Errorf("oauth = %v", out)
	}
	if out := w.ok(alice, ToolConnectLink, map[string]any{"server": "k"}); out["link"] != base+"/servers/"+k.ID+"#connection" {
		t.Errorf("bearer = %v", out)
	}
	if out := w.ok(alice, ToolConnectLink, map[string]any{"server": "n"}); out["link"] != base+"/servers/"+n.ID || out["connection"] != "no connection needed" {
		t.Errorf("none = %v", out)
	}
}

func TestDeleteServer(t *testing.T) {
	w := newWorld(t)
	s := w.servers.add(store.MCPServer{Name: "notes", URL: "https://notes.example.com/mcp", OwnerUserID: alice, AuthKind: store.MCPAuthNone})
	res, err := w.call(alice, ToolDeleteServer, map[string]any{"server": "notes"})
	if err != nil {
		t.Fatal(err)
	}
	if len(w.servers.deleted) != 1 || w.servers.deleted[0] != s.ID {
		t.Fatalf("deleted = %v", w.servers.deleted)
	}
	if len(w.mgr.changed) != 1 || w.mgr.changed[0] != s.ID {
		t.Errorf("ServerChanged after delete = %v", w.mgr.changed)
	}
	tool, _ := w.reg.Get(App + "." + ToolDeleteServer)
	if ids := tool.ResultIDs(res); ids["server_id"] != s.ID {
		t.Errorf("result ids = %v", ids)
	}
	if id := tool.ResourceIdentity(map[string]any{"server": "notes"}); id["server"] != "notes" {
		t.Errorf("resource identity = %v", id)
	}
	// A value that is not a server name or id never reaches the audit row.
	if id := tool.ResourceIdentity(map[string]any{"server": "Bearer abc def"}); id["server"] == "Bearer abc def" {
		t.Errorf("resource identity echoes an arbitrary value: %v", id)
	}
}
