//go:build integration || e2e || security

package security

// Cross-user attacks on user-added servers: a private server's tools,
// resources, prompts and tunnel are invisible and unusable to everyone
// else; every {id} route of the servers portal and the admin pages
// refuses another user (and non-admins) exactly like an unknown id, with
// no state change.

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/federation/auth"
	"github.com/huynle/mcp-gateway/internal/federation/tunnel"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

func randomUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// TestSecurityFedPrivateServerInvisibleOnMCP: bob cannot see or use
// alice's private server through /mcp: tools/list, resources/list,
// resources/templates/list and prompts/list show nothing of it; calling
// a tool, reading a resource (listed URI or template expansion) and
// getting a prompt answer exactly like a server that does not exist. The
// upstream never hears from bob.
func TestSecurityFedPrivateServerInvisibleOnMCP(t *testing.T) {
	w := newWorld(t, options{federation: true})
	ctx := t.Context()
	w.allowLoopback()
	up := newUpstream(t, notesServer)
	s := w.addServer(w.alice, "secretnotes", up.URL(), nil)
	w.review(w.alice, s, "search", "create_note")
	alice := w.client(w.alice)
	if names := toolNames(t, alice); !contains(names, "secretnotes.search") {
		t.Fatalf("alice's tools = %v", names)
	}
	up.reset()

	bob := w.client(w.bob)
	for _, n := range toolNames(t, bob) {
		if strings.HasPrefix(n, "secretnotes.") {
			t.Errorf("bob lists %s", n)
		}
	}
	rl, err := bob.ListResources(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rl.Resources {
		if strings.Contains(r.URI, "secretnotes") {
			t.Errorf("bob lists resource %s", r.URI)
		}
	}
	tl, err := bob.ListResourceTemplates(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range tl.ResourceTemplates {
		if strings.Contains(r.URITemplate, "secretnotes") {
			t.Errorf("bob lists template %s", r.URITemplate)
		}
	}
	pl, err := bob.ListPrompts(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pl.Prompts {
		if strings.HasPrefix(p.Name, "secretnotes.") {
			t.Errorf("bob lists prompt %s", p.Name)
		}
	}

	// Calls compare byte for byte (minus the id and the name itself)
	// with a server that does not exist.
	bobTok := w.token(w.bob, tokens.CreateRequest{})
	wire := func(method string, params map[string]any) string {
		_, _, b := w.rawRPC(bobTok, method, params)
		return stripID(b)
	}
	same := func(what, a, b string) {
		if a != b {
			t.Errorf("%s differs from a nonexistent server:\n  private: %s\n  unknown: %s", what, a, b)
		}
	}
	same("tools/call",
		strings.ReplaceAll(wire("tools/call", map[string]any{"name": "secretnotes.search", "arguments": map[string]any{"q": "x"}}), "secretnotes", "S"),
		strings.ReplaceAll(wire("tools/call", map[string]any{"name": "nosuchsrv.search", "arguments": map[string]any{"q": "x"}}), "nosuchsrv", "S"))
	same("resources/read",
		strings.ReplaceAll(wire("resources/read", map[string]any{"uri": "mcpgw://secretnotes/notes://readme"}), "secretnotes", "S"),
		strings.ReplaceAll(wire("resources/read", map[string]any{"uri": "mcpgw://nosuchsrv/notes://readme"}), "nosuchsrv", "S"))
	same("resources/read (template)",
		strings.ReplaceAll(wire("resources/read", map[string]any{"uri": "mcpgw://secretnotes/notes://note/1"}), "secretnotes", "S"),
		strings.ReplaceAll(wire("resources/read", map[string]any{"uri": "mcpgw://nosuchsrv/notes://note/1"}), "nosuchsrv", "S"))
	same("prompts/get",
		strings.ReplaceAll(wire("prompts/get", map[string]any{"name": "secretnotes.summarize"}), "secretnotes", "S"),
		strings.ReplaceAll(wire("prompts/get", map[string]any{"name": "nosuchsrv.summarize"}), "nosuchsrv", "S"))
	if n := len(up.requests()); n != 0 {
		t.Errorf("the private upstream received %d requests from bob's attempts", n)
	}
}

// rawRPC posts one JSON-RPC request to /mcp with the token.
func (w *world) rawRPC(token, method string, params map[string]any) (int, http.Header, []byte) {
	w.t.Helper()
	return w.rawBody(token, map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
}

// TestSecurityFedPortalIDOR: every {id} route of the servers portal, as
// bob, on alice's private server answers exactly like a random id (404,
// same page), and nothing changes: the server, its credential, alice's
// connection and alice's tunnel are intact, bob stores nothing. On a
// server published to bob, owner-only routes are 404 too and the review
// is refused (an admin's job).
func TestSecurityFedPortalIDOR(t *testing.T) {
	w := newWorld(t, options{federation: true})
	ctx := t.Context()
	w.allowLoopback()
	up := newUpstream(t, notesServer)
	up.setGate(requireKey("alice-idor-key"))
	w.forbid("alice-idor-key", "upstream API key")
	s := w.addServer(w.alice, "idornotes", up.URL(), apiKeyServer)
	if err := w.fed.Auth.SetUserCredential(ctx, w.alice.id, s.ID, auth.Credential{APIKey: "alice-idor-key"}); err != nil {
		t.Fatal(err)
	}
	w.review(w.alice, s, "search")
	tun, raw, err := w.fed.Tunnels.CreateTunnel(ctx, w.alice.id, "alice-laptop")
	if err != nil {
		t.Fatal(err)
	}
	w.forbid(raw, "tunnel token")
	up.reset()

	routes := []struct {
		method, path string
		form         url.Values
	}{
		{"GET", "/servers/%s", nil},
		{"POST", "/servers/%s/credential", url.Values{"api_key": {"bob-planted-key"}}},
		{"POST", "/servers/%s/disconnect", nil},
		{"POST", "/servers/%s/refresh", nil},
		{"GET", "/servers/%s/review", nil},
		{"POST", "/servers/%s/review", url.Values{"version": {"1"}, "enable": {"0", "1", "2"}}},
		{"GET", "/servers/%s/resources", nil},
		{"POST", "/servers/%s/resources/read", url.Values{"uri": {"notes://readme"}}},
		{"GET", "/servers/%s/prompts/summarize", nil},
		{"POST", "/servers/%s/prompts/summarize", nil},
		{"GET", "/servers/%s/edit", nil},
		{"POST", "/servers/%s/edit", url.Values{"url_mode": {"https"}, "url": {"https://evil.example/mcp"}, "auth_kind": {"none"}}},
		{"POST", "/servers/%s/delete", nil},
	}
	do := func(method, path string, form url.Values) (int, string) {
		if method == "GET" {
			code, _, body := w.get(w.bob, path)
			return code, body
		}
		code, _, body := w.post(w.bob, path, form)
		return code, body
	}
	random := randomUUID()
	for _, r := range routes {
		code, body := do(r.method, fmt.Sprintf(r.path, s.ID), r.form)
		rcode, rbody := do(r.method, fmt.Sprintf(r.path, random), r.form)
		if code != http.StatusNotFound || code != rcode || body != rbody {
			t.Errorf("%s %s as bob = %d, random id = %d (bodies equal: %v)", r.method, r.path, code, rcode, body == rbody)
		}
	}
	// The upstream OAuth connect route of the auth service.
	if code, _, _ := w.get(w.bob, "/servers/"+s.ID+"/connect"); code != http.StatusNotFound {
		t.Errorf("GET /servers/{id}/connect as bob = %d, want 404", code)
	}
	// Bob revoking alice's tunnel through his own tunnel form.
	if code, _, _ := w.post(w.bob, "/servers/tunnels/revoke", url.Values{"id": {tun.ID}}); code == http.StatusOK || code == http.StatusSeeOther {
		if w.queryString(`SELECT (revoked_at IS NULL)::text FROM mcp_tunnels WHERE id = $1`, tun.ID) != "true" {
			t.Error("bob revoked alice's tunnel")
		}
	}
	if w.queryString(`SELECT (revoked_at IS NULL)::text FROM mcp_tunnels WHERE id = $1`, tun.ID) != "true" {
		t.Error("alice's tunnel was revoked by bob's attempts")
	}
	if got := w.queryString(`SELECT url FROM mcp_servers WHERE id = $1`, s.ID); got != up.URL() {
		t.Errorf("alice's server URL = %q after bob's attempts", got)
	}
	if got := w.queryString(`SELECT count(*)::text FROM mcp_server_user_connections WHERE user_id = $1`, w.bob.id); got != "0" {
		t.Errorf("bob has %s connection rows", got)
	}
	if got := w.queryString(`SELECT status FROM mcp_server_user_connections WHERE user_id = $1 AND server_id = $2`, w.alice.id, s.ID); got != store.MCPConnectionActive {
		t.Errorf("alice's connection = %q", got)
	}
	if n := len(up.requests()); n != 0 {
		t.Errorf("the upstream received %d requests from bob's attempts", n)
	}

	// Published to bob's role: visible, but owner-only routes stay 404
	// and the review is the admin's.
	w.publish(s, []policy.ToolRule{{App: "idornotes", Tool: "search", Outcome: policy.OutcomeAllow}}, roleRestricted)
	if code, _, _ := w.get(w.bob, "/servers/"+s.ID); code != http.StatusOK {
		t.Fatalf("published server detail as bob = %d", code)
	}
	for _, r := range []string{"/servers/%s/edit", "/servers/%s/delete", "/servers/%s/refresh"} {
		if code, _, _ := w.post(w.bob, fmt.Sprintf(r, s.ID), url.Values{"url_mode": {"https"}, "url": {"https://evil.example/"}, "auth_kind": {"none"}}); code != http.StatusNotFound {
			t.Errorf("POST %s on a published server as bob = %d, want 404", r, code)
		}
	}
	before := w.queryString(`SELECT review::text FROM mcp_server_snapshots WHERE server_id = $1 AND status = 'approved'`, s.ID)
	if code, _, _ := w.post(w.bob, "/servers/"+s.ID+"/review", url.Values{"version": {"1"}, "enable": {"0", "1", "2"}}); code != http.StatusForbidden && code != http.StatusConflict {
		t.Errorf("review of a published server by bob = %d", code)
	}
	if code, _, _ := w.post(w.alice, "/servers/"+s.ID+"/review", url.Values{"version": {"1"}, "enable": {"0", "1", "2"}}); code != http.StatusForbidden && code != http.StatusConflict {
		t.Errorf("review of a published server by its owner = %d (published review is admin-only)", code)
	}
	if after := w.queryString(`SELECT review::text FROM mcp_server_snapshots WHERE server_id = $1 AND status = 'approved'`, s.ID); after != before {
		t.Errorf("the published review changed:\n%s\n%s", before, after)
	}
}

// TestSecurityFedAdminRoutesRefuseMembers: every /admin route of the
// plugins admin pages answers a member with the portal's 404 (routes not
// revealed) and changes nothing; POSTs without the CSRF token are refused
// for admins too.
func TestSecurityFedAdminRoutesRefuseMembers(t *testing.T) {
	w := newWorld(t, options{federation: true})
	ctx := t.Context()
	w.allowLoopback()
	up := newUpstream(t, notesServer)
	s := w.addServer(w.alice, "adminnotes", up.URL(), nil)
	w.review(w.alice, s, "search")
	tun, raw, err := w.fed.Tunnels.CreateTunnel(ctx, w.alice.id, "alice-laptop")
	if err != nil {
		t.Fatal(err)
	}
	w.forbid(raw, "tunnel token")
	hostID := w.queryString(`SELECT id::text FROM netguard_allow_hosts LIMIT 1`)
	roleID := w.queryString(`SELECT id::text FROM roles WHERE name = $1`, roleRestricted)
	gets := []string{"/admin/servers", "/admin/servers/reviews", "/admin/servers/" + s.ID, "/admin/servers/" + s.ID + "/review", "/admin/tunnels", "/admin/network/allow-hosts"}
	posts := map[string]url.Values{
		"/admin/servers/" + s.ID + "/publish":              {"role": {roleID}, "roles": {roleID}},
		"/admin/servers/" + s.ID + "/unpublish":            nil,
		"/admin/servers/" + s.ID + "/shared-credential":    {"api_key": {"planted"}},
		"/admin/servers/" + s.ID + "/static-client":        {"client_id": {"planted"}, "client_secret": {"planted"}},
		"/admin/servers/" + s.ID + "/disable":              nil,
		"/admin/servers/" + s.ID + "/enable":               nil,
		"/admin/servers/" + s.ID + "/delete":               {"confirm": {"adminnotes"}},
		"/admin/servers/" + s.ID + "/refresh":              nil,
		"/admin/servers/" + s.ID + "/review":               {"version": {"1"}, "enable": {"0", "1", "2"}},
		"/admin/tunnels/" + tun.ID + "/revoke":             nil,
		"/admin/network/allow-hosts":                       {"pattern": {"10.0.0.0/8"}, "note": {"planted"}},
		"/admin/network/allow-hosts/" + hostID + "/delete": nil,
	}
	_, _, notFound := w.get(w.bob, "/admin/no-such-page")
	for _, p := range gets {
		if code, _, body := w.get(w.bob, p); code != http.StatusNotFound || body != notFound {
			t.Errorf("GET %s as a member = %d (same 404 page: %v)", p, code, body == notFound)
		}
	}
	for p, form := range posts {
		if code, _, _ := w.post(w.bob, p, form); code != http.StatusNotFound {
			t.Errorf("POST %s as a member = %d, want 404", p, code)
		}
	}
	// Admin without the CSRF token.
	for p, form := range posts {
		if form == nil {
			form = url.Values{}
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, w.srv.URL+p, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(w.admin.cookie)
		res, err := noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		if res.StatusCode != http.StatusForbidden {
			t.Errorf("POST %s as admin without CSRF = %d, want 403", p, res.StatusCode)
		}
	}
	if got := w.queryString(`SELECT audience || '/' || status FROM mcp_servers WHERE id = $1`, s.ID); got != "private/active" {
		t.Errorf("server state after the attempts = %s", got)
	}
	if got := w.queryString(`SELECT count(*)::text FROM netguard_allow_hosts`); got != "1" {
		t.Errorf("allow-list entries = %s, want the original one", got)
	}
	if got := w.queryString(`SELECT (revoked_at IS NULL)::text FROM mcp_tunnels WHERE id = $1`, tun.ID); got != "true" {
		t.Error("the tunnel was revoked")
	}
	if got := w.queryString(`SELECT count(*)::text FROM mcp_server_shared_secrets`); got != "0" {
		t.Error("a shared credential was planted")
	}
}

// TestSecurityFedTunnelMisuse: a tunnel can only carry its owner's
// servers. Bob cannot pick alice's tunnel in the portal; a server row
// pointing at alice's tunnel (any URL form, written below the portal)
// is refused at call time with tunnel_unavailable and alice's tunnel
// client never receives a request; malformed tunnel URLs are refused.
func TestSecurityFedTunnelMisuse(t *testing.T) {
	w := newWorld(t, options{federation: true})
	ctx := t.Context()
	tun, raw, err := w.fed.Tunnels.CreateTunnel(ctx, w.alice.id, "alice-laptop")
	if err != nil {
		t.Fatal(err)
	}
	w.forbid(raw, "tunnel token")
	var served atomic.Int64
	local := newUpstream(t, notesServer)
	agent, err := tunnel.NewAgent(tunnel.AgentOptions{GatewayURL: w.srv.URL, Token: raw, Handler: http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		served.Add(1)
		local.srv.Config.Handler.ServeHTTP(rw, r)
	})})
	if err != nil {
		t.Fatal(err)
	}
	actx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { _ = agent.Run(actx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	waitFor(t, func() bool { return w.fed.Tunnels.Online(tun.ID) })

	// Alice's own tunnel server works (control).
	own := w.addServer(w.alice, "viatunnel", tunnel.URL(tun.ID, "/mcp"), nil)
	w.review(w.alice, own, "search")
	if res, err := w.call(w.client(w.alice), "viatunnel.search", map[string]any{"q": "x"}); err != nil || res.IsError {
		t.Fatalf("alice through her tunnel: %v %+v", err, res)
	}

	// The portal refuses bob's pick of alice's tunnel.
	code, _, body := w.post(w.bob, "/servers/new", url.Values{"name": {"stolen"}, "url_mode": {"tunnel"}, "tunnel_id": {tun.ID}, "auth_kind": {"none"}})
	if code != http.StatusUnprocessableEntity || !strings.Contains(body, "Choose one of your tunnels") {
		t.Errorf("portal create on alice's tunnel as bob = %d", code)
	}
	served.Store(0)
	// Rows written below the portal, every URL form of alice's tunnel.
	for i, u := range []string{
		tunnel.URL(tun.ID, "/mcp"),
		"tunnel://" + strings.ToUpper(tun.ID) + "/mcp",
		"http://" + tun.ID + tunnel.HostSuffix + "/mcp",
		"https://" + tun.ID + tunnel.HostSuffix + "/mcp",
	} {
		s := w.addServer(w.bob, fmt.Sprintf("stolen%d", i), u, nil)
		// The owner-only review cannot even discover through it.
		if _, err := w.factory().Open(ctx, s, w.bob.id); err == nil {
			t.Errorf("%s: bob opened a session through alice's tunnel", u)
		}
		// Force an approved snapshot so the tool exists, then call.
		w.exec(`INSERT INTO mcp_server_snapshots (server_id, version, status, tools, review) VALUES ($1, 1, 'approved', $2::jsonb, $3::jsonb)`,
			s.ID, `[{"name":"search","inputSchema":{"type":"object"}}]`, `{"search":{"enabled":true,"kind":"read"}}`)
		if err := w.fed.Manager.ServerChanged(ctx, s.ID); err != nil {
			t.Fatal(err)
		}
		res, err := w.call(w.client(w.bob), s.Name+".search", map[string]any{})
		if err != nil || !res.IsError || !strings.Contains(text(t, res), "tunnel is not available") {
			t.Errorf("%s: bob's call through alice's tunnel = %v %+v, want the tunnel_unavailable refusal", u, err, res)
		}
	}
	for _, u := range []string{"tunnel://not-a-uuid/mcp", "tunnel://" + tun.ID + ":80/mcp", "tunnel://user@" + tun.ID + "/mcp"} {
		if tunnel.IsTunnelURL(u) {
			t.Errorf("%s accepted as a tunnel URL", u)
		}
	}
	if n := served.Load(); n != 0 {
		t.Errorf("alice's tunnel client served %d requests for bob", n)
	}
}

// waitFor polls cond for up to 5 seconds.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
