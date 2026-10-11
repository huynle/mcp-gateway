package auth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/store"
)

func TestOAuthCIMDUsesDocumentURLAndSkipsDCR(t *testing.T) {
	f := newFixture(t, func(a *testAS) { a.cimd = true })
	rec := f.startConnect("alice", f.server.ID)
	if rec.Code != http.StatusFound {
		t.Fatalf("StartConnect = %d %q", rec.Code, rec.Body.String())
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if got := loc.Query().Get("client_id"); got != gatewayBase+ClientMetadataPath {
		t.Fatalf("client_id = %q, want the metadata document URL", got)
	}
	if f.as.registrations != 0 {
		t.Fatalf("DCR called %d times on a CIMD server", f.as.registrations)
	}
	if cl := f.st.clients[f.server.ID]; cl == nil || cl.Method != store.MCPOAuthClientCIMD || cl.ClientSecret != nil {
		t.Fatalf("stored client = %+v", cl)
	}
	back := f.as.authorize(t, loc.String())
	if cb := f.callback("alice", back); cb.Code >= 400 {
		t.Fatalf("callback = %d %q", cb.Code, cb.Body.String())
	}
	if f.as.lastToken.Get("client_id") != gatewayBase+ClientMetadataPath || f.as.lastTokenAuth != "post" {
		t.Fatalf("token request client auth = %v (%s)", f.as.lastToken, f.as.lastTokenAuth)
	}
	az, err := f.svc.ForUser(t.Context(), f.server, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if seen, err := f.whoami(t.Context(), az); err != nil || !strings.HasPrefix(seen["Authorization"], "Bearer at-") {
		t.Fatalf("whoami = %v %v", seen, err)
	}
}

func TestClientMetadataDocument(t *testing.T) {
	f := newFixture(t, nil)
	rec := httptest.NewRecorder()
	f.svc.ClientMetadataDocument().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, gatewayBase+ClientMetadataPath, nil))
	if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("status %d type %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	var doc struct {
		ClientID     string   `json:"client_id"`
		ClientName   string   `json:"client_name"`
		RedirectURIs []string `json:"redirect_uris"`
		GrantTypes   []string `json:"grant_types"`
		AuthMethod   string   `json:"token_endpoint_auth_method"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.ClientID != gatewayBase+ClientMetadataPath || doc.AuthMethod != "none" || doc.ClientName == "" ||
		!slices.Equal(doc.RedirectURIs, []string{gatewayBase + CallbackPath}) || !slices.Contains(doc.GrantTypes, "refresh_token") {
		t.Fatalf("document = %+v", doc)
	}
}

func TestOAuthStaticClient(t *testing.T) {
	f := newFixture(t, func(a *testAS) {
		a.noRegistration = true
		a.clients["static-id"] = "static-secret-value"
	})
	// No CIMD, no DCR, no static client yet: nothing to connect with.
	if rec := f.startConnect("alice", f.server.ID); rec.Code != http.StatusConflict {
		t.Fatalf("StartConnect without client = %d, want 409", rec.Code)
	}
	// Only the owner (or an admin) sets the static client.
	if err := f.svc.SetStaticClient(t.Context(), Actor{UserID: "alice"}, f.server.ID, "static-id", "static-secret-value", ""); err == nil {
		t.Fatal("non-owner set the static client")
	}
	if err := f.svc.SetStaticClient(t.Context(), Actor{UserID: "owner"}, f.server.ID, "static-id", "static-secret-value", ""); err != nil {
		t.Fatalf("SetStaticClient: %v", err)
	}
	cl := f.st.clients[f.server.ID]
	if cl == nil || cl.Method != store.MCPOAuthClientStatic || cl.ClientSecret == nil || bytes.Contains(cl.ClientSecret.Ciphertext, []byte("static-secret-value")) {
		t.Fatalf("stored static client = %+v", cl)
	}
	f.connect("alice")
	if f.as.lastTokenAuth != "basic" {
		t.Fatalf("token endpoint auth = %s, want basic with the static secret", f.as.lastTokenAuth)
	}
	if f.as.registrations != 0 {
		t.Fatal("DCR called despite a static client")
	}
	// An admin can replace it.
	if err := f.svc.SetStaticClient(t.Context(), Actor{UserID: "admin", Admin: true}, f.server.ID, "static-id", "static-secret-value", f.as.issuer); err != nil {
		t.Fatalf("admin SetStaticClient: %v", err)
	}
}

func TestOAuthRefusesWithoutS256(t *testing.T) {
	f := newFixture(t, func(a *testAS) { a.noS256 = true })
	rec := f.startConnect("alice", f.server.ID)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "PKCE") {
		t.Fatalf("StartConnect = %d %q, want 409 PKCE", rec.Code, rec.Body.String())
	}
}

func TestOAuthIssuerParameter(t *testing.T) {
	f := newFixture(t, func(a *testAS) { a.issParam = true })
	f.connect("alice") // iss present and right

	rec := f.startConnect("bob", f.server.ID)
	back := f.as.authorize(t, rec.Header().Get("Location"))
	q := back.Query()
	q.Set("iss", "http://evil.example")
	back.RawQuery = q.Encode()
	if cb := f.callback("bob", back); cb.Code != http.StatusBadRequest {
		t.Fatalf("wrong iss = %d", cb.Code)
	}
	// The AS advertises iss: a callback without it is refused too.
	rec = f.startConnect("bob", f.server.ID)
	back = f.as.authorize(t, rec.Header().Get("Location"))
	q = back.Query()
	q.Del("iss")
	back.RawQuery = q.Encode()
	if cb := f.callback("bob", back); cb.Code != http.StatusBadRequest {
		t.Fatalf("missing iss = %d", cb.Code)
	}
	if f.st.conn(f.server.ID, "bob") != nil {
		t.Fatal("bob connected despite iss failures")
	}
}

func TestOAuthOfflineAccessAndConfiguredScopes(t *testing.T) {
	f := newFixture(t, func(a *testAS) { a.scopes = append(a.scopes, "offline_access") })
	rec := f.startConnect("alice", f.server.ID)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if sc := strings.Fields(loc.Query().Get("scope")); !slices.Contains(sc, "offline_access") || !slices.Contains(sc, "mcp") {
		t.Fatalf("scope = %v", sc)
	}
	f.server.AuthConfig = []byte(`{"scopes":["mcp:read"]}`)
	f.st.servers[f.server.ID].AuthConfig = f.server.AuthConfig
	rec = f.startConnect("alice", f.server.ID)
	loc, _ = url.Parse(rec.Header().Get("Location"))
	if sc := strings.Fields(loc.Query().Get("scope")); !slices.Equal(sc, []string{"mcp:read", "offline_access"}) {
		t.Fatalf("scope with configured scopes = %v", sc)
	}
}

func TestOAuthAccessDeniedByUser(t *testing.T) {
	f := newFixture(t, nil)
	rec := f.startConnect("alice", f.server.ID)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	back, _ := url.Parse(gatewayBase + CallbackPath)
	back.RawQuery = url.Values{"state": {loc.Query().Get("state")}, "error": {"access_denied"}}.Encode()
	if cb := f.callback("alice", back); cb.Code != http.StatusBadRequest || !strings.Contains(cb.Body.String(), "refused") {
		t.Fatalf("denied callback = %d %q", cb.Code, cb.Body.String())
	}
}

func TestNetguardBlocksInternalTokenEndpoint(t *testing.T) {
	for _, te := range []string{"http://127.0.0.1:9/token", "http://169.254.169.254/token"} {
		t.Run(te, func(t *testing.T) {
			f := newFixture(t, func(a *testAS) { a.tokenEndpoint = te })
			rec := f.startConnect("alice", f.server.ID)
			if rec.Code != http.StatusFound {
				t.Fatalf("StartConnect = %d", rec.Code)
			}
			back := f.as.authorize(t, rec.Header().Get("Location"))
			cb := f.callback("alice", back)
			if cb.Code != http.StatusBadRequest {
				t.Fatalf("callback with internal token endpoint = %d %q", cb.Code, cb.Body.String())
			}
			if f.st.conn(f.server.ID, "alice") != nil {
				t.Fatal("connection stored")
			}
			if !strings.Contains(f.logs.String(), "netguard") && !strings.Contains(f.logs.String(), "blocked") {
				t.Fatalf("refusal not logged: %s", f.logs.String())
			}
		})
	}
}

func TestNetguardAllowListOpensInternalAS(t *testing.T) {
	// The AS really listens on loopback; with 127.0.0.1 allow-listed the
	// gateway may use it, without it discovery refuses.
	as := newTestAS(t)
	mux := http.NewServeMux()
	as.routes(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	as.issuer = ts.URL
	for _, allow := range []bool{false, true} {
		var n *fakeNet
		if allow {
			n = newFakeNet(t, "127.0.0.1")
		} else {
			n = newFakeNet(t)
		}
		smux := http.NewServeMux()
		var base string
		smux.HandleFunc("GET /.well-known/oauth-protected-resource", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, 200, map[string]any{"resource": base, "authorization_servers": []string{ts.URL}})
		})
		smux.Handle("/mcp", gate(mcpHandler(), "Bearer", func(*http.Request) bool { return false }))
		base = n.add("internal-as.example", smux)
		res, err := newDiscoverer(t, n).Detect(t.Context(), base+"/mcp")
		if err != nil {
			t.Fatal(err)
		}
		if got := res.AuthServerMetadata != nil; got != allow {
			t.Fatalf("allow-listed=%v: AS metadata found=%v (blocked %v)", allow, got, res.Blocked)
		}
	}
}

func TestNoSecretsInLogs(t *testing.T) {
	f := newFixture(t, nil)
	f.connect("alice")
	f.clock.Advance(2 * 3600e9)
	az, err := f.svc.ForUser(t.Context(), f.server, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.whoami(t.Context(), az); err != nil {
		t.Fatal(err)
	}
	f.as.failRefresh = "invalid_grant"
	f.clock.Advance(2 * 3600e9)
	az, _ = f.svc.ForUser(t.Context(), f.server, "alice")
	_, _ = f.whoami(t.Context(), az)

	// Shared API key and a per-user key on other servers.
	apiSrv := apiKeyServer(t, f, "k-SHARED-SECRET-1")
	if err := f.svc.SetSharedCredential(t.Context(), Actor{UserID: "owner"}, apiSrv.ID, Credential{APIKey: "k-SHARED-SECRET-1"}); err != nil {
		t.Fatal(err)
	}
	az, _ = f.svc.ForUser(t.Context(), apiSrv, "alice")
	_, _ = f.whoamiAt(t.Context(), apiSrv, az)

	logs := f.logs.String()
	if logs == "" {
		t.Fatal("no logs captured")
	}
	f.as.mu.Lock()
	var secrets []string
	for tok := range f.as.refresh {
		secrets = append(secrets, tok)
	}
	for tok := range f.as.access {
		secrets = append(secrets, tok)
	}
	for _, s := range f.as.clients {
		if s != "" {
			secrets = append(secrets, s)
		}
	}
	f.as.mu.Unlock()
	secrets = append(secrets, "at-", "rt-", "code-", "k-SHARED-SECRET-1", "at-should-not-leak")
	for _, s := range secrets {
		if strings.Contains(logs, s) {
			t.Fatalf("secret %q in logs:\n%s", s, logs)
		}
	}
	if !strings.Contains(logs, "federation.auth_needs_reconnect") || !strings.Contains(logs, "federation.auth_refreshed") {
		t.Fatalf("expected events missing from logs:\n%s", logs)
	}
}
