package authserver_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"

	"github.com/huynle/mcp-gateway/internal/authserver"
	"github.com/huynle/mcp-gateway/internal/authserver/authservertest"
	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/fake"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/identity/identitytest"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/portal"
	"github.com/huynle/mcp-gateway/internal/tokens"
	"github.com/huynle/mcp-gateway/internal/tokens/tokenstest"
)

const dexIssuer = "http://localhost:15556/dex"

// gateway is an in-process gateway: the real portal (sign-in sessions,
// CSRF, MountUser), the authorization server mounted the way cmd/gateway
// mounts it, and /mcp behind the composite authenticator, all over
// in-memory stores.
type gateway struct {
	srv     *httptest.Server
	idSvc   *identity.Service
	authSvc *authserver.Service
	tokens  *tokens.Service
	tstore  *tokenstest.MemStore
	astore  *authservertest.MemStore
	alice   string
}

func newGateway(t *testing.T) *gateway {
	t.Helper()
	log := slog.New(slog.DiscardHandler)
	g := &gateway{}

	// The server's URL is only known once it listens; route through a
	// handler that is swapped in below.
	var handler http.Handler
	g.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(g.srv.Close)
	base := g.srv.URL

	idStore := identitytest.NewMemStore()
	idSvc, err := identity.New(identity.Config{
		BaseURL:         base,
		Providers:       []config.OIDCProvider{{Name: "dex", DisplayName: "dex", Issuer: dexIssuer, ClientID: "gateway", ClientSecret: "s", AllowedDomains: []string{"example.com"}}},
		DefaultRole:     "member",
		IdleTimeout:     12 * time.Hour,
		AbsoluteTimeout: 7 * 24 * time.Hour,
	}, idStore, log)
	if err != nil {
		t.Fatal(err)
	}
	g.idSvc = idSvc
	res, err := idSvc.SignIn(context.Background(), "dex", identity.Claims{Issuer: dexIssuer, Subject: "alice", Name: "Alice", Email: "alice@example.com", EmailVerified: true})
	if err != nil {
		t.Fatal(err)
	}
	g.alice = res.Principal.UserID

	g.tstore = tokenstest.NewMemStore()
	signedIn := time.Now().Add(-time.Hour)
	g.tstore.AddUser(g.alice, &signedIn)
	g.tokens, err = tokens.New(tokens.Config{SignInMaxAge: tokens.DefaultSignInMaxAge}, g.tstore, nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}

	g.astore = authservertest.NewMemStore()
	g.astore.AddUser(g.alice, &signedIn)
	cfg, err := authserver.ConfigFromEnv(base, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	g.authSvc, err = authserver.New(cfg, g.astore, mustProviderWith(t, 3), authserver.Options{Log: log})
	if err != nil {
		t.Fatal(err)
	}

	p, err := portal.New(idSvc, log)
	if err != nil {
		t.Fatal(err)
	}
	session := func(r *http.Request) (string, string) {
		pr := identity.PrincipalFrom(r.Context())
		if pr == nil {
			return "", ""
		}
		return pr.UserID, pr.CSRFToken
	}
	g.authSvc.MountPortal(p.MountUser, session)
	idSvc.OnDisable(g.authSvc.DisableHook())

	f := fake.New(fake.Options{AutoAccount: true})
	registry := connectors.NewRegistry()
	if err := connectors.RegisterConnector(registry, f, f.Accounts()); err != nil {
		t.Fatal(err)
	}
	mcpHandler, err := mcp.Handler(mcp.Options{
		Registry:      registry,
		Authenticator: authserver.Composite(g.tokens, g.authSvc.Authenticator()),
		Visibility:    mcp.ScopeVisibility{},
		Accounts:      f.Accounts(),
		BaseURL:       base,
		Log:           log,
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	g.authSvc.Mount(mux)
	mux.Handle("/mcp", mcpHandler)
	mux.Handle("/", p.Handler())
	handler = mux
	return g
}

// browser is an http.Client with a cookie jar that does not follow
// redirects, so every hop can be asserted.
func (g *gateway) browser(t *testing.T, signedIn bool) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if signedIn {
		res, err := g.idSvc.SignIn(context.Background(), "dex", identity.Claims{Issuer: dexIssuer, Subject: "alice", Name: "Alice", Email: "alice@example.com", EmailVerified: true})
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(g.srv.URL)
		jar.SetCookies(u, []*http.Cookie{res.Cookie})
	}
	return c
}

func (g *gateway) csrf(t *testing.T, c *http.Client) string {
	t.Helper()
	// The account page echoes the CSRF token in the sign-out form.
	r := get(t, c, g.srv.URL+"/account")
	const marker = `name="_csrf" value="`
	i := strings.Index(string(r.body), marker)
	if i < 0 {
		t.Fatalf("no CSRF token on /account (status %d)", r.status)
	}
	rest := string(r.body[i+len(marker):])
	end := strings.Index(rest, `"`)
	if end < 0 {
		t.Fatal("unterminated CSRF value")
	}
	return rest[:end]
}

func mcpClient(t *testing.T, endpoint, bearer string) (*sdk.ClientSession, error) {
	t.Helper()
	hc := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		r = r.Clone(r.Context())
		r.Header.Set("Authorization", "Bearer "+bearer)
		return http.DefaultTransport.RoundTrip(r)
	})}
	transport := &sdk.StreamableClientTransport{Endpoint: endpoint, HTTPClient: hc}
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "test", Version: "0"}, nil).Connect(t.Context(), transport, nil)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs, nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// reply is one HTTP exchange's outcome.
type reply struct {
	status int
	header http.Header
	body   []byte
}

func (r reply) location() *url.URL {
	u, _ := url.Parse(r.header.Get("Location"))
	return u
}

// get and postForm run a request with the test context and drain the body.
func get(t *testing.T, c *http.Client, u string) reply {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	return send(t, c, req)
}

func postForm(t *testing.T, c *http.Client, u string, form url.Values) reply {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return send(t, c, req)
}

func postJSON(t *testing.T, c *http.Client, u, body string) reply {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, u, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	return send(t, c, req)
}

func send(t *testing.T, c *http.Client, req *http.Request) reply {
	t.Helper()
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return reply{status: resp.StatusCode, header: resp.Header, body: body}
}

// TestEndToEndOAuthFlow is the acceptance path: a harness discovers the
// authorization server from /mcp's 401, registers, sends the user through
// company sign-in and consent, exchanges the code with PKCE, and calls
// tools/list with the access token through the official SDK client.
func TestEndToEndOAuthFlow(t *testing.T) {
	g := newGateway(t)
	ctx := context.Background()
	base := g.srv.URL
	resource := base + "/mcp"
	hc := http.DefaultClient

	// 1. Unauthenticated MCP request: 401 with the resource metadata URL.
	r := postJSON(t, hc, resource, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if r.status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /mcp: %d", r.status)
	}
	challenges, err := oauthex.ParseWWWAuthenticate(r.header.Values("WWW-Authenticate"))
	if err != nil || len(challenges) != 1 {
		t.Fatalf("WWW-Authenticate %q: %v", r.header.Get("WWW-Authenticate"), err)
	}
	prmURL := challenges[0].Params["resource_metadata"]
	if prmURL != base+"/.well-known/oauth-protected-resource" {
		t.Fatalf("resource_metadata = %q", prmURL)
	}

	// 2. Protected resource metadata, validated by the SDK against the
	// resource URL, then the authorization server metadata.
	prm, err := oauthex.GetProtectedResourceMetadata(ctx, prmURL, resource, hc)
	if err != nil {
		t.Fatalf("PRM: %v", err)
	}
	if len(prm.AuthorizationServers) != 1 || prm.AuthorizationServers[0] != base {
		t.Fatalf("authorization_servers = %v", prm.AuthorizationServers)
	}
	meta, err := sdkauth.GetAuthServerMetadata(ctx, prm.AuthorizationServers[0], hc)
	if err != nil || meta == nil {
		t.Fatalf("AS metadata: %v %v", meta, err)
	}
	if meta.TokenEndpoint != base+"/oauth/token" || meta.RegistrationEndpoint != base+"/oauth/register" {
		t.Fatalf("metadata = %+v", meta)
	}

	// 3. Dynamic client registration through the SDK.
	reg, err := oauthex.RegisterClient(ctx, meta.RegistrationEndpoint, &oauthex.ClientRegistrationMetadata{
		RedirectURIs: []string{"http://localhost:33333/callback"}, ClientName: "Claude Desktop",
		TokenEndpointAuthMethod: "none", GrantTypes: []string{"authorization_code", "refresh_token"},
	}, hc)
	if err != nil {
		t.Fatalf("DCR: %v", err)
	}
	if reg.ClientID == "" || reg.ClientSecret != "" {
		t.Fatalf("registration = %+v", reg)
	}

	// 4. The browser is sent to the authorization endpoint. Anonymous: the
	// portal redirects to sign-in with the request as return_to.
	authURL := meta.AuthorizationEndpoint + "?" + url.Values{
		"client_id": {reg.ClientID}, "redirect_uri": {"http://localhost:33333/callback"}, "response_type": {"code"},
		"code_challenge": {challenge()}, "code_challenge_method": {"S256"}, "state": {"s1"}, "scope": {"mcp"}, "resource": {resource},
	}.Encode()
	anon := g.browser(t, false)
	r = get(t, anon, authURL)
	if loc := r.location(); r.status != http.StatusSeeOther || loc.Path != "/signin" || !strings.HasPrefix(loc.Query().Get("return_to"), "/oauth/authorize?") {
		t.Fatalf("anonymous authorize: %d %s", r.status, r.header.Get("Location"))
	}

	// Signed in: the consent page.
	br := g.browser(t, true)
	r = get(t, br, authURL)
	if r.status != http.StatusOK || !strings.Contains(string(r.body), "Claude Desktop") {
		t.Fatalf("consent page: %d %s", r.status, r.body)
	}

	// 5. Approve: the consent form posts the request back with the CSRF
	// token (the portal checks it) and the user lands on the redirect URI
	// with a code.
	form, _ := url.ParseQuery(strings.TrimPrefix(authURL, meta.AuthorizationEndpoint+"?"))
	form.Set("action", "approve")
	form.Set("_csrf", g.csrf(t, br))
	r = postForm(t, br, base+"/oauth/authorize/consent", form)
	loc := r.location()
	if r.status != http.StatusSeeOther || loc.Host != "localhost:33333" || loc.Query().Get("state") != "s1" || loc.Query().Get("code") == "" {
		t.Fatalf("consent: %d %s", r.status, r.header.Get("Location"))
	}
	code := loc.Query().Get("code")

	// A consent POST without the CSRF token is refused by the portal.
	bad, _ := url.ParseQuery(form.Encode())
	bad.Del("_csrf")
	if r := postForm(t, br, base+"/oauth/authorize/consent", bad); r.status != http.StatusForbidden {
		t.Errorf("consent without CSRF: %d", r.status)
	}

	// 6. Token exchange with the verifier and the resource.
	r = postForm(t, hc, meta.TokenEndpoint, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"http://localhost:33333/callback"},
		"client_id": {reg.ClientID}, "code_verifier": {verifier}, "resource": {resource},
	})
	var tok struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if r.status != http.StatusOK {
		t.Fatalf("token: %d %s", r.status, r.body)
	}
	if err := json.Unmarshal(r.body, &tok); err != nil || tok.TokenType != "Bearer" || tok.ExpiresIn != 3600 || tok.RefreshToken == "" {
		t.Fatalf("token response %s: %v", r.body, err)
	}

	// 7. tools/list through the SDK client with the access token.
	cs, err := mcpClient(t, resource, tok.AccessToken)
	if err != nil {
		t.Fatalf("connect with access token: %v", err)
	}
	list, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	var names []string
	for _, tool := range list.Tools {
		names = append(names, tool.Name)
	}
	if !contains(names, "fake.list_items") || !contains(names, "fake.create_item") {
		t.Errorf("tools = %v", names)
	}

	// 8. The JWKS verifies the token's signature (a resource server
	// elsewhere could do the same).
	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	_ = json.Unmarshal(get(t, hc, meta.JWKSURI).body, &jwks)
	if len(jwks.Keys) != 1 || jwks.Keys[0]["kid"] != kidOf(t, tok.AccessToken) || jwks.Keys[0]["d"] != nil {
		t.Errorf("jwks = %v", jwks)
	}

	// 9. Refresh: rotation issues new tokens, the old refresh token is dead.
	r = postForm(t, hc, meta.TokenEndpoint, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken}, "client_id": {reg.ClientID}, "resource": {resource}})
	var tok2 struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if r.status != http.StatusOK || json.Unmarshal(r.body, &tok2) != nil || tok2.RefreshToken == tok.RefreshToken {
		t.Fatalf("refresh: %d %s", r.status, r.body)
	}
	if _, err := mcpClient(t, resource, tok2.AccessToken); err != nil {
		t.Errorf("refreshed access token: %v", err)
	}

	// 10. The harnesses page lists the client; disconnecting it ends the
	// refresh-token family (the still-valid access token is bounded by its
	// hour).
	r = get(t, br, base+"/harnesses")
	if r.status != http.StatusOK || !strings.Contains(string(r.body), "Claude Desktop") {
		t.Fatalf("harnesses page: %d %s", r.status, r.body)
	}
	family := g.astore.RefreshTokens()[0].FamilyID
	if r := postForm(t, br, base+"/harnesses/"+family+"/revoke", url.Values{"_csrf": {g.csrf(t, br)}}); r.status != http.StatusSeeOther {
		t.Fatalf("revoke harness: %d", r.status)
	}
	if r := postForm(t, hc, meta.TokenEndpoint, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok2.RefreshToken}, "client_id": {reg.ClientID}}); r.status != http.StatusBadRequest {
		t.Errorf("refresh after disconnect: %d", r.status)
	}
}

// A token minted for another resource (same keys, same issuer) is refused
// by /mcp with 401, as is one from another issuer; a generated mgw_ token
// still works through the composite authenticator.
func TestMCPRejectsForeignAudience(t *testing.T) {
	g := newGateway(t)
	ctx := context.Background()
	resource := g.srv.URL + "/mcp"

	other := g.authSvc.Config()
	other.ResourcePath = "/other-mcp"
	foreign, _, err := authserver.NewMinter(other, g.authSvc.Keys()).Mint(ctx, authserver.Grant{UserID: g.alice, ClientID: "c", Scope: "mcp", Resource: other.Resource(), FamilyID: "00000000-0000-4000-8000-0000000000f1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mcpClient(t, resource, foreign); err == nil || !strings.Contains(err.Error(), "Unauthorized") {
		t.Errorf("token for another resource accepted by /mcp: %v", err)
	}

	elsewhere := g.authSvc.Config()
	elsewhere.Issuer = "https://other-gateway.example.com"
	wrongIss, _, err := authserver.NewMinter(elsewhere, g.authSvc.Keys()).Mint(ctx, authserver.Grant{UserID: g.alice, ClientID: "c", Scope: "mcp", Resource: resource, FamilyID: "00000000-0000-4000-8000-0000000000f1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mcpClient(t, resource, wrongIss); err == nil || !strings.Contains(err.Error(), "Unauthorized") {
		t.Errorf("token from another issuer accepted by /mcp: %v", err)
	}

	created, err := g.tokens.Create(ctx, g.alice, tokens.CreateRequest{Name: "laptop"})
	if err != nil {
		t.Fatal(err)
	}
	cs, err := mcpClient(t, resource, created.Raw)
	if err != nil {
		t.Fatalf("mgw_ token through the composite: %v", err)
	}
	if _, err := cs.ListTools(ctx, nil); err != nil {
		t.Errorf("tools/list with mgw_ token: %v", err)
	}
}

// Disabling the user through the identity service runs the hook: refresh
// tokens stop working at once.
func TestDisableUserRevokesHarnesses(t *testing.T) {
	g := newGateway(t)
	ctx := context.Background()
	base := g.srv.URL
	hc := http.DefaultClient
	reg, err := oauthex.RegisterClient(ctx, base+"/oauth/register", &oauthex.ClientRegistrationMetadata{RedirectURIs: []string{"http://localhost:1/cb"}, TokenEndpointAuthMethod: "none"}, hc)
	if err != nil {
		t.Fatal(err)
	}
	br := g.browser(t, true)
	form := url.Values{
		"client_id": {reg.ClientID}, "redirect_uri": {"http://localhost:1/cb"}, "response_type": {"code"},
		"code_challenge": {challenge()}, "code_challenge_method": {"S256"}, "state": {"s"}, "resource": {base + "/mcp"},
		"action": {"approve"}, "_csrf": {g.csrf(t, br)},
	}
	loc := postForm(t, br, base+"/oauth/authorize/consent", form).location()
	r := postForm(t, hc, base+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")}, "redirect_uri": {"http://localhost:1/cb"},
		"client_id": {reg.ClientID}, "code_verifier": {verifier},
	})
	var tok struct {
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.Unmarshal(r.body, &tok)
	if tok.RefreshToken == "" {
		t.Fatalf("no refresh token: %d %s", r.status, r.body)
	}
	if err := g.idSvc.DisableUser(ctx, "", g.alice); err != nil {
		t.Fatal(err)
	}
	if r := postForm(t, hc, base+"/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken}, "client_id": {reg.ClientID}}); r.status != http.StatusBadRequest {
		t.Errorf("refresh after disable: %d", r.status)
	}
}
