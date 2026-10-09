// Package oauthattack is the OAuth attack suite (Brain task cjedpxp6,
// decisions ysorv868 / 8vs3qdkc): adversarial, deterministic tests against
// the gateway's authorization server and its resource-side token
// validation. Every case runs the whole gateway in-process (real portal
// sessions and CSRF, the authorization server mounted the way cmd/gateway
// mounts it, /mcp behind the composite authenticator) over in-memory
// stores with an injected clock, and asserts the exact HTTP status, OAuth
// error code and, where the server records one, the audit action and log
// event. The cases follow the MCP authorization spec and RFC 9700 (OAuth
// 2.0 Security Best Current Practice).
//
// Run with `make test-attack` (or `make test`, which includes it).
package oauthattack

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/authserver"
	"github.com/huynle/mcp-gateway/internal/authserver/authservertest"
	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/fake"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/identity/identitytest"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/portal"
	"github.com/huynle/mcp-gateway/internal/tokens"
	"github.com/huynle/mcp-gateway/internal/tokens/tokenstest"
)

const dexIssuer = "http://localhost:15556/dex"

// t0 is where every gateway's clock starts.
var t0 = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

// --- clock, audit and log capture ---------------------------------------------

// fakeClock is the injected time source (authserver.Service.SetClock and
// the store's created_at stamps).
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// auditLog captures audit events the authorization server records.
type auditLog struct {
	mu     sync.Mutex
	events []audit.Event
}

func (a *auditLog) Record(_ context.Context, ev audit.Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, ev)
	return nil
}

// Actions lists the recorded action names in order.
func (a *auditLog) Actions() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []string
	for _, ev := range a.events {
		out = append(out, ev.ResourceIdentity["action"])
	}
	return out
}

// Find returns the events with the given action.
func (a *auditLog) Find(action string) []audit.Event {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []audit.Event
	for _, ev := range a.events {
		if ev.ResourceIdentity["action"] == action {
			out = append(out, ev)
		}
	}
	return out
}

// logRecord is one captured slog record: its message, level and attrs.
type logRecord struct {
	Level   slog.Level
	Message string
	Attrs   map[string]string
}

// logStore is the shared record sink behind every derived handler.
type logStore struct {
	mu      sync.Mutex
	records []logRecord
}

// logCapture is a slog.Handler that keeps every record.
type logCapture struct {
	store *logStore
	attrs []slog.Attr
}

func newLogCapture() *logCapture { return &logCapture{store: &logStore{}} }

func (l *logCapture) Enabled(context.Context, slog.Level) bool { return true }

func (l *logCapture) Handle(_ context.Context, r slog.Record) error {
	rec := logRecord{Level: r.Level, Message: r.Message, Attrs: map[string]string{}}
	for _, a := range l.attrs {
		rec.Attrs[a.Key] = a.Value.String()
	}
	r.Attrs(func(a slog.Attr) bool {
		rec.Attrs[a.Key] = a.Value.String()
		return true
	})
	l.store.mu.Lock()
	defer l.store.mu.Unlock()
	l.store.records = append(l.store.records, rec)
	return nil
}

func (l *logCapture) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &logCapture{store: l.store, attrs: append(append([]slog.Attr{}, l.attrs...), attrs...)}
}

func (l *logCapture) WithGroup(string) slog.Handler { return l }

// Events returns the records whose "event" attribute equals event.
func (l *logCapture) Events(event string) []logRecord {
	l.store.mu.Lock()
	defer l.store.mu.Unlock()
	var out []logRecord
	for _, r := range l.store.records {
		if r.Attrs["event"] == event {
			out = append(out, r)
		}
	}
	return out
}

// Last returns the most recent record with the event, or false.
func (l *logCapture) Last(event string) (logRecord, bool) {
	evs := l.Events(event)
	if len(evs) == 0 {
		return logRecord{}, false
	}
	return evs[len(evs)-1], true
}

// All returns every captured record.
func (l *logCapture) All() []logRecord {
	l.store.mu.Lock()
	defer l.store.mu.Unlock()
	return append([]logRecord{}, l.store.records...)
}

// --- the gateway -------------------------------------------------------------

// gateway is an in-process gateway: the real portal (sign-in sessions,
// CSRF, MountUser), the authorization server mounted the way cmd/gateway
// mounts it, and /mcp behind the composite authenticator, all over
// in-memory stores and the fake clock.
type gateway struct {
	srv      *httptest.Server
	base     string
	resource string
	idSvc    *identity.Service
	authSvc  *authserver.Service
	tokens   *tokens.Service
	tstore   *tokenstest.MemStore
	astore   *authservertest.MemStore
	alice    string
	clock    *fakeClock
	audit    *auditLog
	logs     *logCapture
	env      map[string]string
	cfg      authserver.Config
	signIn   time.Duration
}

// option tunes newGateway.
type option func(*gateway)

// withEnv sets GATEWAY_OAUTH_* variables the authorization server reads.
func withEnv(kv map[string]string) option {
	return func(g *gateway) {
		for k, v := range kv {
			g.env[k] = v
		}
	}
}

// withSignInMaxAge sets GATEWAY_TOKEN_SIGNIN_MAX_AGE for refresh tokens.
func withSignInMaxAge(d time.Duration) option {
	return func(g *gateway) { g.signIn = d }
}

func newGateway(t *testing.T, opts ...option) *gateway {
	t.Helper()
	g := &gateway{env: map[string]string{
		// Most cases register several clients; the flooding case lowers it.
		authserver.EnvRegisterPerMin: "1000",
	}, clock: &fakeClock{now: t0}, audit: &auditLog{}, logs: newLogCapture()}
	for _, o := range opts {
		o(g)
	}
	log := slog.New(g.logs)

	var handler http.Handler
	g.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(g.srv.Close)
	g.base = g.srv.URL
	g.resource = g.base + "/mcp"

	idStore := identitytest.NewMemStore()
	idSvc, err := identity.New(identity.Config{
		BaseURL:         g.base,
		Providers:       []config.OIDCProvider{{Name: "dex", DisplayName: "dex", Issuer: dexIssuer, ClientID: "gateway", ClientSecret: "s", AllowedDomains: []string{"example.com"}}},
		DefaultRole:     "member",
		IdleTimeout:     12 * time.Hour,
		AbsoluteTimeout: 7 * 24 * time.Hour,
	}, idStore, log)
	if err != nil {
		t.Fatal(err)
	}
	g.idSvc = idSvc
	res, err := idSvc.SignIn(context.Background(), "dex", aliceClaims())
	if err != nil {
		t.Fatal(err)
	}
	g.alice = res.Principal.UserID

	g.tstore = tokenstest.NewMemStore()
	signedIn := t0.Add(-time.Hour)
	g.tstore.AddUser(g.alice, &signedIn)
	g.tokens, err = tokens.New(tokens.Config{SignInMaxAge: tokens.DefaultSignInMaxAge}, g.tstore, nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}

	g.astore = authservertest.NewMemStore()
	g.astore.Now = g.clock.Now
	g.astore.AddUser(g.alice, &signedIn)
	cfg, err := authserver.ConfigFromEnv(g.base, func(k string) string { return g.env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if g.signIn > 0 {
		cfg.SignInMaxAge = g.signIn
	}
	g.cfg = cfg
	g.authSvc, err = authserver.New(cfg, g.astore, keyProvider(t), authserver.Options{Log: log, Audit: g.audit, Metrics: observability.NewMetrics()})
	if err != nil {
		t.Fatal(err)
	}
	g.authSvc.SetClock(g.clock.Now)

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
		BaseURL:       g.base,
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

func keyProvider(t *testing.T) crypto.KeyProvider {
	t.Helper()
	kp, err := crypto.NewStaticProvider("k1", map[string][]byte{"k1": []byte(strings.Repeat("\x03", 32))})
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func aliceClaims() identity.Claims {
	return identity.Claims{Issuer: dexIssuer, Subject: "alice", Name: "Alice", Email: "alice@example.com", EmailVerified: true}
}

// decoy is a second authorization server / resource server on its own
// origin: the same company, a different issuer and resource. shareKeys
// makes it sign with the gateway's own signing keys (the "same AS, other
// resource" confusion); otherwise it has keys of its own.
type decoy struct {
	srv      *httptest.Server
	base     string
	resource string
	svc      *authserver.Service
	store    *authservertest.MemStore
}

func (g *gateway) newDecoy(t *testing.T, shareKeys bool) *decoy {
	t.Helper()
	d := &decoy{}
	var handler http.Handler
	d.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(d.srv.Close)
	d.base = d.srv.URL
	d.resource = d.base + "/mcp"
	d.store = g.astore
	if !shareKeys {
		d.store = authservertest.NewMemStore()
		d.store.Now = g.clock.Now
		signedIn := t0.Add(-time.Hour)
		d.store.AddUser(g.alice, &signedIn)
	}
	cfg, err := authserver.ConfigFromEnv(d.base, func(k string) string { return g.env[k] })
	if err != nil {
		t.Fatal(err)
	}
	d.svc, err = authserver.New(cfg, d.store, keyProvider(t), authserver.Options{Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	d.svc.SetClock(g.clock.Now)
	mux := http.NewServeMux()
	d.svc.Mount(mux)
	handler = mux
	return d
}

// mintWith signs an access token with the given minter config over the
// gateway's own keys at the given time (what the AS's own bug, or another
// resource of the same AS, could produce).
func (g *gateway) mintWith(t *testing.T, cfg authserver.Config, now time.Time, grant authserver.Grant) string {
	t.Helper()
	m := authserver.NewMinter(cfg, g.authSvc.Keys())
	m.SetClock(func() time.Time { return now })
	raw, _, err := m.Mint(context.Background(), grant)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// grant is a valid grant for alice at the gateway's resource.
func (g *gateway) grant() authserver.Grant {
	return authserver.Grant{UserID: g.alice, ClientID: "gwc_test", Scope: authserver.ScopeFull, Resource: g.resource, FamilyID: "00000000-0000-4000-8000-0000000000f1"}
}

// --- HTTP helpers ------------------------------------------------------------

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

// oauthError decodes an RFC 6749 error body.
func (r reply) oauthError() (code, description string) {
	var e struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	_ = json.Unmarshal(r.body, &e)
	return e.Error, e.Description
}

func (r reply) json() map[string]any {
	var out map[string]any
	_ = json.Unmarshal(r.body, &out)
	return out
}

// noRedirect does not follow redirects, so every hop can be asserted.
var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// browser is an http.Client with a cookie jar that does not follow
// redirects; signedIn gives it alice's session.
func (g *gateway) browser(t *testing.T, signedIn bool) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if signedIn {
		res, err := g.idSvc.SignIn(context.Background(), "dex", aliceClaims())
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(g.base)
		jar.SetCookies(u, []*http.Cookie{res.Cookie})
	}
	return c
}

// csrf reads the session's CSRF token off the account page.
func (g *gateway) csrf(t *testing.T, c *http.Client) string {
	t.Helper()
	r := get(t, c, g.base+"/account")
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

func get(t *testing.T, c *http.Client, u string, headers ...string) reply {
	t.Helper()
	return do(t, c, http.MethodGet, u, nil, headers...)
}

func postForm(t *testing.T, c *http.Client, u string, form url.Values, headers ...string) reply {
	t.Helper()
	return do(t, c, http.MethodPost, u, strings.NewReader(form.Encode()), append([]string{"Content-Type", "application/x-www-form-urlencoded"}, headers...)...)
}

func postJSON(t *testing.T, c *http.Client, u, body string, headers ...string) reply {
	t.Helper()
	return do(t, c, http.MethodPost, u, strings.NewReader(body), append([]string{"Content-Type", "application/json"}, headers...)...)
}

// do sends one request; headers are key/value pairs, "Host" sets the
// Host header (request target) and a header set to "" is removed.
func do(t *testing.T, c *http.Client, method, u string, body io.Reader, headers ...string) reply {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, u, body)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		switch {
		case headers[i] == "Host":
			req.Host = headers[i+1]
		case headers[i+1] == "":
			req.Header.Del(headers[i])
		default:
			req.Header.Set(headers[i], headers[i+1])
		}
	}
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

// --- OAuth helpers -----------------------------------------------------------

// pkce is a verifier / S256 challenge pair.
type pkce struct{ verifier, challenge string }

func newPKCE(t *testing.T) pkce {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	v := base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(v))
	return pkce{verifier: v, challenge: base64.RawURLEncoding.EncodeToString(sum[:])}
}

// client is a registered OAuth client.
type client struct {
	id       string
	secret   string
	redirect string
}

// register registers a public client with the given redirect URIs (the
// first is the one the flow uses) and fails the test on refusal.
func (g *gateway) register(t *testing.T, redirectURIs ...string) client {
	t.Helper()
	r := g.registerDoc(t, map[string]any{"client_name": "Attack harness", "redirect_uris": redirectURIs, "token_endpoint_auth_method": "none"})
	if r.status != http.StatusCreated {
		t.Fatalf("register %v: %d %s", redirectURIs, r.status, r.body)
	}
	out := r.json()
	return client{id: out["client_id"].(string), redirect: redirectURIs[0]}
}

// registerDoc posts an arbitrary registration document.
func (g *gateway) registerDoc(t *testing.T, doc map[string]any, headers ...string) reply {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return postJSON(t, noRedirect, g.base+"/oauth/register", string(b), headers...)
}

// authorizeParams is a valid authorization request for c.
func (g *gateway) authorizeParams(c client, p pkce, state string) url.Values {
	return url.Values{
		"client_id": {c.id}, "redirect_uri": {c.redirect}, "response_type": {"code"},
		"code_challenge": {p.challenge}, "code_challenge_method": {"S256"}, "state": {state},
		"scope": {"mcp"}, "resource": {g.resource},
	}
}

// authorize is GET /oauth/authorize with the browser.
func (g *gateway) authorize(t *testing.T, br *http.Client, q url.Values) reply {
	t.Helper()
	return get(t, br, g.base+"/oauth/authorize?"+q.Encode())
}

// consent posts the user's answer with the browser's CSRF token.
func (g *gateway) consent(t *testing.T, br *http.Client, q url.Values, action string, headers ...string) reply {
	t.Helper()
	form := url.Values{}
	for k, v := range q {
		form[k] = v
	}
	form.Set("action", action)
	form.Set("_csrf", g.csrf(t, br))
	return postForm(t, br, g.base+"/oauth/authorize/consent", form, headers...)
}

// code runs authorize + approve for c and returns the code.
func (g *gateway) code(t *testing.T, br *http.Client, c client, p pkce, state string) string {
	t.Helper()
	q := g.authorizeParams(c, p, state)
	if r := g.authorize(t, br, q); r.status != http.StatusOK {
		t.Fatalf("authorize: %d %s", r.status, r.body)
	}
	r := g.consent(t, br, q, "approve")
	loc := r.location()
	if r.status != http.StatusSeeOther || loc.Query().Get("code") == "" || loc.Query().Get("state") != state {
		t.Fatalf("approve: %d %s %s", r.status, r.header.Get("Location"), r.body)
	}
	return loc.Query().Get("code")
}

// exchangeForm is the authorization_code grant form for c.
func (g *gateway) exchangeForm(c client, code string, p pkce) url.Values {
	f := url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {c.redirect},
		"client_id": {c.id}, "code_verifier": {p.verifier}, "resource": {g.resource},
	}
	if c.secret != "" {
		f.Set("client_secret", c.secret)
	}
	return f
}

// token posts to the token endpoint.
func (g *gateway) token(t *testing.T, form url.Values, headers ...string) reply {
	t.Helper()
	return postForm(t, noRedirect, g.base+"/oauth/token", form, headers...)
}

// tokenPair is a successful token response.
type tokenPair struct {
	access, refresh string
}

// issue runs the whole code flow for c and returns the token pair.
func (g *gateway) issue(t *testing.T, br *http.Client, c client) tokenPair {
	t.Helper()
	p := newPKCE(t)
	code := g.code(t, br, c, p, nonce(t))
	r := g.token(t, g.exchangeForm(c, code, p))
	if r.status != http.StatusOK {
		t.Fatalf("exchange: %d %s", r.status, r.body)
	}
	out := r.json()
	return tokenPair{access: out["access_token"].(string), refresh: out["refresh_token"].(string)}
}

// refresh posts the refresh_token grant.
func (g *gateway) refresh(t *testing.T, c client, refreshToken string, extra ...string) reply {
	t.Helper()
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}, "client_id": {c.id}}
	if c.secret != "" {
		form.Set("client_secret", c.secret)
	}
	for i := 0; i+1 < len(extra); i += 2 {
		form.Set(extra[i], extra[i+1])
	}
	return g.token(t, form)
}

// mcpCall posts tools/list to /mcp with the bearer and returns the reply.
func (g *gateway) mcpCall(t *testing.T, bearer string) reply {
	t.Helper()
	headers := []string{"Accept", "application/json, text/event-stream"}
	if bearer != "" {
		headers = append(headers, "Authorization", "Bearer "+bearer)
	}
	return postJSON(t, noRedirect, g.resource, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, headers...)
}

// wantMCPOK asserts the bearer is accepted by /mcp.
func (g *gateway) wantMCPOK(t *testing.T, bearer string) {
	t.Helper()
	if r := g.mcpCall(t, bearer); r.status != http.StatusOK {
		t.Fatalf("/mcp with a valid token: %d %s", r.status, r.body)
	}
}

// --- assertions --------------------------------------------------------------

// wantOAuthError asserts an OAuth JSON error with the exact status and
// code and returns the description.
func wantOAuthError(t *testing.T, r reply, status int, code string) string {
	t.Helper()
	got, desc := r.oauthError()
	if r.status != status || got != code {
		t.Fatalf("status %d error %q (%s), want %d %q; body %s", r.status, got, desc, status, code, r.body)
	}
	if cc := r.header.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("error response Cache-Control = %q, want no-store", cc)
	}
	noStackTrace(t, r.body)
	return desc
}

// wantRedirectError asserts a 303 to the client's redirect URI carrying
// error=code and the state, and no code.
func wantRedirectError(t *testing.T, r reply, redirectURI, code, state string) *url.URL {
	t.Helper()
	loc := r.location()
	if r.status != http.StatusSeeOther {
		t.Fatalf("status %d, want 303; body %s", r.status, r.body)
	}
	want, _ := url.Parse(redirectURI)
	if loc.Scheme != want.Scheme || loc.Host != want.Host || loc.Path != want.Path {
		t.Fatalf("redirected to %s, want %s", loc, redirectURI)
	}
	if loc.Query().Get("error") != code || loc.Query().Get("state") != state {
		t.Fatalf("redirect %s: want error=%s state=%s", loc, code, state)
	}
	if loc.Query().Get("code") != "" {
		t.Fatalf("redirect %s carries a code with an error", loc)
	}
	return loc
}

// wantErrorPage asserts an HTML error page (no redirect, no code).
func wantErrorPage(t *testing.T, r reply, status int) string {
	t.Helper()
	if r.status != status {
		t.Fatalf("status %d, want %d; Location %q; body %s", r.status, status, r.header.Get("Location"), r.body)
	}
	if loc := r.header.Get("Location"); loc != "" {
		t.Fatalf("error page must not redirect, got Location %q", loc)
	}
	if ct := r.header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("error page Content-Type = %q", ct)
	}
	noStackTrace(t, r.body)
	return string(r.body)
}

// wantMCPUnauthorized asserts /mcp answered 401 invalid_token with the
// resource metadata challenge and returns the WWW-Authenticate value.
func wantMCPUnauthorized(t *testing.T, g *gateway, r reply) string {
	t.Helper()
	wa := r.header.Get("WWW-Authenticate")
	if r.status != http.StatusUnauthorized {
		t.Fatalf("/mcp status %d, WWW-Authenticate %q, body %s; want 401", r.status, wa, r.body)
	}
	if code, _ := r.oauthError(); code != "invalid_token" {
		t.Fatalf("/mcp error %q, want invalid_token; body %s", code, r.body)
	}
	if !strings.Contains(wa, `error="invalid_token"`) || !strings.Contains(wa, `resource_metadata="`+g.base+`/.well-known/oauth-protected-resource"`) {
		t.Fatalf("WWW-Authenticate = %q", wa)
	}
	noStackTrace(t, r.body)
	return wa
}

// wantAuthFailed asserts the authorization server logged an access-token
// rejection whose detail (the check that failed) is the given one.
func wantAuthFailed(t *testing.T, g *gateway, detail string) {
	t.Helper()
	rec, ok := g.logs.Last("authserver.auth_failed")
	if !ok {
		t.Fatalf("no authserver.auth_failed log event; events: %v", eventNames(g.logs.All()))
	}
	if rec.Attrs["detail"] != detail {
		t.Fatalf("auth_failed detail = %q (reason %q), want %q", rec.Attrs["detail"], rec.Attrs["reason"], detail)
	}
}

// wantLogEvent asserts the event was logged at least once and returns the
// last record.
func wantLogEvent(t *testing.T, g *gateway, event string) logRecord {
	t.Helper()
	rec, ok := g.logs.Last(event)
	if !ok {
		t.Fatalf("no %s log event; events: %v", event, eventNames(g.logs.All()))
	}
	return rec
}

// wantAudit asserts exactly n audit events with the action and decision.
func wantAudit(t *testing.T, g *gateway, action, decision string, n int) []audit.Event {
	t.Helper()
	evs := g.audit.Find(action)
	if len(evs) != n {
		t.Fatalf("%d %s audit events, want %d; actions: %v", len(evs), action, n, g.audit.Actions())
	}
	for _, ev := range evs {
		if ev.Decision != decision {
			t.Fatalf("%s audit decision = %q, want %q", action, ev.Decision, decision)
		}
	}
	return evs
}

func eventNames(recs []logRecord) []string {
	var out []string
	for _, r := range recs {
		if e := r.Attrs["event"]; e != "" {
			out = append(out, e)
		}
	}
	return out
}

// noStackTrace fails when body carries anything that looks like a Go
// stack trace or an internal error.
func noStackTrace(t *testing.T, body []byte) {
	t.Helper()
	s := string(body)
	for _, needle := range []string{"goroutine ", "runtime/", ".go:", "panic", "SQLSTATE"} {
		if strings.Contains(s, needle) {
			t.Fatalf("response leaks internals (%q): %s", needle, s)
		}
	}
}

// nonce returns a short random string for state values.
func nonce(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", b)
}
