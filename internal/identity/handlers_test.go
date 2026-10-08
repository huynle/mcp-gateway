package identity_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/identity/identitytest"
)

// gateway is a test gateway: the identity routes plus a /whoami endpoint
// behind the session middleware, backed by the in-memory store and a fake
// provider.
type gateway struct {
	srv *httptest.Server
	svc *identity.Service
	st  *identitytest.MemStore
	idp *fakeIDP
}

type whoami struct {
	Anonymous   bool
	UserID      string
	DisplayName string
	Roles       []string
	SessionID   string
	CSRFToken   string
}

func newGateway(t *testing.T) *gateway {
	t.Helper()
	idp := newFakeIDP(t)
	st := identitytest.NewMemStore()
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)

	cfg := testConfig(config.OIDCProvider{
		Name:           "dex",
		DisplayName:    "Local dex",
		Issuer:         idp.issuer(),
		ClientID:       idp.clientID,
		ClientSecret:   idp.clientSecret,
		AllowedDomains: []string{"example.com"},
	})
	cfg.BaseURL = srv.URL
	svc, _ := newService(t, cfg, st)

	mux := http.NewServeMux()
	mux.Handle("/auth/", svc.Handler())
	mux.HandleFunc("GET /whoami", func(w http.ResponseWriter, r *http.Request) {
		p := identity.PrincipalFrom(r.Context())
		if p == nil {
			writeJSON(w, whoami{Anonymous: true})
			return
		}
		writeJSON(w, whoami{UserID: p.UserID, DisplayName: p.DisplayName, Roles: p.Roles, SessionID: p.SessionID, CSRFToken: p.CSRFToken})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "home "+r.URL.String())
	})
	srv.Config.Handler = svc.Middleware(mux)
	return &gateway{srv: srv, svc: svc, st: st, idp: idp}
}

// client returns an HTTP client with a cookie jar; follow controls whether
// redirects are followed.
func (g *gateway) client(t *testing.T, follow bool) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Client{Jar: jar}
	if !follow {
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	return c
}

// result is a fully read response: the body is consumed and closed.
type result struct {
	*http.Response
	Text string
}

// do issues a request with the test context; absolute URLs are used as-is,
// paths are resolved against the gateway.
func (g *gateway) do(t *testing.T, c *http.Client, method, target string, form url.Values) *result {
	t.Helper()
	if strings.HasPrefix(target, "/") {
		target = g.srv.URL + target
	}
	var bodyReader io.Reader
	if form != nil {
		bodyReader = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(t.Context(), method, target, bodyReader)
	if err != nil {
		t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return &result{Response: resp, Text: string(b)}
}

func (g *gateway) get(t *testing.T, c *http.Client, target string) *result {
	t.Helper()
	return g.do(t, c, http.MethodGet, target, nil)
}

func (g *gateway) whoami(t *testing.T, c *http.Client) whoami {
	t.Helper()
	return decodeWhoami(t, g.get(t, c, "/whoami"))
}

func decodeWhoami(t *testing.T, resp *result) whoami {
	t.Helper()
	var w whoami
	if err := json.Unmarshal([]byte(resp.Text), &w); err != nil {
		t.Fatalf("decode whoami %q: %v", resp.Text, err)
	}
	return w
}

// signIn drives the browser through the whole flow and returns the final
// response.
func (g *gateway) signIn(t *testing.T, c *http.Client, returnTo string) *result {
	t.Helper()
	path := "/auth/dex/start"
	if returnTo != "" {
		path += "?return_to=" + url.QueryEscape(returnTo)
	}
	return g.get(t, c, path)
}

func TestFullSignInFlow(t *testing.T) {
	g := newGateway(t)
	c := g.client(t, true)

	resp := g.signIn(t, c, "/whoami?after=signin")
	if resp.StatusCode != http.StatusOK || resp.Request.URL.Path != "/whoami" || resp.Request.URL.Query().Get("after") != "signin" {
		t.Fatalf("flow ended at %s with %d, want 200 at /whoami?after=signin", resp.Request.URL, resp.StatusCode)
	}
	w := decodeWhoami(t, resp)
	if w.Anonymous || w.DisplayName != "dev" || !slices.Equal(w.Roles, []string{"member"}) || w.CSRFToken == "" {
		t.Errorf("whoami after sign-in = %+v", w)
	}
	if g.st.UserCount() != 1 {
		t.Errorf("users = %d, want 1", g.st.UserCount())
	}
	auth := g.idp.lastAuthRequest()
	if auth.method != "S256" || auth.challenge == "" || auth.nonce == "" || auth.state == "" {
		t.Errorf("authorization request lacked PKCE/nonce/state: %+v", auth)
	}
	if !strings.Contains(auth.scope, "openid") {
		t.Errorf("scope = %q, want openid", auth.scope)
	}
	if auth.redirectURI != g.srv.URL+"/auth/dex/callback" {
		t.Errorf("redirect_uri = %q", auth.redirectURI)
	}
	// The login-state cookie is gone, the session cookie is set.
	for _, ck := range c.Jar.Cookies(mustURL(g.srv.URL)) {
		if ck.Name == identity.LoginCookie {
			t.Error("login-state cookie must be cleared after the callback")
		}
	}

	// Second sign-in in the same browser reuses the user and rotates the session.
	first := w.SessionID
	g.signIn(t, c, "")
	w = g.whoami(t, c)
	if w.SessionID == first {
		t.Error("session should be rotated on sign-in")
	}
	if g.st.UserCount() != 1 || g.st.LiveSessions(w.UserID) != 1 {
		t.Errorf("users = %d, live sessions = %d; want 1 and 1 (old session revoked)", g.st.UserCount(), g.st.LiveSessions(w.UserID))
	}
}

func TestSignInRejectsStateMismatch(t *testing.T) {
	g := newGateway(t)
	c := g.client(t, false)

	resp := g.signIn(t, c, "")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("start = %d, want 302", resp.StatusCode)
	}
	resp = g.get(t, c, resp.Header.Get("Location"))
	cb := mustURL(resp.Header.Get("Location"))
	q := cb.Query()
	q.Set("state", "tampered")
	cb.RawQuery = q.Encode()

	resp = g.get(t, c, cb.String())
	if b := resp.Text; resp.StatusCode != http.StatusBadRequest || !strings.Contains(b, "sign-in") {
		t.Errorf("tampered state = %d %q, want 400 with a sign-in error page", resp.StatusCode, b)
	}
	if g.st.UserCount() != 0 {
		t.Error("no user must be created on a state mismatch")
	}
	if g.whoami(t, c).Anonymous != true {
		t.Error("must stay anonymous")
	}
}

func TestSignInRejectsNonceMismatch(t *testing.T) {
	g := newGateway(t)
	g.idp.nonceOverride = "not-the-nonce"
	c := g.client(t, true)
	resp := g.signIn(t, c, "")
	if b := resp.Text; resp.StatusCode != http.StatusUnauthorized || !strings.Contains(b, "sign-in") {
		t.Errorf("nonce mismatch = %d %q, want 401", resp.StatusCode, b)
	}
	if g.st.UserCount() != 0 || !g.whoami(t, c).Anonymous {
		t.Error("no user or session on a nonce mismatch")
	}
}

func TestSignInRejectsPKCEMismatch(t *testing.T) {
	g := newGateway(t)
	g.idp.breakPKCE = true
	c := g.client(t, true)
	resp := g.signIn(t, c, "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("PKCE mismatch = %d, want 401", resp.StatusCode)
	}
	if g.st.UserCount() != 0 || !g.whoami(t, c).Anonymous {
		t.Error("no user or session on a PKCE failure")
	}
}

func TestCallbackWithoutLoginCookie(t *testing.T) {
	g := newGateway(t)
	c := g.client(t, false)
	resp := g.get(t, c, "/auth/dex/callback?code=x&state=y")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("callback without login cookie = %d, want 400", resp.StatusCode)
	}
}

func TestCallbackAfterLoginCookieExpired(t *testing.T) {
	g := newGateway(t)
	c := g.client(t, false)
	now := time.Now()
	g.svc.SetClock(func() time.Time { return now })
	resp := g.signIn(t, c, "")
	resp = g.get(t, c, resp.Header.Get("Location"))
	g.svc.SetClock(func() time.Time { return now.Add(11 * time.Minute) })
	resp = g.get(t, c, resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("stale login cookie = %d, want 400", resp.StatusCode)
	}
	if g.st.UserCount() != 0 {
		t.Error("no user on a stale login")
	}
}

func TestCallbackProviderError(t *testing.T) {
	g := newGateway(t)
	c := g.client(t, false)
	g.signIn(t, c, "")
	// The provider sends the user back with an error instead of a code.
	resp := g.get(t, c, "/auth/dex/callback?error=access_denied&error_description=nope&state=whatever")
	if b := resp.Text; resp.StatusCode != http.StatusBadRequest || !strings.Contains(b, "access_denied") {
		t.Errorf("provider error = %d %q, want 400 mentioning the error code", resp.StatusCode, b)
	}
}

func TestSignInRejectsDisallowedDomainOverHTTP(t *testing.T) {
	g := newGateway(t)
	g.idp.setClaim("email", "intruder@evil.test")
	c := g.client(t, true)
	resp := g.signIn(t, c, "")
	if b := resp.Text; resp.StatusCode != http.StatusForbidden || !strings.Contains(b, "not allowed") {
		t.Errorf("disallowed domain = %d %q, want 403", resp.StatusCode, b)
	}
	if g.st.UserCount() != 0 {
		t.Error("no user for a disallowed domain")
	}
}

func TestDisabledUserSignInOverHTTP(t *testing.T) {
	g := newGateway(t)
	c := g.client(t, true)
	g.signIn(t, c, "")
	w := g.whoami(t, c)
	if err := g.svc.DisableUser(context.Background(), "", w.UserID); err != nil {
		t.Fatal(err)
	}
	if !g.whoami(t, c).Anonymous {
		t.Error("disabling must end the session")
	}
	resp := g.signIn(t, c, "")
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("disabled user sign-in = %d, want 403", resp.StatusCode)
	}
}

func TestUnknownProviderIs404(t *testing.T) {
	g := newGateway(t)
	c := g.client(t, false)
	for _, p := range []string{"/auth/nope/start", "/auth/nope/callback?code=1&state=2"} {
		resp := g.get(t, c, p)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s = %d, want 404", p, resp.StatusCode)
		}
	}
}

func TestReturnToMustBeRelative(t *testing.T) {
	cases := map[string]string{
		"":                              "/",
		"/whoami":                       "/whoami",
		"/whoami?x=1&y=2":               "/whoami?x=1&y=2",
		"https://evil.test/":            "/",
		"//evil.test/x":                 "/",
		"/\\evil.test":                  "/",
		"javascript:alert(1)":           "/",
		"whoami":                        "/",
		"/auth/dex/start":               "/", // never loop back into sign-in
		"/%2F%2Fevil.test":              "/",
		"/ok/../path":                   "/",
		"/path#frag":                    "/path",
		"/path with space":              "/path%20with%20space",
		" /padded ":                     "/padded",
		"/" + strings.Repeat("a", 3000): "/",
	}
	for in, want := range cases {
		if got := identity.SafeReturnTo(in); got != want {
			t.Errorf("SafeReturnTo(%q) = %q, want %q", in, got, want)
		}
	}

	g := newGateway(t)
	c := g.client(t, true)
	resp := g.signIn(t, c, "https://evil.test/")
	b := resp.Text
	if resp.Request.URL.Host != mustURL(g.srv.URL).Host || !strings.HasPrefix(b, "home /") {
		t.Errorf("open redirect: landed on %s (%q)", resp.Request.URL, b)
	}
}

func TestSignOut(t *testing.T) {
	g := newGateway(t)
	c := g.client(t, true)
	g.signIn(t, c, "")
	w := g.whoami(t, c)
	if w.Anonymous {
		t.Fatal("expected a session")
	}
	resp := g.do(t, c, http.MethodPost, "/auth/signout", url.Values{})
	if resp.Request.URL.Path != "/" {
		t.Errorf("sign-out should land on /, got %s", resp.Request.URL)
	}
	if !g.whoami(t, c).Anonymous {
		t.Error("session must be gone after sign-out")
	}
	if g.st.LiveSessions(w.UserID) != 0 {
		t.Error("the session row must be revoked")
	}
	// Sign-out without a session is harmless.
	resp = g.do(t, c, http.MethodPost, "/auth/signout", url.Values{})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("anonymous sign-out = %d", resp.StatusCode)
	}
	// GET is not allowed (sign-out is state-changing).
	resp = g.get(t, c, "/auth/signout")
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET /auth/signout = %d, want 405", resp.StatusCode)
	}
}

func TestSessionTimeouts(t *testing.T) {
	cases := []struct {
		name  string
		after time.Duration
		alive bool
	}{
		{"fresh", time.Minute, true},
		{"within idle", 11 * time.Hour, true},
		{"idle exceeded", 13 * time.Hour, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newGateway(t)
			start := time.Now()
			g.svc.SetClock(func() time.Time { return start })
			c := g.client(t, true)
			g.signIn(t, c, "")
			g.svc.SetClock(func() time.Time { return start.Add(tc.after) })
			w := g.whoami(t, c)
			if w.Anonymous == tc.alive {
				t.Errorf("after %v anonymous=%v, want alive=%v", tc.after, w.Anonymous, tc.alive)
			}
		})
	}

	// Activity extends the idle window but not the absolute one.
	g := newGateway(t)
	start := time.Now()
	g.svc.SetClock(func() time.Time { return start })
	c := g.client(t, true)
	g.signIn(t, c, "")
	for h := 6; h < 7*24; h += 6 {
		g.svc.SetClock(func() time.Time { return start.Add(time.Duration(h) * time.Hour) })
		if g.whoami(t, c).Anonymous {
			t.Fatalf("session died after %dh of regular activity", h)
		}
	}
	g.svc.SetClock(func() time.Time { return start.Add(7*24*time.Hour + time.Minute) })
	if !g.whoami(t, c).Anonymous {
		t.Error("absolute timeout must end the session despite activity")
	}
}

func TestMiddlewareIgnoresBogusCookies(t *testing.T) {
	g := newGateway(t)
	c := g.client(t, false)
	c.Jar.SetCookies(mustURL(g.srv.URL), []*http.Cookie{{Name: identity.SessionCookie, Value: "not-a-session"}})
	if w := g.whoami(t, c); !w.Anonymous {
		t.Error("unknown session cookie must be anonymous")
	}
}

func TestPrincipalFromEmptyContext(t *testing.T) {
	if identity.PrincipalFrom(context.Background()) != nil {
		t.Error("PrincipalFrom on an empty context must be nil")
	}
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}
