package authserver_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/authserver"
	"github.com/huynle/mcp-gateway/internal/store"
)

const (
	csrf        = "csrf-token-value"
	redirectURI = "http://localhost:45678/callback"
	verifier    = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)

func challenge(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// flow drives one client through the server: registration, the
// authorization and consent pages (as the signed-in user f.user) and the
// token endpoint.
type flow struct {
	*svcFixture
	t        *testing.T
	user     string
	clientID string
	secret   string
}

func newFlow(t *testing.T) *flow {
	t.Helper()
	fx := newService(t)
	fl := &flow{svcFixture: fx, t: t, user: alice}
	fl.svc.SetIdentity(func(*http.Request) (string, string) {
		if fl.user == "" {
			return "", ""
		}
		return fl.user, csrf
	})
	code, out := fl.register(t, map[string]any{"client_name": "Claude Code", "redirect_uris": []string{redirectURI, "https://app.example.com/cb"}})
	if code != http.StatusCreated {
		t.Fatalf("register: %d %v", code, out)
	}
	fl.clientID = out["client_id"].(string)
	return fl
}

// authorizeParams is a valid authorization request; tests mutate it.
func (f *flow) authorizeParams() url.Values {
	return url.Values{
		"client_id":             {f.clientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"code_challenge":        {challenge(verifier)},
		"code_challenge_method": {"S256"},
		"state":                 {"xyz"},
		"scope":                 {"mcp"},
		"resource":              {f.cfg.Resource()},
	}
}

func (f *flow) authorize(q url.Values) *httptest.ResponseRecorder {
	f.t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, authserver.AuthorizePath+"?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	f.svc.ServeAuthorize(rec, req)
	return rec
}

func (f *flow) consent(q url.Values, action, csrfToken string) *httptest.ResponseRecorder {
	f.t.Helper()
	form := url.Values{}
	for k, v := range q {
		form[k] = v
	}
	form.Set("action", action)
	form.Set("_csrf", csrfToken)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, authserver.ConsentPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.svc.ServeConsent(rec, req)
	return rec
}

// code runs authorize + approve and returns the issued code.
func (f *flow) code() string {
	f.t.Helper()
	rec := f.consent(f.authorizeParams(), "approve", csrf)
	loc := redirect(f.t, rec)
	if loc.Query().Get("code") == "" || loc.Query().Get("state") != "xyz" {
		f.t.Fatalf("approve redirect = %s", loc)
	}
	return loc.Query().Get("code")
}

func (f *flow) token(form url.Values, headers ...string) (int, map[string]any) {
	f.t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, authserver.TokenPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	rec := httptest.NewRecorder()
	f.svc.ServeToken(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		f.t.Errorf("token response Cache-Control = %q", cc)
	}
	return rec.Code, out
}

func (f *flow) exchange(code string) (int, map[string]any) {
	return f.token(url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI},
		"client_id": {f.clientID}, "code_verifier": {verifier}, "resource": {f.cfg.Resource()},
	})
}

func (f *flow) refresh(refreshToken string, extra ...string) (int, map[string]any) {
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}, "client_id": {f.clientID}}
	for i := 0; i+1 < len(extra); i += 2 {
		form.Set(extra[i], extra[i+1])
	}
	return f.token(form)
}

// tokens runs the whole code flow and returns access + refresh tokens.
func (f *flow) tokens() (access, refresh string) {
	f.t.Helper()
	status, out := f.exchange(f.code())
	if status != http.StatusOK {
		f.t.Fatalf("exchange: %d %v", status, out)
	}
	return out["access_token"].(string), out["refresh_token"].(string)
}

// redirect asserts a 303 and returns its Location.
func redirect(t *testing.T, rec *httptest.ResponseRecorder) *url.URL {
	t.Helper()
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d, want 303; body: %s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

// --- authorize ---------------------------------------------------------------

func TestAuthorizeRequiresSignIn(t *testing.T) {
	f := newFlow(t)
	f.user = ""
	loc := redirect(t, f.authorize(f.authorizeParams()))
	if loc.Path != "/signin" {
		t.Fatalf("redirected to %s", loc)
	}
	back := loc.Query().Get("return_to")
	if !strings.HasPrefix(back, authserver.AuthorizePath+"?") || !strings.Contains(back, "code_challenge=") {
		t.Errorf("return_to = %q", back)
	}
}

func TestAuthorizeRefusesBadClientWithoutRedirecting(t *testing.T) {
	f := newFlow(t)
	for name, mutate := range map[string]func(url.Values){
		"unknown client":        func(q url.Values) { q.Set("client_id", "gwc_nope") },
		"missing client":        func(q url.Values) { q.Del("client_id") },
		"unregistered redirect": func(q url.Values) { q.Set("redirect_uri", "http://localhost:45678/other") },
		"redirect with extra":   func(q url.Values) { q.Set("redirect_uri", redirectURI+"?x=1") },
		"missing redirect":      func(q url.Values) { q.Del("redirect_uri") },
		"evil redirect":         func(q url.Values) { q.Set("redirect_uri", "https://evil.test/cb") },
	} {
		t.Run(name, func(t *testing.T) {
			q := f.authorizeParams()
			mutate(q)
			rec := f.authorize(q)
			if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
				t.Errorf("status %d, Location %q; want 400 and no redirect", rec.Code, rec.Header().Get("Location"))
			}
			if strings.Contains(rec.Body.String(), "evil.test") {
				t.Errorf("error page echoes the attacker's URL")
			}
		})
	}
}

func TestAuthorizeRedirectsProtocolErrors(t *testing.T) {
	f := newFlow(t)
	cases := map[string]struct {
		mutate func(url.Values)
		want   string
	}{
		"missing pkce":          {func(q url.Values) { q.Del("code_challenge"); q.Del("code_challenge_method") }, "invalid_request"},
		"plain pkce":            {func(q url.Values) { q.Set("code_challenge_method", "plain"); q.Set("code_challenge", verifier) }, "invalid_request"},
		"no pkce method":        {func(q url.Values) { q.Del("code_challenge_method") }, "invalid_request"},
		"short challenge":       {func(q url.Values) { q.Set("code_challenge", "abc") }, "invalid_request"},
		"missing state":         {func(q url.Values) { q.Del("state") }, "invalid_request"},
		"missing resource":      {func(q url.Values) { q.Del("resource") }, "invalid_target"},
		"wrong resource":        {func(q url.Values) { q.Set("resource", "https://other.example.com/mcp") }, "invalid_target"},
		"resource with slash":   {func(q url.Values) { q.Set("resource", f.cfg.Resource()+"/") }, "invalid_target"},
		"resource is issuer":    {func(q url.Values) { q.Set("resource", f.cfg.Issuer) }, "invalid_target"},
		"token response type":   {func(q url.Values) { q.Set("response_type", "token") }, "unsupported_response_type"},
		"missing response type": {func(q url.Values) { q.Del("response_type") }, "invalid_request"},
		"unknown scope":         {func(q url.Values) { q.Set("scope", "mcp admin") }, "invalid_scope"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			q := f.authorizeParams()
			c.mutate(q)
			loc := redirect(t, f.authorize(q))
			if !strings.HasPrefix(loc.String(), redirectURI+"?") {
				t.Fatalf("redirected to %s", loc)
			}
			if got := loc.Query().Get("error"); got != c.want {
				t.Errorf("error = %q (%q), want %q", got, loc.Query().Get("error_description"), c.want)
			}
			if loc.Query().Get("code") != "" {
				t.Error("a code was issued")
			}
			if q.Get("state") != "" && loc.Query().Get("state") != "xyz" {
				t.Errorf("state not echoed: %s", loc)
			}
		})
	}
	// The same checks apply to the consent POST: a tampered hidden field
	// cannot get a code.
	q := f.authorizeParams()
	q.Set("resource", "https://other.example.com/mcp")
	loc := redirect(t, f.consent(q, "approve", csrf))
	if loc.Query().Get("error") != "invalid_target" || loc.Query().Get("code") != "" {
		t.Errorf("consent with tampered resource: %s", loc)
	}
	if n := len(f.st.Codes()); n != 0 {
		t.Errorf("%d codes stored", n)
	}
}

func TestAuthorizeRendersConsent(t *testing.T) {
	f := newFlow(t)
	rec := f.authorize(f.authorizeParams())
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"Claude Code", f.cfg.Resource(), "localhost:45678", csrf, `name="code_challenge"`, `value="approve"`, `value="deny"`, "Cache-Control"} {
		if want == "Cache-Control" {
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Errorf("consent page is cacheable")
			}
			continue
		}
		if !strings.Contains(body, want) {
			t.Errorf("consent page lacks %q", want)
		}
	}
	// Read-only scope is explained as such.
	q := f.authorizeParams()
	q.Set("scope", "mcp:read")
	if b := f.authorize(q).Body.String(); !strings.Contains(strings.ToLower(b), "read") {
		t.Errorf("read scope not described")
	}
	// A client name is HTML-escaped.
	_, out := f.register(t, map[string]any{"client_name": `<img src=x onerror=alert(1)>`, "redirect_uris": []string{redirectURI}})
	q = f.authorizeParams()
	q.Set("client_id", out["client_id"].(string))
	if b := f.authorize(q).Body.String(); strings.Contains(b, "<img") {
		t.Error("client name not escaped")
	}
}

func TestConsentDeny(t *testing.T) {
	f := newFlow(t)
	loc := redirect(t, f.consent(f.authorizeParams(), "deny", csrf))
	if loc.Query().Get("error") != "access_denied" || loc.Query().Get("state") != "xyz" || loc.Query().Get("code") != "" {
		t.Errorf("deny redirect = %s", loc)
	}
	if n := len(f.st.Codes()); n != 0 {
		t.Errorf("%d codes stored on deny", n)
	}
}

func TestConsentNeedsSessionAndCSRF(t *testing.T) {
	f := newFlow(t)
	if rec := f.consent(f.authorizeParams(), "approve", "wrong"); rec.Code != http.StatusForbidden {
		t.Errorf("wrong csrf: %d", rec.Code)
	}
	f.user = ""
	if rec := f.consent(f.authorizeParams(), "approve", csrf); rec.Code != http.StatusUnauthorized && rec.Code != http.StatusSeeOther {
		t.Errorf("anonymous consent: %d", rec.Code)
	}
	if n := len(f.st.Codes()); n != 0 {
		t.Errorf("%d codes stored", n)
	}
}

func TestConsentApproveIssuesBoundCode(t *testing.T) {
	f := newFlow(t)
	code := f.code()
	if len(code) < 32 {
		t.Errorf("code too short: %q", code)
	}
	rows := f.st.Codes()
	if len(rows) != 1 {
		t.Fatalf("%d codes", len(rows))
	}
	c := rows[0]
	if string(c.CodeHash) == code || c.UserID != alice || c.RedirectURI != redirectURI || c.Resource != f.cfg.Resource() || c.CodeChallenge != challenge(verifier) || c.Scope != "mcp" || !c.ExpiresAt.Equal(t0.Add(f.cfg.CodeTTL)) || c.ConsumedAt != nil {
		t.Errorf("stored code = %+v", c)
	}
	if cl := f.st.Clients()[0]; cl.LastUsedAt == nil {
		t.Errorf("client not marked used at consent")
	}
}

// --- token: authorization_code -----------------------------------------------

func TestTokenExchange(t *testing.T) {
	f := newFlow(t)
	status, out := f.exchange(f.code())
	if status != http.StatusOK {
		t.Fatalf("exchange: %d %v", status, out)
	}
	if out["token_type"] != "Bearer" || out["expires_in"] != float64(3600) || out["scope"] != "mcp" {
		t.Errorf("response = %v", out)
	}
	access, _ := out["access_token"].(string)
	refresh, _ := out["refresh_token"].(string)
	if len(strings.Split(access, ".")) != 3 || len(refresh) < 32 {
		t.Errorf("tokens = %q / %q", access, refresh)
	}
	p, err := f.svc.Authenticator().Authenticate(context.Background(), access)
	if err != nil {
		t.Fatalf("access token rejected by the gateway's own authenticator: %v", err)
	}
	rows := f.st.RefreshTokens()
	if len(rows) != 1 {
		t.Fatalf("%d refresh tokens", len(rows))
	}
	rt := rows[0]
	if p.UserID != alice || p.TokenID != rt.FamilyID || rt.FamilyID != rt.ID || string(rt.TokenHash) == refresh || rt.Resource != f.cfg.Resource() || !rt.ExpiresAt.Equal(t0.Add(f.cfg.RefreshTokenTTL)) {
		t.Errorf("principal %+v / refresh row %+v", p, rt)
	}
	if c := f.st.Codes()[0]; c.ConsumedAt == nil || c.FamilyID == nil || *c.FamilyID != rt.FamilyID {
		t.Errorf("code after exchange = %+v", c)
	}
}

func TestTokenRejectsBadCodeExchanges(t *testing.T) {
	f := newFlow(t)
	_, out := f.register(t, map[string]any{"client_name": "other", "redirect_uris": []string{redirectURI}})
	otherClient := out["client_id"].(string)
	cases := map[string]struct {
		mutate func(url.Values)
		want   string
	}{
		"wrong verifier":      {func(v url.Values) { v.Set("code_verifier", strings.Repeat("a", 43)) }, "invalid_grant"},
		"missing verifier":    {func(v url.Values) { v.Del("code_verifier") }, "invalid_request"},
		"short verifier":      {func(v url.Values) { v.Set("code_verifier", "short") }, "invalid_request"},
		"wrong client":        {func(v url.Values) { v.Set("client_id", otherClient) }, "invalid_grant"},
		"unknown client":      {func(v url.Values) { v.Set("client_id", "gwc_nope") }, "invalid_client"},
		"wrong redirect":      {func(v url.Values) { v.Set("redirect_uri", "https://app.example.com/cb") }, "invalid_grant"},
		"missing redirect":    {func(v url.Values) { v.Del("redirect_uri") }, "invalid_grant"},
		"wrong resource":      {func(v url.Values) { v.Set("resource", "https://other.example.com/mcp") }, "invalid_target"},
		"unknown code":        {func(v url.Values) { v.Set("code", "nope") }, "invalid_grant"},
		"unsupported grant":   {func(v url.Values) { v.Set("grant_type", "password") }, "unsupported_grant_type"},
		"missing grant":       {func(v url.Values) { v.Del("grant_type") }, "invalid_request"},
		"client credentials":  {func(v url.Values) { v.Set("grant_type", "client_credentials") }, "unsupported_grant_type"},
		"missing code":        {func(v url.Values) { v.Del("code") }, "invalid_request"},
		"resource not needed": {func(v url.Values) { v.Del("resource") }, ""}, // bound by the code; omission is accepted
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			code := f.code()
			form := url.Values{
				"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI},
				"client_id": {f.clientID}, "code_verifier": {verifier}, "resource": {f.cfg.Resource()},
			}
			c.mutate(form)
			status, out := f.token(form)
			if c.want == "" {
				if status != http.StatusOK {
					t.Errorf("status %d %v, want 200", status, out)
				}
				return
			}
			wantStatus := http.StatusBadRequest
			if c.want == "invalid_client" {
				wantStatus = http.StatusUnauthorized
			}
			if status != wantStatus || out["error"] != c.want {
				t.Errorf("status %d, body %v; want %d %s", status, out, wantStatus, c.want)
			}
		})
	}
	// Wrong Content-Type and a GET are refused.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, authserver.TokenPath, strings.NewReader(`{"grant_type":"authorization_code"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	f.svc.ServeToken(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("JSON body: %d", rec.Code)
	}
	req = httptest.NewRequestWithContext(context.Background(), http.MethodGet, authserver.TokenPath+"?grant_type=authorization_code", nil)
	rec = httptest.NewRecorder()
	f.svc.ServeToken(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d", rec.Code)
	}
}

func TestCodeIsSingleUseAndReplayRevokesFamily(t *testing.T) {
	f := newFlow(t)
	code := f.code()
	status, out := f.exchange(code)
	if status != http.StatusOK {
		t.Fatalf("first exchange: %d %v", status, out)
	}
	refresh := out["refresh_token"].(string)
	status, out = f.exchange(code)
	if status != http.StatusBadRequest || out["error"] != "invalid_grant" {
		t.Fatalf("replay: %d %v", status, out)
	}
	// OAuth 2.1 section 4.1.3: the tokens issued from the replayed code are
	// revoked.
	if status, out := f.refresh(refresh); status != http.StatusBadRequest || out["error"] != "invalid_grant" {
		t.Errorf("refresh after code replay: %d %v", status, out)
	}
	for _, rt := range f.st.RefreshTokens() {
		if rt.RevokedAt == nil {
			t.Errorf("refresh token %s not revoked after code replay", rt.ID)
		}
	}
}

func TestCodeExpires(t *testing.T) {
	f := newFlow(t)
	code := f.code()
	f.now = t0.Add(f.cfg.CodeTTL + time.Second)
	if status, out := f.exchange(code); status != http.StatusBadRequest || out["error"] != "invalid_grant" {
		t.Errorf("expired code: %d %v", status, out)
	}
}

func TestExchangeRefusesDisabledUser(t *testing.T) {
	f := newFlow(t)
	code := f.code()
	f.st.SetUser(alice, store.UserDisabled, nil)
	if status, out := f.exchange(code); status != http.StatusBadRequest || out["error"] != "invalid_grant" {
		t.Errorf("disabled user: %d %v", status, out)
	}
}

// --- token: refresh_token ----------------------------------------------------

func TestRefreshRotatesAndDetectsReuse(t *testing.T) {
	f := newFlow(t)
	access1, refresh1 := f.tokens()
	f.now = t0.Add(10 * time.Minute)
	status, out := f.refresh(refresh1)
	if status != http.StatusOK {
		t.Fatalf("refresh: %d %v", status, out)
	}
	access2, refresh2 := out["access_token"].(string), out["refresh_token"].(string)
	if refresh2 == refresh1 || access2 == access1 || out["scope"] != "mcp" {
		t.Errorf("rotation did not issue new tokens: %v", out)
	}
	rows := f.st.RefreshTokens()
	if len(rows) != 2 || rows[0].RotatedAt == nil || rows[1].RotatedFrom == nil || *rows[1].RotatedFrom != rows[0].ID || rows[1].FamilyID != rows[0].FamilyID || !rows[1].ExpiresAt.Equal(f.now.Add(f.cfg.RefreshTokenTTL)) {
		t.Errorf("rows after rotation = %+v", rows)
	}
	if p, err := f.svc.Authenticator().Authenticate(context.Background(), access2); err != nil || p.TokenID != rows[0].FamilyID {
		t.Errorf("new access token: %v %v", p, err)
	}
	// Reuse of the rotated token: the whole family is revoked, including
	// the current token.
	if status, out := f.refresh(refresh1); status != http.StatusBadRequest || out["error"] != "invalid_grant" {
		t.Errorf("reuse: %d %v", status, out)
	}
	if status, out := f.refresh(refresh2); status != http.StatusBadRequest || out["error"] != "invalid_grant" {
		t.Errorf("current token after reuse: %d %v", status, out)
	}
	for _, rt := range f.st.RefreshTokens() {
		if rt.RevokedAt == nil {
			t.Errorf("token %s survived reuse detection", rt.ID)
		}
	}
}

func TestRefreshRules(t *testing.T) {
	f := newFlow(t)
	_, out := f.register(t, map[string]any{"client_name": "other", "redirect_uris": []string{redirectURI}})
	otherClient := out["client_id"].(string)

	t.Run("wrong client", func(t *testing.T) {
		_, refresh := f.tokens()
		if status, out := f.refresh(refresh, "client_id", otherClient); status != http.StatusBadRequest || out["error"] != "invalid_grant" {
			t.Errorf("%d %v", status, out)
		}
	})
	t.Run("unknown token", func(t *testing.T) {
		if status, out := f.refresh("gwr_nope"); status != http.StatusBadRequest || out["error"] != "invalid_grant" {
			t.Errorf("%d %v", status, out)
		}
	})
	t.Run("missing token", func(t *testing.T) {
		if status, out := f.token(url.Values{"grant_type": {"refresh_token"}, "client_id": {f.clientID}}); status != http.StatusBadRequest || out["error"] != "invalid_request" {
			t.Errorf("%d %v", status, out)
		}
	})
	t.Run("expired", func(t *testing.T) {
		_, refresh := f.tokens()
		f.now = t0.Add(f.cfg.RefreshTokenTTL + time.Second)
		defer func() { f.now = t0 }()
		if status, out := f.refresh(refresh); status != http.StatusBadRequest || out["error"] != "invalid_grant" {
			t.Errorf("%d %v", status, out)
		}
	})
	t.Run("narrow scope", func(t *testing.T) {
		_, refresh := f.tokens()
		status, out := f.refresh(refresh, "scope", "mcp:read")
		if status != http.StatusOK || out["scope"] != "mcp:read" {
			t.Fatalf("%d %v", status, out)
		}
		p, err := f.svc.Authenticator().Authenticate(context.Background(), out["access_token"].(string))
		if err != nil || !p.Scope.ReadOnly {
			t.Errorf("narrowed token not read-only: %v %v", p, err)
		}
		// The narrowed family cannot widen again.
		if status, out := f.refresh(out["refresh_token"].(string), "scope", "mcp"); status != http.StatusBadRequest || out["error"] != "invalid_scope" {
			t.Errorf("widen: %d %v", status, out)
		}
	})
	t.Run("wrong resource", func(t *testing.T) {
		_, refresh := f.tokens()
		if status, out := f.refresh(refresh, "resource", "https://other.example.com/mcp"); status != http.StatusBadRequest || out["error"] != "invalid_target" {
			t.Errorf("%d %v", status, out)
		}
	})
	t.Run("disabled user", func(t *testing.T) {
		_, refresh := f.tokens()
		f.st.SetUser(alice, store.UserDisabled, nil)
		defer func() { signedIn := t0.Add(-time.Hour); f.st.AddUser(alice, &signedIn) }()
		if status, out := f.refresh(refresh); status != http.StatusBadRequest || out["error"] != "invalid_grant" {
			t.Errorf("%d %v", status, out)
		}
	})
	t.Run("stale sign-in", func(t *testing.T) {
		_, refresh := f.tokens()
		stale := t0.Add(-f.cfg.SignInMaxAge - time.Hour)
		f.st.AddUser(alice, &stale)
		defer func() { signedIn := t0.Add(-time.Hour); f.st.AddUser(alice, &signedIn) }()
		status, out := f.refresh(refresh)
		if status != http.StatusBadRequest || out["error"] != "invalid_grant" || !strings.Contains(out["error_description"].(string), "sign in") {
			t.Errorf("%d %v", status, out)
		}
	})
}

// --- client authentication ---------------------------------------------------

func TestConfidentialClientMustAuthenticate(t *testing.T) {
	f := newFlow(t)
	_, out := f.register(t, map[string]any{"client_name": "server app", "redirect_uris": []string{redirectURI}, "token_endpoint_auth_method": "client_secret_basic"})
	f.clientID, f.secret = out["client_id"].(string), out["client_secret"].(string)
	code := f.code()
	if status, out := f.exchange(code); status != http.StatusUnauthorized || out["error"] != "invalid_client" {
		t.Fatalf("no secret: %d %v", status, out)
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {f.code()}, "redirect_uri": {redirectURI}, "code_verifier": {verifier}, "resource": {f.cfg.Resource()}}
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(f.clientID)+":"+url.QueryEscape("wrong")))
	if status, out := f.token(form, "Authorization", basic); status != http.StatusUnauthorized || out["error"] != "invalid_client" {
		t.Fatalf("wrong secret: %d %v", status, out)
	}
	basic = "Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(f.clientID)+":"+url.QueryEscape(f.secret)))
	if status, out := f.token(form, "Authorization", basic); status != http.StatusOK {
		t.Fatalf("basic: %d %v", status, out)
	}
	form.Set("code", f.code())
	form.Set("client_id", f.clientID)
	form.Set("client_secret", f.secret)
	if status, out := f.token(form); status != http.StatusOK {
		t.Fatalf("post: %d %v", status, out)
	}
}

// --- revocation --------------------------------------------------------------

func (f *flow) revoke(token, clientID string) int {
	f.t.Helper()
	form := url.Values{"token": {token}, "client_id": {clientID}, "token_type_hint": {"refresh_token"}}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, authserver.RevokePath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.svc.ServeRevoke(rec, req)
	return rec.Code
}

func TestRevokeEndpoint(t *testing.T) {
	f := newFlow(t)
	_, out := f.register(t, map[string]any{"client_name": "other", "redirect_uris": []string{redirectURI}})
	otherClient := out["client_id"].(string)
	access, refresh := f.tokens()
	// Another client cannot revoke it, and the answer does not say so.
	if code := f.revoke(refresh, otherClient); code != http.StatusOK {
		t.Errorf("other client: %d", code)
	}
	if status, _ := f.refresh(refresh); status != http.StatusOK {
		t.Fatalf("token revoked by another client")
	}
	_, refresh = f.tokens()
	if code := f.revoke(refresh, f.clientID); code != http.StatusOK {
		t.Errorf("revoke: %d", code)
	}
	if status, out := f.refresh(refresh); status != http.StatusBadRequest || out["error"] != "invalid_grant" {
		t.Errorf("refresh after revoke: %d %v", status, out)
	}
	if code := f.revoke("unknown", f.clientID); code != http.StatusOK {
		t.Errorf("unknown token: %d", code)
	}
	if code := f.revoke(access, f.clientID); code != http.StatusOK { // access tokens are stateless; accepted, no-op
		t.Errorf("access token: %d", code)
	}
	if code := f.revoke(refresh, "gwc_nope"); code != http.StatusUnauthorized {
		t.Errorf("unknown client: %d", code)
	}
}

// --- connected harnesses page + disable hook ---------------------------------

func (f *flow) harnesses() *httptest.ResponseRecorder {
	f.t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, authserver.HarnessesPath, nil)
	rec := httptest.NewRecorder()
	f.svc.ServeHarnesses(rec, req)
	return rec
}

func (f *flow) revokeHarness(familyID string) *httptest.ResponseRecorder {
	f.t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, authserver.HarnessesPath+"/"+familyID+"/revoke", strings.NewReader(url.Values{"_csrf": {csrf}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("id", familyID)
	rec := httptest.NewRecorder()
	f.svc.ServeHarnessRevoke(rec, req)
	return rec
}

func TestHarnessesPage(t *testing.T) {
	f := newFlow(t)
	if rec := f.harnesses(); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "No harnesses") {
		t.Errorf("empty page: %d %s", rec.Code, rec.Body.String())
	}
	_, refresh := f.tokens()
	f.now = t0.Add(time.Hour)
	if status, _ := f.refresh(refresh); status != http.StatusOK {
		t.Fatal("refresh")
	}
	rec := f.harnesses()
	body := rec.Body.String()
	family := f.st.RefreshTokens()[0].FamilyID
	for _, want := range []string{"Claude Code", "2026-10-08 12:00", "2026-10-08 13:00", "/harnesses/" + family + "/revoke", csrf} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if strings.Count(body, "Claude Code") != 1 {
		t.Errorf("a rotated family is listed more than once")
	}
	// Bob sees nothing and cannot revoke Alice's harness.
	f.user = bob
	if b := f.harnesses().Body.String(); strings.Contains(b, "Claude Code") {
		t.Error("bob sees alice's harness")
	}
	if rec := f.revokeHarness(family); rec.Code != http.StatusNotFound {
		t.Errorf("bob revoking alice's harness: %d", rec.Code)
	}
	f.user = alice
	loc := redirect(t, f.revokeHarness(family))
	if loc.Path != authserver.HarnessesPath {
		t.Errorf("redirect to %s", loc)
	}
	if b := f.harnesses().Body.String(); !strings.Contains(b, "revoked") {
		t.Error("revoked harness not shown as revoked")
	}
	for _, rt := range f.st.RefreshTokens() {
		if rt.RevokedAt == nil {
			t.Errorf("token %s not revoked", rt.ID)
		}
	}
	f.user = ""
	if rec := f.harnesses(); rec.Code != http.StatusUnauthorized && rec.Code != http.StatusSeeOther {
		t.Errorf("anonymous: %d", rec.Code)
	}
}

func TestDisableHookRevokesEverything(t *testing.T) {
	f := newFlow(t)
	_, refresh := f.tokens()
	code := f.code() // an unconsumed code
	if err := f.svc.DisableHook()(context.Background(), nil, alice); err != nil {
		t.Fatalf("hook: %v", err)
	}
	if status, _ := f.refresh(refresh); status != http.StatusBadRequest {
		t.Error("refresh token survived disable")
	}
	if status, _ := f.exchange(code); status != http.StatusBadRequest {
		t.Error("pending code survived disable")
	}
}
