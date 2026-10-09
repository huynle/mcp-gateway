package oauthattack

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/authserver"
)

// Dynamic client registration abuse (RFC 7591, decision ysorv868: open
// registration bounded per address, capped and pruned).

// TestDCRFlooding: the per-address budget answers 429 with Retry-After
// once spent (every attempt spends it, valid or not); the unused-client
// cap answers 429 as well; both recover (window / prune).
func TestDCRFlooding(t *testing.T) {
	g := newGateway(t, withEnv(map[string]string{authserver.EnvRegisterPerMin: "5", authserver.EnvMaxUnusedClients: "3", authserver.EnvClientIdle: "1h"}))
	doc := func(i int) map[string]any {
		return map[string]any{"client_name": "flood " + strconv.Itoa(i), "redirect_uris": []string{"https://app.example.com/cb"}}
	}
	// 3 registrations fill the unused cap.
	for i := range 3 {
		if r := g.registerDoc(t, doc(i)); r.status != http.StatusCreated {
			t.Fatalf("registration %d: %d %s", i, r.status, r.body)
		}
	}
	// The 4th is refused by the cap (429, Retry-After an hour).
	r := g.registerDoc(t, doc(3))
	wantOAuthError(t, r, http.StatusTooManyRequests, "too_many_requests")
	if ra := r.header.Get("Retry-After"); ra != "3600" {
		t.Errorf("cap Retry-After = %q", ra)
	}
	// The 5th attempt spends the last unit of the per-minute budget, the
	// 6th is the rate limit (Retry-After in seconds, within the minute).
	wantOAuthError(t, g.registerDoc(t, doc(4)), http.StatusTooManyRequests, "too_many_requests")
	r = g.registerDoc(t, doc(5))
	wantOAuthError(t, r, http.StatusTooManyRequests, "too_many_requests")
	ra, err := strconv.Atoi(r.header.Get("Retry-After"))
	if err != nil || ra < 1 || ra > 60 {
		t.Errorf("rate-limit Retry-After = %q", r.header.Get("Retry-After"))
	}
	// A malformed document is refused by the limiter too (no probing).
	wantOAuthError(t, postJSON(t, noRedirect, g.base+"/oauth/register", `{"redirect_uris":["javascript:alert(1)"]}`), http.StatusTooManyRequests, "too_many_requests")
	if n := len(g.astore.Clients()); n != 3 {
		t.Errorf("%d clients stored, want 3", n)
	}
	// The window passes: the budget is back, the cap still holds.
	g.clock.Advance(time.Minute)
	wantOAuthError(t, g.registerDoc(t, doc(6)), http.StatusTooManyRequests, "too_many_requests")
	// One client completes a sign-in (it counts as used), freeing a slot.
	br := g.browser(t, true)
	c := client{id: g.astore.Clients()[0].ClientID, redirect: "https://app.example.com/cb"}
	g.issue(t, br, c)
	if r := g.registerDoc(t, doc(7)); r.status != http.StatusCreated {
		t.Errorf("registration after a slot freed: %d %s", r.status, r.body)
	}
	// Idle clients are pruned; their codes and refresh tokens go with them.
	g.clock.Advance(2 * time.Hour)
	clients, _, err := g.authSvc.Prune(t.Context())
	if err != nil || clients != 4 {
		t.Errorf("prune: %d clients, %v", clients, err)
	}
	if n := len(g.astore.RefreshTokens()); n != 0 {
		t.Errorf("%d refresh tokens survived their client's pruning", n)
	}
	// A pruned client is invalid_client at the token endpoint and an
	// error page at authorize.
	wantOAuthError(t, g.refresh(t, c, "gwr_x"), http.StatusUnauthorized, "invalid_client")
	wantErrorPage(t, g.authorize(t, br, g.authorizeParams(c, newPKCE(t), "s")), http.StatusBadRequest)
}

// TestDCRBadMetadata: redirect URIs with dangerous schemes, oversized
// names, too many URIs and other hostile documents are invalid_*
// (400) and never stored.
func TestDCRBadMetadata(t *testing.T) {
	g := newGateway(t)
	many := make([]string, 100)
	for i := range many {
		many[i] = "https://app.example.com/cb/" + strconv.Itoa(i)
	}
	cases := map[string]struct {
		doc  map[string]any
		code string
	}{
		"javascript_redirect":     {map[string]any{"redirect_uris": []string{"javascript:alert(1)"}}, "invalid_redirect_uri"},
		"data_redirect":           {map[string]any{"redirect_uris": []string{"data:text/html,<script>"}}, "invalid_redirect_uri"},
		"custom_scheme_redirect":  {map[string]any{"redirect_uris": []string{"myapp://cb"}}, "invalid_redirect_uri"},
		"file_redirect":           {map[string]any{"redirect_uris": []string{"file:///etc/passwd"}}, "invalid_redirect_uri"},
		"http_non_loopback":       {map[string]any{"redirect_uris": []string{"http://app.example.com/cb"}}, "invalid_redirect_uri"},
		"http_loopback_lookalike": {map[string]any{"redirect_uris": []string{"http://localhost.evil.example/cb"}}, "invalid_redirect_uri"},
		"http_127_subnet":         {map[string]any{"redirect_uris": []string{"http://127.0.0.2/cb"}}, "invalid_redirect_uri"},
		"http_0000":               {map[string]any{"redirect_uris": []string{"http://0.0.0.0/cb"}}, "invalid_redirect_uri"},
		"fragment":                {map[string]any{"redirect_uris": []string{"https://app.example.com/cb#frag"}}, "invalid_redirect_uri"},
		"userinfo":                {map[string]any{"redirect_uris": []string{"https://user@app.example.com/cb"}}, "invalid_redirect_uri"},
		"whitespace":              {map[string]any{"redirect_uris": []string{"https://app.example.com/cb /x"}}, "invalid_redirect_uri"},
		"crlf":                    {map[string]any{"redirect_uris": []string{"https://app.example.com/cb\r\nSet-Cookie: x"}}, "invalid_redirect_uri"},
		"null_byte":               {map[string]any{"redirect_uris": []string{"https://app.example.com/cb\x00"}}, "invalid_redirect_uri"},
		"relative":                {map[string]any{"redirect_uris": []string{"/cb"}}, "invalid_redirect_uri"},
		"no_host":                 {map[string]any{"redirect_uris": []string{"https:///cb"}}, "invalid_redirect_uri"},
		"too_long":                {map[string]any{"redirect_uris": []string{"https://app.example.com/" + strings.Repeat("a", 2100)}}, "invalid_redirect_uri"},
		"empty_list":              {map[string]any{"redirect_uris": []string{}}, "invalid_redirect_uri"},
		"missing_list":            {map[string]any{"client_name": "x"}, "invalid_redirect_uri"},
		"hundred_uris":            {map[string]any{"redirect_uris": many}, "invalid_redirect_uri"},
		"one_bad_among_good":      {map[string]any{"redirect_uris": []string{"https://app.example.com/cb", "http://evil.example/cb"}}, "invalid_redirect_uri"},
		"name_10k":                {map[string]any{"redirect_uris": []string{"https://app.example.com/cb"}, "client_name": strings.Repeat("A", 10000)}, "invalid_client_metadata"},
		"name_control_chars":      {map[string]any{"redirect_uris": []string{"https://app.example.com/cb"}, "client_name": "Evil\nharness"}, "invalid_client_metadata"},
		"auth_method_unknown":     {map[string]any{"redirect_uris": []string{"https://app.example.com/cb"}, "token_endpoint_auth_method": "private_key_jwt"}, "invalid_client_metadata"},
		"grant_implicit":          {map[string]any{"redirect_uris": []string{"https://app.example.com/cb"}, "grant_types": []string{"implicit"}}, "invalid_client_metadata"},
		"grant_client_creds":      {map[string]any{"redirect_uris": []string{"https://app.example.com/cb"}, "grant_types": []string{"client_credentials"}}, "invalid_client_metadata"},
		"grant_refresh_only":      {map[string]any{"redirect_uris": []string{"https://app.example.com/cb"}, "grant_types": []string{"refresh_token"}}, "invalid_client_metadata"},
		"response_type_token":     {map[string]any{"redirect_uris": []string{"https://app.example.com/cb"}, "response_types": []string{"token"}}, "invalid_client_metadata"},
		"scope_unknown":           {map[string]any{"redirect_uris": []string{"https://app.example.com/cb"}, "scope": "admin"}, "invalid_client_metadata"},
		"client_uri_http":         {map[string]any{"redirect_uris": []string{"https://app.example.com/cb"}, "client_uri": "http://x.example"}, "invalid_client_metadata"},
		"logo_uri_javascript":     {map[string]any{"redirect_uris": []string{"https://app.example.com/cb"}, "logo_uri": "javascript:alert(1)"}, "invalid_client_metadata"},
		"redirect_not_strings":    {map[string]any{"redirect_uris": []int{1, 2}}, "invalid_client_metadata"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := g.registerDoc(t, tc.doc)
			wantOAuthError(t, r, http.StatusBadRequest, tc.code)
			if strings.Contains(string(r.body), "<") && name != "data_redirect" {
				t.Errorf("error echoes markup: %s", r.body)
			}
		})
	}
	if n := len(g.astore.Clients()); n != 0 {
		t.Errorf("%d clients stored from refused documents", n)
	}
	t.Run("not_json", func(t *testing.T) {
		wantOAuthError(t, postJSON(t, noRedirect, g.base+"/oauth/register", `redirect_uris=https://x`), http.StatusBadRequest, "invalid_client_metadata")
		wantOAuthError(t, postJSON(t, noRedirect, g.base+"/oauth/register", `[]`), http.StatusBadRequest, "invalid_client_metadata")
	})
	t.Run("oversized_document", func(t *testing.T) {
		body := `{"redirect_uris":["https://app.example.com/cb"],"client_name":"x","software_version":"` + strings.Repeat("v", authserver.MaxRegisterBody) + `"}`
		wantOAuthError(t, postJSON(t, noRedirect, g.base+"/oauth/register", body), http.StatusRequestEntityTooLarge, "invalid_client_metadata")
	})
	t.Run("get_is_405", func(t *testing.T) {
		if r := get(t, noRedirect, g.base+"/oauth/register"); r.status != http.StatusMethodNotAllowed {
			t.Errorf("GET /oauth/register: %d", r.status)
		}
	})
	t.Run("name_is_escaped_on_consent", func(t *testing.T) {
		// A hostile client name is stored verbatim and HTML-escaped where shown.
		r := g.registerDoc(t, map[string]any{"redirect_uris": []string{"https://app.example.com/cb"}, "client_name": `<script>alert("x")</script>`})
		if r.status != http.StatusCreated {
			t.Fatalf("register: %d %s", r.status, r.body)
		}
		c := client{id: r.json()["client_id"].(string), redirect: "https://app.example.com/cb"}
		br := g.browser(t, true)
		page := g.authorize(t, br, g.authorizeParams(c, newPKCE(t), "s"))
		if page.status != http.StatusOK || strings.Contains(string(page.body), "<script>alert") {
			t.Errorf("consent page: %d, unescaped name: %v", page.status, strings.Contains(string(page.body), "<script>alert"))
		}
		if !strings.Contains(string(page.body), "&lt;script&gt;") {
			t.Errorf("consent page does not show the escaped name")
		}
	})
	t.Run("secret_shown_once_and_hashed", func(t *testing.T) {
		r := g.registerDoc(t, map[string]any{"redirect_uris": []string{"https://app.example.com/cb"}, "token_endpoint_auth_method": "client_secret_post"})
		if r.status != http.StatusCreated || r.json()["client_secret"] == nil {
			t.Fatalf("register confidential: %d %s", r.status, r.body)
		}
		secret := r.json()["client_secret"].(string)
		for _, c := range g.astore.Clients() {
			if strings.Contains(string(c.ClientSecretHash), secret) || string(c.ClientSecretHash) == secret {
				t.Error("client secret stored in clear")
			}
		}
	})
}
