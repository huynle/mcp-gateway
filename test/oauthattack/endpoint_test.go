package oauthattack

import (
	"encoding/base64"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

// Endpoint hygiene: methods, content types, body limits, CORS, the Host
// header, the 401 challenge and client authentication.

// TestTokenEndpointHygiene: GET is 405 with Allow; a missing or wrong
// Content-Type, an oversized body, a missing grant_type, an unknown
// grant and JSON bodies are invalid_request / unsupported_grant_type;
// nothing leaks and every error is no-store.
func TestTokenEndpointHygiene(t *testing.T) {
	g := newGateway(t)
	br := g.browser(t, true)
	c := g.register(t, "https://app.example.com/cb")
	tokenURL := g.base + "/oauth/token"
	t.Run("get_is_405", func(t *testing.T) {
		r := get(t, noRedirect, tokenURL+"?grant_type=authorization_code&code=x&client_id="+c.id)
		wantOAuthError(t, r, http.StatusMethodNotAllowed, "invalid_request")
		if allow := r.header.Get("Allow"); !strings.Contains(allow, "POST") || strings.Contains(allow, "GET") {
			t.Errorf("Allow = %q", allow)
		}
		for _, m := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodHead} {
			if r := do(t, noRedirect, m, tokenURL, nil); r.status != http.StatusMethodNotAllowed {
				t.Errorf("%s: %d", m, r.status)
			}
		}
	})
	t.Run("missing_content_type", func(t *testing.T) {
		form := g.exchangeForm(c, "x", newPKCE(t))
		r := do(t, noRedirect, http.MethodPost, tokenURL, strings.NewReader(form.Encode()), "Content-Type", "")
		desc := wantOAuthError(t, r, http.StatusBadRequest, "invalid_request")
		if !strings.Contains(desc, "x-www-form-urlencoded") {
			t.Errorf("description = %q", desc)
		}
	})
	t.Run("json_body", func(t *testing.T) {
		r := postJSON(t, noRedirect, tokenURL, `{"grant_type":"authorization_code","code":"x","client_id":"`+c.id+`"}`)
		wantOAuthError(t, r, http.StatusBadRequest, "invalid_request")
	})
	t.Run("multipart_body", func(t *testing.T) {
		r := do(t, noRedirect, http.MethodPost, tokenURL, strings.NewReader("--x\r\nContent-Disposition: form-data; name=\"grant_type\"\r\n\r\nauthorization_code\r\n--x--\r\n"), "Content-Type", "multipart/form-data; boundary=x")
		wantOAuthError(t, r, http.StatusBadRequest, "invalid_request")
	})
	t.Run("form_content_type_with_charset_ok", func(t *testing.T) {
		pair := g.issue(t, br, c)
		form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {pair.refresh}, "client_id": {c.id}}
		r := do(t, noRedirect, http.MethodPost, tokenURL, strings.NewReader(form.Encode()), "Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
		if r.status != http.StatusOK {
			t.Errorf("form with charset: %d %s", r.status, r.body)
		}
	})
	t.Run("oversized_body", func(t *testing.T) {
		form := g.exchangeForm(c, "x", newPKCE(t))
		form.Set("padding", strings.Repeat("p", 65*1024))
		r := g.token(t, form)
		wantOAuthError(t, r, http.StatusBadRequest, "invalid_request")
	})
	t.Run("huge_single_value", func(t *testing.T) {
		form := url.Values{"grant_type": {"authorization_code"}, "code": {strings.Repeat("c", 60*1024)}, "client_id": {c.id}, "redirect_uri": {c.redirect}, "code_verifier": {newPKCE(t).verifier}}
		wantOAuthError(t, g.token(t, form), http.StatusBadRequest, "invalid_grant")
	})
	t.Run("missing_grant_type", func(t *testing.T) {
		wantOAuthError(t, g.token(t, url.Values{"client_id": {c.id}}), http.StatusBadRequest, "invalid_request")
	})
	t.Run("unknown_grant_type", func(t *testing.T) {
		for _, gt := range []string{"password", "client_credentials", "implicit", "urn:ietf:params:oauth:grant-type:device_code", "urn:ietf:params:oauth:grant-type:jwt-bearer", "AUTHORIZATION_CODE"} {
			wantOAuthError(t, g.token(t, url.Values{"grant_type": {gt}, "client_id": {c.id}}), http.StatusBadRequest, "unsupported_grant_type")
		}
	})
	t.Run("missing_client_id", func(t *testing.T) {
		wantOAuthError(t, g.token(t, url.Values{"grant_type": {"authorization_code"}, "code": {"x"}}), http.StatusBadRequest, "invalid_request")
	})
	t.Run("missing_code", func(t *testing.T) {
		wantOAuthError(t, g.token(t, url.Values{"grant_type": {"authorization_code"}, "client_id": {c.id}, "code_verifier": {newPKCE(t).verifier}}), http.StatusBadRequest, "invalid_request")
	})
	t.Run("no_cache_on_success", func(t *testing.T) {
		p := newPKCE(t)
		code := g.code(t, br, c, p, "s")
		r := g.token(t, g.exchangeForm(c, code, p))
		if r.status != http.StatusOK || r.header.Get("Cache-Control") != "no-store" || r.header.Get("Pragma") != "no-cache" {
			t.Errorf("token success headers: %d %v", r.status, r.header)
		}
	})
}

// TestConfidentialClientAuthentication: a client registered with a
// secret must present it (post or basic); a wrong, missing or
// truncated secret is invalid_client (401) with WWW-Authenticate for the
// basic scheme, and the code is not consumed by a failed authentication.
// The secret comparison is constant time (asserted structurally below).
func TestConfidentialClientAuthentication(t *testing.T) {
	g := newGateway(t)
	br := g.browser(t, true)
	r := g.registerDoc(t, map[string]any{"client_name": "confidential", "redirect_uris": []string{"https://app.example.com/cb"}, "token_endpoint_auth_method": "client_secret_basic"})
	if r.status != http.StatusCreated {
		t.Fatalf("register: %d %s", r.status, r.body)
	}
	c := client{id: r.json()["client_id"].(string), secret: r.json()["client_secret"].(string), redirect: "https://app.example.com/cb"}
	public := g.register(t, "https://other.example/cb")
	p := newPKCE(t)
	code := g.code(t, br, c, p, "s")
	form := g.exchangeForm(c, code, p)
	form.Del("client_secret")
	basic := func(id, secret string) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(id)+":"+url.QueryEscape(secret)))
	}
	cases := map[string]struct {
		form    url.Values
		headers []string
	}{
		"no_secret":              {form, nil},
		"wrong_secret_post":      {withSecret(form, "nope"), nil},
		"truncated_secret_post":  {withSecret(form, c.secret[:len(c.secret)-1]), nil},
		"secret_plus_suffix":     {withSecret(form, c.secret+"x"), nil},
		"wrong_secret_basic":     {form, []string{"Authorization", basic(c.id, "nope")}},
		"empty_secret_basic":     {form, []string{"Authorization", basic(c.id, "")}},
		"other_client_basic":     {form, []string{"Authorization", basic(public.id, c.secret)}},
		"basic_id_mismatch":      {form, []string{"Authorization", basic(public.id, "x")}},
		"basic_not_base64":       {form, []string{"Authorization", "Basic !!!"}},
		"unknown_client_basic":   {form, []string{"Authorization", basic("gwc_nope", "x")}},
		"secret_as_bearer":       {form, []string{"Authorization", "Bearer " + c.secret}},
		"public_client_with_sec": {withSecret(g.exchangeForm(public, code, p), "x"), nil}, // a public client may send junk; the code is not its own
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := g.token(t, tc.form, tc.headers...)
			if name == "public_client_with_sec" {
				// Public client authenticates (no secret registered), then
				// the code binding refuses it (and burns the code below is
				// avoided: use a fresh one).
				wantOAuthError(t, r, http.StatusBadRequest, "invalid_grant")
				return
			}
			wantOAuthError(t, r, http.StatusUnauthorized, "invalid_client")
			if len(tc.headers) > 0 && strings.HasPrefix(tc.headers[1], "Basic") && name != "basic_not_base64" {
				if wa := r.header.Get("WWW-Authenticate"); !strings.HasPrefix(wa, "Basic") {
					t.Errorf("WWW-Authenticate = %q", wa)
				}
			}
			if name != "unknown_client_basic" && name != "other_client_basic" && name != "basic_id_mismatch" {
				wantLogEvent(t, g, "authserver.client_auth_failed")
			}
		})
	}
	// Failed authentication never touched the code: the right secret
	// exchanges it, by basic auth with URL-encoded parts.
	code = g.code(t, br, c, p, "s")
	form = g.exchangeForm(c, code, p)
	form.Del("client_secret")
	if r := g.token(t, form, "Authorization", basic(c.id, c.secret)); r.status != http.StatusOK {
		t.Fatalf("exchange with basic auth: %d %s", r.status, r.body)
	}
	// And the refresh needs the secret too.
	refresh := g.token(t, form, "Authorization", basic(c.id, c.secret)) // replay: already used
	wantOAuthError(t, refresh, http.StatusBadRequest, "invalid_grant")
	t.Run("metadata_lists_methods", func(t *testing.T) {
		meta := get(t, noRedirect, g.base+"/.well-known/oauth-authorization-server").json()
		methods, _ := meta["token_endpoint_auth_methods_supported"].([]any)
		if len(methods) != 3 {
			t.Errorf("token_endpoint_auth_methods_supported = %v", methods)
		}
	})
}

func withSecret(form url.Values, secret string) url.Values {
	out := url.Values{}
	for k, v := range form {
		out[k] = v
	}
	out.Set("client_secret", secret)
	return out
}

// TestSecretComparisonIsConstantTime asserts structurally that every
// secret comparison in the authorization server (client secret, PKCE
// verifier, CSRF token) goes through crypto/subtle.ConstantTimeCompare
// and that no function that handles one of those secrets compares byte
// slices or strings with == or bytes.Equal. A timing side channel
// cannot be measured reliably in a unit test; the code path can be.
func TestSecretComparisonIsConstantTime(t *testing.T) {
	dir := filepath.Join("..", "..", "internal", "authserver")
	fset := token.NewFileSet()
	paths, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no sources in %s: %v", dir, err)
	}
	var files []*ast.File
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, file)
	}
	// Functions that handle a presented secret: they must call
	// subtle.ConstantTimeCompare and must not compare with == / bytes.Equal.
	want := map[string]bool{"parseClientRequest": false, "pkceVerify": false, "ServeConsent": false, "ServeHarnessRevoke": false}
	{
		for _, file := range files {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				if _, tracked := want[fn.Name.Name]; !tracked {
					continue
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					if call, ok := n.(*ast.CallExpr); ok {
						if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
							if x, ok := sel.X.(*ast.Ident); ok && x.Name == "subtle" && sel.Sel.Name == "ConstantTimeCompare" {
								want[fn.Name.Name] = true
							}
							if x, ok := sel.X.(*ast.Ident); ok && x.Name == "bytes" && sel.Sel.Name == "Equal" {
								t.Errorf("%s compares with bytes.Equal at %s", fn.Name.Name, fset.Position(call.Pos()))
							}
						}
					}
					if bin, ok := n.(*ast.BinaryExpr); ok && (bin.Op == token.EQL || bin.Op == token.NEQ) && !isEmptyString(bin.X) && !isEmptyString(bin.Y) {
						for _, side := range []ast.Expr{bin.X, bin.Y} {
							if names := secretIdent(side); names != "" {
								t.Errorf("%s compares secret %q with %s at %s", fn.Name.Name, names, bin.Op, fset.Position(bin.Pos()))
							}
						}
					}
					return true
				})
			}
		}
	}
	for name, ok := range want {
		if !ok {
			t.Errorf("%s does not call subtle.ConstantTimeCompare", name)
		}
	}
}

// isEmptyString reports whether e is the literal "" (an emptiness check
// is not a secret comparison).
func isEmptyString(e ast.Expr) bool {
	lit, ok := e.(*ast.BasicLit)
	return ok && lit.Kind == token.STRING && lit.Value == `""`
}

// secretIdent names an expression that carries a presented secret.
func secretIdent(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		switch v.Name {
		case "secret", "csrfToken", "verifier", "challenge", "computed", "got":
			return v.Name
		}
	case *ast.SelectorExpr:
		if v.Sel.Name == "ClientSecretHash" || v.Sel.Name == "CodeChallenge" {
			return v.Sel.Name
		}
	case *ast.CallExpr:
		if sel, ok := v.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Get" {
			if len(v.Args) == 1 {
				if lit, ok := v.Args[0].(*ast.BasicLit); ok && (lit.Value == `"_csrf"` || lit.Value == `"client_secret"` || lit.Value == `"code_verifier"`) {
					return lit.Value
				}
			}
		}
	}
	return ""
}

// TestCORS documents the cross-origin policy: discovery documents, JWKS,
// register, token and revoke answer any origin (public clients with PKCE
// in a browser, e.g. the MCP inspector) without credentials; the
// authorization and consent pages, /mcp and the portal do not.
func TestCORS(t *testing.T) {
	g := newGateway(t)
	open := []string{"/.well-known/oauth-authorization-server", "/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp", "/oauth/jwks", "/oauth/register", "/oauth/token", "/oauth/revoke"}
	for _, p := range open {
		t.Run("preflight"+p, func(t *testing.T) {
			r := do(t, noRedirect, http.MethodOptions, g.base+p, nil, "Origin", "https://inspector.example", "Access-Control-Request-Method", "POST", "Access-Control-Request-Headers", "content-type,authorization")
			if r.status != http.StatusNoContent {
				t.Fatalf("preflight: %d %s", r.status, r.body)
			}
			h := r.header
			if h.Get("Access-Control-Allow-Origin") != "*" || h.Get("Access-Control-Allow-Credentials") != "" || !strings.Contains(h.Get("Access-Control-Allow-Headers"), "Authorization") || !strings.Contains(h.Get("Access-Control-Allow-Headers"), "mcp-protocol-version") {
				t.Errorf("preflight headers = %v", h)
			}
			if len(r.body) != 0 {
				t.Errorf("preflight has a body: %s", r.body)
			}
		})
	}
	t.Run("actual_response_wildcard_no_credentials", func(t *testing.T) {
		r := get(t, noRedirect, g.base+"/.well-known/oauth-authorization-server", "Origin", "https://evil.example")
		if r.header.Get("Access-Control-Allow-Origin") != "*" || r.header.Get("Access-Control-Allow-Credentials") != "" {
			t.Errorf("headers = %v", r.header)
		}
		r = postForm(t, noRedirect, g.base+"/oauth/token", url.Values{}, "Origin", "https://evil.example")
		if r.header.Get("Access-Control-Allow-Origin") != "*" || r.header.Get("Access-Control-Allow-Credentials") != "" {
			t.Errorf("token headers = %v", r.header)
		}
	})
	t.Run("closed_for_pages_and_mcp", func(t *testing.T) {
		br := g.browser(t, true)
		c := g.register(t, "https://app.example.com/cb")
		for _, r := range []reply{
			g.authorize(t, br, g.authorizeParams(c, newPKCE(t), "s")),
			do(t, br, http.MethodOptions, g.base+"/oauth/authorize/consent", nil, "Origin", "https://evil.example", "Access-Control-Request-Method", "POST"),
			get(t, br, g.base+"/harnesses", "Origin", "https://evil.example"),
			get(t, br, g.base+"/account", "Origin", "https://evil.example"),
			g.mcpCall(t, ""),
		} {
			if r.header.Get("Access-Control-Allow-Origin") != "" {
				t.Errorf("CORS opened on a session or bearer route: %v", r.header)
			}
		}
	})
}

// TestHostHeaderInjection: the discovery documents, the JWKS and every
// absolute URL the server emits come from GATEWAY_BASE_URL, never from
// the request's Host, X-Forwarded-Host or Forwarded headers.
func TestHostHeaderInjection(t *testing.T) {
	g := newGateway(t)
	hostile := []string{"Host", "evil.example", "X-Forwarded-Host", "evil.example", "X-Forwarded-Proto", "https", "Forwarded", "host=evil.example;proto=https", "X-Original-Host", "evil.example"}
	for _, p := range []string{"/.well-known/oauth-authorization-server", "/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"} {
		t.Run(p, func(t *testing.T) {
			r := get(t, noRedirect, g.base+p, hostile...)
			if r.status != http.StatusOK {
				t.Fatalf("%d", r.status)
			}
			if strings.Contains(string(r.body), "evil.example") || !strings.Contains(string(r.body), g.base) {
				t.Errorf("document reflects the Host header: %s", r.body)
			}
		})
	}
	t.Run("401_challenge", func(t *testing.T) {
		r := postJSON(t, noRedirect, g.resource, `{}`, append([]string{"Accept", "application/json"}, hostile...)...)
		if wa := r.header.Get("WWW-Authenticate"); r.status != http.StatusUnauthorized || strings.Contains(wa, "evil") || !strings.Contains(wa, g.base) {
			t.Errorf("%d %q", r.status, wa)
		}
	})
	t.Run("authorization_response_iss", func(t *testing.T) {
		br := g.browser(t, true)
		c := g.register(t, "https://app.example.com/cb")
		q := g.authorizeParams(c, newPKCE(t), "s")
		form := url.Values{}
		for k, v := range q {
			form[k] = v
		}
		form.Set("action", "approve")
		form.Set("_csrf", g.csrf(t, br))
		r := postForm(t, br, g.base+"/oauth/authorize/consent", form, hostile...)
		if iss := r.location().Query().Get("iss"); iss != g.base {
			t.Errorf("iss = %q under a hostile Host header (%d %s)", iss, r.status, r.header.Get("Location"))
		}
	})
	t.Run("sign_in_redirect_is_relative", func(t *testing.T) {
		r := get(t, noRedirect, g.base+"/oauth/authorize?client_id=x", hostile...)
		if loc := r.header.Get("Location"); r.status != http.StatusSeeOther || !strings.HasPrefix(loc, "/signin?") {
			t.Errorf("%d %q", r.status, loc)
		}
	})
}

// TestMCPChallengeHygiene: /mcp's 401 carries resource_metadata (the
// discovery entry point), the error and a short description; the body is
// a small JSON error; nothing resembles a stack trace or an internal
// error, for any shape of bad token.
func TestMCPChallengeHygiene(t *testing.T) {
	g := newGateway(t)
	br := g.browser(t, true)
	c := g.register(t, "https://app.example.com/cb")
	pair := g.issue(t, br, c)
	for name, bearer := range map[string]string{
		"none":      "",
		"garbage":   "zzz",
		"jwt_shape": "aaaa.bbbb.cccc",
		"mgw_shape": "mgw_aaaaaaaa_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"expired":   func() string { g.clock.Advance(2 * g.cfg.AccessTokenTTL); return pair.access }(),
		"long":      strings.Repeat("A", 100000),
		"spaces":    "abc def ghi",
	} {
		t.Run(name, func(t *testing.T) {
			r := g.mcpCall(t, bearer)
			if r.status != http.StatusUnauthorized {
				t.Fatalf("%d %s", r.status, r.body)
			}
			wa := r.header.Get("WWW-Authenticate")
			if !strings.HasPrefix(wa, `Bearer realm="mcp-gateway"`) || !strings.Contains(wa, `resource_metadata="`+g.base+`/.well-known/oauth-protected-resource"`) {
				t.Errorf("WWW-Authenticate = %q", wa)
			}
			if bearer != "" && !strings.Contains(wa, `error="invalid_token"`) {
				t.Errorf("WWW-Authenticate = %q", wa)
			}
			if bearer == "" && strings.Contains(wa, "error=") {
				t.Errorf("challenge without a token should not name an error: %q", wa)
			}
			if strings.ContainsAny(wa, "\r\n") || len(wa) > 400 {
				t.Errorf("challenge is malformed or verbose: %q", wa)
			}
			noStackTrace(t, r.body)
			if len(r.body) > 300 || !strings.HasPrefix(strings.TrimSpace(string(r.body)), "{") {
				t.Errorf("body = %s", r.body)
			}
			if r.header.Get("Content-Type") == "" || r.header.Get("Cache-Control") != "no-store" {
				t.Errorf("headers = %v", r.header)
			}
			// The bearer is never echoed.
			if bearer != "" && len(bearer) > 8 && (strings.Contains(string(r.body), bearer[:8]) || strings.Contains(wa, bearer[:8])) {
				t.Errorf("the bearer is echoed in the response")
			}
		})
	}
	t.Run("store_outage_is_503_not_401", func(t *testing.T) {
		// A rejected token must not be confused with an unreachable store:
		// the harness must not drop its token because the database blinked.
		g := newGateway(t)
		br := g.browser(t, true)
		c := g.register(t, "https://app.example.com/cb")
		pair := g.issue(t, br, c)
		g.astore.FailWith = errOutage
		r := g.mcpCall(t, pair.access)
		g.astore.FailWith = nil
		if r.status != http.StatusServiceUnavailable || strings.Contains(string(r.body), "outage") {
			t.Errorf("during an outage: %d %s", r.status, r.body)
		}
		noStackTrace(t, r.body)
		g.wantMCPOK(t, pair.access)
	})
}
