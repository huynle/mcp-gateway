package oauthattack

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// The authorization and consent pages: CSRF on the consent POST (RFC 9700
// section 4.7), tampering with the posted request, open redirects on the
// sign-in return path (RFC 9700 section 4.11), state handling,
// clickjacking (RFC 9700 section 4.16) and disabled users.

// TestConsentCSRF: the consent POST is refused without the session's CSRF
// token, with a wrong one, when the browser labels it cross-site, and
// from an anonymous browser; a refusal never issues a code.
func TestConsentCSRF(t *testing.T) {
	g := newGateway(t)
	br := g.browser(t, true)
	c := g.register(t, "https://app.example.com/cb")
	q := g.authorizeParams(c, newPKCE(t), "s")
	form := func(csrf string) url.Values {
		f := url.Values{}
		for k, v := range q {
			f[k] = v
		}
		f.Set("action", "approve")
		if csrf != "" {
			f.Set("_csrf", csrf)
		}
		return f
	}
	post := func(c *http.Client, f url.Values, headers ...string) reply {
		return postForm(t, c, g.base+"/oauth/authorize/consent", f, headers...)
	}
	other := g.browser(t, true) // another session of the same user: another token
	cases := map[string]struct {
		do     func() reply
		status int
	}{
		"missing_token":        {func() reply { return post(br, form("")) }, http.StatusForbidden},
		"wrong_token":          {func() reply { return post(br, form("not-the-token")) }, http.StatusForbidden},
		"other_sessions_token": {func() reply { return post(br, form(g.csrf(t, other))) }, http.StatusForbidden},
		"cross_site":           {func() reply { return post(br, form(g.csrf(t, br)), "Sec-Fetch-Site", "cross-site") }, http.StatusForbidden},
		// An anonymous POST is sent to sign-in by the portal (303, no code).
		"anonymous": {func() reply { return post(g.browser(t, false), form(g.csrf(t, br))) }, http.StatusSeeOther},
		// GET on the consent URL is not a route (the portal's 404), never an approval.
		"get_with_approve":    {func() reply { return get(t, br, g.base+"/oauth/authorize/consent?"+form(g.csrf(t, br)).Encode()) }, http.StatusNotFound},
		"same_site_header_ok": {func() reply { return post(br, form(g.csrf(t, br)), "Sec-Fetch-Site", "same-origin") }, http.StatusSeeOther},
		// The portal accepts X-CSRF-Token; the consent handler's own check
		// requires the form field (stricter: documented, not a defect).
		"header_token_only":      {func() reply { return post(br, form(""), "X-CSRF-Token", g.csrf(t, br)) }, http.StatusForbidden},
		"approve_without_action": {func() reply { f := form(g.csrf(t, br)); f.Del("action"); return post(br, f) }, http.StatusSeeOther},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			before := len(g.astore.Codes())
			rejectedBefore := len(g.logs.Events("portal.csrf_rejected"))
			r := tc.do()
			if r.status != tc.status {
				t.Fatalf("status %d, want %d; Location %q; body %.200s", r.status, tc.status, r.header.Get("Location"), r.body)
			}
			issued := len(g.astore.Codes()) - before
			switch {
			case tc.status == http.StatusForbidden:
				if issued != 0 || r.header.Get("Location") != "" {
					t.Errorf("a refused consent issued %d codes / redirected to %q", issued, r.header.Get("Location"))
				}
				// Token mismatches are logged by the portal with the user id;
				// a cross-site label is refused before any token is read
				// (403, not logged), and the handler's own form-field check
				// does not log either.
				logged := len(g.logs.Events("portal.csrf_rejected")) - rejectedBefore
				wantLogged := name == "missing_token" || name == "wrong_token" || name == "other_sessions_token"
				if (logged > 0) != wantLogged {
					t.Errorf("portal.csrf_rejected logged %d times, want logged=%v", logged, wantLogged)
				}
			case name == "anonymous":
				if issued != 0 || r.location().Path != "/signin" {
					t.Errorf("anonymous consent issued %d codes / redirected to %q", issued, r.header.Get("Location"))
				}
			case tc.status == http.StatusNotFound:
				if issued != 0 {
					t.Errorf("GET consent issued %d codes", issued)
				}
			case name == "approve_without_action":
				// No action = deny: error=access_denied, no code.
				wantRedirectError(t, r, c.redirect, "access_denied", "s")
				wantAudit(t, g, "oauth_consent_denied", "deny", 1)
			case tc.status == http.StatusSeeOther:
				if issued != 1 || r.location().Query().Get("code") == "" {
					t.Errorf("approve issued %d codes; Location %q", issued, r.header.Get("Location"))
				}
			}
		})
	}
}

// TestConsentTampering: the consent POST is re-validated from its fields.
// Swapping the client_id for another client's (with its redirect URI) is
// not "approving the pending request": there is no server-side pending
// request, so the code that comes out is bound to the posted client and
// is useless to the original one; a swapped client with the original
// redirect URI is an error page; an unknown client is an error page.
func TestConsentTampering(t *testing.T) {
	g := newGateway(t)
	br := g.browser(t, true)
	victim := g.register(t, "https://app.example.com/cb")
	attacker := g.register(t, "https://attacker.example/cb")
	p := newPKCE(t)
	q := g.authorizeParams(victim, p, "s")
	if r := g.authorize(t, br, q); r.status != http.StatusOK {
		t.Fatal(r.status)
	}
	t.Run("client_swapped_keeps_victim_redirect", func(t *testing.T) {
		f := url.Values{}
		for k, v := range q {
			f[k] = v
		}
		f.Set("client_id", attacker.id)
		wantErrorPage(t, g.consent(t, br, f, "approve"))
		wantLogEvent(t, g, "authserver.authorize_refused")
	})
	t.Run("client_swapped_with_own_redirect", func(t *testing.T) {
		f := url.Values{}
		for k, v := range q {
			f[k] = v
		}
		f.Set("client_id", attacker.id)
		f.Set("redirect_uri", attacker.redirect)
		r := g.consent(t, br, f, "approve")
		loc := r.location()
		if r.status != http.StatusSeeOther || loc.Host != "attacker.example" || loc.Query().Get("code") == "" {
			t.Fatalf("consent for the posted client: %d %s", r.status, r.header.Get("Location"))
		}
		code := loc.Query().Get("code")
		// The code belongs to the posted client (the consent audit names
		// it) and the victim client cannot exchange it.
		evs := wantAudit(t, g, "oauth_consent_granted", "allow", 1)
		if evs[0].ResourceIdentity["client_id"] != attacker.id {
			t.Errorf("consent audited for %q, want %q", evs[0].ResourceIdentity["client_id"], attacker.id)
		}
		wantOAuthError(t, g.token(t, g.exchangeForm(victim, code, p)), http.StatusBadRequest, "invalid_grant")
		wantLogEvent(t, g, "authserver.code_wrong_client")
	})
	t.Run("unknown_client", func(t *testing.T) {
		f := url.Values{}
		for k, v := range q {
			f[k] = v
		}
		f.Set("client_id", "gwc_unknown")
		body := wantErrorPage(t, g.consent(t, br, f, "approve"))
		if !strings.Contains(body, "Unknown client") {
			t.Errorf("body: %s", body)
		}
	})
	t.Run("deny_is_access_denied", func(t *testing.T) {
		loc := wantRedirectError(t, g.consent(t, br, q, "deny"), victim.redirect, "access_denied", "s")
		if loc.Query().Get("error_description") == "" {
			t.Error("no error_description")
		}
		wantLogEvent(t, g, "authserver.consent_denied")
		wantAudit(t, g, "oauth_consent_denied", "deny", 1)
	})
	t.Run("consent_page_names_the_redirect_host", func(t *testing.T) {
		// MCP spec (CIMD security): the redirect host is shown to the user.
		page := g.authorize(t, br, g.authorizeParams(attacker, newPKCE(t), "s"))
		if !strings.Contains(string(page.body), "attacker.example") {
			t.Errorf("consent page does not show where the tokens go: %s", page.body)
		}
	})
}

// TestOpenRedirectOnSignIn: /signin?return_to= (and the portal's redirect
// to it) only ever send the browser to a local path.
func TestOpenRedirectOnSignIn(t *testing.T) {
	g := newGateway(t)
	anon := g.browser(t, false)
	evil := []string{
		"https://evil.example/", "http://evil.example", "//evil.example/x", "/\\evil.example", "\\\\evil.example",
		"/%2Fevil.example", "/%5Cevil.example", "https:evil.example", "javascript:alert(1)", "///evil.example",
		"/..//evil.example", "/oauth/../..//evil.example", " //evil.example", "/\t/evil.example", "%2F%2Fevil.example",
		"https://" + strings.TrimPrefix(g.base, "http://") + "/account", "/%2e%2e/%2e%2e/evil",
	}
	for _, rt := range evil {
		t.Run(rt, func(t *testing.T) {
			page := get(t, anon, g.base+"/signin?return_to="+url.QueryEscape(rt))
			if page.status != http.StatusOK {
				t.Fatalf("signin: %d", page.status)
			}
			// The provider start links must carry return_to=/ (the safe
			// default), never the attacker's value.
			body := string(page.body)
			if strings.Contains(body, "evil") || !strings.Contains(body, "return_to=%2F\"") {
				t.Errorf("sign-in page carries the hostile return_to: %s", extractStart(body))
			}
			// The identity start endpoint computes the same safe value and
			// stores it in the login cookie: the final redirect after the
			// provider callback can only be local. (Without a live provider,
			// start fails at discovery; the return_to is sanitised before.)
			r := get(t, anon, g.base+"/auth/dex/start?return_to="+url.QueryEscape(rt))
			if loc := r.header.Get("Location"); strings.Contains(loc, "evil") {
				t.Errorf("start redirected to %q", loc)
			}
		})
	}
	t.Run("nested_return_to_is_a_local_path", func(t *testing.T) {
		// A local path whose query carries another return_to stays a local
		// path; the inner value is never interpreted by the portal.
		page := get(t, anon, g.base+"/signin?return_to="+url.QueryEscape("/oauth/authorize?return_to=//evil.example"))
		if start := extractStart(string(page.body)); !strings.HasPrefix(start, "/auth/dex/start?return_to=%2Foauth%2Fauthorize%3F") {
			t.Errorf("start link = %q", start)
		}
	})
	t.Run("legitimate_authorize_return_to_kept", func(t *testing.T) {
		c := g.register(t, "https://app.example.com/cb")
		q := g.authorizeParams(c, newPKCE(t), "s")
		r := g.authorize(t, anon, q)
		if r.status != http.StatusSeeOther || r.location().Path != "/signin" {
			t.Fatalf("anonymous authorize: %d %s", r.status, r.header.Get("Location"))
		}
		rt := r.location().Query().Get("return_to")
		if !strings.HasPrefix(rt, "/oauth/authorize?") {
			t.Fatalf("return_to = %q", rt)
		}
		page := get(t, anon, g.base+r.header.Get("Location"))
		if !strings.Contains(string(page.body), url.QueryEscape(rt)) && !strings.Contains(string(page.body), strings.ReplaceAll(url.QueryEscape(rt), "%", "%25")) {
			t.Errorf("sign-in page lost the authorize return_to: %s", extractStart(string(page.body)))
		}
	})
}

// extractStart pulls the first provider start link out of the sign-in page.
func extractStart(body string) string {
	i := strings.Index(body, "/auth/")
	if i < 0 {
		return body
	}
	end := strings.Index(body[i:], `"`)
	if end < 0 {
		return body[i:]
	}
	return body[i : i+end]
}

// TestStateHandling: state is required, bounded, echoed verbatim on
// success and error, and never ties two requests together: the same
// state value in two authorizations yields two independent codes (the
// second does not reuse or invalidate the first), each bound to its own
// PKCE challenge.
func TestStateHandling(t *testing.T) {
	g := newGateway(t)
	br := g.browser(t, true)
	c := g.register(t, "https://app.example.com/cb")
	t.Run("required", func(t *testing.T) {
		q := g.authorizeParams(c, newPKCE(t), "")
		q.Del("state")
		loc := wantRedirectError(t, g.authorize(t, br, q), c.redirect, "invalid_request", "")
		if _, has := loc.Query()["state"]; has {
			t.Error("state echoed although none was sent")
		}
		q.Set("state", "")
		wantRedirectError(t, g.authorize(t, br, q), c.redirect, "invalid_request", "")
	})
	t.Run("too_long", func(t *testing.T) {
		long := strings.Repeat("s", 513)
		q := g.authorizeParams(c, newPKCE(t), long)
		wantRedirectError(t, g.authorize(t, br, q), c.redirect, "invalid_request", long)
	})
	t.Run("echoed_verbatim", func(t *testing.T) {
		state := `a b&c=d/é"<>` + "\x7f"
		p := newPKCE(t)
		code := g.code(t, br, c, p, state)
		if code == "" {
			t.Fatal("no code")
		}
	})
	t.Run("reuse_does_not_bind", func(t *testing.T) {
		p1, p2 := newPKCE(t), newPKCE(t)
		code1 := g.code(t, br, c, p1, "same")
		code2 := g.code(t, br, c, p2, "same")
		if code1 == code2 {
			t.Fatal("the same code was issued twice")
		}
		// code2 is bound to p2, not to p1 (the first request's challenge).
		wantOAuthError(t, g.token(t, g.exchangeForm(c, code2, p1)), http.StatusBadRequest, "invalid_grant")
		// code1 is unaffected by the second request and by code2's failure.
		if r := g.token(t, g.exchangeForm(c, code1, p1)); r.status != http.StatusOK {
			t.Errorf("code1 after a second request with the same state: %d %s", r.status, r.body)
		}
	})
	t.Run("iss_in_authorization_response", func(t *testing.T) {
		// RFC 9207 / MCP spec: the authorization response carries iss (on
		// success and on error) and the metadata advertises it, so a client
		// can detect a mix-up with another authorization server.
		meta := get(t, noRedirect, g.base+"/.well-known/oauth-authorization-server").json()
		if meta["authorization_response_iss_parameter_supported"] != true {
			t.Errorf("authorization_response_iss_parameter_supported = %v", meta["authorization_response_iss_parameter_supported"])
		}
		q := g.authorizeParams(c, newPKCE(t), "s")
		loc := g.consent(t, br, q, "approve").location()
		if loc.Query().Get("iss") != g.base {
			t.Errorf("success response iss = %q, want %q (%s)", loc.Query().Get("iss"), g.base, loc)
		}
		q.Set("resource", "https://other.example/mcp")
		loc = g.consent(t, br, q, "approve").location()
		if loc.Query().Get("iss") != g.base || loc.Query().Get("error") != "invalid_target" {
			t.Errorf("error response = %s", loc)
		}
	})
}

// TestClickjacking: the consent page (and every page the authorization
// server renders) forbids framing (RFC 9700 section 4.16).
func TestClickjacking(t *testing.T) {
	g := newGateway(t)
	br := g.browser(t, true)
	c := g.register(t, "https://app.example.com/cb")
	pages := map[string]reply{
		"consent":   g.authorize(t, br, g.authorizeParams(c, newPKCE(t), "s")),
		"harnesses": get(t, br, g.base+"/harnesses"),
		"error":     g.authorize(t, br, url.Values{"client_id": {"gwc_nope"}}),
	}
	for name, r := range pages {
		t.Run(name, func(t *testing.T) {
			if xfo := r.header.Get("X-Frame-Options"); xfo != "DENY" {
				t.Errorf("X-Frame-Options = %q, want DENY", xfo)
			}
			if csp := r.header.Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") {
				t.Errorf("Content-Security-Policy = %q, want frame-ancestors 'none'", csp)
			}
			if cc := r.header.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
				t.Errorf("Cache-Control = %q", cc)
			}
			if ref := r.header.Get("Referrer-Policy"); ref != "no-referrer" {
				t.Errorf("Referrer-Policy = %q, want no-referrer", ref)
			}
		})
	}
}

// TestAuthorizeForDisabledUser: a disabled user's session is dead, so
// the authorization endpoint sends the browser to sign-in; if a session
// somehow survived (another replica's cache), consent would still not
// produce a usable token: the exchange checks the owner's status.
func TestAuthorizeForDisabledUser(t *testing.T) {
	g := newGateway(t)
	br := g.browser(t, true)
	c := g.register(t, "https://app.example.com/cb")
	p := newPKCE(t)
	q := g.authorizeParams(c, p, "s")
	// Status flips in the authorization server's store only (session alive).
	g.astore.SetUser(g.alice, "disabled", nil)
	r := g.consent(t, br, q, "approve")
	if r.status == http.StatusSeeOther && r.location().Query().Get("code") != "" {
		code := r.location().Query().Get("code")
		desc := wantOAuthError(t, g.token(t, g.exchangeForm(c, code, p)), http.StatusBadRequest, "invalid_grant")
		if !strings.Contains(desc, "disabled") {
			t.Errorf("description = %q", desc)
		}
	} else if r.status != http.StatusBadRequest && r.status != http.StatusForbidden && r.status != http.StatusUnauthorized {
		t.Fatalf("consent as a disabled user: %d %s", r.status, r.header.Get("Location"))
	}
	// Disabled through the identity service: the session is revoked.
	if err := g.idSvc.DisableUser(t.Context(), "", g.alice); err != nil {
		t.Fatal(err)
	}
	r = g.authorize(t, br, q)
	if r.status != http.StatusSeeOther || r.location().Path != "/signin" {
		t.Errorf("authorize with a revoked session: %d %s", r.status, r.header.Get("Location"))
	}
	f := url.Values{}
	for k, v := range q {
		f[k] = v
	}
	f.Set("action", "approve")
	f.Set("_csrf", "stale")
	r = postForm(t, br, g.base+"/oauth/authorize/consent", f)
	if r.status != http.StatusSeeOther || r.location().Path != "/signin" || r.location().Query().Get("code") != "" {
		t.Errorf("consent with a revoked session: %d %s", r.status, r.header.Get("Location"))
	}
	if n := len(g.astore.Codes()); n > 1 {
		t.Errorf("%d codes issued for a disabled user", n)
	}
}
