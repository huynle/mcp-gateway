package oauthattack

import (
	"net/http"
	"net/url"
	"testing"
)

// Redirect URI validation (RFC 9700 section 4.1, OAuth 2.1 section 4.1.3
// and 8.4.2, MCP spec "Open Redirection"): the authorization endpoint must
// match the redirect URI exactly against the registration and never
// redirect the user agent when it does not; the only tolerance is the port
// of an http loopback redirect URI.

// TestRedirectURITampering: every variation of a registered
// https://app.example.com/cb is refused on an error page (400) with no
// Location header, no code, and a refusal log event.
func TestRedirectURITampering(t *testing.T) {
	g := newGateway(t)
	br := g.browser(t, true)
	c := g.register(t, "https://app.example.com/cb")
	cases := map[string]string{
		"path_suffix":           "https://app.example.com/cb/sub",
		"path_prefix":           "https://app.example.com/c",
		"other_port":            "https://app.example.com:444/cb",
		"http_downgrade":        "http://app.example.com/cb",
		"trailing_dot_host":     "https://app.example.com./cb",
		"query_added":           "https://app.example.com/cb?x=1",
		"fragment_added":        "https://app.example.com/cb#x",
		"userinfo_prefix":       "https://app.example.com@evil.example/cb",
		"userinfo_prefix_2":     "https://evil.example@app.example.com/cb",
		"unicode_lookalike":     "https://аpp.example.com/cb", // Cyrillic а
		"idn_punycode":          "https://xn--pp-8cd.example.com/cb",
		"case_changed_path":     "https://app.example.com/CB",
		"case_changed_host":     "https://APP.example.com/cb",
		"subdomain":             "https://app.example.com.evil.example/cb",
		"backslash_host":        "https://app.example.com\\@evil.example/cb",
		"loopback_for_https":    "http://127.0.0.1:9999/cb",
		"empty":                 "",
		"javascript_scheme":     "javascript:alert(1)",
		"relative":              "/cb",
		"protocol_relative":     "//app.example.com/cb",
		"encoded_slash_in_path": "https://app.example.com/cb%2Fsub",
		"trailing_slash":        "https://app.example.com/cb/",
		"double_encoded":        "https://app.example.com/%63b",
	}
	for name, uri := range cases {
		t.Run(name, func(t *testing.T) {
			q := g.authorizeParams(c, newPKCE(t), nonce(t))
			q.Set("redirect_uri", uri)
			r := g.authorize(t, br, q)
			body := wantErrorPage(t, r)
			if !containsAny(body, "redirect URI") {
				t.Errorf("error page does not explain the refusal: %s", body)
			}
			rec := wantLogEvent(t, g, "authserver.authorize_refused")
			if rec.Attrs["client_id"] != c.id {
				t.Errorf("refusal log names client %q, want %q", rec.Attrs["client_id"], c.id)
			}
			// The consent POST re-validates: a tampered hidden field cannot
			// obtain a code either.
			r = g.consent(t, br, q, "approve")
			wantErrorPage(t, r)
			if len(g.astore.Codes()) != 0 {
				t.Fatalf("a code was issued for redirect_uri %q", uri)
			}
		})
	}
}

// TestRedirectURILoopbackPortFlexibility: an http loopback redirect URI
// (127.0.0.1, [::1], localhost) registered with one port is accepted at
// any port (OAuth 2.1 section 8.4.2, RFC 8252 section 7.3), provided the
// scheme, host and path match exactly; the code is bound to the port that
// was actually used, so the token exchange must repeat it. Non-loopback
// hosts and https get no such tolerance.
func TestRedirectURILoopbackPortFlexibility(t *testing.T) {
	g := newGateway(t)
	br := g.browser(t, true)
	for _, host := range []string{"127.0.0.1", "localhost", "[::1]"} {
		t.Run(host, func(t *testing.T) {
			registered := "http://" + host + ":4000/callback"
			c := g.register(t, registered)
			p := newPKCE(t)
			used := "http://" + host + ":51234/callback"
			q := g.authorizeParams(c, p, "s1")
			q.Set("redirect_uri", used)
			if r := g.authorize(t, br, q); r.status != http.StatusOK {
				t.Fatalf("authorize with another loopback port: %d %s", r.status, r.body)
			}
			loc := g.consent(t, br, q, "approve").callback(t)
			if loc.Host != host+":51234" || loc.Query().Get("code") == "" {
				t.Fatalf("approve: callback %s", loc)
			}
			code := loc.Query().Get("code")
			// The token request must name the redirect URI that was used,
			// not the registered one (the code is bound to it).
			form := g.exchangeForm(c, code, p)
			form.Set("redirect_uri", registered)
			wantOAuthError(t, g.token(t, form), http.StatusBadRequest, "invalid_grant")
			// The failed check burned the code: even the right redirect URI
			// is now a replay.
			form.Set("redirect_uri", used)
			wantOAuthError(t, g.token(t, form), http.StatusBadRequest, "invalid_grant")

			// A fresh code with the used port exchanges.
			p = newPKCE(t)
			q = g.authorizeParams(c, p, "s2")
			q.Set("redirect_uri", used)
			code = g.consent(t, br, q, "approve").callback(t).Query().Get("code")
			form = g.exchangeForm(c, code, p)
			form.Set("redirect_uri", used)
			if r := g.token(t, form); r.status != http.StatusOK {
				t.Fatalf("exchange with the used loopback port: %d %s", r.status, r.body)
			}

			// Only the port may differ.
			for name, uri := range map[string]string{
				"path":   "http://" + host + ":51234/callback/x",
				"scheme": "https://" + host + ":51234/callback",
				"query":  "http://" + host + ":51234/callback?x=1",
				"host":   "http://" + host + ".evil.example:51234/callback",
			} {
				q := g.authorizeParams(c, newPKCE(t), nonce(t))
				q.Set("redirect_uri", uri)
				if r := g.authorize(t, br, q); r.status != http.StatusBadRequest || r.header.Get("Location") != "" {
					t.Errorf("%s variant %q: %d %q, want 400 error page", name, uri, r.status, r.header.Get("Location"))
				}
			}
		})
	}
	t.Run("not_for_https_or_other_hosts", func(t *testing.T) {
		for _, registered := range []string{"https://app.example.com:4000/cb", "https://127.0.0.1:4000/cb", "https://localhost:4000/cb"} {
			c := g.register(t, registered)
			u, _ := url.Parse(registered)
			u.Host = u.Hostname() + ":51234"
			q := g.authorizeParams(c, newPKCE(t), nonce(t))
			q.Set("redirect_uri", u.String())
			if r := g.authorize(t, br, q); r.status != http.StatusBadRequest || r.header.Get("Location") != "" {
				t.Errorf("%s with another port: %d %q, want 400 error page", registered, r.status, r.header.Get("Location"))
			}
		}
	})
	t.Run("loopback_lookalikes", func(t *testing.T) {
		c := g.register(t, "http://127.0.0.1:4000/cb")
		for _, uri := range []string{"http://127.0.0.2:4000/cb", "http://localhost.evil.example:4000/cb", "http://127.0.0.1.nip.io:4000/cb", "http://[::1]:4000/cb", "http://localhost:4000/cb", "http://0.0.0.0:4000/cb", "http://2130706433:4000/cb", "http://0x7f000001:4000/cb"} {
			q := g.authorizeParams(c, newPKCE(t), nonce(t))
			q.Set("redirect_uri", uri)
			if r := g.authorize(t, br, q); r.status != http.StatusBadRequest || r.header.Get("Location") != "" {
				t.Errorf("%q against a 127.0.0.1 registration: %d %q, want 400 error page", uri, r.status, r.header.Get("Location"))
			}
		}
	})
}

// TestRedirectURIMismatchAtToken: a code is bound to the redirect URI of
// its authorization request; the token endpoint refuses any other value,
// burns the code, and logs nothing a client could use to probe.
func TestRedirectURIMismatchAtToken(t *testing.T) {
	g := newGateway(t)
	br := g.browser(t, true)
	c := g.register(t, "https://app.example.com/cb", "https://app.example.com/cb2")
	for name, uri := range map[string]string{
		"other_registered": "https://app.example.com/cb2",
		"unregistered":     "https://evil.example/cb",
		"missing":          "",
		"suffix":           "https://app.example.com/cb/",
	} {
		t.Run(name, func(t *testing.T) {
			p := newPKCE(t)
			code := g.code(t, br, c, p, nonce(t))
			form := g.exchangeForm(c, code, p)
			form.Set("redirect_uri", uri)
			if uri == "" {
				form.Del("redirect_uri")
			}
			desc := wantOAuthError(t, g.token(t, form), http.StatusBadRequest, "invalid_grant")
			if !containsAny(desc, "redirect_uri") {
				t.Errorf("description %q does not name redirect_uri", desc)
			}
			// Burned: the right redirect URI no longer works.
			wantOAuthError(t, g.token(t, g.exchangeForm(c, code, p)), http.StatusBadRequest, "invalid_grant")
		})
	}
}

func containsAny(s string, needles ...string) bool {
	for _, n := range needles {
		if len(n) > 0 && len(s) >= len(n) && indexOf(s, n) >= 0 {
			return true
		}
	}
	return false
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
