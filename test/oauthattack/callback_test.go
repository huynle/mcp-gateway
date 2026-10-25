package oauthattack

import (
	"html"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

// The page an approval for a loopback redirect URI answers with (instead
// of a bare 303) puts the authorization code on screen and in a curl
// command, for a harness that listens on another host's loopback. It must
// not become a way to leak or misuse the code: hostile client values are
// escaped, nothing loads from another origin, there is no inline script,
// the code keeps its semantics (single use, PKCE-bound), and errors
// (Deny) are still plain redirects.

// TestLoopbackCallbackPage drives the page through the whole gateway.
func TestLoopbackCallbackPage(t *testing.T) {
	g := newGateway(t)
	br := g.browser(t, true)
	const registered = "http://127.0.0.1:4000/cb"
	c := g.register(t, registered)
	hostile := `'"><script>alert(1)</script>`

	t.Run("approve", func(t *testing.T) {
		p := newPKCE(t)
		q := g.authorizeParams(c, p, hostile)
		r := g.consent(t, br, q, "approve")
		loc := r.callback(t)
		if loc.Host != "127.0.0.1:4000" || loc.Path != "/cb" || loc.Query().Get("state") != hostile || loc.Query().Get("iss") != g.base {
			t.Fatalf("callback = %s", loc)
		}
		body := string(r.body)
		if strings.Contains(body, "<script>alert") {
			t.Error("hostile state reached the page unescaped")
		}
		// Script only from same-origin files (CSP script-src 'self'), never inline.
		for _, tag := range regexp.MustCompile(`<script[^>]*>`).FindAllString(body, -1) {
			if !strings.Contains(tag, `src="/`) {
				t.Errorf("inline or foreign script %q", tag)
			}
		}
		for _, ref := range regexp.MustCompile(`(?:src="|<link [^>]*href=")[^"]*`).FindAllString(body, -1) {
			if strings.Contains(ref, "//") {
				t.Errorf("asset from another origin: %q", ref)
			}
		}
		// The curl command is the callback, single-quoted for a POSIX shell
		// (the encoded query carries no quote to escape).
		curl := regexp.MustCompile(`(?s)<pre id="callback-curl">(.*?)</pre>`).FindStringSubmatch(body)
		if curl == nil || html.UnescapeString(curl[1]) != "curl '"+loc.String()+"'" {
			t.Errorf("curl command = %q, want curl '%s'", curl, loc)
		}
		// The code is the one the redirect would have carried: single use.
		code := loc.Query().Get("code")
		if r := g.token(t, g.exchangeForm(c, code, p)); r.status != http.StatusOK {
			t.Fatalf("exchange: %d %s", r.status, r.body)
		}
		wantOAuthError(t, g.token(t, g.exchangeForm(c, code, p)), http.StatusBadRequest, "invalid_grant")
	})

	t.Run("code_still_pkce_bound", func(t *testing.T) {
		p := newPKCE(t)
		code := g.consent(t, br, g.authorizeParams(c, p, "s"), "approve").callback(t).Query().Get("code")
		wantOAuthError(t, g.token(t, g.exchangeForm(c, code, newPKCE(t))), http.StatusBadRequest, "invalid_grant")
	})

	t.Run("deny_is_a_redirect", func(t *testing.T) {
		q := g.authorizeParams(c, newPKCE(t), "s")
		q.Set("remote", "1")
		wantRedirectError(t, g.consent(t, br, q, "deny"), registered, "access_denied", "s")
	})

	t.Run("protocol_error_is_a_redirect", func(t *testing.T) {
		q := g.authorizeParams(c, newPKCE(t), "s")
		q.Set("resource", "https://other.example/mcp")
		wantRedirectError(t, g.consent(t, br, q, "approve"), registered, "invalid_target", "s")
	})

	t.Run("remote_is_not_echoed_from_the_query", func(t *testing.T) {
		// remote=1 only changes the page (no automatic redirect). A link
		// that carries it gets the consent page's own unchecked box, not
		// a hidden copy.
		q := g.authorizeParams(c, newPKCE(t), "s")
		q.Set("remote", "1")
		page := string(g.authorize(t, br, q).body)
		inputs := regexp.MustCompile(`<input[^>]*name="remote"[^>]*>`).FindAllString(page, -1)
		if len(inputs) != 1 || !strings.Contains(inputs[0], `type="checkbox"`) || strings.Contains(inputs[0], "checked") {
			t.Errorf("consent page remote inputs = %q, want one unchecked checkbox", inputs)
		}
	})
}
