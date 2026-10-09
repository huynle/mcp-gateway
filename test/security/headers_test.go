//go:build integration || e2e || security

package security

import (
	"net/http"
	"strings"
	"testing"
)

// TestSecurityPortalHeaders: every portal page (signed-in pages, admin
// pages, error pages, the sign-in page and the static assets) carries
// the anti-framing, nosniff and referrer headers and a CSP baseline
// that still lets the embedded htmx run; the OAuth consent and
// harnesses pages keep their own stricter set.
func TestSecurityPortalHeaders(t *testing.T) {
	w := newWorld(t, options{})
	check := func(t *testing.T, path string, status int, h http.Header) {
		t.Helper()
		if h.Get("X-Frame-Options") != "DENY" {
			t.Errorf("%s (%d): X-Frame-Options = %q, want DENY", path, status, h.Get("X-Frame-Options"))
		}
		if h.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s (%d): X-Content-Type-Options = %q, want nosniff", path, status, h.Get("X-Content-Type-Options"))
		}
		if rp := h.Get("Referrer-Policy"); rp != "no-referrer" && rp != "same-origin" && rp != "strict-origin-when-cross-origin" {
			t.Errorf("%s (%d): Referrer-Policy = %q", path, status, rp)
		}
		csp := h.Get("Content-Security-Policy")
		if !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Errorf("%s (%d): CSP %q lacks frame-ancestors 'none'", path, status, csp)
		}
		if strings.Contains(path, "/oauth/") || strings.HasPrefix(path, "/harnesses") {
			return // the authorization server's own header set
		}
		for _, want := range []string{"default-src 'self'", "script-src 'self'", "object-src 'none'", "base-uri 'self'"} {
			if !strings.Contains(csp, want) {
				t.Errorf("%s (%d): CSP %q lacks %s", path, status, csp, want)
			}
		}
		if strings.Contains(csp, "unsafe-eval") || strings.Contains(csp, "*") {
			t.Errorf("%s (%d): CSP %q allows eval or any origin", path, status, csp)
		}
	}
	for _, path := range []string{
		"/", "/signin", "/account", "/tokens", "/tokens/new", "/connections", "/approvals", "/approvals/history",
		"/operations", "/activity", "/harnesses", "/admin/users", "/admin/roles", "/admin/roles/member",
		"/admin/vendor-apps", "/admin/audit", "/admin/settings/default-role", "/no-such-page",
		"/static/htmx.min.js", "/oauth/authorize?client_id=x",
	} {
		for _, u := range []struct {
			name string
			u    user
		}{{"anonymous", user{}}, {"alice", w.alice}, {"admin", w.admin}} {
			status, h, _ := w.get(u.u, path)
			check(t, path+" as "+u.name, status, h)
		}
	}
	// POST error pages (CSRF refusal, 404 for someone else's id).
	for _, path := range []string{"/tokens/00000000-0000-4000-8000-000000000000/revoke", "/approvals/00000000-0000-4000-8000-000000000000/approve"} {
		status, h, _ := w.post(w.alice, path, nil)
		check(t, "POST "+path, status, h)
	}
	status, h, _ := w.post(user{cookie: w.alice.cookie}, "/tokens/new", nil) // no CSRF token
	check(t, "POST /tokens/new without CSRF", status, h)
}
