package portal_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/portal"
)

// Every portal response, whatever the status (pages, redirects, 404s,
// CSRF refusals, static assets), carries the browser hardening headers
// and the CSP baseline, which permits the embedded htmx and the inline
// attributes the templates use but no eval, plugins or foreign origins.
func TestEveryResponseCarriesHardeningHeaders(t *testing.T) {
	h := newHarness(t)
	ck, _ := h.session(t, memberSub, "Member")
	admin, _ := h.session(t, adminSub, "Admin")
	cases := []request{
		{method: http.MethodGet, path: "/"},
		{method: http.MethodGet, path: "/signin"},
		{method: http.MethodGet, path: "/account", cookie: ck},
		{method: http.MethodGet, path: "/admin/users", cookie: ck},    // 404 for non-admins
		{method: http.MethodGet, path: "/admin/users", cookie: admin}, // the admin page
		{method: http.MethodGet, path: "/no-such-page", cookie: ck},
		{method: http.MethodGet, path: "/static/htmx.min.js"},
		{method: http.MethodPost, path: "/auth/signout", cookie: ck}, // CSRF refusal
	}
	for _, r := range cases {
		rec := h.do(t, r)
		hd := rec.Header()
		if hd.Get("X-Frame-Options") != "DENY" || hd.Get("X-Content-Type-Options") != "nosniff" || hd.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("%s %s (%d): headers = %v", r.method, r.path, rec.Code, hd)
		}
		if csp := hd.Get("Content-Security-Policy"); csp != portal.CSP {
			t.Errorf("%s %s (%d): CSP = %q, want the baseline", r.method, r.path, rec.Code, csp)
		}
	}
	for _, want := range []string{"default-src 'self'", "script-src 'self'", "object-src 'none'", "base-uri 'self'", "frame-ancestors 'none'"} {
		if csp := portal.CSP; !strings.Contains(csp, want) {
			t.Errorf("CSP %q lacks %s", csp, want)
		}
	}
	for _, forbidden := range []string{"unsafe-eval", "*", "http:", "https:"} {
		if csp := portal.CSP; strings.Contains(csp, forbidden) {
			t.Errorf("CSP %q allows %s", csp, forbidden)
		}
	}
}

// A handler mounted inside the portal may tighten or replace a header
// (the OAuth consent page sets Cache-Control; the headers are set before
// the handler runs so it has the last word).
func TestSecurityHeadersSetBeforeTheHandler(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if w.Header().Get("X-Frame-Options") != "DENY" {
			t.Error("headers not set before the handler ran")
		}
		w.Header().Set("Referrer-Policy", "same-origin")
		w.WriteHeader(http.StatusTeapot)
	})
	rec := httptest.NewRecorder()
	portal.SecurityHeaders(inner).ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/x", nil))
	if rec.Code != http.StatusTeapot || rec.Header().Get("Referrer-Policy") != "same-origin" || rec.Header().Get("Content-Security-Policy") != portal.CSP {
		t.Errorf("response = %d %v", rec.Code, rec.Header())
	}
}
