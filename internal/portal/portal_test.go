package portal_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/identity/identitytest"
	"github.com/huynle/mcp-gateway/internal/portal"
	"github.com/huynle/mcp-gateway/internal/store"
)

const (
	issuer       = "http://localhost:15556/dex"
	memberSub    = "member-subject"
	adminSub     = "admin-subject"
	otherSub     = "other-subject"
	defaultRole  = "member"
	reviewerRole = "reviewer"
)

type harness struct {
	h   http.Handler
	svc *identity.Service
	st  *identitytest.MemStore
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	st := identitytest.NewMemStore()
	cfg := identity.Config{
		BaseURL: "http://localhost:18080",
		Providers: []config.OIDCProvider{
			{Name: "dex", DisplayName: "Local dex", Issuer: issuer, ClientID: "gateway", ClientSecret: "s", AllowedDomains: []string{"example.com"}},
			{Name: "google", DisplayName: "Google Workspace", Issuer: "https://accounts.google.com", ClientID: "c", ClientSecret: "s", AllowedDomains: []string{"example.com"}},
		},
		DefaultRole:     defaultRole,
		BootstrapAdmins: []string{issuer + "|" + adminSub},
		IdleTimeout:     12 * time.Hour,
		AbsoluteTimeout: 7 * 24 * time.Hour,
	}
	svc, err := identity.New(cfg, st, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	// An extra role admins can assign.
	_ = st.Bypass(context.Background(), func(tx identity.Tx) error {
		_, err := tx.EnsureRole(context.Background(), reviewerRole, "")
		return err
	})
	p, err := portal.New(svc, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("portal.New: %v", err)
	}
	return &harness{h: p.Handler(), svc: svc, st: st}
}

// session signs a user in directly and returns the session cookie and
// principal.
func (h *harness) session(t *testing.T, subject, name string) (*http.Cookie, *identity.Principal) {
	t.Helper()
	res, err := h.svc.SignIn(context.Background(), "dex", identity.Claims{
		Issuer: issuer, Subject: subject, Name: name, Email: subject + "@example.com", EmailVerified: true,
	})
	if err != nil {
		t.Fatalf("SignIn(%s): %v", subject, err)
	}
	return res.Cookie, res.Principal
}

type request struct {
	method, path string
	cookie       *http.Cookie
	form         url.Values
	header       http.Header
}

func (h *harness) do(t *testing.T, r request) *httptest.ResponseRecorder {
	t.Helper()
	var body io.Reader
	if r.form != nil {
		body = strings.NewReader(r.form.Encode())
	}
	req := httptest.NewRequestWithContext(context.Background(), r.method, r.path, body)
	if r.form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range r.header {
		req.Header[k] = v
	}
	if r.cookie != nil {
		req.AddCookie(r.cookie)
	}
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	return rec
}

func TestHomeRedirects(t *testing.T) {
	h := newHarness(t)
	rec := h.do(t, request{method: http.MethodGet, path: "/"})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/signin" {
		t.Errorf("anonymous GET / = %d %q, want 303 /signin", rec.Code, rec.Header().Get("Location"))
	}
	ck, _ := h.session(t, memberSub, "Member")
	rec = h.do(t, request{method: http.MethodGet, path: "/", cookie: ck})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/account" {
		t.Errorf("signed-in GET / = %d %q, want 303 /account", rec.Code, rec.Header().Get("Location"))
	}
}

func TestSignInPageRendersProviders(t *testing.T) {
	h := newHarness(t)
	rec := h.do(t, request{method: http.MethodGet, path: "/signin?return_to=/account"})
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /signin = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"<!doctype html>", "Local dex", "Google Workspace",
		`href="/auth/dex/start?return_to=%2Faccount"`, `href="/auth/google/start?return_to=%2Faccount"`,
		`/static/htmx.min.js`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("sign-in page lacks %q:\n%s", want, body)
		}
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q", ct)
	}
	// An unsafe return_to is dropped, not echoed.
	rec = h.do(t, request{method: http.MethodGet, path: "/signin?return_to=https://evil.test/"})
	if strings.Contains(rec.Body.String(), "evil.test") {
		t.Error("unsafe return_to must not be echoed into the page")
	}
	// Already signed in: straight to the account page.
	ck, _ := h.session(t, memberSub, "Member")
	rec = h.do(t, request{method: http.MethodGet, path: "/signin", cookie: ck})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/account" {
		t.Errorf("signed-in GET /signin = %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestAccountPage(t *testing.T) {
	h := newHarness(t)
	rec := h.do(t, request{method: http.MethodGet, path: "/account"})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/signin?return_to=%2Faccount" {
		t.Errorf("anonymous GET /account = %d %q, want redirect to sign-in with return_to", rec.Code, rec.Header().Get("Location"))
	}
	ck, p := h.session(t, memberSub, "Member <b>Bold</b>")
	rec = h.do(t, request{method: http.MethodGet, path: "/account", cookie: ck})
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /account = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Member &lt;b&gt;Bold&lt;/b&gt;", defaultRole,
		`action="/auth/signout"`, `name="_csrf" value="` + p.CSRFToken + `"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("account page lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "<b>Bold</b>") {
		t.Error("display name must be HTML-escaped")
	}
	if strings.Contains(body, `href="/admin/users"`) {
		t.Error("non-admins must not see admin navigation")
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("authenticated pages must not be cached, Cache-Control = %q", cc)
	}
}

func TestAdminPagesAre404ForNonAdmins(t *testing.T) {
	h := newHarness(t)
	member, _ := h.session(t, memberSub, "Member")
	admin, _ := h.session(t, adminSub, "Admin")

	rec := h.do(t, request{method: http.MethodGet, path: "/admin/users"})
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/signin") {
		t.Errorf("anonymous GET /admin/users = %d %q, want redirect to sign-in", rec.Code, rec.Header().Get("Location"))
	}
	rec = h.do(t, request{method: http.MethodGet, path: "/admin/users", cookie: member})
	if rec.Code != http.StatusNotFound {
		t.Errorf("member GET /admin/users = %d, want 404", rec.Code)
	}
	notFound := h.do(t, request{method: http.MethodGet, path: "/no-such-page", cookie: member})
	if rec.Body.String() != notFound.Body.String() {
		t.Error("admin 404 must be indistinguishable from an unknown page")
	}
	rec = h.do(t, request{method: http.MethodGet, path: "/admin/users", cookie: admin})
	if rec.Code != http.StatusOK {
		t.Fatalf("admin GET /admin/users = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"Member", "Admin", reviewerRole, "Disable", `href="/admin/users"`} {
		if !strings.Contains(body, want) {
			t.Errorf("admin users page lacks %q:\n%s", want, body)
		}
	}
	// POSTs are gated the same way, before CSRF is even considered.
	_, mp := h.session(t, otherSub, "Other")
	rec = h.do(t, request{method: http.MethodPost, path: "/admin/users/" + mp.UserID + "/disable", cookie: member})
	if rec.Code != http.StatusNotFound {
		t.Errorf("member POST disable = %d, want 404", rec.Code)
	}
}

func TestCSRF(t *testing.T) {
	h := newHarness(t)
	admin, ap := h.session(t, adminSub, "Admin")
	_, mp := h.session(t, memberSub, "Member")
	target := "/admin/users/" + mp.UserID + "/disable"

	rec := h.do(t, request{method: http.MethodPost, path: target, cookie: admin})
	if rec.Code != http.StatusForbidden {
		t.Errorf("POST without CSRF token = %d, want 403", rec.Code)
	}
	rec = h.do(t, request{method: http.MethodPost, path: target, cookie: admin, form: url.Values{"_csrf": {"wrong"}}})
	if rec.Code != http.StatusForbidden {
		t.Errorf("POST with a wrong CSRF token = %d, want 403", rec.Code)
	}
	rec = h.do(t, request{method: http.MethodPost, path: target, cookie: admin, form: url.Values{"_csrf": {ap.CSRFToken}},
		header: http.Header{"Sec-Fetch-Site": {"cross-site"}}})
	if rec.Code != http.StatusForbidden {
		t.Errorf("cross-site POST = %d, want 403", rec.Code)
	}
	if h.st.LiveSessions(mp.UserID) != 1 {
		t.Fatal("rejected POSTs must not have side effects")
	}
	rec = h.do(t, request{method: http.MethodPost, path: target, cookie: admin, form: url.Values{"_csrf": {ap.CSRFToken}}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/users" {
		t.Errorf("POST with the form token = %d %q, want 303 /admin/users", rec.Code, rec.Header().Get("Location"))
	}
	if h.st.LiveSessions(mp.UserID) != 0 {
		t.Error("disable should have revoked the member's sessions")
	}
	// The header form works for htmx; an htmx request gets the row fragment.
	rec = h.do(t, request{method: http.MethodPost, path: "/admin/users/" + mp.UserID + "/enable", cookie: admin,
		header: http.Header{"X-Csrf-Token": {ap.CSRFToken}, "Hx-Request": {"true"}}})
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "<!doctype") || !strings.Contains(rec.Body.String(), "Disable") {
		t.Errorf("htmx enable = %d, want 200 with a row fragment containing the Disable action:\n%s", rec.Code, rec.Body.String())
	}
	// Anonymous POSTs are 403 too (sign-out included).
	rec = h.do(t, request{method: http.MethodPost, path: "/auth/signout"})
	if rec.Code != http.StatusForbidden {
		t.Errorf("anonymous POST /auth/signout = %d, want 403", rec.Code)
	}
	rec = h.do(t, request{method: http.MethodPost, path: "/auth/signout", cookie: admin, form: url.Values{"_csrf": {ap.CSRFToken}}})
	if rec.Code != http.StatusSeeOther {
		t.Errorf("sign-out with token = %d, want 303", rec.Code)
	}
	if h.st.LiveSessions(ap.UserID) != 0 {
		t.Error("sign-out must revoke the admin's session")
	}
}

func TestAdminRoleAssignment(t *testing.T) {
	h := newHarness(t)
	admin, ap := h.session(t, adminSub, "Admin")
	_, mp := h.session(t, memberSub, "Member")
	post := func(role string) *httptest.ResponseRecorder {
		return h.do(t, request{method: http.MethodPost, path: "/admin/users/" + mp.UserID + "/role", cookie: admin,
			form: url.Values{"_csrf": {ap.CSRFToken}, "role": {role}}})
	}
	if rec := post(reviewerRole); rec.Code != http.StatusSeeOther {
		t.Fatalf("assign role = %d: %s", rec.Code, rec.Body.String())
	}
	if got := h.st.RoleNames(mp.UserID); len(got) != 1 || got[0] != reviewerRole {
		t.Errorf("roles = %v, want [%s]", got, reviewerRole)
	}
	if rec := post("does-not-exist"); rec.Code != http.StatusBadRequest {
		t.Errorf("assigning an unknown role = %d, want 400", rec.Code)
	}
	if rec := post(""); rec.Code != http.StatusBadRequest {
		t.Errorf("assigning an empty role = %d, want 400", rec.Code)
	}
	rec := h.do(t, request{method: http.MethodPost, path: "/admin/users/not-a-user/disable", cookie: admin,
		form: url.Values{"_csrf": {ap.CSRFToken}}})
	if rec.Code != http.StatusNotFound {
		t.Errorf("disabling an unknown user = %d, want 404", rec.Code)
	}
	// Admins cannot disable themselves through the portal.
	rec = h.do(t, request{method: http.MethodPost, path: "/admin/users/" + ap.UserID + "/disable", cookie: admin,
		form: url.Values{"_csrf": {ap.CSRFToken}}})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("self-disable = %d, want 400", rec.Code)
	}
	if h.st.LiveSessions(ap.UserID) != 1 {
		t.Error("self-disable must be a no-op")
	}
}

func TestStaticAssetsAreEmbedded(t *testing.T) {
	h := newHarness(t)
	rec := h.do(t, request{method: http.MethodGet, path: "/static/htmx.min.js"})
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Body.String(), "var htmx=") {
		t.Errorf("GET /static/htmx.min.js = %d, body starts %q", rec.Code, firstN(rec.Body.String(), 20))
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Errorf("Content-Type = %q", ct)
	}
	if rec := h.do(t, request{method: http.MethodGet, path: "/static/../templates/layout.html"}); rec.Code == http.StatusOK {
		t.Error("templates must not be served as static files")
	}
	if rec := h.do(t, request{method: http.MethodGet, path: "/static/"}); rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), "htmx") {
		t.Error("directory listings must be off")
	}
}

func TestSignInErrorPageUsesPortalTemplate(t *testing.T) {
	h := newHarness(t)
	// A callback without the login cookie is the simplest identity error.
	rec := h.do(t, request{method: http.MethodGet, path: "/auth/dex/callback?code=x&state=y"})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "<!doctype html>") || !strings.Contains(rec.Body.String(), "Sign-in failed") {
		t.Errorf("identity error = %d:\n%s", rec.Code, rec.Body.String())
	}
}

func TestDisabledUserIsAnonymous(t *testing.T) {
	h := newHarness(t)
	ck, p := h.session(t, memberSub, "Member")
	_ = h.st.Bypass(context.Background(), func(tx identity.Tx) error {
		return tx.SetUserStatus(context.Background(), p.UserID, store.UserDisabled, time.Now())
	})
	rec := h.do(t, request{method: http.MethodGet, path: "/account", cookie: ck})
	if rec.Code != http.StatusSeeOther {
		t.Errorf("disabled user GET /account = %d, want redirect to sign-in", rec.Code)
	}
}

func firstN(s string, n int) string {
	if len(s) < n {
		return s
	}
	return s[:n]
}
