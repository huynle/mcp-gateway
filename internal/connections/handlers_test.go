package connections_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connections/connectionstest"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/identity/identitytest"
	"github.com/huynle/mcp-gateway/internal/portal"
)

const (
	issuer    = "http://localhost:15556/dex"
	memberSub = "member-subject"
	adminSub  = "admin-subject"
)

// harness is the real portal with the connection pages mounted the way
// cmd/gateway mounts them, over in-memory identity and connection stores.
type harness struct {
	h    http.Handler
	svc  *identity.Service
	conn *connections.Service
	mem  *connectionstest.MemStore
	logs *bytes.Buffer
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	st := identitytest.NewMemStore()
	cfg := identity.Config{
		BaseURL:         "http://localhost:18080",
		Providers:       []config.OIDCProvider{{Name: "dex", DisplayName: "Local dex", Issuer: issuer, ClientID: "gateway", ClientSecret: "s", AllowedDomains: []string{"example.com"}}},
		DefaultRole:     "member",
		BootstrapAdmins: []string{issuer + "|" + adminSub},
		IdleTimeout:     12 * time.Hour,
		AbsoluteTimeout: 7 * 24 * time.Hour,
	}
	svc, err := identity.New(cfg, st, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	p, err := portal.New(svc, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	kp, _ := crypto.NewStaticProvider("k1", map[string][]byte{"k1": bytes.Repeat([]byte{9}, 32)})
	logs := &bytes.Buffer{}
	mem := connectionstest.NewMemStore()
	csvc, err := connections.New(connections.Config{BaseURL: cfg.BaseURL}, mem, kp, connections.Options{Log: slog.New(slog.NewTextHandler(logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	who := func(r *http.Request) (string, string, bool) {
		pr := identity.PrincipalFrom(r.Context())
		if pr == nil {
			return "", "", false
		}
		return pr.UserID, pr.CSRFToken, pr.IsAdmin()
	}
	cp := connections.NewPortal(csvc, who, slog.New(slog.DiscardHandler))
	cp.MountUser(p.MountUser)
	cp.MountConnect(p.MountUser)
	cp.MountAdmin(p.MountAdmin)
	svc.OnDisable(csvc.DisableHook())
	return &harness{h: p.Handler(), svc: svc, conn: csvc, mem: mem, logs: logs}
}

func (h *harness) session(t *testing.T, subject, name string) (*http.Cookie, *identity.Principal) {
	t.Helper()
	res, err := h.svc.SignIn(context.Background(), "dex", identity.Claims{Issuer: issuer, Subject: subject, Name: name, Email: subject + "@example.com", EmailVerified: true})
	if err != nil {
		t.Fatalf("SignIn(%s): %v", subject, err)
	}
	return res.Cookie, res.Principal
}

type request struct {
	method, path string
	cookie       *http.Cookie
	form         url.Values
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
	if r.cookie != nil {
		req.AddCookie(r.cookie)
	}
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	return rec
}

func TestConnectionPagesThroughThePortal(t *testing.T) {
	h := newHarness(t)
	v := newFakeVendor(t)
	member, mp := h.session(t, memberSub, "Member")
	admin, ap := h.session(t, adminSub, "Admin")

	// Anonymous: redirected to sign-in; the callback too (no session, no flow).
	for _, path := range []string{"/connections", "/connect/fake/start", "/connect/fake/callback?state=x&code=y"} {
		rec := h.do(t, request{method: http.MethodGet, path: path})
		if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/signin?return_to=") {
			t.Errorf("anonymous GET %s = %d %q", path, rec.Code, rec.Header().Get("Location"))
		}
	}
	// Nothing configured yet.
	if rec := h.do(t, request{method: http.MethodGet, path: "/connections", cookie: member}); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "No vendor apps are configured") {
		t.Errorf("GET /connections = %d:\n%s", rec.Code, rec.Body)
	}
	if rec := h.do(t, request{method: http.MethodGet, path: "/connect/fake/start", cookie: member}); rec.Code != http.StatusNotFound {
		t.Errorf("start unconfigured = %d", rec.Code)
	}

	// Admin pages: 404 for members, both as GET and POST (before CSRF).
	for _, path := range []string{"/admin/vendor-apps", "/admin/vendor-apps/github", "/admin/vendor-apps/google/internal"} {
		if rec := h.do(t, request{method: http.MethodGet, path: path, cookie: member}); rec.Code != http.StatusNotFound {
			t.Errorf("member GET %s = %d, want 404", path, rec.Code)
		}
	}
	if rec := h.do(t, request{method: http.MethodPost, path: "/admin/vendor-apps/github", cookie: member, form: url.Values{"client_id": {"x"}}}); rec.Code != http.StatusNotFound {
		t.Errorf("member POST = %d, want 404", rec.Code)
	}
	rec := h.do(t, request{method: http.MethodGet, path: "/admin/vendor-apps", cookie: admin})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "/admin/vendor-apps/google/external") || !strings.Contains(rec.Body.String(), "not configured") {
		t.Fatalf("admin list = %d:\n%s", rec.Code, rec.Body)
	}
	// The editor is prefilled with the vendor's documented endpoints.
	rec = h.do(t, request{method: http.MethodGet, path: "/admin/vendor-apps/github", cookie: admin})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "https://github.com/login/oauth/authorize") || !strings.Contains(rec.Body.String(), "/connect/github/callback") {
		t.Fatalf("github editor = %d:\n%s", rec.Code, rec.Body)
	}
	// Admin POST without CSRF is refused.
	form := url.Values{
		"client_id": {v.clientID}, "client_secret": {v.secret},
		"auth_url": {v.URL() + "/authorize"}, "token_url": {v.URL() + "/token"}, "userinfo_url": {v.URL() + "/userinfo"}, "revoke_url": {v.URL() + "/revoke"},
		"scopes": {"read:user"}, "extra": {"company_domains=acme.test\nname_field=login"}, "enabled": {"1"},
	}
	if rec := h.do(t, request{method: http.MethodPost, path: "/admin/vendor-apps/fake", cookie: admin, form: form}); rec.Code != http.StatusForbidden {
		t.Errorf("admin POST without CSRF = %d, want 403", rec.Code)
	}
	form.Set("_csrf", ap.CSRFToken)
	// Validation errors re-render the form without the secret.
	bad := url.Values{}
	for k, vals := range form {
		bad[k] = vals
	}
	bad.Set("token_url", "")
	rec = h.do(t, request{method: http.MethodPost, path: "/admin/vendor-apps/fake", cookie: admin, form: bad})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Token URL is required") || strings.Contains(rec.Body.String(), v.secret) {
		t.Fatalf("invalid save = %d:\n%s", rec.Code, rec.Body)
	}
	rec = h.do(t, request{method: http.MethodPost, path: "/admin/vendor-apps/fake", cookie: admin, form: form})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/vendor-apps/fake?saved=1" {
		t.Fatalf("save = %d %q:\n%s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	// The secret is never rendered anywhere: editor, list, logs.
	for _, path := range []string{"/admin/vendor-apps/fake?saved=1", "/admin/vendor-apps"} {
		rec = h.do(t, request{method: http.MethodGet, path: path, cookie: admin})
		if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), v.secret) {
			t.Fatalf("GET %s = %d, secret rendered=%v", path, rec.Code, strings.Contains(rec.Body.String(), v.secret))
		}
	}
	if !strings.Contains(rec.Body.String(), "enabled") || !strings.Contains(rec.Body.String(), v.clientID) {
		t.Fatalf("admin list after save:\n%s", rec.Body)
	}
	rec = h.do(t, request{method: http.MethodGet, path: "/admin/vendor-apps/fake", cookie: admin})
	if !strings.Contains(rec.Body.String(), "a secret is stored") || !strings.Contains(rec.Body.String(), `type="password" name="client_secret" value=""`) {
		t.Fatalf("editor after save:\n%s", rec.Body)
	}
	if strings.Contains(h.logs.String(), v.secret) {
		t.Fatalf("secret in logs:\n%s", h.logs.String())
	}

	// Member: the connect button appears; start redirects to the vendor.
	rec = h.do(t, request{method: http.MethodGet, path: "/connections", cookie: member})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `href="/connect/fake/start?variant=default"`) {
		t.Fatalf("GET /connections = %d:\n%s", rec.Code, rec.Body)
	}
	rec = h.do(t, request{method: http.MethodGet, path: "/connect/fake/start?variant=default&scopes=repo", cookie: member})
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), v.URL()+"/authorize?") {
		t.Fatalf("start = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	// The vendor sends the browser back to the gateway's callback.
	authorize, _ := url.Parse(rec.Header().Get("Location"))
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, authorize.String(), nil)
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	back, _ := url.Parse(res.Header.Get("Location"))
	if back.Scheme+"://"+back.Host != "http://localhost:18080" || back.Path != "/connect/fake/callback" {
		t.Fatalf("vendor redirected to %s", back)
	}
	// Another user's session cannot finish it.
	if rec := h.do(t, request{method: http.MethodGet, path: back.RequestURI(), cookie: admin}); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/connections?error=flow_invalid" {
		t.Fatalf("foreign callback = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	// The flow was consumed by that attempt (one use), so the member must
	// start over; this time it completes.
	rec = h.do(t, request{method: http.MethodGet, path: "/connect/fake/start", cookie: member})
	authorize, _ = url.Parse(rec.Header().Get("Location"))
	req, _ = http.NewRequestWithContext(context.Background(), http.MethodGet, authorize.String(), nil)
	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	back, _ = url.Parse(res.Header.Get("Location"))
	rec = h.do(t, request{method: http.MethodGet, path: back.RequestURI(), cookie: member})
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/connections?connected=") {
		t.Fatalf("callback = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	rec = h.do(t, request{method: http.MethodGet, path: rec.Header().Get("Location"), cookie: member})
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "Account connected.") || !strings.Contains(body, "alice") || !strings.Contains(body, `class="pill company"`) || !strings.Contains(body, "Grant more access") {
		t.Fatalf("GET /connections after connect = %d:\n%s", rec.Code, body)
	}
	for _, tok := range v.allTokens() {
		if strings.Contains(body, tok) || strings.Contains(h.logs.String(), tok) {
			t.Fatalf("token %q rendered or logged", tok)
		}
	}
	// Disconnect: CSRF required; then the account is gone from the page.
	id := regexp.MustCompile(`/connections/([0-9a-f-]+)/disconnect`).FindStringSubmatch(body)
	if id == nil {
		t.Fatalf("no disconnect form:\n%s", body)
	}
	if rec := h.do(t, request{method: http.MethodPost, path: "/connections/" + id[1] + "/disconnect", cookie: member, form: url.Values{}}); rec.Code != http.StatusForbidden {
		t.Errorf("disconnect without CSRF = %d", rec.Code)
	}
	if rec := h.do(t, request{method: http.MethodPost, path: "/connections/" + id[1] + "/disconnect", cookie: admin, form: url.Values{"_csrf": {ap.CSRFToken}}}); rec.Code != http.StatusNotFound {
		t.Errorf("foreign disconnect = %d, want 404", rec.Code)
	}
	rec = h.do(t, request{method: http.MethodPost, path: "/connections/" + id[1] + "/disconnect", cookie: member, form: url.Values{"_csrf": {mp.CSRFToken}}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/connections?disconnected=1" {
		t.Fatalf("disconnect = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	rec = h.do(t, request{method: http.MethodGet, path: "/connections?disconnected=1", cookie: member})
	if !strings.Contains(rec.Body.String(), "Account disconnected") || !strings.Contains(rec.Body.String(), "No Fake account connected") {
		t.Fatalf("after disconnect:\n%s", rec.Body)
	}
	if n := len(h.mem.SecretRows()); n != 0 {
		t.Fatalf("secrets left = %d", n)
	}
	// Vendor errors come back as a message, never a 500.
	rec = h.do(t, request{method: http.MethodGet, path: "/connect/fake/start", cookie: member})
	state := mustQuery(t, rec.Header().Get("Location")).Get("state")
	rec = h.do(t, request{method: http.MethodGet, path: "/connect/fake/callback?state=" + state + "&error=access_denied", cookie: member})
	if rec.Header().Get("Location") != "/connections?error=vendor_denied" {
		t.Fatalf("vendor error = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	rec = h.do(t, request{method: http.MethodGet, path: "/connections?error=vendor_denied", cookie: member})
	if !strings.Contains(rec.Body.String(), "did not authorize") {
		t.Fatalf("error message missing:\n%s", rec.Body)
	}
}
