//go:build integration

package main

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/policy/policytest"
	"github.com/huynle/mcp-gateway/internal/tokens"
	"github.com/huynle/mcp-gateway/internal/tokens/tokenstest"
)

// The admin servers pages are mounted on the real portal next to the
// users' servers portal (a conflicting pattern would panic here), behind
// the admin check: anonymous users are sent to sign in, members get the
// portal's 404 (GET and POST), admins get the page.
func TestIntegrationAdminServersMounted(t *testing.T) {
	st := openFederationStore(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	log := slog.New(slog.DiscardHandler)
	const issuer = "https://dex.example.com"
	cfg := config.Default()
	cfg.BaseURL = "http://gateway.test"
	cfg.OIDCProviders = []config.OIDCProvider{{Name: "dex", DisplayName: "Dex", Issuer: issuer, ClientID: "gateway", ClientSecret: "s", AllowedDomains: []string{"example.com"}}}
	cfg.BootstrapAdmins = []string{issuer + "|admin-subject"}
	keys, err := crypto.NewStaticProvider("k1", map[string][]byte{"k1": bytes.Repeat([]byte{5}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	policySvc, err := policy.New(policytest.NewMemStore(), policy.Options{Log: log})
	if err != nil {
		t.Fatal(err)
	}
	registry := connectors.NewRegistry()
	fed, err := newFederation(ctx, cfg, st, keys, registry, policySvc, nil, observability.NewMetrics(), log)
	if err != nil || fed == nil {
		t.Fatalf("newFederation = %v, %v", fed, err)
	}
	tokenSvc, err := tokens.New(tokens.Config{SignInMaxAge: time.Hour}, tokenstest.NewMemStore(), nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	var idSvc *identity.Service
	capture := func(s *identity.Service, _ func(string, http.Handler), _ func(*http.Request) (string, string), _ *slog.Logger, _ http.Handler) {
		idSvc = s
	}
	// The real identity store: allow-list rows reference the admin user.
	portalHandler, err := newPortal(cfg, identity.NewPostgresStore(st), noReader{}, tokenSvc, policySvc, nil, nil, registry, nil, nil, log,
		withFederationPages(fed, st, cfg.BaseURL, policySvc, audit.NopRecorder{}), withFederationAdmin(fed, st, audit.NopRecorder{}), capture)
	if err != nil {
		t.Fatalf("newPortal: %v", err)
	}
	srv := httptest.NewServer(newMux(observability.NewReadiness(time.Second), portalHandler, nil, nil, withFederationRoutes(fed)))
	defer srv.Close()
	signIn := func(sub string) (*http.Cookie, *identity.Principal) {
		res, err := idSvc.SignIn(ctx, "dex", identity.Claims{Issuer: issuer, Subject: sub, Name: sub, Email: sub + "@example.com", EmailVerified: true})
		if err != nil {
			t.Fatalf("sign in %s: %v", sub, err)
		}
		return res.Cookie, res.Principal
	}
	adminCookie, adminPr := signIn("admin-subject")
	memberCookie, memberPr := signIn("member-subject")
	if !adminPr.IsAdmin() || memberPr.IsAdmin() {
		t.Fatalf("admin flags: admin %v member %v", adminPr.IsAdmin(), memberPr.IsAdmin())
	}
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	do := func(method, path string, cookie *http.Cookie, form url.Values) (int, string, string) {
		t.Helper()
		var body *strings.Reader
		if form != nil {
			body = strings.NewReader(form.Encode())
		} else {
			body = strings.NewReader("")
		}
		req, _ := http.NewRequestWithContext(ctx, method, srv.URL+path, body)
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		if cookie != nil {
			req.AddCookie(cookie)
		}
		res, err := noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		var b bytes.Buffer
		_, _ = b.ReadFrom(res.Body)
		return res.StatusCode, res.Header.Get("Location"), b.String()
	}
	pages := []string{"/admin/servers", "/admin/servers/reviews", "/admin/tunnels", "/admin/network/allow-hosts"}
	for _, p := range pages {
		if code, loc, _ := do(http.MethodGet, p, nil, nil); code != http.StatusSeeOther || !strings.HasPrefix(loc, "/signin") {
			t.Errorf("anonymous GET %s = %d %q, want a redirect to sign-in", p, code, loc)
		}
		if code, _, _ := do(http.MethodGet, p, memberCookie, nil); code != http.StatusNotFound {
			t.Errorf("member GET %s = %d, want 404", p, code)
		}
		code, _, body := do(http.MethodGet, p, adminCookie, nil)
		if code != http.StatusOK {
			t.Errorf("admin GET %s = %d, want 200", p, code)
		}
		if !strings.Contains(body, `href="/admin/servers"`) {
			t.Errorf("admin page %s has no Servers admin link", p)
		}
	}
	if code, _, _ := do(http.MethodPost, "/admin/network/allow-hosts", memberCookie, url.Values{"_csrf": {memberPr.CSRFToken}, "pattern": {"10.0.0.0/8"}}); code != http.StatusNotFound {
		t.Errorf("member POST allow-host = %d, want 404", code)
	}
	if code, _, _ := do(http.MethodPost, "/admin/network/allow-hosts", adminCookie, url.Values{"pattern": {"10.0.0.0/8"}}); code != http.StatusForbidden {
		t.Errorf("admin POST without CSRF = %d, want 403", code)
	}
	code, loc, _ := do(http.MethodPost, "/admin/network/allow-hosts", adminCookie, url.Values{"_csrf": {adminPr.CSRFToken}, "pattern": {"10.99.0.0/16"}, "note": {"wiring test"}})
	if code != http.StatusSeeOther || !strings.HasPrefix(loc, "/admin/network/allow-hosts") {
		t.Fatalf("admin POST allow-host = %d %q", code, loc)
	}
	if _, _, body := do(http.MethodGet, "/admin/network/allow-hosts", adminCookie, nil); !strings.Contains(body, "10.99.0.0/16") {
		t.Error("the added allow-list entry is not listed")
	}
	// The allow list the netguard guard uses was invalidated: it already
	// knows the new entry.
	if !fed.AllowList.Allowed(ctx, "", netip.MustParseAddr("10.99.1.2")) {
		t.Error("netguard allow list does not include the new entry after the admin added it")
	}
}
