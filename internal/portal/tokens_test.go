package portal_test

import (
	"context"
	"html"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/identity/identitytest"
	"github.com/huynle/mcp-gateway/internal/portal"
	"github.com/huynle/mcp-gateway/internal/tokens"
	"github.com/huynle/mcp-gateway/internal/tokens/tokenstest"
)

// The token pages mounted through MountUser, end to end: session cookie,
// anonymous redirect, CSRF, one-time display, prefix-only list, revoke.
func TestTokenPagesThroughThePortal(t *testing.T) {
	st := identitytest.NewMemStore()
	cfg := identity.Config{
		BaseURL:         "http://localhost:18080",
		Providers:       []config.OIDCProvider{{Name: "dex", DisplayName: "Local dex", Issuer: issuer, ClientID: "gateway", ClientSecret: "s", AllowedDomains: []string{"example.com"}}},
		DefaultRole:     defaultRole,
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
	tst := tokenstest.NewMemStore()
	tsvc, err := tokens.New(tokens.Config{SignInMaxAge: tokens.DefaultSignInMaxAge}, tst, nil, nil, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	who := func(r *http.Request) (string, string) {
		pr := identity.PrincipalFrom(r.Context())
		if pr == nil {
			return "", ""
		}
		return pr.UserID, pr.CSRFToken
	}
	tokens.NewPortal(tsvc, who, cfg.BaseURL, slog.New(slog.DiscardHandler)).Mount(p.MountUser)
	// The disable hook is what main wires; exercise it here too.
	svc.OnDisable(tsvc.DisableHook())

	h := &harness{h: p.Handler(), svc: svc, st: st}
	cookie, principal := h.session(t, memberSub, "Member")
	now := time.Now()
	tst.AddUser(principal.UserID, &now)

	// Anonymous: redirected to sign-in.
	rec := h.do(t, request{method: http.MethodGet, path: "/tokens"})
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/signin?return_to=") {
		t.Errorf("anonymous GET /tokens = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	// Signed in: list and form render inside the portal.
	if rec := h.do(t, request{method: http.MethodGet, path: "/tokens", cookie: cookie}); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "No tokens yet") {
		t.Errorf("GET /tokens = %d:\n%s", rec.Code, rec.Body)
	}
	// POST without the CSRF token is refused before the handler runs.
	form := url.Values{"name": {"laptop"}}
	if rec := h.do(t, request{method: http.MethodPost, path: "/tokens/new", cookie: cookie, form: form}); rec.Code != http.StatusForbidden {
		t.Errorf("POST without CSRF = %d, want 403", rec.Code)
	}
	if list, _ := tsvc.List(context.Background(), principal.UserID); len(list) != 0 {
		t.Fatalf("CSRF-less POST created a token: %+v", list)
	}
	// With it: the token is shown once.
	form.Set("_csrf", principal.CSRFToken)
	rec = h.do(t, request{method: http.MethodPost, path: "/tokens/new", cookie: cookie, form: form})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /tokens/new = %d:\n%s", rec.Code, rec.Body)
	}
	raw := regexp.MustCompile(tokens.ScanPattern).FindString(html.UnescapeString(rec.Body.String()))
	if raw == "" {
		t.Fatalf("created page shows no token:\n%s", rec.Body)
	}
	pr, err := tsvc.Authenticate(context.Background(), raw)
	if err != nil || pr.UserID != principal.UserID {
		t.Fatalf("created token = %+v, %v", pr, err)
	}
	// The list shows the prefix only.
	body := h.do(t, request{method: http.MethodGet, path: "/tokens", cookie: cookie}).Body.String()
	if strings.Contains(body, raw) || !strings.Contains(body, "mgw_"+pr.PublicID) {
		t.Errorf("list page:\n%s", body)
	}
	// Revoke through the portal (CSRF header variant).
	rec = h.do(t, request{method: http.MethodPost, path: "/tokens/" + pr.TokenID + "/revoke", cookie: cookie,
		header: http.Header{"X-Csrf-Token": {principal.CSRFToken}}}) // canonical key: what htmx's hx-headers sends
	if rec.Code != http.StatusSeeOther {
		t.Errorf("revoke = %d", rec.Code)
	}
	if _, err := tsvc.Authenticate(context.Background(), raw); err == nil {
		t.Error("token still valid after revoke")
	}

	// Disabling the user revokes the rest through the hook.
	form = url.Values{"name": {"second"}, "_csrf": {principal.CSRFToken}}
	rec = h.do(t, request{method: http.MethodPost, path: "/tokens/new", cookie: cookie, form: form})
	second := regexp.MustCompile(tokens.ScanPattern).FindString(html.UnescapeString(rec.Body.String()))
	if second == "" {
		t.Fatal("second token not created")
	}
	if err := svc.DisableUser(context.Background(), "", principal.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := tsvc.Authenticate(context.Background(), second); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Errorf("after disable = %v, want revoked", err)
	}
}
