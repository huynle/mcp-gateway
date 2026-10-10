package portal_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/fake"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/identity/identitytest"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/policy/policytest"
	"github.com/huynle/mcp-gateway/internal/portal"
)

// The role pages mounted through MountAdmin, end to end: a member gets the
// portal's 404, an admin's POST without the CSRF token is refused before
// anything changes, and the editor round-trips a structured role.
func TestRolePagesThroughThePortal(t *testing.T) {
	st := identitytest.NewMemStore()
	cfg := identity.Config{
		BaseURL:         "http://localhost:18080",
		Providers:       []config.OIDCProvider{{Name: "dex", DisplayName: "Local dex", Issuer: issuer, ClientID: "gateway", ClientSecret: "s", AllowedDomains: []string{"example.com"}}},
		DefaultRole:     defaultRole,
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
	f := fake.New(fake.Options{})
	reg := connectors.NewRegistry()
	if err := connectors.RegisterConnector(reg, f, f.Accounts()); err != nil {
		t.Fatal(err)
	}
	pst := policytest.NewMemStore()
	pst.PutRole(policy.Role{Name: defaultRole})
	psvc, err := policy.New(pst, policy.Options{Log: slog.New(slog.DiscardHandler)})
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
	policy.NewPortal(psvc, reg, who, slog.New(slog.DiscardHandler)).Mount(p.MountAdmin)

	h := &harness{h: p.Handler(), svc: svc, st: st}
	member, _ := h.session(t, memberSub, "Member")
	admin, adminPrincipal := h.session(t, adminSub, "Admin")

	// Anonymous: redirected; member: the portal's 404 page for every route.
	if rec := h.do(t, request{method: http.MethodGet, path: "/admin/roles"}); rec.Code != http.StatusSeeOther {
		t.Errorf("anonymous GET /admin/roles = %d", rec.Code)
	}
	for _, path := range []string{"/admin/roles", "/admin/roles/new", "/admin/roles/" + defaultRole, "/admin/settings/default-role"} {
		rec := h.do(t, request{method: http.MethodGet, path: path, cookie: member})
		if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "Page not found") {
			t.Errorf("member GET %s = %d", path, rec.Code)
		}
	}
	form := url.Values{"name": {"auditor"}, "outcome.fake.*": {"allow"}}
	if rec := h.do(t, request{method: http.MethodPost, path: "/admin/roles/new", cookie: member, form: form}); rec.Code != http.StatusNotFound {
		t.Errorf("member POST = %d, want 404", rec.Code)
	}
	// Admin without the CSRF token: refused, nothing created.
	if rec := h.do(t, request{method: http.MethodPost, path: "/admin/roles/new", cookie: admin, form: form}); rec.Code != http.StatusForbidden {
		t.Errorf("admin POST without CSRF = %d, want 403", rec.Code)
	}
	if _, err := psvc.Role(context.Background(), "auditor"); err == nil {
		t.Fatal("CSRF-less POST created a role")
	}
	// With it: created, redirected to the editor, visible in the list.
	form.Set("_csrf", adminPrincipal.CSRFToken)
	rec := h.do(t, request{method: http.MethodPost, path: "/admin/roles/new", cookie: admin, form: form})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/roles/auditor" {
		t.Fatalf("admin POST = %d %q:\n%s", rec.Code, rec.Header().Get("Location"), firstN(rec.Body.String(), 400))
	}
	role, err := psvc.Role(context.Background(), "auditor")
	if err != nil || len(role.Rules) != 1 || role.Rules[0].Tool != "*" || role.Rules[0].Outcome != policy.OutcomeAllow {
		t.Errorf("created role = %+v, %v", role, err)
	}
	if rec := h.do(t, request{method: http.MethodGet, path: "/admin/roles", cookie: admin}); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "/admin/roles/auditor") {
		t.Errorf("admin GET /admin/roles = %d:\n%s", rec.Code, firstN(rec.Body.String(), 400))
	}
	// The identity admin page can now assign it (the existing role select).
	if rec := h.do(t, request{method: http.MethodGet, path: "/admin/roles/auditor", cookie: admin}); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `name="outcome.fake.list_items"`) {
		t.Errorf("editor = %d", rec.Code)
	}
}
