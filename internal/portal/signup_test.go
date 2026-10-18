package portal_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/identity/identitytest"
	"github.com/huynle/mcp-gateway/internal/portal"
	"github.com/huynle/mcp-gateway/internal/store"
)

func newSignupHarness(t *testing.T, mode string) *harness {
	t.Helper()
	st := identitytest.NewMemStore()
	cfg := identity.Config{
		BaseURL: "https://gw.example.com",
		Providers: []config.OIDCProvider{
			{Name: "dex", DisplayName: "Local dex", Issuer: issuer, ClientID: "gateway", ClientSecret: "s", AllowedDomains: []string{config.AnyDomainWildcard}},
		},
		DefaultRole:     defaultRole,
		BootstrapAdmins: []string{issuer + "|" + adminSub},
		IdleTimeout:     12 * time.Hour,
		AbsoluteTimeout: 7 * 24 * time.Hour,
		SignupMode:      mode,
	}
	svc, err := identity.New(cfg, st, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	p, err := portal.New(svc, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	// A module page mounted like /tokens or /connect/{vendor}/start.
	p.MountUser("GET /mounted", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("mounted")) }))
	return &harness{h: p.Handler(), svc: svc, st: st, portal: p}
}

func (h *harness) pendingSession(t *testing.T, subject string) (*http.Cookie, *identity.PendingUser) {
	t.Helper()
	res, err := h.svc.SignIn(context.Background(), "dex", identity.Claims{
		Issuer: issuer, Subject: subject, Name: "New " + subject, Email: subject + "@gmail.com", EmailVerified: true,
	})
	if err != nil || !res.Pending {
		t.Fatalf("SignIn(%s) = %+v, %v; want pending", subject, res, err)
	}
	return res.Cookie, res.PendingUser
}

func TestPendingUserOnlyReachesThePendingPage(t *testing.T) {
	h := newSignupHarness(t, config.SignupApproval)
	ck, pu := h.pendingSession(t, "newbie")

	for _, path := range []string{"/", "/signin", "/account", "/admin/users", "/mounted"} {
		rec := h.do(t, request{method: http.MethodGet, path: path, cookie: ck})
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != identity.PendingPath {
			t.Errorf("pending GET %s = %d %q, want 303 %s", path, rec.Code, rec.Header().Get("Location"), identity.PendingPath)
		}
	}
	rec := h.do(t, request{method: http.MethodGet, path: "/pending", cookie: ck})
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "Waiting for approval") || !strings.Contains(body, `value="`+pu.CSRFToken+`"`) {
		t.Fatalf("GET /pending = %d:\n%s", rec.Code, body)
	}
	if strings.Contains(body, `href="/account"`) || strings.Contains(body, `href="/tokens"`) {
		t.Error("the pending page must not link into the portal")
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q", cc)
	}
	// A pending user may not submit any form except sign-out.
	rec = h.do(t, request{method: http.MethodPost, path: "/account/rate-limit", cookie: ck, form: url.Values{"_csrf": {pu.CSRFToken}}})
	if rec.Code == http.StatusOK || rec.Code == http.StatusSeeOther && rec.Header().Get("Location") != identity.PendingPath {
		t.Errorf("pending POST = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	rec = h.do(t, request{method: http.MethodPost, path: "/auth/signout", cookie: ck, form: url.Values{"_csrf": {"wrong"}}})
	if rec.Code != http.StatusForbidden {
		t.Errorf("pending sign-out with a wrong token = %d, want 403", rec.Code)
	}
	rec = h.do(t, request{method: http.MethodPost, path: "/auth/signout", cookie: ck, form: url.Values{"_csrf": {pu.CSRFToken}}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("pending sign-out = %d", rec.Code)
	}
	if h.st.LiveSessions(pu.UserID) != 0 {
		t.Error("sign-out should end the pending session")
	}
}

func TestPendingPageForOthers(t *testing.T) {
	h := newSignupHarness(t, config.SignupApproval)
	rec := h.do(t, request{method: http.MethodGet, path: "/pending"})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/signin" {
		t.Errorf("anonymous GET /pending = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	admin, _ := h.session(t, adminSub, "Admin")
	rec = h.do(t, request{method: http.MethodGet, path: "/pending", cookie: admin})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/account" {
		t.Errorf("active GET /pending = %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestAdminApprovesAndRejectsPendingUsers(t *testing.T) {
	h := newSignupHarness(t, config.SignupApproval)
	admin, ap := h.session(t, adminSub, "Admin")
	ck1, p1 := h.pendingSession(t, "one")
	_, p2 := h.pendingSession(t, "two")

	rec := h.do(t, request{method: http.MethodGet, path: "/admin/users", cookie: admin})
	body := rec.Body.String()
	for _, want := range []string{"Pending approval", `<span class="pill pending">2</span>`,
		`action="/admin/users/` + p1.UserID + `/approve"`, `action="/admin/users/` + p2.UserID + `/reject"`} {
		if !strings.Contains(body, want) {
			t.Errorf("users page lacks %q", want)
		}
	}
	if strings.Contains(body, `action="/admin/users/`+p1.UserID+`/role"`) {
		t.Error("a pending user's role is set by approval, not by the role select")
	}

	rec = h.do(t, request{method: http.MethodPost, path: "/admin/users/" + p1.UserID + "/approve", cookie: admin, form: url.Values{"_csrf": {ap.CSRFToken}}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("approve = %d", rec.Code)
	}
	if roles := h.st.RoleNames(p1.UserID); !slices.Equal(roles, []string{defaultRole}) {
		t.Errorf("approved roles = %v", roles)
	}
	// The approved user's existing session is now a full session.
	if rec := h.do(t, request{method: http.MethodGet, path: "/account", cookie: ck1}); rec.Code != http.StatusOK {
		t.Errorf("approved user GET /account = %d", rec.Code)
	}
	// Approving twice is a conflict.
	rec = h.do(t, request{method: http.MethodPost, path: "/admin/users/" + p1.UserID + "/approve", cookie: admin, form: url.Values{"_csrf": {ap.CSRFToken}}})
	if rec.Code != http.StatusConflict {
		t.Errorf("approve again = %d, want 409", rec.Code)
	}
	rec = h.do(t, request{method: http.MethodPost, path: "/admin/users/" + p2.UserID + "/reject", cookie: admin, form: url.Values{"_csrf": {ap.CSRFToken}},
		header: http.Header{"Hx-Request": {"true"}}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `pill disabled`) {
		t.Errorf("htmx reject = %d %s", rec.Code, rec.Body.String())
	}
	if u := h.userStatus(t, p2.UserID); u != store.UserDisabled {
		t.Errorf("rejected status = %q", u)
	}
	// Enable refuses a pending user; set-role too.
	_, p3 := h.pendingSession(t, "three")
	for _, action := range []string{"enable", "role"} {
		rec = h.do(t, request{method: http.MethodPost, path: "/admin/users/" + p3.UserID + "/" + action, cookie: admin, form: url.Values{"_csrf": {ap.CSRFToken}, "role": {defaultRole}}})
		if rec.Code != http.StatusConflict {
			t.Errorf("%s on a pending user = %d, want 409", action, rec.Code)
		}
	}
	if h.userStatus(t, p3.UserID) != store.UserPending || len(h.st.RoleNames(p3.UserID)) != 0 {
		t.Error("a refused enable / set-role must not change the pending user")
	}
	// Non-admins get the 404.
	member, mp := h.session(t, "one", "One")
	rec = h.do(t, request{method: http.MethodPost, path: "/admin/users/" + p3.UserID + "/approve", cookie: member, form: url.Values{"_csrf": {mp.CSRFToken}}})
	if rec.Code != http.StatusNotFound {
		t.Errorf("member approve = %d, want 404", rec.Code)
	}
	rec = h.do(t, request{method: http.MethodPost, path: "/admin/users/not-a-user/approve", cookie: admin, form: url.Values{"_csrf": {ap.CSRFToken}}})
	if rec.Code != http.StatusNotFound {
		t.Errorf("approve unknown = %d, want 404", rec.Code)
	}
}

func (h *harness) userStatus(t *testing.T, id string) string {
	t.Helper()
	var status string
	_ = h.st.Bypass(context.Background(), func(tx identity.Tx) error {
		u, err := tx.GetUser(context.Background(), id)
		if err == nil {
			status = u.Status
		}
		return err
	})
	return status
}

var inviteCodeRE = regexp.MustCompile(`mgwi_[A-Za-z0-9_-]{43}`)

func TestAdminInvites(t *testing.T) {
	h := newSignupHarness(t, config.SignupInvite)
	admin, ap := h.session(t, adminSub, "Admin")

	rec := h.do(t, request{method: http.MethodGet, path: "/admin/users", cookie: admin})
	if !strings.Contains(rec.Body.String(), `action="/admin/users/invites"`) {
		t.Fatal("invite mode: the users page should offer invites")
	}
	rec = h.do(t, request{method: http.MethodPost, path: "/admin/users/invites", cookie: admin, form: url.Values{"_csrf": {ap.CSRFToken}, "label": {"for <b>bob</b>"}, "days": {"7"}}})
	body := rec.Body.String()
	code := inviteCodeRE.FindString(body)
	if rec.Code != http.StatusOK || code == "" {
		t.Fatalf("create invite = %d:\n%s", rec.Code, body)
	}
	if !strings.Contains(body, "https://gw.example.com/signin?invite="+code) || !strings.Contains(body, "for &lt;b&gt;bob&lt;/b&gt;") {
		t.Errorf("invite page lacks the link or the escaped label:\n%s", body)
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q", cc)
	}
	// Shown once: the list never repeats the code.
	rec = h.do(t, request{method: http.MethodGet, path: "/admin/users", cookie: admin})
	if strings.Contains(rec.Body.String(), code) || !strings.Contains(rec.Body.String(), "unused") {
		t.Error("the users page must list the invite without its code")
	}
	// The sign-in page carries the invite to every provider.
	rec = h.do(t, request{method: http.MethodGet, path: "/signin?invite=" + url.QueryEscape(code)})
	if !strings.Contains(rec.Body.String(), "invite="+code) {
		t.Errorf("sign-in page does not carry the invite:\n%s", rec.Body.String())
	}
	for _, days := range []string{"0", "31", "x"} {
		rec = h.do(t, request{method: http.MethodPost, path: "/admin/users/invites", cookie: admin, form: url.Values{"_csrf": {ap.CSRFToken}, "days": {days}}})
		if rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("days=%s = %d, want 422", days, rec.Code)
		}
	}
	list, _ := h.svc.ListInvites(context.Background())
	if len(list) != 1 {
		t.Fatalf("invites = %d", len(list))
	}
	rec = h.do(t, request{method: http.MethodPost, path: "/admin/users/invites/" + list[0].ID + "/revoke", cookie: admin, form: url.Values{"_csrf": {ap.CSRFToken}}})
	if rec.Code != http.StatusSeeOther {
		t.Errorf("revoke = %d", rec.Code)
	}
	rec = h.do(t, request{method: http.MethodPost, path: "/admin/users/invites/" + list[0].ID + "/revoke", cookie: admin, form: url.Values{"_csrf": {ap.CSRFToken}}})
	if rec.Code != http.StatusNotFound {
		t.Errorf("revoke twice = %d, want 404", rec.Code)
	}
	if _, err := h.svc.SignInWith(context.Background(), "dex", identity.Claims{Issuer: issuer, Subject: "x", Email: "x@gmail.com", EmailVerified: true}, identity.Attempt{InviteCode: code}); err == nil {
		t.Error("a revoked invite must not sign anyone up")
	}
}

func TestInvitesAreHiddenOutsideInviteMode(t *testing.T) {
	h := newSignupHarness(t, config.SignupApproval)
	admin, ap := h.session(t, adminSub, "Admin")
	rec := h.do(t, request{method: http.MethodGet, path: "/admin/users", cookie: admin})
	if strings.Contains(rec.Body.String(), `action="/admin/users/invites"`) {
		t.Error("approval mode should not offer invites")
	}
	rec = h.do(t, request{method: http.MethodPost, path: "/admin/users/invites", cookie: admin, form: url.Values{"_csrf": {ap.CSRFToken}, "days": {"7"}}})
	if rec.Code != http.StatusNotFound {
		t.Errorf("create invite outside invite mode = %d, want 404", rec.Code)
	}
}
