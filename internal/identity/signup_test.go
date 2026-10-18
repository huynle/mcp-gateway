package identity_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/identity/identitytest"
	"github.com/huynle/mcp-gateway/internal/store"
)

// memAudit collects audit events.
type memAudit struct {
	mu     sync.Mutex
	events []audit.Event
}

func (m *memAudit) Record(_ context.Context, ev audit.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, ev)
	return nil
}

func (m *memAudit) actions() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, ev := range m.events {
		out = append(out, ev.ResourceIdentity["action"])
	}
	return out
}

func (m *memAudit) find(action string) (audit.Event, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ev := range m.events {
		if ev.ResourceIdentity["action"] == action {
			return ev, true
		}
	}
	return audit.Event{}, false
}

func signupService(t *testing.T, mode string, mutate ...func(*identity.Config)) (*identity.Service, *identitytest.MemStore, *memAudit) {
	t.Helper()
	st := identitytest.NewMemStore()
	cfg := testConfig(dexProvider())
	cfg.SignupMode = mode
	for _, m := range mutate {
		m(&cfg)
	}
	svc, _ := newService(t, cfg, st)
	rec := &memAudit{}
	svc.SetAudit(rec)
	return svc, st, rec
}

func claimsFor(sub string) identity.Claims {
	c := devClaims()
	c.Subject = sub
	c.Name = "user " + sub
	return c
}

func TestOpenModeKeepsTodaysBehaviour(t *testing.T) {
	svc, st, rec := signupService(t, config.SignupOpen)
	res, err := svc.SignIn(context.Background(), "dex", devClaims())
	if err != nil {
		t.Fatal(err)
	}
	if res.Pending || res.Principal == nil || !slices.Equal(st.RoleNames(res.Principal.UserID), []string{"member"}) {
		t.Fatalf("open sign-in = %+v, want an active member", res)
	}
	ev, ok := rec.find("user.signed_up")
	if !ok || ev.UserID != res.Principal.UserID || ev.ResourceIdentity["mode"] != "open" || ev.ResourceIdentity["status"] != "active" {
		t.Errorf("user.signed_up event = %+v (found %v)", ev, ok)
	}
}

func TestApprovalModeCreatesPendingUserWithoutRoleOrPrincipal(t *testing.T) {
	svc, st, rec := signupService(t, config.SignupApproval)
	ctx := context.Background()
	res, err := svc.SignIn(ctx, "dex", devClaims())
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	if !res.Pending || res.Principal != nil || res.PendingUser == nil || res.Cookie == nil {
		t.Fatalf("approval sign-in = %+v, want pending, no principal, a session cookie", res)
	}
	uid := res.PendingUser.UserID
	if roles := st.RoleNames(uid); len(roles) != 0 {
		t.Errorf("pending user roles = %v, want none", roles)
	}
	if ev, ok := rec.find("user.signed_up"); !ok || ev.ResourceIdentity["status"] != store.UserPending {
		t.Errorf("user.signed_up = %+v, want status pending", ev)
	}

	// Signing in again stays pending.
	res, err = svc.SignIn(ctx, "dex", devClaims())
	if err != nil || !res.Pending || res.Principal != nil {
		t.Fatalf("second sign-in = %+v, %v; want still pending", res, err)
	}

	// Approve: active, default role, audited under the admin.
	if err := svc.ApproveUser(ctx, "admin-1", uid); err != nil {
		t.Fatalf("ApproveUser: %v", err)
	}
	if roles := st.RoleNames(uid); !slices.Equal(roles, []string{"member"}) {
		t.Errorf("roles after approval = %v, want [member]", roles)
	}
	ev, ok := rec.find("user.approved")
	if !ok || ev.UserID != "admin-1" || ev.ResourceIdentity["target_user_id"] != uid {
		t.Errorf("user.approved = %+v", ev)
	}
	if err := svc.ApproveUser(ctx, "admin-1", uid); !errors.Is(err, identity.ErrNotPending) {
		t.Errorf("approving twice = %v, want ErrNotPending", err)
	}
	res, err = svc.SignIn(ctx, "dex", devClaims())
	if err != nil || res.Pending || res.Principal == nil {
		t.Fatalf("sign-in after approval = %+v, %v; want active", res, err)
	}
}

func TestApprovalUsesTheFlaggedDefaultRole(t *testing.T) {
	svc, st, _ := signupService(t, config.SignupApproval)
	st.SetDefaultRole("public")
	res, err := svc.SignIn(context.Background(), "dex", devClaims())
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveUser(context.Background(), "a", res.PendingUser.UserID); err != nil {
		t.Fatal(err)
	}
	if roles := st.RoleNames(res.PendingUser.UserID); !slices.Equal(roles, []string{"public"}) {
		t.Errorf("roles = %v, want [public]", roles)
	}
}

func TestRejectDisablesPendingUserAndEndsSessions(t *testing.T) {
	svc, st, rec := signupService(t, config.SignupApproval)
	ctx := context.Background()
	hookRan := false
	svc.OnDisable(func(context.Context, store.Tx, string) error { hookRan = true; return nil })
	res, err := svc.SignIn(ctx, "dex", devClaims())
	if err != nil {
		t.Fatal(err)
	}
	uid := res.PendingUser.UserID
	if err := svc.RejectUser(ctx, "admin-1", uid); err != nil {
		t.Fatalf("RejectUser: %v", err)
	}
	if st.LiveSessions(uid) != 0 || !hookRan {
		t.Errorf("after reject: live sessions %d, hook ran %v", st.LiveSessions(uid), hookRan)
	}
	if ev, ok := rec.find("user.rejected"); !ok || ev.ResourceIdentity["target_user_id"] != uid {
		t.Errorf("user.rejected = %+v", ev)
	}
	if _, err := svc.SignIn(ctx, "dex", devClaims()); !errors.Is(err, identity.ErrUserDisabled) {
		t.Errorf("sign-in after reject = %v, want ErrUserDisabled", err)
	}
	if err := svc.RejectUser(ctx, "admin-1", uid); !errors.Is(err, identity.ErrNotPending) {
		t.Errorf("rejecting a disabled user = %v, want ErrNotPending", err)
	}
	if err := svc.ApproveUser(ctx, "admin-1", "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("approving an unknown user = %v, want ErrNotFound", err)
	}
}

func TestEnableDoesNotApprovePendingUsers(t *testing.T) {
	svc, _, _ := signupService(t, config.SignupApproval)
	res, err := svc.SignIn(context.Background(), "dex", devClaims())
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.EnableUser(context.Background(), "a", res.PendingUser.UserID); !errors.Is(err, identity.ErrUserPending) {
		t.Errorf("EnableUser(pending) = %v, want ErrUserPending", err)
	}
}

func TestExistingUsersAreUnaffectedBySignupMode(t *testing.T) {
	st := identitytest.NewMemStore()
	open, _ := newService(t, testConfig(dexProvider()), st)
	if _, err := open.SignIn(context.Background(), "dex", devClaims()); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{config.SignupApproval, config.SignupInvite} {
		cfg := testConfig(dexProvider())
		cfg.SignupMode = mode
		cfg.SignupPerIPPerHour, cfg.SignupGlobalPerHour = 1, 1
		svc, _ := newService(t, cfg, st)
		for i := 0; i < 3; i++ {
			res, err := svc.SignIn(context.Background(), "dex", devClaims())
			if err != nil || res.Pending || res.Principal == nil {
				t.Fatalf("%s: existing user sign-in = %+v, %v; want active", mode, res, err)
			}
		}
	}
}

func TestBootstrapAdminsAreAlwaysActive(t *testing.T) {
	for _, mode := range []string{config.SignupApproval, config.SignupInvite} {
		svc, st, _ := signupService(t, mode, func(c *identity.Config) {
			c.BootstrapAdmins = []string{dexIssuer + "|" + devClaims().Subject}
		})
		res, err := svc.SignIn(context.Background(), "dex", devClaims())
		if err != nil || res.Pending || res.Principal == nil || !res.Principal.IsAdmin() {
			t.Fatalf("%s: bootstrap admin = %+v, %v; want active admin", mode, res, err)
		}
		if roles := st.RoleNames(res.Principal.UserID); !slices.Contains(roles, "member") {
			t.Errorf("%s: bootstrap admin roles = %v, want the default role too", mode, roles)
		}
	}
}

func TestPendingBootstrapAdminIsActivated(t *testing.T) {
	st := identitytest.NewMemStore()
	cfg := testConfig(dexProvider())
	cfg.SignupMode = config.SignupApproval
	svc, _ := newService(t, cfg, st)
	res, err := svc.SignIn(context.Background(), "dex", devClaims())
	if err != nil || !res.Pending {
		t.Fatalf("first sign-in = %+v, %v", res, err)
	}
	cfg.BootstrapAdmins = []string{dexIssuer + "|" + devClaims().Subject}
	svc, _ = newService(t, cfg, st)
	res, err = svc.SignIn(context.Background(), "dex", devClaims())
	if err != nil || res.Pending || !res.Principal.IsAdmin() || !slices.Contains(res.Principal.Roles, "member") {
		t.Fatalf("bootstrap admin after listing = %+v, %v; want active admin + member", res, err)
	}
}

func TestInviteMode(t *testing.T) {
	svc, st, rec := signupService(t, config.SignupInvite)
	ctx := context.Background()

	if _, err := svc.SignIn(ctx, "dex", claimsFor("a")); !errors.Is(err, identity.ErrInviteRequired) {
		t.Fatalf("sign-in without code = %v, want ErrInviteRequired", err)
	}
	for _, bad := range []string{"nope", "mgwi_" + strings.Repeat("A", 43)} {
		if _, err := svc.SignInWith(ctx, "dex", claimsFor("a"), identity.Attempt{InviteCode: bad}); !errors.Is(err, identity.ErrInviteInvalid) {
			t.Errorf("sign-in with %q = %v, want ErrInviteInvalid", bad, err)
		}
	}
	if st.UserCount() != 0 {
		t.Fatalf("refused sign-ins created %d users", st.UserCount())
	}

	code, inv, err := svc.CreateInvite(ctx, "admin-1", "for alice", 24*time.Hour)
	if err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}
	if !strings.HasPrefix(code, "mgwi_") || inv.ID == "" || strings.Contains(fmt.Sprint(inv.CodeHash), code) {
		t.Errorf("invite = %q, %+v", code, inv)
	}
	if ev, ok := rec.find("signup_invite.created"); !ok || ev.UserID != "admin-1" || ev.ResourceIdentity["invite_id"] != inv.ID {
		t.Errorf("signup_invite.created = %+v", ev)
	}
	for _, ev := range rec.events {
		for _, v := range ev.ResourceIdentity {
			if strings.Contains(v, code) || v == "for alice" {
				t.Errorf("audit event carries the code or the label: %+v", ev)
			}
		}
	}

	res, err := svc.SignInWith(ctx, "dex", claimsFor("a"), identity.Attempt{InviteCode: code})
	if err != nil || res.Pending || res.Principal == nil {
		t.Fatalf("sign-in with a valid code = %+v, %v; want active", res, err)
	}
	if roles := st.RoleNames(res.Principal.UserID); !slices.Equal(roles, []string{"member"}) {
		t.Errorf("invited user roles = %v", roles)
	}
	// Single use.
	if _, err := svc.SignInWith(ctx, "dex", claimsFor("b"), identity.Attempt{InviteCode: code}); !errors.Is(err, identity.ErrInviteInvalid) {
		t.Errorf("reusing the code = %v, want ErrInviteInvalid", err)
	}
	// The invited user signs in again without a code.
	if _, err := svc.SignIn(ctx, "dex", claimsFor("a")); err != nil {
		t.Errorf("invited user's second sign-in = %v", err)
	}

	// Expired and revoked codes are refused.
	now := time.Now().UTC()
	svc.SetClock(func() time.Time { return now })
	expiring, _, err := svc.CreateInvite(ctx, "admin-1", "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	revoked, rinv, err := svc.CreateInvite(ctx, "admin-1", "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.RevokeInvite(ctx, "admin-1", rinv.ID); err != nil {
		t.Fatalf("RevokeInvite: %v", err)
	}
	if _, ok := rec.find("signup_invite.revoked"); !ok {
		t.Error("no signup_invite.revoked event")
	}
	if _, err := svc.SignInWith(ctx, "dex", claimsFor("c"), identity.Attempt{InviteCode: revoked}); !errors.Is(err, identity.ErrInviteInvalid) {
		t.Errorf("revoked code = %v, want ErrInviteInvalid", err)
	}
	svc.SetClock(func() time.Time { return now.Add(2 * time.Hour) })
	if _, err := svc.SignInWith(ctx, "dex", claimsFor("c"), identity.Attempt{InviteCode: expiring}); !errors.Is(err, identity.ErrInviteInvalid) {
		t.Errorf("expired code = %v, want ErrInviteInvalid", err)
	}
	if _, _, err := svc.CreateInvite(ctx, "admin-1", "", 0); err == nil {
		t.Error("an invite without a lifetime must be refused")
	}
	if _, _, err := svc.CreateInvite(ctx, "admin-1", strings.Repeat("x", 101), time.Hour); err == nil {
		t.Error("an over-long label must be refused")
	}
	list, err := svc.ListInvites(ctx)
	if err != nil || len(list) != 3 {
		t.Errorf("ListInvites = %d, %v; want 3", len(list), err)
	}
}

func TestInviteCodesAreIgnoredOutsideInviteMode(t *testing.T) {
	svc, _, _ := signupService(t, config.SignupApproval)
	res, err := svc.SignInWith(context.Background(), "dex", devClaims(), identity.Attempt{InviteCode: "garbage"})
	if err != nil || !res.Pending {
		t.Fatalf("approval mode with a code = %+v, %v; want pending", res, err)
	}
}

func TestSignupRateLimits(t *testing.T) {
	svc, st, rec := signupService(t, config.SignupOpen, func(c *identity.Config) {
		c.SignupPerIPPerHour, c.SignupGlobalPerHour = 2, 3
	})
	ctx := context.Background()
	now := time.Now().UTC()
	svc.SetClock(func() time.Time { return now })
	signUp := func(sub, ip string) error {
		_, err := svc.SignInWith(ctx, "dex", claimsFor(sub), identity.Attempt{ClientIP: ip})
		return err
	}
	for i, ip := range []string{"192.0.2.1", "192.0.2.1"} {
		if err := signUp(fmt.Sprint("a", i), ip); err != nil {
			t.Fatalf("sign-up %d: %v", i, err)
		}
	}
	var rl *identity.SignupRateLimitedError
	if err := signUp("a2", "192.0.2.1"); !errors.Is(err, identity.ErrSignupRateLimited) || !errors.As(err, &rl) || rl.Scope != "ip" {
		t.Fatalf("third sign-up from one IP = %v, want ErrSignupRateLimited (ip)", err)
	}
	ev, ok := rec.find("signup.rate_limited")
	if !ok || ev.UserID != "" || ev.ResourceIdentity["scope"] != "ip" || ev.Outcome != "denied" {
		t.Errorf("signup.rate_limited = %+v", ev)
	}
	for _, v := range ev.ResourceIdentity {
		if strings.Contains(v, "192.0.2") {
			t.Errorf("audit event carries the client IP: %+v", ev)
		}
	}
	if err := signUp("b0", "198.51.100.7"); err != nil {
		t.Fatalf("other IP: %v", err)
	}
	if err := signUp("b1", "198.51.100.8"); !errors.Is(err, identity.ErrSignupRateLimited) || !errors.As(err, &rl) || rl.Scope != "global" {
		t.Fatalf("fourth sign-up = %v, want global limit", err)
	}
	if st.UserCount() != 3 {
		t.Errorf("users = %d, want 3 (refused sign-ups create nothing)", st.UserCount())
	}
	// Existing users always sign in.
	if err := signUp("a0", "192.0.2.1"); err != nil {
		t.Errorf("existing user sign-in under the limit = %v", err)
	}
	// The window rolls.
	svc.SetClock(func() time.Time { return now.Add(61 * time.Minute) })
	if err := signUp("c0", "192.0.2.1"); err != nil {
		t.Errorf("sign-up after the window = %v", err)
	}
}

func TestPendingSessionResolvesToPendingUserNotPrincipal(t *testing.T) {
	svc, _, _ := signupService(t, config.SignupApproval)
	res, err := svc.SignIn(context.Background(), "dex", devClaims())
	if err != nil {
		t.Fatal(err)
	}
	var gotP *identity.Principal
	var gotPending *identity.PendingUser
	h := svc.Middleware(httpHandlerFunc(func(ctx context.Context) {
		gotP = identity.PrincipalFrom(ctx)
		gotPending = identity.PendingFrom(ctx)
	}))
	serve(t, h, res.Cookie)
	if gotP != nil || gotPending == nil || gotPending.UserID != res.PendingUser.UserID || gotPending.CSRFToken == "" {
		t.Fatalf("pending session: principal %+v, pending %+v", gotP, gotPending)
	}
	if err := svc.ApproveUser(context.Background(), "a", res.PendingUser.UserID); err != nil {
		t.Fatal(err)
	}
	serve(t, h, res.Cookie)
	if gotP == nil || gotPending != nil {
		t.Fatalf("approved session: principal %+v, pending %+v", gotP, gotPending)
	}
}

func httpHandlerFunc(fn func(context.Context)) http.Handler {
	return http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { fn(r.Context()) })
}

func serve(t *testing.T, h http.Handler, ck *http.Cookie) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(ck)
	h.ServeHTTP(httptest.NewRecorder(), req)
}

// --- over HTTP ------------------------------------------------------------------

func TestPendingSignInRedirectsToThePendingPage(t *testing.T) {
	g := newGatewayWith(t, func(c *identity.Config) { c.SignupMode = config.SignupApproval })
	c := g.client(t, false)
	resp := g.get(t, c, "/auth/dex/start?return_to=/whoami")
	for resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther {
		loc := resp.Header.Get("Location")
		if resp.Request.URL.Path == "/auth/dex/callback" {
			if loc != identity.PendingPath {
				t.Fatalf("callback redirected a pending user to %q, want %s", loc, identity.PendingPath)
			}
			break
		}
		resp = g.get(t, c, loc)
	}
	if w := g.whoami(t, c); !w.Anonymous {
		t.Errorf("pending user is a principal: %+v", w)
	}
}

func TestInviteCodeTravelsThroughTheSignInFlow(t *testing.T) {
	g := newGatewayWith(t, func(c *identity.Config) { c.SignupMode = config.SignupInvite })
	c := g.client(t, true)
	resp := g.get(t, c, "/auth/dex/start")
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(resp.Text, "invite") {
		t.Fatalf("sign-in without an invite = %d %q, want 403 mentioning the invite", resp.StatusCode, resp.Text)
	}
	code, _, err := g.svc.CreateInvite(t.Context(), "", "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	resp = g.get(t, c, "/auth/dex/start?return_to=/whoami&invite="+url.QueryEscape(code))
	if resp.StatusCode != http.StatusOK || resp.Request.URL.Path != "/whoami" {
		t.Fatalf("sign-in with an invite ended at %s with %d", resp.Request.URL, resp.StatusCode)
	}
	if w := decodeWhoami(t, resp); w.Anonymous {
		t.Error("invited user should be signed in")
	}
	if strings.Contains(g.idp.lastAuthRequest().state, code) {
		t.Error("the invite code must not be sent to the identity provider")
	}
}

func TestSignupRateLimitIs429(t *testing.T) {
	g := newGatewayWith(t, func(c *identity.Config) { c.SignupPerIPPerHour, c.SignupGlobalPerHour = 1, 10 })
	if resp := g.signIn(t, g.client(t, true), ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("first sign-up = %d", resp.StatusCode)
	}
	g.idp.setClaim("sub", "second-user")
	resp := g.signIn(t, g.client(t, true), "")
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("second sign-up from the same IP = %d (Retry-After %q), want 429", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
}
