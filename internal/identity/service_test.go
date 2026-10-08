package identity_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/store"
)

const dexIssuer = "http://localhost:15556/dex"

func dexProvider() config.OIDCProvider {
	return config.OIDCProvider{
		Name:           "dex",
		DisplayName:    "Local dex",
		Issuer:         dexIssuer,
		ClientID:       "gateway",
		ClientSecret:   "gateway-dev-secret",
		AllowedDomains: []string{"example.com"},
	}
}

func testConfig(providers ...config.OIDCProvider) identity.Config {
	return identity.Config{
		BaseURL:         "http://localhost:18080",
		Providers:       providers,
		DefaultRole:     "member",
		IdleTimeout:     12 * time.Hour,
		AbsoluteTimeout: 7 * 24 * time.Hour,
	}
}

func newService(t *testing.T, cfg identity.Config, st identity.Store) (*identity.Service, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logs, nil))
	svc, err := identity.New(cfg, st, log)
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}
	return svc, &logs
}

func devClaims() identity.Claims {
	return identity.Claims{
		Issuer:        dexIssuer,
		Subject:       "08a8684b-db88-4b73-90a9-3cd1661f5466",
		Name:          "dev",
		Email:         "dev@example.com",
		EmailVerified: true,
	}
}

func TestSignInCreatesUserWithDefaultRole(t *testing.T) {
	st := newMemStore()
	svc, logs := newService(t, testConfig(dexProvider()), st)

	res, err := svc.SignIn(context.Background(), "dex", devClaims())
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	if !res.Created {
		t.Error("first sign-in should create the user")
	}
	if res.Principal.DisplayName != "dev" {
		t.Errorf("DisplayName = %q, want dev", res.Principal.DisplayName)
	}
	if got := st.roleNames(res.Principal.UserID); !slices.Equal(got, []string{"member"}) {
		t.Errorf("roles = %v, want [member]", got)
	}
	if !slices.Equal(res.Principal.Roles, []string{"member"}) {
		t.Errorf("Principal.Roles = %v, want [member]", res.Principal.Roles)
	}
	if res.Principal.IsAdmin() {
		t.Error("a default-role user must not be admin")
	}
	if res.Cookie == nil || res.Cookie.Value == "" || !res.Cookie.HttpOnly {
		t.Errorf("session cookie = %+v, want a set HttpOnly cookie", res.Cookie)
	}
	if st.liveSessions(res.Principal.UserID) != 1 {
		t.Errorf("live sessions = %d, want 1", st.liveSessions(res.Principal.UserID))
	}
	if !strings.Contains(logs.String(), `"event":"identity.signin"`) {
		t.Errorf("expected a structured sign-in event, got logs:\n%s", logs.String())
	}
	if strings.Contains(logs.String(), "dev@example.com") {
		t.Errorf("logs must not contain the email address:\n%s", logs.String())
	}
}

func TestSecondSignInReusesUserAndRotatesSession(t *testing.T) {
	st := newMemStore()
	svc, _ := newService(t, testConfig(dexProvider()), st)
	ctx := context.Background()

	first, err := svc.SignIn(ctx, "dex", devClaims())
	if err != nil {
		t.Fatal(err)
	}
	// The admin changed the user's role in between; sign-in must not reset it.
	if err := st.Bypass(ctx, func(tx identity.Tx) error {
		r, err := tx.EnsureRole(ctx, "reviewer", "")
		if err != nil {
			return err
		}
		return tx.SetUserRole(ctx, first.Principal.UserID, r.ID, nil)
	}); err != nil {
		t.Fatal(err)
	}
	claims := devClaims()
	claims.Name = "Dev Renamed"
	second, err := svc.SignIn(ctx, "dex", claims)
	if err != nil {
		t.Fatal(err)
	}
	if second.Created {
		t.Error("second sign-in must not create a user")
	}
	if second.Principal.UserID != first.Principal.UserID {
		t.Errorf("second sign-in user %s != first %s", second.Principal.UserID, first.Principal.UserID)
	}
	if st.userCount() != 1 {
		t.Errorf("user count = %d, want 1", st.userCount())
	}
	if got := st.roleNames(first.Principal.UserID); !slices.Equal(got, []string{"reviewer"}) {
		t.Errorf("roles after second sign-in = %v, want [reviewer] (default role must only apply on create)", got)
	}
	if second.Principal.DisplayName != "Dev Renamed" {
		t.Errorf("display name should follow the provider, got %q", second.Principal.DisplayName)
	}
	if second.Cookie.Value == first.Cookie.Value {
		t.Error("session must be rotated on sign-in")
	}
	if st.liveSessions(first.Principal.UserID) != 2 {
		t.Errorf("live sessions = %d, want 2 (a new browser sign-in does not revoke other browsers)", st.liveSessions(first.Principal.UserID))
	}
}

func TestSignInRecordsLastCompanySignIn(t *testing.T) {
	st := newMemStore()
	svc, _ := newService(t, testConfig(dexProvider()), st)
	at := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	svc.SetClock(func() time.Time { return at })

	res, err := svc.SignIn(context.Background(), "dex", devClaims())
	if err != nil {
		t.Fatal(err)
	}
	_ = st.Bypass(context.Background(), func(tx identity.Tx) error {
		u, err := tx.GetUser(context.Background(), res.Principal.UserID)
		if err != nil {
			return err
		}
		if u.LastCompanySignInAt == nil || !u.LastCompanySignInAt.Equal(at) {
			t.Errorf("LastCompanySignInAt = %v, want %v", u.LastCompanySignInAt, at)
		}
		return nil
	})
}

func TestSignInRejectsDisallowedDomain(t *testing.T) {
	st := newMemStore()
	svc, logs := newService(t, testConfig(dexProvider()), st)

	claims := devClaims()
	claims.Email = "intruder@evil.test"
	_, err := svc.SignIn(context.Background(), "dex", claims)
	if !errors.Is(err, identity.ErrNotAllowed) {
		t.Fatalf("SignIn = %v, want ErrNotAllowed", err)
	}
	if st.userCount() != 0 {
		t.Error("a rejected sign-in must not create a user")
	}
	if !strings.Contains(logs.String(), `"event":"identity.signin_rejected"`) || !strings.Contains(logs.String(), `"reason":"domain_not_allowed"`) {
		t.Errorf("expected a structured rejection event, got logs:\n%s", logs.String())
	}
}

func TestSignInAllowRules(t *testing.T) {
	cases := []struct {
		name     string
		provider config.OIDCProvider
		claims   identity.Claims
		allowed  bool
	}{
		{
			name:     "google hd claim",
			provider: config.OIDCProvider{Name: "google", Issuer: "https://accounts.google.com", ClientID: "c", ClientSecret: "s", AllowedDomains: []string{"example.com"}},
			claims:   identity.Claims{Issuer: "https://accounts.google.com", Subject: "1", Email: "a@example.com", EmailVerified: true, Extra: map[string]any{"hd": "example.com"}},
			allowed:  true,
		},
		{
			name:     "google hd mismatch beats email",
			provider: config.OIDCProvider{Name: "google", Issuer: "https://accounts.google.com", ClientID: "c", ClientSecret: "s", AllowedDomains: []string{"example.com"}},
			claims:   identity.Claims{Issuer: "https://accounts.google.com", Subject: "1", Email: "a@example.com", EmailVerified: true, Extra: map[string]any{"hd": "other.com"}},
			allowed:  false,
		},
		{
			name:     "unverified email domain is not trusted",
			provider: dexProvider(),
			claims:   identity.Claims{Issuer: dexIssuer, Subject: "1", Email: "a@example.com", EmailVerified: false},
			allowed:  false,
		},
		{
			name:     "email domain is case-insensitive",
			provider: dexProvider(),
			claims:   identity.Claims{Issuer: dexIssuer, Subject: "1", Email: "a@Example.COM", EmailVerified: true},
			allowed:  true,
		},
		{
			name:     "entra tenant",
			provider: config.OIDCProvider{Name: "entra", Issuer: "https://login.microsoftonline.com/t1/v2.0", ClientID: "c", ClientSecret: "s", AllowedTenants: []string{"t1"}},
			claims:   identity.Claims{Issuer: "https://login.microsoftonline.com/t1/v2.0", Subject: "1", Extra: map[string]any{"tid": "t1"}},
			allowed:  true,
		},
		{
			name:     "entra wrong tenant",
			provider: config.OIDCProvider{Name: "entra", Issuer: "https://login.microsoftonline.com/t1/v2.0", ClientID: "c", ClientSecret: "s", AllowedTenants: []string{"t1"}},
			claims:   identity.Claims{Issuer: "https://login.microsoftonline.com/t1/v2.0", Subject: "1", Extra: map[string]any{"tid": "t2"}},
			allowed:  false,
		},
		{
			name:     "custom domain claim",
			provider: config.OIDCProvider{Name: "okta", Issuer: "https://co.okta.com", ClientID: "c", ClientSecret: "s", AllowedDomains: []string{"example.com"}, DomainClaim: "org_domain"},
			claims:   identity.Claims{Issuer: "https://co.okta.com", Subject: "1", Email: "a@example.com", EmailVerified: true, Extra: map[string]any{"org_domain": "other.com"}},
			allowed:  false,
		},
		{
			name:     "no domain information at all",
			provider: dexProvider(),
			claims:   identity.Claims{Issuer: dexIssuer, Subject: "1"},
			allowed:  false,
		},
		{
			name:     "issuer must match the provider",
			provider: dexProvider(),
			claims:   identity.Claims{Issuer: "https://evil.test", Subject: "1", Email: "a@example.com", EmailVerified: true},
			allowed:  false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := newService(t, testConfig(tc.provider), newMemStore())
			_, err := svc.SignIn(context.Background(), tc.provider.Name, tc.claims)
			if tc.allowed && err != nil {
				t.Errorf("SignIn = %v, want success", err)
			}
			if !tc.allowed && !errors.Is(err, identity.ErrNotAllowed) {
				t.Errorf("SignIn = %v, want ErrNotAllowed", err)
			}
		})
	}
}

func TestSignInUnknownProvider(t *testing.T) {
	svc, _ := newService(t, testConfig(dexProvider()), newMemStore())
	if _, err := svc.SignIn(context.Background(), "nope", devClaims()); !errors.Is(err, identity.ErrUnknownProvider) {
		t.Fatalf("SignIn = %v, want ErrUnknownProvider", err)
	}
}

func TestBootstrapAdminGetsAdminRole(t *testing.T) {
	st := newMemStore()
	cfg := testConfig(dexProvider())
	cfg.BootstrapAdmins = []string{dexIssuer + "|" + devClaims().Subject}
	svc, _ := newService(t, cfg, st)

	res, err := svc.SignIn(context.Background(), "dex", devClaims())
	if err != nil {
		t.Fatal(err)
	}
	got := st.roleNames(res.Principal.UserID)
	slices.Sort(got)
	if !slices.Equal(got, []string{"admin", "member"}) {
		t.Errorf("roles = %v, want [admin member]", got)
	}
	if !res.Principal.IsAdmin() {
		t.Error("bootstrap admin should be admin")
	}
	// Still admin on the next sign-in even if someone removed the role.
	_ = st.Bypass(context.Background(), func(tx identity.Tx) error {
		r, _ := tx.FindRoleByName(context.Background(), "member")
		return tx.SetUserRole(context.Background(), res.Principal.UserID, r.ID, nil)
	})
	res, err = svc.SignIn(context.Background(), "dex", devClaims())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Principal.IsAdmin() {
		t.Error("bootstrap admin must be re-granted admin on every sign-in")
	}
}

func TestDisabledUserCannotSignIn(t *testing.T) {
	st := newMemStore()
	svc, _ := newService(t, testConfig(dexProvider()), st)
	ctx := context.Background()
	res, err := svc.SignIn(ctx, "dex", devClaims())
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.DisableUser(ctx, "", res.Principal.UserID); err != nil {
		t.Fatalf("DisableUser: %v", err)
	}
	if _, err := svc.SignIn(ctx, "dex", devClaims()); !errors.Is(err, identity.ErrUserDisabled) {
		t.Fatalf("SignIn of a disabled user = %v, want ErrUserDisabled", err)
	}
}

func TestDisableRevokesSessionsAndRunsHooks(t *testing.T) {
	st := newMemStore()
	svc, _ := newService(t, testConfig(dexProvider()), st)
	ctx := context.Background()
	res, err := svc.SignIn(ctx, "dex", devClaims())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SignIn(ctx, "dex", devClaims()); err != nil {
		t.Fatal(err)
	}
	var hooked []string
	svc.OnDisable(func(_ context.Context, _ store.Tx, userID string) error {
		hooked = append(hooked, userID)
		return nil
	})
	if err := svc.DisableUser(ctx, "", res.Principal.UserID); err != nil {
		t.Fatalf("DisableUser: %v", err)
	}
	if st.liveSessions(res.Principal.UserID) != 0 {
		t.Errorf("live sessions after disable = %d, want 0", st.liveSessions(res.Principal.UserID))
	}
	if !slices.Equal(hooked, []string{res.Principal.UserID}) {
		t.Errorf("hooks called with %v, want [%s]", hooked, res.Principal.UserID)
	}
	users, err := svc.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 || users[0].Status != store.UserDisabled || !slices.Equal(users[0].Roles, []string{"member"}) {
		t.Errorf("ListUsers = %+v, want one disabled member", users)
	}
	if err := svc.EnableUser(ctx, "", res.Principal.UserID); err != nil {
		t.Fatalf("EnableUser: %v", err)
	}
	users, _ = svc.ListUsers(ctx)
	if users[0].Status != store.UserActive {
		t.Errorf("status after enable = %s", users[0].Status)
	}
	// A failing hook aborts the disable.
	svc.OnDisable(func(context.Context, store.Tx, string) error { return errors.New("boom") })
	if err := svc.DisableUser(ctx, "", res.Principal.UserID); err == nil {
		t.Error("DisableUser should surface hook errors")
	}
}

func TestSetUserRole(t *testing.T) {
	st := newMemStore()
	svc, _ := newService(t, testConfig(dexProvider()), st)
	ctx := context.Background()
	res, err := svc.SignIn(ctx, "dex", devClaims())
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.SetUserRole(ctx, res.Principal.UserID, res.Principal.UserID, "admin"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("SetUserRole with an unknown role = %v, want ErrNotFound (roles are not created by assignment)", err)
	}
	_ = st.Bypass(ctx, func(tx identity.Tx) error {
		_, err := tx.EnsureRole(ctx, "admin", "")
		return err
	})
	if err := svc.SetUserRole(ctx, res.Principal.UserID, res.Principal.UserID, "admin"); err != nil {
		t.Fatalf("SetUserRole: %v", err)
	}
	if got := st.roleNames(res.Principal.UserID); !slices.Equal(got, []string{"admin"}) {
		t.Errorf("roles = %v, want [admin]", got)
	}
	roles, err := svc.ListRoles(ctx)
	if err != nil || len(roles) != 2 {
		t.Errorf("ListRoles = %v, %v; want 2 roles", roles, err)
	}
}

func TestProvidersAreListedInConfigOrder(t *testing.T) {
	google := config.OIDCProvider{Name: "google", DisplayName: "Google", Issuer: "https://accounts.google.com", ClientID: "c", ClientSecret: "s", AllowedDomains: []string{"example.com"}}
	svc, _ := newService(t, testConfig(dexProvider(), google), newMemStore())
	got := svc.Providers()
	if len(got) != 2 || got[0].Name != "dex" || got[0].DisplayName != "Local dex" || got[1].Name != "google" {
		t.Errorf("Providers = %+v", got)
	}
}
