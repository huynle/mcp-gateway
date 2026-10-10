package tokens_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/tokens"
	"github.com/huynle/mcp-gateway/internal/tokens/tokenstest"
)

const (
	alice = "00000000-0000-4000-8000-00000000000a"
	bob   = "00000000-0000-4000-8000-00000000000b"
)

// fixture is a service over the in-memory store with a fixed clock, a
// metrics registry and a log buffer.
type fixture struct {
	st      *tokenstest.MemStore
	svc     *tokens.Service
	metrics *observability.Metrics
	logs    *bytes.Buffer
	now     time.Time
	audit   *recordingRecorder
}

type recordingRecorder struct{ events []audit.Event }

func (r *recordingRecorder) Record(_ context.Context, ev audit.Event) error {
	r.events = append(r.events, ev)
	return nil
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{
		st:      tokenstest.NewMemStore(),
		metrics: observability.NewMetrics(),
		logs:    &bytes.Buffer{},
		now:     time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC),
		audit:   &recordingRecorder{},
	}
	// The production logger is the redacting one; the tests still assert
	// that the service never hands it the secret in the first place by
	// using a plain handler here.
	log := slog.New(slog.NewTextHandler(f.logs, nil))
	svc, err := tokens.New(tokens.Config{SignInMaxAge: 30 * 24 * time.Hour}, f.st, f.metrics, f.audit, log)
	if err != nil {
		t.Fatal(err)
	}
	svc.SetClock(func() time.Time { return f.now })
	f.svc = svc
	signedIn := f.now.Add(-time.Hour)
	f.st.AddUser(alice, &signedIn)
	f.st.AddUser(bob, &signedIn)
	return f
}

func (f *fixture) create(t *testing.T, userID string, req tokens.CreateRequest) *tokens.Created {
	t.Helper()
	c, err := f.svc.Create(t.Context(), userID, req)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return c
}

// failures returns the auth_failures_total counter for reason.
func (f *fixture) failures(t *testing.T, reason string) float64 {
	t.Helper()
	families, err := f.metrics.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, fam := range families {
		if fam.GetName() != "auth_failures_total" {
			continue
		}
		for _, m := range fam.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "reason" && l.GetValue() == reason {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

func TestNewRequiresPositiveSignInMaxAge(t *testing.T) {
	if _, err := tokens.New(tokens.Config{}, tokenstest.NewMemStore(), nil, nil, nil); err == nil {
		t.Error("zero SignInMaxAge accepted")
	}
}

func TestCreateReturnsTheTokenOnceAndStoresOnlyTheHash(t *testing.T) {
	f := newFixture(t)
	c := f.create(t, alice, tokens.CreateRequest{Name: "laptop"})
	publicID, secret, err := tokens.Parse(c.Raw)
	if err != nil {
		t.Fatalf("created token does not parse: %v", err)
	}
	if c.Token.PublicID != publicID || c.Token.Name != "laptop" || c.Token.UserID != alice {
		t.Errorf("created info = %+v", c.Token)
	}
	if c.Token.Prefix() != "mgw_"+publicID {
		t.Errorf("prefix = %q", c.Token.Prefix())
	}
	if want := f.now.Add(30 * 24 * time.Hour); !c.Token.ExpiresAt.Equal(want) {
		t.Errorf("default expiry = %v, want %v (30 days)", c.Token.ExpiresAt, want)
	}
	row := f.st.Token(c.Token.ID)
	if !bytes.Equal(row.TokenHash, tokens.HashSecret(secret)) {
		t.Error("stored hash != sha256(secret)")
	}
	if strings.Contains(string(row.TokenHash), secret) || row.Scope != nil || row.ReadOnly {
		t.Errorf("row = %+v", row)
	}
	// The list never carries the raw token or the hash.
	list, err := f.svc.List(t.Context(), alice)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != c.Token.ID || list[0].PublicID != publicID {
		t.Fatalf("list = %+v", list)
	}
	if len(f.audit.events) != 1 || f.audit.events[0].UserID != alice || f.audit.events[0].TokenID != c.Token.ID || f.audit.events[0].ResourceIdentity["action"] != "token_created" {
		t.Errorf("audit events = %+v", f.audit.events)
	}
}

func TestCreateValidatesNameExpiryAndScope(t *testing.T) {
	f := newFixture(t)
	bad := []tokens.CreateRequest{
		{Name: ""},
		{Name: "   "},
		{Name: strings.Repeat("n", tokens.MaxNameLen+1)},
		{Name: "x", ExpiryDays: 91},
		{Name: "x", ExpiryDays: -1},
		{Name: "x", AllowList: "git/hub"},
	}
	for _, req := range bad {
		if _, err := f.svc.Create(t.Context(), alice, req); !errors.Is(err, tokens.ErrInvalid) {
			t.Errorf("Create(%+v) = %v, want ErrInvalid", req, err)
		}
	}
	c := f.create(t, alice, tokens.CreateRequest{Name: " CI runner ", ExpiryDays: 90, ReadOnly: true, AllowList: "github, slack.post_message"})
	if c.Token.Name != "CI runner" {
		t.Errorf("name = %q, want trimmed", c.Token.Name)
	}
	if want := f.now.Add(90 * 24 * time.Hour); !c.Token.ExpiresAt.Equal(want) {
		t.Errorf("expiry = %v, want %v", c.Token.ExpiresAt, want)
	}
	if got := c.Token.Scope.String(); got != "github, slack.post_message, read-only" {
		t.Errorf("scope = %q", got)
	}
	row := f.st.Token(c.Token.ID)
	if !row.ReadOnly || string(row.Scope) != `{"apps":["github"],"tools":["slack.post_message"]}` {
		t.Errorf("stored row = read_only %v scope %s", row.ReadOnly, row.Scope)
	}
}

func TestAuthenticateSuccessReturnsPrincipalWithScope(t *testing.T) {
	f := newFixture(t)
	c := f.create(t, alice, tokens.CreateRequest{Name: "laptop", ReadOnly: true, AllowList: "github"})
	p, err := f.svc.Authenticate(t.Context(), c.Raw)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if p.UserID != alice || p.TokenID != c.Token.ID || p.PublicID != c.Token.PublicID {
		t.Errorf("principal = %+v", p)
	}
	if !p.Scope.ReadOnly || !p.Scope.Allows("github.create_issue") || p.Scope.Allows("slack.post_message") {
		t.Errorf("scope = %+v", p.Scope)
	}
	// An unrestricted token allows everything and is not read-only.
	c2 := f.create(t, alice, tokens.CreateRequest{Name: "desktop"})
	p2, err := f.svc.Authenticate(t.Context(), c2.Raw)
	if err != nil {
		t.Fatal(err)
	}
	if p2.Scope.ReadOnly || !p2.Scope.Allows("anything.goes") {
		t.Errorf("unrestricted scope = %+v", p2.Scope)
	}
	// Success touches last_used_at.
	if row := f.st.Token(c.Token.ID); row.LastUsedAt == nil || !row.LastUsedAt.Equal(f.now) {
		t.Errorf("last_used_at = %v, want %v", row.LastUsedAt, f.now)
	}
	if strings.Contains(f.logs.String(), "tokens.auth_failed") {
		t.Errorf("success logged a failure: %s", f.logs.String())
	}
}

func TestAuthenticateFailureReasons(t *testing.T) {
	f := newFixture(t)
	good := f.create(t, alice, tokens.CreateRequest{Name: "laptop"})
	revoked := f.create(t, alice, tokens.CreateRequest{Name: "old"})
	if err := f.svc.Revoke(t.Context(), alice, revoked.Token.ID); err != nil {
		t.Fatal(err)
	}
	expired := f.create(t, alice, tokens.CreateRequest{Name: "short", ExpiryDays: 1})
	bobs := f.create(t, bob, tokens.CreateRequest{Name: "bob"})
	publicID, _, _ := tokens.Parse(good.Raw)
	wrongSecret := tokens.Prefix + publicID + "_" + strings.Repeat("Z", tokens.SecretLen)
	unknownID := tokens.Prefix + "zzzzzzzz" + good.Raw[len(tokens.Prefix)+tokens.PublicIDLen:]

	cases := []struct {
		name     string
		bearer   string
		before   func()
		reason   tokens.Reason
		publicID string
	}{
		{"malformed", "not-a-token", nil, tokens.ReasonMalformed, ""},
		{"empty", "", nil, tokens.ReasonMalformed, ""},
		{"unknown id", unknownID, nil, tokens.ReasonUnknown, "zzzzzzzz"},
		{"wrong secret", wrongSecret, nil, tokens.ReasonUnknown, publicID},
		{"revoked", revoked.Raw, nil, tokens.ReasonRevoked, revoked.Token.PublicID},
		{"expired", expired.Raw, func() { f.now = f.now.Add(24*time.Hour + time.Second) }, tokens.ReasonExpired, expired.Token.PublicID},
		{"user disabled", bobs.Raw, func() { f.st.SetUser(bob, store.UserDisabled, &f.now) }, tokens.ReasonUserDisabled, bobs.Token.PublicID},
		{"sign-in stale", good.Raw, func() {
			stale := f.now.Add(-30*24*time.Hour - time.Second)
			f.st.SetUser(alice, store.UserActive, &stale)
		}, tokens.ReasonSignInStale, good.Token.PublicID},
		{"never signed in", good.Raw, func() { f.st.SetUser(alice, store.UserActive, nil) }, tokens.ReasonSignInStale, good.Token.PublicID},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.before != nil {
				c.before()
			}
			before := f.failures(t, string(c.reason))
			f.logs.Reset()
			p, err := f.svc.Authenticate(t.Context(), c.bearer)
			if p != nil {
				t.Fatalf("principal returned: %+v", p)
			}
			var authErr *tokens.Error
			if !errors.As(err, &authErr) {
				t.Fatalf("error %v (%T) is not *tokens.Error", err, err)
			}
			if authErr.Reason != c.reason || authErr.PublicID != c.publicID {
				t.Errorf("error = %+v, want reason %s public id %q", authErr, c.reason, c.publicID)
			}
			if got := f.failures(t, string(c.reason)); got != before+1 {
				t.Errorf("auth_failures_total{reason=%s} = %v, want %v", c.reason, got, before+1)
			}
			logs := f.logs.String()
			if !strings.Contains(logs, "tokens.auth_failed") || !strings.Contains(logs, "reason="+string(c.reason)) {
				t.Errorf("log lacks event/reason: %s", logs)
			}
			if c.publicID != "" && !strings.Contains(logs, "public_id="+c.publicID) {
				t.Errorf("log lacks public id: %s", logs)
			}
		})
	}
	if msg := (&tokens.Error{Reason: tokens.ReasonSignInStale}).Error(); !strings.Contains(msg, "sign in to the portal to reactivate your tokens") {
		t.Errorf("stale message = %q", msg)
	}
}

func TestAuthenticateStaleBoundary(t *testing.T) {
	f := newFixture(t)
	c := f.create(t, alice, tokens.CreateRequest{Name: "laptop"})
	exactly := f.now.Add(-30 * 24 * time.Hour)
	f.st.SetUser(alice, store.UserActive, &exactly)
	if _, err := f.svc.Authenticate(t.Context(), c.Raw); err != nil {
		t.Errorf("sign-in exactly max age old rejected: %v", err)
	}
	// Expiry boundary: a token is valid until, not at, expires_at.
	f.now = c.Token.ExpiresAt.Add(-time.Nanosecond)
	fresh := f.now
	f.st.SetUser(alice, store.UserActive, &fresh)
	if _, err := f.svc.Authenticate(t.Context(), c.Raw); err != nil {
		t.Errorf("token a nanosecond before expiry rejected: %v", err)
	}
	f.now = c.Token.ExpiresAt
	var authErr *tokens.Error
	if _, err := f.svc.Authenticate(t.Context(), c.Raw); !errors.As(err, &authErr) || authErr.Reason != tokens.ReasonExpired {
		t.Errorf("token at expiry = %v, want expired", err)
	}
}

func TestRevokeIsImmediateAndScopedToOwner(t *testing.T) {
	f := newFixture(t)
	c := f.create(t, alice, tokens.CreateRequest{Name: "laptop"})
	if err := f.svc.Revoke(t.Context(), bob, c.Token.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("bob revoking alice's token = %v, want ErrNotFound", err)
	}
	if _, err := f.svc.Authenticate(t.Context(), c.Raw); err != nil {
		t.Fatalf("token broken by a foreign revoke: %v", err)
	}
	if err := f.svc.Revoke(t.Context(), alice, c.Token.ID); err != nil {
		t.Fatal(err)
	}
	var authErr *tokens.Error
	if _, err := f.svc.Authenticate(t.Context(), c.Raw); !errors.As(err, &authErr) || authErr.Reason != tokens.ReasonRevoked {
		t.Errorf("after revoke = %v, want revoked", err)
	}
	f.now = f.now.Add(time.Minute)
	if err := f.svc.Revoke(t.Context(), alice, c.Token.ID); err != nil {
		t.Errorf("second revoke = %v, want nil", err)
	}
	list, err := f.svc.List(t.Context(), alice)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].RevokedAt == nil {
		t.Errorf("list after revoke = %+v", list)
	}
	if n := len(f.audit.events); n != 2 || f.audit.events[1].ResourceIdentity["action"] != "token_revoked" {
		t.Errorf("audit events = %+v", f.audit.events)
	}
}

func TestLastUsedIsThrottledAndBestEffort(t *testing.T) {
	f := newFixture(t)
	c := f.create(t, alice, tokens.CreateRequest{Name: "laptop"})
	auth := func() {
		t.Helper()
		if _, err := f.svc.Authenticate(t.Context(), c.Raw); err != nil {
			t.Fatal(err)
		}
	}
	first := f.now
	auth()
	f.now = first.Add(30 * time.Second)
	auth()
	if row := f.st.Token(c.Token.ID); !row.LastUsedAt.Equal(first) {
		t.Errorf("last_used_at touched within a minute: %v", row.LastUsedAt)
	}
	f.now = first.Add(time.Minute)
	auth()
	if row := f.st.Token(c.Token.ID); !row.LastUsedAt.Equal(f.now) {
		t.Errorf("last_used_at not touched after a minute: %v", row.LastUsedAt)
	}
	// A failing touch never fails authentication.
	f.st.TouchErr = errors.New("database gone")
	f.now = f.now.Add(2 * time.Minute)
	auth()
	if !strings.Contains(f.logs.String(), "tokens.touch_failed") {
		t.Errorf("touch failure not logged: %s", f.logs.String())
	}
}

func TestDisableHookRevokesEveryToken(t *testing.T) {
	f := newFixture(t)
	a1 := f.create(t, alice, tokens.CreateRequest{Name: "one"})
	a2 := f.create(t, alice, tokens.CreateRequest{Name: "two"})
	b1 := f.create(t, bob, tokens.CreateRequest{Name: "bob"})
	// tx is nil for non-PostgreSQL stores; the hook falls back to Bypass.
	if err := f.svc.DisableHook()(t.Context(), nil, alice); err != nil {
		t.Fatal(err)
	}
	for _, c := range []*tokens.Created{a1, a2} {
		var authErr *tokens.Error
		if _, err := f.svc.Authenticate(t.Context(), c.Raw); !errors.As(err, &authErr) || authErr.Reason != tokens.ReasonRevoked {
			t.Errorf("%s after disable = %v, want revoked", c.Token.Name, err)
		}
	}
	if _, err := f.svc.Authenticate(t.Context(), b1.Raw); err != nil {
		t.Errorf("bob's token revoked by alice's disable: %v", err)
	}
}

func TestSecretNeverReachesTheLog(t *testing.T) {
	f := newFixture(t)
	c := f.create(t, alice, tokens.CreateRequest{Name: "laptop"})
	_, secret, _ := tokens.Parse(c.Raw)
	// Exercise every path: success, revoke, each failure, hook, touch failure.
	_, _ = f.svc.Authenticate(t.Context(), c.Raw)
	_, _ = f.svc.Authenticate(t.Context(), tokens.Prefix+c.Token.PublicID+"_"+strings.Repeat("Z", tokens.SecretLen))
	_, _ = f.svc.Authenticate(t.Context(), "garbage "+c.Raw)
	f.st.TouchErr = errors.New("db down while touching " + c.Raw)
	f.now = f.now.Add(2 * time.Minute)
	_, _ = f.svc.Authenticate(t.Context(), c.Raw)
	_ = f.svc.Revoke(t.Context(), alice, c.Token.ID)
	_, _ = f.svc.Authenticate(t.Context(), c.Raw)
	_ = f.svc.DisableHook()(t.Context(), nil, alice)
	_, _ = f.svc.Authenticate(t.Context(), c.Raw)

	logs := f.logs.String()
	if logs == "" {
		t.Fatal("nothing was logged")
	}
	if strings.Contains(logs, secret) || strings.Contains(logs, c.Raw) {
		t.Fatalf("secret reached the log:\n%s", logs)
	}
	if !strings.Contains(logs, c.Token.PublicID) {
		t.Errorf("public id missing from the log:\n%s", logs)
	}
}
