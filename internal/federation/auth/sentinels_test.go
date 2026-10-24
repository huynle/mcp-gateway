package auth

import (
	"errors"
	"testing"

	"github.com/huynle/mcp-gateway/internal/store"
)

// The owner-only sub-sentinels wrap ErrNotConfigured (callers that test
// errors.Is(err, ErrNotConfigured) keep working) and keep its text, so
// nothing a user or a log saw before changes.
func TestNotConfiguredSubSentinels(t *testing.T) {
	for _, e := range []error{ErrSharedMissing, ErrModeInvalid, ErrNowRequiresAuth} {
		if !errors.Is(e, ErrNotConfigured) {
			t.Errorf("%v does not wrap ErrNotConfigured", e)
		}
		if e.Error() != ErrNotConfigured.Error() {
			t.Errorf("sub-sentinel text = %q, want %q", e.Error(), ErrNotConfigured.Error())
		}
	}
	if errors.Is(ErrSharedMissing, ErrModeInvalid) || errors.Is(ErrModeInvalid, ErrNowRequiresAuth) || errors.Is(ErrNowRequiresAuth, ErrSharedMissing) {
		t.Error("the sub-sentinels must be distinguishable")
	}
	if errors.Is(ErrUserHeaderMissing, ErrNotConfigured) {
		t.Error("ErrUserHeaderMissing is the user's to fix, not the owner's")
	}
}

func TestForUserOwnerOnlyErrorsAreSubSentinels(t *testing.T) {
	f := newFixture(t, nil)
	ctx := t.Context()
	srv := apiKeyServer(t, f, "k")
	_, err := f.svc.ForUser(ctx, srv, "alice")
	if !errors.Is(err, ErrSharedMissing) || !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("no shared credential = %v, want ErrSharedMissing", err)
	}
	if err.Error() != "auth: server authentication is not configured: no shared credential" {
		t.Errorf("text changed: %q", err.Error())
	}
	if err := f.svc.SetSharedCredential(ctx, Actor{UserID: "owner"}, srv.ID, Credential{APIKey: "k"}); err != nil {
		t.Fatal(err)
	}
	moved := *srv
	moved.URL += "/moved"
	if _, err := f.svc.ForUser(ctx, &moved, "alice"); !errors.Is(err, ErrSharedMissing) {
		t.Errorf("unreadable shared credential = %v, want ErrSharedMissing", err)
	}
	// A shared bundle without the key the kind needs.
	asBearer := *srv
	asBearer.AuthKind = store.MCPAuthBearer
	if _, err := f.svc.ForUser(ctx, &asBearer, "alice"); !errors.Is(err, ErrSharedMissing) {
		t.Errorf("incomplete shared credential = %v", err)
	}

	badKind := *srv
	badKind.AuthKind = "auto"
	if _, err := f.svc.ForUser(ctx, &badKind, "alice"); !errors.Is(err, ErrModeInvalid) {
		t.Errorf("unknown auth kind = %v, want ErrModeInvalid", err)
	}
	badMode := *srv
	badMode.CredentialMode = "team"
	if _, err := f.svc.ForUser(ctx, &badMode, "alice"); !errors.Is(err, ErrModeInvalid) {
		t.Errorf("unknown credential mode = %v, want ErrModeInvalid", err)
	}
	sharedOAuth := *srv
	sharedOAuth.AuthKind = store.MCPAuthOAuth
	if _, err := f.svc.ForUser(ctx, &sharedOAuth, "alice"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("shared OAuth = %v, want ErrUnsupported (unchanged)", err)
	}
}

// A no-auth server that starts answering 401 is the owner's to fix:
// ErrNowRequiresAuth (a sub-sentinel of ErrNotConfigured).
func TestNoAuthServerAnswering401IsNowRequiresAuth(t *testing.T) {
	f := newFixture(t, nil)
	srv := addStaticServer(t, f, store.MCPCredentialShared, store.MCPAuthNone, `{}`, `{}`, "only-with-key")
	az, err := f.svc.ForUser(t.Context(), srv, "alice")
	if err != nil {
		t.Fatal(err)
	}
	err = Reauth(t.Context(), az, func() error {
		_, err := f.whoamiAt(t.Context(), srv, az)
		return err
	})
	if !errors.Is(err, ErrNowRequiresAuth) || !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("401 from a no-auth server = %v, want ErrNowRequiresAuth", err)
	}
}

// Missing per-user header values: dropped silently by default (today's
// behaviour), refused with ErrUserHeaderMissing when the service requires
// them (GATEWAY_CREDENTIAL_LINKS_ENABLED).
func TestUserHeaderMissing(t *testing.T) {
	f := newFixture(t, nil)
	ctx := t.Context()
	perUser := addStaticServer(t, f, store.MCPCredentialPerUser, store.MCPAuthAPIKey, `{"api_key":{"header":"X-Api-Key"}}`,
		`{"per_user":["X-Brain-Project"]}`, "alice-key", "bob-key")
	shared := addStaticServer(t, f, store.MCPCredentialShared, store.MCPAuthAPIKey, `{"api_key":{"header":"X-Api-Key"}}`,
		`{"per_user":["X-Brain-Project"]}`, "shared-key")
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(f.svc.SetUserCredential(ctx, "alice", perUser.ID, Credential{APIKey: "alice-key"}))
	must(f.svc.SetSharedCredential(ctx, Actor{UserID: "owner"}, shared.ID, Credential{APIKey: "shared-key"}))

	strict := f.svc.UserHeadersRequired(true)
	if strict == f.svc {
		t.Fatal("UserHeadersRequired must return a view, not change the service")
	}
	if f.svc.UserHeadersRequired(false) != f.svc {
		t.Error("UserHeadersRequired(false) on a lenient service should return it")
	}
	// Lenient (default): the header is dropped, the call goes ahead.
	for _, srv := range []*store.MCPServer{perUser, shared} {
		if _, err := f.svc.ForUser(ctx, srv, "alice"); err != nil {
			t.Errorf("lenient %s: %v", srv.CredentialMode, err)
		}
		_, err := strict.ForUser(ctx, srv, "alice")
		if !errors.Is(err, ErrUserHeaderMissing) {
			t.Errorf("strict %s without the header = %v, want ErrUserHeaderMissing", srv.CredentialMode, err)
		}
	}
	// Shared: bob has no connection row at all.
	if _, err := strict.ForUser(ctx, shared, "bob"); !errors.Is(err, ErrUserHeaderMissing) {
		t.Errorf("strict shared, no row = %v, want ErrUserHeaderMissing", err)
	}
	// Per user: no connection is still ErrNotConnected (connect first).
	if _, err := strict.ForUser(ctx, perUser, "bob"); !errors.Is(err, ErrNotConnected) {
		t.Errorf("strict per_user, no row = %v, want ErrNotConnected", err)
	}
	// Once set, the strict service sends it.
	must(f.svc.SetUserCredential(ctx, "alice", perUser.ID, Credential{APIKey: "alice-key", Headers: map[string]string{"x-brain-project": "p1"}}))
	must(f.svc.SetUserCredential(ctx, "alice", shared.ID, Credential{Headers: map[string]string{"X-Brain-Project": "p2"}}))
	for srv, want := range map[*store.MCPServer]string{perUser: "p1", shared: "p2"} {
		az, err := strict.ForUser(ctx, srv, "alice")
		must(err)
		seen, err := f.whoamiAt(ctx, srv, az)
		must(err)
		if seen["X-Brain-Project"] != want {
			t.Errorf("%s header = %q, want %q", srv.CredentialMode, seen["X-Brain-Project"], want)
		}
	}

	// The option on New does the same.
	svc, err := New(Options{HTTPClient: f.n.client(), Store: f.st, Keys: f.svc.keys, BaseURL: gatewayBase, RequireUserHeaders: true})
	must(err)
	if _, err := svc.ForUser(ctx, shared, "bob"); !errors.Is(err, ErrUserHeaderMissing) {
		t.Errorf("Options.RequireUserHeaders: %v", err)
	}
	if svc.UserHeadersRequired(true) != svc {
		t.Error("UserHeadersRequired(true) on a strict service should return it")
	}
}
