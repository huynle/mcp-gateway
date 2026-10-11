package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/huynle/mcp-gateway/internal/federation/client"
	"github.com/huynle/mcp-gateway/internal/store"
)

var serverSeq atomic.Int64

// apiKeyServer adds an upstream that accepts any of keys in X-Api-Key (or
// ?key= / bearer / any header value, see accepts) and registers it as a
// shared api_key server owned by "owner", visible to alice and bob.
func apiKeyServer(t *testing.T, f *fixture, keys ...string) *store.MCPServer {
	t.Helper()
	return addStaticServer(t, f, store.MCPCredentialShared, store.MCPAuthAPIKey, `{"api_key":{"header":"X-Api-Key"}}`, `{}`, keys...)
}

func addStaticServer(t *testing.T, f *fixture, mode, kind, authCfg, headerCfg string, keys ...string) *store.MCPServer {
	t.Helper()
	n := serverSeq.Add(1)
	accepted := func(r *http.Request) bool {
		for _, k := range keys {
			if r.Header.Get("X-Api-Key") == k || r.URL.Query().Get("key") == k ||
				r.Header.Get("Authorization") == "Bearer "+k || r.Header.Get("X-Custom-Auth") == k {
				return true
			}
		}
		return false
	}
	mux := http.NewServeMux()
	mux.Handle("/mcp", gate(mcpHandler(), "", accepted))
	base := f.n.add(fmt.Sprintf("static%d.example", n), mux)
	return f.st.addServer(store.MCPServer{
		ID: fmt.Sprintf("srv-static-%d", n), Name: fmt.Sprintf("static%d", n), URL: base + "/mcp", OwnerUserID: "owner",
		CredentialMode: mode, AuthKind: kind, AuthConfig: []byte(authCfg), HeaderConfig: []byte(headerCfg), Status: store.MCPServerActive,
	}, "alice", "bob")
}

func (f *fixture) whoamiAt(ctx context.Context, server *store.MCPServer, az client.Authorizer) (map[string]string, error) {
	saved := f.server
	f.server = server
	defer func() { f.server = saved }()
	return f.whoami(ctx, az)
}

func TestSharedAPIKeyUsedForAllUsers(t *testing.T) {
	f := newFixture(t, nil)
	srv := apiKeyServer(t, f, "shared-key-1")
	if _, err := f.svc.ForUser(t.Context(), srv, "alice"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("ForUser before the shared key is set = %v, want ErrNotConfigured", err)
	}
	if err := f.svc.SetSharedCredential(t.Context(), Actor{UserID: "alice"}, srv.ID, Credential{APIKey: "x"}); err == nil {
		t.Fatal("a non-owner set the shared credential")
	}
	if err := f.svc.SetSharedCredential(t.Context(), Actor{UserID: "owner"}, srv.ID, Credential{APIKey: "shared-key-1"}); err != nil {
		t.Fatalf("SetSharedCredential: %v", err)
	}
	sec := f.st.shared[srv.ID]
	if sec == nil || strings.Contains(string(sec.Secret.Ciphertext), "shared-key-1") || len(sec.SecretKeys) == 0 {
		t.Fatalf("shared secret = %+v", sec)
	}
	for _, u := range []string{"alice", "bob"} {
		az, err := f.svc.ForUser(t.Context(), srv, u)
		if err != nil {
			t.Fatalf("ForUser(%s): %v", u, err)
		}
		seen, err := f.whoamiAt(t.Context(), srv, az)
		if err != nil || seen["X-Api-Key"] != "shared-key-1" {
			t.Fatalf("%s: whoami = %v, %v", u, seen, err)
		}
	}
	// Admins may set it too.
	if err := f.svc.SetSharedCredential(t.Context(), Actor{UserID: "root", Admin: true}, srv.ID, Credential{APIKey: "shared-key-2"}); err != nil {
		t.Fatalf("admin SetSharedCredential: %v", err)
	}
	// The upstream rejects the new key: shared credentials are not
	// marked per user; the error says the shared credential was rejected.
	az, _ := f.svc.ForUser(t.Context(), srv, "alice")
	err := Reauth(t.Context(), az, func() error { _, err := f.whoamiAt(t.Context(), srv, az); return err })
	if !errors.Is(err, ErrSharedCredentialRejected) {
		t.Fatalf("Reauth = %v, want ErrSharedCredentialRejected", err)
	}
}

func TestPerUserKeyIsolated(t *testing.T) {
	f := newFixture(t, nil)
	srv := addStaticServer(t, f, store.MCPCredentialPerUser, store.MCPAuthAPIKey, `{"api_key":{"header":"X-Api-Key"}}`, `{}`, "alice-key", "bob-key")
	if err := f.svc.SetUserCredential(t.Context(), "alice", srv.ID, Credential{APIKey: "alice-key"}); err != nil {
		t.Fatalf("SetUserCredential: %v", err)
	}
	if _, err := f.svc.ForUser(t.Context(), srv, "bob"); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("bob ForUser = %v, want ErrNotConnected", err)
	}
	if err := f.svc.SetUserCredential(t.Context(), "bob", srv.ID, Credential{APIKey: "bob-key"}); err != nil {
		t.Fatal(err)
	}
	for u, want := range map[string]string{"alice": "alice-key", "bob": "bob-key"} {
		az, err := f.svc.ForUser(t.Context(), srv, u)
		if err != nil {
			t.Fatal(err)
		}
		seen, err := f.whoamiAt(t.Context(), srv, az)
		if err != nil || seen["X-Api-Key"] != want {
			t.Fatalf("%s sees %v (%v), want %s", u, seen, err, want)
		}
	}
	// A user who cannot see the server cannot store a key for it.
	if err := f.svc.SetUserCredential(t.Context(), "mallory", srv.ID, Credential{APIKey: "m"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("mallory SetUserCredential = %v, want ErrNotFound", err)
	}
	// Copying alice's ciphertext onto bob's row does not give bob alice's
	// key: the envelope is bound to the user.
	f.st.mu.Lock()
	a, b := f.st.conns[[2]string{srv.ID, "alice"}], f.st.conns[[2]string{srv.ID, "bob"}]
	b.Secret = a.Secret
	f.st.mu.Unlock()
	if _, err := f.svc.ForUser(t.Context(), srv, "bob"); !errors.Is(err, ErrNeedsReconnect) {
		t.Fatalf("ForUser with a moved ciphertext = %v, want ErrNeedsReconnect", err)
	}
	// A rejected per-user key marks the connection needs_reconnect.
	if err := f.svc.SetUserCredential(t.Context(), "alice", srv.ID, Credential{APIKey: "wrong"}); err != nil {
		t.Fatal(err)
	}
	az, _ := f.svc.ForUser(t.Context(), srv, "alice")
	err := Reauth(t.Context(), az, func() error { _, err := f.whoamiAt(t.Context(), srv, az); return err })
	if !errors.Is(err, ErrNeedsReconnect) || f.st.conn(srv.ID, "alice").Status != store.MCPConnectionNeedsReconnect {
		t.Fatalf("Reauth = %v, status %q", err, f.st.conn(srv.ID, "alice").Status)
	}
	// Setting the key again revives it.
	if err := f.svc.SetUserCredential(t.Context(), "alice", srv.ID, Credential{APIKey: "alice-key"}); err != nil {
		t.Fatal(err)
	}
	if c := f.st.conn(srv.ID, "alice"); c.Status != store.MCPConnectionActive {
		t.Fatalf("status after new key = %q", c.Status)
	}
	// Disconnect removes it.
	if err := f.svc.Disconnect(t.Context(), "alice", srv.ID); err != nil || f.st.conn(srv.ID, "alice") != nil {
		t.Fatalf("Disconnect = %v", err)
	}
}

func TestAPIKeyQueryBearerAndHeaders(t *testing.T) {
	f := newFixture(t, nil)
	q := addStaticServer(t, f, store.MCPCredentialShared, store.MCPAuthAPIKey, `{"api_key":{"query":"key"}}`, `{}`, "q-key")
	b := addStaticServer(t, f, store.MCPCredentialShared, store.MCPAuthBearer, `{}`, `{}`, "b-token")
	h := addStaticServer(t, f, store.MCPCredentialShared, store.MCPAuthHeaders, `{}`, `{"per_user":["X-Brain-Project"]}`, "h-value")
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(f.svc.SetSharedCredential(t.Context(), Actor{UserID: "owner"}, q.ID, Credential{APIKey: "q-key"}))
	must(f.svc.SetSharedCredential(t.Context(), Actor{UserID: "owner"}, b.ID, Credential{Bearer: "b-token"}))
	must(f.svc.SetSharedCredential(t.Context(), Actor{UserID: "owner"}, h.ID, Credential{Headers: map[string]string{"x-custom-auth": "h-value"}}))
	// alice supplies her own value for the per-user header.
	must(f.svc.SetUserCredential(t.Context(), "alice", h.ID, Credential{Headers: map[string]string{"X-Brain-Project": "alice-proj"}}))
	// A per-user value for a header the owner did not declare is refused.
	if err := f.svc.SetUserCredential(t.Context(), "alice", h.ID, Credential{Headers: map[string]string{"X-Other": "v"}}); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("undeclared per-user header = %v", err)
	}

	for _, srv := range []*store.MCPServer{q, b, h} {
		az, err := f.svc.ForUser(t.Context(), srv, "alice")
		must(err)
		seen, err := f.whoamiAt(t.Context(), srv, az)
		if err != nil {
			t.Fatalf("%s: %v", srv.AuthKind, err)
		}
		switch srv {
		case b:
			if seen["Authorization"] != "Bearer b-token" {
				t.Fatalf("bearer: %v", seen)
			}
		case h:
			if seen["X-Brain-Project"] != "alice-proj" {
				t.Fatalf("per-user header: %v", seen)
			}
		}
	}
	// bob has no per-user value: the shared header still works.
	az, _ := f.svc.ForUser(t.Context(), h, "bob")
	if seen, err := f.whoamiAt(t.Context(), h, az); err != nil || seen["X-Brain-Project"] != "" {
		t.Fatalf("bob: %v %v", seen, err)
	}
}

func TestCredentialValidation(t *testing.T) {
	f := newFixture(t, nil)
	srv := apiKeyServer(t, f)
	bad := []Credential{
		{},                 // nothing for api_key
		{Bearer: "x"},      // wrong kind
		{APIKey: "a\r\nb"}, // control characters
		{APIKey: "k", Headers: map[string]string{"Host": "x"}},
		{APIKey: "k", Headers: map[string]string{"Mcp-Session-Id": "x"}},
		{APIKey: "k", Headers: map[string]string{"bad header": "x"}},
	}
	for i, c := range bad {
		if err := f.svc.SetSharedCredential(t.Context(), Actor{UserID: "owner"}, srv.ID, c); !errors.Is(err, ErrInvalidCredential) {
			t.Fatalf("case %d: %v, want ErrInvalidCredential", i, err)
		}
	}
	// OAuth servers take no shared credential and no per-user key.
	if err := f.svc.SetSharedCredential(t.Context(), Actor{UserID: "owner"}, f.server.ID, Credential{Bearer: "x"}); err == nil {
		t.Fatal("shared credential accepted for an OAuth server")
	}
}

// TestStoredCredentialsBoundToServerURL: an owner may edit a server's URL
// (even once published). Stored credentials (another user's own key, the
// shared credential, a static client secret) must not follow it to the new
// address: they are sealed to the URL and no longer open (security task
// rvrfpzzj, test/security TestSecurityFedURLSwapNeverCarriesOtherUsersCredentials).
func TestStoredCredentialsBoundToServerURL(t *testing.T) {
	f := newFixture(t, nil)
	ctx := t.Context()
	shared := apiKeyServer(t, f, "shared-key-url")
	if err := f.svc.SetSharedCredential(ctx, Actor{UserID: "admin", Admin: true}, shared.ID, Credential{APIKey: "shared-key-url"}); err != nil {
		t.Fatal(err)
	}
	perUser := addStaticServer(t, f, store.MCPCredentialPerUser, store.MCPAuthAPIKey, `{"api_key":{"header":"X-Api-Key"}}`, `{}`, "bob-key-url")
	if err := f.svc.SetUserCredential(ctx, "bob", perUser.ID, Credential{APIKey: "bob-key-url"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ForUser(ctx, shared, "bob"); err != nil {
		t.Fatalf("shared before the move: %v", err)
	}
	if _, err := f.svc.ForUser(ctx, perUser, "bob"); err != nil {
		t.Fatalf("per-user before the move: %v", err)
	}
	movedShared, movedPerUser := *shared, *perUser
	movedShared.URL, movedPerUser.URL = "https://owner-capture.example/mcp", "https://owner-capture.example/mcp"
	if _, err := f.svc.ForUser(ctx, &movedShared, "bob"); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("shared credential after a URL change: %v, want ErrNotConfigured", err)
	}
	if _, err := f.svc.ForUser(ctx, &movedPerUser, "bob"); !errors.Is(err, ErrNeedsReconnect) {
		t.Errorf("per-user credential after a URL change: %v, want ErrNeedsReconnect", err)
	}

	if err := f.svc.SetStaticClient(ctx, Actor{UserID: "admin", Admin: true}, f.server.ID, "static-id", "static-secret-url", ""); err != nil {
		t.Fatal(err)
	}
	row, err := f.svc.loadClient(ctx, f.server.ID)
	if err != nil || row == nil {
		t.Fatalf("loadClient: %v %v", row, err)
	}
	if got, err := f.svc.clientSecret(ctx, f.server, row); err != nil || got != "static-secret-url" {
		t.Fatalf("static secret at the original URL: %q %v", got, err)
	}
	moved := *f.server
	moved.URL = "https://owner-capture.example/mcp"
	if got, err := f.svc.clientSecret(ctx, &moved, row); err == nil {
		t.Errorf("static client secret opened for a changed URL: %q", got)
	}
}
