package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/federation/client"
	"github.com/huynle/mcp-gateway/internal/store"
)

const gatewayBase = "https://gw.example"

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func testKeys(t *testing.T) crypto.KeyProvider {
	t.Helper()
	p, err := crypto.NewStaticProvider("k1", map[string][]byte{"k1": bytes.Repeat([]byte{7}, crypto.DataKeySize)})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// fixture is a gateway auth service over the in-memory store and the fake
// network, with one Brain-shaped OAuth server owned by "owner" and
// published to alice and bob.
type fixture struct {
	t      *testing.T
	n      *fakeNet
	st     *memStore
	svc    *Service
	clock  *testClock
	logs   *logBuffer
	as     *testAS
	server *store.MCPServer
	mcpURL string
}

func newFixture(t *testing.T, configure func(*testAS)) *fixture {
	t.Helper()
	f := &fixture{t: t, n: newFakeNet(t), st: newMemStore(), clock: &testClock{now: time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)}, logs: &logBuffer{}}
	f.mcpURL, f.as = brainServer(t, f.n, "brain.example", configure)
	f.server = f.st.addServer(store.MCPServer{
		ID: "srv-brain", Name: "brain", URL: f.mcpURL, OwnerUserID: "owner",
		CredentialMode: store.MCPCredentialPerUser, AuthKind: store.MCPAuthOAuth,
		AuthConfig: []byte(`{}`), HeaderConfig: []byte(`{}`), Status: store.MCPServerActive,
	}, "alice", "bob")
	svc, err := New(Options{
		HTTPClient: f.n.client(), Store: f.st, Keys: testKeys(t), BaseURL: gatewayBase,
		Log: f.logs.logger(), Clock: f.clock.Now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	f.svc = svc
	return f
}

func userFunc(id string) UserFunc {
	return func(*http.Request) (string, bool) { return id, id != "" }
}

// startConnect runs GET /servers/{id}/connect as user and returns the
// redirect to the AS.
func (f *fixture) startConnect(user, serverID string) *httptest.ResponseRecorder {
	f.t.Helper()
	mux := http.NewServeMux()
	mux.Handle("GET /servers/{id}/connect", f.svc.StartConnect(userFunc(user)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequestWithContext(f.t.Context(), http.MethodGet, gatewayBase+"/servers/"+serverID+"/connect", nil))
	return rec
}

// callback runs GET /servers/oauth/callback?... as user.
func (f *fixture) callback(user string, back *url.URL) *httptest.ResponseRecorder {
	f.t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(f.t.Context(), http.MethodGet, gatewayBase+"/servers/oauth/callback?"+back.RawQuery, nil)
	f.svc.Callback(userFunc(user)).ServeHTTP(rec, req)
	return rec
}

// connect runs the whole browser dance for user and fails the test unless
// it succeeds.
func (f *fixture) connect(user string) {
	f.t.Helper()
	rec := f.startConnect(user, f.server.ID)
	if rec.Code != http.StatusFound {
		f.t.Fatalf("connect: status %d body %q", rec.Code, rec.Body.String())
	}
	back := f.as.authorize(f.t, rec.Header().Get("Location"))
	if got := back.Scheme + "://" + back.Host + back.Path; got != gatewayBase+"/servers/oauth/callback" {
		f.t.Fatalf("redirect_uri = %s", got)
	}
	cb := f.callback(user, back)
	if cb.Code >= 400 {
		f.t.Fatalf("callback: status %d body %q", cb.Code, cb.Body.String())
	}
}

// whoami calls the upstream tool through the federation client with az and
// returns the headers the upstream saw.
func (f *fixture) whoami(ctx context.Context, az client.Authorizer) (map[string]string, error) {
	f.t.Helper()
	c, err := client.New(client.Options{HTTPClient: f.n.client(), Authorizer: az, Timeout: 5 * time.Second})
	if err != nil {
		return nil, err
	}
	s, err := c.Connect(ctx, client.Endpoint{URL: f.server.URL})
	if err != nil {
		return nil, err
	}
	defer func() { _ = s.Close() }()
	res, err := s.CallTool(ctx, "whoami", map[string]any{})
	if err != nil {
		return nil, err
	}
	return structured(f.t, res), nil
}

func structured(t *testing.T, res *mcp.CallToolResult) map[string]string {
	t.Helper()
	out := map[string]string{}
	b, _ := json.Marshal(res.StructuredContent)
	_ = json.Unmarshal(b, &out)
	return out
}

func TestOAuthDCREndToEnd(t *testing.T) {
	f := newFixture(t, nil)
	rec := f.startConnect("alice", f.server.ID)
	if rec.Code != http.StatusFound {
		t.Fatalf("StartConnect status = %d, body %q", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	q := loc.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		t.Fatalf("no PKCE S256 in %v", q)
	}
	if q.Get("resource") != f.as.issuer {
		t.Fatalf("resource = %q, want %q", q.Get("resource"), f.as.issuer)
	}
	if q.Get("redirect_uri") != gatewayBase+"/servers/oauth/callback" || q.Get("state") == "" || q.Get("response_type") != "code" {
		t.Fatalf("authorize params = %v", q)
	}
	if f.as.registrations != 1 || !strings.HasPrefix(q.Get("client_id"), "dcr-") {
		t.Fatalf("DCR registrations = %d, client_id %q", f.as.registrations, q.Get("client_id"))
	}
	if !strings.Contains(q.Get("scope"), "mcp") {
		t.Fatalf("scope = %q", q.Get("scope"))
	}
	cl := f.st.clients[f.server.ID]
	if cl == nil || cl.Method != store.MCPOAuthClientDCR || cl.ClientID != q.Get("client_id") || cl.Issuer != f.as.issuer {
		t.Fatalf("stored client = %+v", cl)
	}

	back := f.as.authorize(t, loc.String())
	cb := f.callback("alice", back)
	if cb.Code >= 400 {
		t.Fatalf("Callback status = %d body %q", cb.Code, cb.Body.String())
	}
	if f.as.lastToken.Get("resource") != f.as.issuer || f.as.lastToken.Get("code_verifier") == "" {
		t.Fatalf("token request = %v", f.as.lastToken)
	}
	conn := f.st.conn(f.server.ID, "alice")
	if conn == nil || conn.Status != store.MCPConnectionActive {
		t.Fatalf("connection = %+v", conn)
	}
	if bytes.Contains(conn.Secret.Ciphertext, []byte("at-")) || bytes.Contains(conn.Secret.Ciphertext, []byte("rt-")) || len(conn.Secret.WrappedDataKey) == 0 {
		t.Fatal("token bundle is not encrypted")
	}
	if conn.ExpiresAt == nil || !conn.ExpiresAt.Equal(f.clock.Now().Add(time.Hour)) {
		t.Fatalf("ExpiresAt = %v", conn.ExpiresAt)
	}
	// Reusing a second registration is not needed for the next user.
	f.connect("bob")
	if f.as.registrations != 1 {
		t.Fatalf("registrations = %d after second user, want 1 (client reused)", f.as.registrations)
	}

	az, err := f.svc.ForUser(t.Context(), f.server, "alice")
	if err != nil {
		t.Fatalf("ForUser: %v", err)
	}
	seen, err := f.whoami(t.Context(), az)
	if err != nil {
		t.Fatalf("whoami: %v", err)
	}
	if !strings.HasPrefix(seen["Authorization"], "Bearer at-") {
		t.Fatalf("Authorization = %q", seen["Authorization"])
	}
}

func TestOAuthRefreshRotation(t *testing.T) {
	f := newFixture(t, nil)
	f.connect("alice")
	before := f.st.conn(f.server.ID, "alice")
	f.clock.Advance(2 * time.Hour) // access token expired
	az, err := f.svc.ForUser(t.Context(), f.server, "alice")
	if err != nil {
		t.Fatalf("ForUser: %v", err)
	}
	seen, err := f.whoami(t.Context(), az)
	if err != nil {
		t.Fatalf("whoami after expiry: %v", err)
	}
	if f.as.refreshCalls != 1 {
		t.Fatalf("refresh calls = %d, want 1", f.as.refreshCalls)
	}
	if f.as.lastToken.Get("resource") != f.as.issuer {
		t.Fatalf("refresh without resource: %v", f.as.lastToken)
	}
	after := f.st.conn(f.server.ID, "alice")
	if bytes.Equal(before.Secret.Ciphertext, after.Secret.Ciphertext) || after.LastRefreshedAt == nil {
		t.Fatal("refreshed bundle not stored")
	}
	tok, err := f.svc.openUserBundle(t.Context(), f.server, after)
	if err != nil || tok.OAuth == nil {
		t.Fatalf("open bundle: %v", err)
	}
	if "Bearer "+tok.OAuth.AccessToken != seen["Authorization"] {
		t.Fatalf("upstream saw %q, stored %q", seen["Authorization"], tok.OAuth.AccessToken)
	}
	if !f.as.refresh[tok.OAuth.RefreshToken] {
		t.Fatal("rotated refresh token not stored")
	}
	if f.st.locks == 0 {
		t.Fatal("refresh did not take the connection lock")
	}
}

func TestOAuthInvalidGrantNeedsReconnect(t *testing.T) {
	f := newFixture(t, nil)
	f.connect("alice")
	f.clock.Advance(2 * time.Hour)
	f.as.failRefresh = "invalid_grant"
	az, err := f.svc.ForUser(t.Context(), f.server, "alice")
	if err != nil {
		t.Fatalf("ForUser: %v", err)
	}
	_, err = f.whoami(t.Context(), az)
	var ce *client.Error
	if !errors.As(err, &ce) || ce.Class != client.ClassAuthRequired || !errors.Is(err, ErrNeedsReconnect) {
		t.Fatalf("whoami = %v, want auth_required wrapping ErrNeedsReconnect", err)
	}
	if c := f.st.conn(f.server.ID, "alice"); c.Status != store.MCPConnectionNeedsReconnect {
		t.Fatalf("status = %q, want needs_reconnect", c.Status)
	}
	if _, err := f.svc.ForUser(t.Context(), f.server, "alice"); !errors.Is(err, ErrNeedsReconnect) {
		t.Fatalf("ForUser after invalid_grant = %v, want ErrNeedsReconnect", err)
	}
	// Reconnecting revives the connection.
	f.as.failRefresh = ""
	f.connect("alice")
	if c := f.st.conn(f.server.ID, "alice"); c.Status != store.MCPConnectionActive {
		t.Fatalf("status after reconnect = %q", c.Status)
	}
}

func TestOAuthUpstream401RefreshesOnceThenNeedsReconnect(t *testing.T) {
	f := newFixture(t, nil)
	f.connect("alice")
	az, err := f.svc.ForUser(t.Context(), f.server, "alice")
	if err != nil {
		t.Fatalf("ForUser: %v", err)
	}
	f.as.revokeAll() // upstream now rejects the (unexpired) access token
	calls := 0
	err = Reauth(t.Context(), az, func() error {
		calls++
		_, err := f.whoami(t.Context(), az)
		return err
	})
	if err != nil || calls != 2 || f.as.refreshCalls != 1 {
		t.Fatalf("Reauth = %v after %d calls and %d refreshes, want success after 2 calls / 1 refresh", err, calls, f.as.refreshCalls)
	}
	// The upstream keeps answering 401 even with a fresh token.
	f.as.mu.Lock()
	f.as.denyAll = true
	f.as.mu.Unlock()
	az, _ = f.svc.ForUser(t.Context(), f.server, "alice")
	err = Reauth(t.Context(), az, func() error {
		_, err := f.whoami(t.Context(), az)
		return err
	})
	if !errors.Is(err, ErrNeedsReconnect) {
		t.Fatalf("Reauth with persistent 401 = %v, want ErrNeedsReconnect", err)
	}
	if c := f.st.conn(f.server.ID, "alice"); c.Status != store.MCPConnectionNeedsReconnect {
		t.Fatalf("status = %q, want needs_reconnect", c.Status)
	}
}

func TestOAuthStateBoundToUserAndOneUse(t *testing.T) {
	f := newFixture(t, nil)
	rec := f.startConnect("alice", f.server.ID)
	back := f.as.authorize(t, rec.Header().Get("Location"))
	if cb := f.callback("bob", back); cb.Code < 400 {
		t.Fatalf("bob used alice's state: %d", cb.Code)
	}
	if f.st.conn(f.server.ID, "bob") != nil {
		t.Fatal("bob got a connection from alice's flow")
	}
	if cb := f.callback("alice", back); cb.Code >= 400 {
		t.Fatalf("alice callback = %d %q", cb.Code, cb.Body.String())
	}
	if cb := f.callback("alice", back); cb.Code < 400 {
		t.Fatal("state replay accepted")
	}
	// Tampered state.
	q := back.Query()
	q.Set("state", q.Get("state")+"x")
	back.RawQuery = q.Encode()
	if cb := f.callback("alice", back); cb.Code < 400 {
		t.Fatal("tampered state accepted")
	}
	// Expired state.
	rec = f.startConnect("alice", f.server.ID)
	back = f.as.authorize(t, rec.Header().Get("Location"))
	f.clock.Advance(time.Hour)
	if cb := f.callback("alice", back); cb.Code < 400 {
		t.Fatal("expired state accepted")
	}
}

func TestOAuthHandlersRequireSignIn(t *testing.T) {
	f := newFixture(t, nil)
	if rec := f.startConnect("", f.server.ID); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous connect = %d", rec.Code)
	}
	// A user who cannot see the server gets 404.
	if rec := f.startConnect("mallory", f.server.ID); rec.Code != http.StatusNotFound {
		t.Fatalf("invisible server connect = %d", rec.Code)
	}
}
