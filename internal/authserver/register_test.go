package authserver_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/authserver"
	"github.com/huynle/mcp-gateway/internal/authserver/authservertest"
	"github.com/huynle/mcp-gateway/internal/store"
)

// svcFixture is the whole authorization server over the in-memory store
// with a settable clock; the handlers are exercised through ServeHTTP.
type svcFixture struct {
	st    *authservertest.MemStore
	svc   *authserver.Service
	now   time.Time
	cfg   authserver.Config
	clock func() time.Time
	ip    string
}

func newService(t *testing.T, mutate ...func(*authserver.Config)) *svcFixture {
	t.Helper()
	f := &svcFixture{st: authservertest.NewMemStore(), now: t0, cfg: testConfig(), ip: "203.0.113.5"}
	for _, m := range mutate {
		m(&f.cfg)
	}
	f.clock = func() time.Time { return f.now }
	f.st.Now = f.clock
	svc, err := authserver.New(f.cfg, f.st, mustProviderWith(t, 7), authserver.Options{
		Log:      slog.New(slog.DiscardHandler),
		ClientIP: func(*http.Request) string { return f.ip },
	})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetClock(f.clock)
	f.svc = svc
	signedIn := t0.Add(-time.Hour)
	f.st.AddUser(alice, &signedIn)
	f.st.AddUser(bob, &signedIn)
	return f
}

// register posts a registration document and decodes the answer.
func (f *svcFixture) register(t *testing.T, doc map[string]any) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(doc)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, authserver.RegisterPath, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	f.svc.ServeRegister(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestRegisterPublicClient(t *testing.T) {
	f := newService(t)
	code, out := f.register(t, map[string]any{
		"client_name":   "Claude Code",
		"redirect_uris": []string{"http://localhost:45678/callback", "https://app.example.com/oauth/cb"},
		"grant_types":   []string{"authorization_code", "refresh_token"},
	})
	if code != http.StatusCreated {
		t.Fatalf("status %d: %v", code, out)
	}
	id, _ := out["client_id"].(string)
	if id == "" || out["client_secret"] != nil || out["token_endpoint_auth_method"] != "none" || out["client_name"] != "Claude Code" {
		t.Errorf("response = %v", out)
	}
	if uris, _ := out["redirect_uris"].([]any); len(uris) != 2 {
		t.Errorf("redirect_uris = %v", out["redirect_uris"])
	}
	if _, ok := out["client_id_issued_at"].(float64); !ok {
		t.Errorf("client_id_issued_at missing: %v", out)
	}
	clients := f.st.Clients()
	if len(clients) != 1 || clients[0].ClientID != id || clients[0].ClientSecretHash != nil || clients[0].LastUsedAt != nil {
		t.Errorf("stored = %+v", clients)
	}
}

func TestRegisterConfidentialClientGetsSecretOnce(t *testing.T) {
	f := newService(t)
	code, out := f.register(t, map[string]any{
		"redirect_uris":              []string{"https://app.example.com/cb"},
		"token_endpoint_auth_method": "client_secret_basic",
	})
	if code != http.StatusCreated {
		t.Fatalf("status %d: %v", code, out)
	}
	secret, _ := out["client_secret"].(string)
	if len(secret) < 32 || out["client_secret_expires_at"] != float64(0) || out["token_endpoint_auth_method"] != "client_secret_basic" {
		t.Errorf("response = %v", out)
	}
	if c := f.st.Clients()[0]; len(c.ClientSecretHash) == 0 || bytes.Contains(c.ClientSecretHash, []byte(secret)) {
		t.Errorf("secret not hashed: %+v", c)
	}
	if out["client_name"] == "" {
		t.Errorf("a nameless client gets a default name: %v", out)
	}
}

func TestRegisterRejectsBadMetadata(t *testing.T) {
	// Invalid attempts spend the per-IP budget too (anti-probing), so
	// give this test room for all of its cases.
	f := newService(t, func(c *authserver.Config) { c.RegisterPerMin = 100 })
	cases := []struct {
		name string
		doc  map[string]any
		want string
	}{
		{"no redirect uris", map[string]any{"client_name": "x"}, "invalid_redirect_uri"},
		{"empty list", map[string]any{"redirect_uris": []string{}}, "invalid_redirect_uri"},
		{"plain http", map[string]any{"redirect_uris": []string{"http://app.example.com/cb"}}, "invalid_redirect_uri"},
		{"loopback lookalike", map[string]any{"redirect_uris": []string{"http://localhost.evil.test/cb"}}, "invalid_redirect_uri"},
		{"fragment", map[string]any{"redirect_uris": []string{"https://app.example.com/cb#x"}}, "invalid_redirect_uri"},
		{"javascript", map[string]any{"redirect_uris": []string{"javascript:alert(1)"}}, "invalid_redirect_uri"},
		{"custom scheme", map[string]any{"redirect_uris": []string{"myapp://callback"}}, "invalid_redirect_uri"},
		{"relative", map[string]any{"redirect_uris": []string{"/cb"}}, "invalid_redirect_uri"},
		{"too many", map[string]any{"redirect_uris": many("https://app.example.com/cb", 11)}, "invalid_redirect_uri"},
		{"auth method", map[string]any{"redirect_uris": []string{"https://a.example.com/cb"}, "token_endpoint_auth_method": "private_key_jwt"}, "invalid_client_metadata"},
		{"grant type", map[string]any{"redirect_uris": []string{"https://a.example.com/cb"}, "grant_types": []string{"implicit"}}, "invalid_client_metadata"},
		{"response type", map[string]any{"redirect_uris": []string{"https://a.example.com/cb"}, "response_types": []string{"token"}}, "invalid_client_metadata"},
		{"scope", map[string]any{"redirect_uris": []string{"https://a.example.com/cb"}, "scope": "mcp admin"}, "invalid_client_metadata"},
		{"long name", map[string]any{"redirect_uris": []string{"https://a.example.com/cb"}, "client_name": strings.Repeat("n", 101)}, "invalid_client_metadata"},
		{"http client_uri", map[string]any{"redirect_uris": []string{"https://a.example.com/cb"}, "client_uri": "http://x.example.com"}, "invalid_client_metadata"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out := f.register(t, c.doc)
			if code != http.StatusBadRequest || out["error"] != c.want {
				t.Errorf("status %d, body %v; want 400 %s", code, out, c.want)
			}
		})
	}
	if n := len(f.st.Clients()); n != 0 {
		t.Errorf("%d clients stored from invalid requests", n)
	}
	// Not JSON, and too large.
	for _, body := range []string{"not json", `{"redirect_uris":"https://a.example.com/cb"}`} {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, authserver.RegisterPath, strings.NewReader(body))
		rec := httptest.NewRecorder()
		f.svc.ServeRegister(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%q: status %d", body, rec.Code)
		}
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, authserver.RegisterPath, strings.NewReader(`{"client_name":"`+strings.Repeat("x", 70000)+`"}`))
	rec := httptest.NewRecorder()
	f.svc.ServeRegister(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge && rec.Code != http.StatusBadRequest {
		t.Errorf("oversized body: status %d", rec.Code)
	}
}

func many(s string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = s
	}
	return out
}

func TestRegisterIsRateLimitedPerIP(t *testing.T) {
	f := newService(t, func(c *authserver.Config) { c.RegisterPerMin = 3 })
	doc := map[string]any{"redirect_uris": []string{"http://127.0.0.1/cb"}}
	for i := 0; i < 3; i++ {
		if code, out := f.register(t, doc); code != http.StatusCreated {
			t.Fatalf("registration %d: %d %v", i, code, out)
		}
	}
	code, out := f.register(t, doc)
	if code != http.StatusTooManyRequests {
		t.Fatalf("4th registration: %d %v", code, out)
	}
	// Another address is unaffected; the first recovers after the window.
	f.ip = "203.0.113.6"
	if code, _ := f.register(t, doc); code != http.StatusCreated {
		t.Errorf("other IP: %d", code)
	}
	f.ip = "203.0.113.5"
	f.now = t0.Add(time.Minute + time.Second)
	if code, _ := f.register(t, doc); code != http.StatusCreated {
		t.Errorf("after the window: %d", code)
	}
}

func TestRegisterIsCappedOnUnusedClients(t *testing.T) {
	f := newService(t, func(c *authserver.Config) { c.MaxUnusedClients = 2; c.RegisterPerMin = 100 })
	doc := map[string]any{"redirect_uris": []string{"http://[::1]:8080/cb"}}
	for i := 0; i < 2; i++ {
		if code, _ := f.register(t, doc); code != http.StatusCreated {
			t.Fatalf("registration %d refused", i)
		}
	}
	if code, out := f.register(t, doc); code != http.StatusTooManyRequests || out["error_description"] == nil {
		t.Errorf("over the cap: %d %v", code, out)
	}
	// Once a client has been used (a sign-in completed) it no longer counts.
	used := f.st.Clients()[0]
	_ = f.st.Bypass(context.Background(), func(tx authserver.Tx) error { return tx.TouchClient(context.Background(), used.ID, f.now) })
	if code, _ := f.register(t, doc); code != http.StatusCreated {
		t.Errorf("after one client was used: %d", code)
	}
}

func TestPruneRemovesIdleClientsAndExpiredCodes(t *testing.T) {
	f := newService(t, func(c *authserver.Config) { c.ClientIdle = 24 * time.Hour })
	ctx := context.Background()
	_, idle := f.register(t, map[string]any{"client_name": "idle", "redirect_uris": []string{"http://localhost/cb"}})
	f.now = t0.Add(12 * time.Hour)
	_, fresh := f.register(t, map[string]any{"client_name": "fresh", "redirect_uris": []string{"http://localhost/cb"}})
	_, usedRecently := f.register(t, map[string]any{"client_name": "used", "redirect_uris": []string{"http://localhost/cb"}})
	// "used" was registered long ago but completed a sign-in recently.
	var usedRow store.OAuthClient
	for _, c := range f.st.Clients() {
		if c.ClientID == usedRecently["client_id"] {
			usedRow = c
		}
	}
	_ = f.st.Bypass(ctx, func(tx authserver.Tx) error {
		if err := tx.TouchClient(ctx, usedRow.ID, t0.Add(30*time.Hour)); err != nil {
			return err
		}
		return tx.CreateCode(ctx, &store.OAuthCode{CodeHash: []byte("h"), UserID: alice, ClientID: usedRow.ID, RedirectURI: "http://localhost/cb", Resource: f.cfg.Resource(), CodeChallenge: "c", ExpiresAt: t0.Add(13 * time.Hour)})
	})
	f.now = t0.Add(30 * time.Hour)
	job := f.svc.PruneJob(0)
	if job.Name() == "" || job.Interval() <= 0 {
		t.Errorf("job = %q every %v", job.Name(), job.Interval())
	}
	if err := job.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}
	var left []string
	for _, c := range f.st.Clients() {
		left = append(left, c.ClientName)
	}
	if len(left) != 2 || contains(left, "idle") {
		t.Errorf("clients after prune = %v, want fresh and used", left)
	}
	if n := len(f.st.Codes()); n != 0 {
		t.Errorf("%d expired codes left", n)
	}
	// The pruned client_id is gone for good.
	err := f.st.Bypass(ctx, func(tx authserver.Tx) error {
		_, err := tx.FindClientByClientID(ctx, idle["client_id"].(string))
		return err
	})
	if err == nil {
		t.Error("pruned client still found")
	}
	_ = fresh
}

func contains(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}
