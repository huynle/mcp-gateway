package machineclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Unix(1_800_000_000, 0)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// logBuffer is a concurrency-safe capture of a debug-level logger.
type logBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func captureLogger() (*slog.Logger, *logBuffer) {
	lb := &logBuffer{}
	return slog.New(slog.NewTextHandler(lb, &slog.HandlerOptions{Level: slog.LevelDebug})), lb
}

func assertNoSecrets(t *testing.T, where, text string, secrets []string) {
	t.Helper()
	for _, s := range secrets {
		if s != "" && strings.Contains(text, s) {
			t.Errorf("%s leaks a secret %.12q…:\n%s", where, s, text)
		}
	}
}

func testKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestDeviceAuthorizationAndPoll(t *testing.T) {
	g := newFakeGateway(t)
	g.pollScript = []string{"authorization_pending"}
	log, logs := captureLogger()
	c := NewClient(g.URL(), "v1.2.3", log)
	k := testKey(t)
	da, err := c.DeviceAuthorization(context.Background(), "huy-mac", PublicJWK(k.Public().(ed25519.PublicKey)))
	if err != nil {
		t.Fatal(err)
	}
	if da.DeviceCode != "dev-code-SECRET" || da.UserCode != "BCDF-GHJK" || da.Interval != 5 || da.ExpiresIn != 600 ||
		da.VerificationURI != g.URL()+"/activate" || da.VerificationURIComplete != g.URL()+"/activate?code=BCDF-GHJK" {
		t.Fatalf("%+v", da)
	}
	req := g.deviceReqs[0]
	if req["name"] != "huy-mac" || req["client_version"] != "v1.2.3" {
		t.Fatalf("request %v", req)
	}
	_, err = c.PollDeviceToken(context.Background(), da.DeviceCode)
	var ae *APIError
	if !errors.As(err, &ae) || ae.Code != "authorization_pending" || ae.Status != 400 {
		t.Fatalf("want authorization_pending, got %v", err)
	}
	enr, err := c.PollDeviceToken(context.Background(), da.DeviceCode)
	if err != nil {
		t.Fatal(err)
	}
	if enr.MachineID != g.machineID || enr.Name != "huy-mac" || enr.Gateway != g.URL() {
		t.Fatalf("%+v", enr)
	}
	assertNoSecrets(t, "debug log", logs.String(), g.secrets())
	assertNoSecrets(t, "error", err2s(err), g.secrets())
}

func err2s(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestEnroll(t *testing.T) {
	g := newFakeGateway(t)
	log, logs := captureLogger()
	c := NewClient(g.URL(), "v1", log)
	jwk := PublicJWK(testKey(t).Public().(ed25519.PublicKey))
	_, err := c.Enroll(context.Background(), "mge_wrong", "m1", jwk)
	var ae *APIError
	if !errors.As(err, &ae) || ae.Code != "invalid_code" {
		t.Fatalf("want invalid_code, got %v", err)
	}
	enr, err := c.Enroll(context.Background(), "mge_ENROLLSECRET", "m1", jwk)
	if err != nil || enr.MachineID != g.machineID || enr.Name != "m1" {
		t.Fatalf("%v %+v", err, enr)
	}
	if g.enrollReqs[1]["client_version"] != "v1" {
		t.Fatalf("%v", g.enrollReqs[1])
	}
	assertNoSecrets(t, "debug log", logs.String(), g.secrets())
}

func TestMintAssertion(t *testing.T) {
	k := testKey(t)
	now := time.Unix(1_800_000_000, 0)
	a, err := MintAssertion(k, "mid", "https://g.example.com/machine/token", now)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(a, ".")
	if len(parts) != 3 {
		t.Fatal(a)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if !ed25519.Verify(k.Public().(ed25519.PublicKey), []byte(parts[0]+"."+parts[1]), sig) {
		t.Fatal("bad signature")
	}
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	if string(hb) != `{"alg":"EdDSA","typ":"JWT"}` {
		t.Fatalf("header %s", hb)
	}
	var c map[string]any
	cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if err := json.Unmarshal(cb, &c); err != nil {
		t.Fatal(err)
	}
	if c["iss"] != "mid" || c["sub"] != "mid" || c["aud"] != "https://g.example.com/machine/token" ||
		c["iat"] != float64(now.Unix()) || c["exp"].(float64) > float64(now.Unix()+300) || c["exp"].(float64) <= float64(now.Unix()) {
		t.Fatalf("claims %v", c)
	}
	b, _ := MintAssertion(k, "mid", "aud", now)
	var c2 map[string]any
	cb2, _ := base64.RawURLEncoding.DecodeString(strings.Split(b, ".")[1])
	_ = json.Unmarshal(cb2, &c2)
	if c["jti"] == c2["jti"] || len(c["jti"].(string)) < 16 {
		t.Fatalf("jti must be random and unique: %v %v", c["jti"], c2["jti"])
	}
}

// enrolled returns a fake gateway that knows the machine key, and a token
// source on a fake clock shared with the gateway.
func enrolled(t *testing.T) (*fakeGateway, *TokenSource, *fakeClock, *logBuffer) {
	t.Helper()
	g := newFakeGateway(t)
	clk := newFakeClock()
	g.now = clk.Now
	k := testKey(t)
	g.pub = k.Public().(ed25519.PublicKey)
	log, logs := captureLogger()
	ts := &TokenSource{Client: NewClient(g.URL(), "v1", log), MachineID: g.machineID, Key: k, Now: clk.Now}
	return g, ts, clk, logs
}

func TestTokenSourceCachesAndRefreshesBeforeExpiry(t *testing.T) {
	g, ts, clk, logs := enrolled(t)
	ctx := context.Background()
	t1, err := ts.Token(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(t1, "mgm_") {
		t.Fatalf("token %q", t1)
	}
	clk.Advance(4 * time.Minute)
	t2, _ := ts.Token(ctx)
	if t2 != t1 || g.issued != 1 {
		t.Fatalf("token not cached: issued %d", g.issued)
	}
	// 10-minute token: refreshed in the last minute, before it expires.
	clk.Advance(5*time.Minute + 30*time.Second)
	t3, err := ts.Token(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if t3 == t1 || g.issued != 2 {
		t.Fatalf("token not refreshed before expiry: issued %d", g.issued)
	}
	// Invalidating the current token forces a new one; invalidating a stale
	// one does not.
	ts.Invalidate(t1)
	if t4, _ := ts.Token(ctx); t4 != t3 {
		t.Fatal("invalidating an old token dropped the current one")
	}
	ts.Invalidate(t3)
	if t5, _ := ts.Token(ctx); t5 == t3 || g.issued != 3 {
		t.Fatalf("invalidate did not refresh: issued %d", g.issued)
	}
	assertNoSecrets(t, "debug log", logs.String(), g.secrets())
}

func TestTokenSourceShortTTL(t *testing.T) {
	g, ts, clk, _ := enrolled(t)
	g.tokenTTL = 60
	ctx := context.Background()
	t1, _ := ts.Token(ctx)
	clk.Advance(20 * time.Second)
	if t2, _ := ts.Token(ctx); t2 != t1 {
		t.Fatal("refreshed too early for a short token")
	}
	clk.Advance(15 * time.Second) // past half the lifetime
	if t3, _ := ts.Token(ctx); t3 == t1 {
		t.Fatal("not refreshed past half of a short lifetime")
	}
}

func TestTokenSourceRejected(t *testing.T) {
	g, ts, _, _ := enrolled(t)
	g.revoked = true
	_, err := ts.Token(context.Background())
	if !errors.Is(err, ErrMachineRejected) {
		t.Fatalf("want ErrMachineRejected, got %v", err)
	}
	assertNoSecrets(t, "error", err.Error(), g.secrets())
}

func TestTokenSourceConcurrent(t *testing.T) {
	g, ts, _, _ := enrolled(t)
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			if _, err := ts.Token(context.Background()); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if g.issued != 1 {
		t.Fatalf("concurrent callers minted %d tokens, want 1", g.issued)
	}
}

func TestMachineAPI(t *testing.T) {
	g, ts, _, logs := enrolled(t)
	api := &MachineAPI{Client: ts.Client, Tokens: ts}
	ctx := context.Background()
	res, err := api.PutServer(ctx, "fusion360", KindHTTP)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Created || res.TunnelID != "tun-1" || res.ServerID != "srv-1" || res.ReviewURL != g.URL()+"/servers/srv-1" || res.Name != "fusion360" {
		t.Fatalf("%+v", res)
	}
	res, _ = api.PutServer(ctx, "fusion360", KindHTTP)
	if res.Created {
		t.Fatal("second put must not create")
	}
	self, err := api.Self(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if self.MachineID != g.machineID || self.Owner != "Huy" || len(self.Servers) != 1 || self.Servers[0].TunnelID != "tun-1" || self.Servers[0].Status != "active" {
		t.Fatalf("%+v", self)
	}
	ref, err := api.RefreshServer(ctx, "fusion360")
	if err != nil || ref.Added != 3 || ref.ReviewURL == "" || ref.Version != 1 {
		t.Fatalf("%v %+v", err, ref)
	}
	g.offline = true
	_, err = api.RefreshServer(ctx, "fusion360")
	var ae *APIError
	if !errors.As(err, &ae) || ae.Code != "offline" {
		t.Fatalf("want offline, got %v", err)
	}
	g.nameTakenFor["taken"] = true
	if _, err = api.PutServer(ctx, "taken", KindStdio); !errors.As(err, &ae) || ae.Code != "name_taken" || ae.Status != 409 {
		t.Fatalf("want name_taken, got %v", err)
	}
	assertNoSecrets(t, "debug log", logs.String(), g.secrets())
}

func TestMachineAPIRetriesOnceOnInvalidToken(t *testing.T) {
	g, ts, _, _ := enrolled(t)
	api := &MachineAPI{Client: ts.Client, Tokens: ts}
	ctx := context.Background()
	if _, err := api.Self(ctx); err != nil {
		t.Fatal(err)
	}
	g.failNextAPI = 1
	if _, err := api.Self(ctx); err != nil {
		t.Fatalf("one invalid_token must be retried with a fresh token: %v", err)
	}
	if g.issued != 2 {
		t.Fatalf("issued %d", g.issued)
	}
	g.failNextAPI = 2
	_, err := api.Self(ctx)
	var ae *APIError
	if !errors.As(err, &ae) || ae.Code != "invalid_token" {
		t.Fatalf("second invalid_token must fail: %v", err)
	}
}

func TestMachineAPIRevokedAndLogout(t *testing.T) {
	g, ts, _, _ := enrolled(t)
	api := &MachineAPI{Client: ts.Client, Tokens: ts}
	ctx := context.Background()
	if err := api.Logout(ctx); err != nil {
		t.Fatal(err)
	}
	if g.logouts != 1 {
		t.Fatal("logout not sent")
	}
	if _, err := api.Self(ctx); !errors.Is(err, ErrRevoked) && !errors.Is(err, ErrMachineRejected) {
		t.Fatalf("after logout: %v", err)
	}
	// A cached token on a revoked machine: 403 revoked.
	g2, ts2, _, _ := enrolled(t)
	api2 := &MachineAPI{Client: ts2.Client, Tokens: ts2}
	if _, err := api2.Self(ctx); err != nil {
		t.Fatal(err)
	}
	g2.revoked = true
	if _, err := api2.Self(ctx); !errors.Is(err, ErrRevoked) {
		t.Fatalf("want ErrRevoked, got %v", err)
	}
}

func TestClientRefusesRedirectsAndBigBodies(t *testing.T) {
	var hits int
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer other.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/machine/v1/self" {
			http.Redirect(w, r, other.URL+"/steal", http.StatusTemporaryRedirect)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"error":"x","error_description":"` + strings.Repeat("a", 2<<20) + `"}`))
	}))
	defer redir.Close()
	c := NewClient(redir.URL, "v1", nil)
	api := &MachineAPI{Client: c, Tokens: staticTokens("mgm_static")}
	if _, err := api.Self(context.Background()); err == nil {
		t.Fatal("a redirect must be an error")
	}
	if hits != 0 {
		t.Fatal("the redirect was followed")
	}
	_, err := c.PollDeviceToken(context.Background(), "x")
	if err == nil || len(err.Error()) > 1000 {
		t.Fatalf("huge error bodies must be bounded: %d bytes", len(err2s(err)))
	}
}

type staticTokens string

func (s staticTokens) Token(context.Context) (string, error) { return string(s), nil }
func (staticTokens) Invalidate(string)                       {}
