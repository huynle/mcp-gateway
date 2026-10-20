package machines

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/federation/tunnel"
	"github.com/huynle/mcp-gateway/internal/store"
)

const (
	base  = "https://gw.example"
	alice = "a0000000-0000-4000-8000-000000000001"
	bob   = "b0000000-0000-4000-8000-000000000002"
	carol = "c0000000-0000-4000-8000-000000000003" // pending
)

type recorder struct {
	mu  sync.Mutex
	evs []audit.Event
}

func (r *recorder) Record(_ context.Context, ev audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evs = append(r.evs, ev)
	return nil
}

func (r *recorder) actions() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, e := range r.evs {
		out = append(out, e.ResourceIdentity["action"])
	}
	return out
}

type env struct {
	t   *testing.T
	svc *Service
	st  *memStore
	sv  *fakeServers
	tn  *fakeTunnels
	rec *recorder
	srv *httptest.Server
	mu  sync.Mutex
	now time.Time
	ip  string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, st: newMemStore(), sv: newFakeServers(), tn: newFakeTunnels(), rec: &recorder{}, now: time.Unix(1_800_000_000, 0), ip: "198.51.100.7"}
	e.st.addUser(alice, "Alice", store.UserActive)
	e.st.addUser(bob, "Bob", store.UserActive)
	e.st.addUser(carol, "Carol", store.UserPending)
	svc, err := New(Options{
		Store: e.st, Servers: e.sv, Tunnels: e.tn, BaseURL: base, Audit: e.rec, Log: slog.New(slog.DiscardHandler),
		Now:      e.clock,
		ClientIP: func(*http.Request) string { e.mu.Lock(); defer e.mu.Unlock(); return e.ip },
	})
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	mux := http.NewServeMux()
	svc.Mount(mux)
	e.srv = httptest.NewServer(mux)
	t.Cleanup(e.srv.Close)
	return e
}

func (e *env) clock() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.now
}

func (e *env) advance(d time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.now = e.now.Add(d)
}

func (e *env) setIP(ip string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ip = ip
}

// do sends a request and returns the status and decoded JSON body.
func (e *env) do(method, path, ctype, token string, body string) (int, map[string]any) {
	e.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, e.srv.URL+path, strings.NewReader(body))
	if err != nil {
		e.t.Fatal(err)
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(b, &out)
	if resp.StatusCode != http.StatusNoContent && resp.Header.Get("Cache-Control") != "no-store" && strings.HasPrefix(path, "/machine") {
		e.t.Errorf("%s %s: Cache-Control %q", method, path, resp.Header.Get("Cache-Control"))
	}
	return resp.StatusCode, out
}

func (e *env) json(path string, v any) (int, map[string]any) {
	b, _ := json.Marshal(v)
	return e.do(http.MethodPost, path, "application/json", "", string(b))
}

func (e *env) form(v url.Values) (int, map[string]any) {
	return e.do(http.MethodPost, "/machine/token", "application/x-www-form-urlencoded", "", v.Encode())
}

func deviceGrant(code string) url.Values {
	return url.Values{"grant_type": {GrantDeviceCode}, "device_code": {code}}
}

// requestDevice starts a device flow for a new key.
func (e *env) requestDevice(name string) (map[string]any, ed25519.PrivateKey) {
	e.t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	code, body := e.json("/machine/device_authorization", map[string]any{"name": name, "public_key": PublicJWK(pub), "client_version": "1.0.0"})
	if code != http.StatusOK {
		e.t.Fatalf("device_authorization = %d %v", code, body)
	}
	return body, priv
}

// approve approves a user code as user.
func (e *env) approve(user, userCode string) (*store.Machine, error) {
	e.t.Helper()
	d, err := e.svc.LookupUserCode(context.Background(), user, userCode)
	if err != nil {
		return nil, err
	}
	return e.svc.Approve(context.Background(), user, d.ID)
}

// enroll runs the whole device flow for user and returns the machine id
// and key.
func (e *env) enroll(user, name string) (string, ed25519.PrivateKey) {
	e.t.Helper()
	body, priv := e.requestDevice(name)
	if _, err := e.approve(user, body["user_code"].(string)); err != nil {
		e.t.Fatal(err)
	}
	code, out := e.form(deviceGrant(body["device_code"].(string)))
	if code != http.StatusOK {
		e.t.Fatalf("device token = %d %v", code, out)
	}
	return out["machine_id"].(string), priv
}

func (e *env) assertion(priv ed25519.PrivateKey, machineID string, mod func(map[string]any)) string {
	now := e.clock()
	c := map[string]any{"iss": machineID, "sub": machineID, "aud": base + "/machine/token", "iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(), "jti": "jti-" + randomSuffix()}
	if mod != nil {
		mod(c)
	}
	return signAssertion(e.t, priv, c, nil)
}

func randomSuffix() string { return rand.Text() }

func (e *env) token(priv ed25519.PrivateKey, machineID string) string {
	e.t.Helper()
	code, out := e.form(url.Values{"grant_type": {GrantJWTBearer}, "assertion": {e.assertion(priv, machineID, nil)}})
	if code != http.StatusOK {
		e.t.Fatalf("jwt-bearer = %d %v", code, out)
	}
	return out["access_token"].(string)
}

func TestDeviceFlowApproveAndPoll(t *testing.T) {
	e := newEnv(t)
	body, _ := e.requestDevice("laptop")
	uc := body["user_code"].(string)
	if _, ok := NormalizeUserCode(uc); !ok || body["verification_uri"] != base+"/activate" ||
		body["verification_uri_complete"] != base+"/activate?code="+uc || body["expires_in"] != float64(600) || body["interval"] != float64(5) {
		t.Fatalf("device authorization = %v", body)
	}
	dc := body["device_code"].(string)
	if !ValidSecret(DeviceCodePrefix, dc) {
		t.Fatalf("device code %q", dc)
	}
	if code, out := e.form(deviceGrant(dc)); code != http.StatusBadRequest || out["error"] != "authorization_pending" {
		t.Fatalf("first poll = %d %v", code, out)
	}
	if code, out := e.form(deviceGrant(dc)); code != http.StatusBadRequest || out["error"] != "slow_down" {
		t.Fatalf("fast poll = %d %v", code, out)
	}
	e.advance(11 * time.Second)
	m, err := e.approve(bob, uc) // approved by Bob: the machine is Bob's
	if err != nil {
		t.Fatal(err)
	}
	if m.OwnerUserID != bob || m.Name != "laptop" {
		t.Fatalf("machine = %+v", m)
	}
	code, out := e.form(deviceGrant(dc))
	if code != http.StatusOK || out["machine_id"] != m.ID || out["name"] != "laptop" || out["gateway"] != base {
		t.Fatalf("approved poll = %d %v", code, out)
	}
	e.advance(20 * time.Second)
	if code, out := e.form(deviceGrant(dc)); code != http.StatusBadRequest || out["error"] != "expired_token" {
		t.Fatalf("second redemption = %d %v", code, out)
	}
	acts := strings.Join(e.rec.actions(), ",")
	if !strings.Contains(acts, "machine.device_requested") || !strings.Contains(acts, "machine.approved") {
		t.Fatalf("audit actions = %s", acts)
	}
}

func TestDeviceFlowDeniedExpiredAndUnknown(t *testing.T) {
	e := newEnv(t)
	body, _ := e.requestDevice("laptop")
	d, err := e.svc.LookupUserCode(context.Background(), alice, body["user_code"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Deny(context.Background(), alice, d.ID); err != nil {
		t.Fatal(err)
	}
	if code, out := e.form(deviceGrant(body["device_code"].(string))); code != http.StatusBadRequest || out["error"] != "access_denied" {
		t.Fatalf("denied poll = %d %v", code, out)
	}
	if _, err := e.approve(alice, body["user_code"].(string)); err == nil {
		t.Fatal("a denied request was approved")
	}

	body2, _ := e.requestDevice("desk")
	e.advance(601 * time.Second)
	if _, err := e.approve(alice, body2["user_code"].(string)); err == nil {
		t.Fatal("an expired request was approved")
	}
	if code, out := e.form(deviceGrant(body2["device_code"].(string))); code != http.StatusBadRequest || out["error"] != "expired_token" {
		t.Fatalf("expired poll = %d %v", code, out)
	}
	fake, _ := NewSecret(DeviceCodePrefix)
	for _, dc := range []string{fake, "nope", ""} {
		if code, out := e.form(deviceGrant(dc)); code != http.StatusBadRequest || out["error"] != "expired_token" {
			t.Fatalf("unknown device code %q = %d %v", dc, code, out)
		}
	}
}

func TestApprovalRefusesInactiveUsersAndBadCodes(t *testing.T) {
	e := newEnv(t)
	body, _ := e.requestDevice("laptop")
	if _, err := e.approve(carol, body["user_code"].(string)); !errors.Is(err, ErrInactiveOwner) {
		t.Fatalf("pending user approves: %v", err)
	}
	if _, err := e.svc.LookupUserCode(context.Background(), alice, "BCDF-GHJK"); !errors.Is(err, ErrUnknownUserCode) {
		t.Fatalf("unknown code: %v", err)
	}
	// Guessing is rate limited per user.
	var last error
	for range 20 {
		_, last = e.svc.LookupUserCode(context.Background(), bob, "BCDF-GHJK")
	}
	if !errors.Is(last, ErrTooManyAttempts) {
		t.Fatalf("after 20 wrong codes: %v, want ErrTooManyAttempts", last)
	}
	// Alice is not affected by Bob's guesses.
	if _, err := e.svc.LookupUserCode(context.Background(), alice, body["user_code"].(string)); err != nil {
		t.Fatalf("alice after bob's guesses: %v", err)
	}
}

func TestDeviceAuthorizationValidatesAndRateLimits(t *testing.T) {
	e := newEnv(t)
	pub, _, _ := ed25519.GenerateKey(nil)
	for name, v := range map[string]any{
		"bad name":    map[string]any{"name": "Laptop!", "public_key": PublicJWK(pub)},
		"long name":   map[string]any{"name": strings.Repeat("a", 64), "public_key": PublicJWK(pub)},
		"bad key":     map[string]any{"name": "laptop", "public_key": map[string]any{"kty": "RSA"}},
		"no key":      map[string]any{"name": "laptop"},
		"long ver":    map[string]any{"name": "laptop", "public_key": PublicJWK(pub), "client_version": strings.Repeat("1", 65)},
		"unknown key": map[string]any{"name": "laptop", "public_key": PublicJWK(pub), "extra": 1},
	} {
		if code, out := e.json("/machine/device_authorization", v); code != http.StatusBadRequest || out["error"] != "invalid_request" {
			t.Errorf("%s: %d %v", name, code, out)
		}
	}
	e.setIP("203.0.113.50")
	var code int
	for range 30 {
		code, _ = e.json("/machine/device_authorization", map[string]any{"name": "laptop", "public_key": PublicJWK(pub)})
	}
	if code != http.StatusTooManyRequests {
		t.Fatalf("30 requests from one address: last %d, want 429", code)
	}
	e.setIP("203.0.113.51")
	if code, _ := e.json("/machine/device_authorization", map[string]any{"name": "laptop", "public_key": PublicJWK(pub)}); code != http.StatusOK {
		t.Fatalf("another address: %d", code)
	}
}

func TestJWTBearerIssuesShortLivedTokens(t *testing.T) {
	e := newEnv(t)
	id, priv := e.enroll(alice, "laptop")
	a := e.assertion(priv, id, nil)
	code, out := e.form(url.Values{"grant_type": {GrantJWTBearer}, "assertion": {a}})
	if code != http.StatusOK || out["token_type"] != "Bearer" || out["expires_in"] != float64(600) || out["scope"] != "machine" ||
		!ValidSecret(AccessTokenPrefix, out["access_token"].(string)) {
		t.Fatalf("token = %d %v", code, out)
	}
	// Replay.
	if code, out := e.form(url.Values{"grant_type": {GrantJWTBearer}, "assertion": {a}}); code != http.StatusBadRequest || out["error"] != "invalid_grant" {
		t.Fatalf("replayed assertion = %d %v", code, out)
	}
	_, other, _ := ed25519.GenerateKey(nil)
	for name, assertion := range map[string]string{
		"other key": e.assertion(other, id, nil),
		"wrong aud": e.assertion(priv, id, func(c map[string]any) { c["aud"] = base + "/mcp" }),
		"expired": e.assertion(priv, id, func(c map[string]any) {
			c["iat"], c["exp"] = e.clock().Add(-5*time.Minute).Unix(), e.clock().Add(-2*time.Minute).Unix()
		}),
		"garbage": "x.y.z",
	} {
		if code, out := e.form(url.Values{"grant_type": {GrantJWTBearer}, "assertion": {assertion}}); code != http.StatusBadRequest || out["error"] != "invalid_grant" {
			t.Errorf("%s: %d %v", name, code, out)
		}
	}
	if code, out := e.form(url.Values{"grant_type": {"password"}}); code != http.StatusBadRequest || out["error"] != "unsupported_grant_type" {
		t.Fatalf("unknown grant = %d %v", code, out)
	}

	// The token expires after ten minutes.
	tok := e.token(priv, id)
	if code, _ := e.do(http.MethodGet, "/machine/v1/self", "", tok, ""); code != http.StatusOK {
		t.Fatalf("fresh token: %d", code)
	}
	e.advance(601 * time.Second)
	if code, out := e.do(http.MethodGet, "/machine/v1/self", "", tok, ""); code != http.StatusUnauthorized || out["error"] != "invalid_token" {
		t.Fatalf("expired token: %d %v", code, out)
	}
}

func TestRevokedMachineAndInactiveOwnerAreRefused(t *testing.T) {
	e := newEnv(t)
	id, priv := e.enroll(alice, "laptop")
	tok := e.token(priv, id)
	if err := e.svc.Revoke(context.Background(), id, alice, alice, store.MachineRevokedByOwner); err != nil {
		t.Fatal(err)
	}
	if got := e.tn.droppedIDs(); len(got) != 1 || got[0] != id {
		t.Fatalf("dropped = %v", got)
	}
	if code, out := e.do(http.MethodGet, "/machine/v1/self", "", tok, ""); code != http.StatusForbidden || out["error"] != "revoked" {
		t.Fatalf("revoked machine's token: %d %v", code, out)
	}
	if code, out := e.form(url.Values{"grant_type": {GrantJWTBearer}, "assertion": {e.assertion(priv, id, nil)}}); code != http.StatusBadRequest || out["error"] != "invalid_grant" {
		t.Fatalf("revoked machine's assertion = %d %v", code, out)
	}

	id2, priv2 := e.enroll(bob, "desk")
	tok2 := e.token(priv2, id2)
	e.st.setStatus(bob, store.UserDisabled)
	if code, _ := e.do(http.MethodGet, "/machine/v1/self", "", tok2, ""); code != http.StatusForbidden {
		t.Fatalf("disabled owner's token: %d", code)
	}
	if code, _ := e.form(url.Values{"grant_type": {GrantJWTBearer}, "assertion": {e.assertion(priv2, id2, nil)}}); code != http.StatusBadRequest {
		t.Fatalf("disabled owner's assertion: %d", code)
	}
}

func TestMachineAPIRefusesBadTokens(t *testing.T) {
	e := newEnv(t)
	fake, _ := NewSecret(AccessTokenPrefix)
	for _, tok := range []string{"", "mgw_abc", fake, "mge_x"} {
		code, out := e.do(http.MethodGet, "/machine/v1/self", "", tok, "")
		if code != http.StatusUnauthorized || out["error"] != "invalid_token" {
			t.Errorf("token %q: %d %v", tok, code, out)
		}
	}
}

func TestPutServerRegistersTunnelAndServerIdempotently(t *testing.T) {
	e := newEnv(t)
	id, priv := e.enroll(alice, "laptop")
	tok := e.token(priv, id)
	code, out := e.do(http.MethodPut, "/machine/v1/servers/fusion360", "application/json", tok, `{"kind":"http","path":"/mcp"}`)
	if code != http.StatusOK || out["created"] != true || out["name"] != "fusion360" {
		t.Fatalf("PUT = %d %v", code, out)
	}
	tid := out["tunnel_id"].(string)
	sid := out["server_id"].(string)
	if out["review_url"] != base+"/servers/"+sid+"/review" {
		t.Fatalf("review_url = %v", out["review_url"])
	}
	s, _ := e.sv.OwnServer(context.Background(), alice, "fusion360")
	if s.URL != tunnel.URL(tid, "/mcp") || s.AuthKind != store.MCPAuthNone || s.OwnerUserID != alice {
		t.Fatalf("server = %+v", s)
	}
	code, out = e.do(http.MethodPut, "/machine/v1/servers/fusion360", "application/json", tok, `{"kind":"http","path":"/mcp"}`)
	if code != http.StatusOK || out["created"] != false || out["tunnel_id"] != tid || out["server_id"] != sid {
		t.Fatalf("second PUT = %d %v", code, out)
	}
	if len(e.tn.synced) == 0 {
		t.Fatal("the tunnel service was not told about the new tunnel")
	}

	// self lists it.
	e.tn.setOnline(tid)
	code, out = e.do(http.MethodGet, "/machine/v1/self", "", tok, "")
	servers, _ := out["servers"].([]any)
	if code != http.StatusOK || out["machine_id"] != id || out["owner"] != "Alice" || len(servers) != 1 {
		t.Fatalf("self = %d %v", code, out)
	}
	first := servers[0].(map[string]any)
	if first["name"] != "fusion360" || first["status"] != "online" || first["tunnel_id"] != tid || first["approved_tools"] != float64(0) {
		t.Fatalf("self server = %v", first)
	}

	for name, body := range map[string]string{
		"bad kind": `{"kind":"ftp"}`, "bad path": `{"kind":"http","path":"mcp"}`, "scheme path": `{"kind":"http","path":"//evil/x"}`,
		"not json": `x`,
	} {
		if code, out := e.do(http.MethodPut, "/machine/v1/servers/other", "application/json", tok, body); code != http.StatusBadRequest {
			t.Errorf("%s: %d %v", name, code, out)
		}
	}
	if code, out := e.do(http.MethodPut, "/machine/v1/servers/Bad%20Name", "application/json", tok, `{"kind":"stdio"}`); code != http.StatusBadRequest || out["error"] != "invalid_name" {
		t.Errorf("bad name: %d %v", code, out)
	}
}

func TestPutServerRefusesNamesItDoesNotOwn(t *testing.T) {
	e := newEnv(t)
	// Alice has a server "notes" of her own, not behind this machine.
	if err := e.sv.CreateServer(context.Background(), &store.MCPServer{Name: "notes", OwnerUserID: alice, URL: "https://notes.example/mcp"}); err != nil {
		t.Fatal(err)
	}
	// Bob owns "bobs".
	if err := e.sv.CreateServer(context.Background(), &store.MCPServer{Name: "bobs", OwnerUserID: bob, URL: "https://b.example/mcp"}); err != nil {
		t.Fatal(err)
	}
	id, priv := e.enroll(alice, "laptop")
	tok := e.token(priv, id)
	for _, name := range []string{"notes", "bobs"} {
		code, out := e.do(http.MethodPut, "/machine/v1/servers/"+name, "application/json", tok, `{"kind":"stdio"}`)
		if code != http.StatusConflict || out["error"] != "name_taken" {
			t.Fatalf("%s: %d %v", name, code, out)
		}
	}
	// No tunnel was left behind.
	ts, _ := e.st.MachineTunnels(context.Background(), id)
	for _, tn := range ts {
		if tn.RevokedAt == nil {
			t.Fatalf("live tunnel left after a refused PUT: %+v", tn)
		}
	}
	// Bob's server cannot be refreshed through Alice's machine either.
	if code, _ := e.do(http.MethodPost, "/machine/v1/servers/bobs/refresh", "", tok, ""); code != http.StatusNotFound {
		t.Fatalf("refresh of bob's server: %d", code)
	}

	// Another machine of Alice cannot take over this machine's server.
	if code, _ := e.do(http.MethodPut, "/machine/v1/servers/fusion", "application/json", tok, `{"kind":"stdio"}`); code != http.StatusOK {
		t.Fatal("PUT fusion")
	}
	id2, priv2 := e.enroll(alice, "desk")
	tok2 := e.token(priv2, id2)
	if code, out := e.do(http.MethodPut, "/machine/v1/servers/fusion", "application/json", tok2, `{"kind":"stdio"}`); code != http.StatusConflict || out["error"] != "name_taken" {
		t.Fatalf("other machine takes over: %d %v", code, out)
	}
}

func TestPutServerRespectsCaps(t *testing.T) {
	e := newEnv(t)
	id, priv := e.enroll(alice, "laptop")
	tok := e.token(priv, id)
	e.st.maxTun = 1
	if code, _ := e.do(http.MethodPut, "/machine/v1/servers/one", "application/json", tok, `{"kind":"stdio"}`); code != http.StatusOK {
		t.Fatal("first PUT")
	}
	code, out := e.do(http.MethodPut, "/machine/v1/servers/two", "application/json", tok, `{"kind":"stdio"}`)
	if code != http.StatusConflict || out["error"] != "cap_exceeded" || !strings.Contains(out["error_description"].(string), "tunnels") {
		t.Fatalf("over the tunnel cap: %d %v", code, out)
	}
	e.st.maxTun = 0
	e.sv.maxPer = 1
	code, out = e.do(http.MethodPut, "/machine/v1/servers/three", "application/json", tok, `{"kind":"stdio"}`)
	if code != http.StatusConflict || out["error"] != "cap_exceeded" {
		t.Fatalf("over the server cap: %d %v", code, out)
	}
}

func TestRefreshRunsThroughTheLiveConnectionAndNeverApproves(t *testing.T) {
	e := newEnv(t)
	id, priv := e.enroll(alice, "laptop")
	tok := e.token(priv, id)
	_, out := e.do(http.MethodPut, "/machine/v1/servers/fusion", "application/json", tok, `{"kind":"stdio"}`)
	tid := out["tunnel_id"].(string)
	if code, out := e.do(http.MethodPost, "/machine/v1/servers/fusion/refresh", "", tok, ""); code != http.StatusConflict || out["error"] != "offline" {
		t.Fatalf("offline refresh = %d %v", code, out)
	}
	e.tn.setOnline(tid)
	e.sv.refreshFn = func(*store.MCPServer) (int, snapshot.Diff, error) {
		return 3, snapshot.Diff{Added: []string{"a"}, Removed: []string{"b"}, Changed: []snapshot.ToolChange{{Name: "c"}}}, nil
	}
	code, out := e.do(http.MethodPost, "/machine/v1/servers/fusion/refresh", "", tok, "")
	if code != http.StatusOK || out["version"] != float64(3) || len(out["added"].([]any)) != 1 || len(out["changed"].([]any)) != 1 ||
		len(out["removed"].([]any)) != 1 || !strings.HasPrefix(out["review_url"].(string), base+"/servers/") {
		t.Fatalf("refresh = %d %v", code, out)
	}
	e.sv.refreshFn = func(*store.MCPServer) (int, snapshot.Diff, error) {
		return 0, snapshot.Diff{}, &tunnel.Error{Class: tunnel.ClassOffline}
	}
	if code, out := e.do(http.MethodPost, "/machine/v1/servers/fusion/refresh", "", tok, ""); code != http.StatusConflict || out["error"] != "offline" {
		t.Fatalf("refresh failing offline = %d %v", code, out)
	}
	if code, _ := e.do(http.MethodPost, "/machine/v1/servers/nope/refresh", "", tok, ""); code != http.StatusNotFound {
		t.Fatalf("unknown server refresh = %d", code)
	}
}

func TestLogoutRevokesTheMachine(t *testing.T) {
	e := newEnv(t)
	id, priv := e.enroll(alice, "laptop")
	tok := e.token(priv, id)
	if code, _ := e.do(http.MethodPost, "/machine/v1/logout", "", tok, ""); code != http.StatusNoContent {
		t.Fatalf("logout = %d", code)
	}
	if code, _ := e.do(http.MethodGet, "/machine/v1/self", "", tok, ""); code != http.StatusForbidden {
		t.Fatalf("after logout = %d", code)
	}
	m, _ := e.st.Machine(context.Background(), id)
	if m.RevokeReason != store.MachineRevokedSelf {
		t.Fatalf("reason = %q", m.RevokeReason)
	}
}

func TestConnectNeedsAMachineToken(t *testing.T) {
	e := newEnv(t)
	id, priv := e.enroll(alice, "laptop")
	if code, _ := e.do(http.MethodGet, "/machine/v1/connect", "", "", ""); code != http.StatusUnauthorized {
		t.Fatalf("anonymous connect = %d", code)
	}
	tok := e.token(priv, id)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, e.srv.URL+"/machine/v1/connect", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(b) != "serving "+id {
		t.Fatalf("connect handed %q to the tunnel service", b)
	}
}

func TestEnrollmentCodes(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	raw, c, err := e.svc.CreateEnrollmentCode(ctx, alice, "ci runner", 24*time.Hour)
	if err != nil || !ValidSecret(EnrollmentCodePrefix, raw) || c.OwnerUserID != alice {
		t.Fatalf("create = %q %+v %v", raw, c, err)
	}
	if _, _, err := e.svc.CreateEnrollmentCode(ctx, alice, "x", 2*time.Hour); !errors.Is(err, ErrInvalidLifetime) {
		t.Fatalf("odd lifetime = %v", err)
	}
	pub, _, _ := ed25519.GenerateKey(nil)
	enroll := func(code string) (int, map[string]any) {
		return e.json("/machine/enroll", map[string]any{"code": code, "name": "runner", "public_key": PublicJWK(pub), "client_version": "1"})
	}
	code, out := enroll(raw)
	if code != http.StatusOK || out["name"] != "runner" || out["gateway"] != base {
		t.Fatalf("enroll = %d %v", code, out)
	}
	m, _ := e.st.Machine(ctx, out["machine_id"].(string))
	if m.OwnerUserID != alice || m.EnrolledVia != store.MachineEnrolledCode {
		t.Fatalf("machine = %+v", m)
	}
	if code, out := enroll(raw); code != http.StatusBadRequest || out["error"] != "invalid_code" {
		t.Fatalf("reuse = %d %v", code, out)
	}
	fake, _ := NewSecret(EnrollmentCodePrefix)
	if code, out := enroll(fake); code != http.StatusBadRequest || out["error"] != "invalid_code" {
		t.Fatalf("unknown = %d %v", code, out)
	}
	// A code of an owner who is no longer active.
	raw2, _, _ := e.svc.CreateEnrollmentCode(ctx, bob, "", time.Hour)
	e.st.setStatus(bob, store.UserDisabled)
	if code, out := enroll(raw2); code != http.StatusBadRequest || out["error"] != "invalid_code" {
		t.Fatalf("inactive owner = %d %v", code, out)
	}
	// Revoked codes.
	raw3, c3, _ := e.svc.CreateEnrollmentCode(ctx, alice, "", 7*24*time.Hour)
	if err := e.svc.RevokeEnrollmentCode(ctx, bob, c3.ID); err == nil {
		t.Fatal("bob revoked alice's code")
	}
	if err := e.svc.RevokeEnrollmentCode(ctx, alice, c3.ID); err != nil {
		t.Fatal(err)
	}
	if code, _ := enroll(raw3); code != http.StatusBadRequest {
		t.Fatal("revoked code enrolled")
	}
	acts := strings.Join(e.rec.actions(), ",")
	for _, a := range []string{"machine.enrollment_code_created", "machine.enrolled", "machine.enrollment_code_revoked"} {
		if !strings.Contains(acts, a) {
			t.Errorf("audit lacks %s: %s", a, acts)
		}
	}
	for _, ev := range e.rec.evs {
		for k, v := range ev.ResourceIdentity {
			if strings.Contains(v, raw) || strings.Contains(v, "mge_") || strings.Contains(v, "mgm_") || strings.Contains(v, "mgd_") {
				t.Fatalf("audit %s=%q carries a secret", k, v)
			}
		}
	}
}

func TestReEnrollingTheSameNameReplacesTheOldMachine(t *testing.T) {
	e := newEnv(t)
	id, priv := e.enroll(alice, "laptop")
	tok := e.token(priv, id)
	_, out := e.do(http.MethodPut, "/machine/v1/servers/fusion", "application/json", tok, `{"kind":"stdio"}`)
	tid := out["tunnel_id"].(string)
	id2, priv2 := e.enroll(alice, "laptop")
	if id2 == id {
		t.Fatal("same id")
	}
	old, _ := e.st.Machine(context.Background(), id)
	if old.RevokedAt == nil || old.RevokeReason != store.MachineReplaced {
		t.Fatalf("old machine = %+v", old)
	}
	if got := e.tn.droppedIDs(); len(got) == 0 || got[len(got)-1] != id {
		t.Fatalf("old connection not dropped: %v", got)
	}
	tok2 := e.token(priv2, id2)
	code, out := e.do(http.MethodPut, "/machine/v1/servers/fusion", "application/json", tok2, `{"kind":"stdio"}`)
	if code != http.StatusOK || out["tunnel_id"] != tid || out["created"] != false {
		t.Fatalf("re-enrolled machine's PUT = %d %v (want the moved tunnel)", code, out)
	}
}

func TestMachineCap(t *testing.T) {
	e := newEnv(t)
	e.st.maxMach = 1
	e.enroll(alice, "one")
	body, _ := e.requestDevice("two")
	_, err := e.approve(alice, body["user_code"].(string))
	if err == nil || !strings.Contains(err.Error(), "machines") {
		t.Fatalf("approve over the cap: %v", err)
	}
}
