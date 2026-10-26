package authserver_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/authserver"
	"github.com/huynle/mcp-gateway/internal/store"
)

// The device authorization grant (RFC 8628) for harnesses on hosts
// without a browser: POST /oauth/device_authorization, the user allows
// the request at /activate (LookupDeviceGrant / ApproveDeviceGrant /
// DenyDeviceGrant, driven by the machines portal), the harness polls
// POST /oauth/token with the device_code grant.

const sshUserAgent = "remote-harness/1.4 (linux; ssh)"

var userCodeRE = regexp.MustCompile(`^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$`)

// deviceFlow is a flow with a public client registered for the device grant.
type deviceFlow struct {
	*flow
	deviceClient string
}

func newDeviceFlow(t *testing.T, mutate ...func(*authserver.Config)) *deviceFlow {
	t.Helper()
	fx := newService(t, mutate...)
	fl := &flow{svcFixture: fx, t: t, user: alice}
	fl.svc.SetIdentity(func(*http.Request) (string, string) { return fl.user, csrf })
	code, out := fl.register(t, map[string]any{"client_name": "Remote Claude", "grant_types": []string{authserver.GrantDeviceCode, "refresh_token"}})
	if code != http.StatusCreated {
		t.Fatalf("register device client: %d %v", code, out)
	}
	return &deviceFlow{flow: fl, deviceClient: out["client_id"].(string)}
}

func (f *deviceFlow) deviceParams() url.Values {
	return url.Values{"client_id": {f.deviceClient}, "scope": {"mcp"}, "resource": {f.cfg.Resource()}}
}

func (f *deviceFlow) deviceAuthorize(form url.Values) (int, map[string]any, http.Header) {
	f.t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, authserver.DeviceAuthorizationPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", sshUserAgent)
	rec := httptest.NewRecorder()
	f.svc.ServeDeviceAuthorization(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out, rec.Header()
}

// start runs device_authorization and returns the device and user codes.
func (f *deviceFlow) start() (deviceCode, userCode string) {
	f.t.Helper()
	status, out, _ := f.deviceAuthorize(f.deviceParams())
	if status != http.StatusOK {
		f.t.Fatalf("device_authorization: %d %v", status, out)
	}
	return out["device_code"].(string), out["user_code"].(string)
}

func (f *deviceFlow) poll(deviceCode string) (int, map[string]any) {
	return f.token(url.Values{"grant_type": {authserver.GrantDeviceCode}, "device_code": {deviceCode}, "client_id": {f.deviceClient}})
}

// approve looks the user code up and allows it as alice.
func (f *deviceFlow) approve(userCode string) *authserver.DeviceGrantView {
	f.t.Helper()
	v, err := f.svc.LookupDeviceGrant(context.Background(), userCode)
	if err != nil {
		f.t.Fatalf("lookup %s: %v", userCode, err)
	}
	if _, err := f.svc.ApproveDeviceGrant(context.Background(), alice, v.ID); err != nil {
		f.t.Fatalf("approve: %v", err)
	}
	return v
}

func TestRegisterDeviceClient(t *testing.T) {
	f := newService(t, func(c *authserver.Config) { c.RegisterPerMin = 100 })
	code, out := f.register(t, map[string]any{"client_name": "Remote Claude", "grant_types": []string{authserver.GrantDeviceCode, "refresh_token"}})
	if code != http.StatusCreated {
		t.Fatalf("device-only client: %d %v", code, out)
	}
	if g, _ := out["grant_types"].([]any); len(g) != 2 || g[0] != authserver.GrantDeviceCode {
		t.Errorf("grant_types = %v", out["grant_types"])
	}
	if r, ok := out["redirect_uris"].([]any); !ok || len(r) != 0 {
		t.Errorf("redirect_uris = %v, want []", out["redirect_uris"])
	}
	if r, ok := out["response_types"].([]any); !ok || len(r) != 0 {
		t.Errorf("response_types = %v, want []", out["response_types"])
	}
	// Both flows in one registration.
	code, out = f.register(t, map[string]any{"redirect_uris": []string{redirectURI}, "grant_types": []string{"authorization_code", authserver.GrantDeviceCode, "refresh_token"}})
	if code != http.StatusCreated {
		t.Fatalf("code + device client: %d %v", code, out)
	}
	for name, doc := range map[string]map[string]any{
		"confidential device client":  {"grant_types": []string{authserver.GrantDeviceCode}, "token_endpoint_auth_method": "client_secret_post"},
		"device client asks for code": {"grant_types": []string{authserver.GrantDeviceCode}, "response_types": []string{"code"}},
		"refresh only":                {"grant_types": []string{"refresh_token"}, "redirect_uris": []string{redirectURI}},
	} {
		if code, out := f.register(t, doc); code != http.StatusBadRequest || out["error"] != "invalid_client_metadata" {
			t.Errorf("%s: %d %v", name, code, out)
		}
	}
}

func TestDeviceAuthorizationIssuesCodes(t *testing.T) {
	f := newDeviceFlow(t)
	status, out, h := f.deviceAuthorize(f.deviceParams())
	if status != http.StatusOK || h.Get("Cache-Control") != "no-store" {
		t.Fatalf("device_authorization: %d %v %v", status, out, h)
	}
	dc, _ := out["device_code"].(string)
	uc, _ := out["user_code"].(string)
	if !strings.HasPrefix(dc, authserver.DeviceCodePrefix) || len(dc) < 40 || !userCodeRE.MatchString(uc) {
		t.Fatalf("codes = %q / %q", dc, uc)
	}
	want := map[string]any{
		"verification_uri":          "https://gw.example.com/activate",
		"verification_uri_complete": "https://gw.example.com/activate?code=" + uc,
		"expires_in":                float64(600),
		"interval":                  float64(5),
	}
	for k, v := range want {
		if out[k] != v {
			t.Errorf("%s = %v, want %v", k, out[k], v)
		}
	}
	grants := f.st.DeviceGrants()
	if len(grants) != 1 {
		t.Fatalf("%d grants stored", len(grants))
	}
	g := grants[0]
	if bytes.Contains(g.DeviceCodeHash, []byte(dc)) || bytes.Contains(g.UserCodeHash, []byte(strings.ReplaceAll(uc, "-", ""))) || len(g.DeviceCodeHash) != 32 || len(g.UserCodeHash) != 32 {
		t.Errorf("codes not stored as hashes: %+v", g)
	}
	if g.Status != store.OAuthDevicePending || g.Scope != "mcp" || g.Resource != f.cfg.Resource() || g.RequestIP != f.ip || g.UserAgent != sshUserAgent ||
		g.Interval != 5 || !g.ExpiresAt.Equal(t0.Add(10*time.Minute)) || g.UserID != "" {
		t.Errorf("stored grant = %+v", g)
	}
}

func TestDeviceAuthorizationRefusesBadRequests(t *testing.T) {
	// Invalid attempts spend the per-IP budget too.
	f := newDeviceFlow(t, func(c *authserver.Config) { c.DevicePerMin = 100 })
	codeClient := newFlow(t) // authorization_code-only client on another service: unknown here
	_, out := f.register(t, map[string]any{"redirect_uris": []string{redirectURI}})
	codeOnly := out["client_id"].(string)
	for name, c := range map[string]struct {
		mutate func(url.Values)
		status int
		code   string
	}{
		"unknown client":   {func(q url.Values) { q.Set("client_id", codeClient.clientID) }, http.StatusUnauthorized, "invalid_client"},
		"no client":        {func(q url.Values) { q.Del("client_id") }, http.StatusBadRequest, "invalid_request"},
		"code-only client": {func(q url.Values) { q.Set("client_id", codeOnly) }, http.StatusBadRequest, "unauthorized_client"},
		"bad scope":        {func(q url.Values) { q.Set("scope", "mcp admin") }, http.StatusBadRequest, "invalid_scope"},
		"no resource":      {func(q url.Values) { q.Del("resource") }, http.StatusBadRequest, "invalid_target"},
		"other resource":   {func(q url.Values) { q.Set("resource", "https://gw.example.com/other") }, http.StatusBadRequest, "invalid_target"},
		"other origin":     {func(q url.Values) { q.Set("resource", "https://evil.example.com/mcp") }, http.StatusBadRequest, "invalid_target"},
		"two resources":    {func(q url.Values) { q["resource"] = []string{f.cfg.Resource(), f.cfg.Resource()} }, http.StatusBadRequest, "invalid_request"},
	} {
		t.Run(name, func(t *testing.T) {
			q := f.deviceParams()
			c.mutate(q)
			status, out, _ := f.deviceAuthorize(q)
			if status != c.status || out["error"] != c.code {
				t.Errorf("%d %v; want %d %s", status, out, c.status, c.code)
			}
		})
	}
	// mcp:read is a valid narrower scope; an empty scope means mcp.
	for _, scope := range []string{"mcp:read", ""} {
		q := f.deviceParams()
		q.Set("scope", scope)
		if status, out, _ := f.deviceAuthorize(q); status != http.StatusOK {
			t.Errorf("scope %q: %d %v", scope, status, out)
		}
	}
	if n := len(f.st.DeviceGrants()); n != 2 {
		t.Errorf("%d grants stored, want only the 2 valid ones", n)
	}
	// JSON is not a form.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, authserver.DeviceAuthorizationPath, strings.NewReader(`{"client_id":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	f.svc.ServeDeviceAuthorization(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("JSON body: %d", rec.Code)
	}
}

func TestDeviceAuthorizationRateLimits(t *testing.T) {
	f := newDeviceFlow(t, func(c *authserver.Config) { c.DevicePerMin = 3 })
	for range 3 {
		f.start()
	}
	status, out, h := f.deviceAuthorize(f.deviceParams())
	if status != http.StatusTooManyRequests || out["error"] != "too_many_requests" || h.Get("Retry-After") == "" {
		t.Fatalf("4th request from one address: %d %v %v", status, out, h)
	}
	f.ip = "203.0.113.99"
	if status, out, _ := f.deviceAuthorize(f.deviceParams()); status != http.StatusOK {
		t.Fatalf("another address: %d %v", status, out)
	}
}

func TestDeviceAuthorizationCapsPendingGrantsPerClient(t *testing.T) {
	f := newDeviceFlow(t, func(c *authserver.Config) { c.DevicePerMin = 100 })
	for range authserver.MaxPendingDeviceGrants {
		f.start()
	}
	status, out, h := f.deviceAuthorize(f.deviceParams())
	if status != http.StatusTooManyRequests || h.Get("Retry-After") == "" {
		t.Fatalf("over the pending cap: %d %v", status, out)
	}
	// Expired grants do not count.
	f.now = t0.Add(11 * time.Minute)
	if status, out, _ := f.deviceAuthorize(f.deviceParams()); status != http.StatusOK {
		t.Fatalf("after expiry: %d %v", status, out)
	}
}

func TestDeviceFlowIssuesTheCodeFlowsTokens(t *testing.T) {
	f := newDeviceFlow(t)
	dc, uc := f.start()
	if status, out := f.poll(dc); status != http.StatusBadRequest || out["error"] != "authorization_pending" {
		t.Fatalf("first poll: %d %v", status, out)
	}
	f.now = f.now.Add(5 * time.Second)

	// Case- and hyphen-insensitive lookup; the view carries what the
	// approval page shows.
	v, err := f.svc.LookupDeviceGrant(context.Background(), strings.ToLower(strings.ReplaceAll(uc, "-", " ")))
	if err != nil {
		t.Fatal(err)
	}
	if v.UserCode != uc || v.ClientName != "Remote Claude" || v.ClientID != f.deviceClient || v.Scope != "mcp" || len(v.Scopes) != 1 ||
		v.RequestIP != f.ip || v.UserAgent != sshUserAgent || !v.ExpiresAt.Equal(t0.Add(10*time.Minute)) {
		t.Fatalf("view = %+v", v)
	}
	if _, err := f.svc.ApproveDeviceGrant(context.Background(), alice, v.ID); err != nil {
		t.Fatal(err)
	}
	status, out := f.poll(dc)
	if status != http.StatusOK {
		t.Fatalf("poll after approval: %d %v", status, out)
	}
	if out["token_type"] != "Bearer" || out["expires_in"] != float64(3600) || out["scope"] != "mcp" || !strings.HasPrefix(out["refresh_token"].(string), authserver.RefreshTokenPrefix) {
		t.Errorf("response = %v", out)
	}
	p, err := f.svc.Authenticator().Authenticate(context.Background(), out["access_token"].(string))
	if err != nil {
		t.Fatalf("access token rejected: %v", err)
	}
	rows := f.st.RefreshTokens()
	if len(rows) != 1 || p.UserID != alice || p.TokenID != rows[0].FamilyID || rows[0].Resource != f.cfg.Resource() {
		t.Fatalf("principal %+v, refresh rows %+v", p, rows)
	}
	g := f.st.DeviceGrants()[0]
	if g.Status != store.OAuthDeviceRedeemed || g.UserID != alice || g.FamilyID == nil || *g.FamilyID != rows[0].FamilyID {
		t.Errorf("grant after redemption = %+v", g)
	}
	// It is a connected harness like any other: listed, refreshable, and
	// Disconnect ends it.
	hs, err := f.svc.ListHarnesses(context.Background(), alice)
	if err != nil || len(hs) != 1 || hs[0].ClientName != "Remote Claude" {
		t.Fatalf("harnesses = %+v, %v", hs, err)
	}
	refresh := out["refresh_token"].(string)
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {f.deviceClient}}
	status, out = f.token(form)
	if status != http.StatusOK {
		t.Fatalf("refresh: %d %v", status, out)
	}
	if err := f.svc.RevokeHarness(context.Background(), alice, hs[0].FamilyID); err != nil {
		t.Fatal(err)
	}
	form.Set("refresh_token", out["refresh_token"].(string))
	if status, out := f.token(form); status != http.StatusBadRequest || out["error"] != "invalid_grant" {
		t.Errorf("refresh after disconnect: %d %v", status, out)
	}
}

func TestDevicePollingSlowDown(t *testing.T) {
	f := newDeviceFlow(t)
	dc, _ := f.start()
	f.poll(dc)
	if status, out := f.poll(dc); status != http.StatusBadRequest || out["error"] != "slow_down" {
		t.Fatalf("immediate second poll: %d %v", status, out)
	}
	if g := f.st.DeviceGrants()[0]; g.Interval != 10 {
		t.Fatalf("interval after slow_down = %d, want 10", g.Interval)
	}
	// The raised interval applies from the last poll.
	f.now = f.now.Add(6 * time.Second)
	if status, out := f.poll(dc); out["error"] != "slow_down" {
		t.Fatalf("poll 6s later at interval 10: %d %v", status, out)
	}
	f.now = f.now.Add(15 * time.Second)
	if status, out := f.poll(dc); out["error"] != "authorization_pending" {
		t.Fatalf("poll after the interval: %d %v", status, out)
	}
}

func TestDevicePollingErrors(t *testing.T) {
	f := newDeviceFlow(t)
	dc, uc := f.start()

	if status, out := f.poll("gwd_unknown"); status != http.StatusBadRequest || out["error"] != "invalid_grant" {
		t.Errorf("unknown device code: %d %v", status, out)
	}
	if status, out := f.token(url.Values{"grant_type": {authserver.GrantDeviceCode}, "client_id": {f.deviceClient}}); status != http.StatusBadRequest || out["error"] != "invalid_request" {
		t.Errorf("missing device code: %d %v", status, out)
	}
	// Another (device-capable) client presenting the code.
	_, other := f.register(t, map[string]any{"grant_types": []string{authserver.GrantDeviceCode}})
	if status, out := f.token(url.Values{"grant_type": {authserver.GrantDeviceCode}, "device_code": {dc}, "client_id": {other["client_id"].(string)}}); status != http.StatusUnauthorized || out["error"] != "invalid_client" {
		t.Errorf("wrong client: %d %v", status, out)
	}
	// A client not registered for the grant.
	_, codeOnly := f.register(t, map[string]any{"redirect_uris": []string{redirectURI}})
	if status, out := f.token(url.Values{"grant_type": {authserver.GrantDeviceCode}, "device_code": {dc}, "client_id": {codeOnly["client_id"].(string)}}); status != http.StatusBadRequest || out["error"] != "unauthorized_client" {
		t.Errorf("code-only client: %d %v", status, out)
	}

	// Denied.
	v, err := f.svc.LookupDeviceGrant(context.Background(), uc)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.DenyDeviceGrant(context.Background(), alice, v.ID); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		f.now = f.now.Add(time.Minute)
		if status, out := f.poll(dc); status != http.StatusBadRequest || out["error"] != "access_denied" {
			t.Errorf("denied: %d %v", status, out)
		}
	}
	if _, err := f.svc.ApproveDeviceGrant(context.Background(), alice, v.ID); !errors.Is(err, authserver.ErrDeviceGrantGone) {
		t.Errorf("approve after deny = %v", err)
	}
	if _, err := f.svc.LookupDeviceGrant(context.Background(), uc); !errors.Is(err, authserver.ErrDeviceGrantGone) {
		t.Errorf("lookup after deny = %v", err)
	}

	// Expired.
	dc2, uc2 := f.start()
	f.now = f.now.Add(10*time.Minute + time.Second)
	if _, err := f.svc.LookupDeviceGrant(context.Background(), uc2); !errors.Is(err, authserver.ErrDeviceGrantGone) {
		t.Errorf("lookup after expiry = %v", err)
	}
	if status, out := f.poll(dc2); status != http.StatusBadRequest || out["error"] != "expired_token" {
		t.Errorf("expired: %d %v", status, out)
	}
	if _, err := f.svc.LookupDeviceGrant(context.Background(), "not a code"); !errors.Is(err, authserver.ErrDeviceGrantGone) {
		t.Errorf("lookup of garbage = %v", err)
	}
}

func TestDeviceCodeIsSingleUseAndReplayRevokesFamily(t *testing.T) {
	f := newDeviceFlow(t)
	dc, uc := f.start()
	f.approve(uc)
	status, out := f.poll(dc)
	if status != http.StatusOK {
		t.Fatalf("redeem: %d %v", status, out)
	}
	refresh := out["refresh_token"].(string)
	f.now = f.now.Add(time.Minute)
	if status, out := f.poll(dc); status != http.StatusBadRequest || out["error"] != "invalid_grant" {
		t.Fatalf("replay: %d %v", status, out)
	}
	for _, rt := range f.st.RefreshTokens() {
		if rt.RevokedAt == nil {
			t.Errorf("refresh token %s not revoked after device code replay", rt.ID)
		}
	}
	if status, out := f.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {f.deviceClient}}); out["error"] != "invalid_grant" {
		t.Errorf("refresh after replay: %d %v", status, out)
	}
	if _, err := f.svc.LookupDeviceGrant(context.Background(), uc); !errors.Is(err, authserver.ErrDeviceGrantGone) {
		t.Errorf("lookup after redemption = %v", err)
	}
}

func TestDeviceRedemptionRefusesDisabledUser(t *testing.T) {
	f := newDeviceFlow(t)
	dc, uc := f.start()
	f.approve(uc)
	f.st.SetUser(alice, store.UserDisabled, nil)
	if status, out := f.poll(dc); status != http.StatusBadRequest || out["error"] != "invalid_grant" {
		t.Errorf("disabled user: %d %v", status, out)
	}
	if n := len(f.st.RefreshTokens()); n != 0 {
		t.Errorf("%d refresh tokens issued for a disabled user", n)
	}
}

func TestDeviceReadScopeAndPrune(t *testing.T) {
	f := newDeviceFlow(t)
	q := f.deviceParams()
	q.Set("scope", "mcp:read")
	_, out, _ := f.deviceAuthorize(q)
	dc, uc := out["device_code"].(string), out["user_code"].(string)
	if v := f.approve(uc); v.Scope != "mcp:read" {
		t.Errorf("view scope = %q", v.Scope)
	}
	status, out := f.poll(dc)
	if status != http.StatusOK || out["scope"] != "mcp:read" {
		t.Fatalf("read-only redemption: %d %v", status, out)
	}
	f.start()
	f.now = f.now.Add(11 * time.Minute)
	if _, _, err := f.svc.Prune(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := len(f.st.DeviceGrants()); n != 0 {
		t.Errorf("%d device grants left after pruning", n)
	}
}
