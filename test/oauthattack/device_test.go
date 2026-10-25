package oauthattack

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/authserver"
	"github.com/huynle/mcp-gateway/internal/store"
)

// Device authorization grant (RFC 8628; RFC 8628 section 5 security
// considerations, RFC 9700 section 4): a harness on a remote host gets a
// device code and a user code, the user allows it at /activate in the
// portal, the harness polls the token endpoint.

// deviceClient is a public client registered for the device grant.
func (g *gateway) deviceClient(t *testing.T) client {
	t.Helper()
	r := g.registerDoc(t, map[string]any{"client_name": "Remote harness", "grant_types": []string{authserver.GrantDeviceCode, "refresh_token"}})
	if r.status != http.StatusCreated {
		t.Fatalf("register device client: %d %s", r.status, r.body)
	}
	return client{id: r.json()["client_id"].(string)}
}

// deviceStart is POST /oauth/device_authorization.
func (g *gateway) deviceStart(t *testing.T, form url.Values) reply {
	t.Helper()
	return postForm(t, noRedirect, g.base+authserver.DeviceAuthorizationPath, form, "User-Agent", "remote-harness/2.0 (ssh)")
}

type deviceCodes struct{ device, user string }

func (g *gateway) startDevice(t *testing.T, c client) deviceCodes {
	t.Helper()
	r := g.deviceStart(t, url.Values{"client_id": {c.id}, "scope": {"mcp"}, "resource": {g.resource}})
	if r.status != http.StatusOK {
		t.Fatalf("device_authorization: %d %s", r.status, r.body)
	}
	out := r.json()
	return deviceCodes{device: out["device_code"].(string), user: out["user_code"].(string)}
}

func (g *gateway) pollDevice(t *testing.T, c client, deviceCode string) reply {
	t.Helper()
	return g.token(t, url.Values{"grant_type": {authserver.GrantDeviceCode}, "device_code": {deviceCode}, "client_id": {c.id}})
}

// activate posts the /activate form with the browser's CSRF token.
func (g *gateway) activate(t *testing.T, br *http.Client, userCode, requestID, action string) reply {
	t.Helper()
	return postForm(t, br, g.base+"/activate", url.Values{"_csrf": {g.csrf(t, br)}, "code": {userCode}, "request_id": {requestID}, "action": {action}})
}

// grantID reads the request id off the /activate confirmation page.
func grantID(t *testing.T, r reply) string {
	t.Helper()
	const marker = `name="request_id" value="`
	i := strings.Index(string(r.body), marker)
	if i < 0 {
		t.Fatalf("no request id on /activate (status %d): %s", r.status, r.body)
	}
	id, _, ok := strings.Cut(string(r.body[i+len(marker):]), `"`)
	if !ok {
		t.Fatal("unterminated request id")
	}
	return id
}

// allow confirms and allows the user code in the browser.
func (g *gateway) allow(t *testing.T, br *http.Client, userCode string) {
	t.Helper()
	page := get(t, br, g.base+"/activate?code="+url.QueryEscape(userCode))
	if r := g.activate(t, br, userCode, grantID(t, page), "approve"); r.status != http.StatusOK || !strings.Contains(string(r.body), "Harness connected") {
		t.Fatalf("allow: %d %s", r.status, r.body)
	}
}

// The happy path end to end through the real portal: the tokens are the
// code flow's (accepted by /mcp, a refresh family alice can disconnect)
// and every step is audited.
func TestDeviceFlowThroughThePortal(t *testing.T) {
	g := newGateway(t)
	c := g.deviceClient(t)
	codes := g.startDevice(t, c)
	wantOAuthError(t, g.pollDevice(t, c, codes.device), http.StatusBadRequest, "authorization_pending")

	// Anonymous: sign in first, with the code kept in the return path.
	r := get(t, g.browser(t, false), g.base+"/activate?code="+codes.user)
	if r.status != http.StatusSeeOther || !strings.HasPrefix(r.location().Path, "/signin") || !strings.Contains(r.location().Query().Get("return_to"), codes.user) {
		t.Fatalf("anonymous /activate: %d %s", r.status, r.header.Get("Location"))
	}
	br := g.browser(t, true)
	page := get(t, br, g.base+"/activate?code="+codes.user)
	for _, want := range []string{"Remote harness", "127.0.0.1", "remote-harness/2.0 (ssh)", "Allow", "Deny"} {
		if !strings.Contains(string(page.body), want) {
			t.Errorf("confirmation page lacks %q", want)
		}
	}
	if page.header.Get("X-Frame-Options") != "DENY" || !strings.Contains(page.header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Errorf("confirmation page framing headers: %v", page.header)
	}
	g.allow(t, br, codes.user)
	g.clock.Advance(5 * time.Second)
	r = g.pollDevice(t, c, codes.device)
	if r.status != http.StatusOK {
		t.Fatalf("redeem: %d %s", r.status, r.body)
	}
	out := r.json()
	g.wantMCPOK(t, out["access_token"].(string))
	ev := wantAudit(t, g, "oauth_device_authorization_requested", "allow", 1)[0]
	if ev.UserID != "" || ev.ResourceIdentity["client_id"] != c.id {
		t.Errorf("requested event = %+v", ev)
	}
	if ev := wantAudit(t, g, "oauth_device_approved", "allow", 1)[0]; ev.UserID != g.alice {
		t.Errorf("approved event = %+v", ev)
	}
	red := wantAudit(t, g, "oauth_device_redeemed", "allow", 1)[0]
	if red.UserID != g.alice || red.TokenID == "" {
		t.Errorf("redeemed event = %+v", red)
	}
	// Disconnect on /harnesses ends it like any harness.
	if err := g.authSvc.RevokeHarness(t.Context(), g.alice, red.TokenID); err != nil {
		t.Fatal(err)
	}
	wantOAuthError(t, g.refresh(t, c, out["refresh_token"].(string)), http.StatusBadRequest, "invalid_grant")
}

// Reusing a redeemed device code fails, and the replay revokes what the
// first redemption issued (the authorization-code replay rule).
func TestDeviceCodeReuseRevokesFamily(t *testing.T) {
	g := newGateway(t)
	c := g.deviceClient(t)
	codes := g.startDevice(t, c)
	g.allow(t, g.browser(t, true), codes.user)
	r := g.pollDevice(t, c, codes.device)
	if r.status != http.StatusOK {
		t.Fatalf("redeem: %d %s", r.status, r.body)
	}
	refresh := r.json()["refresh_token"].(string)
	wantOAuthError(t, g.pollDevice(t, c, codes.device), http.StatusBadRequest, "invalid_grant")
	wantLogEvent(t, g, "authserver.device_code_replayed")
	wantAudit(t, g, "oauth_device_code_replayed", "deny", 1)
	wantOAuthError(t, g.refresh(t, c, refresh), http.StatusBadRequest, "invalid_grant")
	// Still burnt later.
	g.clock.Advance(time.Minute)
	wantOAuthError(t, g.pollDevice(t, c, codes.device), http.StatusBadRequest, "invalid_grant")
}

// Polling faster than the interval is slow_down, and the interval grows
// by 5 seconds each time (RFC 8628 section 3.5).
func TestDevicePollingTooFastIsSlowDown(t *testing.T) {
	g := newGateway(t)
	c := g.deviceClient(t)
	codes := g.startDevice(t, c)
	wantOAuthError(t, g.pollDevice(t, c, codes.device), http.StatusBadRequest, "authorization_pending")
	wantOAuthError(t, g.pollDevice(t, c, codes.device), http.StatusBadRequest, "slow_down")
	g.clock.Advance(6 * time.Second)
	wantOAuthError(t, g.pollDevice(t, c, codes.device), http.StatusBadRequest, "slow_down") // the interval is 10 now
	g.clock.Advance(16 * time.Second)
	wantOAuthError(t, g.pollDevice(t, c, codes.device), http.StatusBadRequest, "authorization_pending")
	g.clock.Advance(16 * time.Second)
	wantOAuthError(t, g.pollDevice(t, c, codes.device), http.StatusBadRequest, "authorization_pending")
}

// User codes cannot be brute forced on /activate: wrong codes are
// limited per user, and once limited even the right code is refused.
func TestDeviceUserCodeBruteForceIsLimited(t *testing.T) {
	g := newGateway(t)
	c := g.deviceClient(t)
	codes := g.startDevice(t, c)
	br := g.browser(t, true)
	limited := false
	for i := range 25 {
		guess := "BCDF-" + string("BCDFGHJKLMNPQRSTVWXZ"[i%20]) + "ZZZ"
		if guess == codes.user {
			continue
		}
		if r := get(t, br, g.base+"/activate?code="+guess); r.status == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("25 wrong user codes were never limited")
	}
	if r := get(t, br, g.base+"/activate?code="+codes.user); r.status != http.StatusTooManyRequests || strings.Contains(string(r.body), "Remote harness") {
		t.Fatalf("right code while limited: %d", r.status)
	}
	wantOAuthError(t, g.pollDevice(t, c, codes.device), http.StatusBadRequest, "authorization_pending")
}

// The resource indicator must be this gateway's /mcp (RFC 8707), as on
// the authorization endpoint; nothing is stored for a refused request.
func TestDeviceAuthorizationResourceMismatch(t *testing.T) {
	g := newGateway(t)
	c := g.deviceClient(t)
	d := g.newDecoy(t, false)
	for name, res := range map[string][]string{
		"decoy resource":   {d.resource},
		"missing":          nil,
		"issuer, not /mcp": {g.base},
		"path suffix":      {g.resource + "/admin"},
		"two resources":    {g.resource, d.resource},
	} {
		t.Run(name, func(t *testing.T) {
			want := "invalid_target"
			if len(res) > 1 {
				want = "invalid_request"
			}
			wantOAuthError(t, g.deviceStart(t, url.Values{"client_id": {c.id}, "scope": {"mcp"}, "resource": res}), http.StatusBadRequest, want)
		})
	}
	if n := len(g.astore.DeviceGrants()); n != 0 {
		t.Fatalf("%d device grants stored from refused requests", n)
	}
}

// A device code is bound to the client that requested it: another client
// presenting it (a stolen code) is invalid_client, and the rightful
// client still gets its tokens.
func TestDeviceCodeWrongClient(t *testing.T) {
	g := newGateway(t)
	c := g.deviceClient(t)
	thief := g.deviceClient(t)
	codes := g.startDevice(t, c)
	g.allow(t, g.browser(t, true), codes.user)
	wantOAuthError(t, g.pollDevice(t, thief, codes.device), http.StatusUnauthorized, "invalid_client")
	wantLogEvent(t, g, "authserver.device_code_wrong_client")
	// A code-flow-only client is not even allowed the grant.
	codeOnly := g.register(t, "http://localhost:1234/cb")
	wantOAuthError(t, g.pollDevice(t, codeOnly, codes.device), http.StatusBadRequest, "unauthorized_client")
	if r := g.pollDevice(t, c, codes.device); r.status != http.StatusOK {
		t.Fatalf("rightful client after the theft attempt: %d %s", r.status, r.body)
	}
}

// After expiry the device code is expired_token and the user code no
// longer resolves.
func TestDeviceCodeExpires(t *testing.T) {
	g := newGateway(t)
	c := g.deviceClient(t)
	codes := g.startDevice(t, c)
	g.clock.Advance(g.cfg.CodeTTL + time.Second)
	wantOAuthError(t, g.pollDevice(t, c, codes.device), http.StatusBadRequest, "expired_token")
	if r := get(t, g.browser(t, true), g.base+"/activate?code="+codes.user); r.status != http.StatusOK || !strings.Contains(string(r.body), "No pending request") {
		t.Fatalf("expired user code: %d %s", r.status, r.body)
	}
}

// A denied grant is access_denied and can never be redeemed or approved
// afterwards.
func TestDeviceGrantDenied(t *testing.T) {
	g := newGateway(t)
	c := g.deviceClient(t)
	codes := g.startDevice(t, c)
	br := g.browser(t, true)
	id := grantID(t, get(t, br, g.base+"/activate?code="+codes.user))
	if r := g.activate(t, br, codes.user, id, "deny"); r.status != http.StatusOK || !strings.Contains(string(r.body), "denied") {
		t.Fatalf("deny: %d %s", r.status, r.body)
	}
	wantAudit(t, g, "oauth_device_denied", "deny", 1)
	wantOAuthError(t, g.pollDevice(t, c, codes.device), http.StatusBadRequest, "access_denied")
	if r := g.activate(t, br, codes.user, id, "approve"); strings.Contains(string(r.body), "Harness connected") {
		t.Fatal("approved after deny")
	}
	g.clock.Advance(30 * time.Second)
	wantOAuthError(t, g.pollDevice(t, c, codes.device), http.StatusBadRequest, "access_denied")
}

// Approving needs the session's CSRF token: a cross-site form post (no
// token, a forged one, or another session's) changes nothing.
func TestDeviceApprovalNeedsCSRF(t *testing.T) {
	g := newGateway(t)
	c := g.deviceClient(t)
	codes := g.startDevice(t, c)
	br := g.browser(t, true)
	id := grantID(t, get(t, br, g.base+"/activate?code="+codes.user))
	other := g.browser(t, true)
	for name, token := range map[string]string{"missing": "", "forged": "not-the-token", "other session": g.csrf(t, other)} {
		r := postForm(t, br, g.base+"/activate", url.Values{"_csrf": {token}, "code": {codes.user}, "request_id": {id}, "action": {"approve"}})
		if r.status != http.StatusForbidden {
			t.Errorf("%s CSRF token: %d", name, r.status)
		}
	}
	wantOAuthError(t, g.pollDevice(t, c, codes.device), http.StatusBadRequest, "authorization_pending")
	if n := len(g.audit.Find("oauth_device_approved")); n != 0 {
		t.Fatalf("%d approvals recorded", n)
	}
}

// verification_uri_complete only fills the form: opening it (or being
// sent it) never approves anything.
func TestDevicePrefilledCodeDoesNotApprove(t *testing.T) {
	g := newGateway(t)
	c := g.deviceClient(t)
	out := g.deviceStart(t, url.Values{"client_id": {c.id}, "resource": {g.resource}}).json()
	complete, _ := out["verification_uri_complete"].(string)
	if !strings.HasPrefix(complete, g.base+"/activate?code=") {
		t.Fatalf("verification_uri_complete = %q", complete)
	}
	br := g.browser(t, true)
	for range 3 {
		if p := get(t, br, complete); p.status != http.StatusOK || !strings.Contains(string(p.body), "Allow") {
			t.Fatalf("prefilled link: %d", p.status)
		}
	}
	wantOAuthError(t, g.pollDevice(t, c, out["device_code"].(string)), http.StatusBadRequest, "authorization_pending")
	if n := len(g.audit.Find("oauth_device_approved")); n != 0 {
		t.Fatalf("%d approvals recorded from GETs", n)
	}
}

// device_authorization is limited per address.
func TestDeviceAuthorizationFlooding(t *testing.T) {
	g := newGateway(t, withEnv(map[string]string{authserver.EnvDevicePerMin: "5"}))
	c := g.deviceClient(t)
	for range 5 {
		g.startDevice(t, c)
	}
	r := g.deviceStart(t, url.Values{"client_id": {c.id}, "resource": {g.resource}})
	wantOAuthError(t, r, http.StatusTooManyRequests, "too_many_requests")
	if r.header.Get("Retry-After") == "" {
		t.Error("no Retry-After")
	}
}

// A client registered only for the device grant cannot use the
// authorization code flow: registration refuses its redirect URIs, and a
// stored device-only client that has one (an older registration) gets
// unauthorized_client at /oauth/authorize, at consent and at the token
// endpoint, never a code.
func TestDeviceOnlyClientCannotUseTheCodeFlow(t *testing.T) {
	g := newGateway(t)
	r := g.registerDoc(t, map[string]any{"grant_types": []string{authserver.GrantDeviceCode, "refresh_token"}, "redirect_uris": []string{"http://localhost:7777/cb"}})
	wantOAuthError(t, r, http.StatusBadRequest, "invalid_redirect_uri")

	// Without redirect URIs the authorization endpoint has nowhere to
	// send it: an error page.
	dev := g.deviceClient(t)
	p := newPKCE(t)
	br := g.browser(t, true)
	wantErrorPage(t, g.authorize(t, br, g.authorizeParams(client{id: dev.id, redirect: "http://localhost:7777/cb"}, p, "s1")))

	// A stored device-only client with a registered redirect URI.
	stored := &store.OAuthClient{ClientID: "gwc_stored_device_only", ClientName: "Stored", RedirectURIs: []string{"http://localhost:7777/cb"},
		Metadata: []byte(`{"token_endpoint_auth_method":"none","grant_types":["` + authserver.GrantDeviceCode + `","refresh_token"],"response_types":[]}`)}
	if err := g.astore.Bypass(t.Context(), func(tx authserver.Tx) error { return tx.CreateClient(t.Context(), stored) }); err != nil {
		t.Fatal(err)
	}
	c := client{id: stored.ClientID, redirect: "http://localhost:7777/cb"}
	q := g.authorizeParams(c, p, "s2")
	wantRedirectError(t, g.authorize(t, br, q), c.redirect, "unauthorized_client", "s2")
	wantRedirectError(t, g.consent(t, br, q, "approve"), c.redirect, "unauthorized_client", "s2")
	if n := len(g.astore.Codes()); n != 0 {
		t.Fatalf("%d codes issued to a device-only client", n)
	}
	wantOAuthError(t, g.token(t, g.exchangeForm(c, "any-code", p)), http.StatusBadRequest, "unauthorized_client")
}
