package oauthattack

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Refresh token attacks (OAuth 2.1 section 4.3.1, RFC 9700 section 4.14):
// rotation on every use, reuse of a rotated token revokes the family,
// and a token stops working with its owner.

// TestRefreshReuseAfterRotationRevokesFamily: presenting a rotated
// refresh token again is theft: the whole family (including the newest
// token) is revoked and audited.
func TestRefreshReuseAfterRotationRevokesFamily(t *testing.T) {
	g := newGateway(t)
	br := g.browser(t, true)
	c := g.register(t, "https://app.example.com/cb")
	pair := g.issue(t, br, c)

	r := g.refresh(t, c, pair.refresh)
	if r.status != http.StatusOK {
		t.Fatalf("first refresh: %d %s", r.status, r.body)
	}
	next := r.json()["refresh_token"].(string)
	if next == pair.refresh {
		t.Fatal("refresh token not rotated")
	}
	g.wantMCPOK(t, r.json()["access_token"].(string))

	// Reuse of the old one.
	desc := wantOAuthError(t, g.refresh(t, c, pair.refresh), http.StatusBadRequest, "invalid_grant")
	if !strings.Contains(desc, "already used") {
		t.Errorf("description = %q", desc)
	}
	rec := wantLogEvent(t, g, "authserver.refresh_reuse")
	if rec.Attrs["client_id"] != c.id || rec.Attrs["user_id"] != g.alice {
		t.Errorf("log = %v", rec.Attrs)
	}
	evs := wantAudit(t, g, "oauth_refresh_reuse", "deny", 1)
	if evs[0].TokenID == "" || evs[0].ResourceIdentity["client_id"] != c.id {
		t.Errorf("audit = %+v", evs[0])
	}
	// The newest token is dead too.
	desc = wantOAuthError(t, g.refresh(t, c, next), http.StatusBadRequest, "invalid_grant")
	if !strings.Contains(desc, "revoked") {
		t.Errorf("newest token after reuse: %q", desc)
	}
	// Reusing again does not record a second reuse (already revoked wins).
	wantOAuthError(t, g.refresh(t, c, pair.refresh), http.StatusBadRequest, "invalid_grant")
	wantAudit(t, g, "oauth_refresh_reuse", "deny", 1)
	// The harness shows as revoked.
	page := get(t, br, g.base+"/harnesses")
	if page.status != http.StatusOK || !strings.Contains(string(page.body), "revoked") {
		t.Errorf("harnesses page: %d", page.status)
	}
}

// TestRefreshByOtherClient: a refresh token is bound to its client; another
// client presenting it gets invalid_grant, it is logged, and the token
// is not rotated or revoked by the attempt (the legitimate client is not
// punished for a leak it did not cause... but reuse detection still
// protects it on its next refresh).
func TestRefreshByOtherClient(t *testing.T) {
	g := newGateway(t)
	br := g.browser(t, true)
	victim := g.register(t, "https://app.example.com/cb")
	attacker := g.register(t, "https://attacker.example/cb")
	pair := g.issue(t, br, victim)
	desc := wantOAuthError(t, g.refresh(t, attacker, pair.refresh), http.StatusBadRequest, "invalid_grant")
	if !strings.Contains(desc, "not issued to this client") {
		t.Errorf("description = %q", desc)
	}
	rec := wantLogEvent(t, g, "authserver.refresh_wrong_client")
	if rec.Attrs["client_id"] != attacker.id {
		t.Errorf("log = %v", rec.Attrs)
	}
	if r := g.refresh(t, victim, pair.refresh); r.status != http.StatusOK {
		t.Errorf("victim's refresh after the attempt: %d %s", r.status, r.body)
	}
	// An unknown client id is invalid_client regardless of the token.
	wantOAuthError(t, g.refresh(t, client{id: "gwc_nope"}, pair.refresh), http.StatusUnauthorized, "invalid_client")
	// An unknown / malformed refresh token is invalid_grant.
	for _, bad := range []string{"gwr_nope", "", strings.Repeat("x", 5000), pair.access} {
		form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {bad}, "client_id": {victim.id}}
		want := "invalid_grant"
		if bad == "" {
			want = "invalid_request"
		}
		wantOAuthError(t, g.token(t, form), http.StatusBadRequest, want)
	}
}

// TestRefreshOfDisabledUser: disabling the user revokes every family
// through the identity hook, so the refresh fails; and a user whose
// status is disabled without the hook (another replica's view) is refused
// by the refresh check itself.
func TestRefreshOfDisabledUser(t *testing.T) {
	g := newGateway(t)
	br := g.browser(t, true)
	c := g.register(t, "https://app.example.com/cb")
	pair := g.issue(t, br, c)
	t.Run("status_check", func(t *testing.T) {
		g.astore.SetUser(g.alice, "disabled", nil)
		desc := wantOAuthError(t, g.refresh(t, c, pair.refresh), http.StatusBadRequest, "invalid_grant")
		if !strings.Contains(desc, "disabled") {
			t.Errorf("description = %q", desc)
		}
		signedIn := t0.Add(-time.Hour)
		g.astore.SetUser(g.alice, "active", &signedIn)
	})
	t.Run("disable_hook_revokes", func(t *testing.T) {
		if err := g.idSvc.DisableUser(t.Context(), "", g.alice); err != nil {
			t.Fatal(err)
		}
		wantLogEvent(t, g, "authserver.revoked_on_disable")
		desc := wantOAuthError(t, g.refresh(t, c, pair.refresh), http.StatusBadRequest, "invalid_grant")
		if !strings.Contains(desc, "revoked") {
			t.Errorf("description = %q", desc)
		}
		// The session is gone as well: authorize redirects to sign-in.
		r := g.authorize(t, br, g.authorizeParams(c, newPKCE(t), "s"))
		if r.status != http.StatusSeeOther || r.location().Path != "/signin" {
			t.Errorf("authorize as a disabled user: %d %s", r.status, r.header.Get("Location"))
		}
		// Re-enabling restores nothing.
		if err := g.idSvc.EnableUser(t.Context(), "", g.alice); err != nil {
			t.Fatal(err)
		}
		wantOAuthError(t, g.refresh(t, c, pair.refresh), http.StatusBadRequest, "invalid_grant")
	})
}

// TestRefreshAfterSignInMaxAge: a refresh token stops working once the
// owner's last company sign-in is older than GATEWAY_TOKEN_SIGNIN_MAX_AGE
// (decision uamxx6ba), well before the refresh token's own 30 days; a
// fresh sign-in restores it.
func TestRefreshAfterSignInMaxAge(t *testing.T) {
	g := newGateway(t, withSignInMaxAge(24*time.Hour))
	br := g.browser(t, true)
	c := g.register(t, "https://app.example.com/cb")
	pair := g.issue(t, br, c)
	g.clock.Advance(23 * time.Hour)
	r := g.refresh(t, c, pair.refresh)
	if r.status != http.StatusOK {
		t.Fatalf("refresh inside the window: %d %s", r.status, r.body)
	}
	next := r.json()["refresh_token"].(string)
	g.clock.Advance(2 * time.Hour) // last sign-in was t0-1h: now 26h ago
	desc := wantOAuthError(t, g.refresh(t, c, next), http.StatusBadRequest, "invalid_grant")
	if !strings.Contains(desc, "sign in to the portal") {
		t.Errorf("description = %q", desc)
	}
	// Not rotated by the refusal, not revoked: a new company sign-in
	// reactivates the harness.
	now := g.clock.Now()
	g.astore.SetUser(g.alice, "active", &now)
	if r := g.refresh(t, c, next); r.status != http.StatusOK {
		t.Errorf("refresh after a new sign-in: %d %s", r.status, r.body)
	}
	t.Run("never_signed_in", func(t *testing.T) {
		g.astore.SetUser(g.alice, "active", nil)
		pair := g.issue(t, br, c)
		wantOAuthError(t, g.refresh(t, c, pair.refresh), http.StatusBadRequest, "invalid_grant")
	})
}

// TestRefreshExpiry: the refresh token's own lifetime is enforced.
func TestRefreshExpiry(t *testing.T) {
	g := newGateway(t, withEnv(map[string]string{"GATEWAY_OAUTH_REFRESH_TOKEN_TTL": "48h"}), withSignInMaxAge(365*24*time.Hour))
	br := g.browser(t, true)
	c := g.register(t, "https://app.example.com/cb")
	pair := g.issue(t, br, c)
	g.clock.Advance(49 * time.Hour)
	desc := wantOAuthError(t, g.refresh(t, c, pair.refresh), http.StatusBadRequest, "invalid_grant")
	if !strings.Contains(desc, "expired") {
		t.Errorf("description = %q", desc)
	}
}

// TestRevokedHarnessRefreshFails: the user disconnects the harness on
// /harnesses (CSRF-protected), and the client's own RFC 7009 revocation,
// each end the family; a revoked token presented again is invalid_grant
// and is not a reuse event.
func TestRevokedHarnessRefreshFails(t *testing.T) {
	g := newGateway(t)
	br := g.browser(t, true)
	c := g.register(t, "https://app.example.com/cb")
	t.Run("portal_disconnect", func(t *testing.T) {
		pair := g.issue(t, br, c)
		family := familyOf(t, g, pair.refresh)
		// Without the CSRF token the portal refuses.
		if r := postForm(t, br, g.base+"/harnesses/"+family+"/revoke", url.Values{}); r.status != http.StatusForbidden {
			t.Errorf("revoke without CSRF: %d", r.status)
		}
		// Another user's session (a second account) cannot revoke it.
		if r := postForm(t, br, g.base+"/harnesses/00000000-0000-4000-8000-000000000bad/revoke", url.Values{"_csrf": {g.csrf(t, br)}}); r.status != http.StatusNotFound {
			t.Errorf("revoke an unknown family: %d", r.status)
		}
		if r := postForm(t, br, g.base+"/harnesses/"+family+"/revoke", url.Values{"_csrf": {g.csrf(t, br)}}); r.status != http.StatusSeeOther {
			t.Fatalf("revoke: %d %s", r.status, r.body)
		}
		wantAudit(t, g, "oauth_harness_revoked", "allow", 1)
		desc := wantOAuthError(t, g.refresh(t, c, pair.refresh), http.StatusBadRequest, "invalid_grant")
		if !strings.Contains(desc, "revoked") {
			t.Errorf("description = %q", desc)
		}
		wantAudit(t, g, "oauth_refresh_reuse", "deny", 0)
	})
	t.Run("rfc7009_revoke", func(t *testing.T) {
		pair := g.issue(t, br, c)
		r := g.token(t, url.Values{"token": {pair.refresh}, "client_id": {c.id}}) // wrong endpoint: token
		wantOAuthError(t, r, http.StatusBadRequest, "invalid_request")
		revoke := func(token, clientID string) reply {
			return postForm(t, noRedirect, g.base+"/oauth/revoke", url.Values{"token": {token}, "client_id": {clientID}})
		}
		// Another client cannot revoke it (200 by the RFC, nothing happens).
		other := g.register(t, "https://other.example/cb")
		if r := revoke(pair.refresh, other.id); r.status != http.StatusOK {
			t.Errorf("revoke by another client: %d", r.status)
		}
		r = g.refresh(t, c, pair.refresh)
		if r.status != http.StatusOK {
			t.Fatalf("refresh after a foreign revoke: %d %s", r.status, r.body)
		}
		next := r.json()["refresh_token"].(string)
		if r := revoke(next, c.id); r.status != http.StatusOK {
			t.Fatalf("revoke: %d %s", r.status, r.body)
		}
		wantAudit(t, g, "oauth_harness_revoked_by_client", "allow", 1)
		wantOAuthError(t, g.refresh(t, c, next), http.StatusBadRequest, "invalid_grant")
		// Unknown token and an unknown client: 200 and invalid_client.
		if r := revoke("gwr_nope", c.id); r.status != http.StatusOK {
			t.Errorf("revoke unknown token: %d", r.status)
		}
		wantOAuthError(t, revoke(next, "gwc_nope"), http.StatusUnauthorized, "invalid_client")
		wantOAuthError(t, postForm(t, noRedirect, g.base+"/oauth/revoke", url.Values{"client_id": {c.id}}), http.StatusBadRequest, "invalid_request")
	})
}

// TestRefreshScopeWidening: a refresh may narrow the scope, never widen it.
func TestRefreshScopeWidening(t *testing.T) {
	g := newGateway(t)
	br := g.browser(t, true)
	c := g.register(t, "https://app.example.com/cb")
	p := newPKCE(t)
	q := g.authorizeParams(c, p, "s")
	q.Set("scope", "mcp:read")
	if r := g.authorize(t, br, q); r.status != http.StatusOK {
		t.Fatalf("authorize: %d", r.status)
	}
	code := g.consent(t, br, q, "approve").location().Query().Get("code")
	r := g.token(t, g.exchangeForm(c, code, p))
	if r.status != http.StatusOK || r.json()["scope"] != "mcp:read" {
		t.Fatalf("exchange: %d %s", r.status, r.body)
	}
	refresh := r.json()["refresh_token"].(string)
	wantOAuthError(t, g.refresh(t, c, refresh, "scope", "mcp"), http.StatusBadRequest, "invalid_scope")
	wantOAuthError(t, g.refresh(t, c, refresh, "scope", "mcp mcp:read"), http.StatusBadRequest, "invalid_scope")
	wantOAuthError(t, g.refresh(t, c, refresh, "scope", "admin"), http.StatusBadRequest, "invalid_scope")
	// Not rotated by the refusals.
	r = g.refresh(t, c, refresh, "scope", "mcp:read")
	if r.status != http.StatusOK || r.json()["scope"] != "mcp:read" {
		t.Fatalf("refresh with the same scope: %d %s", r.status, r.body)
	}
	// The read-only token cannot run a write tool.
	call := postJSON(t, noRedirect, g.resource, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fake.create_item","arguments":{"name":"x"}}}`,
		"Accept", "application/json, text/event-stream", "Authorization", "Bearer "+r.json()["access_token"].(string))
	if call.status != http.StatusOK || !strings.Contains(string(call.body), `"error"`) {
		t.Errorf("write with a read-only token: %d %s", call.status, call.body)
	}
}

// familyOf finds the family id of a refresh token through the store.
func familyOf(t *testing.T, g *gateway, raw string) string {
	t.Helper()
	for _, rt := range g.astore.RefreshTokens() {
		if string(rt.TokenHash) == string(hashSecret(raw)) {
			return rt.FamilyID
		}
	}
	t.Fatal("refresh token not found")
	return ""
}
