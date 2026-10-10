package oauthattack

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Authorization code attacks (RFC 9700 section 4.5 code injection, OAuth
// 2.1 sections 4.1.3 and 7.5, MCP spec "Authorization Code Protection"):
// a code is single use and bound to the client, the redirect URI, the
// resource and the PKCE challenge; a replay revokes what it produced.

// TestCodeReplayRevokesFamily: the second exchange of a code is
// invalid_grant, the refresh-token family it produced is revoked (the
// first refresh token stops working) and the replay is audited.
func TestCodeReplayRevokesFamily(t *testing.T) {
	g := newGateway(t)
	br := g.browser(t, true)
	c := g.register(t, "https://app.example.com/cb")
	p := newPKCE(t)
	code := g.code(t, br, c, p, "s1")
	first := g.token(t, g.exchangeForm(c, code, p))
	if first.status != http.StatusOK {
		t.Fatalf("first exchange: %d %s", first.status, first.body)
	}
	pair := tokenPair{access: first.json()["access_token"].(string), refresh: first.json()["refresh_token"].(string)}
	g.wantMCPOK(t, pair.access)

	// Replay by the legitimate client.
	desc := wantOAuthError(t, g.token(t, g.exchangeForm(c, code, p)), http.StatusBadRequest, "invalid_grant")
	if !strings.Contains(desc, "already used") {
		t.Errorf("description = %q", desc)
	}
	wantLogEvent(t, g, "authserver.code_replayed")
	evs := wantAudit(t, g, "oauth_code_replayed", "deny", 1)
	if evs[0].UserID != g.alice || evs[0].TokenID == "" || evs[0].ResourceIdentity["client_id"] != c.id {
		t.Errorf("audit event = %+v", evs[0])
	}
	// The family is dead: the refresh token the code produced no longer
	// works (invalid_grant), and nothing else is revoked twice.
	desc = wantOAuthError(t, g.refresh(t, c, pair.refresh), http.StatusBadRequest, "invalid_grant")
	if !strings.Contains(desc, "revoked") {
		t.Errorf("refresh after replay: %q", desc)
	}
	for _, rt := range g.astore.RefreshTokens() {
		if rt.RevokedAt == nil {
			t.Errorf("refresh token %s of the replayed family is still live", rt.ID)
		}
	}
	// The access token is stateless and bounded by its hour: it still
	// verifies (documented; decision 8vs3qdkc item 8). Past its lifetime
	// it is gone.
	g.wantMCPOK(t, pair.access)
	g.clock.Advance(g.cfg.AccessTokenTTL + authserverLeeway)
	wantMCPUnauthorized(t, g, g.mcpCall(t, pair.access))
	wantAuthFailed(t, g, "expired")

	// A replay by another client is the same invalid_grant, and still
	// revokes (whoever holds the code, the tokens are not safe).
	t.Run("replay_by_other_client", func(t *testing.T) {
		g := newGateway(t)
		br := g.browser(t, true)
		victim := g.register(t, "https://app.example.com/cb")
		attacker := g.register(t, "https://attacker.example/cb")
		p := newPKCE(t)
		code := g.code(t, br, victim, p, "s1")
		if r := g.token(t, g.exchangeForm(victim, code, p)); r.status != http.StatusOK {
			t.Fatalf("first exchange: %d %s", r.status, r.body)
		}
		form := g.exchangeForm(attacker, code, p)
		form.Set("redirect_uri", victim.redirect)
		wantOAuthError(t, g.token(t, form), http.StatusBadRequest, "invalid_grant")
		wantAudit(t, g, "oauth_code_replayed", "deny", 1)
		for _, rt := range g.astore.RefreshTokens() {
			if rt.RevokedAt == nil {
				t.Errorf("refresh token %s still live after a cross-client replay", rt.ID)
			}
		}
	})
}

// TestCodeIssuedToClientAExchangedByClientB: a stolen code is useless to
// another registered client (even with the victim's redirect URI and the
// right verifier), is burned, and the attempt is logged with both ids.
func TestCodeIssuedToClientAExchangedByClientB(t *testing.T) {
	g := newGateway(t)
	br := g.browser(t, true)
	victim := g.register(t, "https://app.example.com/cb")
	attacker := g.register(t, "https://attacker.example/cb")
	p := newPKCE(t)
	code := g.code(t, br, victim, p, "s1")
	form := g.exchangeForm(attacker, code, p)
	form.Set("redirect_uri", victim.redirect)
	desc := wantOAuthError(t, g.token(t, form), http.StatusBadRequest, "invalid_grant")
	if !strings.Contains(desc, "not issued to this client") {
		t.Errorf("description = %q", desc)
	}
	rec := wantLogEvent(t, g, "authserver.code_wrong_client")
	if rec.Attrs["client_id"] != attacker.id || rec.Attrs["user_id"] != g.alice {
		t.Errorf("log = %v", rec.Attrs)
	}
	// Burned: the victim cannot use it either.
	wantOAuthError(t, g.token(t, g.exchangeForm(victim, code, p)), http.StatusBadRequest, "invalid_grant")
	if n := len(g.astore.RefreshTokens()); n != 0 {
		t.Errorf("%d refresh tokens issued", n)
	}
	// An unknown client_id is invalid_client (401), not a hint about the code.
	form = g.exchangeForm(client{id: "gwc_unknown", redirect: victim.redirect}, code, p)
	wantOAuthError(t, g.token(t, form), http.StatusUnauthorized, "invalid_client")
	// An unknown code is invalid_grant and logged.
	form = g.exchangeForm(victim, "not-a-code", p)
	wantOAuthError(t, g.token(t, form), http.StatusBadRequest, "invalid_grant")
	wantLogEvent(t, g, "authserver.code_unknown")
}

// TestPKCE covers the PKCE downgrade and mismatch attacks: at the
// authorization endpoint (no challenge, method plain, no method, malformed
// challenge) the request is reported to the client with invalid_request
// and no code; at the token endpoint a missing, malformed, wrong or
// swapped verifier is refused and burns the code.
func TestPKCE(t *testing.T) {
	g := newGateway(t)
	br := g.browser(t, true)
	c := g.register(t, "https://app.example.com/cb")
	authorizeCases := map[string]func(url.Values){
		"missing_challenge":      func(q url.Values) { q.Del("code_challenge") },
		"missing_challenge_only": func(q url.Values) { q.Del("code_challenge"); q.Del("code_challenge_method") },
		"method_plain":           func(q url.Values) { q.Set("code_challenge_method", "plain") },
		"method_missing":         func(q url.Values) { q.Del("code_challenge_method") },
		"method_lowercase":       func(q url.Values) { q.Set("code_challenge_method", "s256") },
		"method_unknown":         func(q url.Values) { q.Set("code_challenge_method", "S512") },
		"challenge_too_short":    func(q url.Values) { q.Set("code_challenge", "abc") },
		"challenge_bad_alphabet": func(q url.Values) { q.Set("code_challenge", strings.Repeat("+", 43)) },
		"challenge_is_verifier": func(q url.Values) {
			q.Set("code_challenge_method", "plain")
			q.Set("code_challenge", newPKCE(t).verifier)
		},
		"challenge_with_padding": func(q url.Values) { q.Set("code_challenge", q.Get("code_challenge")+"=") },
		"challenge_too_long":     func(q url.Values) { q.Set("code_challenge", strings.Repeat("a", 129)) },
	}
	for name, mutate := range authorizeCases {
		t.Run("authorize_"+name, func(t *testing.T) {
			state := nonce(t)
			q := g.authorizeParams(c, newPKCE(t), state)
			mutate(q)
			wantRedirectError(t, g.authorize(t, br, q), c.redirect, "invalid_request", state)
			rec := wantLogEvent(t, g, "authserver.authorize_rejected")
			if rec.Attrs["error"] != "invalid_request" || rec.Attrs["client_id"] != c.id {
				t.Errorf("log = %v", rec.Attrs)
			}
			// The consent POST applies the same rule.
			wantRedirectError(t, g.consent(t, br, q, "approve"), c.redirect, "invalid_request", state)
			if len(g.astore.Codes()) != 0 {
				t.Fatal("a code was issued without a valid S256 challenge")
			}
		})
	}

	tokenCases := map[string]struct {
		verifier string
		code     string // OAuth error expected
		burns    bool
	}{
		"missing_verifier":   {verifier: "", code: "invalid_request", burns: false},
		"short_verifier":     {verifier: "abc", code: "invalid_request", burns: false},
		"wrong_verifier":     {verifier: newPKCE(t).verifier, code: "invalid_grant", burns: true},
		"challenge_as_verif": {verifier: "CHALLENGE", code: "invalid_grant", burns: true}, // a valid-looking verifier that hashes wrong
	}
	for name, tc := range tokenCases {
		t.Run("token_"+name, func(t *testing.T) {
			p := newPKCE(t)
			code := g.code(t, br, c, p, nonce(t))
			form := g.exchangeForm(c, code, p)
			verifier := tc.verifier
			if verifier == "CHALLENGE" {
				verifier = p.challenge // the challenge itself (plain-method confusion)
			}
			if verifier == "" {
				form.Del("code_verifier")
			} else {
				form.Set("code_verifier", verifier)
			}
			wantOAuthError(t, g.token(t, form), http.StatusBadRequest, tc.code)
			if tc.code == "invalid_grant" {
				wantLogEvent(t, g, "authserver.pkce_failed")
			}
			// A request refused before the code is consumed leaves it usable;
			// one refused after consumption burns it.
			r := g.token(t, g.exchangeForm(c, code, p))
			if tc.burns && r.status != http.StatusBadRequest {
				t.Errorf("code survived a failed PKCE check: %d %s", r.status, r.body)
			}
			if !tc.burns && r.status != http.StatusOK {
				t.Errorf("code burned by a malformed request: %d %s", r.status, r.body)
			}
		})
	}
	t.Run("token_verifier_for_another_code", func(t *testing.T) {
		p1, p2 := newPKCE(t), newPKCE(t)
		code1 := g.code(t, br, c, p1, "s1")
		code2 := g.code(t, br, c, p2, "s2")
		wantOAuthError(t, g.token(t, g.exchangeForm(c, code1, p2)), http.StatusBadRequest, "invalid_grant")
		wantLogEvent(t, g, "authserver.pkce_failed")
		// code1 is burned; code2 with its own verifier still works.
		wantOAuthError(t, g.token(t, g.exchangeForm(c, code1, p1)), http.StatusBadRequest, "invalid_grant")
		if r := g.token(t, g.exchangeForm(c, code2, p2)); r.status != http.StatusOK {
			t.Errorf("code2 with its own verifier: %d %s", r.status, r.body)
		}
	})
	t.Run("metadata_advertises_s256_only", func(t *testing.T) {
		meta := get(t, noRedirect, g.base+"/.well-known/oauth-authorization-server").json()
		methods, _ := meta["code_challenge_methods_supported"].([]any)
		if len(methods) != 1 || methods[0] != "S256" {
			t.Errorf("code_challenge_methods_supported = %v", methods)
		}
	})
}

// TestCodeExpiry: a code older than GATEWAY_OAUTH_CODE_TTL is
// invalid_grant and the prune job deletes it.
func TestCodeExpiry(t *testing.T) {
	g := newGateway(t)
	br := g.browser(t, true)
	c := g.register(t, "https://app.example.com/cb")
	p := newPKCE(t)
	code := g.code(t, br, c, p, "s1")
	g.clock.Advance(g.cfg.CodeTTL + 1)
	desc := wantOAuthError(t, g.token(t, g.exchangeForm(c, code, p)), http.StatusBadRequest, "invalid_grant")
	if !strings.Contains(desc, "expired") {
		t.Errorf("description = %q", desc)
	}
	if _, codes, err := g.authSvc.Prune(t.Context()); err != nil || codes != 1 {
		t.Errorf("prune: %d codes, %v", codes, err)
	}
	wantOAuthError(t, g.token(t, g.exchangeForm(c, code, p)), http.StatusBadRequest, "invalid_grant")
}
