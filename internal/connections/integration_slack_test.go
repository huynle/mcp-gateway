//go:build integration

package connections_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors/slack"
)

// TestIntegrationSlackConnectStoresUserToken runs the Slack connect flow
// end to end on PostgreSQL against the fake Slack vendor (bot + user
// scopes, then a user_scope-only app): the stored, encrypted bundle is
// the authed_user token, TokenSource hands it out under the user's RLS
// context, the secret row has no expiry, SlackIdentity reads the
// company connection back, and no issued token appears in any row.
func TestIntegrationSlackConnectStoresUserToken(t *testing.T) {
	env := openPGEnv(t)
	ctx := t.Context()
	v := newFakeVendor(t)
	v.slack = slackBotAndUser
	app := connections.Defaults(connections.VendorSlack, "")
	app.ClientID, app.ClientSecret = v.clientID, v.secret
	app.AuthURL, app.TokenURL, app.RevokeURL = v.URL()+"/authorize", v.URL()+"/token", v.URL()+"/revoke"
	app.Scopes = []string{"channels:read"}
	app.Extra[slack.ExtraCompanyTeamID] = "TACME"
	app.Extra[slack.ExtraMarkerReconcile] = "true"
	if _, err := env.svc.SaveVendorApp(ctx, env.alice, app); err != nil {
		t.Fatalf("SaveVendorApp: %v", err)
	}
	env.svc.RegisterBinder(connections.VendorSlack, slack.Binder{})
	te := &testEnv{svc: env.svc, logs: env.logs}

	info, err := connectVendor(t, te, connections.VendorSlack, env.alice, "acct-company", "chat:write")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if info.ExternalAccountID != "TACME:UACCT-COMPANY" || info.Label != "company" || strings.Join(info.Scopes, " ") != "channels:read chat:write" {
		t.Fatalf("info = %+v", info)
	}
	tok, err := env.svc.TokenSource(ctx, env.alice, info.ID).Token()
	if err != nil {
		t.Fatalf("TokenSource: %v", err)
	}
	if !strings.HasPrefix(tok.AccessToken, "xoxp-") || tok.RefreshToken != "" || !tok.Expiry.IsZero() {
		t.Errorf("stored token = %+v, want the authed_user token without refresh/expiry", tok)
	}
	var expires *string
	var secret []byte
	if err := env.super.QueryRow(ctx, `SELECT token_expires_at::text, secret_ciphertext FROM connection_secrets WHERE connection_id = $1`, info.ID).Scan(&expires, &secret); err != nil {
		t.Fatalf("secret row: %v", err)
	}
	if expires != nil {
		t.Errorf("token_expires_at = %q, want NULL", *expires)
	}
	for _, issued := range v.allTokens() {
		if strings.Contains(string(secret), issued) {
			t.Errorf("token %q stored in plaintext", issued)
		}
		if strings.Contains(env.logs.String(), issued) {
			t.Errorf("token %q leaked into logs", issued)
		}
	}
	if user, team, ok, err := env.svc.SlackIdentity(ctx, env.alice); !ok || err != nil || user != "UACCT-COMPANY" || team != "TACME" {
		t.Errorf("SlackIdentity = %q %q %v %v", user, team, ok, err)
	}
	// The authorize URL the flow produced carried no binder hint.
	if calls := v.authTestTokens(); len(calls) != 1 || calls[0] != tok.AccessToken {
		t.Errorf("auth.test tokens = %v, want one call with the stored user token", calls)
	}
	v.mu.Lock()
	authorize := append([]url.Values(nil), v.authorize...)
	v.mu.Unlock()
	for _, q := range authorize {
		for _, key := range []string{slack.ExtraCompanyTeamID, slack.ExtraMarkerReconcile, connections.ExtraScopeParam} {
			if _, has := q[key]; has {
				t.Errorf("authorize request carried %s: %v", key, q)
			}
		}
	}

	// A user_scope-only answer (no top-level access_token) connects too;
	// bob's connection is his own.
	v.slack = slackUserOnly
	bobInfo, err := connectVendor(t, te, connections.VendorSlack, env.bob, "acct-personal")
	if err != nil {
		t.Fatalf("connect (user only): %v", err)
	}
	bobTok, err := env.svc.TokenSource(ctx, env.bob, bobInfo.ID).Token()
	if err != nil {
		t.Fatalf("TokenSource (bob): %v", err)
	}
	if !strings.HasPrefix(bobTok.AccessToken, "xoxp-") || bobTok.AccessToken == tok.AccessToken {
		t.Errorf("bob's token = %+v", bobTok)
	}
	if _, err := env.svc.TokenSource(ctx, env.alice, bobInfo.ID).Token(); err == nil {
		t.Error("alice could read bob's Slack token")
	}
}
