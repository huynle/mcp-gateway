package connections_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors/slack"
)

// registerSlackApp registers the fake vendor as the Slack app (the
// documented defaults with the endpoints pointed at the fake) and installs
// the real Slack binder, as cmd/gateway does.
func registerSlackApp(t *testing.T, env *testEnv, v *fakeVendor, scopes ...string) connections.VendorApp {
	t.Helper()
	app := connections.Defaults(connections.VendorSlack, "")
	app.ClientID, app.ClientSecret = v.clientID, v.secret
	app.AuthURL, app.TokenURL, app.RevokeURL = v.URL()+"/authorize", v.URL()+"/token", v.URL()+"/revoke"
	app.Scopes = scopes
	app.Extra[slack.ExtraCompanyTeamID] = "TACME"
	saved, err := env.svc.SaveVendorApp(context.Background(), userAlice, app)
	if err != nil {
		t.Fatalf("SaveVendorApp: %v", err)
	}
	env.svc.RegisterBinder(connections.VendorSlack, slack.Binder{})
	return saved
}

// TestSlackConnectStoresTheUserToken: a Slack v2 exchange of an app with
// bot + user scopes (docs/vendor-apps.md 2.5) answers with the BOT token
// at the top level and the user's under authed_user. The connection must
// store the USER token (what slack.* tools get from TokenSource), with
// the user's scopes, identified through auth.test with that same token.
func TestSlackConnectStoresTheUserToken(t *testing.T) {
	env := newTestEnv(t)
	v := newFakeVendor(t)
	v.slack = slackBotAndUser
	registerSlackApp(t, env, v, "channels:read")

	info, err := connectVendor(t, env, connections.VendorSlack, userAlice, "acct-company", "chat:write")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if info.Vendor != "slack" || info.ExternalAccountID != "TACME:UACCT-COMPANY" || info.Label != "company" || info.DisplayName != "Acme / alice" {
		t.Fatalf("info = %+v", info)
	}
	if got := strings.Join(info.Scopes, " "); got != "channels:read chat:write" {
		t.Errorf("Scopes = %q, want the user scopes, never the bot's chat:write,im:write", got)
	}
	tok, err := env.svc.TokenSource(context.Background(), userAlice, info.ID).Token()
	if err != nil {
		t.Fatalf("TokenSource: %v", err)
	}
	if !strings.HasPrefix(tok.AccessToken, "xoxp-") || tok.Type() != "Bearer" {
		t.Errorf("stored token = %+v, want the authed_user (xoxp) bearer token", tok)
	}
	if tok.RefreshToken != "" || !tok.Expiry.IsZero() {
		t.Errorf("stored token = %+v, want no refresh token and no expiry (rotation off)", tok)
	}
	if secrets := env.store.SecretRows(); len(secrets) != 1 || secrets[0].TokenExpiresAt != nil {
		t.Errorf("secret rows = %+v, want one without an expiry", secrets)
	}
	if calls := v.authTestTokens(); len(calls) != 1 || calls[0] != tok.AccessToken {
		t.Errorf("auth.test tokens = %v, want one call with the stored user token", calls)
	}
	for _, issued := range v.allTokens() {
		if strings.Contains(env.logs.String(), issued) {
			t.Errorf("token %q leaked into logs", issued)
		}
	}
}

// TestSlackConnectUserScopeOnlyApp: an app that requests only user_scope
// gets no top-level access_token; the exchange must still succeed with
// the authed_user token. With token rotation the user token's own
// refresh_token and expires_in are what the connection keeps.
func TestSlackConnectUserScopeOnlyApp(t *testing.T) {
	env := newTestEnv(t)
	v := newFakeVendor(t)
	v.slack = slackUserOnly
	registerSlackApp(t, env, v, "channels:read", "users:read")

	info, err := connectVendor(t, env, connections.VendorSlack, userAlice, "acct-company")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	tok, err := env.svc.TokenSource(context.Background(), userAlice, info.ID).Token()
	if err != nil {
		t.Fatalf("TokenSource: %v", err)
	}
	if !strings.HasPrefix(tok.AccessToken, "xoxp-") || tok.RefreshToken != "" || !tok.Expiry.IsZero() {
		t.Errorf("stored token = %+v, want the user token without refresh/expiry", tok)
	}
	if got := strings.Join(info.Scopes, " "); got != "channels:read users:read" {
		t.Errorf("Scopes = %q", got)
	}

	// Token rotation: expiry normalized against the service clock.
	fixed := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	env.svc.SetClock(func() time.Time { return fixed })
	v.slackRotation = true
	v.expiresIn = 43200
	rotated, err := connectVendor(t, env, connections.VendorSlack, userBob, "acct-personal")
	if err != nil {
		t.Fatalf("connect (rotation): %v", err)
	}
	tok, err = env.svc.TokenSource(context.Background(), userBob, rotated.ID).Token()
	if err != nil {
		t.Fatalf("TokenSource (rotation): %v", err)
	}
	if !strings.HasPrefix(tok.AccessToken, "xoxp-") || !strings.HasPrefix(tok.RefreshToken, "xoxe-1-user-") || !tok.Expiry.Equal(fixed.Add(12*time.Hour)) {
		t.Errorf("rotated token = %+v, want the user token, its refresh token and expiry %v", tok, fixed.Add(12*time.Hour))
	}
	if rotated.Label != "company" || rotated.ExternalAccountID != "TACME:UACCT-PERSONAL" || rotated.DisplayName != "Acme / alice-home" {
		t.Errorf("rotated = %+v", rotated)
	}
}

// TestSlackExchangeErrorIsAFlowError: Slack answers a bad code with HTTP
// 200 {"ok":false,"error":"invalid_code"}; the flow fails as it does for
// any vendor, with the Slack error code in the log, never the body.
func TestSlackExchangeErrorIsAFlowError(t *testing.T) {
	env := newTestEnv(t)
	v := newFakeVendor(t)
	v.slack = slackBotAndUser
	registerSlackApp(t, env, v)
	ctx := context.Background()
	redirect, err := env.svc.Start(ctx, connections.StartRequest{UserID: userAlice, Vendor: connections.VendorSlack})
	if err != nil {
		t.Fatal(err)
	}
	state := mustQuery(t, redirect).Get("state")
	_, err = env.svc.Callback(ctx, connections.CallbackRequest{UserID: userAlice, Vendor: connections.VendorSlack, State: state, Code: "never-issued"})
	if !errors.Is(err, connections.ErrFlowInvalid) || !strings.Contains(err.Error(), "invalid_code") {
		t.Fatalf("err = %v, want ErrFlowInvalid naming invalid_code", err)
	}
	if !strings.Contains(env.logs.String(), "vendor_error=invalid_code") {
		t.Errorf("logs lack the Slack error code:\n%s", env.logs.String())
	}
	if n := len(env.store.ConnectionRows()); n != 0 {
		t.Errorf("connections = %d", n)
	}
}
