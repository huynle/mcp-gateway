package connections_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors"
)

// TestCallbackStoresTheBinderToken: a binder that returns Bound.Token
// (Slack: the authed_user token, not the top-level bot token) decides
// what the connection stores: TokenSource hands that token out, its
// expiry is normalized against the service clock, and the granted
// scopes are the binder's. A nil Bound.Token keeps the exchanged token.
func TestCallbackStoresTheBinderToken(t *testing.T) {
	env := newTestEnv(t)
	v := newFakeVendor(t)
	registerFakeApp(t, env, v)
	fixed := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	env.svc.SetClock(func() time.Time { return fixed })

	var exchanged *oauth2.Token
	env.svc.RegisterBinder(connections.VendorFake, connections.BinderFunc(func(_ context.Context, in connections.BindInput) (connections.Bound, error) {
		exchanged = in.Token
		return connections.Bound{
			ExternalAccountID: "acct-user", DisplayName: "alice (user)", Label: connectors.LabelCompany,
			Scopes: []string{"users:read", "chat:write"},
			Token:  &oauth2.Token{AccessToken: "user-token-xyz", RefreshToken: "user-refresh-xyz", TokenType: "Bearer", ExpiresIn: 7200},
		}, nil
	}))
	info, err := connect(t, env, userAlice, "acct-company")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if exchanged == nil || !strings.HasPrefix(exchanged.AccessToken, "access-") {
		t.Fatalf("binder got token %+v, want the exchanged one", exchanged)
	}
	if got := strings.Join(info.Scopes, " "); got != "chat:write users:read" {
		t.Errorf("Scopes = %q, want the binder's", got)
	}
	tok, err := env.svc.TokenSource(context.Background(), userAlice, info.ID).Token()
	if err != nil {
		t.Fatalf("TokenSource: %v", err)
	}
	if tok.AccessToken != "user-token-xyz" || tok.RefreshToken != "user-refresh-xyz" || tok.TokenType != "Bearer" {
		t.Errorf("stored token = %+v, want the binder's", tok)
	}
	if want := fixed.Add(2 * time.Hour); !tok.Expiry.Equal(want) {
		t.Errorf("Expiry = %v, want %v (ExpiresIn normalized against the service clock)", tok.Expiry, want)
	}
	secrets := env.store.SecretRows()
	if len(secrets) != 1 || secrets[0].TokenExpiresAt == nil || !secrets[0].TokenExpiresAt.Equal(fixed.Add(2*time.Hour)) {
		t.Errorf("secret row = %+v", secrets)
	}
	// The exchanged (top-level) token is not what the connection uses.
	if strings.Contains(env.logs.String(), "user-token-xyz") {
		t.Errorf("binder token leaked into logs")
	}

	// A binder token without an access token is a binder failure, not a
	// stored connection.
	env.svc.RegisterBinder(connections.VendorFake, connections.BinderFunc(func(context.Context, connections.BindInput) (connections.Bound, error) {
		return connections.Bound{ExternalAccountID: "acct-empty", DisplayName: "x", Label: connectors.LabelCompany, Token: &oauth2.Token{}}, nil
	}))
	if _, err := connect(t, env, userAlice, "acct-company"); !errors.Is(err, connections.ErrFlowInvalid) {
		t.Errorf("empty binder token err = %v, want ErrFlowInvalid", err)
	}
	if n := len(env.store.ConnectionRows()); n != 1 {
		t.Errorf("connections = %d, want only the first", n)
	}

	// Without Bound.Token the exchanged token is stored, as before.
	env.svc.RegisterBinder(connections.VendorFake, connections.BinderFunc(func(_ context.Context, in connections.BindInput) (connections.Bound, error) {
		return connections.Bound{ExternalAccountID: "acct-plain", DisplayName: "plain", Label: connectors.LabelCompany}, nil
	}))
	plain, err := connect(t, env, userAlice, "acct-company", "repo")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	tok, err = env.svc.TokenSource(context.Background(), userAlice, plain.ID).Token()
	if err != nil {
		t.Fatalf("TokenSource: %v", err)
	}
	if !strings.HasPrefix(tok.AccessToken, "access-") || strings.Join(plain.Scopes, " ") != "read:user repo" {
		t.Errorf("plain token = %+v scopes %v, want the exchanged token and the vendor's scope", tok, plain.Scopes)
	}
}
