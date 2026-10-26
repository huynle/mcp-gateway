package authserver_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/authserver"
	"github.com/huynle/mcp-gateway/internal/store"
)

// A client may only use the grants it registered (RFC 7591 grant_types):
// a device-only client gets no authorization codes and cannot exchange
// one, and a client without refresh_token cannot refresh. Clients stored
// without grant_types (registered before the field was recorded) keep
// the authorization_code + refresh_token default.

// storeClient writes a client row directly, as an older registration (or
// one this server no longer accepts) would have left it.
func storeClient(t *testing.T, f *svcFixture, clientID string, meta string) *store.OAuthClient {
	t.Helper()
	c := &store.OAuthClient{ClientID: clientID, ClientName: "Stored " + clientID, RedirectURIs: []string{redirectURI}, Metadata: json.RawMessage(meta)}
	if err := f.st.Bypass(context.Background(), func(tx authserver.Tx) error { return tx.CreateClient(context.Background(), c) }); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRegisterRefusesRedirectURIsWithoutTheCodeGrant(t *testing.T) {
	f := newService(t)
	code, out := f.register(t, map[string]any{"grant_types": []string{authserver.GrantDeviceCode, "refresh_token"}, "redirect_uris": []string{redirectURI}})
	if code != http.StatusBadRequest || out["error"] != "invalid_redirect_uri" {
		t.Fatalf("device-only client with redirect_uris: %d %v", code, out)
	}
}

func TestAuthorizeRefusesClientsWithoutTheCodeGrant(t *testing.T) {
	f := newFlow(t)
	dev := storeClient(t, f.svcFixture, "gwc_device_only", `{"token_endpoint_auth_method":"none","grant_types":["`+authserver.GrantDeviceCode+`","refresh_token"],"response_types":[]}`)
	q := f.authorizeParams()
	q.Set("client_id", dev.ClientID)
	loc := redirect(t, f.authorize(q))
	if loc.Query().Get("error") != "unauthorized_client" || loc.Query().Get("state") != "xyz" || loc.Query().Get("code") != "" {
		t.Fatalf("authorize for a device-only client redirected to %s", loc)
	}
	// The consent POST is refused the same way: no code is issued.
	rec := f.consent(q, "approve", csrf)
	if l := redirect(t, rec); l.Query().Get("error") != "unauthorized_client" {
		t.Fatalf("consent for a device-only client: %s", l)
	}
	if n := len(f.st.Codes()); n != 0 {
		t.Fatalf("%d codes issued to a device-only client", n)
	}
	// An unregistered redirect URI is still an error page, never a redirect.
	q.Set("redirect_uri", "https://evil.example.com/cb")
	if rec := f.authorize(q); rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
		t.Fatalf("unregistered redirect: %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestTokenEndpointEnforcesRegisteredGrants(t *testing.T) {
	f := newFlow(t)
	dev := storeClient(t, f.svcFixture, "gwc_device_only", `{"token_endpoint_auth_method":"none","grant_types":["`+authserver.GrantDeviceCode+`","refresh_token"],"response_types":[]}`)
	// A code bound to the device-only client (as if one had been issued).
	codeRaw := "code-for-a-device-only-client-0123456789abcdef"
	err := f.st.Bypass(context.Background(), func(tx authserver.Tx) error {
		return tx.CreateCode(context.Background(), &store.OAuthCode{
			CodeHash: sha(codeRaw), UserID: alice, ClientID: dev.ID, RedirectURI: redirectURI, Resource: f.cfg.Resource(),
			Scope: "mcp", CodeChallenge: challenge(), ExpiresAt: t0.Add(time.Minute),
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	status, out := f.token(url.Values{
		"grant_type": {"authorization_code"}, "code": {codeRaw}, "redirect_uri": {redirectURI},
		"client_id": {dev.ClientID}, "code_verifier": {verifier},
	})
	if status != http.StatusBadRequest || out["error"] != "unauthorized_client" {
		t.Fatalf("authorization_code for a device-only client: %d %v", status, out)
	}
	if n := len(f.st.RefreshTokens()); n != 0 {
		t.Fatalf("%d refresh tokens issued", n)
	}

	// A code-only client (no refresh_token grant) cannot refresh.
	codeOnly := storeClient(t, f.svcFixture, "gwc_code_only", `{"token_endpoint_auth_method":"none","grant_types":["authorization_code"],"response_types":["code"]}`)
	refreshRaw := authserver.RefreshTokenPrefix + "stored-refresh-token-for-code-only-client"
	err = f.st.Bypass(context.Background(), func(tx authserver.Tx) error {
		return tx.CreateRefreshToken(context.Background(), &store.OAuthRefreshToken{
			UserID: alice, ClientID: codeOnly.ID, Resource: f.cfg.Resource(), TokenHash: sha(refreshRaw),
			Scope: []byte(`"mcp"`), ExpiresAt: t0.Add(time.Hour),
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	status, out = f.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshRaw}, "client_id": {codeOnly.ClientID}})
	if status != http.StatusBadRequest || out["error"] != "unauthorized_client" {
		t.Fatalf("refresh for a client without refresh_token: %d %v", status, out)
	}
}

// Rows without grant_types keep working: authorization code and refresh.
func TestClientsWithoutRecordedGrantTypesKeepTheDefault(t *testing.T) {
	f := newFlow(t)
	legacy := storeClient(t, f.svcFixture, "gwc_legacy", `{}`)
	f.clientID = legacy.ClientID
	_, refresh := f.tokens()
	if status, out := f.refresh(refresh); status != http.StatusOK {
		t.Fatalf("legacy client refresh: %d %v", status, out)
	}
}

func sha(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}
