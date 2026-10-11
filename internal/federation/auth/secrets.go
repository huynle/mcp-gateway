package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/store"
)

// AAD kinds. Every envelope this package writes is bound to its row: a
// user connection to (user, server, auth kind), a shared secret to
// (server, auth kind), an OAuth client secret to (server, registration
// method), a connect-flow state to (user, server).
const (
	aadKindUserConnection = "mcp_user_connection"
	aadKindSharedSecret   = "mcp_shared_secret"
	aadKindOAuthClient    = "mcp_oauth_client"
	aadKindFlowState      = "mcp_oauth_state"
)

func aadUserConnection(userID, serverID, kind string) crypto.AAD {
	return crypto.AAD{UserID: userID, Kind: aadKindUserConnection, RecordID: serverID, App: kind}
}

func aadShared(serverID, kind string) crypto.AAD {
	return crypto.AAD{Kind: aadKindSharedSecret, RecordID: serverID, App: kind}
}

func aadOAuthClient(serverID, method string) crypto.AAD {
	return crypto.AAD{Kind: aadKindOAuthClient, RecordID: serverID, App: method}
}

func aadState(userID, serverID string) crypto.AAD {
	return crypto.AAD{UserID: userID, Kind: aadKindFlowState, RecordID: serverID}
}

// secretBundle is the plaintext of a per-user connection or a shared
// secret. Exactly the fields of the server's auth kind are set; Headers
// may accompany any kind (per-user header values).
type secretBundle struct {
	APIKey  string            `json:"api_key,omitempty"`
	Bearer  string            `json:"bearer,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	OAuth   *tokenBundle      `json:"oauth,omitempty"`
}

// tokenBundle is an OAuth connection: the tokens plus everything a refresh
// needs, pinned at connect time so a later change of the server's
// settings cannot redirect a user's refresh token elsewhere.
type tokenBundle struct {
	AccessToken   string    `json:"access_token"`
	RefreshToken  string    `json:"refresh_token,omitempty"`
	TokenType     string    `json:"token_type,omitempty"`
	Expiry        time.Time `json:"expiry,omitzero"`
	Issuer        string    `json:"issuer"`
	TokenEndpoint string    `json:"token_endpoint"`
	ClientID      string    `json:"client_id"`
	AuthMethod    string    `json:"auth_method"`
	Resource      string    `json:"resource,omitempty"`
	Scopes        []string  `json:"scopes,omitempty"`
}

// fresh reports whether the access token is usable at now with skew.
func (t *tokenBundle) fresh(now time.Time, skew time.Duration) bool {
	return t != nil && t.AccessToken != "" && (t.Expiry.IsZero() || t.Expiry.After(now.Add(skew)))
}

func (s *Service) seal(ctx context.Context, aad crypto.AAD, v any) (store.Encrypted, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return store.Encrypted{}, fmt.Errorf("auth: encode secret: %w", err)
	}
	env, err := crypto.Encrypt(ctx, s.keys, aad, plain)
	clear(plain)
	if err != nil {
		return store.Encrypted{}, fmt.Errorf("auth: encrypt secret: %w", err)
	}
	return store.Encrypted(env), nil
}

func (s *Service) open(ctx context.Context, aad crypto.AAD, enc store.Encrypted, v any) error {
	plain, err := crypto.Decrypt(ctx, s.keys, aad, crypto.Envelope(enc))
	if err != nil {
		return fmt.Errorf("auth: decrypt secret: %w", err)
	}
	defer clear(plain)
	if err := json.Unmarshal(plain, v); err != nil {
		return fmt.Errorf("auth: decode secret: %w", err)
	}
	return nil
}

// openUserBundle decrypts a user's connection to server.
func (s *Service) openUserBundle(ctx context.Context, server *store.MCPServer, c *store.MCPUserConnection) (*secretBundle, error) {
	var b secretBundle
	if err := s.open(ctx, aadUserConnection(c.UserID, server.ID, server.AuthKind), c.Secret, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

// clientSecret decrypts an OAuth client's secret ("" for public clients).
func (s *Service) clientSecret(ctx context.Context, c *store.MCPOAuthClient) (string, error) {
	if c == nil || c.ClientSecret == nil {
		return "", nil
	}
	var secret string
	if err := s.open(ctx, aadOAuthClient(c.ServerID, c.Method), *c.ClientSecret, &secret); err != nil {
		return "", err
	}
	return secret, nil
}
