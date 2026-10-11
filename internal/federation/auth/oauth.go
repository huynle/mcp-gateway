package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/store"
)

// The gateway never uses x/oauth2's HTTP paths (Exchange, TokenSource):
// they fall back to http.DefaultClient unless the client is put in the
// context, and they cannot send RFC 8707 resource on refresh. Every
// registration, token and refresh request below goes through Service.http,
// netguard's client. Only the PKCE helpers of x/oauth2 are used.

// Token endpoint client authentication methods.
const (
	authMethodNone  = "none"
	authMethodBasic = "client_secret_basic"
	authMethodPost  = "client_secret_post"
)

const (
	maxTokenResponseBytes = 1 << 20
	tokenTimeout          = 30 * time.Second
)

// authConfig is the non-secret part of MCPServer.AuthConfig this package
// reads.
type authConfig struct {
	// Scopes override the discovered scopes for OAuth.
	Scopes []string `json:"scopes,omitempty"`
	// APIKey says where an api_key goes: Header (preferred) or Query.
	APIKey *apiKeyConfig `json:"api_key,omitempty"`
}

type apiKeyConfig struct {
	Header string `json:"header,omitempty"`
	Query  string `json:"query,omitempty"`
}

// headerConfig is MCPServer.HeaderConfig: static non-secret headers (the
// connector passes them as client.Endpoint.Headers) and the names of
// headers whose values each user supplies.
type headerConfig struct {
	Static  map[string]string `json:"static,omitempty"`
	PerUser []string          `json:"per_user,omitempty"`
}

func parseAuthConfig(raw []byte) authConfig {
	var c authConfig
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &c)
	}
	return c
}

func parseHeaderConfig(raw []byte) headerConfig {
	var c headerConfig
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &c)
	}
	return c
}

// oauthErrorCodeRE bounds what of an AS error code is logged or kept.
var oauthErrorCodeRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

func safeCode(code string) string {
	if oauthErrorCodeRE.MatchString(code) {
		return code
	}
	return "invalid_error_code"
}

// tokenError is a failed token request: the AS's OAuth error code, or a
// class (network, http_<status>, invalid_response). Never the body.
type tokenError struct {
	Code  string
	cause error
}

func (e *tokenError) Error() string { return "auth: token endpoint answered " + e.Code }
func (e *tokenError) Unwrap() error { return e.cause }

func tokenErrorCode(err error) string {
	var te *tokenError
	if errors.As(err, &te) {
		return te.Code
	}
	return "error"
}

// clientCreds is how the gateway authenticates at a token endpoint.
type clientCreds struct {
	ID, Secret, Method string
}

// tokenRequest posts form to endpoint and decodes the answer.
func (s *Service) tokenRequest(ctx context.Context, endpoint string, cc clientCreds, form url.Values) (*tokenBundle, error) {
	ctx, cancel := context.WithTimeout(ctx, tokenTimeout)
	defer cancel()
	switch cc.Method {
	case authMethodBasic:
	case authMethodPost:
		form.Set("client_id", cc.ID)
		form.Set("client_secret", cc.Secret)
	default:
		form.Set("client_id", cc.ID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, &tokenError{Code: "invalid_endpoint"}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if cc.Method == authMethodBasic {
		req.SetBasicAuth(url.QueryEscape(cc.ID), url.QueryEscape(cc.Secret))
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return nil, &tokenError{Code: "network", cause: err}
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseBytes+1))
	if err != nil || len(body) > maxTokenResponseBytes {
		return nil, &tokenError{Code: "invalid_response"}
	}
	var raw struct {
		AccessToken  string      `json:"access_token"`
		TokenType    string      `json:"token_type"`
		ExpiresIn    json.Number `json:"expires_in"`
		RefreshToken string      `json:"refresh_token"`
		Scope        string      `json:"scope"`
		Error        string      `json:"error"`
	}
	decodeErr := json.Unmarshal(body, &raw)
	clear(body)
	if resp.StatusCode != http.StatusOK || decodeErr != nil || raw.Error != "" {
		code := fmt.Sprintf("http_%d", resp.StatusCode)
		if raw.Error != "" {
			code = safeCode(raw.Error)
		} else if resp.StatusCode == http.StatusOK {
			code = "invalid_response"
		}
		return nil, &tokenError{Code: code}
	}
	if raw.AccessToken == "" || (raw.TokenType != "" && !strings.EqualFold(raw.TokenType, "bearer")) {
		return nil, &tokenError{Code: "invalid_response"}
	}
	tok := &tokenBundle{AccessToken: raw.AccessToken, RefreshToken: raw.RefreshToken, TokenType: "Bearer", Scopes: strings.Fields(raw.Scope)}
	if n, err := raw.ExpiresIn.Int64(); err == nil && n > 0 {
		tok.Expiry = s.clock().Add(time.Duration(n) * time.Second)
	}
	return tok, nil
}

// --- client registration ----------------------------------------------------------

// ensureClient returns the gateway's client at the server's authorization
// server: a static client set by the owner or an admin always wins (an
// explicit choice; with an issuer set it must match); else a stored
// CIMD/DCR client of the same issuer is reused; else the gateway's client
// ID metadata document when the AS supports CIMD; else dynamic client
// registration. The client is stored through the bypass scope because any
// user of a published server may be the first to connect.
func (s *Service) ensureClient(ctx context.Context, server *store.MCPServer, asm *AuthServerMetadata) (*store.MCPOAuthClient, string, error) {
	row, err := s.loadClient(ctx, server.ID)
	if err != nil {
		return nil, "", err
	}
	if row != nil {
		switch {
		case row.Method == store.MCPOAuthClientStatic:
			if row.Issuer != "" && strings.TrimSuffix(row.Issuer, "/") != strings.TrimSuffix(asm.Issuer, "/") {
				return nil, "", fmt.Errorf("%w: the static client is for another issuer", ErrNoClient)
			}
			secret, err := s.clientSecret(ctx, server, row)
			return row, secret, err
		case row.Issuer == asm.Issuer && row.Method == store.MCPOAuthClientCIMD && row.ClientID == s.ClientMetadataURL():
			return row, "", nil
		case row.Issuer == asm.Issuer && row.Method == store.MCPOAuthClientDCR:
			secret, err := s.clientSecret(ctx, server, row)
			return row, secret, err
		}
	}
	switch {
	case asm.ClientIDMetadataDocumentSupported:
		row = &store.MCPOAuthClient{ServerID: server.ID, Method: store.MCPOAuthClientCIMD, ClientID: s.ClientMetadataURL(), Issuer: asm.Issuer}
		if err := s.store.Bypass(ctx, func(tx Tx) error { return tx.UpsertOAuthClient(ctx, row) }); err != nil {
			return nil, "", fmt.Errorf("auth: store client: %w", err)
		}
		s.log.Info("oauth client: metadata document", "event", "federation.auth_client_cimd", "server_id", server.ID)
		return row, "", nil
	case asm.RegistrationEndpoint != "":
		return s.register(ctx, server, asm)
	}
	return nil, "", ErrNoClient
}

func (s *Service) loadClient(ctx context.Context, serverID string) (*store.MCPOAuthClient, error) {
	var row *store.MCPOAuthClient
	err := s.store.Bypass(ctx, func(tx Tx) (err error) {
		row, err = tx.GetOAuthClient(ctx, serverID)
		return err
	})
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("auth: load client: %w", err)
	}
	return row, nil
}

// clientMetadata is the gateway's client metadata (RFC 7591), used both as
// the DCR request and as the CIMD document.
func (s *Service) clientMetadata(authMethod string) map[string]any {
	return map[string]any{
		"client_name":                s.name,
		"client_uri":                 s.base,
		"redirect_uris":              []string{s.RedirectURL()},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": authMethod,
	}
}

// register runs RFC 7591 dynamic client registration and stores the
// client (secret enveloped).
func (s *Service) register(ctx context.Context, server *store.MCPServer, asm *AuthServerMetadata) (*store.MCPOAuthClient, string, error) {
	want := authMethodNone
	if m := asm.TokenEndpointAuthMethodsSupported; len(m) > 0 && !slices.Contains(m, authMethodNone) {
		want = authMethodBasic
		if !slices.Contains(m, authMethodBasic) && slices.Contains(m, authMethodPost) {
			want = authMethodPost
		}
	}
	reqBody, err := json.Marshal(s.clientMetadata(want))
	if err != nil {
		return nil, "", err
	}
	ctx2, cancel := context.WithTimeout(ctx, tokenTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx2, http.MethodPost, asm.RegistrationEndpoint, bytes.NewReader(reqBody))
	if err != nil {
		return nil, "", fmt.Errorf("%w: bad registration endpoint", ErrNoClient)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := s.http.Do(req)
	if err != nil {
		s.log.Warn("client registration failed", "event", "federation.auth_dcr_failed", "server_id", server.ID, "error", observability.RedactError(err))
		return nil, "", fmt.Errorf("%w: registration failed", ErrNoClient)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataBytes+1))
	if err != nil || len(body) > maxMetadataBytes || (resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK) {
		s.log.Warn("client registration refused", "event", "federation.auth_dcr_failed", "server_id", server.ID, "status", resp.StatusCode)
		return nil, "", fmt.Errorf("%w: registration refused (HTTP %d)", ErrNoClient, resp.StatusCode)
	}
	var reg struct {
		ClientID                string `json:"client_id"`
		ClientSecret            string `json:"client_secret"`
		TokenEndpointAuthMethod string `json:"token_endpoint_auth_method"`
	}
	if json.Unmarshal(body, &reg) != nil || reg.ClientID == "" {
		return nil, "", fmt.Errorf("%w: registration answer without client_id", ErrNoClient)
	}
	clear(body)
	row := &store.MCPOAuthClient{ServerID: server.ID, Method: store.MCPOAuthClientDCR, ClientID: reg.ClientID, Issuer: asm.Issuer}
	if reg.ClientSecret != "" {
		enc, err := s.seal(ctx, aadOAuthClient(server, store.MCPOAuthClientDCR), reg.ClientSecret)
		if err != nil {
			return nil, "", err
		}
		row.ClientSecret = &enc
	}
	if err := s.store.Bypass(ctx, func(tx Tx) error { return tx.UpsertOAuthClient(ctx, row) }); err != nil {
		return nil, "", fmt.Errorf("auth: store client: %w", err)
	}
	s.log.Info("oauth client registered", "event", "federation.auth_dcr_registered", "server_id", server.ID, "confidential", reg.ClientSecret != "")
	return row, reg.ClientSecret, nil
}

// tokenAuthMethod picks how to authenticate at the token endpoint.
func tokenAuthMethod(secret string, asm *AuthServerMetadata) string {
	if secret == "" {
		return authMethodNone
	}
	m := asm.TokenEndpointAuthMethodsSupported
	if len(m) == 0 || slices.Contains(m, authMethodBasic) || !slices.Contains(m, authMethodPost) {
		return authMethodBasic
	}
	return authMethodPost
}

// --- connect flow -----------------------------------------------------------------

// ConnectURL starts an OAuth connection of userID to serverID: it checks
// the user can see the server, discovers its authorization server
// (refusing one without PKCE S256), obtains the gateway's client, and
// returns the authorization URL to redirect the browser to. The state
// carries everything the callback needs, sealed to the user and server.
func (s *Service) ConnectURL(ctx context.Context, userID, serverID string) (string, error) {
	server, err := s.visibleServer(ctx, userID, serverID)
	if err != nil {
		return "", err
	}
	if server.AuthKind != store.MCPAuthOAuth {
		return "", fmt.Errorf("%w: the server does not use OAuth", ErrNotConfigured)
	}
	if server.CredentialMode != store.MCPCredentialPerUser {
		return "", fmt.Errorf("%w: shared OAuth connections", ErrUnsupported)
	}
	det, err := s.Detect(ctx, server.URL)
	if err != nil {
		return "", err
	}
	asm := det.AuthServerMetadata
	if asm == nil {
		return "", ErrNoOAuth
	}
	if !det.SupportsS256 {
		return "", ErrPKCEUnsupported
	}
	cl, secret, err := s.ensureClient(ctx, server, asm)
	if err != nil {
		return "", err
	}
	scopes := det.Scopes
	if cfg := parseAuthConfig(server.AuthConfig); len(cfg.Scopes) > 0 {
		scopes = slices.Clone(cfg.Scopes)
	}
	if det.OfflineAccess && !slices.Contains(scopes, "offline_access") {
		scopes = append(scopes, "offline_access")
	}
	id, err := randomID()
	if err != nil {
		return "", err
	}
	verifier := oauth2.GenerateVerifier()
	st := &flowState{
		ID: id, UserID: userID, ServerID: server.ID, Verifier: verifier,
		Issuer: asm.Issuer, IssRequired: asm.AuthorizationResponseIssParameterSupported,
		TokenEndpoint: asm.TokenEndpoint, ClientID: cl.ClientID, ClientMethod: cl.Method,
		AuthMethod: tokenAuthMethod(secret, asm), Resource: det.Resource, Scopes: scopes, ServerURL: server.URL,
		Exp: s.clock().Add(s.ttl).Unix(),
	}
	state, err := s.encodeState(ctx, st)
	if err != nil {
		return "", err
	}
	au, err := url.Parse(asm.AuthorizationEndpoint)
	if err != nil {
		return "", ErrNoOAuth
	}
	q := au.Query()
	q.Set("response_type", "code")
	q.Set("client_id", cl.ClientID)
	q.Set("redirect_uri", s.RedirectURL())
	q.Set("state", state)
	q.Set("code_challenge", oauth2.S256ChallengeFromVerifier(verifier))
	q.Set("code_challenge_method", "S256")
	q.Set("resource", det.Resource)
	if len(scopes) > 0 {
		q.Set("scope", strings.Join(scopes, " "))
	}
	au.RawQuery = q.Encode()
	s.log.Info("oauth connect started", "event", "federation.auth_connect_started", "user_id", userID, "server_id", server.ID,
		"client_method", cl.Method, "scopes", strings.Join(scopes, " "))
	return au.String(), nil
}

// CallbackRequest is what the authorization server sent to the callback,
// plus the signed-in gateway user.
type CallbackRequest struct {
	UserID string
	State  string
	Code   string
	// Iss is the RFC 9207 iss parameter ("" when absent).
	Iss string
	// Error is the AS's error parameter ("" on success).
	Error string
}

// CompleteConnect finishes a flow: the state must open for this user, be
// unexpired and unused; the RFC 9207 issuer must match when the AS
// advertises it (or sends it); the code is exchanged with the PKCE
// verifier and the resource; the token bundle is stored encrypted as the
// user's connection (active). It returns the server ID (also on most
// errors, for the finish page).
func (s *Service) CompleteConnect(ctx context.Context, req CallbackRequest) (string, error) {
	st, err := s.decodeState(ctx, req.UserID, req.State)
	if err != nil {
		s.log.Warn("oauth callback rejected", "event", "federation.auth_flow_rejected", "user_id", req.UserID, "reason", "state")
		return "", err
	}
	fresh, err := s.replay.Use(ctx, st.ID, time.Unix(st.Exp, 0))
	if err != nil {
		return st.ServerID, fmt.Errorf("auth: replay guard: %w", err)
	}
	if !fresh {
		s.log.Warn("oauth callback rejected", "event", "federation.auth_flow_rejected", "user_id", req.UserID, "server_id", st.ServerID, "reason", "replay")
		return st.ServerID, fmt.Errorf("%w: state already used", ErrFlowInvalid)
	}
	if req.Error != "" {
		s.log.Warn("authorization refused", "event", "federation.auth_flow_rejected", "user_id", req.UserID, "server_id", st.ServerID, "reason", "as_error", "as_error", safeCode(req.Error))
		return st.ServerID, ErrDenied
	}
	if (st.IssRequired || req.Iss != "") && req.Iss != st.Issuer {
		s.log.Warn("oauth callback rejected", "event", "federation.auth_flow_rejected", "user_id", req.UserID, "server_id", st.ServerID, "reason", "issuer_mismatch")
		return st.ServerID, fmt.Errorf("%w: issuer mismatch", ErrFlowInvalid)
	}
	if req.Code == "" {
		return st.ServerID, fmt.Errorf("%w: missing code", ErrFlowInvalid)
	}
	server, err := s.visibleServer(ctx, req.UserID, st.ServerID)
	if err != nil {
		return st.ServerID, err
	}
	if server.AuthKind != store.MCPAuthOAuth || server.CredentialMode != store.MCPCredentialPerUser {
		return st.ServerID, fmt.Errorf("%w: the server's authentication changed", ErrFlowInvalid)
	}
	if server.URL != st.ServerURL {
		s.log.Warn("oauth callback rejected", "event", "federation.auth_flow_rejected", "user_id", req.UserID, "server_id", st.ServerID, "reason", "server_url_changed")
		return st.ServerID, fmt.Errorf("%w: the server's address changed", ErrFlowInvalid)
	}
	secret := ""
	if st.AuthMethod != authMethodNone {
		row, err := s.loadClient(ctx, server.ID)
		if err != nil {
			return st.ServerID, err
		}
		if row == nil || row.ClientID != st.ClientID {
			return st.ServerID, fmt.Errorf("%w: the OAuth client changed", ErrFlowInvalid)
		}
		if secret, err = s.clientSecret(ctx, server, row); err != nil {
			return st.ServerID, err
		}
	}
	tok, err := s.tokenRequest(ctx, st.TokenEndpoint, clientCreds{ID: st.ClientID, Secret: secret, Method: st.AuthMethod}, url.Values{
		"grant_type": {"authorization_code"}, "code": {req.Code}, "redirect_uri": {s.RedirectURL()},
		"code_verifier": {st.Verifier}, "resource": {st.Resource},
	})
	if err != nil {
		s.logTokenFailure("code exchange failed", "federation.auth_exchange_failed", req.UserID, server.ID, err)
		return st.ServerID, fmt.Errorf("%w: code exchange failed (%s)", ErrFlowInvalid, tokenErrorCode(err))
	}
	tok.Issuer, tok.TokenEndpoint, tok.ClientID, tok.AuthMethod, tok.Resource = st.Issuer, st.TokenEndpoint, st.ClientID, st.AuthMethod, st.Resource
	if len(tok.Scopes) == 0 {
		tok.Scopes = st.Scopes
	}
	if err := s.storeUserToken(ctx, server, req.UserID, tok, nil); err != nil {
		return st.ServerID, err
	}
	s.log.Info("oauth connected", "event", "federation.auth_connected", "user_id", req.UserID, "server_id", server.ID, "scopes", strings.Join(tok.Scopes, " "))
	return st.ServerID, nil
}

// storeUserToken seals tok (keeping the user's per-user headers from prev)
// as the user's active connection. It opens its own transaction unless tx
// is given.
func (s *Service) storeUserToken(ctx context.Context, server *store.MCPServer, userID string, tok *tokenBundle, tx Tx) error {
	write := func(tx Tx) error {
		bundle := &secretBundle{OAuth: tok}
		if prev, err := tx.GetUserConnection(ctx, server.ID, userID); err == nil {
			if old, err := s.openUserBundle(ctx, server, prev); err == nil {
				bundle.Headers = old.Headers
			}
		}
		enc, err := s.seal(ctx, aadUserConnection(userID, server), bundle)
		if err != nil {
			return err
		}
		c := &store.MCPUserConnection{ServerID: server.ID, UserID: userID, Status: store.MCPConnectionActive, Scopes: tok.Scopes, Secret: enc}
		if !tok.Expiry.IsZero() {
			exp := tok.Expiry
			c.ExpiresAt = &exp
		}
		if err := tx.UpsertUserConnection(ctx, c); err != nil {
			return err
		}
		return tx.TouchUserConnectionRefreshed(ctx, server.ID, userID, s.clock())
	}
	var err error
	if tx != nil {
		err = write(tx)
	} else {
		err = s.store.AsUser(ctx, userID, write)
	}
	if err != nil {
		return fmt.Errorf("auth: store connection: %w", err)
	}
	return nil
}

func (s *Service) logTokenFailure(msg, event, userID, serverID string, err error) {
	attrs := []any{"event", event, "user_id", userID, "server_id", serverID, "as_error", tokenErrorCode(err)}
	var te *tokenError
	if errors.As(err, &te) && te.cause != nil {
		attrs = append(attrs, "error", observability.RedactError(te.cause))
	}
	s.log.Warn(msg, attrs...)
}

// visibleServer loads the server as userID (row-level security: the owner
// or a user it is published to). store.ErrNotFound otherwise.
func (s *Service) visibleServer(ctx context.Context, userID, serverID string) (*store.MCPServer, error) {
	if userID == "" || serverID == "" {
		return nil, store.ErrNotFound
	}
	var server *store.MCPServer
	err := s.store.AsUser(ctx, userID, func(tx Tx) (err error) {
		server, err = tx.GetServer(ctx, serverID)
		return err
	})
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, fmt.Errorf("auth: load server: %w", err)
	}
	return server, nil
}

// --- refresh ------------------------------------------------------------------------

// userToken returns userID's usable access token for server. When the
// stored token is expired (or within RefreshSkew), or is the token the
// upstream just rejected, it refreshes under the connection's row lock:
// one refresh at a time per connection across replicas, waiters read the
// result; a rotated refresh token is stored; invalid_grant (or no refresh
// token) marks the connection needs_reconnect and returns
// ErrNeedsReconnect.
func (s *Service) userToken(ctx context.Context, server *store.MCPServer, userID, rejected string) (*tokenBundle, error) {
	// The client row is read before the user transaction (no nested
	// transactions); it is only used when a refresh is needed.
	clientRow, err := s.loadClient(ctx, server.ID)
	if err != nil {
		return nil, err
	}
	var (
		out            *tokenBundle
		needsReconnect bool
		refreshErr     error
	)
	err = s.store.AsUser(ctx, userID, func(tx Tx) error {
		c, err := tx.LockUserConnection(ctx, server.ID, userID)
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotConnected
		}
		if err != nil {
			return err
		}
		if c.Status != store.MCPConnectionActive {
			needsReconnect = true
			return nil
		}
		mark := func(reason string) error {
			needsReconnect = true
			s.log.Warn("connection needs reconnect", "event", "federation.auth_needs_reconnect", "user_id", userID, "server_id", server.ID, "reason", reason)
			return tx.SetUserConnectionStatus(ctx, server.ID, userID, store.MCPConnectionNeedsReconnect)
		}
		b, err := s.openUserBundle(ctx, server, c)
		if err != nil || b.OAuth == nil {
			return mark("unreadable")
		}
		t := b.OAuth
		now := s.clock()
		if t.fresh(now, s.skew) && (rejected == "" || t.AccessToken != rejected) {
			out = t
			return nil
		}
		if t.RefreshToken == "" {
			return mark("no_refresh_token")
		}
		secret := ""
		if t.AuthMethod != authMethodNone && clientRow != nil && clientRow.ClientID == t.ClientID {
			if secret, err = s.clientSecret(ctx, server, clientRow); err != nil {
				return err
			}
		}
		form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {t.RefreshToken}}
		if t.Resource != "" {
			form.Set("resource", t.Resource)
		}
		nt, err := s.tokenRequest(ctx, t.TokenEndpoint, clientCreds{ID: t.ClientID, Secret: secret, Method: t.AuthMethod}, form)
		if err != nil {
			s.logTokenFailure("token refresh failed", "federation.auth_refresh_failed", userID, server.ID, err)
			if tokenErrorCode(err) == "invalid_grant" {
				return mark("invalid_grant")
			}
			refreshErr = err
			return nil
		}
		if nt.RefreshToken == "" {
			nt.RefreshToken = t.RefreshToken
		}
		if len(nt.Scopes) == 0 {
			nt.Scopes = t.Scopes
		}
		nt.Issuer, nt.TokenEndpoint, nt.ClientID, nt.AuthMethod, nt.Resource = t.Issuer, t.TokenEndpoint, t.ClientID, t.AuthMethod, t.Resource
		if err := s.storeUserToken(ctx, server, userID, nt, tx); err != nil {
			return err
		}
		s.log.Info("token refreshed", "event", "federation.auth_refreshed", "user_id", userID, "server_id", server.ID, "rotated", nt.RefreshToken != t.RefreshToken)
		out = nt
		return nil
	})
	switch {
	case err != nil:
		return nil, err
	case needsReconnect:
		return nil, ErrNeedsReconnect
	case refreshErr != nil:
		return nil, fmt.Errorf("auth: refresh failed: %w", refreshErr)
	}
	return out, nil
}

// markNeedsReconnect flags userID's connection to serverID.
func (s *Service) markNeedsReconnect(ctx context.Context, serverID, userID, reason string) {
	err := s.store.AsUser(ctx, userID, func(tx Tx) error {
		return tx.SetUserConnectionStatus(ctx, serverID, userID, store.MCPConnectionNeedsReconnect)
	})
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.log.Error("mark needs reconnect failed", "event", "federation.auth_mark_failed", "user_id", userID, "server_id", serverID, "error", observability.RedactError(err))
		return
	}
	s.log.Warn("connection needs reconnect", "event", "federation.auth_needs_reconnect", "user_id", userID, "server_id", serverID, "reason", reason)
}
