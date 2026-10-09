package connections

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/store"
)

// Errors the connect flow reports. The message after the sentinel is safe
// to show the user.
var (
	// ErrNotConfigured means no enabled app is registered for the vendor
	// and variant.
	ErrNotConfigured = errors.New("connections: vendor app not configured")
	// ErrFlowInvalid covers an unknown, expired, foreign or replayed state,
	// a failed code exchange (including a PKCE mismatch) and a binder that
	// could not identify the account.
	ErrFlowInvalid = errors.New("connections: connect flow invalid")
	// ErrVendorDenied means the vendor sent back an error (the user
	// cancelled, or the app is not allowed there).
	ErrVendorDenied = errors.New("connections: vendor refused the connection")
	// ErrPersonalRefused means the account is personal and the user's
	// roles do not allow personal accounts for this app.
	ErrPersonalRefused = errors.New("connections: personal accounts are not allowed for this app")
)

// StartRequest begins a connect flow for the signed-in user.
type StartRequest struct {
	UserID  string
	Vendor  string
	Variant string
	// Scopes are requested on top of the app's base scopes ("grant more
	// access" passes the tool's required scopes).
	Scopes []string
	// ReturnTo is the portal path to go back to afterwards.
	ReturnTo string
}

// CallbackRequest is what the vendor sent to /connect/{vendor}/callback.
type CallbackRequest struct {
	UserID           string
	Vendor           string
	State            string
	Code             string
	Error            string
	ErrorDescription string
}

// Info is a connection as the portal and the account source see it:
// never tokens.
type Info struct {
	ID                string
	UserID            string
	Vendor            string
	Variant           string
	ExternalAccountID string
	Label             string
	DisplayName       string
	Scopes            []string
	Status            string
	LastRefreshedAt   *time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// NeedsReconnect reports whether the connection's tokens are dead.
func (i Info) NeedsReconnect() bool { return i.Status == store.ConnectionNeedsReconnect }

// Active reports whether the connection can be used.
func (i Info) Active() bool { return i.Status == store.ConnectionActive }

// Start stores a flow (state, PKCE verifier, requested scopes) for the
// user and returns the vendor's authorization URL to redirect to.
func (s *Service) Start(ctx context.Context, req StartRequest) (string, error) {
	app, _, err := s.enabledApp(ctx, req.Vendor, req.Variant)
	if err != nil {
		return "", err
	}
	state, err := randomToken()
	if err != nil {
		return "", err
	}
	verifier := oauth2.GenerateVerifier()
	scopes := unionScopes(app.Scopes, req.Scopes)
	flow := &store.ConnectFlow{
		State: state, UserID: req.UserID, VendorAppID: app.ID, Verifier: verifier, Scopes: scopes,
		ReturnTo: req.ReturnTo, ExpiresAt: s.clock().Add(s.cfg.FlowTTL),
	}
	if err := s.store.AsUser(ctx, req.UserID, func(tx Tx) error { return tx.CreateConnectFlow(ctx, flow) }); err != nil {
		return "", fmt.Errorf("connections: start flow: %w", err)
	}
	conf := s.oauthConfig(app, "", scopes)
	opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier)}
	for _, kv := range app.AuthParams() {
		opts = append(opts, oauth2.SetAuthURLParam(kv[0], kv[1]))
	}
	if param := app.Extra[ExtraScopeParam]; param != "" && param != "scope" {
		conf.Scopes = nil
		opts = append(opts, oauth2.SetAuthURLParam(param, strings.Join(scopes, " ")))
	}
	s.log.Info("connect flow started", "event", "connections.flow_started", "user_id", req.UserID, "vendor", app.Vendor, "variant", app.Variant, "scopes", strings.Join(scopes, " "))
	return conf.AuthCodeURL(state, opts...), nil
}

// Callback finishes a flow: it consumes the state (one use, same user),
// exchanges the code with PKCE, asks the vendor's binder who the account
// is, applies the personal-account policy, and stores the connection and
// its encrypted token bundle: the binder's Bound.Token when it returned
// one (Slack's authed_user token), else the exchanged token. Reconnecting
// an account the user already connected updates that connection with the
// union of scopes.
func (s *Service) Callback(ctx context.Context, req CallbackRequest) (Info, error) {
	if req.State == "" || req.UserID == "" {
		return Info{}, fmt.Errorf("%w: missing state", ErrFlowInvalid)
	}
	now := s.clock()
	var flow *store.ConnectFlow
	err := s.store.AsUser(ctx, req.UserID, func(tx Tx) (err error) {
		flow, err = tx.TakeConnectFlow(ctx, req.State, now)
		return err
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.log.Warn("connect callback with unknown state", "event", "connections.flow_rejected", "user_id", req.UserID, "vendor", req.Vendor, "reason", "unknown_state")
		return Info{}, fmt.Errorf("%w: unknown or expired state", ErrFlowInvalid)
	case err != nil:
		return Info{}, fmt.Errorf("connections: take flow: %w", err)
	}
	if req.Error != "" {
		s.log.Warn("vendor refused connection", "event", "connections.flow_rejected", "user_id", req.UserID, "vendor", req.Vendor, "reason", "vendor_error", "vendor_error", req.Error)
		return Info{}, fmt.Errorf("%w: %s", ErrVendorDenied, req.Error)
	}
	if req.Code == "" {
		return Info{}, fmt.Errorf("%w: missing code", ErrFlowInvalid)
	}
	app, row, err := s.appByID(ctx, flow.VendorAppID)
	if err != nil {
		return Info{}, err
	}
	if app.Vendor != strings.ToLower(strings.TrimSpace(req.Vendor)) {
		return Info{}, fmt.Errorf("%w: state belongs to another vendor", ErrFlowInvalid)
	}
	secret, err := s.clientSecret(ctx, row)
	if err != nil {
		return Info{}, err
	}
	conf := s.oauthConfig(app, secret, flow.Scopes)
	octx := s.oauthContext(ctx)
	tok, err := conf.Exchange(octx, req.Code, oauth2.VerifierOption(flow.Verifier))
	if err != nil {
		code := vendorErrorCode(err)
		s.log.Warn("code exchange failed", "event", "connections.exchange_failed", "user_id", req.UserID, "vendor", app.Vendor, "vendor_error", code)
		return Info{}, fmt.Errorf("%w: code exchange failed (%s)", ErrFlowInvalid, code)
	}
	s.normalizeExpiry(tok)
	bound, err := s.binderFor(app.Vendor).Bind(ctx, BindInput{
		App: app, Token: tok, Client: oauth2.NewClient(octx, oauth2.StaticTokenSource(tok)), RequestedScopes: flow.Scopes,
	})
	if err != nil {
		s.log.Warn("account binding failed", "event", "connections.bind_failed", "user_id", req.UserID, "vendor", app.Vendor, "error", observability.RedactError(err))
		return Info{}, fmt.Errorf("%w: could not identify the account", ErrFlowInvalid)
	}
	if bound.ExternalAccountID == "" {
		return Info{}, fmt.Errorf("%w: binder returned no account ID", ErrFlowInvalid)
	}
	label := string(bound.Label)
	if label != store.AccountCompany && label != store.AccountPersonal {
		return Info{}, fmt.Errorf("%w: binder returned label %q", ErrFlowInvalid, label)
	}
	stored := tok
	if bound.Token != nil {
		if bound.Token.AccessToken == "" {
			return Info{}, fmt.Errorf("%w: binder returned a token without an access token", ErrFlowInvalid)
		}
		stored = bound.Token
		s.normalizeExpiry(stored)
	}
	granted := unionScopes(bound.Scopes)
	if bound.Scopes == nil {
		granted = grantedScopes(stored, flow.Scopes)
	}
	if label == store.AccountPersonal {
		allowed, err := s.personalAllowed(ctx, req.UserID, app.Vendor)
		if err != nil {
			return Info{}, err
		}
		if !allowed {
			s.record(ctx, req.UserID, "", label, map[string]string{"action": "connect_refused", "vendor": app.Vendor, "variant": app.Variant}, "denied", "personal_account_denied")
			s.log.Warn("personal account refused by policy", "event", "connections.personal_refused", "user_id", req.UserID, "vendor", app.Vendor)
			return Info{}, ErrPersonalRefused
		}
	}
	var conn *store.Connection
	err = s.store.AsUser(ctx, req.UserID, func(tx Tx) error {
		existing, err := tx.FindConnection(ctx, req.UserID, app.ID, bound.ExternalAccountID)
		switch {
		case err == nil:
			conn = existing
			if conn.Status == store.ConnectionRevoked {
				conn.Scopes = granted
			} else {
				conn.Scopes = unionScopes(conn.Scopes, granted)
			}
			conn.Label, conn.DisplayName, conn.Status = label, bound.DisplayName, store.ConnectionActive
			if err := tx.UpdateConnection(ctx, conn); err != nil {
				return err
			}
		case errors.Is(err, store.ErrNotFound):
			conn = &store.Connection{
				UserID: req.UserID, VendorAppID: app.ID, ExternalAccountID: bound.ExternalAccountID,
				Label: label, DisplayName: bound.DisplayName, Scopes: granted, Status: store.ConnectionActive,
			}
			if err := tx.CreateConnection(ctx, conn); err != nil {
				return err
			}
		default:
			return err
		}
		if err := s.putToken(ctx, tx, req.UserID, conn.ID, app.Vendor, stored); err != nil {
			return err
		}
		if err := tx.TouchConnectionRefreshed(ctx, conn.ID, now); err != nil {
			return err
		}
		conn.LastRefreshedAt = &now
		return nil
	})
	if err != nil {
		return Info{}, fmt.Errorf("connections: store connection: %w", err)
	}
	s.record(ctx, req.UserID, conn.ID, label, map[string]string{"action": "connected", "vendor": app.Vendor, "variant": app.Variant}, "succeeded", "")
	s.log.Info("account connected", "event", "connections.connected", "user_id", req.UserID, "vendor", app.Vendor, "variant", app.Variant,
		"connection_id", conn.ID, "label", label, "scopes", strings.Join(conn.Scopes, " "))
	return toInfo(conn, app.Vendor, app.Variant), nil
}

// personalAllowed reports whether any connector app that uses the
// vendor's accounts allows personal ones for the user: a personal account
// is only useless, and therefore refused, when every app denies it (the
// per-call policy still denies the apps that do).
func (s *Service) personalAllowed(ctx context.Context, userID, vendor string) (bool, error) {
	for _, app := range s.appsFor(vendor) {
		ok, err := s.personalPolicy().PersonalAccountsAllowed(ctx, userID, app)
		if err != nil {
			return false, fmt.Errorf("connections: personal account policy: %w", err)
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// SetPolicy replaces the personal-account policy (tests, late wiring).
func (s *Service) SetPolicy(p PersonalAccountPolicy) {
	if p == nil {
		p = allowAllPolicy{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policy = p
}

// enabledApp loads the enabled app for vendor/variant.
func (s *Service) enabledApp(ctx context.Context, vendor, variant string) (VendorApp, *store.VendorApp, error) {
	vendor, variant = normalizeKey(vendor, variant)
	if !KnownVendor(vendor) {
		return VendorApp{}, nil, fmt.Errorf("%w: unknown vendor %q", ErrNotConfigured, vendor)
	}
	var row *store.VendorApp
	err := s.store.Bypass(ctx, func(tx Tx) (err error) {
		row, err = tx.FindVendorApp(ctx, vendor, variant)
		return err
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		return VendorApp{}, nil, fmt.Errorf("%w: %s/%s", ErrNotConfigured, vendor, variant)
	case err != nil:
		return VendorApp{}, nil, fmt.Errorf("connections: load vendor app: %w", err)
	}
	app, err := fromRow(row)
	if err != nil {
		return VendorApp{}, nil, err
	}
	if !app.Enabled {
		return VendorApp{}, nil, fmt.Errorf("%w: %s/%s is disabled", ErrNotConfigured, vendor, variant)
	}
	return app, row, nil
}

// appByID loads a vendor app by row ID.
func (s *Service) appByID(ctx context.Context, id string) (VendorApp, *store.VendorApp, error) {
	var row *store.VendorApp
	err := s.store.Bypass(ctx, func(tx Tx) (err error) {
		row, err = tx.GetVendorApp(ctx, id)
		return err
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		return VendorApp{}, nil, fmt.Errorf("%w: vendor app removed", ErrNotConfigured)
	case err != nil:
		return VendorApp{}, nil, fmt.Errorf("connections: load vendor app: %w", err)
	}
	app, err := fromRow(row)
	if err != nil {
		return VendorApp{}, nil, err
	}
	if !app.Enabled {
		return VendorApp{}, nil, fmt.Errorf("%w: %s/%s is disabled", ErrNotConfigured, app.Vendor, app.Variant)
	}
	return app, row, nil
}

// oauthConfig builds the x/oauth2 configuration for an app.
func (s *Service) oauthConfig(app VendorApp, secret string, scopes []string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     app.ClientID,
		ClientSecret: secret,
		Endpoint:     oauth2.Endpoint{AuthURL: app.AuthURL, TokenURL: app.TokenURL},
		RedirectURL:  s.RedirectURL(app.Vendor),
		Scopes:       scopes,
	}
}

// oauthContext makes x/oauth2 use the service's HTTP client.
func (s *Service) oauthContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, s.client)
}

// vendorErrorCode classifies an x/oauth2 error for logs: the OAuth error
// code when the vendor sent one, else a short class. Never the body.
func vendorErrorCode(err error) string {
	var re *oauth2.RetrieveError
	if errors.As(err, &re) {
		if re.ErrorCode != "" {
			return re.ErrorCode
		}
		return fmt.Sprintf("http_%d", re.Response.StatusCode)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	return "network"
}

// grantedScopes reads the vendor's "scope" field from the token response
// (space or comma separated) and falls back to what was requested.
func grantedScopes(tok *oauth2.Token, requested []string) []string {
	if raw, ok := tok.Extra("scope").(string); ok && strings.TrimSpace(raw) != "" {
		return SplitScopes(raw)
	}
	return unionScopes(requested)
}

// tokenBundle is the plaintext of a connection secret.
type tokenBundle struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type,omitempty"`
	Expiry       time.Time `json:"expiry,omitempty"`
}

func (b tokenBundle) token() *oauth2.Token {
	return &oauth2.Token{AccessToken: b.AccessToken, RefreshToken: b.RefreshToken, TokenType: b.TokenType, Expiry: b.Expiry}
}

func encodeBundle(tok *oauth2.Token) ([]byte, error) {
	if tok == nil || tok.AccessToken == "" {
		return nil, errors.New("connections: vendor returned no access token")
	}
	b, err := json.Marshal(tokenBundle{AccessToken: tok.AccessToken, RefreshToken: tok.RefreshToken, TokenType: tok.TokenType, Expiry: tok.Expiry})
	if err != nil {
		return nil, fmt.Errorf("connections: encode token: %w", err)
	}
	return b, nil
}

func decodeBundle(plain []byte) (*oauth2.Token, error) {
	var b tokenBundle
	if err := json.Unmarshal(plain, &b); err != nil {
		return nil, fmt.Errorf("connections: decode token: %w", err)
	}
	return b.token(), nil
}

// aadFor is the associated data a connection's token bundle is sealed
// under: it binds the ciphertext to the user, the connection and the
// vendor so it cannot be moved between rows.
func aadFor(userID, connectionID, vendor string) crypto.AAD {
	return crypto.AAD{UserID: userID, Kind: aadKindConnection, RecordID: connectionID, App: vendor}
}

// putToken encrypts tok for the connection and stores it.
func (s *Service) putToken(ctx context.Context, tx Tx, userID, connectionID, vendor string, tok *oauth2.Token) error {
	plain, err := encodeBundle(tok)
	if err != nil {
		return err
	}
	env, err := crypto.Encrypt(ctx, s.keys, aadFor(userID, connectionID, vendor), plain)
	if err != nil {
		return fmt.Errorf("connections: encrypt token: %w", err)
	}
	sec := &store.ConnectionSecret{ConnectionID: connectionID, UserID: userID, Secret: store.Encrypted(env)}
	if !tok.Expiry.IsZero() {
		exp := tok.Expiry
		sec.TokenExpiresAt = &exp
	}
	return tx.PutSecret(ctx, sec)
}

// getToken loads and decrypts the connection's token bundle.
func (s *Service) getToken(ctx context.Context, tx Tx, userID, connectionID, vendor string) (*oauth2.Token, error) {
	sec, err := tx.GetSecret(ctx, connectionID)
	if err != nil {
		return nil, err
	}
	plain, err := crypto.Decrypt(ctx, s.keys, aadFor(userID, connectionID, vendor), crypto.Envelope(sec.Secret))
	if err != nil {
		return nil, fmt.Errorf("connections: decrypt token: %w", err)
	}
	return decodeBundle(plain)
}

func toInfo(c *store.Connection, vendor, variant string) Info {
	return Info{
		ID: c.ID, UserID: c.UserID, Vendor: vendor, Variant: variant, ExternalAccountID: c.ExternalAccountID,
		Label: c.Label, DisplayName: c.DisplayName, Scopes: append([]string(nil), c.Scopes...), Status: c.Status,
		LastRefreshedAt: c.LastRefreshedAt, CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt,
	}
}

// randomToken returns 32 random bytes, base64url encoded (the state).
func randomToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("connections: random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
