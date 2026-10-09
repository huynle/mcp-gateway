package authserver

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/store"
)

// The token endpoint (OAuth 2.1 section 3.2): authorization_code with
// PKCE and refresh_token with rotation. Codes are single use; a replayed
// code revokes the refresh-token family it produced (section 4.1.3). A
// refresh token is exchanged for a successor in the same family and
// marked rotated; presenting a rotated token again is reuse and revokes
// the family (section 4.3.1). Access tokens are minted here and never
// stored.

// RefreshTokenPrefix starts every refresh token so logs and scanners can
// tell it apart from codes and generated tokens.
const RefreshTokenPrefix = "gwr_"

// tokenResponse is the RFC 6749 section 5.1 success body.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope"`
}

// tokenError is a refused token request.
type tokenError struct {
	status            int
	code, description string
}

func (e *tokenError) Error() string { return e.code + ": " + e.description }

func badRequest(code, description string) *tokenError {
	return &tokenError{status: http.StatusBadRequest, code: code, description: description}
}

var errInvalidClient = &tokenError{status: http.StatusUnauthorized, code: "invalid_client", description: "client authentication failed"}

// ServeToken is POST /oauth/token.
func (s *Service) ServeToken(w http.ResponseWriter, r *http.Request) {
	form, client, terr := s.parseClientRequest(w, r)
	if terr != nil {
		s.writeTokenError(w, terr)
		return
	}
	var resp *tokenResponse
	switch form.Get("grant_type") {
	case "":
		terr = badRequest("invalid_request", "grant_type is required")
	case GrantAuthorizationCode:
		resp, terr = s.exchangeCode(r.Context(), client, form)
	case GrantRefreshToken:
		resp, terr = s.refreshTokens(r.Context(), client, form)
	default:
		terr = badRequest("unsupported_grant_type", "grant_type must be authorization_code or refresh_token")
	}
	if terr != nil {
		s.writeTokenError(w, terr)
		return
	}
	s.touchClient(r.Context(), client.ID, s.now())
	writeJSON(w, http.StatusOK, resp)
}

// ServeRevoke is POST /oauth/revoke (RFC 7009): a refresh token of the
// authenticated client is revoked together with its family. Access
// tokens are not stored and cannot be revoked individually (they expire
// within the hour; revoking the family stops renewal); unknown tokens and
// other clients' tokens are answered 200 like a success, as the RFC asks.
func (s *Service) ServeRevoke(w http.ResponseWriter, r *http.Request) {
	form, client, terr := s.parseClientRequest(w, r)
	if terr != nil {
		s.writeTokenError(w, terr)
		return
	}
	token := form.Get("token")
	if token == "" {
		s.writeTokenError(w, badRequest("invalid_request", "token is required"))
		return
	}
	now := s.now()
	var revoked int64
	err := s.st.Bypass(r.Context(), func(tx Tx) error {
		l, err := tx.FindRefreshTokenByHash(r.Context(), hashSecret(token))
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if l.Token.ClientID != client.ID {
			return nil
		}
		revoked, err = tx.RevokeRefreshFamily(r.Context(), l.Token.FamilyID, now)
		if err == nil && revoked > 0 {
			s.log.Info("refresh token family revoked by client", "event", "authserver.family_revoked", "user_id", l.Token.UserID, "family_id", l.Token.FamilyID, "client_id", client.ClientID)
			s.record(r.Context(), l.Token.UserID, l.Token.FamilyID, "oauth_harness_revoked_by_client", client, "allow", "succeeded")
		}
		return err
	})
	if err != nil {
		s.log.Error("revocation failed", "event", "authserver.revoke_failed", "error", observability.RedactError(err))
		s.writeTokenError(w, &tokenError{status: http.StatusServiceUnavailable, code: "server_error", description: "revocation is temporarily unavailable"})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}

// parseClientRequest reads the form body and authenticates the client:
// HTTP Basic (client_secret_basic), client_secret in the body
// (client_secret_post), or just client_id for public clients. A client
// registered with a secret must present it.
func (s *Service) parseClientRequest(w http.ResponseWriter, r *http.Request) (url.Values, *store.OAuthClient, *tokenError) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		return nil, nil, &tokenError{status: http.StatusMethodNotAllowed, code: "invalid_request", description: "POST only"}
	}
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(strings.ToLower(ct), "application/x-www-form-urlencoded") {
		return nil, nil, badRequest("invalid_request", "the body must be application/x-www-form-urlencoded")
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		return nil, nil, badRequest("invalid_request", "the form could not be read")
	}
	form := r.PostForm
	// OAuth 2.1 section 3.2.2: no parameter may appear more than once.
	if duplicated(form, "grant_type", "client_id", "client_secret", "code", "redirect_uri", "code_verifier", "refresh_token", "resource", "scope", "token") {
		return nil, nil, badRequest("invalid_request", "a parameter is repeated")
	}
	clientID, secret := form.Get("client_id"), form.Get("client_secret")
	viaBasic := false
	if user, pass, ok := r.BasicAuth(); ok {
		viaBasic = true
		// RFC 6749 section 2.3.1: both parts are form-urlencoded.
		u, err1 := url.QueryUnescape(user)
		p, err2 := url.QueryUnescape(pass)
		if err1 != nil || err2 != nil || (clientID != "" && clientID != u) {
			return nil, nil, errInvalidClient
		}
		clientID, secret = u, p
	}
	if clientID == "" {
		return nil, nil, badRequest("invalid_request", "client_id is required")
	}
	var client *store.OAuthClient
	err := s.st.Bypass(r.Context(), func(tx Tx) error {
		var err error
		client, err = tx.FindClientByClientID(r.Context(), clientID)
		return err
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		if viaBasic {
			w.Header().Set("WWW-Authenticate", `Basic realm="mcp-gateway"`)
		}
		return nil, nil, errInvalidClient
	case err != nil:
		s.log.Error("client lookup failed", "event", "authserver.client_lookup_failed", "error", observability.RedactError(err))
		return nil, nil, &tokenError{status: http.StatusServiceUnavailable, code: "server_error", description: "temporarily unavailable"}
	}
	if len(client.ClientSecretHash) > 0 {
		if secret == "" || subtle.ConstantTimeCompare(hashSecret(secret), client.ClientSecretHash) != 1 {
			if viaBasic {
				w.Header().Set("WWW-Authenticate", `Basic realm="mcp-gateway"`)
			}
			s.log.Warn("client authentication failed", "event", "authserver.client_auth_failed", "client_id", clientID)
			return nil, nil, errInvalidClient
		}
	}
	return form, client, nil
}

// exchangeCode is the authorization_code grant. Consuming the code, the
// checks, the refresh-token row and the code's family are one
// transaction, so a racing replay (which waits on the row lock) sees the
// family it must revoke, and a failed check still burns the code.
func (s *Service) exchangeCode(ctx context.Context, client *store.OAuthClient, form url.Values) (*tokenResponse, *tokenError) {
	code, verifier := form.Get("code"), form.Get("code_verifier")
	switch {
	case code == "":
		return nil, badRequest("invalid_request", "code is required")
	case verifier == "":
		return nil, badRequest("invalid_request", "code_verifier is required (PKCE)")
	case !pkceRE.MatchString(verifier):
		return nil, badRequest("invalid_request", "code_verifier must be 43 to 128 characters of [A-Za-z0-9._~-]")
	}
	now := s.now()
	var row *store.OAuthCode
	var consumed bool
	var terr *tokenError
	var refreshRaw, familyID string
	meta := clientMeta(client)
	wantRefresh := false
	for _, g := range meta.GrantTypes {
		if g == GrantRefreshToken {
			wantRefresh = true
		}
	}
	err := s.st.Bypass(ctx, func(tx Tx) error {
		var err error
		row, consumed, err = tx.ConsumeCode(ctx, hashSecret(code), now)
		if err != nil || !consumed {
			return err
		}
		terr = s.checkCode(ctx, tx, client, row, form, verifier, now)
		if terr != nil || !wantRefresh {
			return nil
		}
		refreshRaw, familyID, err = s.createRefresh(ctx, tx, issue{userID: row.UserID, client: client, scope: row.Scope, resource: row.Resource}, now)
		if err != nil {
			return err
		}
		return tx.SetCodeFamily(ctx, row.ID, familyID)
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.log.Warn("unknown authorization code", "event", "authserver.code_unknown", "client_id", client.ClientID)
		return nil, badRequest("invalid_grant", "the authorization code is invalid")
	case err != nil:
		return nil, s.serverError("exchange code", err)
	case !consumed:
		// Replay: whoever holds the code now, the tokens it produced are
		// not safe to keep.
		s.revokeFamilyOnReplay(ctx, row, client)
		return nil, badRequest("invalid_grant", "the authorization code was already used")
	case terr != nil:
		return nil, terr
	}
	resp, terr := s.mintResponse(ctx, Grant{UserID: row.UserID, ClientID: client.ClientID, Scope: row.Scope, Resource: row.Resource, FamilyID: familyID}, refreshRaw, now)
	if terr != nil {
		return nil, terr
	}
	s.log.Info("tokens issued", "event", "authserver.tokens_issued", "grant", GrantAuthorizationCode, "user_id", row.UserID, "client_id", client.ClientID, "family_id", familyID, "scope", row.Scope)
	return resp, nil
}

// checkCode applies the code-binding checks and the owner check.
func (s *Service) checkCode(ctx context.Context, tx Tx, client *store.OAuthClient, row *store.OAuthCode, form url.Values, verifier string, now time.Time) *tokenError {
	switch {
	case row.ClientID != client.ID:
		s.log.Warn("authorization code presented by another client", "event", "authserver.code_wrong_client", "client_id", client.ClientID, "user_id", row.UserID)
		return badRequest("invalid_grant", "the authorization code was not issued to this client")
	case now.After(row.ExpiresAt):
		return badRequest("invalid_grant", "the authorization code has expired")
	case form.Get("redirect_uri") != row.RedirectURI:
		return badRequest("invalid_grant", "redirect_uri does not match the authorization request")
	case form.Get("resource") != "" && !sameResource(form.Get("resource"), row.Resource):
		return badRequest("invalid_target", "resource must be "+row.Resource)
	case !pkceVerify(verifier, row.CodeChallenge):
		s.log.Warn("PKCE verification failed", "event", "authserver.pkce_failed", "client_id", client.ClientID, "user_id", row.UserID)
		return badRequest("invalid_grant", "code_verifier does not match the code challenge")
	}
	facts, err := tx.FindUserAuthFacts(ctx, row.UserID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return badRequest("invalid_grant", "the user no longer exists")
	case err != nil:
		return s.serverError("user lookup", err)
	case facts.Status != store.UserActive:
		return badRequest("invalid_grant", "the user is disabled")
	}
	return nil
}

// revokeFamilyOnReplay revokes the refresh-token family a replayed code
// produced and records the event.
func (s *Service) revokeFamilyOnReplay(ctx context.Context, row *store.OAuthCode, client *store.OAuthClient) {
	s.log.Warn("authorization code replayed", "event", "authserver.code_replayed", "client_id", client.ClientID, "user_id", row.UserID)
	if row.FamilyID == nil {
		return
	}
	now := s.now()
	err := s.st.Bypass(ctx, func(tx Tx) error {
		_, err := tx.RevokeRefreshFamily(ctx, *row.FamilyID, now)
		return err
	})
	if err != nil {
		s.log.Error("family not revoked after code replay", "event", "authserver.replay_revoke_failed", "error", observability.RedactError(err))
		return
	}
	s.record(ctx, row.UserID, *row.FamilyID, "oauth_code_replayed", client, "deny", "denied")
}

// refreshTokens is the refresh_token grant with rotation and reuse
// detection.
func (s *Service) refreshTokens(ctx context.Context, client *store.OAuthClient, form url.Values) (*tokenResponse, *tokenError) {
	raw := form.Get("refresh_token")
	if raw == "" {
		return nil, badRequest("invalid_request", "refresh_token is required")
	}
	now := s.now()
	var l *store.RefreshTokenLookup
	err := s.st.Bypass(ctx, func(tx Tx) error {
		var err error
		l, err = tx.FindRefreshTokenByHash(ctx, hashSecret(raw))
		return err
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, badRequest("invalid_grant", "the refresh token is invalid")
	case err != nil:
		s.log.Error("refresh token lookup failed", "event", "authserver.refresh_lookup_failed", "error", observability.RedactError(err))
		return nil, &tokenError{status: http.StatusServiceUnavailable, code: "server_error", description: "temporarily unavailable"}
	}
	t := l.Token
	switch {
	case t.ClientID != client.ID:
		s.log.Warn("refresh token presented by another client", "event", "authserver.refresh_wrong_client", "client_id", client.ClientID, "user_id", t.UserID, "family_id", t.FamilyID)
		return nil, badRequest("invalid_grant", "the refresh token was not issued to this client")
	case t.RevokedAt != nil:
		return nil, badRequest("invalid_grant", "the refresh token was revoked")
	case t.RotatedAt != nil:
		s.revokeFamilyOnReuse(ctx, &t, client)
		return nil, badRequest("invalid_grant", "the refresh token was already used; sign in again")
	case now.After(t.ExpiresAt):
		return nil, badRequest("invalid_grant", "the refresh token has expired; sign in again")
	case l.UserStatus != store.UserActive:
		return nil, badRequest("invalid_grant", "the user is disabled")
	case l.LastCompanySignInAt == nil || now.Sub(*l.LastCompanySignInAt) > s.cfg.SignInMaxAge:
		return nil, badRequest("invalid_grant", "sign in to the portal to reactivate this harness")
	case form.Get("resource") != "" && !sameResource(form.Get("resource"), t.Resource):
		return nil, badRequest("invalid_target", "resource must be "+t.Resource)
	}
	scope := scopeFromStore(t.Scope)
	if requested := form.Get("scope"); requested != "" {
		canonical, ok := ParseScope(requested)
		if !ok || !scopeWithin(canonical, scope) {
			return nil, badRequest("invalid_scope", "scope must be within "+scope)
		}
		scope = canonical
	}
	var refreshRaw string
	err = s.st.Bypass(ctx, func(tx Tx) error {
		rotated, err := tx.RotateRefreshToken(ctx, t.ID, now)
		if err != nil {
			return err
		}
		if !rotated {
			return errRotatedConcurrently
		}
		refreshRaw, _, err = s.createRefresh(ctx, tx, issue{userID: t.UserID, client: client, scope: scope, resource: t.Resource, rotate: &t}, now)
		return err
	})
	switch {
	case errors.Is(err, errRotatedConcurrently):
		// Two exchanges raced on the same token: the loser is the reuse case.
		s.revokeFamilyOnReuse(ctx, &t, client)
		return nil, badRequest("invalid_grant", "the refresh token was already used; sign in again")
	case err != nil:
		return nil, s.serverError("rotate refresh token", err)
	}
	resp, terr := s.mintResponse(ctx, Grant{UserID: t.UserID, ClientID: client.ClientID, Scope: scope, Resource: t.Resource, FamilyID: t.FamilyID}, refreshRaw, now)
	if terr != nil {
		return nil, terr
	}
	s.log.Info("tokens issued", "event", "authserver.tokens_issued", "grant", GrantRefreshToken, "user_id", t.UserID, "client_id", client.ClientID, "family_id", t.FamilyID, "scope", scope)
	return resp, nil
}

// revokeFamilyOnReuse revokes a family whose rotated token came back and
// records the event.
func (s *Service) revokeFamilyOnReuse(ctx context.Context, t *store.OAuthRefreshToken, client *store.OAuthClient) {
	s.log.Warn("refresh token reuse detected; family revoked", "event", "authserver.refresh_reuse", "user_id", t.UserID, "family_id", t.FamilyID, "client_id", client.ClientID)
	now := s.now()
	err := s.st.Bypass(ctx, func(tx Tx) error {
		_, err := tx.RevokeRefreshFamily(ctx, t.FamilyID, now)
		return err
	})
	if err != nil {
		s.log.Error("family not revoked after reuse", "event", "authserver.reuse_revoke_failed", "error", observability.RedactError(err))
		return
	}
	s.record(ctx, t.UserID, t.FamilyID, "oauth_refresh_reuse", client, "deny", "denied")
}

// issue describes a refresh token to create.
type issue struct {
	userID   string
	client   *store.OAuthClient
	scope    string
	resource string
	// rotate is the token being exchanged (nil for a new family).
	rotate *store.OAuthRefreshToken
}

// createRefresh stores a refresh token inside tx and returns the raw
// token and its family id.
func (s *Service) createRefresh(ctx context.Context, tx Tx, in issue, now time.Time) (raw, familyID string, err error) {
	raw, err = randomToken(32)
	if err != nil {
		return "", "", fmt.Errorf("refresh token: %w", err)
	}
	raw = RefreshTokenPrefix + raw
	scopeDoc, err := json.Marshal(in.scope) // the scope column is jsonb: a JSON string
	if err != nil {
		return "", "", err
	}
	row := &store.OAuthRefreshToken{UserID: in.userID, ClientID: in.client.ID, Resource: in.resource, TokenHash: hashSecret(raw), Scope: scopeDoc, ExpiresAt: now.Add(s.cfg.RefreshTokenTTL)}
	if in.rotate != nil {
		row.FamilyID = in.rotate.FamilyID
		row.RotatedFrom = &in.rotate.ID
	}
	if err := tx.CreateRefreshToken(ctx, row); err != nil {
		return "", "", err
	}
	return raw, row.FamilyID, nil
}

// mintResponse signs the access token and builds the token response.
func (s *Service) mintResponse(ctx context.Context, g Grant, refreshRaw string, now time.Time) (*tokenResponse, *tokenError) {
	access, exp, err := s.mint.Mint(ctx, g)
	if err != nil {
		return nil, s.serverError("mint access token", err)
	}
	return &tokenResponse{AccessToken: access, TokenType: "Bearer", ExpiresIn: int64(exp.Sub(now) / time.Second), RefreshToken: refreshRaw, Scope: g.Scope}, nil
}

var errRotatedConcurrently = errors.New("authserver: refresh token rotated concurrently")

func (s *Service) serverError(what string, err error) *tokenError {
	s.log.Error("token issue failed", "event", "authserver.issue_failed", "what", what, "error", observability.RedactError(err))
	return &tokenError{status: http.StatusServiceUnavailable, code: "server_error", description: "tokens are temporarily unavailable"}
}

func (s *Service) writeTokenError(w http.ResponseWriter, e *tokenError) {
	writeError(w, e.status, e.code, e.description)
}

// pkceVerify checks S256(verifier) against the stored challenge in
// constant time.
func pkceVerify(verifier, challenge string) bool {
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

// scopeFromStore decodes the jsonb scope column (a JSON string; rows
// written before the authorization server existed hold '{}').
func scopeFromStore(raw []byte) string {
	var scope string
	if err := json.Unmarshal(raw, &scope); err != nil || scope == "" {
		return ScopeFull
	}
	return scope
}
