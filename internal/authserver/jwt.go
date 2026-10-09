package authserver

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// Access tokens are JWTs (RFC 9068 profile: typ "at+jwt") signed with the
// active ES256 key: iss = the issuer, sub = the user id, aud = the
// resource the client asked for (RFC 8707), client_id, scope, jti, and
// fid, the refresh-token family the token belongs to (one family = one
// connected harness; it is the principal's TokenID so audit rows name the
// harness). They are not stored: a replica validates one with the JWKS it
// loaded from the shared table.

const (
	// accessTokenType is the typ header (RFC 9068).
	accessTokenType = "at+jwt"
	// Leeway tolerates clock skew between replicas on exp / nbf.
	Leeway = 30 * time.Second
	// PublicIDPrefix marks OAuth principals in logs ("oauth_" + 8 chars
	// of the family id), the way "mgw_" marks generated tokens.
	PublicIDPrefix = "oauth_"
)

// Grant is what an access token asserts.
type Grant struct {
	UserID   string
	ClientID string
	// Scope is a space-separated list from ScopesSupported.
	Scope    string
	Resource string
	// FamilyID is the refresh-token family (a uuid) the token belongs to.
	FamilyID string
}

// accessClaims is the JWT body.
type accessClaims struct {
	jwt.Claims
	ClientID string `json:"client_id"`
	Scope    string `json:"scope"`
	FamilyID string `json:"fid"`
}

// Minter signs access tokens.
type Minter struct {
	cfg  Config
	keys *Keys
	now  func() time.Time
}

// NewMinter builds a minter for cfg over the key manager.
func NewMinter(cfg Config, keys *Keys) *Minter {
	return &Minter{cfg: cfg, keys: keys, now: func() time.Time { return time.Now().UTC() }}
}

// SetClock replaces the time source (tests).
func (m *Minter) SetClock(now func() time.Time) { m.now = now }

// Mint signs an access token for g and returns it with its expiry.
func (m *Minter) Mint(ctx context.Context, g Grant) (string, time.Time, error) {
	key, err := m.keys.Current(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: key.Algorithm, Key: key.Private},
		(&jose.SignerOptions{}).WithType(accessTokenType).WithHeader("kid", key.KID))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("authserver: signer: %w", err)
	}
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", time.Time{}, fmt.Errorf("authserver: jti: %w", err)
	}
	now := m.now()
	exp := now.Add(m.cfg.AccessTokenTTL)
	claims := accessClaims{
		Claims: jwt.Claims{
			Issuer:    m.cfg.issuer(),
			Subject:   g.UserID,
			Audience:  jwt.Audience{g.Resource},
			ID:        base64.RawURLEncoding.EncodeToString(jti),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Expiry:    jwt.NewNumericDate(exp),
		},
		ClientID: g.ClientID,
		Scope:    g.Scope,
		FamilyID: g.FamilyID,
	}
	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("authserver: sign: %w", err)
	}
	return raw, exp, nil
}

// AuthenticatorOptions configures NewJWTAuthenticator.
type AuthenticatorOptions struct {
	// Metrics counts rejections in auth_failures_total{reason}; nil
	// disables that.
	Metrics *observability.Metrics
	// Log defaults to slog.Default().
	Log *slog.Logger
}

// JWTAuthenticator is the tokens.Authenticator for the gateway's own
// access tokens: signature by kid, issuer, audience (the MCP resource),
// expiry, then the owner's status. Every rejection is a *tokens.Error so
// the bearer middleware answers 401 and counts it; a store outage is a
// plain error (503).
type JWTAuthenticator struct {
	cfg     Config
	st      Store
	keys    *Keys
	metrics *observability.Metrics
	log     *slog.Logger
	now     func() time.Time
}

// NewJWTAuthenticator builds the authenticator.
func NewJWTAuthenticator(cfg Config, st Store, keys *Keys, opts AuthenticatorOptions) *JWTAuthenticator {
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	return &JWTAuthenticator{cfg: cfg, st: st, keys: keys, metrics: opts.Metrics, log: opts.Log, now: func() time.Time { return time.Now().UTC() }}
}

// SetClock replaces the time source (tests).
func (a *JWTAuthenticator) SetClock(now func() time.Time) { a.now = now }

// Authenticate implements tokens.Authenticator.
func (a *JWTAuthenticator) Authenticate(ctx context.Context, bearer string) (*tokens.Principal, error) {
	tok, err := jwt.ParseSigned(bearer, []jose.SignatureAlgorithm{SigningAlgorithm})
	if err != nil || len(tok.Headers) != 1 {
		return nil, a.reject(tokens.ReasonMalformed, "", "parse")
	}
	kid := tok.Headers[0].KeyID
	if kid == "" {
		return nil, a.reject(tokens.ReasonMalformed, "", "no_kid")
	}
	pub, err := a.keys.Verifier(ctx, kid)
	switch {
	case errors.Is(err, ErrUnknownKey):
		return nil, a.reject(tokens.ReasonUnknown, "", "unknown_kid")
	case err != nil:
		return nil, err
	}
	var claims accessClaims
	if err := tok.Claims(pub, &claims); err != nil {
		return nil, a.reject(tokens.ReasonUnknown, "", "bad_signature")
	}
	publicID := PublicIDPrefix + shortID(claims.FamilyID)
	now := a.now()
	err = claims.ValidateWithLeeway(jwt.Expected{Issuer: a.cfg.issuer(), AnyAudience: jwt.Audience{a.cfg.Resource()}, Time: now}, Leeway)
	switch {
	case errors.Is(err, jwt.ErrExpired):
		return nil, a.reject(tokens.ReasonExpired, publicID, "expired")
	case errors.Is(err, jwt.ErrInvalidAudience):
		return nil, a.reject(tokens.ReasonUnknown, publicID, "wrong_audience")
	case errors.Is(err, jwt.ErrInvalidIssuer):
		return nil, a.reject(tokens.ReasonUnknown, publicID, "wrong_issuer")
	case err != nil:
		return nil, a.reject(tokens.ReasonUnknown, publicID, "invalid_claims")
	}
	if claims.Subject == "" || claims.FamilyID == "" {
		return nil, a.reject(tokens.ReasonMalformed, publicID, "missing_claims")
	}
	scope, ok := ScopeToTokens(claims.Scope)
	if !ok {
		return nil, a.reject(tokens.ReasonUnknown, publicID, "bad_scope")
	}
	var facts *store.UserAuthFacts
	err = a.st.Bypass(ctx, func(tx Tx) error {
		var err error
		facts, err = tx.FindUserAuthFacts(ctx, claims.Subject)
		return err
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, a.reject(tokens.ReasonUnknown, publicID, "unknown_user")
	case err != nil:
		a.log.Error("user lookup failed", "event", "authserver.auth_lookup_failed", "public_id", publicID, "error", observability.RedactError(err))
		return nil, fmt.Errorf("authserver: user lookup: %w", err)
	case facts.Status != store.UserActive:
		return nil, a.reject(tokens.ReasonUserDisabled, publicID, "user_disabled")
	}
	return &tokens.Principal{UserID: claims.Subject, TokenID: claims.FamilyID, PublicID: publicID, Scope: scope}, nil
}

// reject counts and logs a failure and builds its error. detail names the
// check that failed (for the log only; the harness sees the reason).
func (a *JWTAuthenticator) reject(reason tokens.Reason, publicID, detail string) error {
	if a.metrics != nil {
		a.metrics.AuthFailure(string(reason))
	}
	a.log.Warn("access token rejected", "event", "authserver.auth_failed", "reason", string(reason), "detail", detail, "public_id", publicID)
	return &tokens.Error{Reason: reason, PublicID: publicID}
}

// ParseScope validates a requested scope string against ScopesSupported
// and returns it canonicalised (sorted, de-duplicated, space-separated).
// Empty means ScopeFull. ok is false for an unknown scope value.
func ParseScope(requested string) (string, bool) {
	fields := strings.Fields(requested)
	if len(fields) == 0 {
		return ScopeFull, true
	}
	for _, f := range fields {
		if !slices.Contains(ScopesSupported, f) {
			return "", false
		}
	}
	slices.Sort(fields)
	return strings.Join(slices.Compact(fields), " "), true
}

// ScopeToTokens maps an OAuth scope string onto the pipeline's token
// scope: "mcp" is unrestricted, "mcp:read" alone is read-only. The user's
// role still bounds everything (policy combines both).
func ScopeToTokens(scope string) (tokens.Scope, bool) {
	canonical, ok := ParseScope(scope)
	if !ok {
		return tokens.Scope{}, false
	}
	fields := strings.Fields(canonical)
	return tokens.Scope{ReadOnly: !slices.Contains(fields, ScopeFull)}, true
}

// shortID is the first 8 characters of an id, for logs.
func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// Composite routes a bearer to the generated-token authenticator (mgw_
// prefix) or the access-token authenticator (three dot-separated
// segments, a JWS). Anything else goes to the generated-token one, whose
// "malformed" answer is the right one for it.
func Composite(mgw, jwtAuth tokens.Authenticator) tokens.Authenticator {
	return composite{mgw: mgw, jwt: jwtAuth}
}

type composite struct{ mgw, jwt tokens.Authenticator }

func (c composite) Authenticate(ctx context.Context, bearer string) (*tokens.Principal, error) {
	if strings.HasPrefix(bearer, tokens.Prefix) {
		return c.mgw.Authenticate(ctx, bearer)
	}
	if looksLikeJWS(bearer) {
		return c.jwt.Authenticate(ctx, bearer)
	}
	return c.mgw.Authenticate(ctx, bearer)
}

// looksLikeJWS reports whether bearer has the compact JWS shape: three
// non-empty base64url segments.
func looksLikeJWS(bearer string) bool {
	parts := strings.Split(bearer, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, r := range p {
			if !isBase64URLRune(r) {
				return false
			}
		}
	}
	return true
}

func isBase64URLRune(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_'
}
