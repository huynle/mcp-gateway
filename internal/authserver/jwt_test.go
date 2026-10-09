package authserver_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/huynle/mcp-gateway/internal/authserver"
	"github.com/huynle/mcp-gateway/internal/authserver/authservertest"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

const (
	alice = "00000000-0000-4000-8000-00000000000a"
	bob   = "00000000-0000-4000-8000-00000000000b"
)

var t0 = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

// jwtFixture is the signing side (keys + minter) and the verifying side
// (authenticator) over one in-memory store and a settable clock.
type jwtFixture struct {
	st    *authservertest.MemStore
	keys  *authserver.Keys
	mint  *authserver.Minter
	auth  *authserver.JWTAuthenticator
	now   time.Time
	cfg   authserver.Config
	clock func() time.Time
}

func newJWT(t *testing.T) *jwtFixture {
	t.Helper()
	f := &jwtFixture{st: authservertest.NewMemStore(), now: t0, cfg: testConfig()}
	f.clock = func() time.Time { return f.now }
	f.st.Now = f.clock
	kp, err := crypto.NewStaticProvider("k1", map[string][]byte{"k1": bytes.Repeat([]byte{7}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.DiscardHandler)
	f.keys = authserver.NewKeys(f.st, kp, authserver.KeysOptions{Grace: f.cfg.KeyGrace, Log: log})
	f.keys.SetClock(f.clock)
	f.mint = authserver.NewMinter(f.cfg, f.keys)
	f.mint.SetClock(f.clock)
	f.auth = authserver.NewJWTAuthenticator(f.cfg, f.st, f.keys, authserver.AuthenticatorOptions{Log: log})
	f.auth.SetClock(f.clock)
	signedIn := t0.Add(-time.Hour)
	f.st.AddUser(alice, &signedIn)
	return f
}

func (f *jwtFixture) grant() authserver.Grant {
	return authserver.Grant{UserID: alice, ClientID: "client-1", Scope: authserver.ScopeFull, Resource: f.cfg.Resource(), FamilyID: "00000000-0000-4000-8000-0000000000f1"}
}

func reason(t *testing.T, err error) tokens.Reason {
	t.Helper()
	var te *tokens.Error
	if !errors.As(err, &te) {
		t.Fatalf("error %v is not a *tokens.Error", err)
	}
	return te.Reason
}

func TestMintAndAuthenticate(t *testing.T) {
	f := newJWT(t)
	ctx := context.Background()
	raw, exp, err := f.mint.Mint(ctx, f.grant())
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if !exp.Equal(t0.Add(time.Hour)) {
		t.Errorf("exp = %v, want %v", exp, t0.Add(time.Hour))
	}
	// Three base64url segments, an at+jwt header with a kid and ES256.
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts", len(parts))
	}
	hdr, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var header map[string]any
	_ = json.Unmarshal(hdr, &header)
	if header["alg"] != "ES256" || header["typ"] != "at+jwt" || header["kid"] == "" {
		t.Errorf("header = %v", header)
	}
	body, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	_ = json.Unmarshal(body, &claims)
	if claims["iss"] != "https://gw.example.com" || claims["sub"] != alice || claims["client_id"] != "client-1" || claims["scope"] != "mcp" || claims["jti"] == "" {
		t.Errorf("claims = %v", claims)
	}
	if aud, _ := claims["aud"].(string); aud != "https://gw.example.com/mcp" {
		t.Errorf("aud = %v", claims["aud"])
	}

	p, err := f.auth.Authenticate(ctx, raw)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if p.UserID != alice || p.TokenID != "00000000-0000-4000-8000-0000000000f1" || p.Scope.ReadOnly || p.Scope.IsRestricted() || p.PublicID == "" {
		t.Errorf("principal = %+v", p)
	}
	// Second call hits the kid cache and still works.
	if _, err := f.auth.Authenticate(ctx, raw); err != nil {
		t.Fatalf("second Authenticate: %v", err)
	}
}

func TestReadScopeIsReadOnlyPrincipal(t *testing.T) {
	f := newJWT(t)
	g := f.grant()
	g.Scope = authserver.ScopeRead
	raw, _, err := f.mint.Mint(context.Background(), g)
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.auth.Authenticate(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Scope.ReadOnly {
		t.Errorf("mcp:read token should be read-only: %+v", p.Scope)
	}
}

func TestRejectedTokens(t *testing.T) {
	f := newJWT(t)
	ctx := context.Background()
	good, _, err := f.mint.Mint(ctx, f.grant())
	if err != nil {
		t.Fatal(err)
	}
	otherResource := f.grant()
	otherResource.Resource = "https://other.example.com/mcp"
	forOther, _, _ := f.mint.Mint(ctx, otherResource)

	otherIssuer := f.cfg
	otherIssuer.Issuer = "https://evil.example.com"
	badIss := authserver.NewMinter(otherIssuer, f.keys)
	badIss.SetClock(f.clock)
	wrongIss, _, _ := badIss.Mint(ctx, f.grant())

	// A token signed by a key this gateway never had (same kid, other key).
	foreignKeys := authserver.NewKeys(authservertest.NewMemStore(), mustProvider(t), authserver.KeysOptions{Grace: time.Hour})
	foreignKeys.SetClock(f.clock)
	foreignMint := authserver.NewMinter(f.cfg, foreignKeys)
	foreignMint.SetClock(f.clock)
	foreign, _, _ := foreignMint.Mint(ctx, f.grant())

	// alg=none and HS256 with the public key as secret.
	none := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"at+jwt"}`)) + "." + strings.Split(good, ".")[1] + "."
	hs, err := jwt.Signed(mustSigner(t, jose.HS256, bytes.Repeat([]byte("s"), 32))).Claims(map[string]any{"iss": "https://gw.example.com", "sub": alice, "aud": f.cfg.Resource(), "exp": t0.Add(time.Hour).Unix()}).Serialize()
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		token string
		want  tokens.Reason
		at    time.Time
	}{
		{"garbage", "not.a.jwt", tokens.ReasonMalformed, t0},
		{"two parts", "a.b", tokens.ReasonMalformed, t0},
		{"alg none", none, tokens.ReasonMalformed, t0},
		{"hs256", hs, tokens.ReasonMalformed, t0},
		{"wrong audience", forOther, tokens.ReasonUnknown, t0},
		{"wrong issuer", wrongIss, tokens.ReasonUnknown, t0},
		{"unknown kid", foreign, tokens.ReasonUnknown, t0},
		{"expired", good, tokens.ReasonExpired, t0.Add(time.Hour + time.Minute)},
		{"tampered", good[:len(good)-4] + "AAAA", tokens.ReasonUnknown, t0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f.now = c.at
			defer func() { f.now = t0 }()
			_, err := f.auth.Authenticate(ctx, c.token)
			if err == nil {
				t.Fatalf("accepted")
			}
			if got := reason(t, err); got != c.want {
				t.Errorf("reason = %q, want %q (%v)", got, c.want, err)
			}
		})
	}
}

// Regression (attack suite cjedpxp6, RFC 9068 section 4): a correctly
// signed token without exp is refused; go-jose only validates exp when
// it is present.
func TestTokenWithoutExpIsRejected(t *testing.T) {
	f := newJWT(t)
	ctx := context.Background()
	key, err := f.keys.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key.Private}, (&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", key.KID))
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{"iss": strings.TrimSuffix(f.cfg.Issuer, "/"), "sub": alice, "aud": f.cfg.Resource(), "iat": t0.Unix(), "nbf": t0.Unix(), "jti": "x", "client_id": "c", "scope": "mcp", "fid": "00000000-0000-4000-8000-0000000000f1"}
	noExp, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.auth.Authenticate(ctx, noExp); err == nil {
		t.Fatal("token without exp accepted")
	} else if got := reason(t, err); got != tokens.ReasonUnknown {
		t.Errorf("reason = %q, want unknown", got)
	}
	claims["exp"] = t0.Add(time.Hour).Unix()
	withExp, _ := jwt.Signed(signer).Claims(claims).Serialize()
	if _, err := f.auth.Authenticate(ctx, withExp); err != nil {
		t.Errorf("the same token with exp: %v", err)
	}
}

func TestDisabledUserIsRejected(t *testing.T) {
	f := newJWT(t)
	ctx := context.Background()
	raw, _, err := f.mint.Mint(ctx, f.grant())
	if err != nil {
		t.Fatal(err)
	}
	f.st.SetUser(alice, store.UserDisabled, nil)
	_, err = f.auth.Authenticate(ctx, raw)
	if got := reason(t, err); got != tokens.ReasonUserDisabled {
		t.Errorf("reason = %q, want user_disabled", got)
	}
	// A user the store no longer knows is "unknown", not a 503.
	g := f.grant()
	g.UserID = bob
	raw, _, _ = f.mint.Mint(ctx, g)
	_, err = f.auth.Authenticate(ctx, raw)
	if got := reason(t, err); got != tokens.ReasonUnknown {
		t.Errorf("reason = %q, want unknown", got)
	}
}

func TestStoreOutageIsNotATokenError(t *testing.T) {
	f := newJWT(t)
	ctx := context.Background()
	raw, _, err := f.mint.Mint(ctx, f.grant())
	if err != nil {
		t.Fatal(err)
	}
	f.st.FailWith = errors.New("connection refused")
	_, err = f.auth.Authenticate(ctx, raw)
	var te *tokens.Error
	if err == nil || errors.As(err, &te) {
		t.Errorf("outage error = %v, want a plain error", err)
	}
}

// Rotation: the new key signs, the previous one still verifies for the
// grace period and appears in the JWKS, then disappears.
func TestKeyRotationKeepsPreviousKeyForGrace(t *testing.T) {
	f := newJWT(t)
	ctx := context.Background()
	// Mint with a lifetime longer than the grace period so the rejection
	// below is the key's retirement, not the token's own expiry.
	long := f.cfg
	long.AccessTokenTTL = 2 * f.cfg.KeyGrace
	longMint := authserver.NewMinter(long, f.keys)
	longMint.SetClock(f.clock)
	old, _, err := longMint.Mint(ctx, f.grant())
	if err != nil {
		t.Fatal(err)
	}
	oldKID := kidOf(t, old)
	f.now = t0.Add(time.Minute)
	if err := f.keys.Rotate(ctx); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	fresh, _, err := f.mint.Mint(ctx, f.grant())
	if err != nil {
		t.Fatal(err)
	}
	if kidOf(t, fresh) == oldKID {
		t.Fatal("rotation did not change the signing key")
	}
	set, err := f.keys.JWKS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 2 {
		t.Errorf("JWKS has %d keys during grace, want 2", len(set.Keys))
	}
	for _, k := range set.Keys {
		if !k.IsPublic() {
			t.Fatalf("JWKS leaks a private key: %s", k.KeyID)
		}
	}
	if _, err := f.auth.Authenticate(ctx, old); err != nil {
		t.Errorf("old key rejected during grace: %v", err)
	}
	if _, err := f.auth.Authenticate(ctx, fresh); err != nil {
		t.Errorf("new key rejected: %v", err)
	}
	// Past the grace period the old key is gone: the still-unexpired token
	// is rejected and the JWKS no longer lists the key.
	f.now = t0.Add(time.Minute + f.cfg.KeyGrace + time.Second)
	if _, err := f.auth.Authenticate(ctx, old); err == nil {
		t.Error("old key still accepted after grace")
	}
	if err := f.keys.Rotate(ctx); err != nil { // the job also sweeps retired keys
		t.Fatal(err)
	}
	set, _ = f.keys.JWKS(ctx)
	for _, k := range set.Keys {
		if k.KeyID == oldKID {
			t.Errorf("retired key %s still published after grace", oldKID)
		}
	}
	var keys []string
	for _, k := range f.st.SigningKeys() {
		keys = append(keys, k.Status)
	}
	if len(f.st.SigningKeys()) != 2 {
		t.Errorf("stored keys = %v, want the retired key deleted (2 left)", keys)
	}
}

// Rotate is a no-op while the active key is younger than the rotation
// period, so the job can run every hour and still rotate monthly.
func TestRotateIfDueHonoursPeriod(t *testing.T) {
	f := newJWT(t)
	ctx := context.Background()
	if _, err := f.keys.Current(ctx); err != nil {
		t.Fatal(err)
	}
	rotated, err := f.keys.RotateIfDue(ctx, 24*time.Hour)
	if err != nil || rotated {
		t.Fatalf("RotateIfDue early = %v, %v; want false", rotated, err)
	}
	f.now = t0.Add(25 * time.Hour)
	rotated, err = f.keys.RotateIfDue(ctx, 24*time.Hour)
	if err != nil || !rotated {
		t.Fatalf("RotateIfDue due = %v, %v; want true", rotated, err)
	}
}

// A second replica sharing the store signs with the key the first one
// created and verifies tokens the first one minted.
func TestReplicasShareKeys(t *testing.T) {
	f := newJWT(t)
	ctx := context.Background()
	raw, _, err := f.mint.Mint(ctx, f.grant())
	if err != nil {
		t.Fatal(err)
	}
	other := authserver.NewKeys(f.st, mustProviderWith(t, 7), authserver.KeysOptions{Grace: f.cfg.KeyGrace})
	other.SetClock(f.clock)
	auth := authserver.NewJWTAuthenticator(f.cfg, f.st, other, authserver.AuthenticatorOptions{})
	auth.SetClock(f.clock)
	if _, err := auth.Authenticate(ctx, raw); err != nil {
		t.Fatalf("replica rejected token: %v", err)
	}
	m := authserver.NewMinter(f.cfg, other)
	m.SetClock(f.clock)
	raw2, _, err := m.Mint(ctx, f.grant())
	if err != nil {
		t.Fatal(err)
	}
	if kidOf(t, raw2) != kidOf(t, raw) {
		t.Errorf("replica created its own key instead of using the stored one")
	}
}

// The private key is stored envelope-encrypted under its kid; a row moved
// to another kid does not decrypt.
func TestPrivateKeyIsEncryptedAndBoundToKID(t *testing.T) {
	f := newJWT(t)
	ctx := context.Background()
	if _, err := f.keys.Current(ctx); err != nil {
		t.Fatal(err)
	}
	rows := f.st.SigningKeys()
	if len(rows) != 1 {
		t.Fatalf("%d keys", len(rows))
	}
	k := rows[0]
	if k.PrivateKey.KeyID != "k1" || len(k.PrivateKey.Ciphertext) == 0 || bytes.Contains(k.PrivateKey.Ciphertext, []byte("PRIVATE")) {
		t.Errorf("private key not envelope-encrypted: %+v", k.PrivateKey)
	}
	kp := mustProviderWith(t, 7)
	if _, err := crypto.Decrypt(ctx, kp, crypto.AAD{Kind: "signing_key", RecordID: k.KID}, crypto.Envelope(k.PrivateKey)); err != nil {
		t.Errorf("decrypt under the right AAD: %v", err)
	}
	if _, err := crypto.Decrypt(ctx, kp, crypto.AAD{Kind: "signing_key", RecordID: "other-kid"}, crypto.Envelope(k.PrivateKey)); err == nil {
		t.Error("decrypt under another kid succeeded")
	}
}

func TestCompositeRoutesByShape(t *testing.T) {
	f := newJWT(t)
	ctx := context.Background()
	raw, _, err := f.mint.Mint(ctx, f.grant())
	if err != nil {
		t.Fatal(err)
	}
	mgw := &recordingAuth{}
	comp := authserver.Composite(mgw, f.auth)
	if p, err := comp.Authenticate(ctx, raw); err != nil || p.UserID != alice {
		t.Errorf("JWT via composite: %v, %v", p, err)
	}
	if mgw.calls != 0 {
		t.Errorf("JWT reached the mgw authenticator")
	}
	for _, bearer := range []string{"mgw_abcdefgh_" + strings.Repeat("x", 43), "garbage", "a.b", ""} {
		_, _ = comp.Authenticate(ctx, bearer)
	}
	if mgw.calls != 4 || mgw.last != "" {
		t.Errorf("non-JWT bearers reached mgw %d times (last %q), want 4", mgw.calls, mgw.last)
	}
}

type recordingAuth struct {
	calls int
	last  string
}

func (r *recordingAuth) Authenticate(_ context.Context, bearer string) (*tokens.Principal, error) {
	r.calls++
	r.last = bearer
	return nil, &tokens.Error{Reason: tokens.ReasonUnknown}
}

func kidOf(t *testing.T, raw string) string {
	t.Helper()
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	return tok.Headers[0].KeyID
}

func mustSigner(t *testing.T, alg jose.SignatureAlgorithm, key any) jose.Signer {
	t.Helper()
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustProvider(t *testing.T) crypto.KeyProvider { return mustProviderWith(t, 9) }

func mustProviderWith(t *testing.T, b byte) crypto.KeyProvider {
	t.Helper()
	kp, err := crypto.NewStaticProvider("k1", map[string][]byte{"k1": bytes.Repeat([]byte{b}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	return kp
}
