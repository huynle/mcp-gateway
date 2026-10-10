package oauthattack

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/huynle/mcp-gateway/internal/authserver"
)

// Access-token forgery and misuse against /mcp (OAuth 2.1 section 5.2,
// RFC 9068, RFC 8725 JWT BCP): every token below is rejected with 401
// invalid_token, the resource metadata challenge, no internals in the
// body, and a logged reason naming the check that failed.

// TestForgedAccessTokens covers the claim-level attacks with correctly
// signed tokens (the AS's own keys) and the signature-level attacks
// (alg=none, HS256 key confusion, unknown kid, wrong key, tampered body).
func TestForgedAccessTokens(t *testing.T) {
	g := newGateway(t, withEnv(map[string]string{authserver.EnvAccessTokenTTL: "5h", authserver.EnvKeyGrace: "2h"}))
	now := g.clock.Now()
	good := g.mintWith(t, g.cfg, now, g.grant())
	g.wantMCPOK(t, good)
	kid := headerOf(t, good)["kid"].(string)

	t.Run("wrong_iss", func(t *testing.T) {
		cfg := g.cfg
		cfg.Issuer = "https://other-gateway.example.com"
		tok := g.mintWith(t, cfg, now, g.grant())
		wantMCPUnauthorized(t, g, g.mcpCall(t, tok))
		wantAuthFailed(t, g, "wrong_issuer")
	})
	t.Run("iss_trailing_slash", func(t *testing.T) {
		tok := resign(t, g, good, func(c map[string]any) { c["iss"] = g.base + "/" })
		wantMCPUnauthorized(t, g, g.mcpCall(t, tok))
		wantAuthFailed(t, g, "wrong_issuer")
	})
	t.Run("wrong_aud", func(t *testing.T) {
		grant := g.grant()
		grant.Resource = g.base + "/other"
		tok := g.mintWith(t, g.cfg, now, grant)
		wantMCPUnauthorized(t, g, g.mcpCall(t, tok))
		wantAuthFailed(t, g, "wrong_audience")
	})
	t.Run("aud_missing", func(t *testing.T) {
		tok := resign(t, g, good, func(c map[string]any) { delete(c, "aud") })
		wantMCPUnauthorized(t, g, g.mcpCall(t, tok))
		wantAuthFailed(t, g, "wrong_audience")
	})
	t.Run("aud_list_with_ours_and_decoy", func(t *testing.T) {
		// A multi-audience token that includes us is acceptable per RFC
		// 7519; document that it is accepted (AnyAudience) and that one
		// without us is not.
		tok := resign(t, g, good, func(c map[string]any) { c["aud"] = []string{g.resource, g.base + "/other"} })
		g.wantMCPOK(t, tok)
		tok = resign(t, g, good, func(c map[string]any) { c["aud"] = []string{g.base + "/other", g.base + "/another"} })
		wantMCPUnauthorized(t, g, g.mcpCall(t, tok))
		wantAuthFailed(t, g, "wrong_audience")
	})
	t.Run("expired_exp", func(t *testing.T) {
		tok := g.mintWith(t, g.cfg, now.Add(-g.cfg.AccessTokenTTL-authserverLeeway), g.grant())
		wantMCPUnauthorized(t, g, g.mcpCall(t, tok))
		wantAuthFailed(t, g, "expired")
	})
	t.Run("exp_within_leeway_still_valid", func(t *testing.T) {
		tok := g.mintWith(t, g.cfg, now.Add(-g.cfg.AccessTokenTTL+time.Second), g.grant())
		g.wantMCPOK(t, tok)
	})
	t.Run("future_nbf", func(t *testing.T) {
		tok := g.mintWith(t, g.cfg, now.Add(time.Hour), g.grant())
		wantMCPUnauthorized(t, g, g.mcpCall(t, tok))
		wantAuthFailed(t, g, "invalid_claims")
	})
	t.Run("exp_missing", func(t *testing.T) {
		tok := resign(t, g, good, func(c map[string]any) { delete(c, "exp") })
		wantMCPUnauthorized(t, g, g.mcpCall(t, tok))
		wantAuthFailed(t, g, "invalid_claims")
	})
	t.Run("sub_missing", func(t *testing.T) {
		tok := resign(t, g, good, func(c map[string]any) { delete(c, "sub") })
		wantMCPUnauthorized(t, g, g.mcpCall(t, tok))
		wantAuthFailed(t, g, "missing_claims")
	})
	t.Run("fid_missing", func(t *testing.T) {
		tok := resign(t, g, good, func(c map[string]any) { delete(c, "fid") })
		wantMCPUnauthorized(t, g, g.mcpCall(t, tok))
		wantAuthFailed(t, g, "missing_claims")
	})
	t.Run("unknown_user", func(t *testing.T) {
		tok := resign(t, g, good, func(c map[string]any) { c["sub"] = "00000000-0000-4000-8000-00000000dead" })
		wantMCPUnauthorized(t, g, g.mcpCall(t, tok))
		wantAuthFailed(t, g, "unknown_user")
	})
	t.Run("unknown_scope", func(t *testing.T) {
		tok := resign(t, g, good, func(c map[string]any) { c["scope"] = "admin" })
		wantMCPUnauthorized(t, g, g.mcpCall(t, tok))
		wantAuthFailed(t, g, "bad_scope")
	})
	t.Run("alg_none", func(t *testing.T) {
		for _, alg := range []string{"none", "None", "NONE"} {
			hdr := b64(t, map[string]any{"alg": alg, "typ": "at+jwt", "kid": kid})
			body := strings.Split(good, ".")[1]
			for _, sig := range []string{"", "AAAA"} {
				r := g.mcpCall(t, hdr+"."+body+"."+sig)
				if r.status != http.StatusUnauthorized {
					t.Fatalf("alg=%s sig=%q: %d %s", alg, sig, r.status, r.body)
				}
				if code, _ := r.oauthError(); code != "invalid_token" {
					t.Fatalf("alg=%s: error %q", alg, code)
				}
			}
		}
	})
	t.Run("hs256_key_confusion", func(t *testing.T) {
		// Sign with HMAC using the public key (DER, PEM and JWK forms) as
		// the secret: a verifier that trusts the alg header would accept it.
		jwks := get(t, noRedirect, g.base+"/oauth/jwks")
		var set jose.JSONWebKeySet
		if err := json.Unmarshal(jwks.body, &set); err != nil || len(set.Keys) == 0 {
			t.Fatalf("jwks: %v %s", err, jwks.body)
		}
		pub := set.Keys[0].Key.(*ecdsa.PublicKey)
		der, _ := x509.MarshalPKIXPublicKey(pub)
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
		jwkBytes, _ := set.Keys[0].MarshalJSON()
		body := strings.Split(good, ".")[1]
		for name, secret := range map[string][]byte{"der": der, "pem": pemBytes, "jwk": jwkBytes} {
			hdr := b64(t, map[string]any{"alg": "HS256", "typ": "at+jwt", "kid": kid})
			mac := hmac.New(sha256.New, secret)
			mac.Write([]byte(hdr + "." + body))
			tok := hdr + "." + body + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
			wantMCPUnauthorized(t, g, g.mcpCall(t, tok))
			wantAuthFailed(t, g, "parse")
			_ = name
		}
	})
	t.Run("unknown_kid", func(t *testing.T) {
		priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tok := signWith(t, priv, "attacker-kid", claimsOf(t, good))
		wantMCPUnauthorized(t, g, g.mcpCall(t, tok))
		wantAuthFailed(t, g, "unknown_kid")
	})
	t.Run("right_kid_wrong_key", func(t *testing.T) {
		priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tok := signWith(t, priv, kid, claimsOf(t, good))
		wantMCPUnauthorized(t, g, g.mcpCall(t, tok))
		wantAuthFailed(t, g, "bad_signature")
	})
	t.Run("no_kid", func(t *testing.T) {
		parts := strings.Split(good, ".")
		hdr := b64(t, map[string]any{"alg": "ES256", "typ": "at+jwt"})
		wantMCPUnauthorized(t, g, g.mcpCall(t, hdr+"."+parts[1]+"."+parts[2]))
		wantAuthFailed(t, g, "no_kid")
	})
	t.Run("tampered_body", func(t *testing.T) {
		parts := strings.Split(good, ".")
		claims := decodeSegment(t, parts[1])
		claims["scope"] = "mcp"
		claims["sub"] = "00000000-0000-4000-8000-00000000dead"
		wantMCPUnauthorized(t, g, g.mcpCall(t, parts[0]+"."+b64(t, claims)+"."+parts[2]))
		wantAuthFailed(t, g, "bad_signature")
	})
	t.Run("jwk_in_header_ignored", func(t *testing.T) {
		// An embedded jwk / jku header must not be used as the verification key.
		priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pubJWK := jose.JSONWebKey{Key: &priv.PublicKey, KeyID: "embedded", Algorithm: "ES256"}
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: priv}, (&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", "embedded").WithHeader("jwk", pubJWK).WithHeader("jku", "https://attacker.example/jwks"))
		if err != nil {
			t.Fatal(err)
		}
		tok, err := jwt.Signed(signer).Claims(claimsOf(t, good)).Serialize()
		if err != nil {
			t.Fatal(err)
		}
		wantMCPUnauthorized(t, g, g.mcpCall(t, tok))
		wantAuthFailed(t, g, "unknown_kid")
	})
	t.Run("garbage_bearers", func(t *testing.T) {
		for _, b := range []string{"a.b", "a.b.c.d", "..", "eyJ.eyJ.", "mgw_x_y", strings.Repeat("A", 10000), "Bearer " + good, good + ".x", strings.ToUpper(good)} {
			r := g.mcpCall(t, b)
			if r.status != http.StatusUnauthorized {
				t.Errorf("bearer %.20q: %d", b, r.status)
			}
			noStackTrace(t, r.body)
		}
	})
	t.Run("rotated_key_after_grace", func(t *testing.T) {
		// The token outlives the key: valid during the grace period after a
		// rotation, refused once the retired key is past it (and gone from
		// the JWKS), although exp is still in the future.
		tok := g.mintWith(t, g.cfg, g.clock.Now(), g.grant())
		if err := g.authSvc.Keys().Rotate(t.Context()); err != nil {
			t.Fatal(err)
		}
		g.clock.Advance(g.cfg.KeyGrace - time.Minute)
		g.wantMCPOK(t, tok)
		g.clock.Advance(2 * time.Minute)
		wantMCPUnauthorized(t, g, g.mcpCall(t, tok))
		wantAuthFailed(t, g, "unknown_kid")
		var set jose.JSONWebKeySet
		_ = json.Unmarshal(get(t, noRedirect, g.base+"/oauth/jwks").body, &set)
		for _, k := range set.Keys {
			if k.KeyID == headerOf(t, tok)["kid"] {
				t.Error("retired key past its grace period still in the JWKS")
			}
		}
		// After the sweep the row is gone as well.
		if _, err := g.authSvc.Keys().RotateIfDue(t.Context(), 365*24*time.Hour); err != nil {
			t.Fatal(err)
		}
		wantMCPUnauthorized(t, g, g.mcpCall(t, tok))
		// A token minted with the new key works.
		g.wantMCPOK(t, g.mintWith(t, g.cfg, g.clock.Now(), g.grant()))
	})
	t.Run("jwks_has_no_private_material", func(t *testing.T) {
		var set map[string]any
		_ = json.Unmarshal(get(t, noRedirect, g.base+"/oauth/jwks").body, &set)
		for _, k := range set["keys"].([]any) {
			km := k.(map[string]any)
			if km["d"] != nil || km["kty"] != "EC" || km["use"] != "sig" || km["alg"] != "ES256" {
				t.Errorf("jwk = %v", km)
			}
		}
	})
}

// TestDisabledUserTokenRejected: a valid token of a user disabled after it
// was issued is refused at once (the owner check runs per request).
func TestDisabledUserTokenRejected(t *testing.T) {
	g := newGateway(t)
	br := g.browser(t, true)
	c := g.register(t, "https://app.example.com/cb")
	pair := g.issue(t, br, c)
	g.wantMCPOK(t, pair.access)
	g.astore.SetUser(g.alice, "disabled", nil)
	r := g.mcpCall(t, pair.access)
	wantMCPUnauthorized(t, g, r)
	wantAuthFailed(t, g, "user_disabled")
	if !strings.Contains(r.header.Get("WWW-Authenticate"), "disabled") {
		t.Errorf("WWW-Authenticate = %q", r.header.Get("WWW-Authenticate"))
	}
}

// --- JWT helpers -------------------------------------------------------------

func b64(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func headerOf(t *testing.T, raw string) map[string]any {
	t.Helper()
	return decodeSegment(t, strings.Split(raw, ".")[0])
}

func claimsOf(t *testing.T, raw string) map[string]any {
	t.Helper()
	return decodeSegment(t, strings.Split(raw, ".")[1])
}

// signWith signs claims as ES256 with the given key and kid.
func signWith(t *testing.T, priv *ecdsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: priv}, (&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", kid))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// resign re-signs a token's claims (mutated by edit) with the gateway's
// real active key: a correctly signed token with attacker-chosen claims,
// the strongest claim-level test.
func resign(t *testing.T, g *gateway, good string, edit func(map[string]any)) string {
	t.Helper()
	claims := claimsOf(t, good)
	edit(claims)
	key, err := g.authSvc.Keys().Current(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return signWith(t, key.Private, key.KID, claims)
}
