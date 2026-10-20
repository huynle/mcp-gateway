package machines

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	testMachine  = "0b9c4f3e-1111-4222-8333-444455556666"
	testAudience = "https://gw.example/machine/token"
)

// signAssertion signs claims with priv the way the CLI does.
func signAssertion(t *testing.T, priv ed25519.PrivateKey, claims map[string]any, headers map[jose.HeaderKey]any) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithType("JWT")
	for k, v := range headers {
		opts = opts.WithHeader(k, v)
	}
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: priv}, opts)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jwt.Signed(sig).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func goodClaims(now time.Time) map[string]any {
	return map[string]any{
		"iss": testMachine, "sub": testMachine, "aud": testAudience,
		"iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(), "jti": "4f1c2b7a9e8d6c5b4a39281706f5e4d3",
	}
}

func keyFor(pub ed25519.PublicKey) func(string) (ed25519.PublicKey, error) {
	return func(id string) (ed25519.PublicKey, error) {
		if id != testMachine {
			return nil, errors.New("unknown machine")
		}
		return pub, nil
	}
}

func TestVerifyAssertionAcceptsAWellFormedAssertion(t *testing.T) {
	pub, priv := newKey(t)
	now := time.Unix(1_800_000_000, 0)
	raw := signAssertion(t, priv, goodClaims(now), nil)
	a, err := VerifyAssertion(raw, keyFor(pub), testAudience, now)
	if err != nil {
		t.Fatal(err)
	}
	if a.MachineID != testMachine || a.JTI != "4f1c2b7a9e8d6c5b4a39281706f5e4d3" || !a.ExpiresAt.Equal(now.Add(2*time.Minute)) {
		t.Fatalf("assertion = %+v", a)
	}
	// An audience array containing the token endpoint is fine too.
	c := goodClaims(now)
	c["aud"] = []string{testAudience}
	if _, err := VerifyAssertion(signAssertion(t, priv, c, nil), keyFor(pub), testAudience, now); err != nil {
		t.Fatalf("audience array: %v", err)
	}
	// Clock skew up to 60 s either way.
	if _, err := VerifyAssertion(raw, keyFor(pub), testAudience, now.Add(-59*time.Second)); err != nil {
		t.Fatalf("issued 59 s in the future: %v", err)
	}
	if _, err := VerifyAssertion(raw, keyFor(pub), testAudience, now.Add(2*time.Minute+59*time.Second)); err != nil {
		t.Fatalf("expired 59 s ago: %v", err)
	}
}

func TestVerifyAssertionRefusesForgeries(t *testing.T) {
	pub, priv := newKey(t)
	_, otherPriv := newKey(t)
	now := time.Unix(1_800_000_000, 0)
	mod := func(f func(map[string]any)) string {
		c := goodClaims(now)
		f(c)
		return signAssertion(t, priv, c, nil)
	}
	good := signAssertion(t, priv, goodClaims(now), nil)
	parts := strings.Split(good, ".")
	header := func(h string) string { return base64.RawURLEncoding.EncodeToString([]byte(h)) }
	hs := hmac.New(sha256.New, pub) // the public key as an HMAC secret (alg confusion)
	hs.Write([]byte(header(`{"alg":"HS256","typ":"JWT"}`) + "." + parts[1]))
	hsToken := header(`{"alg":"HS256","typ":"JWT"}`) + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(hs.Sum(nil))

	cases := map[string]string{
		"other key":         signAssertion(t, otherPriv, goodClaims(now), nil),
		"alg none":          header(`{"alg":"none","typ":"JWT"}`) + "." + parts[1] + ".",
		"alg HS256":         hsToken,
		"tampered payload":  parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"`+testMachine+`"}`)) + "." + parts[2],
		"wrong typ":         signAssertion(t, priv, goodClaims(now), map[jose.HeaderKey]any{"typ": "at+jwt"}),
		"wrong aud":         mod(func(c map[string]any) { c["aud"] = "https://gw.example/mcp" }),
		"aud of another gw": mod(func(c map[string]any) { c["aud"] = "https://evil.example/machine/token" }),
		"no aud":            mod(func(c map[string]any) { delete(c, "aud") }),
		"sub differs":       mod(func(c map[string]any) { c["sub"] = "0b9c4f3e-1111-4222-8333-444455556667" }),
		"iss not a uuid":    mod(func(c map[string]any) { c["iss"], c["sub"] = "laptop", "laptop" }),
		"expired": mod(func(c map[string]any) {
			c["iat"], c["exp"] = now.Add(-5*time.Minute).Unix(), now.Add(-61*time.Second).Unix()
		}),
		"issued in future": mod(func(c map[string]any) {
			c["iat"], c["exp"] = now.Add(2*time.Minute).Unix(), now.Add(3*time.Minute).Unix()
		}),
		"too long":       mod(func(c map[string]any) { c["exp"] = now.Add(301 * time.Second).Unix() }),
		"exp before iat": mod(func(c map[string]any) { c["exp"] = now.Add(-time.Second).Unix() }),
		"no exp":         mod(func(c map[string]any) { delete(c, "exp") }),
		"no iat":         mod(func(c map[string]any) { delete(c, "iat") }),
		"no jti":         mod(func(c map[string]any) { delete(c, "jti") }),
		"short jti":      mod(func(c map[string]any) { c["jti"] = "x" }),
		"nbf in future":  mod(func(c map[string]any) { c["nbf"] = now.Add(2 * time.Minute).Unix() }),
		"empty":          "",
		"garbage":        "a.b.c",
		"unknown machine id": mod(func(c map[string]any) {
			c["iss"], c["sub"] = "0b9c4f3e-1111-4222-8333-444455556667", "0b9c4f3e-1111-4222-8333-444455556667"
		}),
		"oversized": strings.Repeat("a", 9000),
	}
	for name, raw := range cases {
		if _, err := VerifyAssertion(raw, keyFor(pub), testAudience, now); !errors.Is(err, ErrInvalidAssertion) {
			t.Errorf("%s: err = %v, want ErrInvalidAssertion", name, err)
		}
	}
}

func TestVerifyAssertionErrorNeverEchoesTheAssertion(t *testing.T) {
	pub, priv := newKey(t)
	now := time.Unix(1_800_000_000, 0)
	c := goodClaims(now)
	c["aud"] = "https://elsewhere.example/x"
	raw := signAssertion(t, priv, c, nil)
	_, err := VerifyAssertion(raw, keyFor(pub), testAudience, now)
	if err == nil || strings.Contains(err.Error(), raw) || strings.Contains(err.Error(), "elsewhere") {
		t.Fatalf("error %q leaks the assertion", err)
	}
	b, _ := json.Marshal(err.Error())
	if len(b) > 200 {
		t.Fatalf("error too long: %s", b)
	}
}
