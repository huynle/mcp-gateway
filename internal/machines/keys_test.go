package machines

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// RFC 8037 appendix A.3: the thumbprint of the example Ed25519 key.
const (
	rfcX          = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
	rfcThumbprint = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
)

func TestParsePublicKeyAndThumbprint(t *testing.T) {
	pub, err := ParsePublicKey(json.RawMessage(`{"kty":"OKP","crv":"Ed25519","x":"` + rfcX + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := Thumbprint(pub); got != rfcThumbprint {
		t.Fatalf("thumbprint = %s, want %s", got, rfcThumbprint)
	}
	if got := DisplayFingerprint(rfcThumbprint); got != "kPrK _qmx VWaY VA9w" {
		t.Fatalf("display = %q", got)
	}
}

func TestParsePublicKeyRefusesEverythingElse(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	d := base64.RawURLEncoding.EncodeToString(priv.Seed())
	for name, raw := range map[string]string{
		"not json":    `nope`,
		"rsa":         `{"kty":"RSA","n":"x","e":"AQAB"}`,
		"ec":          `{"kty":"EC","crv":"P-256","x":"` + rfcX + `","y":"` + rfcX + `"}`,
		"x25519":      `{"kty":"OKP","crv":"X25519","x":"` + rfcX + `"}`,
		"short x":     `{"kty":"OKP","crv":"Ed25519","x":"AAAA"}`,
		"padded x":    `{"kty":"OKP","crv":"Ed25519","x":"` + rfcX + `="}`,
		"private key": `{"kty":"OKP","crv":"Ed25519","x":"` + rfcX + `","d":"` + d + `"}`,
		"missing x":   `{"kty":"OKP","crv":"Ed25519"}`,
		"array":       `[]`,
	} {
		if _, err := ParsePublicKey(json.RawMessage(raw)); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("%s: err = %v, want ErrInvalidKey", name, err)
		}
	}
}

func TestUserCodes(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		c, err := NewUserCode()
		if err != nil {
			t.Fatal(err)
		}
		if len(c) != 9 || c[4] != '-' {
			t.Fatalf("user code %q", c)
		}
		for _, r := range strings.ReplaceAll(c, "-", "") {
			if !strings.ContainsRune(UserCodeAlphabet, r) {
				t.Fatalf("user code %q has %q outside the alphabet", c, r)
			}
		}
		seen[c] = true
		n, ok := NormalizeUserCode(" " + strings.ToLower(c) + " ")
		if !ok || n != strings.ReplaceAll(c, "-", "") {
			t.Fatalf("normalize(%q) = %q, %v", c, n, ok)
		}
		if FormatUserCode(n) != c {
			t.Fatalf("format(%q) = %q", n, FormatUserCode(n))
		}
	}
	if len(seen) < 190 {
		t.Fatalf("only %d distinct codes in 200", len(seen))
	}
	for _, bad := range []string{"", "BCDF-GHJ", "BCDF-GHJKL", "ABCD-EFGH", "BCDF-GHJ1", "BCDF GHJK X"} {
		if _, ok := NormalizeUserCode(bad); ok {
			t.Errorf("normalize(%q) accepted", bad)
		}
	}
	if strings.ContainsAny(UserCodeAlphabet, "AEIOUY01") {
		t.Fatalf("alphabet %q has ambiguous characters or vowels", UserCodeAlphabet)
	}
}

func TestSecrets(t *testing.T) {
	for _, prefix := range []string{AccessTokenPrefix, EnrollmentCodePrefix, DeviceCodePrefix} {
		s, err := NewSecret(prefix)
		if err != nil {
			t.Fatal(err)
		}
		if !ValidSecret(prefix, s) || len(s) != len(prefix)+8+1+43 {
			t.Fatalf("secret %q not valid for %q", s, prefix)
		}
		for _, other := range []string{AccessTokenPrefix, EnrollmentCodePrefix, DeviceCodePrefix} {
			if other != prefix && ValidSecret(other, s) {
				t.Fatalf("%q accepted as %q", s, other)
			}
		}
		if len(HashSecret(s)) != 32 {
			t.Fatal("hash is not SHA-256")
		}
		if ValidSecret(prefix, s+"x") || ValidSecret(prefix, s[:len(s)-1]+"!") || ValidSecret(prefix, "") {
			t.Fatal("malformed secret accepted")
		}
	}
}

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestJWKRoundTrip(t *testing.T) {
	pub, _ := newKey(t)
	got, err := ParsePublicKey(PublicJWK(pub))
	if err != nil || !got.Equal(pub) {
		t.Fatalf("round trip = %v, %v", got, err)
	}
}
