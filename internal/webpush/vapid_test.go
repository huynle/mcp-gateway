package webpush

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestGenerateKeysPublicKey(t *testing.T) {
	k, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	pub := k.PublicKey()
	if strings.ContainsAny(pub, "=+/") {
		t.Fatalf("PublicKey %q is not unpadded base64url", pub)
	}
	raw := b64(t, pub)
	if len(raw) != 65 || raw[0] != 0x04 {
		t.Fatalf("PublicKey decodes to %d bytes starting %#x", len(raw), raw[0])
	}
	if _, err := ecdh.P256().NewPublicKey(raw); err != nil {
		t.Fatalf("PublicKey is not a P-256 point: %v", err)
	}
}

func TestKeysMarshalParseRoundTrip(t *testing.T) {
	k, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	der, err := k.MarshalPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	k2, err := ParsePrivateKey(der)
	if err != nil {
		t.Fatal(err)
	}
	if k2.PublicKey() != k.PublicKey() {
		t.Fatal("public key changed across marshal/parse")
	}
	der2, err := k2.MarshalPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(der, der2) {
		t.Fatal("DER changed across marshal/parse")
	}
}

func TestParsePrivateKeyRejectsGarbageAndNilKeys(t *testing.T) {
	if _, err := ParsePrivateKey([]byte("not der")); err == nil {
		t.Error("garbage accepted")
	}
	var k *Keys
	if _, err := k.MarshalPrivateKey(); err == nil {
		t.Error("nil Keys marshalled")
	}
}

func TestVAPIDAuthorization(t *testing.T) {
	k, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	h, err := k.authorization("https://fcm.googleapis.com:443/fcm/send/abc?x=1", "mailto:ops@example.com", now)
	if err != nil {
		t.Fatal(err)
	}
	rest, ok := strings.CutPrefix(h, "vapid t=")
	if !ok {
		t.Fatalf("header %q lacks vapid t=", h)
	}
	jwt, kpart, ok := strings.Cut(rest, ", k=")
	if !ok || kpart != k.PublicKey() {
		t.Fatalf("header %q: bad k= part", h)
	}
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT has %d parts", len(parts))
	}
	var hdr map[string]any
	if err := json.Unmarshal(b64(t, parts[0]), &hdr); err != nil {
		t.Fatal(err)
	}
	if hdr["typ"] != "JWT" || hdr["alg"] != "ES256" || len(hdr) != 2 {
		t.Fatalf("JWT header = %v", hdr)
	}
	var claims struct {
		Aud string `json:"aud"`
		Exp int64  `json:"exp"`
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(b64(t, parts[1]), &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Aud != "https://fcm.googleapis.com" {
		t.Errorf("aud = %q", claims.Aud)
	}
	if claims.Sub != "mailto:ops@example.com" {
		t.Errorf("sub = %q", claims.Sub)
	}
	if exp := time.Unix(claims.Exp, 0); exp.Sub(now) != 12*time.Hour {
		t.Errorf("exp - now = %v, want 12h", exp.Sub(now))
	}
	sig := b64(t, parts[2])
	if len(sig) != 64 {
		t.Fatalf("signature is %d bytes, want 64", len(sig))
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	pub := k.priv.Public().(*ecdsa.PublicKey)
	if !ecdsa.Verify(pub, digest[:], r, s) {
		t.Fatal("JWT signature does not verify with the public key")
	}
	if base64.RawURLEncoding.EncodeToString(sig) != parts[2] {
		t.Fatal("signature not canonical base64url")
	}
}
