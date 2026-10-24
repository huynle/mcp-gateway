package webpush

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// vapidTTL is the JWT lifetime; RFC 8292 Section 2 caps it at 24 hours.
const vapidTTL = 12 * time.Hour

// Keys is the application server's VAPID key pair (ECDSA P-256).
type Keys struct {
	priv *ecdsa.PrivateKey
}

// GenerateKeys creates a new VAPID key pair.
func GenerateKeys() (*Keys, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("webpush: generate vapid key: %w", err)
	}
	return &Keys{priv: priv}, nil
}

// ParsePrivateKey parses a PKCS#8 DER-encoded P-256 ECDSA private key, as
// produced by MarshalPrivateKey.
func ParsePrivateKey(der []byte) (*Keys, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("webpush: parse vapid key: %w", err)
	}
	priv, ok := key.(*ecdsa.PrivateKey)
	if !ok || priv.Curve != elliptic.P256() {
		return nil, errors.New("webpush: vapid key is not an ECDSA P-256 key")
	}
	return &Keys{priv: priv}, nil
}

// MarshalPrivateKey encodes the private key as PKCS#8 DER. The result is a
// secret: store it encrypted.
func (k *Keys) MarshalPrivateKey() ([]byte, error) {
	if k == nil || k.priv == nil {
		return nil, errors.New("webpush: nil vapid key")
	}
	der, err := x509.MarshalPKCS8PrivateKey(k.priv)
	if err != nil {
		return nil, fmt.Errorf("webpush: marshal vapid key: %w", err)
	}
	return der, nil
}

// PublicKey returns the uncompressed public key point, base64url-encoded
// without padding: the applicationServerKey the browser passes to
// PushManager.subscribe, and the k= parameter of the VAPID header.
func (k *Keys) PublicKey() string {
	pub, err := k.priv.PublicKey.ECDH()
	if err != nil {
		return "" // unreachable for a P-256 key
	}
	return base64.RawURLEncoding.EncodeToString(pub.Bytes())
}

// authorization builds the RFC 8292 Authorization header value for a
// request to endpoint.
func (k *Keys) authorization(endpoint, subject string, now time.Time) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", errors.New("webpush: invalid endpoint for vapid audience")
	}
	aud := strings.ToLower(u.Scheme + "://" + u.Hostname())
	if p := u.Port(); p != "" && (u.Scheme != "https" || p != "443") {
		aud += ":" + p
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT","alg":"ES256"}`))
	claims, err := json.Marshal(struct {
		Aud string `json:"aud"`
		Exp int64  `json:"exp"`
		Sub string `json:"sub"`
	}{Aud: aud, Exp: now.Add(vapidTTL).Unix(), Sub: subject})
	if err != nil {
		return "", fmt.Errorf("webpush: vapid claims: %w", err)
	}
	signingInput := header + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, k.priv, digest[:])
	if err != nil {
		return "", fmt.Errorf("webpush: sign vapid jwt: %w", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	jwt := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
	return "vapid t=" + jwt + ", k=" + k.PublicKey(), nil
}
