package webpush

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// MaxSubscriptionJSON bounds the input to ParseSubscription.
const MaxSubscriptionJSON = 4 << 10

// Subscription is a browser push subscription: where to send and the keys
// to encrypt for. Endpoint is a bearer capability; treat it as a secret.
type Subscription struct {
	Endpoint string
	P256dh   []byte // uncompressed P-256 public key, 65 bytes
	Auth     []byte // authentication secret, 16 bytes
}

// ParseSubscription parses and validates the JSON of a browser's
// PushSubscription.toJSON():
//
//	{"endpoint": "...", "expirationTime": null,
//	 "keys": {"p256dh": "<base64url>", "auth": "<base64url>"}}
//
// The endpoint must pass ValidateEndpoint, p256dh must be a valid
// uncompressed P-256 point and auth exactly 16 bytes. Keys may be
// base64url with or without padding. Input over MaxSubscriptionJSON bytes
// is refused.
func ParseSubscription(js []byte) (Subscription, error) {
	if len(js) > MaxSubscriptionJSON {
		return Subscription{}, fmt.Errorf("webpush: subscription larger than %d bytes", MaxSubscriptionJSON)
	}
	var in struct {
		Endpoint       string           `json:"endpoint"`
		ExpirationTime *json.RawMessage `json:"expirationTime"`
		Keys           struct {
			P256dh string `json:"p256dh"`
			Auth   string `json:"auth"`
		} `json:"keys"`
	}
	dec := json.NewDecoder(bytes.NewReader(js))
	if err := dec.Decode(&in); err != nil {
		return Subscription{}, errors.New("webpush: subscription is not a valid JSON object")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Subscription{}, errors.New("webpush: trailing data after subscription JSON")
	}
	if err := ValidateEndpoint(in.Endpoint); err != nil {
		return Subscription{}, err
	}
	p256dh, err := decodeKey(in.Keys.P256dh)
	if err != nil {
		return Subscription{}, fmt.Errorf("webpush: subscription p256dh: %w", err)
	}
	if _, err := ecdh.P256().NewPublicKey(p256dh); err != nil {
		return Subscription{}, errors.New("webpush: subscription p256dh is not an uncompressed P-256 point")
	}
	auth, err := decodeKey(in.Keys.Auth)
	if err != nil {
		return Subscription{}, fmt.Errorf("webpush: subscription auth: %w", err)
	}
	if len(auth) != authSize {
		return Subscription{}, fmt.Errorf("webpush: subscription auth is %d bytes, want %d", len(auth), authSize)
	}
	return Subscription{Endpoint: in.Endpoint, P256dh: p256dh, Auth: auth}, nil
}

// decodeKey decodes base64url with or without padding.
func decodeKey(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("missing")
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return nil, errors.New("not base64url")
	}
	return b, nil
}
