package webpush

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
)

const testEndpoint = "https://fcm.googleapis.com/fcm/send/secret-token-123"

func subJSON(endpoint, p256dh, auth string) []byte {
	return fmt.Appendf(nil, `{"endpoint":%q,"expirationTime":null,"keys":{"p256dh":%q,"auth":%q}}`, endpoint, p256dh, auth)
}

func TestParseSubscriptionValid(t *testing.T) {
	ua, auth := newUAKeys(t)
	pub := ua.PublicKey().Bytes()
	for name, enc := range map[string]*base64.Encoding{
		"raw url":    base64.RawURLEncoding,
		"padded url": base64.URLEncoding,
	} {
		t.Run(name, func(t *testing.T) {
			sub, err := ParseSubscription(subJSON(testEndpoint, enc.EncodeToString(pub), enc.EncodeToString(auth)))
			if err != nil {
				t.Fatal(err)
			}
			if sub.Endpoint != testEndpoint || !bytes.Equal(sub.P256dh, pub) || !bytes.Equal(sub.Auth, auth) {
				t.Fatalf("sub = %+v", sub)
			}
		})
	}
	// expirationTime may also be a number.
	js := fmt.Appendf(nil, `{"endpoint":%q,"expirationTime":1700000000000,"keys":{"p256dh":%q,"auth":%q}}`,
		testEndpoint, base64.RawURLEncoding.EncodeToString(pub), base64.RawURLEncoding.EncodeToString(auth))
	if _, err := ParseSubscription(js); err != nil {
		t.Fatalf("numeric expirationTime: %v", err)
	}
}

func TestParseSubscriptionInvalid(t *testing.T) {
	ua, auth := newUAKeys(t)
	pub := base64.RawURLEncoding.EncodeToString(ua.PublicKey().Bytes())
	a := base64.RawURLEncoding.EncodeToString(auth)
	notOnCurve := make([]byte, 65)
	notOnCurve[0] = 4
	notOnCurve[64] = 1
	big := subJSON(testEndpoint, pub, a)
	big = append(big[:len(big)-1], []byte(`,"pad":"`+strings.Repeat("x", 5000)+`"}`)...)
	tests := map[string][]byte{
		"not json":          []byte("nope"),
		"empty":             nil,
		"array":             []byte(`[]`),
		"missing endpoint":  subJSON("", pub, a),
		"http endpoint":     subJSON("http://fcm.googleapis.com/fcm/send/x", pub, a),
		"evil endpoint":     subJSON("https://evil.example/x", pub, a),
		"missing p256dh":    subJSON(testEndpoint, "", a),
		"missing auth":      subJSON(testEndpoint, pub, ""),
		"bad base64 p256dh": subJSON(testEndpoint, "!!!!", a),
		"std base64 chars":  subJSON(testEndpoint, strings.Repeat("+/", 44), a),
		"compressed point":  subJSON(testEndpoint, base64.RawURLEncoding.EncodeToString(append([]byte{2}, ua.PublicKey().Bytes()[1:33]...)), a),
		"not on curve":      subJSON(testEndpoint, base64.RawURLEncoding.EncodeToString(notOnCurve), a),
		"auth 15 bytes":     subJSON(testEndpoint, pub, base64.RawURLEncoding.EncodeToString(auth[:15])),
		"auth 17 bytes":     subJSON(testEndpoint, pub, base64.RawURLEncoding.EncodeToString(append(auth, 0))),
		"too large":         big,
		"trailing data":     append(subJSON(testEndpoint, pub, a), []byte(`{}`)...),
	}
	for name, js := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseSubscription(js); err == nil {
				t.Fatalf("ParseSubscription accepted %s", name)
			}
		})
	}
}

func TestParseSubscriptionEndpointErrorIsWrapped(t *testing.T) {
	ua, auth := newUAKeys(t)
	_, err := ParseSubscription(subJSON("https://evil.example/secret-path",
		base64.RawURLEncoding.EncodeToString(ua.PublicKey().Bytes()), base64.RawURLEncoding.EncodeToString(auth)))
	if !errors.Is(err, ErrEndpointNotAllowed) {
		t.Fatalf("err = %v, want ErrEndpointNotAllowed", err)
	}
	if strings.Contains(err.Error(), "secret-path") {
		t.Fatalf("error leaks the endpoint path: %v", err)
	}
}
