package machines

import (
	"crypto/ed25519"
	"errors"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Machine assertions (RFC 7523 JWT bearer grant). A machine proves it
// holds its private key by signing a short-lived JWT:
//
//	header  {"alg":"EdDSA","typ":"JWT"}
//	claims  iss = sub = machine id, aud = <base>/machine/token,
//	        iat, exp (exp - iat <= 5 min), jti (unique; replay-checked)
//
// Only EdDSA is accepted (no alg confusion), the key is the one stored at
// enrollment (never one carried by the token), and ±60 s of clock skew is
// tolerated.
const (
	// MaxAssertionLifetime bounds exp - iat.
	MaxAssertionLifetime = 5 * time.Minute
	// ClockSkew is the tolerated clock difference.
	ClockSkew = 60 * time.Second
	// maxAssertionBytes bounds the compact serialization.
	maxAssertionBytes = 4 << 10
	minJTI, maxJTI    = 16, 128
)

// ErrInvalidAssertion matches every assertion failure (errors.Is). Its
// message names the check that failed, never the assertion or a claim
// value.
var ErrInvalidAssertion = errors.New("machines: invalid assertion")

type assertionError struct{ reason string }

func (e *assertionError) Error() string        { return "machines: invalid assertion (" + e.reason + ")" }
func (e *assertionError) Is(target error) bool { return target == ErrInvalidAssertion }

func invalid(reason string) error { return &assertionError{reason: reason} }

// AssertionReason is the short reason of an assertion failure ("" when err
// is not one), for logs.
func AssertionReason(err error) string {
	var ae *assertionError
	if errors.As(err, &ae) {
		return ae.reason
	}
	return ""
}

// Assertion is a verified machine assertion.
type Assertion struct {
	MachineID string
	JTI       string
	ExpiresAt time.Time
}

// VerifyAssertion checks a machine assertion for the token endpoint
// audience at now. key returns the enrolled public key of a machine id (an
// error for an unknown or unusable machine). Replay (jti) is the caller's
// check.
func VerifyAssertion(raw string, key func(machineID string) (ed25519.PublicKey, error), audience string, now time.Time) (*Assertion, error) {
	if raw == "" || len(raw) > maxAssertionBytes {
		return nil, invalid("malformed")
	}
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil || len(tok.Headers) != 1 {
		return nil, invalid("malformed")
	}
	h := tok.Headers[0]
	if h.Algorithm != string(jose.EdDSA) || h.JSONWebKey != nil {
		return nil, invalid("header")
	}
	if typ, _ := h.ExtraHeaders[jose.HeaderType].(string); typ != "JWT" {
		return nil, invalid("header")
	}
	// The issuer picks the key; nothing else is trusted before the
	// signature checks out.
	var unverified jwt.Claims
	if err := tok.UnsafeClaimsWithoutVerification(&unverified); err != nil || !uuidRE.MatchString(unverified.Issuer) {
		return nil, invalid("issuer")
	}
	pub, err := key(unverified.Issuer)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, invalid("unknown_machine")
	}
	var c struct {
		jwt.Claims
	}
	if err := tok.Claims(pub, &c); err != nil {
		return nil, invalid("signature")
	}
	switch {
	case c.Issuer != unverified.Issuer || c.Subject != c.Issuer:
		return nil, invalid("subject")
	case !slices.Contains([]string(c.Audience), audience):
		return nil, invalid("audience")
	case c.IssuedAt == nil || c.Expiry == nil:
		return nil, invalid("times")
	case len(c.ID) < minJTI || len(c.ID) > maxJTI || !printable(c.ID):
		return nil, invalid("jti")
	}
	iat, exp := c.IssuedAt.Time(), c.Expiry.Time()
	switch {
	case !exp.After(iat) || exp.Sub(iat) > MaxAssertionLifetime:
		return nil, invalid("lifetime")
	case iat.After(now.Add(ClockSkew)):
		return nil, invalid("issued_in_future")
	case now.After(exp.Add(ClockSkew)):
		return nil, invalid("expired")
	case c.NotBefore != nil && c.NotBefore.Time().After(now.Add(ClockSkew)):
		return nil, invalid("not_yet_valid")
	}
	return &Assertion{MachineID: c.Issuer, JTI: c.ID, ExpiresAt: exp}, nil
}

func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
