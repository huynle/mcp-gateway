package tokens

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
)

// User codes of the device authorization flows (RFC 8628 §6.1): machine
// enrollment (internal/machines) and harness sign-in (internal/authserver)
// share the format and the /activate page.

// UserCodeAlphabet is the user code alphabet: consonants only (no vowels,
// so no words; no look-alike digits, no O or I).
const UserCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"

// UserCodeLen is the number of letters in a user code (20^8 ≈ 2^34.6).
const UserCodeLen = 8

// NewUserCode returns a random user code formatted "ABCD-EFGH".
func NewUserCode() (string, error) {
	b := make([]byte, UserCodeLen)
	n := big.NewInt(int64(len(UserCodeAlphabet)))
	for i := range b {
		v, err := rand.Int(rand.Reader, n)
		if err != nil {
			return "", fmt.Errorf("tokens: user code: %w", err)
		}
		b[i] = UserCodeAlphabet[v.Int64()]
	}
	return FormatUserCode(string(b)), nil
}

// NormalizeUserCode accepts a user code as typed (any case, spaces and
// dashes) and returns its eight letters, or false when it cannot be one.
func NormalizeUserCode(s string) (string, bool) {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		switch {
		case r == '-' || r == ' ' || r == '\t':
			continue
		case strings.ContainsRune(UserCodeAlphabet, r):
			b.WriteRune(r)
		default:
			return "", false
		}
		if b.Len() > UserCodeLen {
			return "", false
		}
	}
	if b.Len() != UserCodeLen {
		return "", false
	}
	return b.String(), true
}

// FormatUserCode formats eight normalized letters as "ABCD-EFGH".
func FormatUserCode(n string) string {
	if len(n) != UserCodeLen {
		return n
	}
	return n[:4] + "-" + n[4:]
}
