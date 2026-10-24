package ref

import (
	"crypto/sha256"
	_ "embed"
	"strings"
)

//go:embed wordlist.txt
var wordlist string

// words is the fingerprint wordlist: exactly 256 short, distinct, lowercase
// English words, so one byte of the digest picks one word.
var words = strings.Fields(wordlist)

// FingerprintWords is the number of words in a fingerprint.
const FingerprintWords = 4

// Fingerprint returns a short, deterministic, human-comparable name for a
// handle: four words joined by "-", taken from the first four bytes of
// SHA-256(handle). The entry page and the agent both show it so the user
// can tell that the link belongs to the request (32 bits; it is a visual
// check, not a secret and not an identifier).
func Fingerprint(handle string) string {
	sum := sha256.Sum256([]byte(handle))
	parts := make([]string, FingerprintWords)
	for i := range parts {
		parts[i] = words[int(sum[i])%len(words)]
	}
	return strings.Join(parts, "-")
}
