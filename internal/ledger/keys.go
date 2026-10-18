package ledger

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"unicode"
)

// Idempotency key scopes (decision dovthftx): an approval executes at
// most once, so its key is the approval id; an unconfirmed write is keyed
// by user, account, tool and the canonical argument digest, and the key
// only refers to the same operation inside Config.IdempotencyWindow. A
// per-call write (Intent.PerCall: tools of user-added MCP servers) gets a
// random key of its own, so it never matches another operation.
const (
	approvalKeyPrefix = "approval:"
	digestKeyPrefix   = "digest:"
	callKeyPrefix     = "call:"
)

// CallKey returns a fresh, unique idempotency key for a per-call write:
// "call:" and 128 random bits, hex encoded.
func CallKey() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return callKeyPrefix + hex.EncodeToString(b[:]), nil
}

// ApprovalKey is the idempotency key of a write that consumed approval id.
func ApprovalKey(approvalID string) string { return approvalKeyPrefix + approvalID }

// DigestKey is the idempotency key of an unconfirmed write: a SHA-256 over
// user, account, tool and the argument digest, hex encoded.
func DigestKey(userID, accountID, tool string, digest []byte) string {
	h := sha256.New()
	for _, part := range []string{userID, accountID, tool} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	h.Write(digest)
	return digestKeyPrefix + hex.EncodeToString(h.Sum(nil))
}

// Digest is the SHA-256 of the canonical JSON encoding of args (keys
// sorted at every level, no insignificant whitespace), the per-argument
// part of DigestKey. nil and empty arguments digest alike.
func Digest(args map[string]any) []byte {
	if args == nil {
		args = map[string]any{}
	}
	// encoding/json sorts map keys and emits no whitespace; nested maps
	// decoded from JSON are map[string]any and sort the same way.
	b, err := json.Marshal(args)
	if err != nil {
		b = []byte("unencodable")
	}
	sum := sha256.Sum256(b)
	return sum[:]
}

// Caps on stored result IDs: identifiers and URLs only, never content
// (decision dovthftx; plan 36bakiw8 security notes).
const (
	MaxResultIDs        = 16
	MaxResultIDKeyLen   = 64
	MaxResultIDValueLen = 512
)

// SanitizeResultIDs returns the entries of ids that look like identifiers:
// non-empty keys up to MaxResultIDKeyLen, non-empty single-line values up
// to MaxResultIDValueLen, at most MaxResultIDs of them (the lexically
// smallest keys win, so the result is deterministic). nil in, nil out.
func SanitizeResultIDs(ids map[string]string) map[string]string {
	if ids == nil {
		return nil
	}
	keys := make([]string, 0, len(ids))
	for k, v := range ids {
		if k == "" || len(k) > MaxResultIDKeyLen || v == "" || len(v) > MaxResultIDValueLen || !singleLine(v) {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > MaxResultIDs {
		keys = keys[:MaxResultIDs]
	}
	out := make(map[string]string, len(keys))
	for _, k := range keys {
		out[k] = strings.TrimSpace(ids[k])
	}
	return out
}

func singleLine(s string) bool {
	for _, r := range s {
		if r == '\n' || r == '\r' || (unicode.IsControl(r) && r != '\t') {
			return false
		}
	}
	return true
}
