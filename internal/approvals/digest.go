package approvals

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
)

// Canonical renders tool arguments as canonical JSON: object keys sorted,
// no insignificant whitespace, HTML left unescaped, a nil map as "{}". Two
// argument maps with the same values have the same canonical form whatever
// order or spacing the harness used (decision s0p05diu). Unicode is not
// normalised: "é" and "e\u0301" are different arguments.
func Canonical(args map[string]any) ([]byte, error) {
	if args == nil {
		args = map[string]any{}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(args); err != nil {
		return nil, fmt.Errorf("approvals: canonical arguments: %w", err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// Digest is the SHA-256 of Canonical(args). Arguments that cannot be
// rendered (a channel, a function) digest as the empty object; they could
// not have arrived over JSON-RPC in the first place.
func Digest(args map[string]any) []byte {
	c, err := Canonical(args)
	if err != nil {
		c = []byte("{}")
	}
	sum := sha256.Sum256(c)
	return sum[:]
}
