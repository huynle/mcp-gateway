package crypto

import (
	"encoding/binary"
	"errors"
)

// AAD is the associated data authenticated alongside every envelope. It binds
// a ciphertext to the row it belongs to so an attacker with database access
// cannot move a secret between users, record kinds, records or apps. UserID
// and App may be empty for system records (vendor app secrets, signing keys);
// Kind and RecordID are always required.
type AAD struct {
	UserID   string
	Kind     string
	RecordID string
	App      string
}

// aadVersion prefixes the canonical form so the encoding can change later
// without old ciphertexts verifying under a new layout.
const aadVersion = "mcp-gateway/aad/v1"

// Validate reports whether the AAD identifies a record.
func (a AAD) Validate() error {
	if a.Kind == "" {
		return errors.New("crypto: AAD kind must not be empty")
	}
	if a.RecordID == "" {
		return errors.New("crypto: AAD record ID must not be empty")
	}
	return nil
}

// Bytes returns the canonical serialization: a version tag followed by each
// field as a big-endian uint32 length and its bytes. Length prefixes make
// field boundaries unambiguous regardless of field contents.
func (a AAD) Bytes() []byte {
	fields := []string{aadVersion, a.UserID, a.Kind, a.RecordID, a.App}
	n := 0
	for _, f := range fields {
		n += 4 + len(f)
	}
	out := make([]byte, 0, n)
	for _, f := range fields {
		out = binary.BigEndian.AppendUint32(out, uint32(len(f)))
		out = append(out, f...)
	}
	return out
}
