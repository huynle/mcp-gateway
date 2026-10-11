package snapshot

import (
	"bytes"
	"encoding/json"
)

// CanonicalJSON re-encodes raw JSON with object keys sorted and no
// insignificant whitespace, keeping numbers exactly as written. PostgreSQL
// jsonb reorders keys, so stored schemas must be compared canonically.
func CanonicalJSON(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	// encoding/json sorts map keys.
	return json.Marshal(v)
}

// EqualJSON reports whether a and b are the same JSON value, ignoring key
// order and whitespace. Empty input and JSON null are equal to each other;
// unparsable input is equal only to identical bytes.
func EqualJSON(a, b []byte) bool {
	a, b = normNull(a), normNull(b)
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	ca, errA := CanonicalJSON(a)
	cb, errB := CanonicalJSON(b)
	if errA != nil || errB != nil {
		return bytes.Equal(a, b)
	}
	return bytes.Equal(ca, cb)
}

func normNull(b []byte) []byte {
	t := bytes.TrimSpace(b)
	if len(t) == 0 || bytes.Equal(t, []byte("null")) {
		return nil
	}
	return t
}
