package snapshot

import (
	"encoding/json"
	"fmt"

	"github.com/google/jsonschema-go/jsonschema"
)

// emptyArgsSchema stands in for a missing input schema: only an empty
// argument object is accepted.
const emptyArgsSchema = `{"type":"object","additionalProperties":false}`

// Check decides whether a call of tool name with args may go upstream,
// given a server's approved snapshot s and its review r (nil s = no
// approved snapshot). It returns the pinned tool and its effective kind
// (an empty review kind counts as write), or:
//   - ErrToolNotReviewed when s is nil or has no such tool;
//   - ErrToolDisabled when the review does not enable it;
//   - ErrArgsInvalid when args do not validate against the pinned input
//     schema, or the schema is unusable (unparsable, or referring to a
//     remote schema, which is never fetched).
//
// Error messages never contain argument values or upstream text.
func Check(s *Snapshot, r Review, name string, args map[string]any) (Tool, Kind, error) {
	t, ok := s.Tool(name)
	if !ok {
		return Tool{}, "", ErrToolNotReviewed
	}
	tr, ok := r[name]
	if !ok || !tr.Enabled {
		return Tool{}, "", ErrToolDisabled
	}
	kind := tr.Kind
	if !kind.Valid() {
		kind = KindWrite
	}
	if err := validateArgs(t.InputSchema, args); err != nil {
		return Tool{}, "", err
	}
	return t, kind, nil
}

func validateArgs(raw json.RawMessage, args map[string]any) error {
	if normNull(raw) == nil {
		raw = json.RawMessage(emptyArgsSchema)
	}
	var schema jsonschema.Schema
	if err := json.Unmarshal(raw, &schema); err != nil {
		return fmt.Errorf("%w (pinned schema unusable)", ErrArgsInvalid)
	}
	// No Loader: a remote $ref fails to resolve instead of being fetched.
	resolved, err := schema.Resolve(nil)
	if err != nil {
		return fmt.Errorf("%w (pinned schema unusable)", ErrArgsInvalid)
	}
	instance, err := normalizeArgs(args)
	if err != nil {
		return ErrArgsInvalid
	}
	// The validator's message may quote argument values: drop it.
	if err := resolved.Validate(instance); err != nil {
		return ErrArgsInvalid
	}
	return nil
}

// normalizeArgs round-trips args through JSON so the validator sees exactly
// what goes on the wire (float64 numbers, map[string]any objects); nil
// becomes an empty object.
func normalizeArgs(args map[string]any) (map[string]any, error) {
	if args == nil {
		return map[string]any{}, nil
	}
	b, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = map[string]any{}
	}
	return out, nil
}
