package google

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Shared schema and argument helpers for the three apps.

// property is one input-schema property: name, type, description and
// optional enum values.
type property struct {
	Name, Type, Description string
	Enum                    []string
}

// objectSchema builds a closed object schema with the given properties
// and required names. Array properties are arrays of strings.
func objectSchema(props []property, required []string) json.RawMessage {
	type schemaProp struct {
		Type        string         `json:"type"`
		Description string         `json:"description"`
		Enum        []string       `json:"enum,omitempty"`
		Items       map[string]any `json:"items,omitempty"`
		Minimum     *int           `json:"minimum,omitempty"`
		Maximum     *int           `json:"maximum,omitempty"`
	}
	properties := map[string]schemaProp{}
	for _, p := range props {
		sp := schemaProp{Type: p.Type, Description: p.Description, Enum: p.Enum}
		if p.Type == "array" {
			sp.Items = map[string]any{"type": "string"}
		}
		if p.Name == "max_results" {
			one, max := 1, maxPerPage
			sp.Minimum, sp.Maximum = &one, &max
		}
		properties[p.Name] = sp
	}
	schema := map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
	if len(required) > 0 {
		schema["required"] = required
	}
	b, err := json.Marshal(schema)
	if err != nil {
		panic(err)
	}
	return b
}

// idRE is the shape of a Google resource id the connector puts in a URL
// path (event ids, task ids, tasklist ids, message ids, label ids,
// calendar ids): no slashes, no whitespace, no control characters.
var idRE = regexp.MustCompile(`^[^\s/\x00-\x1f]+$`)

// requiredString reads a non-blank string argument.
func requiredString(args map[string]any, name string) (string, error) {
	v, _ := args[name].(string)
	v = strings.TrimSpace(v)
	if v == "" {
		return "", invalid("%s is required", name)
	}
	return v, nil
}

// optionalString reads a string argument, "" when absent.
func optionalString(args map[string]any, name string) (string, error) {
	v, ok := args[name]
	if !ok || v == nil {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", invalid("%s must be a string", name)
	}
	return s, nil
}

// idArg reads a required resource id argument (idRE).
func idArg(args map[string]any, name string) (string, error) {
	v, err := requiredString(args, name)
	if err != nil {
		return "", err
	}
	if !idRE.MatchString(v) {
		return "", invalid("%s must be a Google resource id (no slashes or spaces)", name)
	}
	return v, nil
}

// idArgDefault reads an optional resource id argument with a default.
func idArgDefault(args map[string]any, name, def string) (string, error) {
	v, err := optionalString(args, name)
	if err != nil {
		return "", err
	}
	if v = strings.TrimSpace(v); v == "" {
		return def, nil
	}
	if !idRE.MatchString(v) {
		return "", invalid("%s must be a Google resource id (no slashes or spaces)", name)
	}
	return v, nil
}

// optionalBool reads a boolean argument, def when absent.
func optionalBool(args map[string]any, name string, def bool) (bool, error) {
	v, ok := args[name]
	if !ok || v == nil {
		return def, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, invalid("%s must be a boolean", name)
	}
	return b, nil
}

// stringList reads an optional array-of-strings argument (a single
// string is accepted as a one-element list; a comma-separated string is
// split); blank entries are dropped and nil is returned when nothing
// remains.
func stringList(args map[string]any, name string) ([]string, error) {
	v, ok := args[name]
	if !ok || v == nil {
		return nil, nil
	}
	var out []string
	switch list := v.(type) {
	case []string:
		out = append(out, list...)
	case []any:
		for _, item := range list {
			s, ok := item.(string)
			if !ok {
				return nil, invalid("%s must be an array of strings", name)
			}
			out = append(out, s)
		}
	case string:
		out = strings.Split(list, ",")
	default:
		return nil, invalid("%s must be an array of strings", name)
	}
	kept := out[:0]
	for _, s := range out {
		if s = strings.TrimSpace(s); s != "" {
			kept = append(kept, s)
		}
	}
	if len(kept) == 0 {
		return nil, nil
	}
	return kept, nil
}

// optionalTime reads an RFC 3339 timestamp argument; zero when absent.
func optionalTime(args map[string]any, name string) (time.Time, error) {
	v, err := optionalString(args, name)
	if err != nil {
		return time.Time{}, err
	}
	if v = strings.TrimSpace(v); v == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, invalid("%s must be an RFC 3339 timestamp such as 2026-10-09T09:00:00Z", name)
	}
	return t, nil
}

// pageArgs reads max_results (default def, clamped to the bounds;
// clamped reports when it was) and page_token.
func (c *Connector) pageArgs(args map[string]any, def int) (maxResults int, pageToken string, clamped bool, err error) {
	maxResults = min(def, c.bounds.MaxPageSize)
	if v, ok := args["max_results"]; ok && v != nil {
		if maxResults, err = toInt(v); err != nil || maxResults < 1 {
			return 0, "", false, invalid("max_results must be a positive integer")
		}
		if maxResults > c.bounds.MaxPageSize {
			maxResults, clamped = c.bounds.MaxPageSize, true
		}
	}
	if pageToken, err = optionalString(args, "page_token"); err != nil {
		return 0, "", false, err
	}
	return maxResults, strings.TrimSpace(pageToken), clamped, nil
}

func toInt(v any) (int, error) {
	switch n := v.(type) {
	case int:
		return n, nil
	case int64:
		return int(n), nil
	case float64:
		if n != math.Trunc(n) || math.IsInf(n, 0) || math.IsNaN(n) {
			return 0, errors.New("not an integer")
		}
		return int(n), nil
	case json.Number:
		i, err := n.Int64()
		return int(i), err
	case string:
		return strconv.Atoi(strings.TrimSpace(n))
	}
	return 0, fmt.Errorf("not an integer: %T", v)
}

// encodedSize is the serialised size of v, the measure the bounds apply to.
func encodedSize(v any) int {
	b, err := json.Marshal(v)
	if err != nil {
		return 0
	}
	return len(b)
}

// fitBody cuts *body (and sets *truncated) until the object returned by
// obj, which must read both through the same pointers, serialises to at
// most max bytes or the body is gone. Everything but the body stays.
func fitBody(body *string, truncated *bool, max int, obj func() any) {
	if encodedSize(obj()) <= max {
		return
	}
	*truncated = true
	for *body != "" {
		size := encodedSize(obj())
		if size <= max {
			return
		}
		cut := len(*body) - (size - max) - 1
		if cut < 0 {
			cut = 0
		}
		// Keep the cut on a rune boundary.
		for cut > 0 && cut < len(*body) && !isRuneStart((*body)[cut]) {
			cut--
		}
		*body = (*body)[:cut]
	}
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }

// domainOf returns the lower-cased domain of an email address, "" when
// the value is not one.
func domainOf(address string) string {
	_, domain, ok := strings.Cut(strings.ToLower(strings.TrimSpace(address)), "@")
	if !ok || domain == "" || strings.ContainsAny(domain, "@ <>") {
		return ""
	}
	return domain
}

// singleBounds and pagedBounds are the per-tool bounds.
func (c *Connector) singleBounds() connectors.Bounds {
	return connectors.Bounds{MaxResultBytes: c.bounds.MaxResultBytes}
}

func (c *Connector) pagedBounds() connectors.Bounds {
	return connectors.Bounds{MaxPageSize: c.bounds.MaxPageSize, MaxResultBytes: c.bounds.MaxResultBytes}
}
