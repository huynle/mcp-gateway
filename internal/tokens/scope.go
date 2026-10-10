package tokens

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Scope narrows what a token may do below what the user's role allows
// (decision uamxx6ba): an optional allow-list of apps ("github") and
// tools ("github.create_issue"), and a read-only flag. An empty allow-list
// means every tool the user may use. Policy, not this package, decides what
// "read-only" and the user's role permit; Scope only reports the token's
// own restrictions for the pipeline to combine.
type Scope struct {
	Apps     []string
	Tools    []string
	ReadOnly bool
}

// ErrInvalidScope reports an allow-list entry that is not an app or
// app.tool name.
var ErrInvalidScope = errors.New("tokens: invalid app or tool name")

// Allow-list entries are lower-case identifiers: an app, or app.tool.
var entryRE = regexp.MustCompile(`^[a-z0-9_-]+(\.[a-z0-9_-]+)?$`)

// ParseAllowList parses the portal's free-text allow-list: entries
// separated by commas, whitespace or newlines, case-insensitive; "github"
// allows every github tool, "github.create_issue" exactly that tool.
// Entries are de-duplicated and sorted. Empty input is the unrestricted
// scope. ReadOnly is left false; the caller sets it from its own field.
func ParseAllowList(input string) (Scope, error) {
	var s Scope
	fields := strings.FieldsFunc(input, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' })
	for _, f := range fields {
		e := strings.ToLower(f)
		if !entryRE.MatchString(e) {
			return Scope{}, fmt.Errorf("%w: %q", ErrInvalidScope, f)
		}
		if strings.Contains(e, ".") {
			s.Tools = append(s.Tools, e)
		} else {
			s.Apps = append(s.Apps, e)
		}
	}
	slices.Sort(s.Apps)
	slices.Sort(s.Tools)
	s.Apps = slices.Compact(s.Apps)
	s.Tools = slices.Compact(s.Tools)
	return s, nil
}

// IsRestricted reports whether the allow-list narrows the token to some
// apps or tools.
func (s Scope) IsRestricted() bool { return len(s.Apps) > 0 || len(s.Tools) > 0 }

// Allows reports whether tool ("app.tool") passes the allow-list. It says
// nothing about ReadOnly or the user's role.
func (s Scope) Allows(tool string) bool {
	if !s.IsRestricted() {
		return true
	}
	app, _, ok := strings.Cut(tool, ".")
	if !ok {
		return false
	}
	return slices.Contains(s.Apps, app) || slices.Contains(s.Tools, tool)
}

// String renders the scope for the portal: "all tools", "github,
// slack.post_message, read-only".
func (s Scope) String() string {
	var parts []string
	if s.IsRestricted() {
		parts = append(parts, s.Apps...)
		parts = append(parts, s.Tools...)
	} else {
		parts = append(parts, "all tools")
	}
	if s.ReadOnly {
		parts = append(parts, "read-only")
	}
	return strings.Join(parts, ", ")
}

// storedScope is the tokens.scope JSON document.
type storedScope struct {
	Apps  []string `json:"apps,omitempty"`
	Tools []string `json:"tools,omitempty"`
}

// MarshalStore renders the allow-list for the tokens.scope column: nil
// (SQL NULL) when unrestricted. ReadOnly lives in its own column.
func (s Scope) MarshalStore() (json.RawMessage, error) {
	if !s.IsRestricted() {
		return nil, nil
	}
	return json.Marshal(storedScope{Apps: s.Apps, Tools: s.Tools})
}

// ScopeFromStore rebuilds a Scope from the tokens.scope document (nil for
// unrestricted) and the read_only column.
func ScopeFromStore(raw json.RawMessage, readOnly bool) (Scope, error) {
	s := Scope{ReadOnly: readOnly}
	if len(raw) == 0 || string(raw) == "null" {
		return s, nil
	}
	var doc storedScope
	if err := json.Unmarshal(raw, &doc); err != nil {
		return Scope{}, fmt.Errorf("tokens: decode scope: %w", err)
	}
	s.Apps, s.Tools = doc.Apps, doc.Tools
	return s, nil
}
