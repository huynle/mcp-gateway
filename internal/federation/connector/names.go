package connector

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/store"
)

// Errors from server name validation; safe to show.
var (
	// ErrInvalidServerName: not 1-63 characters of [a-z0-9_-] (the
	// schema's CHECK and the registry's app rule).
	ErrInvalidServerName = errors.New("federation: server name must be 1-63 characters of a-z, 0-9, _ and -")
	// ErrReservedServerName: the name of a built-in app (ReservedNames).
	ErrReservedServerName = errors.New("federation: server name is reserved for a built-in app")
)

// serverNameRE is mcp_servers.name's CHECK.
var serverNameRE = regexp.MustCompile(`^[a-z0-9_-]{1,63}$`)

// reserved are the built-in connector apps (registered by cmd/gateway)
// and the vendor products users know them by, plus "mcp" (the vendor of
// the federation's anchor connections). A server named like one of them
// would put its tools next to, or be mistaken for, a built-in app's.
var reserved = []string{
	"atlassian", "calendar", "confluence", "contacts", "docs", "drive", "fake", "github", "gmail",
	"google", "jira", "mcp", "microsoft", "sheets", "slack", "tasks",
}

// ReservedNames returns the server names nobody may use, sorted.
func ReservedNames() []string { return slices.Clone(reserved) }

// ValidateServerName checks a server name before it is stored (create or
// rename): ErrInvalidServerName or ErrReservedServerName. The servers
// portal must call it (Manager.CreateServer / UpdateServer do); the
// database only enforces the shape, and the registry refuses a name a
// built-in connector already registered.
func ValidateServerName(name string) error {
	if !serverNameRE.MatchString(name) {
		return ErrInvalidServerName
	}
	if slices.Contains(reserved, name) {
		return ErrReservedServerName
	}
	return nil
}

// maxToolNameLen bounds a sanitized tool name.
const maxToolNameLen = 64

// ToolName maps an upstream tool name onto the registry's tool rule
// ([a-z0-9_-]): camelCase boundaries become "_", upper case is lowered,
// every other character becomes "_", runs of "_" collapse, leading and
// trailing "_" go, and the result is capped at 64 characters. It reports
// false when nothing usable is left.
func ToolName(upstream string) (string, bool) {
	var b strings.Builder
	prevLower := false
	for _, r := range upstream {
		switch {
		case r >= 'A' && r <= 'Z':
			if prevLower {
				b.WriteByte('_')
			}
			b.WriteRune(r + ('a' - 'A'))
			prevLower = false
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
			b.WriteRune(r)
			prevLower = true
		case r == '-' || r == '_':
			b.WriteRune(r)
			prevLower = false
		default:
			b.WriteByte('_')
			prevLower = false
		}
	}
	name := b.String()
	for strings.Contains(name, "__") {
		name = strings.ReplaceAll(name, "__", "_")
	}
	name = strings.Trim(name, "_")
	if len(name) > maxToolNameLen {
		name = strings.TrimRight(name[:maxToolNameLen], "_")
	}
	return name, name != ""
}

// emptySchema is the input schema of a tool that declared none: the
// snapshot check then accepts only {}.
const emptySchema = `{"type":"object","properties":{},"additionalProperties":false}`

// maxResultBytes is what a federated result may weigh (the federation
// client's default per-message bound).
const maxResultBytes = 4 << 20

// buildTools turns the enabled tools of an approved snapshot into registry
// tools named "<server>.<sanitized tool>", with the pinned schema and
// description (prefixed with the server name as provenance and stripped of
// control and format characters), the reviewed kind (writes reconcile
// none: an upstream MCP call cannot be checked afterwards), and resource
// identity {server: <name>}. handler binds each tool to its upstream name
// and kind. Tools that are disabled or unreviewed are left out silently;
// tools whose name sanitizes to nothing or to the same name as another
// enabled tool, or whose schema is not a JSON object schema, are left out
// and returned in skipped (upstream names, sorted).
func buildTools(server *store.MCPServer, rec *snapshot.Record, handler func(upstream string, kind connectors.Kind) connectors.Handler) (tools []connectors.Tool, skipped []string) {
	if rec == nil || rec.Snapshot == nil {
		return nil, nil
	}
	type candidate struct {
		up     snapshot.Tool
		kind   connectors.Kind
		schema json.RawMessage
	}
	byName := map[string][]candidate{}
	for _, up := range rec.Snapshot.Tools {
		rv, ok := rec.Review[up.Name]
		if !ok || !rv.Enabled {
			continue
		}
		name, ok := ToolName(up.Name)
		schema, schemaOK := objectSchema(up.InputSchema)
		if !ok || !schemaOK {
			skipped = append(skipped, up.Name)
			continue
		}
		kind := connectors.KindWrite
		if rv.Kind == snapshot.KindRead {
			kind = connectors.KindRead
		}
		byName[name] = append(byName[name], candidate{up: up, kind: kind, schema: schema})
	}
	var kept []candidate
	keptNames := map[string]string{}
	for name, cs := range byName {
		if len(cs) > 1 {
			for _, c := range cs {
				skipped = append(skipped, c.up.Name)
			}
			continue
		}
		kept = append(kept, cs[0])
		keptNames[cs[0].up.Name] = name
	}
	slices.SortFunc(kept, func(a, b candidate) int { return strings.Compare(a.up.Name, b.up.Name) })
	slices.Sort(skipped)
	serverName := server.Name
	for _, c := range kept {
		t := connectors.Tool{
			App:         server.Name,
			Name:        keptNames[c.up.Name],
			Description: describe(server.Name, c.up),
			InputSchema: c.schema,
			Kind:        c.kind,
			ResourceIdentity: func(map[string]any) map[string]string {
				return map[string]string{"server": serverName}
			},
			Bounds:  connectors.Bounds{MaxResultBytes: maxResultBytes},
			Handler: handler(c.up.Name, c.kind),
		}
		if c.kind == connectors.KindWrite {
			t.Reconcile = connectors.Reconciliation{Kind: connectors.ReconcileNone}
		}
		tools = append(tools, t)
	}
	return tools, skipped
}

// objectSchema returns the pinned input schema when it is a JSON object
// schema (type "object"), the empty schema when there is none, and false
// otherwise.
func objectSchema(raw json.RawMessage) (json.RawMessage, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return json.RawMessage(emptySchema), true
	}
	var s struct {
		Type any `json:"type"`
	}
	if err := json.Unmarshal(raw, &s); err != nil || s.Type != "object" {
		return nil, false
	}
	return raw, true
}

// describe renders a federated tool's description: "[<server>] " plus the
// sanitized description (or title, or name). Upstream text is data: the
// display helpers drop control and bidi/zero-width characters and cap it.
func describe(server string, up snapshot.Tool) string {
	text := up.Description
	if strings.TrimSpace(text) == "" {
		text = up.Title
	}
	if strings.TrimSpace(text) == "" {
		text = up.Name
	}
	return fmt.Sprintf("[%s] %s", server, snapshot.DisplayDescription(text))
}
