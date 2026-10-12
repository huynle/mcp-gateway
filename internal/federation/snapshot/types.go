package snapshot

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Kind is how the gateway treats a tool: reads run directly, writes go
// through the write path (confirmation / approval).
type Kind string

// Tool kinds.
const (
	KindRead  Kind = "read"
	KindWrite Kind = "write"
)

// Valid reports whether k is a known kind.
func (k Kind) Valid() bool { return k == KindRead || k == KindWrite }

// Annotations are a tool's upstream hints, kept as discovered. They are
// claims of the upstream server, not facts.
type Annotations struct {
	Title           string `json:"title,omitempty"`
	ReadOnlyHint    bool   `json:"readOnlyHint,omitempty"`
	DestructiveHint *bool  `json:"destructiveHint,omitempty"`
	IdempotentHint  bool   `json:"idempotentHint,omitempty"`
	OpenWorldHint   *bool  `json:"openWorldHint,omitempty"`
}

// Tool is one discovered tool. Schemas are kept as raw JSON as discovered;
// compare them with EqualJSON, never byte for byte.
type Tool struct {
	Name         string          `json:"name"`
	Title        string          `json:"title,omitempty"`
	Description  string          `json:"description,omitempty"`
	InputSchema  json.RawMessage `json:"inputSchema,omitempty"`
	OutputSchema json.RawMessage `json:"outputSchema,omitempty"`
	Annotations  *Annotations    `json:"annotations,omitempty"`
}

// HintKind is the kind the upstream's annotations claim: read only when
// readOnlyHint is true; missing annotations or a false hint mean write.
func (t Tool) HintKind() Kind {
	if t.Annotations != nil && t.Annotations.ReadOnlyHint {
		return KindRead
	}
	return KindWrite
}

// Resource is one discovered resource.
type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	MIMEType    string `json:"mimeType,omitempty"`
}

// ResourceTemplate is one discovered resource template.
type ResourceTemplate struct {
	URITemplate string `json:"uriTemplate"`
	Name        string `json:"name"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	MIMEType    string `json:"mimeType,omitempty"`
}

// PromptArgument is one argument of a discovered prompt.
type PromptArgument struct {
	Name        string `json:"name"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

// Prompt is one discovered prompt.
type Prompt struct {
	Name        string           `json:"name"`
	Title       string           `json:"title,omitempty"`
	Description string           `json:"description,omitempty"`
	Arguments   []PromptArgument `json:"arguments,omitempty"`
}

// Snapshot is a server's discovered capability set, each list sorted by its
// key (tool / prompt name, resource URI, template URI template).
type Snapshot struct {
	Tools             []Tool
	Resources         []Resource
	ResourceTemplates []ResourceTemplate
	Prompts           []Prompt
}

// Tool returns the snapshot's tool called name.
func (s *Snapshot) Tool(name string) (Tool, bool) {
	if s == nil {
		return Tool{}, false
	}
	for _, t := range s.Tools {
		if t.Name == name {
			return t, true
		}
	}
	return Tool{}, false
}

// Session is the part of a federation client session (*client.Session)
// that discovery needs.
type Session interface {
	Capabilities() *mcp.ServerCapabilities
	ListTools(ctx context.Context) ([]*mcp.Tool, error)
	ListResources(ctx context.Context) ([]*mcp.Resource, error)
	ListResourceTemplates(ctx context.Context) ([]*mcp.ResourceTemplate, error)
	ListPrompts(ctx context.Context) ([]*mcp.Prompt, error)
}

// KindOverride is a reviewer's override of a tool's kind.
type KindOverride struct {
	Kind Kind      `json:"kind"`
	By   string    `json:"by,omitempty"`
	At   time.Time `json:"at"`
}

// ToolReview is the review state of one tool of an approved snapshot. Kind
// is the effective kind (the override if any, else from readOnlyHint).
// ReviewedBy / ReviewedAt record who last set Enabled.
type ToolReview struct {
	Enabled    bool          `json:"enabled"`
	Kind       Kind          `json:"kind"`
	Override   *KindOverride `json:"kindOverride,omitempty"`
	ReviewedBy string        `json:"reviewedBy,omitempty"`
	ReviewedAt *time.Time    `json:"reviewedAt,omitempty"`
}

// Review is the per-tool review of a snapshot, keyed by tool name (the
// review column of mcp_server_snapshots).
type Review map[string]ToolReview

// Decision is a reviewer's decision about one tool. Nil fields leave the
// state as BuildReview derived it. Kind set to "" clears an override.
type Decision struct {
	Enabled *bool `json:"enabled,omitempty"`
	Kind    *Kind `json:"kind,omitempty"`
}

// ReviewDecisions is what a reviewer submits when approving a snapshot.
// EnableReads enables every read tool (effective kind) that no reviewer has
// decided on yet and that has no Enabled decision here; a tool a reviewer
// explicitly disabled stays disabled, and writes are only ever enabled one
// by one.
//
// Resources, ResourceTemplates and Prompts enable (true) or disable
// (false) one item each, keyed by resource URI, URI template and prompt
// name; an item without a decision keeps what BuildContentReview derived.
type ReviewDecisions struct {
	Tools             map[string]Decision `json:"tools,omitempty"`
	EnableReads       bool                `json:"enableReads,omitempty"`
	Resources         map[string]bool     `json:"resources,omitempty"`
	ResourceTemplates map[string]bool     `json:"resourceTemplates,omitempty"`
	Prompts           map[string]bool     `json:"prompts,omitempty"`
}

// Errors. Their messages never contain argument values or upstream text.
var (
	// ErrToolNotReviewed: the tool is not in the server's approved snapshot
	// (or the server has none).
	ErrToolNotReviewed = errors.New("snapshot: tool not in the reviewed snapshot")
	// ErrToolDisabled: the tool is in the approved snapshot but not enabled.
	ErrToolDisabled = errors.New("snapshot: tool not enabled by review")
	// ErrArgsInvalid: the arguments do not validate against the pinned
	// input schema (or the pinned schema is unusable).
	ErrArgsInvalid = errors.New("snapshot: arguments do not match the reviewed input schema")
	// ErrInvalidSnapshot: the upstream listed an unusable capability set
	// (empty or duplicate names).
	ErrInvalidSnapshot = errors.New("snapshot: invalid capability list")
	// ErrUnknownTool: a review decision names a tool not in the snapshot.
	ErrUnknownTool = errors.New("snapshot: decision for a tool not in the snapshot")
	// ErrInvalidKind: a review decision has a kind other than read / write.
	ErrInvalidKind = errors.New("snapshot: invalid tool kind")
	// ErrNoSnapshot: the server has no snapshot to diff or approve.
	ErrNoSnapshot = errors.New("snapshot: no snapshot")
	// ErrStaleVersion: approval of a version that is neither the latest nor
	// the approved one.
	ErrStaleVersion = errors.New("snapshot: version is not the latest or the approved one")
)
