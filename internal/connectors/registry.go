package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Kind says whether a tool only reads from the app or changes something in
// it. Reads skip approvals and the ledger unless policy says otherwise;
// writes always go through both (decision dovthftx).
type Kind string

// The two kinds.
const (
	KindRead  Kind = "read"
	KindWrite Kind = "write"
)

// Errors returned by Registry.Register.
var (
	// ErrDuplicateTool reports a second tool with the same "app.tool" name.
	ErrDuplicateTool = errors.New("connectors: tool already registered")
	// ErrInvalidTool reports a tool that is missing a required field or
	// whose names are not lower-case identifiers; the wrapped message says
	// which.
	ErrInvalidTool = errors.New("connectors: invalid tool")
)

// identRE is the shape of an app or tool name: lower-case letters, digits,
// underscores and hyphens, no dots (the dot separates app from tool). It
// matches what tokens.ParseAllowList accepts so a token scope can always
// name a registered tool.
var identRE = regexp.MustCompile(`^[a-z0-9_-]+$`)

// Principal is who is calling, as far as a connector needs to know. The
// pipeline fills it from the authenticated token; connectors never see the
// token itself or its scope.
type Principal struct {
	UserID  string
	TokenID string
}

// Call is one invocation of a tool as the connector's handler sees it. The
// gateway-injected arguments (account, approval_id) have been removed from
// Args and placed in Account and ApprovalID; everything else in Args is what
// the harness sent.
type Call struct {
	Principal Principal
	// Tool is the full "app.tool" name.
	Tool string
	// Account is the connected account the call runs against (the id the
	// harness passed, or the one the account-resolve stage picked). Empty
	// until that stage exists.
	Account string
	// ApprovalID is the approval the harness is retrying with, if any.
	ApprovalID string
	// OperationID is the ledger operation a write runs under (set by the
	// ledger stage; empty for reads and until that stage exists). Writes
	// that reconcile by a derived ID or marker derive it from this value
	// so Reconciliation.Check can derive the same one later.
	OperationID string
	Args        map[string]any
}

// Result is what a tool handler returns. Content is the payload the harness
// receives: a string, a JSON-marshalable value, or a slice of SDK content
// blocks. Reads mark Empty (nothing matched), Partial (some pages or
// sources failed) and Unavailable (the app could not be reached) so the
// harness can tell "no results" from "could not look"; writes put the
// created or changed resource's ID in Content.
type Result struct {
	Content     any
	Partial     bool
	Unavailable bool
	Empty       bool
}

// Handler runs a tool call. Any error it returns is shown to the harness as
// a tool error (IsError) after redaction; the pipeline's own failures are
// reported as protocol errors instead.
type Handler func(ctx context.Context, call Call) (Result, error)

// Tool is one capability a connector exposes. The gateway adds the account
// and approval_id properties to InputSchema in tools/list and strips them
// from the arguments before Handler runs, so a connector describes only its
// own arguments.
type Tool struct {
	// App is the connector's name ("github"); Name the tool within it
	// ("list_issues"). Both are lower-case identifiers; the full name is
	// App + "." + Name.
	App  string
	Name string
	// Description is shown to the model.
	Description string
	// InputSchema is a JSON Schema object (type "object") for Args.
	InputSchema json.RawMessage
	Kind        Kind
	// RequiredScopes are the vendor OAuth scopes a connected account must
	// have for this tool (connections task).
	RequiredScopes []string
	// ResourceIdentity extracts the audit resource identity (repo, channel,
	// site, ...) from the arguments; it must never return argument content.
	// nil means the tool has no resource identity.
	ResourceIdentity func(args map[string]any) map[string]string
	// Reconcile says how a write can be checked after an unknown outcome.
	// Every write must set Kind explicitly (ReconcileNone is allowed);
	// reads leave it empty.
	Reconcile Reconciliation
	// ResultIDs extracts the identifiers of what a successful write
	// produced (issue number, message timestamp, item id, URL) from its
	// Result. The ledger stores and replays only these, never the
	// content (decision dovthftx). nil means nothing is kept; reads leave
	// it nil.
	ResultIDs func(res Result) map[string]string
	// Bounds caps page size and result size.
	Bounds Bounds
	// NoAccount marks a tool that runs without a connected account; the
	// account stage skips it. Only "<app>.list_accounts" sets it.
	NoAccount bool
	// Handler runs the call. Nil in a Connector's Tools (RegisterConnector
	// binds it to Connector.Call); required by Registry.Register.
	Handler Handler
}

// FullName returns "app.tool".
func (t Tool) FullName() string { return t.App + "." + t.Name }

// Registry holds every tool the gateway can expose, keyed by full name. It
// is safe for concurrent use: connectors register at start-up and the /mcp
// endpoint reads on every request.
type Registry struct {
	mu       sync.RWMutex
	tools    map[string]Tool
	coverage map[string]ScopeCoverage
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{tools: map[string]Tool{}, coverage: map[string]ScopeCoverage{}}
}

// ScopeCoverage reports whether one of an account's granted scopes
// covers a tool's required scope. Vendors differ: Microsoft Graph's
// Mail.ReadWrite covers Mail.Read, Google's broader scopes imply
// narrower ones, Slack and Atlassian compare names. The default
// (ScopeEquals) is a case-insensitive comparison; connectors with
// richer semantics register theirs with SetScopeCoverage.
type ScopeCoverage func(granted []string, required string) bool

// ScopeEquals is the default ScopeCoverage: required is covered when
// one of the granted scopes equals it, ignoring case and surrounding
// space.
func ScopeEquals(granted []string, required string) bool {
	required = strings.TrimSpace(required)
	for _, g := range granted {
		if strings.EqualFold(strings.TrimSpace(g), required) {
			return true
		}
	}
	return false
}

// SetScopeCoverage installs the coverage function for app's tools; nil
// restores ScopeEquals.
func (r *Registry) SetScopeCoverage(app string, fn ScopeCoverage) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if fn == nil {
		delete(r.coverage, app)
		return
	}
	r.coverage[app] = fn
}

// MissingScopes returns the tool's RequiredScopes that granted does not
// cover under the app's coverage function, in declaration order; nil
// when every required scope is covered or the tool requires none.
func (r *Registry) MissingScopes(t Tool, granted []string) []string {
	r.mu.RLock()
	fn := r.coverage[t.App]
	r.mu.RUnlock()
	if fn == nil {
		fn = ScopeEquals
	}
	var missing []string
	for _, req := range t.RequiredScopes {
		if !fn(granted, req) {
			missing = append(missing, req)
		}
	}
	return missing
}

// Register adds t. The full name must be unique (ErrDuplicateTool) and the
// tool well-formed (ErrInvalidTool); on either error nothing changes.
func (r *Registry) Register(t Tool) error {
	if err := t.validate(); err != nil {
		return err
	}
	name := t.FullName()
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.tools[name]; exists {
		return fmt.Errorf("%w: %s", ErrDuplicateTool, name)
	}
	r.tools[name] = t
	return nil
}

// registerAll registers validated tools atomically: either every name is
// new and all are added, or nothing changes.
func (r *Registry) registerAll(tools []Tool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	seen := map[string]bool{}
	for _, t := range tools {
		name := t.FullName()
		if _, exists := r.tools[name]; exists || seen[name] {
			return fmt.Errorf("%w: %s", ErrDuplicateTool, name)
		}
		seen[name] = true
	}
	for _, t := range tools {
		r.tools[t.FullName()] = t
	}
	return nil
}

// Get returns the tool named "app.tool".
func (r *Registry) Get(name string) (Tool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tools[name]
	return t, ok
}

// List returns every tool sorted by full name.
func (r *Registry) List() []Tool {
	r.mu.RLock()
	out := make([]Tool, 0, len(r.tools))
	for _, t := range r.tools {
		out = append(out, t)
	}
	r.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].FullName() < out[j].FullName() })
	return out
}

func (t Tool) validate() error {
	switch {
	case !identRE.MatchString(t.App):
		return fmt.Errorf("%w: app %q must match %s", ErrInvalidTool, t.App, identRE)
	case !identRE.MatchString(t.Name):
		return fmt.Errorf("%w: name %q must match %s", ErrInvalidTool, t.Name, identRE)
	case t.Kind != KindRead && t.Kind != KindWrite:
		return fmt.Errorf("%w: %s: kind must be read or write, got %q", ErrInvalidTool, t.FullName(), t.Kind)
	case t.Handler == nil:
		return fmt.Errorf("%w: %s: handler is nil", ErrInvalidTool, t.FullName())
	case len(t.InputSchema) == 0:
		return fmt.Errorf("%w: %s: input schema is required", ErrInvalidTool, t.FullName())
	case t.Bounds.MaxPageSize < 0 || t.Bounds.MaxResultBytes < 0:
		return fmt.Errorf("%w: %s: bounds must not be negative", ErrInvalidTool, t.FullName())
	}
	var schema struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(t.InputSchema, &schema); err != nil {
		return fmt.Errorf("%w: %s: input schema: %w", ErrInvalidTool, t.FullName(), err)
	}
	if schema.Type != "object" {
		return fmt.Errorf("%w: %s: input schema type must be \"object\", got %q", ErrInvalidTool, t.FullName(), schema.Type)
	}
	return nil
}
