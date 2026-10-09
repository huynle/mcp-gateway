package mcp

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// Errors from pipeline construction and execution.
var (
	// ErrStageNotFound reports an Insert anchor that is not in the pipeline.
	ErrStageNotFound = errors.New("mcp: pipeline stage not found")
	// ErrDuplicateStage reports two stages with the same name.
	ErrDuplicateStage = errors.New("mcp: pipeline stage already present")
	// ErrInvalidStage reports a nil stage or one with an empty name.
	ErrInvalidStage = errors.New("mcp: invalid pipeline stage")
	// ErrNoDispatch reports a run that reached the end of the pipeline
	// without any stage answering: the dispatch stage is missing.
	ErrNoDispatch = errors.New("mcp: no stage dispatched the call")
)

// CallContext is the state of one tools/call as it moves through the
// pipeline. Stages read what earlier stages set and fill in what later
// stages and the audit record need. Arguments live only in RawArgs and
// Call.Args; nothing here is logged or audited wholesale.
type CallContext struct {
	// Principal is the authenticated token (the authenticate stage checks it
	// is present; the HTTP layer sets it).
	Principal *tokens.Principal
	// Name is the tool the harness asked for, as sent.
	Name string
	// RawArgs are the arguments as received, including the gateway-injected
	// ones. The strip stage derives Call.Args from them.
	RawArgs map[string]any
	// Tool is the resolved registry entry; nil until the resolve stage ran.
	Tool *connectors.Tool
	// Call is what the dispatch stage hands the tool's Handler.
	Call connectors.Call
	// Started is when Run began; audit computes latency from it.
	Started time.Time
	// RequestID is the HTTP request's ID for the audit row.
	RequestID string

	// Audit fields later stages set: the policy decision ("allow", "deny",
	// "confirm"; Run defaults it to "allow" since without a policy stage
	// every resolved call proceeds), the policy version, the resolved
	// account, the consumed approval and the ledger operation.
	Decision      string
	PolicyVersion string
	AccountID     string
	AccountLabel  string
	ApprovalID    string
	OperationID   string
	// AccountScopes are the scopes recorded for the resolved account
	// (nil when the source recorded none); the scope stage checks them
	// against the tool's RequiredScopes.
	AccountScopes []string
	// ResourceIdentity is the identity the policy stage evaluated: the
	// tool's ResourceIdentity hook over Call.Args, passed through the
	// app's connectors.IdentityResolver when it has one (a Slack channel
	// id resolved to its name). Nil until the policy stage ran; audit
	// and the ledger prefer it over recomputing from the arguments.
	ResourceIdentity map[string]string

	// replayed marks a result the ledger stage served from a prior
	// operation; the audit row's error class says so.
	replayed bool
}

// resourceIdentity is the identity later stages record: what the policy
// stage evaluated when it ran, else the tool's hook over the arguments.
func (cc *CallContext) resourceIdentity() map[string]string {
	if cc.ResourceIdentity != nil {
		return cc.ResourceIdentity
	}
	if cc.Tool != nil && cc.Tool.ResourceIdentity != nil {
		return cc.Tool.ResourceIdentity(cc.Call.Args)
	}
	return nil
}

// Next continues the pipeline from the current stage. A stage that answers
// without calling it (dispatch, a cache hit, an early denial) short-circuits
// everything after it.
type Next func(ctx context.Context) (connectors.Result, error)

// Stage is one step of the tools/call pipeline. Stages form an onion: each
// may act before calling next, after it returns, or instead of it. Name is
// the anchor Pipeline.Insert addresses and must be unique in a pipeline.
type Stage interface {
	Name() string
	Run(ctx context.Context, cc *CallContext, next Next) (connectors.Result, error)
}

// Position says where Insert puts a stage relative to its anchor.
type Position int

// The two positions.
const (
	Before Position = iota
	After
)

// Pipeline is an ordered list of stages. It is safe to Insert while other
// goroutines Run; each Run uses the list as it was when the run started.
type Pipeline struct {
	mu     sync.RWMutex
	stages []Stage
}

// NewPipeline builds a pipeline from stages in order. Names must be unique.
func NewPipeline(stages ...Stage) (*Pipeline, error) {
	p := &Pipeline{}
	for _, s := range stages {
		if err := validateStage(s); err != nil {
			return nil, err
		}
		if p.index(s.Name()) >= 0 {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateStage, s.Name())
		}
		p.stages = append(p.stages, s)
	}
	return p, nil
}

// Insert places stage before or after the stage named anchor. Later modules
// use it to add account resolution, policy, confirmation and the ledger
// without touching the transport.
func (p *Pipeline) Insert(pos Position, anchor string, stage Stage) error {
	if err := validateStage(stage); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.index(stage.Name()) >= 0 {
		return fmt.Errorf("%w: %s", ErrDuplicateStage, stage.Name())
	}
	i := p.index(anchor)
	if i < 0 {
		return fmt.Errorf("%w: %q", ErrStageNotFound, anchor)
	}
	if pos == After {
		i++
	}
	p.stages = slices.Insert(slices.Clone(p.stages), i, stage)
	return nil
}

// Names returns the stage names in order.
func (p *Pipeline) Names() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]string, len(p.stages))
	for i, s := range p.stages {
		out[i] = s.Name()
	}
	return out
}

// Run executes the pipeline for cc. It fills Started, Call.Tool and the
// default Decision before the first stage runs.
func (p *Pipeline) Run(ctx context.Context, cc *CallContext) (connectors.Result, error) {
	p.mu.RLock()
	stages := p.stages
	p.mu.RUnlock()

	if cc.Started.IsZero() {
		cc.Started = time.Now()
	}
	if cc.Decision == "" {
		cc.Decision = "allow"
	}
	if cc.Call.Tool == "" {
		cc.Call.Tool = cc.Name
	}
	var step func(ctx context.Context, i int) (connectors.Result, error)
	step = func(ctx context.Context, i int) (connectors.Result, error) {
		if i >= len(stages) {
			return connectors.Result{}, ErrNoDispatch
		}
		return stages[i].Run(ctx, cc, func(ctx context.Context) (connectors.Result, error) {
			return step(ctx, i+1)
		})
	}
	return step(ctx, 0)
}

// index returns the position of the stage named name, or -1. Callers hold
// the lock (or own the pipeline, during construction).
func (p *Pipeline) index(name string) int {
	return slices.IndexFunc(p.stages, func(s Stage) bool { return s.Name() == name })
}

func validateStage(s Stage) error {
	if s == nil {
		return fmt.Errorf("%w: nil stage", ErrInvalidStage)
	}
	if s.Name() == "" {
		return fmt.Errorf("%w: empty name", ErrInvalidStage)
	}
	return nil
}
