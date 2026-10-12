package mcp

import (
	"context"
	"errors"
	"log/slog"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/observability"
)

// StagePrecheck is the pre-policy validation stage (Brain task 8ky7l4e6).
// DefaultPipeline puts it right before StagePolicy (after account and
// scope; before ratelimit when there is no policy stage) when
// PipelineDeps.Precheck is set. It asks the Prechecker whether the call
// can run at all (for a federated tool: the tool is in its server's
// approved snapshot, enabled, and the arguments validate against the
// pinned input schema) so that a call that can never run is refused
// before policy: no approval is created, no approval notification is
// sent, and no ledger operation is recorded for it. A refusal is a
// *ToolError the Prechecker builds; the stage marks the call as denied
// for the audit row. Any other error fails closed with CodeInternal
// (class precheck_unavailable) and the cause stays in the log.
//
// The check does not replace the dispatch-time check: the review may
// change between an approval and its retry, so the tool's handler checks
// again (defence in depth).
const StagePrecheck = "precheck"

// Prechecker validates a call before policy. It returns nil to let the
// call continue, a *ToolError to refuse it (the message must never echo
// argument values), or another error when it could not decide. The call
// carries the stripped arguments (no account / approval_id) and the
// principal.
type Prechecker interface {
	Precheck(ctx context.Context, tool connectors.Tool, call connectors.Call) error
}

// PrecheckerFunc adapts a function to Prechecker.
type PrecheckerFunc func(ctx context.Context, tool connectors.Tool, call connectors.Call) error

// Precheck implements Prechecker.
func (f PrecheckerFunc) Precheck(ctx context.Context, tool connectors.Tool, call connectors.Call) error {
	return f(ctx, tool, call)
}

// errPrecheckUnavailable is the fail-closed answer when the Prechecker
// could not decide.
var errPrecheckUnavailable = NewToolError(CodeInternal, "precheck_unavailable", "the call could not be checked")

// PrecheckStage builds the stage over p (nil lets every call through)
// and log (nil means slog.Default()).
func PrecheckStage(p Prechecker, log *slog.Logger) Stage {
	if log == nil {
		log = slog.Default()
	}
	return stage{StagePrecheck, func(ctx context.Context, cc *CallContext, next Next) (connectors.Result, error) {
		if cc.Tool == nil {
			return connectors.Result{}, ErrToolNotFound(cc.Name)
		}
		if p == nil {
			return next(ctx)
		}
		err := p.Precheck(ctx, *cc.Tool, cc.Call)
		if err == nil {
			return next(ctx)
		}
		cc.Decision = "deny"
		var te *ToolError
		if errors.As(err, &te) {
			return connectors.Result{}, te
		}
		log.Error("precheck failed; call refused", "event", "mcp.precheck_unavailable", "tool", cc.Call.Tool,
			"error", observability.RedactError(err), observability.RequestIDAttr(ctx))
		return connectors.Result{}, errPrecheckUnavailable
	}}
}
