package mcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/ledger"
	"github.com/huynle/mcp-gateway/internal/observability"
)

// StageLedger is the write ledger stage (decision dovthftx), inserted
// after StagePolicy (so the confirm handler has produced the approval id)
// and before StageRateLimit. It applies to write tools and to any call
// that carries an approval (a confirmed read must consume its approval
// too). Before the call it asks ledger.Service.Begin, in one transaction,
// to consume the approval when there is one and to insert the in_progress
// row, or to report a prior operation under the same idempotency key:
//
//   - a prior that succeeded inside the window: the handler does not run
//     and the answer is an explicit replay (replayResult: "_ledger":
//     "replayed", the operation, tool and window, the stored result IDs
//     when there are any, and a message saying how to run it again);
//     tools with connectors.IdempotencyPerCall (user-added MCP servers)
//     are never deduplicated by arguments (Intent.PerCall), so they never
//     replay or wait on an identical earlier call;
//   - a prior still in_progress or unknown: CodePendingVerification with
//     the operation id in error.data;
//   - otherwise Call.OperationID and CallContext.OperationID are set (and,
//     after an approval, Call.Args are the approval's stored arguments),
//     the rest of the pipeline runs, and the outcome is recorded: no error
//     is succeeded with the tool's ResultIDs; connectors.ErrOutcomeUnknown,
//     a deadline, a cancellation, a timeout or a reset connection is
//     unknown (the reconciler takes over); anything else is failed with
//     the error class.
//
// The outcome is recorded even when the request context was cut off by
// the drain, with its own short deadline.
const StageLedger = "ledger"

// finishTimeout bounds the outcome write after a call whose context is gone.
const finishTimeout = 5 * time.Second

// ReplayKey is the key in a replayed result's content that marks it.
const ReplayKey = "_ledger"

// Errors the stage returns.
var (
	errLedgerUnbound = NewToolError(CodeInternal, "ledger_unbound", "write cannot be recorded without a resolved account and policy version")
	errLedgerFailed  = NewToolError(CodeInternal, "ledger_failed", "write could not be recorded")
)

// LedgerStage builds the stage over svc.
func LedgerStage(svc *ledger.Service, log *slog.Logger) Stage {
	if log == nil {
		log = slog.Default()
	}
	return stage{StageLedger, func(ctx context.Context, cc *CallContext, next Next) (connectors.Result, error) {
		if cc.Tool == nil {
			return connectors.Result{}, ErrToolNotFound(cc.Name)
		}
		if cc.Tool.Kind != connectors.KindWrite && cc.ApprovalID == "" {
			return next(ctx)
		}
		if cc.AccountID == "" || cc.PolicyVersion == "" {
			log.Error("write without a bound account or policy version; refusing", "event", "ledger.unbound",
				"tool", cc.Call.Tool, "account", cc.AccountID != "", "policy_version", cc.PolicyVersion != "", observability.RequestIDAttr(ctx))
			return connectors.Result{}, errLedgerUnbound
		}
		in := ledger.Intent{
			UserID: cc.Principal.UserID, TokenID: cc.Principal.TokenID, AccountID: cc.AccountID, Tool: cc.Call.Tool,
			Digest: ledger.Digest(cc.Call.Args), PolicyVersionID: cc.PolicyVersion, ApprovalID: cc.ApprovalID,
			PerCall: cc.Tool.Idempotency == connectors.IdempotencyPerCall,
		}
		in.ResourceIdentity = cc.resourceIdentity()
		op, prior, err := svc.Begin(ctx, in)
		switch {
		case err != nil && cc.ApprovalID != "":
			// The approval could not be consumed: the confirm handler
			// maps the approvals error to the harness's answer.
			return connectors.Result{}, err
		case errors.Is(err, ledger.ErrInvalid):
			return connectors.Result{}, errLedgerUnbound
		case err != nil:
			log.Error("ledger begin failed", "event", "ledger.begin_failed", "tool", cc.Call.Tool,
				"error", observability.RedactError(err), observability.RequestIDAttr(ctx))
			return connectors.Result{}, errLedgerFailed
		}
		switch prior.Kind {
		case ledger.PriorReplay:
			cc.OperationID = prior.Operation.ID
			cc.replayed = true
			return replayResult(prior.Operation), nil
		case ledger.PriorPending:
			cc.OperationID = prior.Operation.ID
			return connectors.Result{}, pendingVerification(prior.Operation)
		}
		cc.OperationID = op.ID
		cc.Call.OperationID = op.ID
		if op.ApprovalID != "" {
			cc.ApprovalID = op.ApprovalID
			cc.Call.ApprovalID = op.ApprovalID
			cc.Call.Args = op.ApprovalArgs
		}
		res, err := next(ctx)
		out := classifyOutcome(res, err, cc.Tool)
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), finishTimeout)
		defer cancel()
		if _, ferr := svc.Finish(fctx, cc.Principal.UserID, op.ID, out); ferr != nil {
			log.Error("ledger outcome not recorded", "event", "ledger.finish_failed", "operation_id", op.ID, "tool", cc.Call.Tool,
				"state", out.State, "error", observability.RedactError(ferr), observability.RequestIDAttr(ctx))
		}
		return res, err
	}}
}

// classifyOutcome maps the call's result onto a ledger outcome.
func classifyOutcome(res connectors.Result, err error, tool *connectors.Tool) ledger.Outcome {
	if err == nil {
		var ids map[string]string
		if tool != nil && tool.ResultIDs != nil {
			ids = tool.ResultIDs(res)
		}
		return ledger.Succeeded(ids)
	}
	var te *ToolError
	var rl *connectors.RateLimited
	var ne net.Error
	switch {
	case errors.As(err, &te):
		// Refused by a later gateway stage (the limiter) before or after
		// the call; the vendor answered, so the outcome is known.
		return ledger.Failed(te.Class())
	case errors.As(err, &rl):
		return ledger.Failed("vendor_rate_limited")
	case errors.Is(err, connectors.ErrOutcomeUnknown):
		return ledger.Unknown("outcome_unknown")
	case errors.Is(err, context.DeadlineExceeded):
		return ledger.Unknown("timeout")
	case errors.Is(err, context.Canceled):
		return ledger.Unknown("canceled")
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE), errors.Is(err, io.ErrUnexpectedEOF):
		return ledger.Unknown("connection_reset")
	case errors.As(err, &ne) && ne.Timeout():
		return ledger.Unknown("timeout")
	}
	return ledger.Failed(errorClass(err, "tool_error"))
}

// replayResult renders a prior operation as the tool result of a replay:
// never content (only the stored result IDs, and the "result" key only
// when there are any), marked so the harness can tell, and with a message
// that says the call was not run again, which operation it repeats and how
// to run it deliberately.
func replayResult(op *ledger.Operation) connectors.Result {
	content := map[string]any{
		ReplayKey:      "replayed",
		"operation_id": op.ID,
		"tool":         op.Tool,
		"state":        op.State,
		"succeeded_at": op.CreatedAt.UTC().Format(time.RFC3339),
	}
	if !op.WindowEnd.IsZero() {
		content["window_ends_at"] = op.WindowEnd.UTC().Format(time.RFC3339)
	}
	msg := fmt.Sprintf("Replay, not run again: an identical call of %s (same account and arguments) already succeeded as operation %s at %s, and the gateway does not repeat identical writes inside its idempotency window",
		op.Tool, op.ID, op.CreatedAt.UTC().Format(time.RFC3339))
	if len(op.ResultIDs) > 0 {
		content["result"] = op.ResultIDs
		keys := make([]string, 0, len(op.ResultIDs))
		for k := range op.ResultIDs {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, k+"="+op.ResultIDs[k])
		}
		msg += ". Stored result identifiers: " + strings.Join(parts, ", ")
	} else {
		msg += "; no result identifiers were stored for it (the gateway keeps identifiers only, never content)"
	}
	msg += ". To run it again deliberately, change the arguments"
	if !op.WindowEnd.IsZero() {
		msg += " or retry after " + op.WindowEnd.UTC().Format(time.RFC3339)
	}
	content["message"] = msg + "."
	return connectors.Result{Content: content}
}

// pendingVerification is the answer while an earlier attempt is open.
func pendingVerification(op *ledger.Operation) *ToolError {
	te := NewToolError(CodePendingVerification, "pending_verification",
		fmt.Sprintf("a previous attempt of this write is still being verified (operation %s); do not retry until it is resolved", op.ID))
	te.Data = map[string]any{"operation_id": op.ID, "state": op.State}
	return te
}
