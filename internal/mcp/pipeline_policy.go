package mcp

import (
	"context"
	"log/slog"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// StagePolicy is the policy stage (decision 490o45d0), inserted after
// StageAccount (after StageStrip when there is no account stage) and
// before StageRateLimit: with the tool resolved, the arguments stripped
// and the account known, it asks the Decider and sets
// CallContext.Decision and PolicyVersion for the audit row. Then:
//
//   - hidden: the very same not-found error as an unknown tool (resolve
//     already hides such tools; this is the second line of defence);
//   - deny: CodeDenied, class "denied";
//   - confirm: the ConfirmHandler (DefaultConfirmHandler answers
//     CodeApprovalRequired; the approvals task supplies one that creates
//     or consumes an approval and then calls next);
//   - allow: next.
//
// When the policy cannot be evaluated the call fails closed with
// CodeInternal and the cause stays in the log.
const StagePolicy = "policy"

// Decider is what the policy stage and PolicyVisibility consult;
// policy.Service implements it.
type Decider interface {
	Decide(ctx context.Context, in policy.Input) (policy.Decision, error)
	Visible(ctx context.Context, in policy.Input) (bool, error)
}

// ConfirmHandler is the hook the policy stage calls when the decision is
// confirm. It owns the rest of the call: it may answer (approval
// pending), or call next once an approval was consumed, setting
// CallContext.ApprovalID for the audit row.
type ConfirmHandler interface {
	Confirm(ctx context.Context, cc *CallContext, next Next) (connectors.Result, error)
}

// ConfirmHandlerFunc adapts a function to ConfirmHandler.
type ConfirmHandlerFunc func(ctx context.Context, cc *CallContext, next Next) (connectors.Result, error)

// Confirm implements ConfirmHandler.
func (f ConfirmHandlerFunc) Confirm(ctx context.Context, cc *CallContext, next Next) (connectors.Result, error) {
	return f(ctx, cc, next)
}

// ErrApprovalRequired is what DefaultConfirmHandler returns: the call
// needs an approval and there is no approval flow yet.
var ErrApprovalRequired = NewToolError(CodeApprovalRequired, "approval_required", "approval required")

// DefaultConfirmHandler refuses every confirm decision with
// ErrApprovalRequired. The approvals task replaces it.
func DefaultConfirmHandler() ConfirmHandler {
	return ConfirmHandlerFunc(func(context.Context, *CallContext, Next) (connectors.Result, error) {
		return connectors.Result{}, ErrApprovalRequired
	})
}

// errPolicyUnavailable is the fail-closed answer when the Decider errs.
var errPolicyUnavailable = NewToolError(CodeInternal, "policy_unavailable", "policy could not be evaluated")

// errDenied is the answer for a deny decision. The reason stays in the
// log and the audit row: the harness learns only that policy refused.
var errDenied = NewToolError(CodeDenied, "denied", "denied by policy")

// PolicyStage builds the stage over d and confirm (nil means
// DefaultConfirmHandler).
func PolicyStage(d Decider, confirm ConfirmHandler, log *slog.Logger) Stage {
	if confirm == nil {
		confirm = DefaultConfirmHandler()
	}
	if log == nil {
		log = slog.Default()
	}
	return stage{StagePolicy, func(ctx context.Context, cc *CallContext, next Next) (connectors.Result, error) {
		if cc.Tool == nil {
			return connectors.Result{}, ErrToolNotFound(cc.Name)
		}
		in := policyInput(cc.Principal, *cc.Tool)
		in.AccountLabel = cc.AccountLabel
		if cc.Tool.ResourceIdentity != nil {
			in.ResourceIdentity = cc.Tool.ResourceIdentity(cc.Call.Args)
		}
		d, err := d.Decide(ctx, in)
		if err != nil {
			cc.Decision = string(policy.OutcomeDeny)
			log.Error("policy unavailable; call refused", "event", "mcp.policy_unavailable", "tool", cc.Call.Tool,
				"error", observability.RedactError(err), observability.RequestIDAttr(ctx))
			return connectors.Result{}, errPolicyUnavailable
		}
		cc.Decision = string(d.Outcome)
		cc.PolicyVersion = d.VersionID
		log.Debug("policy decision", "event", "mcp.policy_decision", "tool", cc.Call.Tool, "decision", d.Outcome,
			"reason", d.Reason, "policy_version", d.Version, observability.RequestIDAttr(ctx))
		switch d.Outcome {
		case policy.OutcomeAllow:
			return next(ctx)
		case policy.OutcomeConfirm:
			return confirm.Confirm(ctx, cc, next)
		case policy.OutcomeDeny:
			return connectors.Result{}, errDenied
		default:
			return connectors.Result{}, ErrToolNotFound(cc.Name)
		}
	}}
}

// PolicyVisibility is the Visibility over the compiled policy: a tool is
// listed when the Decider says it is visible for the user and token. It
// fails closed (nothing visible) when the policy cannot be evaluated.
type PolicyVisibility struct {
	Decider Decider
	Log     *slog.Logger
}

// Visible implements Visibility.
func (v PolicyVisibility) Visible(ctx context.Context, principal *tokens.Principal, tool connectors.Tool) bool {
	if principal == nil || v.Decider == nil {
		return false
	}
	ok, err := v.Decider.Visible(ctx, policyInput(principal, tool))
	if err != nil {
		log := v.Log
		if log == nil {
			log = slog.Default()
		}
		log.Error("policy unavailable; tool hidden", "event", "mcp.policy_unavailable", "tool", tool.FullName(),
			"error", observability.RedactError(err), observability.RequestIDAttr(ctx))
		return false
	}
	return ok
}

// policyInput builds the Input shared by visibility and the stage: the
// principal's identity and token scope plus the tool. The stage adds the
// account label and resource identity.
func policyInput(principal *tokens.Principal, tool connectors.Tool) policy.Input {
	return policy.Input{
		UserID:     principal.UserID,
		TokenID:    principal.TokenID,
		TokenScope: principal.Scope,
		Tool:       tool,
	}
}
