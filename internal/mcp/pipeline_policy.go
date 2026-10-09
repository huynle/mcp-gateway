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
// and the account known, it builds the resource identity (the tool's
// hook, then the app's connectors.IdentityResolver when the connector
// has one: a Slack channel id becomes its name, so name conditions
// hold whichever form the harness used), asks the Decider and sets
// CallContext.Decision, PolicyVersion and ResourceIdentity for the
// audit row. A resolver failure fails closed: CodeDenied, class
// identity_unresolved, before the decider runs. Then:
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

// errIdentityUnresolved is the fail-closed answer when the app's
// IdentityResolver could not name the resource: the policy cannot be
// evaluated against what the rules are written in, so the call is
// refused as a denial. The cause stays in the log.
var errIdentityUnresolved = NewToolError(CodeDenied, "identity_unresolved",
	"denied: the resource could not be identified for policy (pass the channel by name, or check that the account can see it)")

// IdentityResolvers finds the connectors.IdentityResolver of an app;
// *connectors.Registry implements it (RegisterConnector installs the
// resolver of every connector that has one). nil means no app resolves.
type IdentityResolvers interface {
	IdentityResolver(app string) (connectors.IdentityResolver, bool)
}

// errDenied is the answer for a deny decision. The reason stays in the
// log and the audit row: the harness learns only that policy refused.
var errDenied = NewToolError(CodeDenied, "denied", "denied by policy")

// PolicyStage builds the stage over d, confirm (nil means
// DefaultConfirmHandler) and resolvers (nil means no connector resolves
// identities; DefaultPipeline passes the registry).
func PolicyStage(d Decider, confirm ConfirmHandler, resolvers IdentityResolvers, log *slog.Logger) Stage {
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
		cc.ResourceIdentity = in.ResourceIdentity
		if resolved, err := resolveIdentity(ctx, resolvers, cc, in.ResourceIdentity); err != nil {
			cc.Decision = string(policy.OutcomeDeny)
			log.Warn("resource identity unresolved; call denied", "event", "mcp.identity_unresolved", "tool", cc.Call.Tool,
				"app", cc.Tool.App, "error", observability.RedactError(err), observability.RequestIDAttr(ctx))
			return connectors.Result{}, errIdentityUnresolved
		} else {
			in.ResourceIdentity, cc.ResourceIdentity = resolved, resolved
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

// resolveIdentity passes identity through the app's IdentityResolver
// when the tool runs against an account and the app has one; otherwise
// identity comes back as is. An error means the resolver could not name
// the resource and the caller must fail closed.
func resolveIdentity(ctx context.Context, resolvers IdentityResolvers, cc *CallContext, identity map[string]string) (map[string]string, error) {
	if resolvers == nil || cc.Tool.NoAccount {
		return identity, nil
	}
	r, ok := resolvers.IdentityResolver(cc.Tool.App)
	if !ok {
		return identity, nil
	}
	return r.ResolveIdentity(ctx, cc.Call, identity)
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
