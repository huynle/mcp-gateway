package approvals

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/observability"
)

// ConfirmHandler is the mcp.ConfirmHandler the policy stage calls for a
// confirm decision (decision s0p05diu):
//
//   - the call names an approval_id: the approval is consumed (it must
//     be bound to this user, account, tool and policy version) and the
//     STORED arguments run in place of whatever the retry carried; a
//     still-pending one is waited for first;
//   - no approval_id but an approved, unused approval with the same
//     canonical arguments exists: that one is consumed;
//   - otherwise an approval is created, the notifiers told, and the call
//     waits up to Config.Wait for the user; approved in time means the
//     call completes in this round trip, else the harness gets
//     CodeApprovalRequired with the approval id, the portal URL, the
//     expiry and the retry instructions in error.data.
//
// Consumption runs in its own user transaction (Service.ConsumeNow)
// unless DeferConsumption is set: then the handler only resolves which
// approval applies (waiting for a pending one) and the ledger stage
// consumes it in the transaction that inserts the ledger row (decision
// dovthftx; confirm_deferred.go).
type ConfirmHandler struct {
	svc     *Service
	metrics metricsCounter
	log     *slog.Logger
	// deferred leaves consumption to the ledger stage (confirm_deferred.go).
	deferred bool
}

// metricsCounter is the slice of observability.Metrics the handler uses.
type metricsCounter interface {
	Approval(state string)
}

// NewConfirmHandler builds the handler over svc. metrics may be nil (the
// service's own metrics count the row transitions; this one counts
// waited_through).
func NewConfirmHandler(svc *Service, metrics metricsCounter, log *slog.Logger) *ConfirmHandler {
	if log == nil {
		log = slog.Default()
	}
	if metrics == nil {
		metrics = svc.metrics
	}
	return &ConfirmHandler{svc: svc, metrics: metrics, log: log}
}

// Error messages and classes the harness can see. Mismatch, unknown and
// foreign approvals share one answer so nothing leaks about other users'
// approvals.
const (
	msgMismatch = "approval does not match this call"
	msgDenied   = "approval was denied by the user"
	msgUsed     = "approval already used; request a new one by calling the tool again without approval_id"
	msgExpired  = "approval expired; request a new one by calling the tool again without approval_id"
)

var errNoAccount = mcp.NewToolError(mcp.CodeInternal, "approval_unbound", "approval cannot be recorded without a resolved account")

// Confirm implements mcp.ConfirmHandler.
func (h *ConfirmHandler) Confirm(ctx context.Context, cc *mcp.CallContext, next mcp.Next) (connectors.Result, error) {
	if cc.Principal == nil || cc.Tool == nil {
		return connectors.Result{}, mcp.ErrToolNotFound(cc.Name)
	}
	if cc.AccountID == "" || cc.PolicyVersion == "" {
		h.log.Error("confirm decision without a bound account or policy version; refusing", "event", "approvals.unbound",
			"tool", cc.Call.Tool, "account", cc.AccountID != "", "policy_version", cc.PolicyVersion != "", observability.RequestIDAttr(ctx))
		return connectors.Result{}, errNoAccount
	}
	b := Binding{UserID: cc.Principal.UserID, AccountID: cc.AccountID, Tool: cc.Call.Tool, PolicyVersionID: cc.PolicyVersion}
	if h.deferred {
		return h.confirmDeferred(ctx, cc, next, b)
	}
	if cc.Call.ApprovalID != "" {
		b.ApprovalID = cc.Call.ApprovalID
		return h.consumeAndRun(ctx, cc, next, b, true)
	}
	b.Digest = Digest(cc.Call.Args)
	if matched, res, err := h.tryDigest(ctx, cc, next, b); matched {
		return res, err
	}
	// Prefer the identity the policy stage evaluated (after any connector
	// resolution, e.g. a Slack channel id resolved to its name) so the
	// approval shows the user what policy actually judged.
	resource := cc.ResourceIdentity
	if resource == nil && cc.Tool.ResourceIdentity != nil {
		resource = cc.Tool.ResourceIdentity(cc.Call.Args)
	}
	a, err := h.svc.Create(ctx, Request{
		UserID: cc.Principal.UserID, TokenID: cc.Principal.TokenID, AccountID: cc.AccountID, AccountLabel: cc.AccountLabel,
		Tool: cc.Call.Tool, Args: cc.Call.Args, ResourceIdentity: resource, PolicyVersionID: cc.PolicyVersion, Digest: b.Digest,
	})
	if err != nil {
		h.log.Error("approval not created", "event", "approvals.create_failed", "tool", cc.Call.Tool,
			"error", observability.RedactError(err), observability.RequestIDAttr(ctx))
		return connectors.Result{}, mcp.NewToolError(mcp.CodeInternal, "approval_failed", "approval could not be recorded")
	}
	cc.ApprovalID = a.ID
	b.ApprovalID, b.Digest = a.ID, nil
	return h.waitAndRun(ctx, cc, next, b, a)
}

// tryDigest consumes an approved approval with the same arguments when
// one exists. matched is false when none did and the caller should
// create a new approval.
func (h *ConfirmHandler) tryDigest(ctx context.Context, cc *mcp.CallContext, next mcp.Next, b Binding) (matched bool, res connectors.Result, err error) {
	consumed, err := h.svc.ConsumeNow(ctx, b)
	switch {
	case errors.Is(err, ErrNotFound):
		return false, connectors.Result{}, nil
	case err != nil:
		res, err = h.refuse(ctx, cc, err, b.ApprovalID)
		return true, res, err
	}
	res, err = h.run(ctx, cc, next, consumed)
	return true, res, err
}

// consumeAndRun consumes b.ApprovalID and runs the stored arguments. A
// pending approval is waited for (the harness retried early) when wait
// is set.
func (h *ConfirmHandler) consumeAndRun(ctx context.Context, cc *mcp.CallContext, next mcp.Next, b Binding, wait bool) (connectors.Result, error) {
	cc.ApprovalID = b.ApprovalID
	consumed, err := h.svc.ConsumeNow(ctx, b)
	if errors.Is(err, ErrPending) && wait {
		a, gerr := h.svc.Get(ctx, b.UserID, b.ApprovalID)
		if gerr != nil {
			return h.refuse(ctx, cc, gerr, b.ApprovalID)
		}
		return h.waitAndRun(ctx, cc, next, b, a)
	}
	if err != nil {
		return h.refuse(ctx, cc, err, b.ApprovalID)
	}
	return h.run(ctx, cc, next, consumed)
}

// waitAndRun waits up to Config.Wait for a decision on a, then consumes
// and runs, or answers approval required.
func (h *ConfirmHandler) waitAndRun(ctx context.Context, cc *mcp.CallContext, next mcp.Next, b Binding, a *Approval) (connectors.Result, error) {
	status := StatusPending
	if d := h.svc.cfg.Wait; d > 0 {
		var err error
		status, err = h.svc.Wait(ctx, b.UserID, a.ID, d)
		if err != nil {
			if ctx.Err() != nil {
				return connectors.Result{}, ctx.Err()
			}
			return h.refuse(ctx, cc, err, a.ID)
		}
	}
	switch status {
	case StatusApproved:
		consumed, err := h.svc.ConsumeNow(ctx, b)
		if err != nil {
			return h.refuse(ctx, cc, err, a.ID)
		}
		if h.metrics != nil {
			h.metrics.Approval(MetricWaitedThrough)
		}
		return h.run(ctx, cc, next, consumed)
	case StatusPending:
		return connectors.Result{}, h.approvalRequired(a)
	case StatusDenied:
		return h.refuse(ctx, cc, ErrDenied, a.ID)
	case StatusExpired:
		return h.refuse(ctx, cc, ErrExpired, a.ID)
	default:
		return h.refuse(ctx, cc, ErrConsumed, a.ID)
	}
}

// run continues the pipeline with the stored arguments.
func (h *ConfirmHandler) run(ctx context.Context, cc *mcp.CallContext, next mcp.Next, consumed *Consumed) (connectors.Result, error) {
	cc.ApprovalID = consumed.ID
	cc.Call.ApprovalID = consumed.ID
	cc.Call.Args = consumed.Args
	return next(ctx)
}

// approvalRequired is the answer when the user has not decided in time.
func (h *ConfirmHandler) approvalRequired(a *Approval) *mcp.ToolError {
	url := h.svc.PortalURL()
	te := mcp.NewToolError(mcp.CodeApprovalRequired, "approval_required",
		fmt.Sprintf("approval required: ask the user to approve approval %s at %s, then call this tool again with approval_id=%s", a.ID, url, a.ID))
	te.Data = map[string]any{
		"approval_id":  a.ID,
		"portal_url":   url,
		"expires_at":   a.ExpiresAt.UTC().Format(time.RFC3339),
		"instructions": fmt.Sprintf("ask the user to approve, then call this tool again with approval_id=%s", a.ID),
	}
	return te
}

// refuse maps a consume error to the harness's answer.
func (h *ConfirmHandler) refuse(ctx context.Context, cc *mcp.CallContext, err error, id string) (connectors.Result, error) {
	var te *mcp.ToolError
	switch {
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrMismatch):
		// The id is not one of the caller's approvals for this call (or
		// not an approval at all): it is caller-supplied, unverified
		// data and must not be recorded as the call's approval on the
		// audit row, where it would correlate the caller's call with an
		// approval that may belong to someone else.
		cc.ApprovalID = ""
		te = mcp.NewToolError(mcp.CodeDenied, "approval_mismatch", msgMismatch)
	case errors.Is(err, ErrDenied):
		te = mcp.NewToolError(mcp.CodeDenied, "approval_denied", msgDenied)
	case errors.Is(err, ErrConsumed):
		te = mcp.NewToolError(mcp.CodeDenied, "approval_used", msgUsed)
	case errors.Is(err, ErrExpired):
		te = mcp.NewToolError(mcp.CodeDenied, "approval_expired", msgExpired)
	case errors.Is(err, ErrPending):
		a, gerr := h.svc.Get(ctx, cc.Principal.UserID, id)
		if gerr != nil {
			return h.refuse(ctx, cc, gerr, id)
		}
		return connectors.Result{}, h.approvalRequired(a)
	default:
		h.log.Error("approval check failed", "event", "approvals.consume_failed", "approval_id", id, "tool", cc.Call.Tool,
			"error", observability.RedactError(err), observability.RequestIDAttr(ctx))
		return connectors.Result{}, mcp.NewToolError(mcp.CodeInternal, "approval_failed", "approval could not be checked")
	}
	h.log.Info("approval refused", "event", "approvals.refused", "approval_id", id, "tool", cc.Call.Tool, "class", te.Class(), observability.RequestIDAttr(ctx))
	return connectors.Result{}, te
}
