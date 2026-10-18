package approvals

import (
	"context"
	"errors"
	"fmt"

	"github.com/huynle/mcp-gateway/internal/caps"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/ledger"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/observability"
)

// DeferConsumption switches the handler to the ledger-backed mode
// (decision s0p05diu: "approvals are consumed in the same transaction as
// the ledger insert"): the handler still creates approvals, waits for
// the user and answers "approval required", but once an approval applies
// it only passes its id forward (CallContext.ApprovalID, Call.ApprovalID)
// and clears the call's arguments; the ledger stage (mcp.LedgerStage,
// which must be in the pipeline) consumes the approval through
// Service.LedgerConsumer inside Begin's transaction, runs the stored
// arguments, and any consume error that comes back through next is
// mapped to the harness's answer here. Set it only together with the
// ledger stage: without one a confirmed call runs with empty arguments
// and the approval is never used.
func (h *ConfirmHandler) DeferConsumption(v bool) { h.deferred = v }

// Deferred reports whether consumption is left to the ledger stage.
func (h *ConfirmHandler) Deferred() bool { return h.deferred }

// confirmDeferred is Confirm for the deferred mode.
func (h *ConfirmHandler) confirmDeferred(ctx context.Context, cc *mcp.CallContext, next mcp.Next, b Binding) (connectors.Result, error) {
	if cc.Call.ApprovalID != "" {
		b.ApprovalID = cc.Call.ApprovalID
		cc.ApprovalID = b.ApprovalID
		a, err := h.svc.Get(ctx, b.UserID, b.ApprovalID)
		if err != nil {
			return h.refuse(ctx, cc, err, b.ApprovalID)
		}
		if a.Status == StatusPending && a.ExpiresAt.After(h.svc.now()) {
			return h.waitAndForward(ctx, cc, next, b, a)
		}
		return h.forward(ctx, cc, next, b.ApprovalID)
	}
	b.Digest = Digest(cc.Call.Args)
	id, err := h.svc.FindApproved(ctx, b)
	switch {
	case err == nil:
		return h.forward(ctx, cc, next, id)
	case !errors.Is(err, ErrNotFound):
		return h.refuse(ctx, cc, err, "")
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
	if ce := (*caps.ExceededError)(nil); errors.As(err, &ce) {
		return connectors.Result{}, mcp.NewToolError(mcp.CodeDenied, caps.Class, ce.Error())
	}
	if err != nil {
		h.log.Error("approval not created", "event", "approvals.create_failed", "tool", cc.Call.Tool,
			"error", observability.RedactError(err), observability.RequestIDAttr(ctx))
		return connectors.Result{}, mcp.NewToolError(mcp.CodeInternal, "approval_failed", "approval could not be recorded")
	}
	cc.ApprovalID = a.ID
	b.ApprovalID, b.Digest = a.ID, nil
	return h.waitAndForward(ctx, cc, next, b, a)
}

// waitAndForward waits up to Config.Wait for a decision on a, then
// forwards an approved one or answers by its status.
func (h *ConfirmHandler) waitAndForward(ctx context.Context, cc *mcp.CallContext, next mcp.Next, b Binding, a *Approval) (connectors.Result, error) {
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
		if h.metrics != nil && a.Status == StatusPending {
			h.metrics.Approval(MetricWaitedThrough)
		}
		return h.forward(ctx, cc, next, a.ID)
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

// forward hands the approval id to the rest of the pipeline. The call's
// arguments are cleared so that, whatever runs next, the harness's
// regenerated arguments never reach the connector: the ledger stage
// replaces them with the stored ones after the consume. A consume error
// coming back is mapped like a direct one.
func (h *ConfirmHandler) forward(ctx context.Context, cc *mcp.CallContext, next mcp.Next, id string) (connectors.Result, error) {
	cc.ApprovalID = id
	cc.Call.ApprovalID = id
	cc.Call.Args = map[string]any{}
	res, err := next(ctx)
	if err != nil && isConsumeError(err) {
		return h.refuse(ctx, cc, err, id)
	}
	return res, err
}

func isConsumeError(err error) bool {
	for _, known := range []error{ErrNotFound, ErrMismatch, ErrPending, ErrDenied, ErrConsumed, ErrExpired} {
		if errors.Is(err, known) {
			return true
		}
	}
	return false
}

// FindApproved returns the id of the newest approved, unconsumed,
// unexpired approval bound to b with b.Digest, without consuming it
// (ErrNotFound when none): the deferred handler's digest lookup.
func (s *Service) FindApproved(ctx context.Context, b Binding) (string, error) {
	switch {
	case b.UserID == "" || b.AccountID == "" || b.Tool == "" || b.PolicyVersionID == "":
		return "", fmt.Errorf("%w: binding is incomplete", ErrInvalid)
	case len(b.Digest) == 0:
		return "", fmt.Errorf("%w: digest is required", ErrInvalid)
	}
	now := s.now()
	var id string
	err := s.st.AsUser(ctx, b.UserID, func(tx Tx) error {
		var err error
		id, err = tx.FindApprovedApproval(ctx, b.store(), b.Digest, now)
		return err
	})
	if err != nil {
		return "", mapNotFound(err)
	}
	return id, nil
}

// LedgerConsumer adapts the service to ledger.ApprovalConsumer: Consume
// runs inside the ledger's PostgreSQL transaction (Tx.StoreTx), so the
// approval's single use and the in_progress insert commit or roll back
// together. The resource identity recorded with the approval travels
// along so the ledger row carries it.
func (s *Service) LedgerConsumer() ledger.ApprovalConsumer { return ledgerConsumer{svc: s} }

type ledgerConsumer struct{ svc *Service }

func (c ledgerConsumer) Consume(ctx context.Context, tx ledger.Tx, b ledger.ApprovalBinding) (*ledger.ConsumedApproval, error) {
	st := tx.StoreTx()
	if st == nil {
		return nil, fmt.Errorf("%w: the ledger consumer needs a store transaction", ErrInvalid)
	}
	atx := FromStoreTx(st)
	consumed, err := c.svc.Consume(ctx, atx, Binding{
		UserID: b.UserID, AccountID: b.AccountID, Tool: b.Tool, PolicyVersionID: b.PolicyVersionID, ApprovalID: b.ApprovalID,
	})
	if err != nil {
		return nil, err
	}
	out := &ledger.ConsumedApproval{ID: consumed.ID, Args: consumed.Args}
	if rec, err := atx.GetApproval(ctx, consumed.ID); err == nil {
		out.ResourceIdentity = fromRecord(rec).ResourceIdentity
	}
	return out, nil
}
