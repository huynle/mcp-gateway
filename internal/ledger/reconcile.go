package ledger

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/store"
)

// Error classes the reconciler and sweep record on operations (the
// error_code column and the audit error class).
const (
	// ClassReconciled: the reconciler found the write took effect.
	ClassReconciled = "reconciled"
	// ClassNotFound: the reconciler found the write did not take effect.
	ClassNotFound = "not_found"
	// ClassNotReconcilable: the tool declares no reconciliation (or is no
	// longer registered); the user must check the app.
	ClassNotReconcilable = "not_reconcilable"
	// ClassExhausted: MaxReconcileAttempts checks could not tell.
	ClassExhausted = "reconcile_exhausted"
	// ClassExpired: the operation is older than MaxReconcileAge.
	ClassExpired = "reconcile_expired"
	// ClassStale: an in_progress row older than StaleAfter; the replica
	// that owned it is presumed dead.
	ClassStale = "stale"
	// ClassShutdown: this replica stopped while the call was in flight.
	ClassShutdown = "shutdown"
)

// reconcileBatch bounds one run of the reconciler.
const reconcileBatch = 200

// ReconcileStats summarises one Reconcile run.
type ReconcileStats struct {
	// Checked is how many Reconciliation.Check calls ran.
	Checked int
	// Skipped is how many unknown operations were not due yet (backoff).
	Skipped    int
	Succeeded  int
	Failed     int
	Retried    int
	Unresolved int
}

// Reconcile is one pass over the unknown operations (decision dovthftx,
// "unknown outcomes are bounded"): for each one that is due, the tool's
// Reconciliation.Check decides succeeded (found; the resource id becomes
// the result) or failed (not_found); an error from Check is "cannot tell
// yet" and the next check waits twice as long (attempt n runs 2^(n-1)
// minutes after the previous one). After Config.MaxReconcileAttempts, or
// once the operation is older than Config.MaxReconcileAge, or at once
// when the tool declares no reconciliation, the operation is unresolved:
// the user is notified ("verify in the app"), an audit event records it,
// and the idempotency block is lifted (unresolved rows do not block
// Begin). It runs across all users (the bypass scope); the jobs runner
// calls it on one replica every minute.
func (s *Service) Reconcile(ctx context.Context) (ReconcileStats, error) {
	var stats ReconcileStats
	now := s.now()
	var rows []store.LedgerOperation
	err := s.st.Bypass(ctx, func(tx Tx) error {
		var err error
		rows, err = tx.List(ctx, store.LedgerFilter{States: []string{StateUnknown}, Limit: reconcileBatch})
		return err
	})
	if err != nil {
		return stats, fmt.Errorf("ledger: list unknown operations: %w", err)
	}
	for i := range rows {
		if ctx.Err() != nil {
			return stats, ctx.Err()
		}
		op := fromRow(&rows[i])
		if err := s.reconcileOne(ctx, op, now, &stats); err != nil {
			s.log.Error("ledger: reconcile failed", "event", "ledger.reconcile_failed", "operation_id", op.ID, "tool", op.Tool,
				"error", observability.RedactError(err))
		}
	}
	if stats.Checked > 0 || stats.Unresolved > 0 {
		s.log.Info("ledger: reconciled", "event", "ledger.reconcile", "checked", stats.Checked, "succeeded", stats.Succeeded,
			"failed", stats.Failed, "retried", stats.Retried, "unresolved", stats.Unresolved, "skipped", stats.Skipped)
	}
	return stats, nil
}

func (s *Service) reconcileOne(ctx context.Context, op *Operation, now time.Time, stats *ReconcileStats) error {
	tool, ok := s.lookupTool(op.Tool)
	if !ok || tool.Reconcile.Kind == connectors.ReconcileNone || tool.Reconcile.Check == nil {
		stats.Unresolved++
		return s.resolve(ctx, op, StateUnresolved, ClassNotReconcilable, nil, op.ReconcileAttempts, now)
	}
	if now.Sub(op.CreatedAt) > s.cfg.MaxReconcileAge {
		stats.Unresolved++
		return s.resolve(ctx, op, StateUnresolved, ClassExpired, nil, op.ReconcileAttempts, now)
	}
	if now.Before(op.UpdatedAt.Add(backoff(op.ReconcileAttempts))) {
		stats.Skipped++
		return nil
	}
	attempt := op.ReconcileAttempts + 1
	stats.Checked++
	in := connectors.ReconcileInput{
		Call: connectors.Call{
			Principal: connectors.Principal{UserID: op.UserID, TokenID: op.TokenID},
			Tool:      op.Tool, Account: op.AccountID, OperationID: op.ID, ApprovalID: op.ApprovalID,
		},
		OperationID:      op.ID,
		ResourceIdentity: op.ResourceIdentity,
	}
	res, err := tool.Reconcile.Check(ctx, in)
	switch {
	case err != nil:
		s.log.Warn("ledger: reconcile check could not tell", "event", "ledger.reconcile_retry", "operation_id", op.ID, "tool", op.Tool,
			"attempt", attempt, "error", observability.RedactError(err))
		if attempt >= s.cfg.MaxReconcileAttempts {
			stats.Unresolved++
			return s.resolve(ctx, op, StateUnresolved, ClassExhausted, nil, attempt, now)
		}
		stats.Retried++
		return s.retry(ctx, op, attempt, now, "check_error")
	case res.Outcome == connectors.ReconcileFound:
		stats.Succeeded++
		ids := map[string]string{}
		if res.ResourceID != "" {
			ids["id"] = res.ResourceID
		}
		return s.resolve(ctx, op, StateSucceeded, ClassReconciled, ids, attempt, now)
	case res.Outcome == connectors.ReconcileNotFound:
		stats.Failed++
		return s.resolve(ctx, op, StateFailed, ClassNotFound, nil, attempt, now)
	default:
		return fmt.Errorf("ledger: reconcile %s: unexpected outcome %q", op.Tool, res.Outcome)
	}
}

// backoff is how long after the previous attempt (or after the row
// turned unknown) the next check may run: 2^attempts minutes.
func backoff(attempts int) time.Duration {
	if attempts < 0 {
		attempts = 0
	}
	if attempts > 20 {
		attempts = 20
	}
	return time.Minute << uint(attempts)
}

// retry records an inconclusive check: attempts + 1, updated_at = now
// (which the backoff counts from), one reconcile attempt row.
func (s *Service) retry(ctx context.Context, op *Operation, attempt int, now time.Time, class string) error {
	return s.st.Bypass(ctx, func(tx Tx) error {
		ok, err := tx.Transition(ctx, op.ID, []string{StateUnknown}, store.LedgerTransition{State: StateUnknown, ReconcileAttempts: &attempt, At: now})
		if err != nil || !ok {
			return err
		}
		return tx.CreateAttempt(ctx, &store.LedgerAttempt{
			OperationID: op.ID, UserID: op.UserID, AttemptNo: attempt, Kind: store.AttemptReconcile,
			Outcome: "error", ErrorCode: &class, StartedAt: now, FinishedAt: &now,
		})
	})
}

// resolve closes an unknown operation as state with class, records the
// attempt (when one ran), counts, audits and, for unresolved, notifies.
func (s *Service) resolve(ctx context.Context, op *Operation, state, class string, ids map[string]string, attempt int, now time.Time) error {
	t := store.LedgerTransition{State: state, ErrorCode: &class, ReconcileAttempts: &attempt, Finished: true, At: now}
	if state == StateSucceeded {
		t.ResultIDs = encodeIDs(SanitizeResultIDs(ids))
	}
	var changed bool
	err := s.st.Bypass(ctx, func(tx Tx) error {
		var err error
		changed, err = tx.Transition(ctx, op.ID, []string{StateUnknown}, t)
		if err != nil || !changed || attempt == op.ReconcileAttempts {
			return err
		}
		outcome := "found"
		switch state {
		case StateFailed:
			outcome = "not_found"
		case StateUnresolved:
			outcome = "error"
		}
		return tx.CreateAttempt(ctx, &store.LedgerAttempt{
			OperationID: op.ID, UserID: op.UserID, AttemptNo: attempt, Kind: store.AttemptReconcile,
			Outcome: outcome, ErrorCode: &class, StartedAt: now, FinishedAt: &now,
		})
	})
	if err != nil || !changed {
		return err
	}
	op.State, op.ErrorClass, op.ReconcileAttempts, op.UpdatedAt, op.FinishedAt = state, class, attempt, now, &now
	if state == StateSucceeded {
		op.ResultIDs = SanitizeResultIDs(ids)
	}
	s.count(state)
	s.log.Info("ledger: operation resolved", "event", "ledger.resolved", "operation_id", op.ID, "tool", op.Tool, "user_id", op.UserID,
		"state", state, "class", class, "attempts", attempt)
	s.recordAudit(ctx, op, state, class, now)
	if state == StateUnresolved {
		if err := s.notifier.NotifyUnresolved(ctx, *op); err != nil {
			s.log.Warn("ledger: unresolved notification failed", "event", "ledger.notify_failed", "operation_id", op.ID,
				"error", observability.RedactError(err))
		}
	}
	return nil
}

// recordAudit appends the reconciler's verdict as an audit event: the
// user, tool, account, operation and the state as the outcome; never
// arguments.
func (s *Service) recordAudit(ctx context.Context, op *Operation, state, class string, now time.Time) {
	ev := audit.Event{
		Time: now, UserID: op.UserID, TokenID: op.TokenID, Tool: op.Tool, AccountID: op.AccountID,
		ResourceIdentity: op.ResourceIdentity, Decision: "allow", PolicyVersion: op.PolicyVersionID,
		ApprovalID: op.ApprovalID, OperationID: op.ID, Outcome: state, ErrorClass: class,
		RequestID: observability.RequestIDFromContext(ctx),
	}
	if err := s.audit.Record(ctx, ev); err != nil {
		s.log.Error("ledger: reconcile outcome not audited", "event", "ledger.audit_failed", "operation_id", op.ID,
			"error", observability.RedactError(err))
	}
}

func (s *Service) lookupTool(name string) (connectors.Tool, bool) {
	if s.tools == nil {
		return connectors.Tool{}, false
	}
	return s.tools.Get(name)
}

// SweepStale marks every in_progress operation older than
// Config.StaleAfter as unknown (class "stale"): the replica that owned it
// was cut off or died, so the outcome is for the reconciler to find. It
// returns how many rows changed. The jobs runner calls it on one replica
// every 30 seconds.
func (s *Service) SweepStale(ctx context.Context) (int, error) {
	now := s.now()
	class := ClassStale
	var swept []store.LedgerOperation
	err := s.st.Bypass(ctx, func(tx Tx) error {
		var err error
		swept, err = tx.SweepStale(ctx, now.Add(-s.cfg.StaleAfter), now)
		if err != nil {
			return err
		}
		for i := range swept {
			if _, err := tx.Transition(ctx, swept[i].ID, []string{StateUnknown}, store.LedgerTransition{State: StateUnknown, ErrorCode: &class, At: now}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("ledger: sweep stale: %w", err)
	}
	for i := range swept {
		s.untrack(swept[i].ID)
		s.count(StateUnknown)
		s.log.Warn("ledger: stale in_progress operation marked unknown", "event", "ledger.stale", "operation_id", swept[i].ID,
			"tool", swept[i].Tool, "user_id", swept[i].UserID, "age", now.Sub(swept[i].CreatedAt))
	}
	return len(swept), nil
}

// InFlight returns how many operations this replica began and has not
// finished.
func (s *Service) InFlight() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.inFlight)
}

// Forget stops tracking an operation without finishing it (tests, and a
// caller that hands the operation to another owner).
func (s *Service) Forget(opID string) { s.untrack(opID) }

// Shutdown marks every operation this replica still has in flight as
// unknown (class "shutdown"): the server has cut off the calls, so their
// outcome is for the reconciler to find. It returns how many rows
// changed. Call it after the HTTP server's drain, with a context that is
// not the one being shut down.
func (s *Service) Shutdown(ctx context.Context) (int, error) {
	s.mu.Lock()
	pending := make(map[string]string, len(s.inFlight))
	for id, user := range s.inFlight {
		pending[id] = user
	}
	s.mu.Unlock()
	if len(pending) == 0 {
		return 0, nil
	}
	now := s.now()
	class := ClassShutdown
	var n int
	var errs []error
	for id := range pending {
		err := s.st.Bypass(ctx, func(tx Tx) error {
			ok, err := tx.Transition(ctx, id, []string{StateInProgress}, store.LedgerTransition{State: StateUnknown, ErrorCode: &class, At: now})
			if ok {
				n++
			}
			return err
		})
		if err != nil {
			errs = append(errs, err)
			continue
		}
		s.untrack(id)
		s.count(StateUnknown)
	}
	if n > 0 {
		s.log.Warn("ledger: in-flight operations marked unknown at shutdown", "event", "ledger.shutdown", "count", n)
	}
	return n, errors.Join(errs...)
}
