package store

import (
	"context"
	"fmt"
	"time"
)

type approvalRepo struct{ q Querier }

func (r approvalRepo) Create(ctx context.Context, a *Approval) error {
	var keyID *string
	var wrapped, nonce, ciphertext []byte
	if a.Payload != nil {
		keyID = &a.Payload.KeyID
		wrapped, nonce, ciphertext = a.Payload.WrappedDataKey, a.Payload.Nonce, a.Payload.Ciphertext
	}
	err := r.q.QueryRow(ctx, `
		INSERT INTO approvals (user_id, connection_id, tool, digest,
			payload_key_id, payload_wrapped_key, payload_nonce, payload_ciphertext,
			status, policy_version_id, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, coalesce(nullif($9, ''), 'pending')::approval_status, $10, $11)
		RETURNING id, status, created_at`,
		a.UserID, a.ConnectionID, a.Tool, a.Digest,
		keyID, wrapped, nonce, ciphertext,
		a.Status, a.PolicyVersionID, a.ExpiresAt,
	).Scan(&a.ID, &a.Status, &a.CreatedAt)
	if err != nil {
		return fmt.Errorf("store: create approval: %w", err)
	}
	return nil
}

func (r approvalRepo) Get(ctx context.Context, id string) (*Approval, error) {
	var a Approval
	var keyID *string
	var wrapped, nonce, ciphertext []byte
	err := r.q.QueryRow(ctx, `
		SELECT id, user_id, connection_id, tool, digest,
			payload_key_id, payload_wrapped_key, payload_nonce, payload_ciphertext,
			status, policy_version_id, created_at, expires_at, decided_at, consumed_at
		FROM approvals WHERE id = $1`, id,
	).Scan(&a.ID, &a.UserID, &a.ConnectionID, &a.Tool, &a.Digest,
		&keyID, &wrapped, &nonce, &ciphertext,
		&a.Status, &a.PolicyVersionID, &a.CreatedAt, &a.ExpiresAt, &a.DecidedAt, &a.ConsumedAt)
	if err != nil {
		return nil, notFound(err)
	}
	if keyID != nil {
		a.Payload = &Encrypted{KeyID: *keyID, WrappedDataKey: wrapped, Nonce: nonce, Ciphertext: ciphertext}
	}
	return &a, nil
}

type ledgerRepo struct{ q Querier }

func (r ledgerRepo) CreateOperation(ctx context.Context, op *LedgerOperation) error {
	err := r.q.QueryRow(ctx, `
		INSERT INTO ledger_operations (user_id, connection_id, tool, state, idempotency_key,
			window_start, window_end, approval_id, digest, policy_version_id, result_ids)
		VALUES ($1, $2, $3, coalesce(nullif($4, ''), 'in_progress')::ledger_state, $5,
			$6, $7, $8, $9, $10, coalesce($11::jsonb, '{}'::jsonb))
		RETURNING id, state, result_ids, reconcile_attempts, created_at, updated_at`,
		op.UserID, op.ConnectionID, op.Tool, op.State, op.IdempotencyKey,
		op.WindowStart, op.WindowEnd, op.ApprovalID, op.Digest, op.PolicyVersionID, op.ResultIDs,
	).Scan(&op.ID, &op.State, &op.ResultIDs, &op.ReconcileAttempts, &op.CreatedAt, &op.UpdatedAt)
	if err != nil {
		return fmt.Errorf("store: create ledger operation: %w", err)
	}
	return nil
}

func (r ledgerRepo) GetOperation(ctx context.Context, id string) (*LedgerOperation, error) {
	var op LedgerOperation
	err := r.q.QueryRow(ctx, `
		SELECT id, user_id, connection_id, tool, state, idempotency_key, window_start, window_end,
			approval_id, digest, policy_version_id, result_ids, error_code, reconcile_attempts,
			created_at, updated_at, finished_at
		FROM ledger_operations WHERE id = $1`, id,
	).Scan(&op.ID, &op.UserID, &op.ConnectionID, &op.Tool, &op.State, &op.IdempotencyKey, &op.WindowStart, &op.WindowEnd,
		&op.ApprovalID, &op.Digest, &op.PolicyVersionID, &op.ResultIDs, &op.ErrorCode, &op.ReconcileAttempts,
		&op.CreatedAt, &op.UpdatedAt, &op.FinishedAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &op, nil
}

func (r ledgerRepo) CreateAttempt(ctx context.Context, a *LedgerAttempt) error {
	err := r.q.QueryRow(ctx, `
		INSERT INTO ledger_attempts (operation_id, user_id, attempt_no, kind, outcome, error_code, finished_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, started_at`,
		a.OperationID, a.UserID, a.AttemptNo, a.Kind, a.Outcome, a.ErrorCode, a.FinishedAt,
	).Scan(&a.ID, &a.StartedAt)
	if err != nil {
		return fmt.Errorf("store: create ledger attempt: %w", err)
	}
	return nil
}

func (r ledgerRepo) AttemptsForOperation(ctx context.Context, operationID string) ([]LedgerAttempt, error) {
	rows, err := r.q.Query(ctx, `
		SELECT id, operation_id, user_id, attempt_no, kind, outcome, error_code, started_at, finished_at
		FROM ledger_attempts WHERE operation_id = $1 ORDER BY kind, attempt_no`, operationID)
	if err != nil {
		return nil, fmt.Errorf("store: list ledger attempts: %w", err)
	}
	defer rows.Close()
	var out []LedgerAttempt
	for rows.Next() {
		var a LedgerAttempt
		if err := rows.Scan(&a.ID, &a.OperationID, &a.UserID, &a.AttemptNo, &a.Kind, &a.Outcome, &a.ErrorCode, &a.StartedAt, &a.FinishedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

type auditRepo struct{ q Querier }

func (r auditRepo) Create(ctx context.Context, e *AuditEvent) error {
	err := r.q.QueryRow(ctx, `
		INSERT INTO audit_events (event_type, user_id, actor_user_id, token_id, tool, connection_id, account_label,
			resource, decision, policy_version_id, approval_id, operation_id, outcome, latency_ms, details)
		VALUES (coalesce(nullif($1, ''), 'tool_call'), $2, $3, $4, $5, $6, $7::account_label,
			coalesce($8::jsonb, '{}'::jsonb), $9, $10, $11, $12, $13, $14, coalesce($15::jsonb, '{}'::jsonb))
		RETURNING id, event_type, resource, details, created_at`,
		e.EventType, e.UserID, e.ActorUserID, e.TokenID, e.Tool, e.ConnectionID, e.AccountLabel,
		e.Resource, e.Decision, e.PolicyVersionID, e.ApprovalID, e.OperationID, e.Outcome, e.LatencyMS, e.Details,
	).Scan(&e.ID, &e.EventType, &e.Resource, &e.Details, &e.CreatedAt)
	if err != nil {
		return fmt.Errorf("store: create audit event: %w", err)
	}
	return nil
}

func (r auditRepo) Get(ctx context.Context, id string) (*AuditEvent, error) {
	var e AuditEvent
	err := r.q.QueryRow(ctx, `
		SELECT id, event_type, user_id, actor_user_id, token_id, tool, connection_id, account_label,
			resource, decision, policy_version_id, approval_id, operation_id, outcome, latency_ms, details, created_at
		FROM audit_events WHERE id = $1`, id,
	).Scan(&e.ID, &e.EventType, &e.UserID, &e.ActorUserID, &e.TokenID, &e.Tool, &e.ConnectionID, &e.AccountLabel,
		&e.Resource, &e.Decision, &e.PolicyVersionID, &e.ApprovalID, &e.OperationID, &e.Outcome, &e.LatencyMS, &e.Details, &e.CreatedAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &e, nil
}

// Purge deletes events created before olderThan. It declares the retention
// purge to the append-only trigger for this transaction only; it still fails
// for gateway_app, which has no DELETE privilege.
func (r auditRepo) Purge(ctx context.Context, olderThan time.Time) error {
	if _, err := r.q.Exec(ctx, `SELECT set_config('app.audit_purge', 'on', true)`); err != nil {
		return fmt.Errorf("store: audit purge: %w", err)
	}
	if _, err := r.q.Exec(ctx, `DELETE FROM audit_events WHERE created_at < $1`, olderThan); err != nil {
		return fmt.Errorf("store: audit purge: %w", err)
	}
	return nil
}
