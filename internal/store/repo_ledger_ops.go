package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// Ledger-module queries beyond the minimal repository in tx.go (decision
// dovthftx): the per-key advisory lock and lookup that make Begin
// decide once per idempotency key, inserts with the caller's timestamps,
// resource identity and token, conditional state transitions, attempts
// with an explicit start, listing by state and the stale sweep. They take
// a Querier so they run under whichever scope the caller opened: the
// request path under WithUser (row-level security scopes everything to
// the caller), the reconciler and sweep under WithJobs.

// ErrLedgerKeyOpen is returned by CreateLedgerOperation when another
// operation with the same idempotency key is still in_progress or unknown
// (the unique partial index of migration 00012): a concurrent Begin won.
var ErrLedgerKeyOpen = errors.New("store: an operation with this idempotency key is still open")

// LedgerTransition is what TransitionLedgerOperation sets. ResultIDs and
// ErrorCode are left as they are when nil; ReconcileAttempts when nil;
// Finished sets finished_at = At.
type LedgerTransition struct {
	State             string
	ResultIDs         json.RawMessage
	ErrorCode         *string
	ReconcileAttempts *int
	Finished          bool
	At                time.Time
}

// LedgerFilter selects operations for ListLedgerOperations. Zero fields
// do not filter; Limit 0 means 100.
type LedgerFilter struct {
	UserID        string
	States        []string
	CreatedBefore time.Time
	UpdatedBefore time.Time
	Limit         int
}

const ledgerColumns = `
	id, user_id, connection_id, tool, state, idempotency_key, window_start, window_end,
	approval_id, digest, policy_version_id, result_ids, error_code, reconcile_attempts,
	created_at, updated_at, finished_at, resource, token_id`

type ledgerScanner interface {
	Scan(dest ...any) error
}

func scanLedgerOperation(row ledgerScanner) (*LedgerOperation, error) {
	var op LedgerOperation
	err := row.Scan(&op.ID, &op.UserID, &op.ConnectionID, &op.Tool, &op.State, &op.IdempotencyKey, &op.WindowStart, &op.WindowEnd,
		&op.ApprovalID, &op.Digest, &op.PolicyVersionID, &op.ResultIDs, &op.ErrorCode, &op.ReconcileAttempts,
		&op.CreatedAt, &op.UpdatedAt, &op.FinishedAt, &op.Resource, &op.TokenID)
	if err != nil {
		return nil, err
	}
	return &op, nil
}

// LockLedgerKey takes a transaction-scoped advisory lock on the
// idempotency key, so concurrent Begins for the same key run their
// lookup-then-insert one after the other and the loser sees the winner's
// row instead of racing it. The lock is released at commit or rollback;
// pooled connections are safe because it never outlives the transaction.
func LockLedgerKey(ctx context.Context, q Querier, key string) error {
	if _, err := q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, key); err != nil {
		return fmt.Errorf("store: lock ledger key: %w", err)
	}
	return nil
}

// LatestLedgerOperationByKey returns the newest operation with the key
// created at or after since (ErrNotFound when none is visible).
func LatestLedgerOperationByKey(ctx context.Context, q Querier, key string, since time.Time) (*LedgerOperation, error) {
	op, err := scanLedgerOperation(q.QueryRow(ctx, `SELECT`+ledgerColumns+`
		FROM ledger_operations WHERE idempotency_key = $1 AND created_at >= $2
		ORDER BY created_at DESC, id DESC LIMIT 1`, key, since))
	if err != nil {
		return nil, notFound(err)
	}
	return op, nil
}

// CreateLedgerOperation inserts op. CreatedAt and UpdatedAt are taken
// from op when set (the service's clock) and default to now() otherwise;
// a zero State means in_progress. ErrLedgerKeyOpen when another open
// operation holds the key.
func CreateLedgerOperation(ctx context.Context, q Querier, op *LedgerOperation) error {
	resource := op.Resource
	if len(resource) == 0 {
		resource = json.RawMessage(`{}`)
	}
	var created, updated *time.Time
	if !op.CreatedAt.IsZero() {
		created = &op.CreatedAt
	}
	if !op.UpdatedAt.IsZero() {
		updated = &op.UpdatedAt
	}
	err := q.QueryRow(ctx, `
		INSERT INTO ledger_operations (user_id, connection_id, tool, state, idempotency_key,
			window_start, window_end, approval_id, digest, policy_version_id, result_ids,
			created_at, updated_at, resource, token_id)
		VALUES ($1, $2, $3, coalesce(nullif($4, ''), 'in_progress')::ledger_state, $5,
			$6, $7, $8, $9, $10, coalesce($11::jsonb, '{}'::jsonb),
			coalesce($12, now()), coalesce($13, coalesce($12, now())), $14::jsonb, $15)
		RETURNING id, state, result_ids, reconcile_attempts, created_at, updated_at, resource`,
		op.UserID, op.ConnectionID, op.Tool, op.State, op.IdempotencyKey,
		op.WindowStart, op.WindowEnd, op.ApprovalID, op.Digest, op.PolicyVersionID, op.ResultIDs,
		created, updated, resource, op.TokenID,
	).Scan(&op.ID, &op.State, &op.ResultIDs, &op.ReconcileAttempts, &op.CreatedAt, &op.UpdatedAt, &op.Resource)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "ledger_operations_open_key_idx" {
			return ErrLedgerKeyOpen
		}
		return fmt.Errorf("store: create ledger operation: %w", err)
	}
	return nil
}

// GetLedgerOperation reads one operation the scope can see.
func GetLedgerOperation(ctx context.Context, q Querier, id string) (*LedgerOperation, error) {
	op, err := scanLedgerOperation(q.QueryRow(ctx, `SELECT`+ledgerColumns+` FROM ledger_operations WHERE id = $1`, id))
	if err != nil {
		return nil, notFound(err)
	}
	return op, nil
}

// TransitionLedgerOperation moves the operation to t.State when its
// current state is one of from, and reports whether it did. updated_at
// is set to t.At; nil fields in t keep their column values.
func TransitionLedgerOperation(ctx context.Context, q Querier, id string, from []string, t LedgerTransition) (bool, error) {
	if len(from) == 0 {
		return false, errors.New("store: transition ledger operation: from states are required")
	}
	var finished *time.Time
	if t.Finished {
		finished = &t.At
	}
	tag, err := q.Exec(ctx, `
		UPDATE ledger_operations SET
			state = $3::ledger_state,
			updated_at = $4,
			result_ids = coalesce($5::jsonb, result_ids),
			error_code = coalesce($6, error_code),
			reconcile_attempts = coalesce($7, reconcile_attempts),
			finished_at = coalesce($8, finished_at)
		WHERE id = $1 AND state = ANY($2::ledger_state[])`,
		id, from, t.State, t.At, t.ResultIDs, t.ErrorCode, t.ReconcileAttempts, finished)
	if err != nil {
		return false, fmt.Errorf("store: transition ledger operation: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// CreateLedgerAttempt inserts an attempt with the caller's started_at
// (now() when zero).
func CreateLedgerAttempt(ctx context.Context, q Querier, a *LedgerAttempt) error {
	var started *time.Time
	if !a.StartedAt.IsZero() {
		started = &a.StartedAt
	}
	err := q.QueryRow(ctx, `
		INSERT INTO ledger_attempts (operation_id, user_id, attempt_no, kind, outcome, error_code, started_at, finished_at)
		VALUES ($1, $2, $3, $4, $5, $6, coalesce($7, now()), $8)
		RETURNING id, started_at`,
		a.OperationID, a.UserID, a.AttemptNo, a.Kind, a.Outcome, a.ErrorCode, started, a.FinishedAt,
	).Scan(&a.ID, &a.StartedAt)
	if err != nil {
		return fmt.Errorf("store: create ledger attempt: %w", err)
	}
	return nil
}

// ListLedgerOperations returns operations matching f, newest first.
func ListLedgerOperations(ctx context.Context, q Querier, f LedgerFilter) ([]LedgerOperation, error) {
	var where []string
	var args []any
	add := func(clause string, v any) {
		args = append(args, v)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}
	if f.UserID != "" {
		add("user_id = $%d", f.UserID)
	}
	if len(f.States) > 0 {
		add("state = ANY($%d::ledger_state[])", f.States)
	}
	if !f.CreatedBefore.IsZero() {
		add("created_at < $%d", f.CreatedBefore)
	}
	if !f.UpdatedBefore.IsZero() {
		add("updated_at < $%d", f.UpdatedBefore)
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	sql := `SELECT` + ledgerColumns + ` FROM ledger_operations`
	if len(where) > 0 {
		sql += ` WHERE ` + strings.Join(where, " AND ")
	}
	args = append(args, limit)
	sql += fmt.Sprintf(` ORDER BY created_at DESC, id DESC LIMIT $%d`, len(args))
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list ledger operations: %w", err)
	}
	defer rows.Close()
	var out []LedgerOperation
	for rows.Next() {
		op, err := scanLedgerOperation(rows)
		if err != nil {
			return nil, fmt.Errorf("store: list ledger operations: %w", err)
		}
		out = append(out, *op)
	}
	return out, rows.Err()
}

// SweepStaleLedgerOperations marks every in_progress operation created
// before `before` as unknown (updated_at = at) and returns the rows it
// changed, so the caller can count and log them. The stale sweep runs it
// under WithJobs across all users.
func SweepStaleLedgerOperations(ctx context.Context, q Querier, before, at time.Time) ([]LedgerOperation, error) {
	rows, err := q.Query(ctx, `
		UPDATE ledger_operations SET state = 'unknown', updated_at = $2
		WHERE state = 'in_progress' AND created_at < $1
		RETURNING`+ledgerColumns, before, at)
	if err != nil {
		return nil, fmt.Errorf("store: sweep stale ledger operations: %w", err)
	}
	defer rows.Close()
	var out []LedgerOperation
	for rows.Next() {
		op, err := scanLedgerOperation(rows)
		if err != nil {
			return nil, fmt.Errorf("store: sweep stale ledger operations: %w", err)
		}
		out = append(out, *op)
	}
	return out, rows.Err()
}
