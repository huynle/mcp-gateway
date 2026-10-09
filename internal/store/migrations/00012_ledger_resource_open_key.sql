-- Write ledger (decision dovthftx): the reconciler must re-derive a write's
-- stable id / marker after an unknown outcome without the arguments (they
-- are never stored), so the operation keeps the connector's resource
-- identity (keys and short values, as approvals and audit_events do) plus
-- the token the call came through (no foreign key, like audit_events).
-- A unique partial index guarantees at most one open (in_progress or
-- unknown) operation per idempotency key, so two concurrent Begins for the
-- same key can never both insert; succeeded, failed and unresolved rows are
-- outside the index because the window check (and the lifted block after
-- unresolved) is decided by the service, not the schema.

-- +goose Up
ALTER TABLE ledger_operations ADD COLUMN resource jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE ledger_operations ADD COLUMN token_id uuid;
CREATE UNIQUE INDEX ledger_operations_open_key_idx ON ledger_operations (idempotency_key)
    WHERE state IN ('in_progress', 'unknown');

-- +goose Down
DROP INDEX IF EXISTS ledger_operations_open_key_idx;
ALTER TABLE ledger_operations DROP COLUMN IF EXISTS token_id;
ALTER TABLE ledger_operations DROP COLUMN IF EXISTS resource;
