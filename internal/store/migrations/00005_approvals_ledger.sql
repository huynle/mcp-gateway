-- Approvals and the write ledger (plan 36bakiw8 section 3; decisions
-- s0p05diu, dovthftx).

-- +goose Up
CREATE TYPE approval_status AS ENUM ('pending', 'approved', 'denied', 'consumed', 'expired');
CREATE TYPE ledger_state AS ENUM ('in_progress', 'succeeded', 'failed', 'unknown', 'unresolved');

-- A pending approval stores the full canonical argument payload, encrypted
-- (the one carve-out to "no app content stored"). The payload columns are
-- set to NULL when the approval is consumed, denied or expires; the row and
-- its metadata stay for audit. An approval is bound to user + account + tool
-- + policy version and is single-use (consumed_at).
CREATE TABLE approvals (
    id                  uuid            PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             uuid            NOT NULL REFERENCES users(id),
    connection_id       uuid            NOT NULL,
    tool                text            NOT NULL,
    digest              bytea           NOT NULL,
    payload_key_id      text,
    payload_wrapped_key bytea,
    payload_nonce       bytea,
    payload_ciphertext  bytea,
    status              approval_status NOT NULL DEFAULT 'pending',
    policy_version_id   uuid            NOT NULL REFERENCES policy_versions(id),
    created_at          timestamptz     NOT NULL DEFAULT now(),
    expires_at          timestamptz     NOT NULL,
    decided_at          timestamptz,
    consumed_at         timestamptz,
    FOREIGN KEY (connection_id, user_id) REFERENCES connections(id, user_id),
    CHECK (
        (payload_key_id IS NULL AND payload_wrapped_key IS NULL AND payload_nonce IS NULL AND payload_ciphertext IS NULL)
        OR
        (payload_key_id IS NOT NULL AND payload_wrapped_key IS NOT NULL AND payload_nonce IS NOT NULL AND payload_ciphertext IS NOT NULL)
    ),
    CHECK (status = 'pending' OR payload_ciphertext IS NULL)
);
CREATE INDEX approvals_user_status_expires_idx ON approvals (user_id, status, expires_at);
CREATE INDEX approvals_expires_at_idx ON approvals (expires_at) WHERE status = 'pending';
ALTER TABLE approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE approvals FORCE ROW LEVEL SECURITY;
CREATE POLICY approvals_user_scope ON approvals
    USING (user_id = app_user_id()) WITH CHECK (user_id = app_user_id());
GRANT SELECT, INSERT, UPDATE, DELETE ON approvals TO gateway_app, gateway_jobs;

-- One row per write, inserted as in_progress before the app call. The
-- idempotency key is the approval id when one was consumed, otherwise
-- user+account+tool+digest; [window_start, window_end) is the period during
-- which the same key refers to this operation. result_ids keeps IDs only,
-- never content.
CREATE TABLE ledger_operations (
    id                 uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id            uuid         NOT NULL REFERENCES users(id),
    connection_id      uuid         NOT NULL,
    tool               text         NOT NULL,
    state              ledger_state NOT NULL DEFAULT 'in_progress',
    idempotency_key    text         NOT NULL,
    window_start       timestamptz  NOT NULL DEFAULT now(),
    window_end         timestamptz  NOT NULL,
    approval_id        uuid         REFERENCES approvals(id),
    digest             bytea,
    policy_version_id  uuid         NOT NULL REFERENCES policy_versions(id),
    result_ids         jsonb        NOT NULL DEFAULT '{}'::jsonb,
    error_code         text,
    reconcile_attempts integer      NOT NULL DEFAULT 0,
    created_at         timestamptz  NOT NULL DEFAULT now(),
    updated_at         timestamptz  NOT NULL DEFAULT now(),
    finished_at        timestamptz,
    FOREIGN KEY (connection_id, user_id) REFERENCES connections(id, user_id),
    UNIQUE (id, user_id),
    CHECK (window_end >= window_start)
);
CREATE INDEX ledger_operations_idempotency_idx ON ledger_operations (idempotency_key, created_at DESC);
CREATE INDEX ledger_operations_user_state_idx ON ledger_operations (user_id, state, created_at DESC);
CREATE INDEX ledger_operations_state_updated_idx ON ledger_operations (state, updated_at)
    WHERE state IN ('in_progress', 'unknown');
ALTER TABLE ledger_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger_operations FORCE ROW LEVEL SECURITY;
CREATE POLICY ledger_operations_user_scope ON ledger_operations
    USING (user_id = app_user_id()) WITH CHECK (user_id = app_user_id());
GRANT SELECT, INSERT, UPDATE ON ledger_operations TO gateway_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ledger_operations TO gateway_jobs;

-- Each app call or reconciler check against an operation.
CREATE TABLE ledger_attempts (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    operation_id uuid        NOT NULL,
    user_id      uuid        NOT NULL REFERENCES users(id),
    attempt_no   integer     NOT NULL,
    kind         text        NOT NULL CHECK (kind IN ('call', 'reconcile')),
    outcome      text        NOT NULL,
    error_code   text,
    started_at   timestamptz NOT NULL DEFAULT now(),
    finished_at  timestamptz,
    FOREIGN KEY (operation_id, user_id) REFERENCES ledger_operations(id, user_id),
    UNIQUE (operation_id, kind, attempt_no)
);
ALTER TABLE ledger_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger_attempts FORCE ROW LEVEL SECURITY;
CREATE POLICY ledger_attempts_user_scope ON ledger_attempts
    USING (user_id = app_user_id()) WITH CHECK (user_id = app_user_id());
GRANT SELECT, INSERT, UPDATE ON ledger_attempts TO gateway_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ledger_attempts TO gateway_jobs;

-- +goose Down
DROP TABLE IF EXISTS ledger_attempts;
DROP TABLE IF EXISTS ledger_operations;
DROP TABLE IF EXISTS approvals;
DROP TYPE IF EXISTS ledger_state;
DROP TYPE IF EXISTS approval_status;
