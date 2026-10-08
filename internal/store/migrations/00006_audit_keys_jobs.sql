-- Append-only audit, signing keys and background job locks (plan 36bakiw8
-- sections 3, 6 and 7; decisions v6piaxdb, dovthftx).

-- +goose Up

-- Audit events: who, token, tool, account (label), resource identity,
-- decision, policy version, approval, operation, outcome, latency. Never
-- arguments, content or response bodies. There are deliberately no foreign
-- keys: history outlives users, tokens and connections and is kept under
-- their pseudonymous IDs. user_id is NULL for system events.
CREATE TABLE audit_events (
    id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type        text        NOT NULL DEFAULT 'tool_call',
    user_id           uuid,
    actor_user_id     uuid,
    token_id          uuid,
    tool              text,
    connection_id     uuid,
    account_label     account_label,
    resource          jsonb       NOT NULL DEFAULT '{}'::jsonb,
    decision          text        NOT NULL,
    policy_version_id uuid,
    approval_id       uuid,
    operation_id      uuid,
    outcome           text,
    latency_ms        integer,
    details           jsonb       NOT NULL DEFAULT '{}'::jsonb,
    created_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_events_user_created_idx ON audit_events (user_id, created_at DESC);
CREATE INDEX audit_events_created_at_idx ON audit_events (created_at);
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_events_user_scope ON audit_events
    USING (user_id = app_user_id()) WITH CHECK (user_id = app_user_id());
-- gateway_app can only append and read its own; gateway_jobs additionally
-- deletes for retention. The trigger below is the second layer.
GRANT SELECT, INSERT ON audit_events TO gateway_app;
GRANT SELECT, INSERT, DELETE ON audit_events TO gateway_jobs;

-- UPDATE is never allowed, by anyone (superusers included). DELETE is only
-- allowed when the transaction explicitly declares a retention purge via
-- SELECT set_config('app.audit_purge', 'on', true), which only the purge job
-- does (and only gateway_jobs holds the DELETE privilege). The trigger is
-- statement-level so it fires even when no row matches.
-- +goose StatementBegin
CREATE FUNCTION audit_events_append_only() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'DELETE' AND current_setting('app.audit_purge', true) = 'on' THEN
        RETURN NULL;
    END IF;
    RAISE EXCEPTION 'audit_events is append-only: % is not allowed', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END
$$;
-- +goose StatementEnd
CREATE TRIGGER audit_events_append_only
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION audit_events_append_only();

-- Keys that sign the gateway's own OAuth access tokens. The private key is
-- envelope-encrypted; the service needs it, admins only see metadata.
CREATE TABLE signing_keys (
    id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    kid                 text        NOT NULL UNIQUE,
    algorithm           text        NOT NULL,
    public_key          bytea       NOT NULL,
    private_key_id      text        NOT NULL,
    private_wrapped_key bytea       NOT NULL,
    private_nonce       bytea       NOT NULL,
    private_ciphertext  bytea       NOT NULL,
    status              text        NOT NULL DEFAULT 'active'
                                    CHECK (status IN ('active', 'retired')),
    created_at          timestamptz NOT NULL DEFAULT now(),
    retired_at          timestamptz
);
GRANT SELECT, INSERT, UPDATE ON signing_keys TO gateway_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON signing_keys TO gateway_jobs;

-- Leases that make background workers run on exactly one replica.
CREATE TABLE job_locks (
    name        text        PRIMARY KEY,
    holder      text        NOT NULL,
    acquired_at timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL
);
GRANT SELECT ON job_locks TO gateway_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON job_locks TO gateway_jobs;

-- +goose Down
DROP TABLE IF EXISTS job_locks;
DROP TABLE IF EXISTS signing_keys;
DROP TRIGGER IF EXISTS audit_events_append_only ON audit_events;
DROP FUNCTION IF EXISTS audit_events_append_only();
DROP TABLE IF EXISTS audit_events;
