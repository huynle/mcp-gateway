-- Ephemeral secrets (docs/plans/2026-10-23-ephemeral-secrets-design.md).
--
-- An agent harness asks the user for a secret (secrets.request); the user
-- enters it on a one-time gateway page (/s/<request id>); the agent then
-- uses it through a handle (sec_...) that the gateway swaps for the value
-- right before dispatch, only for the target the secret is bound to
-- (server id + tool + argument; arg is NULL for a machine action). One row
-- carries the whole lifecycle:
--
--   pending   requested, not entered yet; the link is valid until
--             link_expires_at (10 minutes)
--   provided  entered: value envelope-encrypted with AAD
--             {owner, "secret", id, server id}; usable while uses_left > 0
--             and expires_at (provided_at + ttl) has not passed
--   denied    the user pressed Deny on the entry page
--   revoked   the user (or a disable / deletion) revoked it
--   expired   the link, the TTL or the uses ran out; the expiry job moves
--             rows here and wipes the ciphertext
--
-- Only SHA-256 hashes of the request id and the handle are stored, never
-- the raw values. The value columns are set only while the row is provided
-- (all-or-none). Ended rows are deleted by the expiry job some days after
-- ended_at. Owner's rows under row security; the expiry job and the
-- disable hook use gateway_jobs.

-- +goose Up
CREATE TABLE secrets (
    id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_user_id     uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    harness_id        text        NOT NULL CHECK (harness_id <> '' AND length(harness_id) <= 200),
    label             text        NOT NULL CHECK (label <> '' AND length(label) <= 100),
    server_id         uuid        NOT NULL REFERENCES mcp_servers(id) ON DELETE CASCADE,
    tool              text        NOT NULL CHECK (tool <> '' AND length(tool) <= 200),
    arg               text        CHECK (arg IS NULL OR (arg <> '' AND length(arg) <= 200)),
    uses_total        integer     NOT NULL CHECK (uses_total BETWEEN 1 AND 100),
    uses_left         integer     NOT NULL CHECK (uses_left BETWEEN 0 AND uses_total),
    ttl_seconds       integer     NOT NULL CHECK (ttl_seconds BETWEEN 1 AND 86400),
    link_expires_at   timestamptz NOT NULL,
    expires_at        timestamptz,
    request_hash      bytea       NOT NULL UNIQUE CHECK (length(request_hash) = 32),
    handle_hash       bytea       NOT NULL UNIQUE CHECK (length(handle_hash) = 32),
    state             text        NOT NULL DEFAULT 'pending'
                                  CHECK (state IN ('pending', 'provided', 'denied', 'revoked', 'expired')),
    value_key_id      text,
    value_wrapped_key bytea,
    value_nonce       bytea,
    value_ciphertext  bytea,
    provided_at       timestamptz,
    ended_at          timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    CHECK (
        (value_key_id IS NULL AND value_wrapped_key IS NULL AND value_nonce IS NULL AND value_ciphertext IS NULL)
        OR
        (value_key_id IS NOT NULL AND value_wrapped_key IS NOT NULL AND value_nonce IS NOT NULL AND value_ciphertext IS NOT NULL)
    ),
    -- A provided row always holds its value and expiry; no other state does.
    CHECK ((state = 'provided') = (value_ciphertext IS NOT NULL)),
    CHECK (state <> 'provided' OR (expires_at IS NOT NULL AND provided_at IS NOT NULL)),
    CHECK (state IN ('pending', 'provided') OR ended_at IS NOT NULL)
);
CREATE INDEX secrets_owner_idx ON secrets (owner_user_id, created_at);
CREATE INDEX secrets_expires_at_idx ON secrets (expires_at) WHERE state = 'provided';
CREATE INDEX secrets_link_expires_at_idx ON secrets (link_expires_at) WHERE state = 'pending';
CREATE INDEX secrets_ended_at_idx ON secrets (ended_at) WHERE ended_at IS NOT NULL;
CREATE INDEX secrets_server_idx ON secrets (server_id);
ALTER TABLE secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE secrets FORCE ROW LEVEL SECURITY;
CREATE POLICY secrets_owner ON secrets
    USING (owner_user_id = app_user_id()) WITH CHECK (owner_user_id = app_user_id());
GRANT SELECT, INSERT, UPDATE ON secrets TO gateway_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON secrets TO gateway_jobs;

-- +goose Down
DROP TABLE IF EXISTS secrets;
