-- Generated tokens and the MCP OAuth authorization server's state (plan
-- 36bakiw8 section 4; decisions uamxx6ba, ysorv868).

-- +goose Up

-- mgw_<id>_<secret>: the id is this row's uuid, the secret is stored as its
-- SHA-256 hash only. scope is NULL for "everything the user may do" or a
-- JSON document listing apps/tools; read_only narrows further.
CREATE TABLE tokens (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      uuid        NOT NULL REFERENCES users(id),
    name         text        NOT NULL,
    token_hash   bytea       NOT NULL UNIQUE,
    read_only    boolean     NOT NULL DEFAULT false,
    scope        jsonb,
    expires_at   timestamptz NOT NULL,
    revoked_at   timestamptz,
    last_used_at timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX tokens_user_id_idx ON tokens (user_id);
ALTER TABLE tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY tokens_user_scope ON tokens
    USING (user_id = app_user_id()) WITH CHECK (user_id = app_user_id());
GRANT SELECT, INSERT, UPDATE, DELETE ON tokens TO gateway_app, gateway_jobs;

-- Dynamically registered MCP clients (harnesses). Global: registration
-- happens before any user is known. Public clients have no secret.
CREATE TABLE oauth_clients (
    id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id          text        NOT NULL UNIQUE,
    client_secret_hash bytea,
    client_name        text        NOT NULL DEFAULT '',
    redirect_uris      text[]      NOT NULL DEFAULT '{}',
    metadata           jsonb       NOT NULL DEFAULT '{}'::jsonb,
    created_at         timestamptz NOT NULL DEFAULT now(),
    last_used_at       timestamptz
);
GRANT SELECT, INSERT, UPDATE, DELETE ON oauth_clients TO gateway_app, gateway_jobs;

-- Rotating refresh tokens (30 days); rotated_from links the chain so reuse of
-- a rotated token can revoke the family.
CREATE TABLE oauth_refresh_tokens (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      uuid        NOT NULL REFERENCES users(id),
    client_id    uuid        NOT NULL REFERENCES oauth_clients(id),
    token_hash   bytea       NOT NULL UNIQUE,
    scope        jsonb       NOT NULL DEFAULT '{}'::jsonb,
    issued_at    timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    rotated_from uuid        REFERENCES oauth_refresh_tokens(id),
    revoked_at   timestamptz,
    last_used_at timestamptz
);
CREATE INDEX oauth_refresh_tokens_user_id_idx ON oauth_refresh_tokens (user_id);
CREATE INDEX oauth_refresh_tokens_client_id_idx ON oauth_refresh_tokens (client_id);
ALTER TABLE oauth_refresh_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_refresh_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY oauth_refresh_tokens_user_scope ON oauth_refresh_tokens
    USING (user_id = app_user_id()) WITH CHECK (user_id = app_user_id());
GRANT SELECT, INSERT, UPDATE, DELETE ON oauth_refresh_tokens TO gateway_app, gateway_jobs;

-- +goose Down
DROP TABLE IF EXISTS oauth_refresh_tokens;
DROP TABLE IF EXISTS oauth_clients;
DROP TABLE IF EXISTS tokens;
