-- MCP OAuth authorization server state (plan 36bakiw8 section 4; decisions
-- 3ycafouv, ysorv868): single-use authorization codes, refresh-token
-- families for rotation and reuse detection, and the audience each refresh
-- token was issued for.

-- +goose Up

-- Authorization codes: issued at consent, consumed exactly once by the
-- token endpoint (UPDATE ... WHERE consumed_at IS NULL), expire after a few
-- minutes. Bound to the user, client, redirect URI, resource and PKCE
-- challenge the authorization request carried. family_id records which
-- refresh-token family the code produced so a replayed code can revoke it
-- (OAuth 2.1 section 4.1.3). Scoped to the consenting user; the token
-- endpoint consumes through the bypass role because no user is known yet.
CREATE TABLE oauth_authorization_codes (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    code_hash      bytea       NOT NULL UNIQUE,
    user_id        uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id      uuid        NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    redirect_uri   text        NOT NULL,
    resource       text        NOT NULL,
    scope          text        NOT NULL DEFAULT '',
    code_challenge text        NOT NULL,
    family_id      uuid,
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,
    consumed_at    timestamptz
);
CREATE INDEX oauth_authorization_codes_expires_at_idx ON oauth_authorization_codes (expires_at);
ALTER TABLE oauth_authorization_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_authorization_codes FORCE ROW LEVEL SECURITY;
CREATE POLICY oauth_authorization_codes_user_scope ON oauth_authorization_codes
    USING (user_id = app_user_id()) WITH CHECK (user_id = app_user_id());
GRANT SELECT, INSERT, UPDATE, DELETE ON oauth_authorization_codes TO gateway_app, gateway_jobs;

-- Refresh tokens: family_id is the id of the first token of a rotation
-- chain (one family = one connected harness); rotated_at marks a token
-- that was exchanged for its successor, so presenting it again is reuse
-- and revokes the family; resource is the audience its access tokens are
-- minted for. Rows written before this migration have no family and are
-- treated as their own.
ALTER TABLE oauth_refresh_tokens
    ADD COLUMN family_id  uuid,
    ADD COLUMN resource   text NOT NULL DEFAULT '',
    ADD COLUMN rotated_at timestamptz;
UPDATE oauth_refresh_tokens SET family_id = id WHERE family_id IS NULL;
ALTER TABLE oauth_refresh_tokens ALTER COLUMN family_id SET NOT NULL;
CREATE INDEX oauth_refresh_tokens_family_id_idx ON oauth_refresh_tokens (family_id);

-- Pruning an idle client deletes its tokens and codes with it.
ALTER TABLE oauth_refresh_tokens DROP CONSTRAINT oauth_refresh_tokens_client_id_fkey;
ALTER TABLE oauth_refresh_tokens
    ADD CONSTRAINT oauth_refresh_tokens_client_id_fkey
    FOREIGN KEY (client_id) REFERENCES oauth_clients(id) ON DELETE CASCADE;

DROP VIEW IF EXISTS admin_oauth_refresh_tokens;
CREATE VIEW admin_oauth_refresh_tokens WITH (security_invoker = true) AS
    SELECT id, user_id, client_id, family_id, resource, scope, issued_at, expires_at,
           rotated_from, rotated_at, revoked_at, last_used_at
    FROM oauth_refresh_tokens;
GRANT SELECT ON admin_oauth_refresh_tokens TO gateway_app, gateway_jobs;

-- +goose Down
DROP VIEW IF EXISTS admin_oauth_refresh_tokens;
CREATE VIEW admin_oauth_refresh_tokens WITH (security_invoker = true) AS
    SELECT id, user_id, client_id, scope, issued_at, expires_at, rotated_from, revoked_at, last_used_at
    FROM oauth_refresh_tokens;
GRANT SELECT ON admin_oauth_refresh_tokens TO gateway_app, gateway_jobs;
ALTER TABLE oauth_refresh_tokens DROP CONSTRAINT oauth_refresh_tokens_client_id_fkey;
ALTER TABLE oauth_refresh_tokens
    ADD CONSTRAINT oauth_refresh_tokens_client_id_fkey
    FOREIGN KEY (client_id) REFERENCES oauth_clients(id);
DROP INDEX IF EXISTS oauth_refresh_tokens_family_id_idx;
ALTER TABLE oauth_refresh_tokens DROP COLUMN rotated_at, DROP COLUMN resource, DROP COLUMN family_id;
DROP TABLE IF EXISTS oauth_authorization_codes;
