-- Vendor app registrations and per-user app connections (plan 36bakiw8
-- section 5; decision mh7c6z3v).
--
-- Encrypted values are stored as four columns produced by the crypto package's
-- envelope encryption: <prefix>_key_id (which master key wrapped the data
-- key), <prefix>_wrapped_key, <prefix>_nonce and <prefix>_ciphertext. The AEAD
-- associated data binds user, connection and app and is recomputed on
-- decrypt, so it is not stored.

-- +goose Up
CREATE TYPE account_label AS ENUM ('company', 'personal');

-- One admin-configured registered app per vendor and kind, e.g.
-- (google, internal) for company accounts and (google, external) for
-- personal ones. Global; the service needs the client secret for OAuth.
CREATE TABLE vendor_apps (
    id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    vendor              text        NOT NULL
                                    CHECK (vendor IN ('github', 'slack', 'atlassian', 'google', 'microsoft', 'fake')),
    name                text        NOT NULL,
    client_id           text        NOT NULL,
    secret_key_id       text        NOT NULL,
    secret_wrapped_key  bytea       NOT NULL,
    secret_nonce        bytea       NOT NULL,
    secret_ciphertext   bytea       NOT NULL,
    config              jsonb       NOT NULL DEFAULT '{}'::jsonb,
    enabled             boolean     NOT NULL DEFAULT true,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (vendor, name)
);
GRANT SELECT, INSERT, UPDATE, DELETE ON vendor_apps TO gateway_app, gateway_jobs;

-- A connection binds a user to one permanent external account of one vendor
-- app. (id, user_id) is unique so child tables can reference both and RLS on
-- them never disagrees with the parent.
CREATE TABLE connections (
    id                  uuid          PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             uuid          NOT NULL REFERENCES users(id),
    vendor_app_id       uuid          NOT NULL REFERENCES vendor_apps(id),
    external_account_id text          NOT NULL,
    label               account_label NOT NULL,
    display_name        text          NOT NULL DEFAULT '',
    scopes              text[]        NOT NULL DEFAULT '{}',
    status              text          NOT NULL DEFAULT 'active'
                                      CHECK (status IN ('active', 'needs_reconnect', 'revoked')),
    last_refreshed_at   timestamptz,
    created_at          timestamptz   NOT NULL DEFAULT now(),
    updated_at          timestamptz   NOT NULL DEFAULT now(),
    UNIQUE (user_id, vendor_app_id, external_account_id),
    UNIQUE (id, user_id)
);
CREATE INDEX connections_user_id_idx ON connections (user_id);
ALTER TABLE connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE connections FORCE ROW LEVEL SECURITY;
CREATE POLICY connections_user_scope ON connections
    USING (user_id = app_user_id()) WITH CHECK (user_id = app_user_id());
GRANT SELECT, INSERT, UPDATE, DELETE ON connections TO gateway_app, gateway_jobs;

-- The vendor access/refresh token bundle, envelope-encrypted. Deleted (not
-- kept) when the connection is removed or the user is deleted.
CREATE TABLE connection_secrets (
    connection_id       uuid        PRIMARY KEY,
    user_id             uuid        NOT NULL REFERENCES users(id),
    secret_key_id       text        NOT NULL,
    secret_wrapped_key  bytea       NOT NULL,
    secret_nonce        bytea       NOT NULL,
    secret_ciphertext   bytea       NOT NULL,
    token_expires_at    timestamptz,
    updated_at          timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (connection_id, user_id) REFERENCES connections(id, user_id) ON DELETE CASCADE
);
ALTER TABLE connection_secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE connection_secrets FORCE ROW LEVEL SECURITY;
CREATE POLICY connection_secrets_user_scope ON connection_secrets
    USING (user_id = app_user_id()) WITH CHECK (user_id = app_user_id());
GRANT SELECT, INSERT, UPDATE, DELETE ON connection_secrets TO gateway_app, gateway_jobs;

-- +goose Down
DROP TABLE IF EXISTS connection_secrets;
DROP TABLE IF EXISTS connections;
DROP TABLE IF EXISTS vendor_apps;
DROP TYPE IF EXISTS account_label;
