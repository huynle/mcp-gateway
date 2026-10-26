-- Harness device authorization grants (RFC 8628) for the MCP OAuth
-- authorization server (docs/harness-setup.md "Signing in from a remote
-- host").
--
-- A harness that cannot open a browser on the user's machine (one running
-- on a remote SSH host) asks POST /oauth/device_authorization for a device
-- code and a user code, shows the user code, and polls POST /oauth/token
-- with grant_type urn:ietf:params:oauth:grant-type:device_code. The user
-- signs in to the portal on any browser, enters the code at /activate (the
-- page machine enrollment uses), checks the client name, scope and the
-- address and User-Agent the request came from, and allows or denies it.
-- The first successful poll after Allow redeems the grant and receives the
-- same tokens the authorization-code grant issues (a new refresh-token
-- family, recorded in family_id so a replayed device code revokes it).
--
--   * device_code_hash / user_code_hash: SHA-256 only, like
--     machine_device_requests (00030). The user code hash is the hash of
--     the normalised eight letters, the same derivation the machine
--     requests use, so a code can be checked against both tables: neither
--     table accepts a user code the other one holds (the inserts check
--     with NOT EXISTS; /activate also refuses a code found in both).
--   * user_id: the user who allowed or denied the grant (NULL while
--     pending); the sign-in user of the issued tokens.
--   * request_ip / user_agent: captured at device_authorization and shown
--     on the approval page (anti-phishing).
--   * interval_seconds / last_polled_at: the polling interval slow_down
--     raises by 5 seconds (RFC 8628 section 3.5).
--
-- Like machine_device_requests: no user is known before approval, so the
-- table is the jobs scope's only (no row security, no gateway_app grant).
-- Rows are pruned once expired (authserver prune job); they cascade with
-- their client (idle-client pruning) and with the deciding user.

-- +goose Up
CREATE TABLE oauth_device_grants (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    device_code_hash bytea       NOT NULL UNIQUE CHECK (length(device_code_hash) = 32),
    user_code_hash   bytea       NOT NULL UNIQUE CHECK (length(user_code_hash) = 32),
    client_id        uuid        NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    scope            text        NOT NULL CHECK (scope <> ''),
    resource         text        NOT NULL CHECK (resource <> ''),
    status           text        NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied', 'redeemed')),
    user_id          uuid        REFERENCES users(id) ON DELETE CASCADE,
    request_ip       text        NOT NULL DEFAULT '' CHECK (length(request_ip) <= 64),
    user_agent       text        NOT NULL DEFAULT '' CHECK (char_length(user_agent) <= 256),
    interval_seconds integer     NOT NULL CHECK (interval_seconds BETWEEN 1 AND 300),
    created_at       timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz NOT NULL,
    last_polled_at   timestamptz,
    decided_at       timestamptz,
    redeemed_at      timestamptz,
    family_id        uuid,
    CHECK ((status = 'pending') = (user_id IS NULL)),
    CHECK (family_id IS NULL OR status = 'redeemed')
);
CREATE INDEX oauth_device_grants_client_status_idx ON oauth_device_grants (client_id, status);
CREATE INDEX oauth_device_grants_expires_at_idx ON oauth_device_grants (expires_at);
GRANT SELECT, INSERT, UPDATE, DELETE ON oauth_device_grants TO gateway_jobs;

-- +goose Down
DROP TABLE IF EXISTS oauth_device_grants;
