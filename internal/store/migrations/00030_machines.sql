-- Enrolled machines (Brain decision ldjix4y1, docs/machines.md).
--
-- A user enrolls a machine once (`mcp-gateway login`): the CLI generates an
-- Ed25519 key pair and either runs a device authorization flow (the user
-- approves the request at /activate after checking name and fingerprint)
-- or presents a one-time enrollment code created in the portal. From then
-- on the machine signs short-lived JWT assertions with its private key
-- (which never leaves the machine) and trades them for 10-minute machine
-- access tokens (mgm_...). A machine token can only manage and serve the
-- tunnels and servers of that machine; one WebSocket per machine carries
-- every tunnel linked to it.
--
--   machines                   owner's rows (row security); public key and
--                              its RFC 7638 thumbprint, never a secret
--   machine_device_requests    pending device authorizations: device and
--                              user codes stored as SHA-256 only; jobs only
--   machine_enrollment_codes   one-time codes (SHA-256 only), owner's rows
--   machine_access_tokens      SHA-256 of live mgm_ tokens; jobs only
--   machine_assertion_jtis     assertion ids seen until they expire
--                              (replay check); jobs only
--   mcp_tunnels                machine_id + server_name link a tunnel to a
--                              machine; such tunnels have no token hash (the
--                              legacy /tunnel/connect never matches them) and
--                              share the machine's owner (composite key)
--   resource caps              new "machines" cap per user
--
-- The token endpoint, enrollment and the machine connection run before any
-- user is known, so they use gateway_jobs; the portal lists a user's own
-- machines and manages their enrollment codes as that user.

-- +goose Up
CREATE TABLE machines (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_user_id  uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name           text        NOT NULL CHECK (name ~ '^[a-z0-9][a-z0-9_-]{0,62}$'),
    public_key     bytea       NOT NULL CHECK (length(public_key) = 32),
    fingerprint    text        NOT NULL CHECK (fingerprint <> '' AND length(fingerprint) <= 64),
    client_version text        NOT NULL DEFAULT '' CHECK (length(client_version) <= 64),
    enrolled_via   text        NOT NULL CHECK (enrolled_via IN ('device', 'enrollment_code')),
    enrolled_ip    text        NOT NULL DEFAULT '' CHECK (length(enrolled_ip) <= 64),
    created_at     timestamptz NOT NULL DEFAULT now(),
    last_seen_at   timestamptz,
    last_ip        text        NOT NULL DEFAULT '' CHECK (length(last_ip) <= 64),
    revoked_at     timestamptz,
    revoked_by     uuid        REFERENCES users(id) ON DELETE SET NULL,
    revoke_reason  text        CHECK (revoke_reason IN ('owner', 'admin', 'self', 'replaced', 'deleted')),
    UNIQUE (id, owner_user_id)
);
CREATE UNIQUE INDEX machines_owner_live_name ON machines (owner_user_id, name) WHERE revoked_at IS NULL;
ALTER TABLE machines ENABLE ROW LEVEL SECURITY;
ALTER TABLE machines FORCE ROW LEVEL SECURITY;
CREATE POLICY machines_owner ON machines
    USING (owner_user_id = app_user_id()) WITH CHECK (owner_user_id = app_user_id());
GRANT SELECT ON machines TO gateway_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON machines TO gateway_jobs;

CREATE TABLE machine_device_requests (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    device_code_hash bytea       NOT NULL UNIQUE,
    user_code_hash   bytea       NOT NULL UNIQUE,
    name             text        NOT NULL CHECK (name ~ '^[a-z0-9][a-z0-9_-]{0,62}$'),
    public_key       bytea       NOT NULL CHECK (length(public_key) = 32),
    fingerprint      text        NOT NULL CHECK (fingerprint <> '' AND length(fingerprint) <= 64),
    client_version   text        NOT NULL DEFAULT '' CHECK (length(client_version) <= 64),
    request_ip       text        NOT NULL DEFAULT '' CHECK (length(request_ip) <= 64),
    created_at       timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz NOT NULL,
    interval_seconds integer     NOT NULL CHECK (interval_seconds BETWEEN 1 AND 300),
    last_polled_at   timestamptz,
    status           text        NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied', 'consumed')),
    decided_by       uuid        REFERENCES users(id) ON DELETE CASCADE,
    decided_at       timestamptz,
    machine_id       uuid        REFERENCES machines(id) ON DELETE CASCADE
);
CREATE INDEX machine_device_requests_expires_at_idx ON machine_device_requests (expires_at);
GRANT SELECT, INSERT, UPDATE, DELETE ON machine_device_requests TO gateway_jobs;

CREATE TABLE machine_enrollment_codes (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_user_id uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash     bytea       NOT NULL UNIQUE,
    label         text        NOT NULL DEFAULT '' CHECK (length(label) <= 100),
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,
    used_at       timestamptz,
    machine_id    uuid        REFERENCES machines(id) ON DELETE SET NULL,
    revoked_at    timestamptz
);
CREATE INDEX machine_enrollment_codes_owner_idx ON machine_enrollment_codes (owner_user_id);
ALTER TABLE machine_enrollment_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE machine_enrollment_codes FORCE ROW LEVEL SECURITY;
CREATE POLICY machine_enrollment_codes_owner ON machine_enrollment_codes
    USING (owner_user_id = app_user_id()) WITH CHECK (owner_user_id = app_user_id());
GRANT SELECT, INSERT, UPDATE ON machine_enrollment_codes TO gateway_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON machine_enrollment_codes TO gateway_jobs;

CREATE TABLE machine_access_tokens (
    token_hash bytea       PRIMARY KEY,
    machine_id uuid        NOT NULL REFERENCES machines(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);
CREATE INDEX machine_access_tokens_machine_idx ON machine_access_tokens (machine_id);
CREATE INDEX machine_access_tokens_expires_at_idx ON machine_access_tokens (expires_at);
GRANT SELECT, INSERT, UPDATE, DELETE ON machine_access_tokens TO gateway_jobs;

CREATE TABLE machine_assertion_jtis (
    machine_id uuid        NOT NULL REFERENCES machines(id) ON DELETE CASCADE,
    jti        text        NOT NULL CHECK (jti <> '' AND length(jti) <= 128),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (machine_id, jti)
);
CREATE INDEX machine_assertion_jtis_expires_at_idx ON machine_assertion_jtis (expires_at);
GRANT SELECT, INSERT, UPDATE, DELETE ON machine_assertion_jtis TO gateway_jobs;

ALTER TABLE mcp_tunnels ALTER COLUMN token_hash DROP NOT NULL;
ALTER TABLE mcp_tunnels ADD COLUMN machine_id uuid;
ALTER TABLE mcp_tunnels ADD COLUMN server_name text;
ALTER TABLE mcp_tunnels ADD CONSTRAINT mcp_tunnels_machine_fkey FOREIGN KEY (machine_id, owner_user_id)
    REFERENCES machines (id, owner_user_id) ON DELETE CASCADE;
ALTER TABLE mcp_tunnels ADD CONSTRAINT mcp_tunnels_credential CHECK (
    (machine_id IS NULL) = (token_hash IS NOT NULL) AND (machine_id IS NULL) = (server_name IS NULL));
CREATE UNIQUE INDEX mcp_tunnels_machine_server ON mcp_tunnels (machine_id, server_name)
    WHERE revoked_at IS NULL AND machine_id IS NOT NULL;

-- Columns appended, so the view is replaced in place (grants kept).
CREATE OR REPLACE VIEW admin_mcp_tunnels WITH (security_invoker = true) AS
    SELECT id, owner_user_id, name, created_at, last_seen_at, revoked_at, machine_id, server_name
    FROM mcp_tunnels;

ALTER TABLE gateway_resource_caps ADD COLUMN machines integer CHECK (machines BETWEEN 0 AND 100000);
ALTER TABLE gateway_user_resource_caps ADD COLUMN machines integer CHECK (machines BETWEEN 0 AND 100000);

-- +goose Down
ALTER TABLE gateway_user_resource_caps DROP COLUMN IF EXISTS machines;
ALTER TABLE gateway_resource_caps DROP COLUMN IF EXISTS machines;
DROP VIEW admin_mcp_tunnels;
CREATE VIEW admin_mcp_tunnels WITH (security_invoker = true) AS
    SELECT id, owner_user_id, name, created_at, last_seen_at, revoked_at
    FROM mcp_tunnels;
GRANT SELECT ON admin_mcp_tunnels TO gateway_app, gateway_jobs;
-- Machine-linked tunnels have no token: they cannot survive the rollback.
DELETE FROM mcp_tunnels WHERE machine_id IS NOT NULL;
DROP INDEX IF EXISTS mcp_tunnels_machine_server;
ALTER TABLE mcp_tunnels DROP CONSTRAINT IF EXISTS mcp_tunnels_credential;
ALTER TABLE mcp_tunnels DROP CONSTRAINT IF EXISTS mcp_tunnels_machine_fkey;
ALTER TABLE mcp_tunnels DROP COLUMN IF EXISTS server_name;
ALTER TABLE mcp_tunnels DROP COLUMN IF EXISTS machine_id;
ALTER TABLE mcp_tunnels ALTER COLUMN token_hash SET NOT NULL;
DROP TABLE IF EXISTS machine_assertion_jtis;
DROP TABLE IF EXISTS machine_access_tokens;
DROP TABLE IF EXISTS machine_enrollment_codes;
DROP TABLE IF EXISTS machine_device_requests;
DROP TABLE IF EXISTS machines;
