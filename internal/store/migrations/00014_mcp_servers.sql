-- User-added MCP servers ("plugins"; Brain plan 0omkv2e1, decision
-- yhd5kcaz, schema decisions recorded for task ug43g1i0).
--
-- Isolation model, on top of the conventions of 00002/00004:
--   * a server is visible to its owner, and to users holding a role it is
--     published to while its audience is 'published';
--   * gateway_app may create, change and delete only its own servers;
--     publishing (audience, mcp_server_roles) is an admin action through the
--     bypass role, enforced with column / table privileges;
--   * credentials (shared secret, OAuth client) are owner-only rows; a user
--     of a published server never reads them, the federation connector does
--     through the bypass role;
--   * per-user connections and tunnels are their user's rows only;
--   * snapshots are visible like their server; the owner writes them only
--     while the server is private (once published, review is an admin
--     action), and may only add pending ones to a published server.
-- Child tables that need an owner check carry owner_user_id through a
-- composite foreign key on (server_id, owner_user_id), as connection_secrets
-- does with (connection_id, user_id), so their policies never read
-- mcp_servers and cannot recurse into its policy.

-- +goose Up
CREATE TABLE mcp_servers (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    name             text        NOT NULL UNIQUE
                                 CHECK (name ~ '^[a-z0-9_-]{1,63}$'),
    url              text        NOT NULL CHECK (url <> ''),
    transport        text        NOT NULL DEFAULT 'auto'
                                 CHECK (transport IN ('auto', 'streamable_http', 'sse')),
    owner_user_id    uuid        NOT NULL REFERENCES users(id),
    audience         text        NOT NULL DEFAULT 'private'
                                 CHECK (audience IN ('private', 'published')),
    credential_mode  text        NOT NULL DEFAULT 'per_user'
                                 CHECK (credential_mode IN ('per_user', 'shared')),
    auth_kind        text        NOT NULL DEFAULT 'auto'
                                 CHECK (auth_kind IN ('oauth', 'api_key', 'bearer', 'headers', 'none', 'auto')),
    auth_config      jsonb       NOT NULL DEFAULT '{}'::jsonb,
    header_config    jsonb       NOT NULL DEFAULT '{}'::jsonb,
    status           text        NOT NULL DEFAULT 'active'
                                 CHECK (status IN ('active', 'disabled', 'error')),
    last_error_class text,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (id, owner_user_id)
);
CREATE INDEX mcp_servers_owner_user_id_idx ON mcp_servers (owner_user_id);

-- Publishing: one row per role a server is published to.
CREATE TABLE mcp_server_roles (
    server_id     uuid        NOT NULL,
    owner_user_id uuid        NOT NULL,
    role_id       uuid        NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (server_id, role_id),
    FOREIGN KEY (server_id, owner_user_id) REFERENCES mcp_servers(id, owner_user_id)
        ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE INDEX mcp_server_roles_role_id_idx ON mcp_server_roles (role_id);

ALTER TABLE mcp_servers ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_servers FORCE ROW LEVEL SECURITY;
CREATE POLICY mcp_servers_visible ON mcp_servers FOR SELECT
    USING (owner_user_id = app_user_id()
        OR (audience = 'published' AND EXISTS (
            SELECT 1 FROM mcp_server_roles sr
            JOIN role_assignments ra ON ra.role_id = sr.role_id
            WHERE sr.server_id = mcp_servers.id AND ra.user_id = app_user_id())));
CREATE POLICY mcp_servers_owner_insert ON mcp_servers FOR INSERT
    WITH CHECK (owner_user_id = app_user_id());
CREATE POLICY mcp_servers_owner_update ON mcp_servers FOR UPDATE
    USING (owner_user_id = app_user_id()) WITH CHECK (owner_user_id = app_user_id());
CREATE POLICY mcp_servers_owner_delete ON mcp_servers FOR DELETE
    USING (owner_user_id = app_user_id());
-- No audience / owner_user_id writes through gateway_app: servers start
-- private and only an admin publishes or transfers them.
GRANT SELECT, DELETE ON mcp_servers TO gateway_app;
GRANT INSERT (id, name, url, transport, owner_user_id, credential_mode, auth_kind,
              auth_config, header_config, status, last_error_class)
    ON mcp_servers TO gateway_app;
GRANT UPDATE (name, url, transport, credential_mode, auth_kind, auth_config, header_config,
              status, last_error_class, updated_at)
    ON mcp_servers TO gateway_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON mcp_servers TO gateway_jobs;

ALTER TABLE mcp_server_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_server_roles FORCE ROW LEVEL SECURITY;
CREATE POLICY mcp_server_roles_visible ON mcp_server_roles FOR SELECT
    USING (owner_user_id = app_user_id()
        OR EXISTS (SELECT 1 FROM role_assignments ra
                   WHERE ra.role_id = mcp_server_roles.role_id AND ra.user_id = app_user_id()));
GRANT SELECT ON mcp_server_roles TO gateway_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON mcp_server_roles TO gateway_jobs;

-- Shared credential (credential_mode 'shared'): one envelope-encrypted
-- bundle per server; secret_keys names what it holds (header names, query
-- parameter) without revealing values.
CREATE TABLE mcp_server_shared_secrets (
    server_id          uuid        PRIMARY KEY,
    owner_user_id      uuid        NOT NULL,
    secret_key_id      text        NOT NULL,
    secret_wrapped_key bytea       NOT NULL,
    secret_nonce       bytea       NOT NULL,
    secret_ciphertext  bytea       NOT NULL,
    secret_keys        text[]      NOT NULL DEFAULT '{}',
    updated_at         timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (server_id, owner_user_id) REFERENCES mcp_servers(id, owner_user_id)
        ON DELETE CASCADE ON UPDATE CASCADE
);
ALTER TABLE mcp_server_shared_secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_server_shared_secrets FORCE ROW LEVEL SECURITY;
CREATE POLICY mcp_server_shared_secrets_owner ON mcp_server_shared_secrets
    USING (owner_user_id = app_user_id()) WITH CHECK (owner_user_id = app_user_id());
GRANT SELECT, INSERT, UPDATE, DELETE ON mcp_server_shared_secrets TO gateway_app, gateway_jobs;

-- Per-user connection: the user's token bundle or API key for one server.
-- A user can only create or update a connection to a server they can see.
CREATE TABLE mcp_server_user_connections (
    id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id          uuid        NOT NULL REFERENCES mcp_servers(id) ON DELETE CASCADE,
    user_id            uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status             text        NOT NULL DEFAULT 'active'
                                   CHECK (status IN ('active', 'needs_reconnect', 'revoked')),
    scopes             text[]      NOT NULL DEFAULT '{}',
    secret_key_id      text        NOT NULL,
    secret_wrapped_key bytea       NOT NULL,
    secret_nonce       bytea       NOT NULL,
    secret_ciphertext  bytea       NOT NULL,
    expires_at         timestamptz,
    last_refreshed_at  timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (server_id, user_id)
);
CREATE INDEX mcp_server_user_connections_user_id_idx ON mcp_server_user_connections (user_id);
ALTER TABLE mcp_server_user_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_server_user_connections FORCE ROW LEVEL SECURITY;
CREATE POLICY mcp_server_user_connections_user_scope ON mcp_server_user_connections
    USING (user_id = app_user_id())
    WITH CHECK (user_id = app_user_id()
        AND EXISTS (SELECT 1 FROM mcp_servers s WHERE s.id = mcp_server_user_connections.server_id));
GRANT SELECT, INSERT, UPDATE, DELETE ON mcp_server_user_connections TO gateway_app, gateway_jobs;

-- The gateway's OAuth client at the upstream authorization server: by
-- dynamic registration, a client ID metadata document, or static.
CREATE TABLE mcp_server_oauth_clients (
    server_id          uuid        PRIMARY KEY,
    owner_user_id      uuid        NOT NULL,
    method             text        NOT NULL CHECK (method IN ('dcr', 'cimd', 'static')),
    client_id          text        NOT NULL,
    secret_key_id      text,
    secret_wrapped_key bytea,
    secret_nonce       bytea,
    secret_ciphertext  bytea,
    issuer             text        NOT NULL DEFAULT '',
    registered_at      timestamptz NOT NULL DEFAULT now(),
    CHECK ((secret_key_id IS NULL) = (secret_wrapped_key IS NULL)
       AND (secret_key_id IS NULL) = (secret_nonce IS NULL)
       AND (secret_key_id IS NULL) = (secret_ciphertext IS NULL)),
    FOREIGN KEY (server_id, owner_user_id) REFERENCES mcp_servers(id, owner_user_id)
        ON DELETE CASCADE ON UPDATE CASCADE
);
ALTER TABLE mcp_server_oauth_clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_server_oauth_clients FORCE ROW LEVEL SECURITY;
CREATE POLICY mcp_server_oauth_clients_owner ON mcp_server_oauth_clients
    USING (owner_user_id = app_user_id()) WITH CHECK (owner_user_id = app_user_id());
GRANT SELECT, INSERT, UPDATE, DELETE ON mcp_server_oauth_clients TO gateway_app, gateway_jobs;

-- Discovered capability snapshots. At most one approved per server.
CREATE TABLE mcp_server_snapshots (
    id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id          uuid        NOT NULL REFERENCES mcp_servers(id) ON DELETE CASCADE,
    version            integer     NOT NULL CHECK (version > 0),
    status             text        NOT NULL DEFAULT 'pending'
                                   CHECK (status IN ('pending', 'approved', 'superseded')),
    discovered_at      timestamptz NOT NULL DEFAULT now(),
    approved_by        uuid        REFERENCES users(id),
    approved_at        timestamptz,
    tools              jsonb       NOT NULL DEFAULT '[]'::jsonb,
    resources          jsonb       NOT NULL DEFAULT '[]'::jsonb,
    resource_templates jsonb       NOT NULL DEFAULT '[]'::jsonb,
    prompts            jsonb       NOT NULL DEFAULT '[]'::jsonb,
    review             jsonb       NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (server_id, version)
);
CREATE UNIQUE INDEX mcp_server_snapshots_one_approved_idx
    ON mcp_server_snapshots (server_id) WHERE status = 'approved';
ALTER TABLE mcp_server_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_server_snapshots FORCE ROW LEVEL SECURITY;
CREATE POLICY mcp_server_snapshots_visible ON mcp_server_snapshots FOR SELECT
    USING (EXISTS (SELECT 1 FROM mcp_servers s WHERE s.id = mcp_server_snapshots.server_id));
CREATE POLICY mcp_server_snapshots_owner_insert ON mcp_server_snapshots FOR INSERT
    WITH CHECK (EXISTS (SELECT 1 FROM mcp_servers s
        WHERE s.id = mcp_server_snapshots.server_id AND s.owner_user_id = app_user_id()
          AND (mcp_server_snapshots.status = 'pending' OR s.audience = 'private')));
CREATE POLICY mcp_server_snapshots_owner_update ON mcp_server_snapshots FOR UPDATE
    USING (EXISTS (SELECT 1 FROM mcp_servers s
        WHERE s.id = mcp_server_snapshots.server_id AND s.owner_user_id = app_user_id() AND s.audience = 'private'))
    WITH CHECK (EXISTS (SELECT 1 FROM mcp_servers s
        WHERE s.id = mcp_server_snapshots.server_id AND s.owner_user_id = app_user_id() AND s.audience = 'private'));
CREATE POLICY mcp_server_snapshots_owner_delete ON mcp_server_snapshots FOR DELETE
    USING (EXISTS (SELECT 1 FROM mcp_servers s
        WHERE s.id = mcp_server_snapshots.server_id AND s.owner_user_id = app_user_id() AND s.audience = 'private'));
GRANT SELECT, INSERT, UPDATE, DELETE ON mcp_server_snapshots TO gateway_app, gateway_jobs;

-- Tunnels: a user's outbound tunnel client (stdio or private HTTP server
-- behind it). Only the hash of the tunnel token is stored.
CREATE TABLE mcp_tunnels (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_user_id uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name          text        NOT NULL,
    token_hash    bytea       NOT NULL UNIQUE,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz,
    revoked_at    timestamptz
);
CREATE INDEX mcp_tunnels_owner_user_id_idx ON mcp_tunnels (owner_user_id);
ALTER TABLE mcp_tunnels ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_tunnels FORCE ROW LEVEL SECURITY;
CREATE POLICY mcp_tunnels_owner ON mcp_tunnels
    USING (owner_user_id = app_user_id()) WITH CHECK (owner_user_id = app_user_id());
GRANT SELECT, INSERT, UPDATE, DELETE ON mcp_tunnels TO gateway_app, gateway_jobs;

-- Admin SSRF allow-list (host name, wildcard or CIDR). Global: every scope
-- reads it at dial time; only admins (bypass role) change it.
CREATE TABLE netguard_allow_hosts (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    pattern    text        NOT NULL UNIQUE CHECK (pattern <> ''),
    note       text        NOT NULL DEFAULT '',
    created_by uuid        REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT ON netguard_allow_hosts TO gateway_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON netguard_allow_hosts TO gateway_jobs;

-- Admin metadata views without secret columns (as 00007).
CREATE VIEW admin_mcp_servers WITH (security_invoker = true) AS
    SELECT s.id, s.name, s.url, s.transport, s.owner_user_id, s.audience, s.credential_mode,
           s.auth_kind, s.auth_config, s.header_config, s.status, s.last_error_class,
           s.created_at, s.updated_at,
           EXISTS (SELECT 1 FROM mcp_server_shared_secrets ss WHERE ss.server_id = s.id) AS has_shared_credential,
           coalesce((SELECT array_agg(sr.role_id ORDER BY sr.role_id) FROM mcp_server_roles sr WHERE sr.server_id = s.id),
                    '{}') AS published_role_ids,
           (SELECT count(*) FROM mcp_server_user_connections uc WHERE uc.server_id = s.id) AS user_connection_count
    FROM mcp_servers s;

CREATE VIEW admin_mcp_tunnels WITH (security_invoker = true) AS
    SELECT id, owner_user_id, name, created_at, last_seen_at, revoked_at
    FROM mcp_tunnels;

GRANT SELECT ON admin_mcp_servers, admin_mcp_tunnels TO gateway_app, gateway_jobs;

-- +goose Down
DROP VIEW IF EXISTS admin_mcp_tunnels;
DROP VIEW IF EXISTS admin_mcp_servers;
DROP TABLE IF EXISTS netguard_allow_hosts;
DROP TABLE IF EXISTS mcp_tunnels;
DROP TABLE IF EXISTS mcp_server_snapshots;
DROP TABLE IF EXISTS mcp_server_oauth_clients;
DROP TABLE IF EXISTS mcp_server_user_connections;
DROP TABLE IF EXISTS mcp_server_shared_secrets;
-- The mcp_servers visibility policy reads mcp_server_roles.
DROP POLICY IF EXISTS mcp_servers_visible ON mcp_servers;
DROP TABLE IF EXISTS mcp_server_roles;
DROP TABLE IF EXISTS mcp_servers;
