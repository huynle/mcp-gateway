-- Upstream URL elicitation relay (plan 2 of
-- docs/plans/2026-10-23-credential-links-and-elicitation-relay-design.md).
--
-- A per-user upstream server may ask the user to open one of its own pages
-- (MCP URL-mode elicitation, -32042). The gateway never hands the upstream
-- URL to the harness: it stores the URL here and gives the harness its own
-- interstitial link (/elicit/<link id>), which shows the signed-in owner
-- the server, the full URL and its registrable domain before a Continue
-- button redirects there.
--
--   * mcp_servers.elicitation_origins: exact https://host[:port] origins,
--     owner-managed on the server edit form, that the server may send users
--     to besides its own registrable domain (tunnel servers have no domain
--     and need the list). Up to 20.
--   * The published lock (00017) is replaced: on a published server the
--     request path may not change elicitation_origins either (GW001); the
--     admin path may, and unlike the address and sign-in settings that does
--     not supersede the approved snapshot: the origins only decide where the
--     interstitial may point, not where tool calls go or what is sent.
--   * upstream_elicitations: one row per relayed elicitation, owned by the
--     user who made the call. Only the SHA-256 of the 256-bit random link
--     id is stored. A row is live until expires_at (10 minutes) unless
--     cancelled; opening it (Continue) keeps it live. The expiry job
--     (gateway_jobs) deletes rows a day after they expired. No envelope
--     encryption: the URL must not carry secrets (MCP spec) and storing it
--     is required to show it.

-- +goose Up
ALTER TABLE mcp_servers ADD COLUMN elicitation_origins text[] NOT NULL DEFAULT '{}'
    CONSTRAINT mcp_servers_elicitation_origins_check CHECK (
        cardinality(elicitation_origins) <= 20
        AND array_position(elicitation_origins, NULL) IS NULL
        AND length(array_to_string(elicitation_origins, ' ')) <= 8192
    );
-- The owner edits the list on the request path (column grants as 00014;
-- new servers start with none).
GRANT UPDATE (elicitation_origins) ON mcp_servers TO gateway_app;

CREATE OR REPLACE VIEW admin_mcp_servers WITH (security_invoker = true) AS
    SELECT s.id, s.name, s.url, s.transport, s.owner_user_id, s.audience, s.credential_mode,
           s.auth_kind, s.auth_config, s.header_config, s.status, s.last_error_class,
           s.created_at, s.updated_at,
           EXISTS (SELECT 1 FROM mcp_server_shared_secrets ss WHERE ss.server_id = s.id) AS has_shared_credential,
           coalesce((SELECT array_agg(sr.role_id ORDER BY sr.role_id) FROM mcp_server_roles sr WHERE sr.server_id = s.id),
                    '{}') AS published_role_ids,
           (SELECT count(*) FROM mcp_server_user_connections uc WHERE uc.server_id = s.id) AS user_connection_count,
           s.elicitation_origins
    FROM mcp_servers s;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION mcp_servers_published_lock() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    backend_changed boolean;
BEGIN
    IF OLD.audience <> 'published' THEN
        RETURN NEW;
    END IF;
    backend_changed := NEW.url IS DISTINCT FROM OLD.url
        OR NEW.transport IS DISTINCT FROM OLD.transport
        OR NEW.auth_kind IS DISTINCT FROM OLD.auth_kind
        OR NEW.auth_config IS DISTINCT FROM OLD.auth_config
        OR NEW.header_config IS DISTINCT FROM OLD.header_config;
    IF NOT backend_changed
       AND NEW.elicitation_origins IS NOT DISTINCT FROM OLD.elicitation_origins THEN
        RETURN NEW;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles
                   WHERE rolname = current_user AND (rolbypassrls OR rolsuper)) THEN
        RAISE EXCEPTION 'published server settings can only be changed by an admin'
            USING ERRCODE = 'GW001';
    END IF;
    IF backend_changed THEN
        UPDATE mcp_server_snapshots SET status = 'superseded'
            WHERE server_id = OLD.id AND status = 'approved';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TABLE upstream_elicitations (
    id                      uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    link_hash               bytea       NOT NULL UNIQUE CHECK (length(link_hash) = 32),
    owner_user_id           uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    server_id               uuid        NOT NULL REFERENCES mcp_servers(id) ON DELETE CASCADE,
    harness_id              text        NOT NULL DEFAULT '' CHECK (length(harness_id) <= 200),
    url                     text        NOT NULL CHECK (url <> '' AND length(url) <= 2048),
    upstream_elicitation_id text        NOT NULL DEFAULT '' CHECK (length(upstream_elicitation_id) <= 200),
    message                 text        NOT NULL DEFAULT '' CHECK (char_length(message) <= 500),
    created_at              timestamptz NOT NULL DEFAULT now(),
    expires_at              timestamptz NOT NULL,
    opened_at               timestamptz,
    cancelled_at            timestamptz,
    CHECK (expires_at > created_at)
);
CREATE INDEX upstream_elicitations_owner_idx ON upstream_elicitations (owner_user_id, expires_at);
CREATE INDEX upstream_elicitations_expires_at_idx ON upstream_elicitations (expires_at);
CREATE INDEX upstream_elicitations_server_idx ON upstream_elicitations (server_id);
ALTER TABLE upstream_elicitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE upstream_elicitations FORCE ROW LEVEL SECURITY;
CREATE POLICY upstream_elicitations_owner ON upstream_elicitations
    USING (owner_user_id = app_user_id()) WITH CHECK (owner_user_id = app_user_id());
GRANT SELECT, INSERT, UPDATE ON upstream_elicitations TO gateway_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON upstream_elicitations TO gateway_jobs;

-- +goose Down
-- Restores schema 31: the 00017 lock function, the 00014 admin view and no
-- elicitation_origins column.
DROP TABLE IF EXISTS upstream_elicitations;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION mcp_servers_published_lock() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.audience <> 'published' THEN
        RETURN NEW;
    END IF;
    IF NEW.url IS NOT DISTINCT FROM OLD.url
       AND NEW.transport IS NOT DISTINCT FROM OLD.transport
       AND NEW.auth_kind IS NOT DISTINCT FROM OLD.auth_kind
       AND NEW.auth_config IS NOT DISTINCT FROM OLD.auth_config
       AND NEW.header_config IS NOT DISTINCT FROM OLD.header_config THEN
        RETURN NEW;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles
                   WHERE rolname = current_user AND (rolbypassrls OR rolsuper)) THEN
        RAISE EXCEPTION 'published server settings can only be changed by an admin'
            USING ERRCODE = 'GW001';
    END IF;
    UPDATE mcp_server_snapshots SET status = 'superseded'
        WHERE server_id = OLD.id AND status = 'approved';
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

DROP VIEW IF EXISTS admin_mcp_servers;
CREATE VIEW admin_mcp_servers WITH (security_invoker = true) AS
    SELECT s.id, s.name, s.url, s.transport, s.owner_user_id, s.audience, s.credential_mode,
           s.auth_kind, s.auth_config, s.header_config, s.status, s.last_error_class,
           s.created_at, s.updated_at,
           EXISTS (SELECT 1 FROM mcp_server_shared_secrets ss WHERE ss.server_id = s.id) AS has_shared_credential,
           coalesce((SELECT array_agg(sr.role_id ORDER BY sr.role_id) FROM mcp_server_roles sr WHERE sr.server_id = s.id),
                    '{}') AS published_role_ids,
           (SELECT count(*) FROM mcp_server_user_connections uc WHERE uc.server_id = s.id) AS user_connection_count
    FROM mcp_servers s;
GRANT SELECT ON admin_mcp_servers TO gateway_app, gateway_jobs;

REVOKE UPDATE (elicitation_origins) ON mcp_servers FROM gateway_app;
ALTER TABLE mcp_servers DROP COLUMN IF EXISTS elicitation_origins;
