-- Published servers are admin-governed (Brain task mpszh6h0, decision
-- q7vbxlyk point 3).
--
-- Once an admin has published a server, its address and sign-in settings
-- (url, transport, credential_mode, auth_kind, auth_config, header_config)
-- decide where every user's tool arguments go and where the answers come
-- from. The admin approved the snapshot for that backend, so:
--
--   * the request path (gateway_app, subject to row-level security) may not
--     change those columns while the server is published: the UPDATE fails
--     with SQLSTATE GW001 (store.ErrMCPServerLocked). The owner asks an
--     admin, or an admin unpublishes the server first;
--   * the admin path (gateway_jobs, BYPASSRLS) may change them, and the
--     server's approved snapshot becomes superseded in the same statement,
--     so nothing is served from the new backend until an admin reviews it
--     again (refresh + approve).
--
-- Other columns (name, status, last_error_class, updated_at) and private
-- servers are unaffected. "Request path" means any role without BYPASSRLS
-- (and not a superuser), so the check does not depend on role names.

-- +goose Up
-- +goose StatementBegin
CREATE FUNCTION mcp_servers_published_lock() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.audience <> 'published' THEN
        RETURN NEW;
    END IF;
    IF NEW.url IS NOT DISTINCT FROM OLD.url
       AND NEW.transport IS NOT DISTINCT FROM OLD.transport
       AND NEW.credential_mode IS NOT DISTINCT FROM OLD.credential_mode
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

CREATE TRIGGER mcp_servers_published_lock
    BEFORE UPDATE ON mcp_servers
    FOR EACH ROW EXECUTE FUNCTION mcp_servers_published_lock();

-- +goose Down
-- Restores schema 16: owners may again edit a published server's address
-- and sign-in settings, and admin edits keep the approved snapshot.
DROP TRIGGER IF EXISTS mcp_servers_published_lock ON mcp_servers;
DROP FUNCTION IF EXISTS mcp_servers_published_lock();
