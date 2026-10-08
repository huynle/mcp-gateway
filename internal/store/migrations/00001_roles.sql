-- Database roles for the two isolation layers (plan 36bakiw8 section 6,
-- decision v6piaxdb). Migrations run as the database owner / a superuser
-- (BYPASSRLS can only be granted by a superuser); the service never runs them.
--
--   gateway_app   the service's request path. NOBYPASSRLS: every user-scoped
--                 table is FORCED into row-level security keyed on the
--                 transaction-local setting app.user_id (see store.WithUser).
--   gateway_jobs  background workers and admin metadata reads. BYPASSRLS.
--
-- Both roles are created NOLOGIN here so no password ever lives in a
-- migration. Operators grant LOGIN and a password out of band
-- (deploy/postgres/init/01-roles.sql does it for the Compose stack; the
-- integration tests do it themselves). Roles are cluster-global, so the Down
-- migration only revokes privileges and leaves the roles in place.

-- +goose Up
-- +goose StatementBegin
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'gateway_app') THEN
        CREATE ROLE gateway_app NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'gateway_jobs') THEN
        CREATE ROLE gateway_jobs NOLOGIN;
    END IF;
END
$$;
-- +goose StatementEnd

ALTER ROLE gateway_app NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
ALTER ROLE gateway_jobs NOSUPERUSER NOCREATEDB NOCREATEROLE BYPASSRLS;

GRANT USAGE ON SCHEMA public TO gateway_app, gateway_jobs;

-- goose creates its version table before the first migration runs; the
-- service reads it for the startup / readiness schema check.
GRANT SELECT ON goose_db_version TO gateway_app, gateway_jobs;

-- app_user_id() is the single place that reads the per-transaction user scope.
-- current_setting(..., true) yields NULL when the setting was never set in the
-- session and '' once a previous transaction's SET LOCAL has been reset, so
-- both are normalised to NULL and every RLS comparison fails closed.
-- +goose StatementBegin
CREATE FUNCTION app_user_id() RETURNS uuid
    LANGUAGE sql STABLE PARALLEL SAFE
    AS $$ SELECT nullif(current_setting('app.user_id', true), '')::uuid $$;
-- +goose StatementEnd

-- +goose Down
DROP FUNCTION IF EXISTS app_user_id();
REVOKE SELECT ON goose_db_version FROM gateway_app, gateway_jobs;
REVOKE USAGE ON SCHEMA public FROM gateway_app, gateway_jobs;
