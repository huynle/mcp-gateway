-- Admin metadata views (decision v6piaxdb: "admins see metadata", "admins
-- never see users' app tokens or content").
--
-- Every view is a column projection that leaves out secrets, hashes and
-- content, and is created WITH (security_invoker = true) so the underlying
-- tables' row-level security applies to the caller: through gateway_app a
-- scoped transaction sees only its own user's rows, and cross-user admin
-- listings go through the bypass role (store.WithJobs). Views owned by the
-- migration role would otherwise bypass RLS for everyone who can select them.

-- +goose Up
CREATE VIEW admin_users WITH (security_invoker = true) AS
    SELECT id, display_name, status, last_company_sign_in_at, disabled_at, created_at, updated_at
    FROM users;

CREATE VIEW admin_identities WITH (security_invoker = true) AS
    SELECT id, user_id, issuer, subject, last_sign_in_at, created_at
    FROM identities;

CREATE VIEW admin_tokens WITH (security_invoker = true) AS
    SELECT id, user_id, name, read_only, scope, expires_at, revoked_at, last_used_at, created_at
    FROM tokens;

CREATE VIEW admin_oauth_clients WITH (security_invoker = true) AS
    SELECT id, client_id, client_name, redirect_uris, created_at, last_used_at
    FROM oauth_clients;

CREATE VIEW admin_oauth_refresh_tokens WITH (security_invoker = true) AS
    SELECT id, user_id, client_id, scope, issued_at, expires_at, rotated_from, revoked_at, last_used_at
    FROM oauth_refresh_tokens;

CREATE VIEW admin_vendor_apps WITH (security_invoker = true) AS
    SELECT id, vendor, name, client_id, config, enabled, created_at, updated_at
    FROM vendor_apps;

CREATE VIEW admin_connections WITH (security_invoker = true) AS
    SELECT c.id, c.user_id, c.vendor_app_id, c.external_account_id, c.label, c.display_name,
           c.scopes, c.status, c.last_refreshed_at, c.created_at, c.updated_at,
           s.token_expires_at, s.updated_at AS token_updated_at
    FROM connections c
    LEFT JOIN connection_secrets s ON s.connection_id = c.id;

CREATE VIEW admin_approvals WITH (security_invoker = true) AS
    SELECT id, user_id, connection_id, tool, status, policy_version_id,
           created_at, expires_at, decided_at, consumed_at
    FROM approvals;

CREATE VIEW admin_ledger_operations WITH (security_invoker = true) AS
    SELECT id, user_id, connection_id, tool, state, idempotency_key, window_start, window_end,
           approval_id, policy_version_id, result_ids, error_code, reconcile_attempts,
           created_at, updated_at, finished_at
    FROM ledger_operations;

CREATE VIEW admin_audit_events WITH (security_invoker = true) AS
    SELECT id, event_type, user_id, actor_user_id, token_id, tool, connection_id, account_label,
           resource, decision, policy_version_id, approval_id, operation_id, outcome, latency_ms,
           details, created_at
    FROM audit_events;

CREATE VIEW admin_signing_keys WITH (security_invoker = true) AS
    SELECT id, kid, algorithm, status, created_at, retired_at
    FROM signing_keys;

GRANT SELECT ON admin_users, admin_identities, admin_tokens, admin_oauth_clients,
    admin_oauth_refresh_tokens, admin_vendor_apps, admin_connections, admin_approvals,
    admin_ledger_operations, admin_audit_events, admin_signing_keys
    TO gateway_app, gateway_jobs;

-- +goose Down
DROP VIEW IF EXISTS admin_signing_keys;
DROP VIEW IF EXISTS admin_audit_events;
DROP VIEW IF EXISTS admin_ledger_operations;
DROP VIEW IF EXISTS admin_approvals;
DROP VIEW IF EXISTS admin_connections;
DROP VIEW IF EXISTS admin_vendor_apps;
DROP VIEW IF EXISTS admin_oauth_refresh_tokens;
DROP VIEW IF EXISTS admin_oauth_clients;
DROP VIEW IF EXISTS admin_tokens;
DROP VIEW IF EXISTS admin_identities;
DROP VIEW IF EXISTS admin_users;
