-- Self-service and admin account deletion (public gateway, feature
-- public-launch; docs/runbooks/user-offboarding.md "Delete").
--
--   users.status 'deleted'   a tombstone: the row stays because approvals,
--                            ledger operations, connections and policy
--                            history reference it, but every personal field
--                            is cleared (store.DeleteUserData), identities
--                            are deleted (signing in again creates a new
--                            user) and nothing ever re-activates it
--                            (store.SetUserStatus refuses deleted rows).
--   users.deleted_at         when it happened.
--
-- Audit events are not touched: they reference users by uuid only (no
-- foreign key, no names), so once the user row is emptied they are
-- pseudonymous. admin_users gains deleted_at (column appended, so the view
-- can be replaced in place; grants are kept).

-- +goose Up
ALTER TABLE users DROP CONSTRAINT users_status_check;
ALTER TABLE users ADD CONSTRAINT users_status_check CHECK (status IN ('active', 'disabled', 'deleted'));
ALTER TABLE users ADD COLUMN deleted_at timestamptz;

CREATE OR REPLACE VIEW admin_users WITH (security_invoker = true) AS
    SELECT id, display_name, status, last_company_sign_in_at, disabled_at, created_at, updated_at, deleted_at
    FROM users;

-- +goose Down
-- For development: deleted users become disabled ones (still without
-- personal fields or identities).
DROP VIEW admin_users;
CREATE VIEW admin_users WITH (security_invoker = true) AS
    SELECT id, display_name, status, last_company_sign_in_at, disabled_at, created_at, updated_at
    FROM users;
GRANT SELECT ON admin_users TO gateway_app, gateway_jobs;

UPDATE users SET status = 'disabled', disabled_at = coalesce(disabled_at, deleted_at) WHERE status = 'deleted';
ALTER TABLE users DROP COLUMN IF EXISTS deleted_at;
ALTER TABLE users DROP CONSTRAINT users_status_check;
ALTER TABLE users ADD CONSTRAINT users_status_check CHECK (status IN ('active', 'disabled'));
