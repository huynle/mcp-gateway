-- Gateway management permission and setting (Brain task ds5tjou2, plan
-- ax0w46sh, decision bnneszc1).
--
--   roles.may_add_servers          the role lets its holders add MCP
--                                  servers (admins always may). Set by
--                                  admins in the role editor.
--   users.gateway_tools_enabled    the user switched on the gateway.* MCP
--                                  tools in My account (default off).
--
-- Privileges are tightened at the same time so the columns mean something:
--
--   * users: gateway_app (the request path, NOBYPASSRLS) may update only
--     gateway_tools_enabled, and the users_self policy limits that to the
--     user's own row. Sign-in bookkeeping, status changes and user creation
--     already run as gateway_jobs (BYPASSRLS), so gateway_app loses
--     INSERT, DELETE and every other UPDATE column.
--   * roles and role_assignments: only the admin path (the policy and
--     identity services, through gateway_jobs) writes them. gateway_app
--     keeps SELECT: the permission check and the mcp_servers visibility
--     policy read them in the user's scope. Before this migration a user
--     scope could even insert its own role_assignments row.

-- +goose Up
ALTER TABLE roles ADD COLUMN may_add_servers boolean NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN gateway_tools_enabled boolean NOT NULL DEFAULT false;

REVOKE INSERT, UPDATE, DELETE ON users FROM gateway_app;
GRANT UPDATE (gateway_tools_enabled) ON users TO gateway_app;

REVOKE INSERT, UPDATE, DELETE ON roles FROM gateway_app;
REVOKE INSERT, UPDATE, DELETE ON role_assignments FROM gateway_app;

-- +goose Down
-- For development: restores the schema 15 grants and drops the columns
-- (role flags and user toggles are lost).
REVOKE UPDATE (gateway_tools_enabled) ON users FROM gateway_app;
GRANT INSERT, UPDATE, DELETE ON users TO gateway_app;
GRANT INSERT, UPDATE, DELETE ON roles TO gateway_app;
GRANT INSERT, UPDATE, DELETE ON role_assignments TO gateway_app;

ALTER TABLE users DROP COLUMN IF EXISTS gateway_tools_enabled;
ALTER TABLE roles DROP COLUMN IF EXISTS may_add_servers;
