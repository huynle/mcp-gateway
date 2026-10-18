-- Durable per-user resource caps for a public gateway: how many MCP
-- servers, tunnels, app connections (per vendor app and in total) and
-- pending approvals one user may hold. Like the rate limits (00018) the
-- environment values are bootstrap defaults; a non-null organization value
-- overrides them and a non-null per-user administrator value overrides
-- both. 0 means unlimited and can only be set here (never by ENV).

-- +goose Up
CREATE TABLE gateway_resource_caps (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    servers integer CHECK (servers BETWEEN 0 AND 100000),
    tunnels integer CHECK (tunnels BETWEEN 0 AND 100000),
    connections_per_app integer CHECK (connections_per_app BETWEEN 0 AND 100000),
    connections_total integer CHECK (connections_total BETWEEN 0 AND 100000),
    pending_approvals integer CHECK (pending_approvals BETWEEN 0 AND 100000),
    version bigint NOT NULL DEFAULT 1,
    updated_by uuid REFERENCES users(id) ON DELETE SET NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO gateway_resource_caps (singleton) VALUES (true);

CREATE TABLE gateway_user_resource_caps (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    servers integer CHECK (servers BETWEEN 0 AND 100000),
    tunnels integer CHECK (tunnels BETWEEN 0 AND 100000),
    connections_per_app integer CHECK (connections_per_app BETWEEN 0 AND 100000),
    connections_total integer CHECK (connections_total BETWEEN 0 AND 100000),
    pending_approvals integer CHECK (pending_approvals BETWEEN 0 AND 100000),
    updated_by uuid REFERENCES users(id) ON DELETE SET NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE gateway_user_resource_caps ENABLE ROW LEVEL SECURITY;
ALTER TABLE gateway_user_resource_caps FORCE ROW LEVEL SECURITY;
CREATE POLICY gateway_user_resource_caps_self ON gateway_user_resource_caps
    USING (user_id = app_user_id()) WITH CHECK (user_id = app_user_id());

-- The request path only reads (its own row); administrators write through
-- the jobs role.
GRANT SELECT ON gateway_resource_caps, gateway_user_resource_caps TO gateway_app;
GRANT ALL ON gateway_resource_caps, gateway_user_resource_caps TO gateway_jobs;

-- +goose Down
DROP TABLE IF EXISTS gateway_user_resource_caps;
DROP TABLE IF EXISTS gateway_resource_caps;
