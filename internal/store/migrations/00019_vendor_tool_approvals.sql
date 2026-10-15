-- Org-wide approval modes (Ask / Auto) of built-in vendor app write tools
-- (Settings -> Vendor apps -> <vendor> -> Tool approvals; gateway.set_tool_approval).
-- Only tools set to Ask are stored: absence means Auto, which leaves the
-- roles' outcome unchanged. The policy service compiles the rows into the
-- Cedar set (internal/policy AppApproval). Admin metadata like roles and
-- rate settings: read and written through the jobs role.

-- +goose Up
CREATE TABLE vendor_tool_approvals (
    app text NOT NULL CHECK (app ~ '^[a-z0-9_-]{1,63}$' AND app <> 'gateway'),
    tool text NOT NULL CHECK (tool ~ '^[a-z0-9_-]{1,128}$'),
    updated_by uuid REFERENCES users(id) ON DELETE SET NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (app, tool)
);

GRANT SELECT ON vendor_tool_approvals TO gateway_app;
GRANT ALL ON vendor_tool_approvals TO gateway_jobs;

-- +goose Down
DROP TABLE IF EXISTS vendor_tool_approvals;
