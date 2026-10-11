-- Anchor connections for federated MCP servers (Brain task fybs78bs,
-- decision recorded with it). Approvals and ledger operations reference
-- connections(id, user_id), so a federated write needs a connections row
-- standing for the user's use of the server. Those rows hang off one
-- disabled vendor app of the new vendor 'mcp' (no OAuth, no tokens:
-- credentials stay in mcp_server_user_connections / shared secrets).

-- +goose Up
ALTER TABLE vendor_apps DROP CONSTRAINT vendor_apps_vendor_check;
ALTER TABLE vendor_apps ADD CONSTRAINT vendor_apps_vendor_check
    CHECK (vendor IN ('github', 'slack', 'atlassian', 'google', 'microsoft', 'fake', 'mcp'));

-- +goose Down
-- Anchor rows stay (approvals, ledger and audit reference them); the old
-- check is restored for new rows only.
ALTER TABLE vendor_apps DROP CONSTRAINT vendor_apps_vendor_check;
ALTER TABLE vendor_apps ADD CONSTRAINT vendor_apps_vendor_check
    CHECK (vendor IN ('github', 'slack', 'atlassian', 'google', 'microsoft', 'fake')) NOT VALID;
