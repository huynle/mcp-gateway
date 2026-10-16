-- Default approval mode Ask for the Slack canvas and Slack List writes
-- added to match Slack's own MCP server (Brain plan 5soa9785):
-- create_canvas, update_canvas, create_list, update_list, add_list_item,
-- update_list_item. Like 00020 they act as the connected user, so every
-- call needs a confirmation until an admin switches a tool to Auto.
-- The new tools that only read (reactions, members, file / user / channel
-- / emoji search, read_file, read_canvas, read_list) are not affected.
--
-- ON CONFLICT keeps a row an admin already wrote; Down removes exactly
-- these rows. cmd/gateway's TestSlackNewWritesAreSeededAsAsk keeps
-- 00020 + 00021 equal to the connector's write tools minus the Auto ones.

-- +goose Up
INSERT INTO vendor_tool_approvals (app, tool) VALUES
    ('slack', 'add_list_item'),
    ('slack', 'create_canvas'),
    ('slack', 'create_list'),
    ('slack', 'update_canvas'),
    ('slack', 'update_list'),
    ('slack', 'update_list_item')
ON CONFLICT (app, tool) DO NOTHING;

-- +goose Down
DELETE FROM vendor_tool_approvals WHERE (app, tool) IN (
    ('slack', 'add_list_item'),
    ('slack', 'create_canvas'),
    ('slack', 'create_list'),
    ('slack', 'update_canvas'),
    ('slack', 'update_list'),
    ('slack', 'update_list_item')
);
