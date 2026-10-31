-- Default approval mode Ask for the Google write tools of increment 5
-- (full Drive, Docs, Sheets, Slides and Forms; Brain decision 9jfy0gb8):
-- every write a consumer Google account can do through those APIs,
-- including the ones earlier increments left out as "too open for a
-- reviewed write" (raw batch_update requests, trash and permanent delete,
-- permission changes and ownership transfer, form creation and
-- publishing). The gateway's approval is now the gate: every call needs a
-- confirmation until an admin switches a tool to Auto (Settings -> Vendor
-- apps -> google -> Tool approvals, or gateway.set_tool_approval).
--
-- vendor_tool_approvals stores only Ask rows (00019), so the seed is one
-- row per tool. ON CONFLICT keeps a row an admin already wrote.
-- cmd/gateway's TestGoogleNewWritesAreSeededAsAsk keeps 00022, 00035 and
-- this list together equal to the connector's write tools minus the Auto
-- ones.

-- +goose Up
INSERT INTO vendor_tool_approvals (app, tool) VALUES
    ('docs', 'batch_update'),
    ('drive', 'copy_file'),
    ('drive', 'create_shortcut'),
    ('drive', 'delete'),
    ('drive', 'delete_comment'),
    ('drive', 'empty_trash'),
    ('drive', 'remove_permission'),
    ('drive', 'reply_comment'),
    ('drive', 'resolve_comment'),
    ('drive', 'transfer_ownership'),
    ('drive', 'trash'),
    ('drive', 'untrash'),
    ('drive', 'update_permission'),
    ('drive', 'upload_new_version'),
    ('forms', 'batch_update'),
    ('forms', 'create'),
    ('forms', 'set_publish_settings'),
    ('sheets', 'batch_update'),
    ('slides', 'batch_update')
ON CONFLICT (app, tool) DO NOTHING;

-- +goose Down
DELETE FROM vendor_tool_approvals WHERE (app, tool) IN (
    ('docs', 'batch_update'),
    ('drive', 'copy_file'),
    ('drive', 'create_shortcut'),
    ('drive', 'delete'),
    ('drive', 'delete_comment'),
    ('drive', 'empty_trash'),
    ('drive', 'remove_permission'),
    ('drive', 'reply_comment'),
    ('drive', 'resolve_comment'),
    ('drive', 'transfer_ownership'),
    ('drive', 'trash'),
    ('drive', 'untrash'),
    ('drive', 'update_permission'),
    ('drive', 'upload_new_version'),
    ('forms', 'batch_update'),
    ('forms', 'create'),
    ('forms', 'set_publish_settings'),
    ('sheets', 'batch_update'),
    ('slides', 'batch_update')
);
