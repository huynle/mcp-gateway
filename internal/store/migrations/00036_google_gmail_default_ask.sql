-- Default approval mode Ask for the Google write tools of increment 5
-- (full Gmail: everything a consumer Google account can do through the
-- Gmail API). They act on the user's mailbox and settings through the
-- user's token (a forward sends mail under the user's name, delete
-- removes mail for good, a filter can forward or delete incoming mail,
-- IMAP / POP / language / signature change how the account works), so
-- every call needs a confirmation until an admin switches a tool to Auto
-- (Settings -> Vendor apps -> google -> Tool approvals, or
-- gateway.set_tool_approval). Later increment-5 Gmail writes append
-- their rows here.
--
-- vendor_tool_approvals stores only Ask rows (00019), so the seed is one
-- row per tool. ON CONFLICT keeps a row an admin already wrote.
-- cmd/gateway's TestGoogleNewWritesAreSeededAsAsk keeps 00022, 00035 and
-- this list together equal to the connector's write tools minus the Auto
-- ones.

-- +goose Up
INSERT INTO vendor_tool_approvals (app, tool) VALUES
    ('gmail', 'batch_modify_labels'),
    ('gmail', 'delete'),
    ('gmail', 'delete_draft'),
    ('gmail', 'forward'),
    ('gmail', 'untrash'),
    ('gmail', 'update_draft')
ON CONFLICT (app, tool) DO NOTHING;

-- +goose Down
DELETE FROM vendor_tool_approvals WHERE (app, tool) IN (
    ('gmail', 'batch_modify_labels'),
    ('gmail', 'delete'),
    ('gmail', 'delete_draft'),
    ('gmail', 'forward'),
    ('gmail', 'untrash'),
    ('gmail', 'update_draft')
);
