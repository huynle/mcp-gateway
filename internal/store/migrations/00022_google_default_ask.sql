-- Default approval mode Ask for the Google write tools added after
-- increments 1 and 2 (calendar update / delete / respond, tasks update /
-- complete / delete, gmail label changes, trash and sending a draft,
-- drive uploads, moves, renames, sharing and comments, docs text
-- replacement, sheets range updates and creation). They act as the
-- connected user through the user's token, so every call needs a
-- confirmation until an admin switches a tool to Auto (Settings -> Vendor
-- apps -> google -> Tool approvals, or gateway.set_tool_approval). The
-- earlier Google writes (calendar.create_event, tasks.create, gmail.send,
-- gmail.create_draft, drive.create_folder, docs.create, docs.append_text,
-- sheets.append_rows) keep their Auto default and are not listed.
--
-- vendor_tool_approvals stores only Ask rows (00019), so the seed is one
-- row per tool. ON CONFLICT keeps a row an admin already wrote.
-- cmd/gateway's TestGoogleNewWritesAreSeededAsAsk keeps this list equal to
-- the connector's write tools minus the Auto ones.

-- +goose Up
INSERT INTO vendor_tool_approvals (app, tool) VALUES
    ('calendar', 'delete_event'),
    ('calendar', 'respond_to_event'),
    ('calendar', 'update_event'),
    ('docs', 'replace_text'),
    ('drive', 'add_comment'),
    ('drive', 'create_file'),
    ('drive', 'share'),
    ('drive', 'update_file'),
    ('gmail', 'modify_labels'),
    ('gmail', 'send_draft'),
    ('gmail', 'trash'),
    ('sheets', 'create'),
    ('sheets', 'update_range'),
    ('tasks', 'complete'),
    ('tasks', 'delete'),
    ('tasks', 'update')
ON CONFLICT (app, tool) DO NOTHING;

-- +goose Down
DELETE FROM vendor_tool_approvals WHERE (app, tool) IN (
    ('calendar', 'delete_event'),
    ('calendar', 'respond_to_event'),
    ('calendar', 'update_event'),
    ('docs', 'replace_text'),
    ('drive', 'add_comment'),
    ('drive', 'create_file'),
    ('drive', 'share'),
    ('drive', 'update_file'),
    ('gmail', 'modify_labels'),
    ('gmail', 'send_draft'),
    ('gmail', 'trash'),
    ('sheets', 'create'),
    ('sheets', 'update_range'),
    ('tasks', 'complete'),
    ('tasks', 'delete'),
    ('tasks', 'update')
);
