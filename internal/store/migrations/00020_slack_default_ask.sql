-- Default approval mode Ask for the Slack write tools added with Brain
-- decision aud38ptd (channel management, member management, message
-- edits / deletes / scheduling, pins, file uploads, the user's own status
-- and Do Not Disturb). They act as the connected user through the user
-- token, so every call needs a confirmation until an admin switches a
-- tool to Auto (Settings -> Vendor apps -> slack -> Tool approvals, or
-- gateway.set_tool_approval). post_message, reply_in_thread and
-- add_reaction keep their Auto default and are not listed.
--
-- vendor_tool_approvals stores only Ask rows (00019), so the seed is one
-- row per tool. ON CONFLICT keeps a row an admin already wrote.
-- cmd/gateway's TestSlackNewWritesAreSeededAsAsk keeps this list equal to
-- the connector's write tools minus the three Auto ones.

-- +goose Up
INSERT INTO vendor_tool_approvals (app, tool) VALUES
    ('slack', 'archive_channel'),
    ('slack', 'clear_status'),
    ('slack', 'create_channel'),
    ('slack', 'delete_message'),
    ('slack', 'delete_scheduled_message'),
    ('slack', 'end_dnd'),
    ('slack', 'invite_to_channel'),
    ('slack', 'join_channel'),
    ('slack', 'leave_channel'),
    ('slack', 'pin_message'),
    ('slack', 'remove_from_channel'),
    ('slack', 'rename_channel'),
    ('slack', 'schedule_message'),
    ('slack', 'set_channel_purpose'),
    ('slack', 'set_channel_topic'),
    ('slack', 'set_dnd'),
    ('slack', 'set_status'),
    ('slack', 'unarchive_channel'),
    ('slack', 'unpin_message'),
    ('slack', 'update_message'),
    ('slack', 'upload_file')
ON CONFLICT (app, tool) DO NOTHING;

-- +goose Down
DELETE FROM vendor_tool_approvals WHERE (app, tool) IN (
    ('slack', 'archive_channel'),
    ('slack', 'clear_status'),
    ('slack', 'create_channel'),
    ('slack', 'delete_message'),
    ('slack', 'delete_scheduled_message'),
    ('slack', 'end_dnd'),
    ('slack', 'invite_to_channel'),
    ('slack', 'join_channel'),
    ('slack', 'leave_channel'),
    ('slack', 'pin_message'),
    ('slack', 'remove_from_channel'),
    ('slack', 'rename_channel'),
    ('slack', 'schedule_message'),
    ('slack', 'set_channel_purpose'),
    ('slack', 'set_channel_topic'),
    ('slack', 'set_dnd'),
    ('slack', 'set_status'),
    ('slack', 'unarchive_channel'),
    ('slack', 'unpin_message'),
    ('slack', 'update_message'),
    ('slack', 'upload_file')
);
