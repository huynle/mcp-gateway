-- Default approval mode Ask for the Microsoft 365 write tools added to
-- close the gap with the reference Microsoft 365 connectors (Brain plan
-- 5soa9785): drafts, reply / forward, move, read state and delete of
-- mail; event update, delete and invitation responses; OneDrive uploads
-- and sharing links; Teams chat messages and thread replies; To Do task
-- writes. They act as the connected user through the user's delegated
-- token, so every call needs a confirmation until an admin switches a
-- tool to Auto (Settings -> Vendor apps -> microsoft -> Tool approvals,
-- or gateway.set_tool_approval). mail_send, calendar_create_event,
-- drive_create_folder and teams_post_channel_message keep their Auto
-- default and are not listed.
--
-- vendor_tool_approvals stores only Ask rows (00019), so the seed is one
-- row per tool. ON CONFLICT keeps a row an admin already wrote.
-- cmd/gateway's TestMicrosoftNewWritesAreSeededAsAsk keeps this list
-- equal to the connector's write tools minus the four Auto ones.

-- +goose Up
INSERT INTO vendor_tool_approvals (app, tool) VALUES
    ('microsoft', 'calendar_delete_event'),
    ('microsoft', 'calendar_respond_event'),
    ('microsoft', 'calendar_update_event'),
    ('microsoft', 'drive_create_share_link'),
    ('microsoft', 'drive_upload_file'),
    ('microsoft', 'mail_create_draft'),
    ('microsoft', 'mail_delete'),
    ('microsoft', 'mail_forward'),
    ('microsoft', 'mail_mark_read'),
    ('microsoft', 'mail_move'),
    ('microsoft', 'mail_reply'),
    ('microsoft', 'mail_send_draft'),
    ('microsoft', 'teams_reply_channel_message'),
    ('microsoft', 'teams_send_chat_message'),
    ('microsoft', 'todo_complete_task'),
    ('microsoft', 'todo_create_task'),
    ('microsoft', 'todo_update_task')
ON CONFLICT (app, tool) DO NOTHING;

-- +goose Down
DELETE FROM vendor_tool_approvals WHERE (app, tool) IN (
    ('microsoft', 'calendar_delete_event'),
    ('microsoft', 'calendar_respond_event'),
    ('microsoft', 'calendar_update_event'),
    ('microsoft', 'drive_create_share_link'),
    ('microsoft', 'drive_upload_file'),
    ('microsoft', 'mail_create_draft'),
    ('microsoft', 'mail_delete'),
    ('microsoft', 'mail_forward'),
    ('microsoft', 'mail_mark_read'),
    ('microsoft', 'mail_move'),
    ('microsoft', 'mail_reply'),
    ('microsoft', 'mail_send_draft'),
    ('microsoft', 'teams_reply_channel_message'),
    ('microsoft', 'teams_send_chat_message'),
    ('microsoft', 'todo_complete_task'),
    ('microsoft', 'todo_create_task'),
    ('microsoft', 'todo_update_task')
);
