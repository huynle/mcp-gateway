-- Default approval mode Ask for the Google write tools of increment 4
-- (Workspace tools): the Workspace-only calendar event types (out of
-- office, working location, focus time) and the Google Chat messages
-- (send_message, reply_in_thread). They act as the connected user
-- through the user's token (an out-of-office or focus-time event can
-- decline the user's invitations; a Chat message is posted under the
-- user's name), so every call needs a confirmation
-- until an admin switches a tool to Auto (Settings -> Vendor apps ->
-- google -> Tool approvals, or gateway.set_tool_approval). Later
-- increment-4 writes append their rows here.
--
-- vendor_tool_approvals stores only Ask rows (00019), so the seed is one
-- row per tool. ON CONFLICT keeps a row an admin already wrote.
-- cmd/gateway's TestGoogleNewWritesAreSeededAsAsk keeps 00022 and this
-- list together equal to the connector's write tools minus the Auto ones.

-- +goose Up
INSERT INTO vendor_tool_approvals (app, tool) VALUES
    ('calendar', 'create_focus_time'),
    ('calendar', 'set_out_of_office'),
    ('calendar', 'set_working_location'),
    ('chat', 'reply_in_thread'),
    ('chat', 'send_message')
ON CONFLICT (app, tool) DO NOTHING;

-- +goose Down
DELETE FROM vendor_tool_approvals WHERE (app, tool) IN (
    ('calendar', 'create_focus_time'),
    ('calendar', 'set_out_of_office'),
    ('calendar', 'set_working_location'),
    ('chat', 'reply_in_thread'),
    ('chat', 'send_message')
);
