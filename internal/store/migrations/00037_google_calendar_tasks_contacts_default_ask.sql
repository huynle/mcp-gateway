-- Default approval mode Ask for the Google write tools of increment 5
-- (Brain decision 9jfy0gb8: everything a consumer Google account can do
-- with the Calendar, Tasks and People APIs). They act as the connected
-- user through the user's token: they create, move, share, clear and
-- delete calendars, events, task lists and contacts, so every call needs
-- a confirmation until an admin switches a tool to Auto (Settings ->
-- Vendor apps -> google -> Tool approvals, or gateway.set_tool_approval).
--
-- vendor_tool_approvals stores only Ask rows (00019), so the seed is one
-- row per tool. ON CONFLICT keeps a row an admin already wrote.
-- cmd/gateway's TestGoogleNewWritesAreSeededAsAsk keeps 00022, 00035 and
-- this list together equal to the connector's write tools minus the Auto
-- ones.

-- +goose Up
INSERT INTO vendor_tool_approvals (app, tool) VALUES
    ('calendar', 'clear_calendar'),
    ('calendar', 'create_calendar'),
    ('calendar', 'delete_calendar'),
    ('calendar', 'move_event'),
    ('calendar', 'quick_add'),
    ('calendar', 'share_calendar'),
    ('calendar', 'subscribe_calendar'),
    ('calendar', 'unshare_calendar'),
    ('calendar', 'unsubscribe_calendar'),
    ('calendar', 'update_acl'),
    ('calendar', 'update_calendar'),
    ('calendar', 'update_calendar_list_entry')
ON CONFLICT (app, tool) DO NOTHING;

-- +goose Down
DELETE FROM vendor_tool_approvals WHERE (app, tool) IN (
    ('calendar', 'clear_calendar'),
    ('calendar', 'create_calendar'),
    ('calendar', 'delete_calendar'),
    ('calendar', 'move_event'),
    ('calendar', 'quick_add'),
    ('calendar', 'share_calendar'),
    ('calendar', 'subscribe_calendar'),
    ('calendar', 'unshare_calendar'),
    ('calendar', 'unsubscribe_calendar'),
    ('calendar', 'update_acl'),
    ('calendar', 'update_calendar'),
    ('calendar', 'update_calendar_list_entry')
);
