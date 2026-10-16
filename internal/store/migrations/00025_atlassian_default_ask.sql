-- Default approval mode Ask for the Jira and Confluence write tools added
-- to close the gap with Atlassian's Rovo MCP server (edit / assign an
-- issue, edit a comment, log work, link issues, watchers, sprint moves,
-- remote links; update a page, page comments and labels). They act as
-- the connected user through the user's OAuth token, so every call needs
-- a confirmation until an admin switches a tool to Auto (Settings ->
-- Vendor apps -> jira / confluence -> Tool approvals, or
-- gateway.set_tool_approval). jira create_issue, add_comment and
-- transition_issue and confluence create_page keep their Auto default
-- and are not listed.
--
-- vendor_tool_approvals stores only Ask rows (00019), so the seed is one
-- row per tool. ON CONFLICT keeps a row an admin already wrote.
-- cmd/gateway's TestAtlassianNewWritesAreSeededAsAsk keeps this list
-- equal to the connectors' write tools minus the Auto ones.

-- +goose Up
INSERT INTO vendor_tool_approvals (app, tool) VALUES
    ('confluence', 'add_page_comment'),
    ('confluence', 'add_page_labels'),
    ('confluence', 'update_page'),
    ('jira', 'add_issues_to_sprint'),
    ('jira', 'add_remote_link'),
    ('jira', 'add_watcher'),
    ('jira', 'add_worklog'),
    ('jira', 'assign_issue'),
    ('jira', 'edit_comment'),
    ('jira', 'link_issues'),
    ('jira', 'remove_watcher'),
    ('jira', 'update_issue')
ON CONFLICT (app, tool) DO NOTHING;

-- +goose Down
DELETE FROM vendor_tool_approvals WHERE (app, tool) IN (
    ('confluence', 'add_page_comment'),
    ('confluence', 'add_page_labels'),
    ('confluence', 'update_page'),
    ('jira', 'add_issues_to_sprint'),
    ('jira', 'add_remote_link'),
    ('jira', 'add_watcher'),
    ('jira', 'add_worklog'),
    ('jira', 'assign_issue'),
    ('jira', 'edit_comment'),
    ('jira', 'link_issues'),
    ('jira', 'remove_watcher'),
    ('jira', 'update_issue')
);
