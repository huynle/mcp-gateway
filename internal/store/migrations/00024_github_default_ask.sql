-- Default approval mode Ask for the GitHub write tools added to close the
-- gap with github/github-mcp-server (Brain plan 5soa9785): file commits,
-- issue and pull request edits, reviews, reviewer requests, merges and
-- GitHub Actions run / re-run / cancel. They act as the connected user
-- through the GitHub App user token, so every call needs a confirmation
-- until an admin switches a tool to Auto (Settings -> Vendor apps ->
-- github -> Tool approvals, or gateway.set_tool_approval). create_issue,
-- add_issue_comment, create_pull_request and create_branch keep their
-- Auto default and are not listed.
--
-- vendor_tool_approvals stores only Ask rows (00019), so the seed is one
-- row per tool. ON CONFLICT keeps a row an admin already wrote.
-- cmd/gateway's TestGitHubNewWritesAreSeededAsAsk keeps this list equal
-- to the connector's write tools minus the four Auto ones.

-- +goose Up
INSERT INTO vendor_tool_approvals (app, tool) VALUES
    ('github', 'cancel_workflow_run'),
    ('github', 'create_or_update_file'),
    ('github', 'create_pull_request_review'),
    ('github', 'merge_pull_request'),
    ('github', 'request_reviewers'),
    ('github', 'rerun_workflow_run'),
    ('github', 'run_workflow'),
    ('github', 'update_issue'),
    ('github', 'update_pull_request')
ON CONFLICT (app, tool) DO NOTHING;

-- +goose Down
DELETE FROM vendor_tool_approvals WHERE (app, tool) IN (
    ('github', 'cancel_workflow_run'),
    ('github', 'create_or_update_file'),
    ('github', 'create_pull_request_review'),
    ('github', 'merge_pull_request'),
    ('github', 'request_reviewers'),
    ('github', 'rerun_workflow_run'),
    ('github', 'run_workflow'),
    ('github', 'update_issue'),
    ('github', 'update_pull_request')
);
