// Tool descriptions and argument shapes are adapted from
// github/github-mcp-server, pkg/github/issues.go (issue_write,
// add_issue_comment), pullrequests.go (create_pull_request) and
// repositories.go (create_branch) at commit
// eb47a99ddb866ca2b8a162920e6bda9521f33ebb, MIT License, Copyright (c)
// 2025 GitHub. Modified for mcp-gateway: one tool per write, snake_case
// arguments, resource identity for policy and audit, the ledger's
// operation id embedded as a hidden marker so an unknown outcome can be
// reconciled, result ids instead of full objects, and the connector's
// error vocabulary (unknown outcomes are reported, never guessed). See
// THIRD_PARTY_NOTICES.md.

package github

import (
	"context"
	"errors"
	"strings"

	gh "github.com/google/go-github/v90/github"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Write tool names.
const (
	ToolCreateIssue       = "create_issue"
	ToolAddIssueComment   = "add_issue_comment"
	ToolCreatePullRequest = "create_pull_request"
	ToolCreateBranch      = "create_branch"
)

// GitHub App permissions the write tools need (see PermissionIssuesRead).
const (
	PermissionIssuesWrite       = "issues:write"
	PermissionPullRequestsWrite = "pull_requests:write"
	PermissionContentsWrite     = "contents:write"
)

// ErrMissingOperation is returned by every write called without
// Call.OperationID: the ledger stage sets it before dispatch, and the
// marker and stable-id reconciliation derive from it, so a write without
// one could never be verified after an unknown outcome. It means a
// pipeline wiring bug (a write dispatched without the ledger), never a
// harness mistake.
var ErrMissingOperation = errors.New("github: write called without a ledger operation id")

// writeTools declares the four write tools.
func (c *Connector) writeTools() []connectors.Tool {
	single := connectors.Bounds{MaxResultBytes: c.bounds.MaxResultBytes}
	return []connectors.Tool{
		{
			App: App, Name: ToolCreateIssue, Kind: connectors.KindWrite,
			Description: "Create a new issue in a GitHub repository with a title and an optional Markdown body, labels and assignees. " +
				"Returns the new issue's number, id and url.",
			InputSchema: objectSchema([]property{
				ownerProperty, repoProperty,
				{"title", "string", "Issue title.", nil},
				{"body", "string", "Issue body in Markdown.", nil},
				{"labels", "array", "Label names to apply.", nil},
				{"assignees", "array", "GitHub logins to assign.", nil},
			}, []string{"owner", "repo", "title"}),
			RequiredScopes:   []string{PermissionIssuesWrite},
			ResourceIdentity: identity(false),
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileMarker, Check: c.checkIssue},
			ResultIDs:        issueResultIDs,
			Bounds:           single,
		},
		{
			App: App, Name: ToolAddIssueComment, Kind: connectors.KindWrite,
			Description: "Add a comment to an issue or pull request of a GitHub repository (pass the pull request number as number). " +
				"Returns the new comment's id and url.",
			InputSchema: objectSchema([]property{
				ownerProperty, repoProperty,
				{"number", "integer", "Issue or pull request number to comment on.", nil},
				{"body", "string", "Comment body in Markdown.", nil},
			}, []string{"owner", "repo", "number", "body"}),
			RequiredScopes:   []string{PermissionIssuesWrite},
			ResourceIdentity: identity(true),
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileMarker, Check: c.checkComment},
			ResultIDs:        commentResultIDs,
			Bounds:           single,
		},
		{
			App: App, Name: ToolCreatePullRequest, Kind: connectors.KindWrite,
			Description: "Open a pull request in a GitHub repository from head (the branch with the changes; use login:branch for a fork) " +
				"into base, with a title and an optional Markdown body; draft opens it as a draft. Returns the new pull request's number, id and url.",
			InputSchema: objectSchema([]property{
				ownerProperty, repoProperty,
				{"title", "string", "Pull request title.", nil},
				{"head", "string", "Branch containing the changes (login:branch for a branch in a fork).", nil},
				{"base", "string", "Branch to merge the changes into.", nil},
				{"body", "string", "Pull request description in Markdown.", nil},
				{"draft", "boolean", "Open the pull request as a draft.", nil},
			}, []string{"owner", "repo", "title", "head", "base"}),
			RequiredScopes:   []string{PermissionPullRequestsWrite},
			ResourceIdentity: branchIdentity("head", "base"),
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileMarker, Check: c.checkPullRequest},
			ResultIDs:        pullRequestResultIDs,
			Bounds:           single,
		},
		{
			App: App, Name: ToolCreateBranch, Kind: connectors.KindWrite,
			Description: "Create a branch in a GitHub repository from from_branch (the repository's default branch when omitted). " +
				"Returns the new branch's ref and commit sha.",
			InputSchema: objectSchema([]property{
				ownerProperty, repoProperty,
				{"branch", "string", "Name of the new branch.", nil},
				{"from_branch", "string", "Source branch; the repository's default branch when omitted.", nil},
			}, []string{"owner", "repo", "branch"}),
			RequiredScopes:   []string{PermissionContentsWrite},
			ResourceIdentity: branchIdentity("branch", ""),
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkBranch},
			ResultIDs:        branchResultIDs,
			Bounds:           single,
		},
	}
}

// writeHandlers maps the write tools' short names to their implementation.
func (c *Connector) writeHandlers() map[string]handler {
	return map[string]handler{
		ToolCreateIssue:       c.createIssue,
		ToolAddIssueComment:   c.addIssueComment,
		ToolCreatePullRequest: c.createPullRequest,
		ToolCreateBranch:      c.createBranch,
	}
}

// branchIdentity extends identity(false) with the branch named by the
// headKey argument under "branch" and, when baseKey is set, that argument
// under "base". Branch names keep their case: git refs are case-sensitive
// and the reconciler looks the branch up by this value.
func branchIdentity(headKey, baseKey string) func(map[string]any) map[string]string {
	base := identity(false)
	return func(args map[string]any) map[string]string {
		out := base(args)
		if v, _ := args[headKey].(string); strings.TrimSpace(v) != "" {
			out["branch"] = strings.TrimSpace(v)
		}
		if baseKey != "" {
			if v, _ := args[baseKey].(string); strings.TrimSpace(v) != "" {
				out["base"] = strings.TrimSpace(v)
			}
		}
		return out
	}
}

// --- result ids -------------------------------------------------------------------

func issueResultIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(CreatedIssue)
	if !ok || v.Number == 0 {
		return nil
	}
	return map[string]string{"number": itoa(v.Number), "id": i64toa(v.ID), "url": v.URL}
}

func commentResultIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(CreatedComment)
	if !ok || v.ID == 0 {
		return nil
	}
	return map[string]string{"id": i64toa(v.ID), "url": v.URL}
}

func pullRequestResultIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(CreatedPullRequest)
	if !ok || v.Number == 0 {
		return nil
	}
	return map[string]string{"number": itoa(v.Number), "id": i64toa(v.ID), "url": v.URL}
}

func branchResultIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(CreatedBranch)
	if !ok || v.SHA == "" {
		return nil
	}
	return map[string]string{"sha": v.SHA, "ref": v.Ref, "url": v.URL}
}

// --- handlers (filled in by the following increments) ------------------------------

func (c *Connector) createIssue(context.Context, *gh.Client, connectors.Call) (connectors.Result, error) {
	return connectors.Result{}, errors.New("github: create_issue not implemented")
}

func (c *Connector) addIssueComment(context.Context, *gh.Client, connectors.Call) (connectors.Result, error) {
	return connectors.Result{}, errors.New("github: add_issue_comment not implemented")
}

func (c *Connector) createPullRequest(context.Context, *gh.Client, connectors.Call) (connectors.Result, error) {
	return connectors.Result{}, errors.New("github: create_pull_request not implemented")
}

func (c *Connector) createBranch(context.Context, *gh.Client, connectors.Call) (connectors.Result, error) {
	return connectors.Result{}, errors.New("github: create_branch not implemented")
}
