// Tool descriptions and argument shapes are adapted from
// github/github-mcp-server, pkg/github/issues.go (list_issues,
// issue_read get_comments, issue_write update) at commit
// eb47a99ddb866ca2b8a162920e6bda9521f33ebb, MIT License, Copyright (c)
// 2025 GitHub. Modified for mcp-gateway: one tool per operation, REST
// instead of GraphQL, flat bounded results, resource identity. See
// THIRD_PARTY_NOTICES.md.

package github

import (
	"context"
	"slices"
	"strings"

	gh "github.com/google/go-github/v90/github"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Issue tool names.
const (
	ToolListIssues        = "list_issues"
	ToolListIssueComments = "list_issue_comments"
	ToolUpdateIssue       = "update_issue"
)

// issueTools declares list_issues, list_issue_comments and update_issue.
func (c *Connector) issueTools() []connectors.Tool {
	paged := connectors.Bounds{MaxPageSize: c.bounds.MaxPageSize, MaxResultBytes: c.bounds.MaxResultBytes}
	single := connectors.Bounds{MaxResultBytes: c.bounds.MaxResultBytes}
	numberProp := property{"number", "integer", "The issue (or pull request) number.", nil}
	return []connectors.Tool{
		{
			App: App, Name: ToolListIssues, Kind: connectors.KindRead,
			Description: "List the issues of a GitHub repository (pull requests are included and flagged is_pull_request), " +
				"filtered by state, labels, assignee, creator, mention or update time. Paginated.",
			InputSchema: objectSchema([]property{ownerProperty, repoProperty,
				{"state", "string", "open (default), closed or all.", []string{"open", "closed", "all"}},
				{"labels", "array", "Only issues carrying all these label names.", nil},
				{"assignee", "string", "Login assigned to the issue; none for unassigned, * for any.", nil},
				{"creator", "string", "Login that created the issue.", nil},
				{"mentioned", "string", "Login mentioned in the issue.", nil},
				{"since", "string", "Only issues updated after this time (ISO 8601).", nil},
				{"sort", "string", "created (default), updated or comments.", []string{"created", "updated", "comments"}},
				{"direction", "string", "asc or desc (default).", []string{"asc", "desc"}},
				pageProperty, perPageProperty,
			}, []string{"owner", "repo"}),
			RequiredScopes: []string{PermissionIssuesRead}, ResourceIdentity: identity(false), Bounds: paged,
		},
		{
			App: App, Name: ToolListIssueComments, Kind: connectors.KindRead,
			Description: "List the comments of an issue or pull request (the conversation, not code review comments), oldest first. Paginated.",
			InputSchema: objectSchema([]property{ownerProperty, repoProperty, numberProp,
				{"since", "string", "Only comments updated after this time (ISO 8601).", nil},
				pageProperty, perPageProperty,
			}, []string{"owner", "repo", "number"}),
			RequiredScopes: []string{PermissionIssuesRead}, ResourceIdentity: identity(true), Bounds: paged,
		},
		{
			App: App, Name: ToolUpdateIssue, Kind: connectors.KindWrite,
			Description: "Edit an issue of a GitHub repository: title, body, state (close or reopen, with a state_reason), " +
				"labels and assignees (each replaces the whole list; an empty list clears it) and milestone number. " +
				"Only the fields given change. Returns the issue's number, id and url.",
			InputSchema: objectSchema([]property{ownerProperty, repoProperty, numberProp,
				{"title", "string", "New title.", nil},
				{"body", "string", "New body in Markdown (replaces the whole body).", nil},
				{"state", "string", "open or closed.", []string{"open", "closed"}},
				{"state_reason", "string", "Why the state changes: completed, not_planned or reopened.", []string{"completed", "not_planned", "reopened"}},
				{"labels", "array", "Label names; replaces every label of the issue.", nil},
				{"assignees", "array", "Logins; replaces every assignee of the issue.", nil},
				{"milestone", "integer", "Milestone number to set.", nil},
			}, []string{"owner", "repo", "number"}),
			RequiredScopes: []string{PermissionIssuesWrite}, ResourceIdentity: identity(true),
			Reconcile: connectors.Reconciliation{Kind: connectors.ReconcileNone}, ResultIDs: issueResultIDs, Bounds: single,
		},
	}
}

// issueHandlers maps the issue tools to their implementation.
func (c *Connector) issueHandlers() (reads, writes map[string]handler) {
	return map[string]handler{ToolListIssues: c.listIssues, ToolListIssueComments: c.listIssueComments},
		map[string]handler{ToolUpdateIssue: c.updateIssue}
}

// enumArg reads an optional string argument that must be one of allowed.
func enumArg(args map[string]any, name string, allowed ...string) (string, error) {
	v, err := optionalString(args, name)
	if err != nil {
		return "", err
	}
	if v = strings.TrimSpace(v); v != "" && !slices.Contains(allowed, v) {
		return "", invalid("%s must be one of %s", name, strings.Join(allowed, ", "))
	}
	return v, nil
}

// replaceList reads an array-of-strings argument meant to replace a
// whole list: absent is nil (leave unchanged), present (even empty) is a
// non-nil slice.
func replaceList(args map[string]any, name string) ([]string, error) {
	if _, ok := args[name]; !ok {
		return nil, nil
	}
	list, err := stringList(args, name)
	if err != nil {
		return nil, err
	}
	if list == nil {
		list = []string{}
	}
	return list, nil
}

func (c *Connector) listIssues(ctx context.Context, client *gh.Client, call connectors.Call) (connectors.Result, error) {
	owner, repo, err := repoArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	opts := &gh.IssueListByRepoOptions{}
	if opts.State, err = enumArg(call.Args, "state", "open", "closed", "all"); err != nil {
		return connectors.Result{}, err
	}
	if opts.Sort, err = enumArg(call.Args, "sort", "created", "updated", "comments"); err != nil {
		return connectors.Result{}, err
	}
	if opts.Direction, err = enumArg(call.Args, "direction", "asc", "desc"); err != nil {
		return connectors.Result{}, err
	}
	for name, dst := range map[string]*string{"assignee": &opts.Assignee, "creator": &opts.Creator, "mentioned": &opts.Mentioned} {
		v, err := optionalString(call.Args, name)
		if err != nil {
			return connectors.Result{}, err
		}
		*dst = strings.TrimSpace(v)
	}
	if opts.Labels, err = stringList(call.Args, "labels"); err != nil {
		return connectors.Result{}, err
	}
	if opts.Since, err = timeArg(call.Args, "since"); err != nil {
		return connectors.Result{}, err
	}
	page, perPage, clamped, err := c.pageArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	opts.ListOptions = gh.ListOptions{Page: page, PerPage: perPage}
	issues, resp, err := client.Issues.ListByRepo(ctx, owner, repo, opts)
	if err := classify("list issues", err); err != nil {
		return connectors.Result{}, err
	}
	items := make([]SearchItem, 0, len(issues))
	for _, is := range issues {
		if is == nil {
			continue
		}
		item := toSearchItem(is)
		if item.Repo == "" {
			item.Repo = owner + "/" + repo
		}
		items = append(items, item)
	}
	return listResult(c, items, page, perPage, resp, clamped), nil
}

// CommentItem is one comment of list_issue_comments (and, with Path and
// Line, of list_pull_request_review_comments).
type CommentItem struct {
	ID                int64  `json:"id"`
	User              string `json:"user,omitempty"`
	Body              string `json:"body"`
	BodyTruncated     bool   `json:"body_truncated,omitempty"`
	AuthorAssociation string `json:"author_association,omitempty"`
	Path              string `json:"path,omitempty"`
	Line              int    `json:"line,omitempty"`
	Side              string `json:"side,omitempty"`
	InReplyTo         int64  `json:"in_reply_to_id,omitempty"`
	ReviewID          int64  `json:"review_id,omitempty"`
	URL               string `json:"url,omitempty"`
	CreatedAt         string `json:"created_at,omitempty"`
	UpdatedAt         string `json:"updated_at,omitempty"`
}

// commentsResult is listResult for comments: when one comment alone is
// over the bound its body is cut (body_truncated).
func commentsResult(c *Connector, items []CommentItem, page, perPage int, resp *gh.Response, clamped bool) connectors.Result {
	res := listResult(c, items, page, perPage, resp, clamped)
	out := res.Content.(ListPage[CommentItem])
	if len(out.Items) == 1 && encodedSize(out) > c.bounds.MaxResultBytes {
		fitBody(&out.Items[0].Body, &out.Items[0].BodyTruncated, c.bounds.MaxResultBytes, func() any { return out })
		res.Content, res.Partial = out, true
	}
	return res
}

func (c *Connector) listIssueComments(ctx context.Context, client *gh.Client, call connectors.Call) (connectors.Result, error) {
	owner, repo, err := repoArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	number, err := numberArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	since, err := timeArg(call.Args, "since")
	if err != nil {
		return connectors.Result{}, err
	}
	page, perPage, clamped, err := c.pageArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	opts := &gh.IssueListCommentsOptions{ListOptions: gh.ListOptions{Page: page, PerPage: perPage}}
	if !since.IsZero() {
		opts.Since = &since
	}
	comments, resp, err := client.Issues.ListComments(ctx, owner, repo, number, opts)
	if err := classify("list issue comments", err); err != nil {
		return connectors.Result{}, err
	}
	items := make([]CommentItem, 0, len(comments))
	for _, cm := range comments {
		if cm != nil {
			items = append(items, CommentItem{ID: cm.GetID(), User: cm.GetUser().GetLogin(), Body: cm.GetBody(), AuthorAssociation: cm.GetAuthorAssociation(),
				URL: cm.GetHTMLURL(), CreatedAt: timestamp(cm.CreatedAt), UpdatedAt: timestamp(cm.UpdatedAt)})
		}
	}
	return commentsResult(c, items, page, perPage, resp, clamped), nil
}

func (c *Connector) updateIssue(ctx context.Context, client *gh.Client, call connectors.Call) (connectors.Result, error) {
	owner, repo, err := repoArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	number, err := numberArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	req := gh.UpdateIssueRequest{}
	changed := false
	for _, name := range []string{"title", "body"} {
		if _, ok := call.Args[name]; !ok {
			continue
		}
		v, err := optionalString(call.Args, name)
		if err != nil {
			return connectors.Result{}, err
		}
		if name == "title" {
			if strings.TrimSpace(v) == "" {
				return connectors.Result{}, invalid("title must not be blank")
			}
			req.Title = gh.Ptr(v)
		} else {
			req.Body = gh.Ptr(v)
		}
		changed = true
	}
	state, err := enumArg(call.Args, "state", "open", "closed")
	if err != nil {
		return connectors.Result{}, err
	}
	reason, err := enumArg(call.Args, "state_reason", "completed", "not_planned", "reopened")
	if err != nil {
		return connectors.Result{}, err
	}
	if state != "" {
		req.State, changed = gh.Ptr(state), true
	}
	if reason != "" {
		req.StateReason, changed = gh.Ptr(reason), true
	}
	if req.Labels, err = replaceList(call.Args, "labels"); err != nil {
		return connectors.Result{}, err
	}
	if req.Assignees, err = replaceList(call.Args, "assignees"); err != nil {
		return connectors.Result{}, err
	}
	changed = changed || req.Labels != nil || req.Assignees != nil
	if v, ok := call.Args["milestone"]; ok && v != nil {
		m, err := toInt(v)
		if err != nil || m < 1 {
			return connectors.Result{}, invalid("milestone must be a positive milestone number")
		}
		req.Milestone, changed = gh.Ptr(m), true
	}
	if !changed {
		return connectors.Result{}, invalid("give at least one field to change: title, body, state, state_reason, labels, assignees or milestone")
	}
	is, _, err := client.Issues.Update(ctx, owner, repo, number, req)
	if err := classifyWrite("update issue", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: toCreatedIssue(is, owner+"/"+repo)}, nil
}
