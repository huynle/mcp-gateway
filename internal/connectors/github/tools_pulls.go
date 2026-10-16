// Tool descriptions and argument shapes are adapted from
// github/github-mcp-server, pkg/github/pullrequests.go (list_pull_requests,
// pull_request_read get_diff / get_status / get_reviews /
// get_review_comments, update_pull_request, pull_request_review_write
// create, merge_pull_request) and the request-reviewers part of
// update_pull_request at commit eb47a99ddb866ca2b8a162920e6bda9521f33ebb,
// MIT License, Copyright (c) 2025 GitHub. Modified for mcp-gateway: one
// tool per operation, flat bounded results, diffs read only up to the
// bound, resource identity, reconciliation by marker or stable id. See
// THIRD_PARTY_NOTICES.md.

package github

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	gh "github.com/google/go-github/v90/github"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Pull request tool names.
const (
	ToolListPullRequests              = "list_pull_requests"
	ToolGetPullRequestDiff            = "get_pull_request_diff"
	ToolGetPullRequestStatus          = "get_pull_request_status"
	ToolListPullRequestReviews        = "list_pull_request_reviews"
	ToolListPullRequestReviewComments = "list_pull_request_review_comments"
	ToolUpdatePullRequest             = "update_pull_request"
	ToolCreatePullRequestReview       = "create_pull_request_review"
	ToolRequestReviewers              = "request_reviewers"
	ToolMergePullRequest              = "merge_pull_request"
)

// GitHub App permissions get_pull_request_status needs besides Pull
// requests: read.
const (
	PermissionStatusesRead = "statuses:read"
	PermissionChecksRead   = "checks:read"
)

// diffMediaType asks the pull request endpoint for the unified diff.
const diffMediaType = "application/vnd.github.v3.diff"

// pullTools declares the pull request tools.
func (c *Connector) pullTools() []connectors.Tool {
	paged := connectors.Bounds{MaxPageSize: c.bounds.MaxPageSize, MaxResultBytes: c.bounds.MaxResultBytes}
	single := connectors.Bounds{MaxResultBytes: c.bounds.MaxResultBytes}
	num := property{"number", "integer", "The pull request number.", nil}
	orn := []string{"owner", "repo", "number"}
	prRead, prWrite := []string{PermissionPullRequestsRead}, []string{PermissionPullRequestsWrite}
	read := func(name, desc string, props []property, scopes []string, b connectors.Bounds) connectors.Tool {
		return connectors.Tool{App: App, Name: name, Kind: connectors.KindRead, Description: desc,
			InputSchema: objectSchema(props, orn), RequiredScopes: scopes, ResourceIdentity: identity(true), Bounds: b}
	}
	return []connectors.Tool{
		{
			App: App, Name: ToolListPullRequests, Kind: connectors.KindRead,
			Description: "List the pull requests of a GitHub repository, filtered by state, head (login:branch) and base branch. Paginated.",
			InputSchema: objectSchema([]property{ownerProperty, repoProperty,
				{"state", "string", "open (default), closed or all.", []string{"open", "closed", "all"}},
				{"head", "string", "Only pull requests from this head, as login:branch.", nil},
				{"base", "string", "Only pull requests into this base branch.", nil},
				{"sort", "string", "created (default), updated, popularity or long-running.", []string{"created", "updated", "popularity", "long-running"}},
				{"direction", "string", "asc or desc.", []string{"asc", "desc"}},
				pageProperty, perPageProperty,
			}, []string{"owner", "repo"}),
			RequiredScopes: prRead, ResourceIdentity: identity(false), Bounds: paged,
		},
		read(ToolGetPullRequestDiff, "Get the unified diff of a pull request, cut to fit the result bounds (truncated says so; use list_pull_request_files to page through large changes).",
			[]property{ownerProperty, repoProperty, num}, prRead, single),
		read(ToolGetPullRequestStatus, "Get the CI status of a pull request's head commit: the combined commit status with each status context, and the check runs (GitHub Actions and other apps).",
			[]property{ownerProperty, repoProperty, num}, []string{PermissionPullRequestsRead, PermissionStatusesRead, PermissionChecksRead}, single),
		read(ToolListPullRequestReviews, "List the reviews of a pull request (approved, changes requested, commented) with their bodies, oldest first. Paginated.",
			[]property{ownerProperty, repoProperty, num, pageProperty, perPageProperty}, prRead, paged),
		read(ToolListPullRequestReviewComments, "List the code review comments of a pull request (on lines of the diff) with path, line and thread, oldest first. Paginated.",
			[]property{ownerProperty, repoProperty, num, pageProperty, perPageProperty}, prRead, paged),
		{
			App: App, Name: ToolUpdatePullRequest, Kind: connectors.KindWrite,
			Description: "Edit a pull request: title, body, state (close or reopen), base branch, and whether maintainers may push to the head branch. " +
				"Only the fields given change. Returns the pull request's number, id and url.",
			InputSchema: objectSchema([]property{ownerProperty, repoProperty, num,
				{"title", "string", "New title.", nil},
				{"body", "string", "New description in Markdown (replaces the whole body).", nil},
				{"state", "string", "open or closed.", []string{"open", "closed"}},
				{"base", "string", "New base branch.", nil},
				{"maintainer_can_modify", "boolean", "Whether maintainers of the base repository may push to the head branch.", nil},
			}, orn),
			RequiredScopes: prWrite, ResourceIdentity: identity(true),
			Reconcile: connectors.Reconciliation{Kind: connectors.ReconcileNone}, ResultIDs: pullRequestResultIDs, Bounds: single,
		},
		{
			App: App, Name: ToolCreatePullRequestReview, Kind: connectors.KindWrite,
			Description: "Submit a review on a pull request: APPROVE, REQUEST_CHANGES or COMMENT (the last two need a body), " +
				"optionally with line comments ({path, line, body, side?, start_line?} on the head commit's diff). Returns the review's id and url.",
			InputSchema: objectSchema([]property{ownerProperty, repoProperty, num,
				{"event", "string", "APPROVE, REQUEST_CHANGES or COMMENT.", []string{"APPROVE", "REQUEST_CHANGES", "COMMENT"}},
				{"body", "string", "Review summary in Markdown; required for REQUEST_CHANGES and COMMENT.", nil},
				{"commit_id", "string", "Commit sha the review is for; the pull request's head when omitted.", nil},
				{"comments", "array", "Line comments: objects with path, line, body and optional side (LEFT or RIGHT) and start_line.", nil},
			}, []string{"owner", "repo", "number", "event"}),
			RequiredScopes: prWrite, ResourceIdentity: identity(true),
			Reconcile: connectors.Reconciliation{Kind: connectors.ReconcileMarker, Check: c.checkReview}, ResultIDs: reviewResultIDs, Bounds: single,
		},
		{
			App: App, Name: ToolRequestReviewers, Kind: connectors.KindWrite,
			Description: "Request reviews on a pull request from users (logins) and/or teams (slugs of the repository's organization). Returns the pull request's number and url.",
			InputSchema: objectSchema([]property{ownerProperty, repoProperty, num,
				{"reviewers", "array", "Logins to request a review from.", nil},
				{"team_reviewers", "array", "Team slugs to request a review from.", nil},
			}, orn),
			RequiredScopes: prWrite, ResourceIdentity: reviewersIdentity,
			Reconcile: connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkReviewers}, ResultIDs: reviewersResultIDs, Bounds: single,
		},
		{
			App: App, Name: ToolMergePullRequest, Kind: connectors.KindWrite,
			Description: "Merge a pull request with merge_method merge (default), squash or rebase; sha makes the merge fail unless the head is still that commit. " +
				"Returns the merge commit sha.",
			InputSchema: objectSchema([]property{ownerProperty, repoProperty, num,
				{"merge_method", "string", "merge (default), squash or rebase.", []string{"merge", "squash", "rebase"}},
				{"commit_title", "string", "Title of the merge or squash commit.", nil},
				{"commit_message", "string", "Extra detail for the merge or squash commit message.", nil},
				{"sha", "string", "Expected head sha; the merge fails if the head moved.", nil},
			}, orn),
			RequiredScopes: []string{PermissionContentsWrite}, ResourceIdentity: identity(true),
			Reconcile: connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkMerged}, ResultIDs: mergeResultIDs, Bounds: single,
		},
	}
}

// pullHandlers maps the pull request tools to their implementation.
func (c *Connector) pullHandlers() (reads, writes map[string]handler) {
	return map[string]handler{
			ToolListPullRequests: c.listPullRequests, ToolGetPullRequestDiff: c.getPullRequestDiff, ToolGetPullRequestStatus: c.getPullRequestStatus,
			ToolListPullRequestReviews: c.listPullRequestReviews, ToolListPullRequestReviewComments: c.listPullRequestReviewComments,
		}, map[string]handler{
			ToolUpdatePullRequest: c.updatePullRequest, ToolCreatePullRequestReview: c.createPullRequestReview,
			ToolRequestReviewers: c.requestReviewers, ToolMergePullRequest: c.mergePullRequest,
		}
}

// reviewersIdentity is identity(true) plus the requested reviewers and
// teams, lower-cased, sorted and comma-joined (logins and slugs are
// identifiers, not content); the reconciler checks them.
func reviewersIdentity(args map[string]any) map[string]string {
	out := identity(true)(args)
	for _, k := range []string{"reviewers", "team_reviewers"} {
		list, _ := stringList(args, k)
		if len(list) == 0 {
			continue
		}
		lower := make([]string, len(list))
		for i, s := range list {
			lower[i] = strings.ToLower(s)
		}
		slices.Sort(lower)
		out[k] = strings.Join(slices.Compact(lower), ",")
	}
	return out
}

// prArgs reads owner, repo and number.
func prArgs(args map[string]any) (owner, repo string, number int, err error) {
	if owner, repo, err = repoArgs(args); err != nil {
		return "", "", 0, err
	}
	number, err = numberArg(args)
	return owner, repo, number, err
}

// --- reads ---------------------------------------------------------------------

// PullItem is one list_pull_requests entry.
type PullItem struct {
	Number    int    `json:"number"`
	Title     string `json:"title"`
	State     string `json:"state"`
	Draft     bool   `json:"draft"`
	URL       string `json:"url"`
	User      string `json:"user,omitempty"`
	Head      string `json:"head,omitempty"`
	Base      string `json:"base,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
	MergedAt  string `json:"merged_at,omitempty"`
}

func (c *Connector) listPullRequests(ctx context.Context, client *gh.Client, call connectors.Call) (connectors.Result, error) {
	owner, repo, err := repoArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	opts := &gh.PullRequestListOptions{}
	if opts.State, err = enumArg(call.Args, "state", "open", "closed", "all"); err != nil {
		return connectors.Result{}, err
	}
	if opts.Sort, err = enumArg(call.Args, "sort", "created", "updated", "popularity", "long-running"); err != nil {
		return connectors.Result{}, err
	}
	if opts.Direction, err = enumArg(call.Args, "direction", "asc", "desc"); err != nil {
		return connectors.Result{}, err
	}
	for name, dst := range map[string]*string{"head": &opts.Head, "base": &opts.Base} {
		v, err := optionalString(call.Args, name)
		if err != nil {
			return connectors.Result{}, err
		}
		*dst = strings.TrimSpace(v)
	}
	page, perPage, clamped, err := c.pageArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	opts.ListOptions = gh.ListOptions{Page: page, PerPage: perPage}
	pulls, resp, err := client.PullRequests.List(ctx, owner, repo, opts)
	if err := classify("list pull requests", err); err != nil {
		return connectors.Result{}, err
	}
	items := make([]PullItem, 0, len(pulls))
	for _, pr := range pulls {
		if pr != nil {
			items = append(items, PullItem{Number: pr.GetNumber(), Title: pr.GetTitle(), State: pr.GetState(), Draft: pr.GetDraft(), URL: pr.GetHTMLURL(),
				User: pr.GetUser().GetLogin(), Head: pr.GetHead().GetLabel(), Base: pr.GetBase().GetRef(),
				CreatedAt: timestamp(pr.CreatedAt), UpdatedAt: timestamp(pr.UpdatedAt), MergedAt: timestamp(pr.MergedAt)})
		}
	}
	return listResult(c, items, page, perPage, resp, clamped), nil
}

// PullDiff is get_pull_request_diff's result.
type PullDiff struct {
	Number    int    `json:"number"`
	Repo      string `json:"repo"`
	Diff      string `json:"diff"`
	Truncated bool   `json:"truncated,omitempty"`
}

func (c *Connector) getPullRequestDiff(ctx context.Context, client *gh.Client, call connectors.Call) (connectors.Result, error) {
	owner, repo, number, err := prArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	data, cut, err := rawGet(ctx, client, fmt.Sprintf("repos/%s/%s/pulls/%d", owner, repo, number), diffMediaType, c.bounds.MaxResultBytes)
	if err := classify("get pull request diff", err); err != nil {
		return connectors.Result{}, err
	}
	if cut {
		data = trimPartialRune(data)
	}
	out := PullDiff{Number: number, Repo: owner + "/" + repo, Diff: string(data), Truncated: cut}
	fitBody(&out.Diff, &out.Truncated, c.bounds.MaxResultBytes, func() any { return out })
	return connectors.Result{Content: out, Partial: out.Truncated, Empty: out.Diff == "" && !out.Truncated}, nil
}

// StatusItem is one commit status context.
type StatusItem struct {
	Context     string `json:"context"`
	State       string `json:"state"`
	Description string `json:"description,omitempty"`
	URL         string `json:"url,omitempty"`
}

// CheckRunItem is one check run.
type CheckRunItem struct {
	Name        string `json:"name"`
	Status      string `json:"status"`
	Conclusion  string `json:"conclusion,omitempty"`
	URL         string `json:"url,omitempty"`
	StartedAt   string `json:"started_at,omitempty"`
	CompletedAt string `json:"completed_at,omitempty"`
}

// PullStatus is get_pull_request_status's result.
type PullStatus struct {
	Number         int            `json:"number"`
	SHA            string         `json:"sha"`
	State          string         `json:"state"`
	TotalStatuses  int            `json:"total_statuses"`
	Statuses       []StatusItem   `json:"statuses"`
	TotalCheckRuns int            `json:"total_check_runs"`
	CheckRuns      []CheckRunItem `json:"check_runs"`
	Truncated      bool           `json:"truncated,omitempty"`
}

func (c *Connector) getPullRequestStatus(ctx context.Context, client *gh.Client, call connectors.Call) (connectors.Result, error) {
	owner, repo, number, err := prArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	pr, _, err := client.PullRequests.Get(ctx, owner, repo, number)
	if err := classify("get pull request", err); err != nil {
		return connectors.Result{}, err
	}
	sha := pr.GetHead().GetSHA()
	combined, _, err := client.Repositories.GetCombinedStatus(ctx, owner, repo, sha, &gh.ListOptions{PerPage: maxPerPage})
	if err := classify("get commit status", err); err != nil {
		return connectors.Result{}, err
	}
	runs, _, err := client.Checks.ListCheckRunsForRef(ctx, owner, repo, sha, &gh.ListCheckRunsOptions{ListOptions: gh.ListOptions{PerPage: maxPerPage}})
	if err := classify("list check runs", err); err != nil {
		return connectors.Result{}, err
	}
	out := PullStatus{Number: number, SHA: sha, State: combined.GetState(), TotalStatuses: combined.GetTotalCount(), Statuses: []StatusItem{},
		TotalCheckRuns: runs.GetTotal(), CheckRuns: []CheckRunItem{}}
	for _, s := range combined.Statuses {
		if s != nil {
			out.Statuses = append(out.Statuses, StatusItem{Context: s.GetContext(), State: s.GetState(), Description: s.GetDescription(), URL: s.GetTargetURL()})
		}
	}
	for _, r := range runs.CheckRuns {
		if r != nil {
			out.CheckRuns = append(out.CheckRuns, CheckRunItem{Name: r.GetName(), Status: r.GetStatus(), Conclusion: r.GetConclusion(), URL: r.GetHTMLURL(),
				StartedAt: timestamp(r.StartedAt), CompletedAt: timestamp(r.CompletedAt)})
		}
	}
	size := func() int { return encodedSize(out) }
	out.Truncated = len(out.Statuses) < out.TotalStatuses || len(out.CheckRuns) < out.TotalCheckRuns
	if fitItems(&out.CheckRuns, c.bounds.MaxResultBytes, size) || fitItems(&out.Statuses, c.bounds.MaxResultBytes, size) {
		out.Truncated = true
	}
	return connectors.Result{Content: out, Partial: out.Truncated}, nil
}

// ReviewItem is one list_pull_request_reviews entry.
type ReviewItem struct {
	ID            int64  `json:"id"`
	User          string `json:"user,omitempty"`
	State         string `json:"state"`
	Body          string `json:"body,omitempty"`
	BodyTruncated bool   `json:"body_truncated,omitempty"`
	CommitID      string `json:"commit_id,omitempty"`
	URL           string `json:"url,omitempty"`
	SubmittedAt   string `json:"submitted_at,omitempty"`
}

func (c *Connector) listPullRequestReviews(ctx context.Context, client *gh.Client, call connectors.Call) (connectors.Result, error) {
	owner, repo, number, err := prArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	page, perPage, clamped, err := c.pageArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	reviews, resp, err := client.PullRequests.ListReviews(ctx, owner, repo, number, &gh.ListOptions{Page: page, PerPage: perPage})
	if err := classify("list pull request reviews", err); err != nil {
		return connectors.Result{}, err
	}
	items := make([]ReviewItem, 0, len(reviews))
	for _, r := range reviews {
		if r != nil {
			items = append(items, ReviewItem{ID: r.GetID(), User: r.GetUser().GetLogin(), State: r.GetState(), Body: r.GetBody(),
				CommitID: r.GetCommitID(), URL: r.GetHTMLURL(), SubmittedAt: timestamp(r.SubmittedAt)})
		}
	}
	res := listResult(c, items, page, perPage, resp, clamped)
	out := res.Content.(ListPage[ReviewItem])
	if len(out.Items) == 1 && encodedSize(out) > c.bounds.MaxResultBytes {
		fitBody(&out.Items[0].Body, &out.Items[0].BodyTruncated, c.bounds.MaxResultBytes, func() any { return out })
		res.Content, res.Partial = out, true
	}
	return res, nil
}

func (c *Connector) listPullRequestReviewComments(ctx context.Context, client *gh.Client, call connectors.Call) (connectors.Result, error) {
	owner, repo, number, err := prArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	page, perPage, clamped, err := c.pageArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	comments, resp, err := client.PullRequests.ListComments(ctx, owner, repo, number, &gh.PullRequestListCommentsOptions{ListOptions: gh.ListOptions{Page: page, PerPage: perPage}})
	if err := classify("list review comments", err); err != nil {
		return connectors.Result{}, err
	}
	items := make([]CommentItem, 0, len(comments))
	for _, cm := range comments {
		if cm != nil {
			items = append(items, CommentItem{ID: cm.GetID(), User: cm.GetUser().GetLogin(), Body: cm.GetBody(), AuthorAssociation: cm.GetAuthorAssociation(),
				Path: cm.GetPath(), Line: cm.GetLine(), Side: cm.GetSide(), InReplyTo: cm.GetInReplyTo(), ReviewID: cm.GetPullRequestReviewID(),
				URL: cm.GetHTMLURL(), CreatedAt: timestamp(cm.CreatedAt), UpdatedAt: timestamp(cm.UpdatedAt)})
		}
	}
	return commentsResult(c, items, page, perPage, resp, clamped), nil
}

// --- writes ----------------------------------------------------------------------

func (c *Connector) updatePullRequest(ctx context.Context, client *gh.Client, call connectors.Call) (connectors.Result, error) {
	owner, repo, number, err := prArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	edit := &gh.PullRequest{}
	changed := false
	for _, name := range []string{"title", "body", "base"} {
		if _, ok := call.Args[name]; !ok {
			continue
		}
		v, err := optionalString(call.Args, name)
		if err != nil {
			return connectors.Result{}, err
		}
		switch name {
		case "title":
			if strings.TrimSpace(v) == "" {
				return connectors.Result{}, invalid("title must not be blank")
			}
			edit.Title = gh.Ptr(v)
		case "body":
			edit.Body = gh.Ptr(v)
		case "base":
			if strings.TrimSpace(v) == "" {
				return connectors.Result{}, invalid("base must not be blank")
			}
			edit.Base = &gh.PullRequestBranch{Ref: gh.Ptr(strings.TrimSpace(v))}
		}
		changed = true
	}
	state, err := enumArg(call.Args, "state", "open", "closed")
	if err != nil {
		return connectors.Result{}, err
	}
	if state != "" {
		edit.State, changed = gh.Ptr(state), true
	}
	mcm, err := optionalBool(call.Args, "maintainer_can_modify")
	if err != nil {
		return connectors.Result{}, err
	}
	if mcm != nil {
		edit.MaintainerCanModify, changed = mcm, true
	}
	if !changed {
		return connectors.Result{}, invalid("give at least one field to change: title, body, state, base or maintainer_can_modify")
	}
	if state == "closed" && edit.Base != nil {
		return connectors.Result{}, invalid("GitHub cannot change the base of a pull request being closed: change base first, then close it")
	}
	pr, _, err := client.PullRequests.Edit(ctx, owner, repo, number, edit)
	if err := classifyWrite("update pull request", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: toCreatedPullRequest(pr, owner+"/"+repo)}, nil
}

// CreatedReview is create_pull_request_review's result.
type CreatedReview struct {
	ID     int64  `json:"id"`
	State  string `json:"state,omitempty"`
	URL    string `json:"url,omitempty"`
	Repo   string `json:"repo"`
	Number int    `json:"number"`
}

func reviewResultIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(CreatedReview)
	if !ok || v.ID == 0 {
		return nil
	}
	return map[string]string{"id": i64toa(v.ID), "url": v.URL}
}

// reviewComments parses the comments argument.
func reviewComments(args map[string]any) ([]*gh.DraftReviewComment, error) {
	v, ok := args["comments"]
	if !ok || v == nil {
		return nil, nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil, invalid("comments must be an array of {path, line, body} objects")
	}
	var out []*gh.DraftReviewComment
	for i, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, invalid("comments[%d] must be an object with path, line and body", i)
		}
		path, _ := m["path"].(string)
		body, _ := m["body"].(string)
		line, err := toInt(m["line"])
		if strings.TrimSpace(path) == "" || strings.TrimSpace(body) == "" || err != nil || line < 1 {
			return nil, invalid("comments[%d] needs path, a positive line and body", i)
		}
		dc := &gh.DraftReviewComment{Path: gh.Ptr(path), Body: gh.Ptr(body), Line: gh.Ptr(line)}
		if side, _ := m["side"].(string); side != "" {
			if side != "LEFT" && side != "RIGHT" {
				return nil, invalid("comments[%d].side must be LEFT or RIGHT", i)
			}
			dc.Side = gh.Ptr(side)
		}
		if sv, ok := m["start_line"]; ok && sv != nil {
			start, err := toInt(sv)
			if err != nil || start < 1 || start >= line {
				return nil, invalid("comments[%d].start_line must be a positive line before line", i)
			}
			dc.StartLine = gh.Ptr(start)
		}
		out = append(out, dc)
	}
	return out, nil
}

func (c *Connector) createPullRequestReview(ctx context.Context, client *gh.Client, call connectors.Call) (connectors.Result, error) {
	owner, repo, number, err := prArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	event, err := enumArg(call.Args, "event", "APPROVE", "REQUEST_CHANGES", "COMMENT")
	if err != nil {
		return connectors.Result{}, err
	}
	if event == "" {
		return connectors.Result{}, invalid("event is required: APPROVE, REQUEST_CHANGES or COMMENT")
	}
	body, err := optionalString(call.Args, "body")
	if err != nil {
		return connectors.Result{}, err
	}
	if event != "APPROVE" && strings.TrimSpace(body) == "" {
		return connectors.Result{}, invalid("body is required for %s", event)
	}
	comments, err := reviewComments(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	req := &gh.PullRequestReviewRequest{Event: gh.Ptr(event), Body: gh.Ptr(withMarker(body, call.OperationID)), Comments: comments}
	commit, err := optionalString(call.Args, "commit_id")
	if err != nil {
		return connectors.Result{}, err
	}
	if commit = strings.TrimSpace(commit); commit != "" {
		req.CommitID = gh.Ptr(commit)
	}
	review, _, err := client.PullRequests.CreateReview(ctx, owner, repo, number, req)
	if err := classifyWrite("create pull request review", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: CreatedReview{ID: review.GetID(), State: review.GetState(), URL: review.GetHTMLURL(), Repo: owner + "/" + repo, Number: number}}, nil
}

// RequestedReviewers is request_reviewers's result.
type RequestedReviewers struct {
	Number        int      `json:"number"`
	URL           string   `json:"url,omitempty"`
	Repo          string   `json:"repo"`
	Reviewers     []string `json:"requested_reviewers,omitempty"`
	TeamReviewers []string `json:"requested_teams,omitempty"`
}

func reviewersResultIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(RequestedReviewers)
	if !ok || v.Number == 0 {
		return nil
	}
	return map[string]string{"number": itoa(v.Number), "url": v.URL}
}

func (c *Connector) requestReviewers(ctx context.Context, client *gh.Client, call connectors.Call) (connectors.Result, error) {
	owner, repo, number, err := prArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	users, err := stringList(call.Args, "reviewers")
	if err != nil {
		return connectors.Result{}, err
	}
	teams, err := stringList(call.Args, "team_reviewers")
	if err != nil {
		return connectors.Result{}, err
	}
	if len(users) == 0 && len(teams) == 0 {
		return connectors.Result{}, invalid("give reviewers (logins) or team_reviewers (team slugs)")
	}
	pr, _, err := client.PullRequests.RequestReviewers(ctx, owner, repo, number, gh.ReviewersRequest{Reviewers: users, TeamReviewers: teams})
	if err := classifyWrite("request reviewers", err); err != nil {
		return connectors.Result{}, err
	}
	out := RequestedReviewers{Number: number, URL: pr.GetHTMLURL(), Repo: owner + "/" + repo, Reviewers: logins(pr.RequestedReviewers)}
	for _, tm := range pr.RequestedTeams {
		if tm != nil {
			out.TeamReviewers = append(out.TeamReviewers, tm.GetSlug())
		}
	}
	return connectors.Result{Content: out}, nil
}

// MergeResult is merge_pull_request's result.
type MergeResult struct {
	Number  int    `json:"number"`
	Merged  bool   `json:"merged"`
	SHA     string `json:"sha,omitempty"`
	Message string `json:"message,omitempty"`
	Repo    string `json:"repo"`
}

func mergeResultIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(MergeResult)
	if !ok || v.Number == 0 {
		return nil
	}
	return map[string]string{"number": itoa(v.Number), "sha": v.SHA}
}

func (c *Connector) mergePullRequest(ctx context.Context, client *gh.Client, call connectors.Call) (connectors.Result, error) {
	owner, repo, number, err := prArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	method, err := enumArg(call.Args, "merge_method", "merge", "squash", "rebase")
	if err != nil {
		return connectors.Result{}, err
	}
	opts := &gh.PullRequestOptions{MergeMethod: method}
	if opts.CommitTitle, err = optionalString(call.Args, "commit_title"); err != nil {
		return connectors.Result{}, err
	}
	if opts.SHA, err = optionalString(call.Args, "sha"); err != nil {
		return connectors.Result{}, err
	}
	opts.SHA = strings.TrimSpace(opts.SHA)
	message, err := optionalString(call.Args, "commit_message")
	if err != nil {
		return connectors.Result{}, err
	}
	merged, _, err := client.PullRequests.Merge(ctx, owner, repo, number, message, opts)
	if err := classifyWrite("merge pull request", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: MergeResult{Number: number, Merged: merged.GetMerged(), SHA: merged.GetSHA(), Message: merged.GetMessage(), Repo: owner + "/" + repo}}, nil
}

// --- reconciliation ----------------------------------------------------------------

// identityNumber reads the pull request number from the resource identity.
func identityNumber(in connectors.ReconcileInput) (int, error) {
	n, err := strconv.Atoi(in.ResourceIdentity["number"])
	if err != nil || n < 1 {
		return 0, fmt.Errorf("%w: resource identity has no pull request number", ErrNotReconcilable)
	}
	return n, nil
}

// checkReview is create_pull_request_review's marker reconciliation:
// the pull request's reviews (listed oldest first) are read newest first
// like checkComment's, bounded by MaxReconcilePages. The marker in a
// review body is found; every page read without it is not_found; running
// out of pages or a listing error is "cannot tell yet".
func (c *Connector) checkReview(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	number, err := identityNumber(in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	tg, err := c.target(ctx, in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	return scanNewestFirst(func(page int) (string, int, error) {
		reviews, resp, err := tg.client.PullRequests.ListReviews(ctx, tg.owner, tg.repo, number, &gh.ListOptions{PerPage: reconcilePerPage, Page: page})
		if err := classify("reconcile: list reviews", err); err != nil {
			return "", 0, err
		}
		for _, r := range reviews {
			if r != nil && hasMarker(r.GetBody(), tg.operationID) {
				return i64toa(r.GetID()), resp.LastPage, nil
			}
		}
		return "", resp.LastPage, nil
	}, fmt.Sprintf("reviews on %s/%s#%d", tg.owner, tg.repo, number))
}

// scanNewestFirst walks an oldest-first paginated listing newest first:
// page 1 tells the last page, then the pages are read backwards, at most
// MaxReconcilePages in all. scan returns the id of the match on a page,
// if any, and the last page number.
func scanNewestFirst(scan func(page int) (id string, last int, err error), what string) (connectors.ReconcileResult, error) {
	id, last, err := scan(1)
	switch {
	case err != nil:
		return connectors.ReconcileResult{}, err
	case id != "":
		return found(id), nil
	case last <= 1:
		return notFound, nil
	}
	for page, reads := last, 1; page >= 2; page-- {
		if reads++; reads > MaxReconcilePages {
			return connectors.ReconcileResult{}, fmt.Errorf("github: reconcile: more than %d pages of %s; cannot tell yet", MaxReconcilePages, what)
		}
		id, _, err := scan(page)
		if err != nil {
			return connectors.ReconcileResult{}, err
		}
		if id != "" {
			return found(id), nil
		}
	}
	return notFound, nil
}

// checkReviewers is request_reviewers's stable-id reconciliation: every
// requested login and team is pending on the pull request: found. A
// missing one cannot be read as not_found (a reviewer who already
// reviewed leaves the pending list), so that is "cannot tell yet" and
// the operation ends unresolved for the user to check.
func (c *Connector) checkReviewers(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	number, err := identityNumber(in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	tg, err := c.target(ctx, in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	pending, _, err := tg.client.PullRequests.ListReviewers(ctx, tg.owner, tg.repo, number)
	if err := classify("reconcile: list requested reviewers", err); err != nil {
		return connectors.ReconcileResult{}, err
	}
	have := map[string]bool{}
	for _, u := range pending.Users {
		have["u:"+strings.ToLower(u.GetLogin())] = true
	}
	for _, tm := range pending.Teams {
		have["t:"+strings.ToLower(tm.GetSlug())] = true
	}
	for key, prefix := range map[string]string{"reviewers": "u:", "team_reviewers": "t:"} {
		for _, name := range strings.Split(in.ResourceIdentity[key], ",") {
			if name != "" && !have[prefix+name] {
				return connectors.ReconcileResult{}, fmt.Errorf("github: reconcile: %s is not pending on %s/%s#%d (never requested, or already reviewed); cannot tell", name, tg.owner, tg.repo, number)
			}
		}
	}
	return found(strconv.Itoa(number)), nil
}

// checkMerged is merge_pull_request's stable-id reconciliation:
// GET .../pulls/{n}/merge answers 204 when merged (found) and 404 when
// not (not_found); anything else is "cannot tell yet".
func (c *Connector) checkMerged(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	number, err := identityNumber(in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	tg, err := c.target(ctx, in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	merged, _, err := tg.client.PullRequests.IsMerged(ctx, tg.owner, tg.repo, number)
	if err := classify("reconcile: is merged", err); err != nil {
		return connectors.ReconcileResult{}, err
	}
	if merged {
		return found(strconv.Itoa(number)), nil
	}
	return notFound, nil
}
