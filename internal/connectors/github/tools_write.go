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
	"fmt"
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

// --- markers and shared write helpers ------------------------------------------------

// markerPhrase is the searchable text inside the marker; the HTML
// comment delimiters around it hide it from readers.
const markerPhrase = "mcp-gateway op:"

// Marker returns the hidden comment for a ledger operation:
// "<!-- mcp-gateway op:<operation id> -->". GitHub renders nothing for
// an HTML comment, so the marker never shows on the issue, comment or
// pull request, while the reconciler can search for it.
func Marker(operationID string) string { return "<!-- " + markerPhrase + operationID + " -->" }

// withMarker appends the operation's marker to body (on its own
// paragraph; just the marker when body is empty).
func withMarker(body, operationID string) string {
	body = strings.TrimRight(body, " \t\r\n")
	if body == "" {
		return Marker(operationID)
	}
	return body + "\n\n" + Marker(operationID)
}

// hasMarker reports whether text carries the operation's marker.
func hasMarker(text, operationID string) bool {
	return operationID != "" && strings.Contains(text, Marker(operationID))
}

// requiredString reads a non-blank string argument.
func requiredString(args map[string]any, name string) (string, error) {
	v, _ := args[name].(string)
	v = strings.TrimSpace(v)
	if v == "" {
		return "", invalid("%s is required", name)
	}
	return v, nil
}

// optionalString reads a string argument, "" when absent.
func optionalString(args map[string]any, name string) (string, error) {
	v, ok := args[name]
	if !ok || v == nil {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", invalid("%s must be a string", name)
	}
	return s, nil
}

// stringList reads an optional array-of-strings argument; blank entries
// are dropped and nil is returned when nothing remains.
func stringList(args map[string]any, name string) ([]string, error) {
	v, ok := args[name]
	if !ok || v == nil {
		return nil, nil
	}
	var out []string
	switch list := v.(type) {
	case []string:
		out = append(out, list...)
	case []any:
		for _, item := range list {
			s, ok := item.(string)
			if !ok {
				return nil, invalid("%s must be an array of strings", name)
			}
			out = append(out, s)
		}
	default:
		return nil, invalid("%s must be an array of strings", name)
	}
	kept := out[:0]
	for _, s := range out {
		if s = strings.TrimSpace(s); s != "" {
			kept = append(kept, s)
		}
	}
	if len(kept) == 0 {
		return nil, nil
	}
	return kept, nil
}

// classifyWrite maps the error of the request that performs a write:
// an answer from GitHub (4xx, rate limit) is a known outcome and is
// classified like a read's; anything that leaves the outcome open (5xx,
// a timeout, a cancelled context, a dropped connection: the request may
// have been applied) wraps connectors.ErrOutcomeUnknown so the ledger
// marks the operation unknown and the reconciler checks it.
func classifyWrite(action string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return fmt.Errorf("%w: %s: GitHub did not answer in time (%w)", connectors.ErrOutcomeUnknown, action, err)
	}
	classified := classify(action, err)
	var e *Error
	if errors.As(classified, &e) && e.Class == ClassUnavailable {
		return fmt.Errorf("%w: %w", connectors.ErrOutcomeUnknown, classified)
	}
	return classified
}

// --- handlers -------------------------------------------------------------------------

func (c *Connector) createIssue(ctx context.Context, client *gh.Client, call connectors.Call) (connectors.Result, error) {
	owner, repo, err := repoArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	title, err := requiredString(call.Args, "title")
	if err != nil {
		return connectors.Result{}, err
	}
	body, err := optionalString(call.Args, "body")
	if err != nil {
		return connectors.Result{}, err
	}
	labels, err := stringList(call.Args, "labels")
	if err != nil {
		return connectors.Result{}, err
	}
	assignees, err := stringList(call.Args, "assignees")
	if err != nil {
		return connectors.Result{}, err
	}
	req := gh.CreateIssueRequest{Title: title, Body: gh.Ptr(withMarker(body, call.OperationID)), Labels: labels, Assignees: assignees}
	is, _, err := client.Issues.Create(ctx, owner, repo, req)
	if err := classifyWrite("create issue", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: toCreatedIssue(is, owner+"/"+repo)}, nil
}

func (c *Connector) addIssueComment(ctx context.Context, client *gh.Client, call connectors.Call) (connectors.Result, error) {
	owner, repo, err := repoArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	number, err := numberArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	body, err := requiredString(call.Args, "body")
	if err != nil {
		return connectors.Result{}, err
	}
	cm, _, err := client.Issues.CreateComment(ctx, owner, repo, number, &gh.IssueComment{Body: gh.Ptr(withMarker(body, call.OperationID))})
	if err := classifyWrite("add issue comment", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: toCreatedComment(cm, owner+"/"+repo, number)}, nil
}

func (c *Connector) createPullRequest(ctx context.Context, client *gh.Client, call connectors.Call) (connectors.Result, error) {
	owner, repo, err := repoArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	title, err := requiredString(call.Args, "title")
	if err != nil {
		return connectors.Result{}, err
	}
	head, err := requiredString(call.Args, "head")
	if err != nil {
		return connectors.Result{}, err
	}
	base, err := requiredString(call.Args, "base")
	if err != nil {
		return connectors.Result{}, err
	}
	body, err := optionalString(call.Args, "body")
	if err != nil {
		return connectors.Result{}, err
	}
	req := gh.CreatePullRequest{Title: gh.Ptr(title), Head: head, Base: base, Body: gh.Ptr(withMarker(body, call.OperationID))}
	if v, ok := call.Args["draft"]; ok && v != nil {
		draft, ok := v.(bool)
		if !ok {
			return connectors.Result{}, invalid("draft must be a boolean")
		}
		req.Draft = gh.Ptr(draft)
	}
	pr, _, err := client.PullRequests.Create(ctx, owner, repo, req)
	if err := classifyWrite("create pull request", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: toCreatedPullRequest(pr, owner+"/"+repo)}, nil
}

// createBranch resolves the source branch (the repository's default
// branch unless from_branch is given), reads its commit and creates the
// ref. The lookups before the write are reads: their failures are known
// outcomes (classify); only the ref creation itself can be unknown
// (classifyWrite).
func (c *Connector) createBranch(ctx context.Context, client *gh.Client, call connectors.Call) (connectors.Result, error) {
	owner, repo, err := repoArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	branch, err := requiredString(call.Args, "branch")
	if err != nil {
		return connectors.Result{}, err
	}
	from, err := optionalString(call.Args, "from_branch")
	if err != nil {
		return connectors.Result{}, err
	}
	if from = strings.TrimSpace(from); from == "" {
		repository, _, err := client.Repositories.Get(ctx, owner, repo)
		if err := classify("get repository", err); err != nil {
			return connectors.Result{}, err
		}
		if from = repository.GetDefaultBranch(); from == "" {
			return connectors.Result{}, &Error{Class: ClassVendorError, Message: "get repository: GitHub reported no default branch; pass from_branch"}
		}
	}
	source, _, err := client.Git.GetRef(ctx, owner, repo, "heads/"+from)
	if err := classify("get source branch", err); err != nil {
		return connectors.Result{}, err
	}
	created, _, err := client.Git.CreateRef(ctx, owner, repo, gh.CreateRef{Ref: "refs/heads/" + branch, SHA: source.GetObject().GetSHA()})
	if err := classifyWrite("create branch", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: toCreatedBranch(created, owner+"/"+repo, branch)}, nil
}
