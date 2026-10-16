// Tool descriptions, argument shapes and the search query handling are
// adapted from github/github-mcp-server, pkg/github/context_tools.go,
// issues.go, pullrequests.go, search_utils.go and params.go (commit
// eb47a99ddb866ca2b8a162920e6bda9521f33ebb), MIT License, Copyright (c)
// 2025 GitHub. Modified for mcp-gateway: one tool per read instead of a
// method-switching tool, snake_case page/per_page clamped to the
// gateway's bounds, resource identity for policy and audit, the
// connectors.Result markers, and no GraphQL enrichment. See
// THIRD_PARTY_NOTICES.md.

package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"

	gh "github.com/google/go-github/v90/github"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Tool names.
const (
	ToolGetMe                = "get_me"
	ToolSearchIssues         = "search_issues"
	ToolGetIssue             = "get_issue"
	ToolGetPullRequest       = "get_pull_request"
	ToolListPullRequestFiles = "list_pull_request_files"
)

// GitHub App permissions (as "<permission>:<access>") each tool needs;
// declared as RequiredScopes for documentation and future scope checks.
// GitHub App user tokens carry no scopes, so nothing hides on them today.
const (
	PermissionIssuesRead       = "issues:read"
	PermissionPullRequestsRead = "pull_requests:read"
)

// maxPerPage is GitHub's own per_page ceiling.
const maxPerPage = 100

// defaultPerPage is the page size when the harness gives none (GitHub's
// default), capped by the bounds.
const defaultPerPage = 30

// nameRE is the shape of a repository owner or name.
var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// readTools declares the five read tools.
func (c *Connector) readTools() []connectors.Tool {
	paged := connectors.Bounds{MaxPageSize: c.bounds.MaxPageSize, MaxResultBytes: c.bounds.MaxResultBytes}
	single := connectors.Bounds{MaxResultBytes: c.bounds.MaxResultBytes}
	return []connectors.Tool{
		{
			App: App, Name: ToolGetMe, Kind: connectors.KindRead,
			Description: "Get the authenticated GitHub user: login, id, name and profile. Use it when a request is about " +
				"the user's own GitHub profile, or to learn the login before other calls.",
			InputSchema:      objectSchema(nil, nil),
			ResourceIdentity: identity(false),
			Bounds:           single,
		},
		{
			App: App, Name: ToolSearchIssues, Kind: connectors.KindRead,
			Description: "Search issues and pull requests across GitHub with the issues search syntax " +
				"(qualifiers such as is:issue, is:pr, is:open, label:bug, author:login, repo:owner/name). " +
				"Give owner and repo to limit the search to one repository. Results are limited to what the connected account " +
				"can see; a page lists number, title, state, url and repo per item.",
			InputSchema: objectSchema([]property{
				{"q", "string", "Search query in GitHub issues search syntax.", nil},
				{"owner", "string", "Optional repository owner; with repo, limits the search to that repository.", nil},
				{"repo", "string", "Optional repository name; with owner, limits the search to that repository.", nil},
				{"sort", "string", "Sort field: comments, reactions, interactions, created or updated. Default: best match.", []string{"comments", "reactions", "reactions-+1", "reactions--1", "reactions-smile", "reactions-thinking_face", "reactions-heart", "reactions-tada", "interactions", "created", "updated"}},
				{"order", "string", "Sort order: asc or desc.", []string{"asc", "desc"}},
				pageProperty, perPageProperty,
			}, []string{"q"}),
			ResourceIdentity: identity(false),
			Bounds:           paged,
		},
		{
			App: App, Name: ToolGetIssue, Kind: connectors.KindRead,
			Description: "Get one issue of a repository by number: title, body, state, labels, assignees, milestone and timestamps. " +
				"Pull requests are issues too; use get_pull_request for branch and merge details.",
			InputSchema:      objectSchema([]property{ownerProperty, repoProperty, {"number", "integer", "The issue number.", nil}}, []string{"owner", "repo", "number"}),
			RequiredScopes:   []string{PermissionIssuesRead},
			ResourceIdentity: identity(true),
			Bounds:           single,
		},
		{
			App: App, Name: ToolGetPullRequest, Kind: connectors.KindRead,
			Description: "Get one pull request of a repository by number: title, body, state, draft and merge status, head and base " +
				"branches, reviewers, and the size of the change.",
			InputSchema:      objectSchema([]property{ownerProperty, repoProperty, {"number", "integer", "The pull request number.", nil}}, []string{"owner", "repo", "number"}),
			RequiredScopes:   []string{PermissionPullRequestsRead},
			ResourceIdentity: identity(true),
			Bounds:           single,
		},
		{
			App: App, Name: ToolListPullRequestFiles, Kind: connectors.KindRead,
			Description: "List the files changed by a pull request with their status, line counts and unified diff patch. " +
				"Paginated: use page and per_page; has_more says whether another page exists.",
			InputSchema:      objectSchema([]property{ownerProperty, repoProperty, {"number", "integer", "The pull request number.", nil}, pageProperty, perPageProperty}, []string{"owner", "repo", "number"}),
			RequiredScopes:   []string{PermissionPullRequestsRead},
			ResourceIdentity: identity(true),
			Bounds:           paged,
		},
	}
}

// handlers maps short tool names to their implementation.
func (c *Connector) handlers() map[string]handler {
	return map[string]handler{
		ToolGetMe:                c.getMe,
		ToolSearchIssues:         c.searchIssues,
		ToolGetIssue:             c.getIssue,
		ToolGetPullRequest:       c.getPullRequest,
		ToolListPullRequestFiles: c.listPullRequestFiles,
	}
}

// --- schema helpers ----------------------------------------------------------

// property is one input-schema property: name, type, description and
// optional enum values.
type property struct {
	Name, Type, Description string
	Enum                    []string
}

var (
	ownerProperty   = property{"owner", "string", "Repository owner (user or organization login).", nil}
	repoProperty    = property{"repo", "string", "Repository name (without the owner).", nil}
	pageProperty    = property{"page", "integer", "Page number, starting at 1.", nil}
	perPageProperty = property{"per_page", "integer", "Results per page (1-100); clamped to the tool's maximum.", nil}
)

// objectSchema builds a closed object schema with the given properties
// and required names.
func objectSchema(props []property, required []string) json.RawMessage {
	type schemaProp struct {
		Type        string   `json:"type"`
		Description string   `json:"description"`
		Enum        []string `json:"enum,omitempty"`
		Minimum     *int     `json:"minimum,omitempty"`
		Maximum     *int     `json:"maximum,omitempty"`
	}
	properties := map[string]schemaProp{}
	for _, p := range props {
		sp := schemaProp{Type: p.Type, Description: p.Description, Enum: p.Enum}
		switch p.Name {
		case "page", "number", "run_id", "job_id", "tail_lines", "milestone":
			one := 1
			sp.Minimum = &one
		case "per_page":
			one, max := 1, maxPerPage
			sp.Minimum, sp.Maximum = &one, &max
		}
		properties[p.Name] = sp
	}
	schema := map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
	if len(required) > 0 {
		schema["required"] = required
	}
	b, err := json.Marshal(schema)
	if err != nil {
		panic(err)
	}
	return b
}

// identity extracts owner, repo ("owner/name"), org (= owner) and, when
// withNumber, number from the arguments; never argument content.
func identity(withNumber bool) func(map[string]any) map[string]string {
	return func(args map[string]any) map[string]string {
		out := map[string]string{}
		owner, _ := args["owner"].(string)
		repo, _ := args["repo"].(string)
		owner, repo = strings.ToLower(strings.TrimSpace(owner)), strings.ToLower(strings.TrimSpace(repo))
		if owner != "" {
			out["owner"] = owner
			out["org"] = owner
		}
		if owner != "" && repo != "" {
			out["repo"] = owner + "/" + repo
		}
		if withNumber {
			if n, err := toInt(args["number"]); err == nil && n > 0 {
				out["number"] = strconv.Itoa(n)
			}
		}
		return out
	}
}

// --- argument helpers ---------------------------------------------------------

func invalid(format string, a ...any) error {
	return &Error{Class: ClassInvalidArgument, Message: fmt.Sprintf(format, a...)}
}

// repoArgs reads and validates owner and repo.
func repoArgs(args map[string]any) (owner, repo string, err error) {
	owner, _ = args["owner"].(string)
	repo, _ = args["repo"].(string)
	owner, repo = strings.TrimSpace(owner), strings.TrimSpace(repo)
	if !nameRE.MatchString(owner) {
		return "", "", invalid("owner is required: the repository owner's login, without the repository name")
	}
	if !nameRE.MatchString(repo) {
		return "", "", invalid("repo is required: the repository name, without the owner")
	}
	return owner, repo, nil
}

// numberArg reads the positive integer "number" argument (an issue or
// pull request number).
func numberArg(args map[string]any) (int, error) {
	v, ok := args["number"]
	if !ok {
		return 0, invalid("number is required")
	}
	n, err := toInt(v)
	if err != nil || n < 1 {
		return 0, invalid("number must be a positive integer")
	}
	return n, nil
}

// pageArgs reads page and per_page; per_page defaults to defaultPerPage
// and is clamped to the bounds (clamped reports when it was).
func (c *Connector) pageArgs(args map[string]any) (page, perPage int, clamped bool, err error) {
	page, perPage = 1, min(defaultPerPage, c.bounds.MaxPageSize)
	if v, ok := args["page"]; ok {
		if page, err = toInt(v); err != nil || page < 1 {
			return 0, 0, false, invalid("page must be a positive integer")
		}
	}
	if v, ok := args["per_page"]; ok {
		if perPage, err = toInt(v); err != nil || perPage < 1 {
			return 0, 0, false, invalid("per_page must be a positive integer")
		}
		if perPage > c.bounds.MaxPageSize {
			perPage, clamped = c.bounds.MaxPageSize, true
		}
	}
	return page, perPage, clamped, nil
}

func toInt(v any) (int, error) {
	switch n := v.(type) {
	case int:
		return n, nil
	case int64:
		return int(n), nil
	case float64:
		if n != math.Trunc(n) || math.IsInf(n, 0) || math.IsNaN(n) {
			return 0, errors.New("not an integer")
		}
		return int(n), nil
	case json.Number:
		i, err := n.Int64()
		return int(i), err
	case string:
		return strconv.Atoi(strings.TrimSpace(n))
	}
	return 0, fmt.Errorf("not an integer: %T", v)
}

// --- handlers -------------------------------------------------------------------

func (c *Connector) getMe(ctx context.Context, client *gh.Client, _ connectors.Call) (connectors.Result, error) {
	user, _, err := client.Users.Get(ctx, "")
	if err := classify("get user", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: toUser(user)}, nil
}

func (c *Connector) searchIssues(ctx context.Context, client *gh.Client, call connectors.Call) (connectors.Result, error) {
	q, _ := call.Args["q"].(string)
	q = strings.TrimSpace(q)
	if q == "" {
		return connectors.Result{}, invalid("q is required: a GitHub issues search query")
	}
	owner, _ := call.Args["owner"].(string)
	repo, _ := call.Args["repo"].(string)
	owner, repo = strings.TrimSpace(owner), strings.TrimSpace(repo)
	if owner != "" && repo != "" {
		if !nameRE.MatchString(owner) || !nameRE.MatchString(repo) {
			return connectors.Result{}, invalid("owner and repo must be a repository owner and name")
		}
		if !hasQualifier(q, "repo") {
			q = "repo:" + owner + "/" + repo + " " + q
		}
	}
	page, perPage, clamped, err := c.pageArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	sortBy, _ := call.Args["sort"].(string)
	order, _ := call.Args["order"].(string)
	opts := &gh.SearchOptions{Sort: sortBy, Order: order, ListOptions: gh.ListOptions{Page: page, PerPage: perPage}}
	result, resp, err := client.Search.Issues(ctx, q, opts)
	if err := classify("search issues", err); err != nil {
		return connectors.Result{}, err
	}
	out := SearchPage{TotalCount: result.GetTotal(), IncompleteResults: result.GetIncompleteResults(), Page: page, PerPage: perPage, HasMore: resp.NextPage > 0, Items: make([]SearchItem, 0, len(result.Issues))}
	for _, is := range result.Issues {
		if is != nil {
			out.Items = append(out.Items, toSearchItem(is))
		}
	}
	res := connectors.Result{Partial: clamped || out.IncompleteResults, Empty: len(out.Items) == 0}
	for encodedSize(out) > c.bounds.MaxResultBytes && len(out.Items) > 1 {
		out.Items = out.Items[:len(out.Items)-1]
		out.Truncated, res.Partial = true, true
	}
	res.Content = out
	return res, nil
}

// hasQualifier reports whether q already carries "<name>:".
func hasQualifier(q, name string) bool {
	for _, f := range strings.Fields(q) {
		if strings.HasPrefix(strings.ToLower(f), name+":") {
			return true
		}
	}
	return false
}

func (c *Connector) getIssue(ctx context.Context, client *gh.Client, call connectors.Call) (connectors.Result, error) {
	owner, repo, err := repoArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	number, err := numberArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	is, _, err := client.Issues.Get(ctx, owner, repo, number)
	if err := classify("get issue", err); err != nil {
		return connectors.Result{}, err
	}
	out := toIssue(is, owner+"/"+repo)
	fitBody(&out.Body, &out.Truncated, c.bounds.MaxResultBytes, func() any { return out })
	return connectors.Result{Content: out, Partial: out.Truncated}, nil
}

func (c *Connector) getPullRequest(ctx context.Context, client *gh.Client, call connectors.Call) (connectors.Result, error) {
	owner, repo, err := repoArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	number, err := numberArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	pr, _, err := client.PullRequests.Get(ctx, owner, repo, number)
	if err := classify("get pull request", err); err != nil {
		return connectors.Result{}, err
	}
	out := toPullRequest(pr, owner+"/"+repo)
	fitBody(&out.Body, &out.Truncated, c.bounds.MaxResultBytes, func() any { return out })
	return connectors.Result{Content: out, Partial: out.Truncated}, nil
}

func (c *Connector) listPullRequestFiles(ctx context.Context, client *gh.Client, call connectors.Call) (connectors.Result, error) {
	owner, repo, err := repoArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	number, err := numberArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	page, perPage, clamped, err := c.pageArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	files, resp, err := client.PullRequests.ListFiles(ctx, owner, repo, number, &gh.ListOptions{Page: page, PerPage: perPage})
	if err := classify("list pull request files", err); err != nil {
		return connectors.Result{}, err
	}
	out := FilesPage{Page: page, PerPage: perPage, HasMore: resp.NextPage > 0, Files: toFiles(files)}
	res := connectors.Result{Partial: clamped, Empty: len(out.Files) == 0}
	// Over the bounds: drop patches largest first, then whole files from
	// the end (never below one), so the harness still sees which files
	// changed.
	if fitFiles(&out.Files, c.bounds.MaxResultBytes, func() int { return encodedSize(out) }, &out.Truncated) {
		res.Partial = true
	}
	res.Content = out
	return res, nil
}

// fitBody cuts *body (and sets *truncated) until the object returned by
// obj, which must read both through the same pointers, serialises to at
// most max bytes or the body is gone. Everything but the body stays.
func fitBody(body *string, truncated *bool, max int, obj func() any) {
	if encodedSize(obj()) <= max {
		return
	}
	*truncated = true
	for *body != "" {
		size := encodedSize(obj())
		if size <= max {
			return
		}
		cut := len(*body) - (size - max) - 1
		if cut < 0 {
			cut = 0
		}
		// Keep the cut on a rune boundary.
		for cut > 0 && cut < len(*body) && !isRuneStart((*body)[cut]) {
			cut--
		}
		*body = (*body)[:cut]
	}
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }
