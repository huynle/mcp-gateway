package github

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	gh "github.com/google/go-github/v90/github"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// MaxReconcilePages bounds how many pages (of reconcilePerPage items) a
// reconciliation check walks before giving up with "cannot tell yet";
// the reconciler retries later with backoff and, after its own limits,
// hands the operation to the user as unresolved.
const MaxReconcilePages = 5

// reconcilePerPage is the page size the checks list with (GitHub's
// maximum).
const reconcilePerPage = 100

// ErrNotReconcilable says the ledger row lacks what the check needs (an
// operation id, the repository, the issue number or the branch in the
// resource identity); the reconciler treats it as "cannot tell".
var ErrNotReconcilable = errors.New("github: operation cannot be reconciled")

// reconcileTarget is what every check starts from: the repository the
// write targeted (from the resource identity the ledger stored), the
// operation id (the marker) and an authenticated client for the same
// account the write ran under.
type reconcileTarget struct {
	owner, repo, operationID string
	client                   *gh.Client
}

// target validates the input and builds the client. Call.Args are empty
// when the reconciler runs from the ledger; everything comes from
// ResourceIdentity and OperationID (decision enlsy40f).
func (c *Connector) target(ctx context.Context, in connectors.ReconcileInput) (reconcileTarget, error) {
	opID := in.OperationID
	if opID == "" {
		opID = in.Call.OperationID
	}
	if opID == "" {
		return reconcileTarget{}, fmt.Errorf("%w: no operation id", ErrNotReconcilable)
	}
	owner, name, ok := strings.Cut(in.ResourceIdentity["repo"], "/")
	if !ok || !nameRE.MatchString(owner) || !nameRE.MatchString(name) {
		return reconcileTarget{}, fmt.Errorf("%w: resource identity has no repository", ErrNotReconcilable)
	}
	if in.Call.Account == "" {
		return reconcileTarget{}, fmt.Errorf("%w: no account", ErrNotReconcilable)
	}
	client, err := c.client(ctx, in.Call)
	if err != nil {
		return reconcileTarget{}, err
	}
	return reconcileTarget{owner: owner, repo: name, operationID: opID, client: client}, nil
}

// found builds a found result.
func found(id string) connectors.ReconcileResult {
	return connectors.ReconcileResult{Outcome: connectors.ReconcileFound, ResourceID: id}
}

// notFound is the definite negative.
var notFound = connectors.ReconcileResult{Outcome: connectors.ReconcileNotFound}

// --- create_issue -------------------------------------------------------------

// checkIssue is create_issue's marker reconciliation. The search API
// (repo:owner/name "mcp-gateway op:<id>" in:body) is tried first: a hit
// whose body carries the marker is the issue. Search only ever proves
// presence (its index lags and may not cover HTML comments), so a miss
// or a search error falls back to listing the repository's issues
// created by the authenticated user, newest first, bounded by
// MaxReconcilePages: the marker on any page is found; reaching the end
// of the list without it is not_found; running out of pages, or any
// listing error, is "cannot tell yet".
func (c *Connector) checkIssue(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	tg, err := c.target(ctx, in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	if is := tg.searchMarker(ctx); is != nil {
		return found(strconv.Itoa(is.GetNumber())), nil
	}
	me, _, err := tg.client.Users.Get(ctx, "")
	if err := classify("reconcile: get user", err); err != nil {
		return connectors.ReconcileResult{}, err
	}
	opts := &gh.IssueListByRepoOptions{
		Creator: me.GetLogin(), State: "all", Sort: "created", Direction: "desc",
		ListOptions: gh.ListOptions{PerPage: reconcilePerPage, Page: 1},
	}
	for page := 1; page <= MaxReconcilePages; page++ {
		opts.ListOptions.Page = page
		issues, resp, err := tg.client.Issues.ListByRepo(ctx, tg.owner, tg.repo, opts)
		if err := classify("reconcile: list issues", err); err != nil {
			return connectors.ReconcileResult{}, err
		}
		for _, is := range issues {
			if is != nil && !is.IsPullRequest() && hasMarker(is.GetBody(), tg.operationID) {
				return found(strconv.Itoa(is.GetNumber())), nil
			}
		}
		if resp.NextPage == 0 {
			return notFound, nil
		}
	}
	return connectors.ReconcileResult{}, fmt.Errorf("github: reconcile: more than %d pages of recent issues by this user in %s/%s; cannot tell yet", MaxReconcilePages, tg.owner, tg.repo)
}

// searchMarker asks the search API for the marker and returns the issue
// whose body carries it, or nil (a miss, an error, or hits without the
// marker: never trusted as absence).
func (tg reconcileTarget) searchMarker(ctx context.Context) *gh.Issue {
	q := fmt.Sprintf("repo:%s/%s %q in:body", tg.owner, tg.repo, markerPhrase+tg.operationID)
	result, _, err := tg.client.Search.Issues(ctx, q, &gh.SearchOptions{ListOptions: gh.ListOptions{PerPage: 10}})
	if err != nil || result == nil {
		return nil
	}
	for _, is := range result.Issues {
		if is != nil && !is.IsPullRequest() && hasMarker(is.GetBody(), tg.operationID) {
			return is
		}
	}
	return nil
}

// --- the other writes (filled in by the following increments) --------------------

// --- add_issue_comment -----------------------------------------------------------

// checkComment is add_issue_comment's marker reconciliation: the issue's
// comments, which GitHub lists oldest first, are read newest first (the
// first page tells where the last one is, then the pages are walked
// backwards) bounded by MaxReconcilePages. The marker on any page is
// found; every page read without it is not_found; running out of pages,
// or any listing error (including a 404: the account may have lost
// access rather than the issue being gone), is "cannot tell yet".
func (c *Connector) checkComment(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	tg, err := c.target(ctx, in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	number, err := strconv.Atoi(in.ResourceIdentity["number"])
	if err != nil || number < 1 {
		return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no issue number", ErrNotReconcilable)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	scan := func(page int) (id string, last int, err error) {
		opts := &gh.IssueListCommentsOptions{ListOptions: gh.ListOptions{PerPage: reconcilePerPage, Page: page}}
		comments, resp, err := tg.client.Issues.ListComments(ctx, tg.owner, tg.repo, number, opts)
		if err := classify("reconcile: list comments", err); err != nil {
			return "", 0, err
		}
		for _, cm := range comments {
			if cm != nil && hasMarker(cm.GetBody(), tg.operationID) {
				return strconv.FormatInt(cm.GetID(), 10), resp.LastPage, nil
			}
		}
		return "", resp.LastPage, nil
	}
	return scanNewestFirst(scan, fmt.Sprintf("comments on %s/%s#%d", tg.owner, tg.repo, number))
}

// --- create_pull_request ----------------------------------------------------------

// checkPullRequest is create_pull_request's marker reconciliation: the
// repository's pull requests from the head branch (head=owner:branch, or
// the login:branch the harness gave for a fork; every state), bounded by
// MaxReconcilePages, newest first. The marker in a body is found; the
// end of the list without it is not_found; running out of pages or a
// listing error is "cannot tell yet". The list endpoint is not a search
// index, so its answer is authoritative.
func (c *Connector) checkPullRequest(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	tg, err := c.target(ctx, in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	head := in.ResourceIdentity["branch"]
	if head == "" {
		return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no head branch", ErrNotReconcilable)
	}
	if !strings.Contains(head, ":") {
		head = tg.owner + ":" + head
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	opts := &gh.PullRequestListOptions{State: "all", Head: head, Sort: "created", Direction: "desc", ListOptions: gh.ListOptions{PerPage: reconcilePerPage}}
	for page := 1; page <= MaxReconcilePages; page++ {
		opts.Page = page
		pulls, resp, err := tg.client.PullRequests.List(ctx, tg.owner, tg.repo, opts)
		if err := classify("reconcile: list pull requests", err); err != nil {
			return connectors.ReconcileResult{}, err
		}
		for _, pr := range pulls {
			if pr != nil && hasMarker(pr.GetBody(), tg.operationID) {
				return found(strconv.Itoa(pr.GetNumber())), nil
			}
		}
		if resp.NextPage == 0 {
			return notFound, nil
		}
	}
	return connectors.ReconcileResult{}, fmt.Errorf("github: reconcile: more than %d pages of pull requests from %s in %s/%s; cannot tell yet", MaxReconcilePages, head, tg.owner, tg.repo)
}

// --- create_branch ----------------------------------------------------------------

// checkBranch is create_branch's stable-id reconciliation: the branch
// name is known before the call (the resource identity stores it with
// its case), so the ref is looked up. Present is found with the commit
// sha; 404 is not_found; anything else is "cannot tell yet".
func (c *Connector) checkBranch(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	tg, err := c.target(ctx, in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	branch := in.ResourceIdentity["branch"]
	if branch == "" {
		return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no branch", ErrNotReconcilable)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	ref, _, err := tg.client.Git.GetRef(ctx, tg.owner, tg.repo, "heads/"+branch)
	if err := classify("reconcile: get branch", err); err != nil {
		if statusOf(err) == http.StatusNotFound {
			return notFound, nil
		}
		return connectors.ReconcileResult{}, err
	}
	if sha := ref.GetObject().GetSHA(); sha != "" {
		return found(sha), nil
	}
	return connectors.ReconcileResult{}, errors.New("github: reconcile: branch answer carried no commit sha; cannot tell yet")
}
