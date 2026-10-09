package atlassian

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// MaxReconcilePages bounds how many pages (of reconcilePageSize items) a
// reconciliation check walks before giving up with "cannot tell yet";
// the reconciler retries later with backoff and, after its own limits,
// hands the operation to the user as unresolved.
const MaxReconcilePages = 5

// reconcilePageSize is the page size the checks list with (Atlassian's
// maximum on the endpoints used).
const reconcilePageSize = 100

// ErrNotReconcilable says the ledger row lacks what the check needs (an
// operation id, the account, the project, the issue key or the space
// key in the resource identity); the reconciler treats it as "cannot
// tell".
var ErrNotReconcilable = errors.New("atlassian: operation cannot be reconciled")

// reconcileTarget is what every check starts from: the operation id
// (the marker) and an authenticated session for the same account the
// write ran under. Call.Args are empty when the reconciler runs from
// the ledger; everything comes from ResourceIdentity and OperationID
// (decision enlsy40f).
type reconcileTarget struct {
	operationID string
	*session
}

// target validates the input and builds the session.
func (c *Connector) target(ctx context.Context, in connectors.ReconcileInput) (reconcileTarget, error) {
	opID := in.OperationID
	if opID == "" {
		opID = in.Call.OperationID
	}
	if opID == "" {
		return reconcileTarget{}, fmt.Errorf("%w: no operation id", ErrNotReconcilable)
	}
	if in.Call.Account == "" {
		return reconcileTarget{}, fmt.Errorf("%w: no account", ErrNotReconcilable)
	}
	s, err := c.session(ctx, in.Call)
	if err != nil {
		return reconcileTarget{}, err
	}
	return reconcileTarget{operationID: opID, session: s}, nil
}

// found builds a found result.
func found(id string) connectors.ReconcileResult {
	return connectors.ReconcileResult{Outcome: connectors.ReconcileFound, ResourceID: id}
}

// notFound is the definite negative.
var notFound = connectors.ReconcileResult{Outcome: connectors.ReconcileNotFound}

// --- jira.create_issue -------------------------------------------------------------

// checkIssue is create_issue's marker reconciliation. A JQL text search
// for the marker in the project's descriptions is tried first: a hit
// whose description carries the marker is the issue. Text search only
// ever proves presence (the index lags), so a miss or a search error
// falls back to listing the project's issues reported by the
// authenticated user, newest first, bounded by MaxReconcilePages: the
// marker on any page is found; the end of the list without it is
// not_found; running out of pages, or any listing error, is "cannot
// tell yet".
func (c *Connector) checkIssue(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	project := in.ResourceIdentity["project"]
	if !projectKeyRE.MatchString(project) {
		return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no project", ErrNotReconcilable)
	}
	tg, err := c.target(ctx, in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	if key := tg.searchMarker(ctx, project); key != "" {
		return found(key), nil
	}
	jql := "project = " + project + " AND reporter = currentUser() ORDER BY created DESC"
	token := ""
	for page := 1; page <= MaxReconcilePages; page++ {
		q := url.Values{"jql": {jql}, "maxResults": {strconv.Itoa(reconcilePageSize)}, "fields": {"description"}}
		if token != "" {
			q.Set("nextPageToken", token)
		}
		var res wireSearch
		if err := c.classify("reconcile: list issues", tg.getJSON(ctx, tg.jiraURL("search/jql", q), &res)); err != nil {
			return connectors.ReconcileResult{}, err
		}
		for _, is := range res.Issues {
			if hasMarker(adfText(is.Fields.Description), tg.operationID) {
				return found(is.Key), nil
			}
		}
		if res.NextPageToken == "" || (res.IsLast != nil && *res.IsLast) || len(res.Issues) == 0 {
			return notFound, nil
		}
		token = res.NextPageToken
	}
	return connectors.ReconcileResult{}, fmt.Errorf("atlassian: reconcile: more than %d pages of recent issues by this user in %s; cannot tell yet", MaxReconcilePages, project)
}

// searchMarker asks JQL text search for the marker and returns the key
// of the issue whose description carries it, or "" (a miss, an error, or
// hits without the marker: never trusted as absence).
func (tg reconcileTarget) searchMarker(ctx context.Context, project string) string {
	jql := fmt.Sprintf(`project = %s AND description ~ "\"%s\""`, project, Marker(tg.operationID))
	q := url.Values{"jql": {jql}, "maxResults": {"10"}, "fields": {"description"}}
	var res wireSearch
	if err := tg.getJSON(ctx, tg.jiraURL("search/jql", q), &res); err != nil {
		return ""
	}
	for _, is := range res.Issues {
		if is.Key != "" && hasMarker(adfText(is.Fields.Description), tg.operationID) {
			return is.Key
		}
	}
	return ""
}

// --- jira.add_comment ---------------------------------------------------------------

// checkComment is add_comment's marker reconciliation: the issue's
// comments listed newest first (orderBy=-created), bounded by
// MaxReconcilePages. The marker on any page is found; every comment read
// without it is not_found; running out of pages, or any listing error
// (including a 404: the account may have lost access rather than the
// issue being gone), is "cannot tell yet".
func (c *Connector) checkComment(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	key, ok := issueKeyArg(in.ResourceIdentity["issue"])
	if !ok {
		return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no issue key", ErrNotReconcilable)
	}
	tg, err := c.target(ctx, in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	startAt := 0
	for page := 1; page <= MaxReconcilePages; page++ {
		q := url.Values{"orderBy": {"-created"}, "maxResults": {strconv.Itoa(reconcilePageSize)}, "startAt": {strconv.Itoa(startAt)}}
		var res wireComments
		if err := c.classify("reconcile: list comments", tg.getJSON(ctx, tg.jiraURL("issue/"+key+"/comment", q), &res)); err != nil {
			return connectors.ReconcileResult{}, err
		}
		for _, cm := range res.Comments {
			if cm.ID != "" && hasMarker(adfText(cm.Body), tg.operationID) {
				return found(cm.ID), nil
			}
		}
		startAt += len(res.Comments)
		if len(res.Comments) == 0 || startAt >= res.Total {
			return notFound, nil
		}
	}
	return connectors.ReconcileResult{}, fmt.Errorf("atlassian: reconcile: more than %d pages of comments on %s; cannot tell yet", MaxReconcilePages, key)
}

// --- confluence.create_page ----------------------------------------------------------

// checkPage is create_page's marker reconciliation. A CQL text search
// for the marker in the space is tried first: a hit whose storage body
// carries the marker is the page. The search index lags, so a miss, a
// hit without the marker or a search error falls back to the space's
// pages (v2, newest created first, bodies included), bounded by
// MaxReconcilePages: the marker on any page is found; the end of the
// list without it is not_found; running out of pages, a space that can
// no longer be resolved, or any listing error is "cannot tell yet".
func (c *Connector) checkPage(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	space := in.ResourceIdentity["space"]
	if !spaceKeyRE.MatchString(space) {
		return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no space", ErrNotReconcilable)
	}
	tg, err := c.target(ctx, in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	if id := tg.searchPageMarker(ctx, space); id != "" {
		return found(id), nil
	}
	spaceID, err := c.spaceID(ctx, tg.session, space)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	cursor := ""
	for page := 1; page <= MaxReconcilePages; page++ {
		q := url.Values{"sort": {"-created-date"}, "limit": {strconv.Itoa(reconcilePageSize)}, "body-format": {"storage"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var res wirePages
		if err := c.classify("reconcile: list pages", tg.getJSON(ctx, tg.wikiURL("api/v2/spaces/"+spaceID+"/pages", q), &res)); err != nil {
			return connectors.ReconcileResult{}, err
		}
		for _, p := range res.Results {
			if p.ID != "" && p.Body != nil && p.Body.Storage != nil && hasMarker(p.Body.Storage.Value, tg.operationID) {
				return found(p.ID), nil
			}
		}
		cursor = nextCursor(res.Links["next"])
		if cursor == "" || len(res.Results) == 0 {
			return notFound, nil
		}
	}
	return connectors.ReconcileResult{}, fmt.Errorf("atlassian: reconcile: more than %d pages of recent pages in space %s; cannot tell yet", MaxReconcilePages, space)
}

// searchPageMarker asks CQL text search for the marker and returns the
// id of the page whose body carries it, or "" (a miss, an error, or hits
// without the marker: never trusted as absence).
func (tg reconcileTarget) searchPageMarker(ctx context.Context, space string) string {
	cql := fmt.Sprintf(`space = %q AND type = page AND text ~ "\"%s\""`, space, Marker(tg.operationID))
	q := url.Values{"cql": {cql}, "limit": {"10"}, "expand": {"body.storage"}}
	var res wireContentSearch
	if err := tg.getJSON(ctx, tg.wikiURL("rest/api/content/search", q), &res); err != nil {
		return ""
	}
	for _, ct := range res.Results {
		if ct.ID != "" && ct.Body != nil && ct.Body.Storage != nil && hasMarker(ct.Body.Storage.Value, tg.operationID) {
			return ct.ID
		}
	}
	return ""
}

// nextCursor extracts the cursor of a v2 "next" link, "" when there is
// none.
func nextCursor(next string) string {
	if next == "" {
		return ""
	}
	u, err := url.Parse(next)
	if err != nil {
		return ""
	}
	return u.Query().Get("cursor")
}
