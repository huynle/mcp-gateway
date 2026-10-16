package atlassian_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/atlassian"
)

// --- tool metadata ----------------------------------------------------------

func TestWriteToolNames(t *testing.T) {
	jira, _ := newJira(t, newAPIServer(t, nil), connectors.Bounds{})
	conf, _ := newConfluence(t, newAPIServer(t, nil), connectors.Bounds{})
	names := func(c *atlassian.Connector) []string {
		var out []string
		for _, tool := range c.Tools() {
			if tool.Kind == connectors.KindWrite {
				out = append(out, tool.Name)
				if tool.Bounds.MaxPageSize != 0 || tool.Bounds.MaxResultBytes <= 0 {
					t.Errorf("%s: Bounds = %+v, want no page size and a result bound", tool.Name, tool.Bounds)
				}
				if tool.ResultIDs == nil {
					t.Errorf("%s: ResultIDs is nil", tool.Name)
				}
			}
		}
		return out
	}
	wantEqual(t, "jira writes", names(jira), []string{"create_issue", "add_comment", "transition_issue",
		"update_issue", "assign_issue", "edit_comment", "add_worklog", "link_issues", "add_watcher", "remove_watcher", "add_issues_to_sprint", "add_remote_link"})
	wantEqual(t, "confluence writes", names(conf), []string{"create_page", "update_page", "add_page_comment", "add_page_labels"})
}

func TestWriteToolsMetadata(t *testing.T) {
	cases := []struct {
		metadataCase
		kind connectors.ReconcileKind
	}{
		{metadataCase{
			app: atlassian.JiraApp, tool: "create_issue", required: []string{"project_key", "issue_type", "summary"},
			props:    []string{"project_key", "issue_type", "summary", "description", "labels", "parent_key", "priority", "assignee_account_id", "fields"},
			args:     map[string]any{"project_key": "mock", "issue_type": "Task", "summary": "secret title", "description": "secret body"},
			identity: map[string]string{"project": "MOCK"},
			scopes:   []string{"write:jira-work"},
		}, connectors.ReconcileMarker},
		{metadataCase{
			app: atlassian.JiraApp, tool: "add_comment", required: []string{"key", "body"}, props: []string{"key", "body"},
			args:     map[string]any{"key": "MOCK-42", "body": "secret body"},
			identity: map[string]string{"project": "MOCK", "issue": "MOCK-42"},
			scopes:   []string{"write:jira-work"},
		}, connectors.ReconcileMarker},
		{metadataCase{
			app: atlassian.JiraApp, tool: "transition_issue", required: []string{"key", "transition_id"}, props: []string{"key", "transition_id"},
			args:     map[string]any{"key": "MOCK-42", "transition_id": "31"},
			identity: map[string]string{"project": "MOCK", "issue": "MOCK-42"},
			scopes:   []string{"write:jira-work"},
		}, connectors.ReconcileNone},
	}
	for _, tc := range cases {
		t.Run(tc.app+"."+tc.tool, func(t *testing.T) {
			checkMetadata(t, tc.metadataCase)
			c, _ := newConnector(t, tc.app, newAPIServer(t, nil), connectors.Bounds{})
			tool := toolNamed(t, c, tc.tool)
			if tool.Kind != connectors.KindWrite {
				t.Errorf("Kind = %q, want write", tool.Kind)
			}
			if tool.Reconcile.Kind != tc.kind {
				t.Errorf("Reconcile.Kind = %q, want %q", tool.Reconcile.Kind, tc.kind)
			}
			if (tc.kind == connectors.ReconcileNone) != (tool.Reconcile.Check == nil) {
				t.Errorf("Reconcile.Check present = %v for kind %q", tool.Reconcile.Check != nil, tc.kind)
			}
		})
	}
}

// --- write helpers ------------------------------------------------------------

const opID = "0f1e2d3c-4b5a-4968-8777-66554433aa11"

// marker is the phrase every marker-reconciled write embeds.
const marker = "mcp-gateway op:" + opID

// write builds a write call under the ledger operation opID.
func write(app, tool string, args map[string]any) connectors.Call {
	c := call(app, tool, args)
	c.OperationID = opID
	return c
}

// adfParagraphs returns the text of each top-level paragraph of an ADF
// document decoded from a request body.
func adfParagraphs(t *testing.T, doc any) []string {
	t.Helper()
	m, ok := doc.(map[string]any)
	if !ok || m["type"] != "doc" || m["version"] != float64(1) {
		t.Fatalf("not an ADF document: %v", doc)
	}
	var out []string
	content, _ := m["content"].([]any)
	for _, n := range content {
		p, _ := n.(map[string]any)
		if p["type"] != "paragraph" {
			t.Fatalf("top-level node is not a paragraph: %v", p)
		}
		var text strings.Builder
		inner, _ := p["content"].([]any)
		for _, tn := range inner {
			tm, _ := tn.(map[string]any)
			s, _ := tm["text"].(string)
			text.WriteString(s)
		}
		out = append(out, text.String())
	}
	return out
}

type writeErrorCase struct {
	name    string
	rt      route
	class   string
	status  int
	unknown bool
	rateLim bool
}

// writeErrorCases are the vendor answers every write maps the same way;
// ok is the route's success answer (delayed for the timeout case).
func writeErrorCases(ok route) []writeErrorCase {
	delayed := ok
	delayed.delay = 2 * time.Second
	return []writeErrorCase{
		{name: "400 invalid argument", rt: route{status: 400, body: "error_validation.json"}, class: atlassian.ClassInvalidArgument, status: 400},
		{name: "403 forbidden", rt: route{status: 403, body: "error_forbidden.json"}, class: atlassian.ClassForbidden, status: 403},
		{name: "404 not found", rt: route{status: 404, body: "error_not_found.json"}, class: atlassian.ClassNotFound, status: 404},
		{name: "401 reconnect", rt: route{status: 401, body: "error_unauthorized.json"}, class: atlassian.ClassReconnectRequired, status: 401},
		{name: "429 rate limited", rt: route{status: 429, body: "error_rate_limit.json", headers: map[string]string{"Retry-After": "7"}}, rateLim: true},
		{name: "500 outcome unknown", rt: route{status: 500, body: "error_server.json"}, unknown: true},
		{name: "502 outcome unknown", rt: route{status: 502, body: ""}, unknown: true},
		{name: "timeout outcome unknown", rt: delayed, unknown: true},
		{name: "unreadable reply outcome unknown", rt: route{status: 201, body: `{"id": "10057", "key": `}, unknown: true},
	}
}

// checkWriteError asserts the outcome of one writeErrorCases entry.
func checkWriteError(t *testing.T, app string, tc writeErrorCase, res connectors.Result, err error) {
	t.Helper()
	switch {
	case tc.unknown:
		if !errors.Is(err, connectors.ErrOutcomeUnknown) {
			t.Fatalf("err = %v (%T), want ErrOutcomeUnknown", err, err)
		}
		if res.Unavailable || res.Content != nil {
			t.Errorf("res = %+v, want an empty result with the error", res)
		}
	case tc.rateLim:
		var rl *connectors.RateLimited
		if !errors.As(err, &rl) || rl.App != app || rl.RetryAfter != 7*time.Second {
			t.Fatalf("err = %v (%T), want *connectors.RateLimited %s of 7s", err, err, app)
		}
	default:
		wantClass(t, err, tc.class, tc.status)
		if errors.Is(err, connectors.ErrOutcomeUnknown) {
			t.Errorf("a vendor answer of %d is a known outcome, got ErrOutcomeUnknown", tc.status)
		}
	}
	if err != nil && strings.Contains(err.Error(), testToken) {
		t.Errorf("error message leaks the token: %q", err.Error())
	}
}

// newWriter builds a connector for app with a short timeout.
func newWriter(t *testing.T, app string, srv *apiServer) *atlassian.Connector {
	t.Helper()
	c, err := atlassian.New(app, atlassian.Options{Tokens: (&tokens{}).source, Sites: (&sites{}).source, BaseURL: srv.URL, Timeout: 300 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// reconcile builds the input the ledger's reconciler hands to Check:
// the principal and account, the operation id and the stored resource
// identity; never arguments.
func reconcile(app, tool string, identity map[string]string) connectors.ReconcileInput {
	return connectors.ReconcileInput{
		Call:             connectors.Call{Principal: connectors.Principal{UserID: alice, TokenID: "tok"}, Tool: app + "." + tool, Account: acct, OperationID: opID},
		OperationID:      opID,
		ResourceIdentity: identity,
	}
}

func wantFound(t *testing.T, res connectors.ReconcileResult, err error, id string) {
	t.Helper()
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if res.Outcome != connectors.ReconcileFound || res.ResourceID != id {
		t.Fatalf("Check = %+v, want found %s", res, id)
	}
}

func wantNotFound(t *testing.T, res connectors.ReconcileResult, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if res.Outcome != connectors.ReconcileNotFound || res.ResourceID != "" {
		t.Fatalf("Check = %+v, want not_found", res)
	}
}

func TestWritesRequireAnOperationID(t *testing.T) {
	srv := newAPIServer(t, nil)
	jira, tk := newJira(t, srv, connectors.Bounds{})
	conf, _ := newConfluence(t, srv, connectors.Bounds{})
	args := map[string]any{"project_key": "MOCK", "issue_type": "Task", "summary": "s", "key": "MOCK-42", "body": "b", "transition_id": "31", "space_key": "DOCS", "title": "t"}
	for _, tool := range []string{"create_issue", "add_comment", "transition_issue"} {
		if _, err := jira.Call(context.Background(), call(atlassian.JiraApp, tool, args)); !errors.Is(err, atlassian.ErrMissingOperation) {
			t.Errorf("jira.%s without an operation id: err = %v, want ErrMissingOperation", tool, err)
		}
	}
	_ = conf
	if len(srv.Requests()) != 0 || len(tk.calls) != 0 {
		t.Errorf("requests = %d, token calls = %v; want none", len(srv.Requests()), tk.calls)
	}
}

// --- jira.create_issue -------------------------------------------------------------------

const createIssuePath = "POST " + jiraBase + "/issue"

func TestCreateIssue(t *testing.T) {
	srv := newAPIServer(t, map[string]route{createIssuePath: {status: 201, body: "created_issue.json"}})
	c, tk := newJira(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), write(atlassian.JiraApp, "create_issue", map[string]any{
		"project_key": "mock", "issue_type": "Task", "summary": "Add a retry to the uploader",
		"description": "The uploader gives up on the first timeout.\n\nSecond paragraph.", "labels": []any{"bug"},
	}))
	if err != nil {
		t.Fatalf("create_issue: %v", err)
	}
	created, ok := res.Content.(atlassian.CreatedIssue)
	if !ok || created.Key != "MOCK-57" || created.ID != "10057" || created.URL != siteURL+"/browse/MOCK-57" || created.Project != "MOCK" {
		t.Errorf("content = %#v", res.Content)
	}
	if res.Empty || res.Partial || res.Unavailable {
		t.Errorf("markers = %+v", res)
	}
	tool := toolNamed(t, c, "create_issue")
	ids := tool.ResultIDs(res)
	if ids["key"] != "MOCK-57" || ids["id"] != "10057" || ids["url"] != created.URL || len(ids) != 3 {
		t.Errorf("ResultIDs = %v", ids)
	}
	if tool.ResultIDs(connectors.Result{}) != nil {
		t.Error("ResultIDs of an empty result should be nil")
	}
	body := jsonBody(t, srv.Last(t, createIssuePath))
	fields, _ := body["fields"].(map[string]any)
	if fields == nil {
		t.Fatalf("body = %v", body)
	}
	if p, _ := fields["project"].(map[string]any); p["key"] != "MOCK" {
		t.Errorf("project = %v", fields["project"])
	}
	if it, _ := fields["issuetype"].(map[string]any); it["name"] != "Task" {
		t.Errorf("issuetype = %v", fields["issuetype"])
	}
	if fields["summary"] != "Add a retry to the uploader" {
		t.Errorf("summary = %v", fields["summary"])
	}
	if got := adfParagraphs(t, fields["description"]); strings.Join(got, "|") != "The uploader gives up on the first timeout.|Second paragraph.|"+marker {
		t.Errorf("description paragraphs = %q, want the text then the marker", got)
	}
	if labels, _ := fields["labels"].([]any); len(labels) != 1 || labels[0] != "bug" {
		t.Errorf("labels = %v", fields["labels"])
	}
	if len(tk.calls) != 1 || tk.calls[0] != alice+"/"+acct {
		t.Errorf("token source calls = %v", tk.calls)
	}
	if ct := srv.Last(t, createIssuePath).Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
}

func TestCreateIssueWithoutDescriptionCarriesOnlyTheMarker(t *testing.T) {
	srv := newAPIServer(t, map[string]route{createIssuePath: {status: 201, body: "created_issue.json"}})
	c, _ := newJira(t, srv, connectors.Bounds{})
	if _, err := c.Call(context.Background(), write(atlassian.JiraApp, "create_issue", map[string]any{"project_key": "MOCK", "issue_type": "Task", "summary": "t"})); err != nil {
		t.Fatal(err)
	}
	fields, _ := jsonBody(t, srv.Last(t, createIssuePath))["fields"].(map[string]any)
	if got := adfParagraphs(t, fields["description"]); len(got) != 1 || got[0] != marker {
		t.Errorf("description paragraphs = %q, want just the marker", got)
	}
	if _, ok := fields["labels"]; ok {
		t.Errorf("labels sent when none given: %v", fields)
	}
}

func TestCreateIssueValidation(t *testing.T) {
	srv := newAPIServer(t, nil)
	c, _ := newJira(t, srv, connectors.Bounds{})
	cases := map[string]map[string]any{
		"missing summary":    {"project_key": "MOCK", "issue_type": "Task"},
		"blank summary":      {"project_key": "MOCK", "issue_type": "Task", "summary": "  "},
		"bad project key":    {"project_key": "1MOCK", "issue_type": "Task", "summary": "t"},
		"missing issue type": {"project_key": "MOCK", "summary": "t"},
		"bad labels":         {"project_key": "MOCK", "issue_type": "Task", "summary": "t", "labels": "bug"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := c.Call(context.Background(), write(atlassian.JiraApp, "create_issue", args))
			wantClass(t, err, atlassian.ClassInvalidArgument, 0)
		})
	}
	if n := len(srv.Requests()); n != 0 {
		t.Errorf("%d requests sent for invalid arguments", n)
	}
}

func TestCreateIssueErrors(t *testing.T) {
	for _, tc := range writeErrorCases(route{status: 201, body: "created_issue.json"}) {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{createIssuePath: tc.rt})
			c := newWriter(t, atlassian.JiraApp, srv)
			res, err := c.Call(context.Background(), write(atlassian.JiraApp, "create_issue", map[string]any{"project_key": "MOCK", "issue_type": "Task", "summary": "t"}))
			checkWriteError(t, "jira", tc, res, err)
		})
	}
}

func TestCreateIssueConnectionLostIsUnknown(t *testing.T) {
	srv := newAPIServer(t, nil)
	c, _ := newJira(t, srv, connectors.Bounds{})
	srv.Close()
	res, err := c.Call(context.Background(), write(atlassian.JiraApp, "create_issue", map[string]any{"project_key": "MOCK", "issue_type": "Task", "summary": "t"}))
	if !errors.Is(err, connectors.ErrOutcomeUnknown) || res.Unavailable {
		t.Fatalf("res = %+v err = %v, want ErrOutcomeUnknown (never Unavailable for a write)", res, err)
	}
}

// --- reconciliation: jira.create_issue -----------------------------------------------

var (
	issueIdentity = map[string]string{"project": "MOCK"}
	markerJQL     = `project = MOCK AND description ~ "\"` + marker + `\""`
	reporterJQL   = "project = MOCK AND reporter = currentUser() ORDER BY created DESC"
)

// searchRoutes answers the marker search with hit and the reporter
// listing with the given pages (by nextPageToken).
func searchRoutes(hit route, pages map[string]route) route {
	out := route{pageParam: "jql", pages: map[string]route{markerJQL: hit}}
	if pages != nil {
		out.pages[reporterJQL] = route{pageParam: "nextPageToken", pages: pages}
	}
	return out
}

func TestCheckIssueFoundBySearch(t *testing.T) {
	srv := newAPIServer(t, map[string]route{searchPath: searchRoutes(route{status: 200, body: "search_marker_hit.json"}, nil)})
	c, tk := newJira(t, srv, connectors.Bounds{})
	res, err := toolNamed(t, c, "create_issue").Reconcile.Check(context.Background(), reconcile(atlassian.JiraApp, "create_issue", issueIdentity))
	wantFound(t, res, err, "MOCK-57")
	q := query(t, srv, jiraBase+"/search/jql")
	if q.Get("jql") != markerJQL || !strings.Contains(q.Get("fields"), "description") {
		t.Errorf("query = %v", q)
	}
	if len(tk.calls) != 1 || tk.calls[0] != alice+"/"+acct {
		t.Errorf("token source calls = %v", tk.calls)
	}
	if srv.Count(searchPath) != 1 {
		t.Error("the fallback listing ran although the search found the issue")
	}
}

func TestCheckIssueSearchHitWithoutMarkerIsNotTrusted(t *testing.T) {
	srv := newAPIServer(t, map[string]route{searchPath: searchRoutes(
		route{status: 200, body: "search_marker_hit_without_marker.json"},
		map[string]route{"": {status: 200, body: "issues_by_reporter_page1.json"}, "PAGE2": {status: 200, body: "issues_by_reporter_page2.json"}},
	)})
	c, _ := newJira(t, srv, connectors.Bounds{})
	res, err := toolNamed(t, c, "create_issue").Reconcile.Check(context.Background(), reconcile(atlassian.JiraApp, "create_issue", issueIdentity))
	wantFound(t, res, err, "MOCK-57")
	if srv.Count(searchPath) != 3 {
		t.Errorf("search requests = %d, want the marker search and two listing pages", srv.Count(searchPath))
	}
}

func TestCheckIssueFallsBackWhenSearchFails(t *testing.T) {
	srv := newAPIServer(t, map[string]route{searchPath: searchRoutes(
		route{status: 400, body: "error_bad_jql.json"},
		map[string]route{"": {status: 200, body: "issues_by_reporter_page1.json"}, "PAGE2": {status: 200, body: "issues_by_reporter_page2.json"}},
	)})
	c, _ := newJira(t, srv, connectors.Bounds{})
	res, err := toolNamed(t, c, "create_issue").Reconcile.Check(context.Background(), reconcile(atlassian.JiraApp, "create_issue", issueIdentity))
	wantFound(t, res, err, "MOCK-57")
	q := query(t, srv, jiraBase+"/search/jql")
	if q.Get("jql") != reporterJQL || q.Get("nextPageToken") != "PAGE2" || q.Get("maxResults") != "100" {
		t.Errorf("last query = %v", q)
	}
}

func TestCheckIssueNotFound(t *testing.T) {
	srv := newAPIServer(t, map[string]route{searchPath: searchRoutes(
		route{status: 200, body: "search_issues_empty.json"},
		map[string]route{"": {status: 200, body: "issues_by_reporter_page1.json"}, "PAGE2": {status: 200, body: "issues_by_reporter_last_without_marker.json"}},
	)})
	c, _ := newJira(t, srv, connectors.Bounds{})
	res, err := toolNamed(t, c, "create_issue").Reconcile.Check(context.Background(), reconcile(atlassian.JiraApp, "create_issue", issueIdentity))
	wantNotFound(t, res, err)
}

func TestCheckIssueCannotTell(t *testing.T) {
	t.Run("listing error", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{searchPath: searchRoutes(
			route{status: 200, body: "search_issues_empty.json"},
			map[string]route{"": {status: 503, body: ""}},
		)})
		c, _ := newJira(t, srv, connectors.Bounds{})
		_, err := toolNamed(t, c, "create_issue").Reconcile.Check(context.Background(), reconcile(atlassian.JiraApp, "create_issue", issueIdentity))
		var aErr *atlassian.Error
		if !errors.As(err, &aErr) || aErr.Class != atlassian.ClassUnavailable {
			t.Fatalf("Check err = %v, want class unavailable (cannot tell yet)", err)
		}
	})
	t.Run("too many pages", func(t *testing.T) {
		pages := map[string]route{}
		for i := 0; i <= atlassian.MaxReconcilePages; i++ {
			token := ""
			if i > 0 {
				token = "P" + string(rune('0'+i))
			}
			next := "P" + string(rune('0'+i+1))
			pages[token] = route{status: 200, body: `{"issues":[{"key":"MOCK-1","fields":{"description":null}}],"isLast":false,"nextPageToken":"` + next + `"}`}
		}
		srv := newAPIServer(t, map[string]route{searchPath: searchRoutes(route{status: 200, body: "search_issues_empty.json"}, pages)})
		c, _ := newJira(t, srv, connectors.Bounds{})
		_, err := toolNamed(t, c, "create_issue").Reconcile.Check(context.Background(), reconcile(atlassian.JiraApp, "create_issue", issueIdentity))
		if err == nil || !strings.Contains(err.Error(), "cannot tell yet") {
			t.Fatalf("Check err = %v, want cannot tell yet", err)
		}
		if n := srv.Count(searchPath); n != atlassian.MaxReconcilePages+1 {
			t.Errorf("search requests = %d, want the marker search plus %d pages", n, atlassian.MaxReconcilePages)
		}
	})
}

func TestCheckIssueNeedsIdentityAndOperation(t *testing.T) {
	srv := newAPIServer(t, nil)
	c, tk := newJira(t, srv, connectors.Bounds{})
	check := toolNamed(t, c, "create_issue").Reconcile.Check
	cases := map[string]connectors.ReconcileInput{
		"no project":  reconcile(atlassian.JiraApp, "create_issue", map[string]string{}),
		"bad project": reconcile(atlassian.JiraApp, "create_issue", map[string]string{"project": "no spaces"}),
	}
	noOp := reconcile(atlassian.JiraApp, "create_issue", issueIdentity)
	noOp.OperationID, noOp.Call.OperationID = "", ""
	cases["no operation id"] = noOp
	noAcct := reconcile(atlassian.JiraApp, "create_issue", issueIdentity)
	noAcct.Call.Account = ""
	cases["no account"] = noAcct
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := check(context.Background(), in)
			if !errors.Is(err, atlassian.ErrNotReconcilable) {
				t.Errorf("err = %v, want ErrNotReconcilable", err)
			}
		})
	}
	if len(srv.Requests()) != 0 || len(tk.calls) != 0 {
		t.Errorf("requests = %d, token calls = %v; want none", len(srv.Requests()), tk.calls)
	}
}

func TestCheckIssueTakesTheOperationIDFromTheCall(t *testing.T) {
	srv := newAPIServer(t, map[string]route{searchPath: searchRoutes(route{status: 200, body: "search_marker_hit.json"}, nil)})
	c, _ := newJira(t, srv, connectors.Bounds{})
	in := reconcile(atlassian.JiraApp, "create_issue", issueIdentity)
	in.OperationID = ""
	res, err := toolNamed(t, c, "create_issue").Reconcile.Check(context.Background(), in)
	wantFound(t, res, err, "MOCK-57")
}

// --- jira.add_comment -------------------------------------------------------------------

const (
	addCommentPath   = "POST " + jiraBase + "/issue/MOCK-42/comment"
	listCommentsPath = "GET " + jiraBase + "/issue/MOCK-42/comment"
)

func TestAddComment(t *testing.T) {
	srv := newAPIServer(t, map[string]route{addCommentPath: {status: 201, body: "created_comment.json"}})
	c, _ := newJira(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), write(atlassian.JiraApp, "add_comment", map[string]any{"key": "mock-42", "body": "Looks good.\nShip it."}))
	if err != nil {
		t.Fatalf("add_comment: %v", err)
	}
	created, ok := res.Content.(atlassian.CreatedComment)
	if !ok || created.ID != "20001" || created.Issue != "MOCK-42" || created.URL != siteURL+"/browse/MOCK-42?focusedCommentId=20001" {
		t.Errorf("content = %#v", res.Content)
	}
	ids := toolNamed(t, c, "add_comment").ResultIDs(res)
	if ids["id"] != "20001" || ids["url"] != created.URL || len(ids) != 2 {
		t.Errorf("ResultIDs = %v", ids)
	}
	body := jsonBody(t, srv.Last(t, addCommentPath))
	if got := adfParagraphs(t, body["body"]); strings.Join(got, "|") != "Looks good.|Ship it.|"+marker {
		t.Errorf("body paragraphs = %q", got)
	}
}

func TestAddCommentValidationAndErrors(t *testing.T) {
	t.Run("validation", func(t *testing.T) {
		srv := newAPIServer(t, nil)
		c, _ := newJira(t, srv, connectors.Bounds{})
		for name, args := range map[string]map[string]any{
			"missing body": {"key": "MOCK-42"},
			"blank body":   {"key": "MOCK-42", "body": " "},
			"bad key":      {"key": "42", "body": "b"},
		} {
			t.Run(name, func(t *testing.T) {
				_, err := c.Call(context.Background(), write(atlassian.JiraApp, "add_comment", args))
				wantClass(t, err, atlassian.ClassInvalidArgument, 0)
			})
		}
		if n := len(srv.Requests()); n != 0 {
			t.Errorf("%d requests sent for invalid arguments", n)
		}
	})
	for _, tc := range writeErrorCases(route{status: 201, body: "created_comment.json"}) {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{addCommentPath: tc.rt})
			c := newWriter(t, atlassian.JiraApp, srv)
			res, err := c.Call(context.Background(), write(atlassian.JiraApp, "add_comment", map[string]any{"key": "MOCK-42", "body": "b"}))
			checkWriteError(t, "jira", tc, res, err)
		})
	}
}

var commentIdentity = map[string]string{"project": "MOCK", "issue": "MOCK-42"}

func commentPages(pages map[string]route) route {
	return route{pageParam: "startAt", pages: pages}
}

func TestCheckCommentFoundOnTheSecondPage(t *testing.T) {
	srv := newAPIServer(t, map[string]route{listCommentsPath: commentPages(map[string]route{
		"0": {status: 200, body: "comments_page1.json"}, "2": {status: 200, body: "comments_page2.json"},
	})})
	c, _ := newJira(t, srv, connectors.Bounds{})
	res, err := toolNamed(t, c, "add_comment").Reconcile.Check(context.Background(), reconcile(atlassian.JiraApp, "add_comment", commentIdentity))
	wantFound(t, res, err, "20002")
	q := query(t, srv, jiraBase+"/issue/MOCK-42/comment")
	if q.Get("orderBy") != "-created" || q.Get("startAt") != "2" || q.Get("maxResults") != "100" {
		t.Errorf("query = %v", q)
	}
}

func TestCheckCommentNotFound(t *testing.T) {
	t.Run("every page read", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{listCommentsPath: commentPages(map[string]route{
			"0": {status: 200, body: "comments_page1.json"}, "2": {status: 200, body: "comments_page2_without_marker.json"},
		})})
		c, _ := newJira(t, srv, connectors.Bounds{})
		res, err := toolNamed(t, c, "add_comment").Reconcile.Check(context.Background(), reconcile(atlassian.JiraApp, "add_comment", commentIdentity))
		wantNotFound(t, res, err)
	})
	t.Run("no comments", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{listCommentsPath: commentPages(map[string]route{"0": {status: 200, body: "comments_empty.json"}})})
		c, _ := newJira(t, srv, connectors.Bounds{})
		res, err := toolNamed(t, c, "add_comment").Reconcile.Check(context.Background(), reconcile(atlassian.JiraApp, "add_comment", commentIdentity))
		wantNotFound(t, res, err)
	})
}

func TestCheckCommentCannotTell(t *testing.T) {
	t.Run("404 may be lost access", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{listCommentsPath: {status: 404, body: "error_not_found.json"}})
		c, _ := newJira(t, srv, connectors.Bounds{})
		_, err := toolNamed(t, c, "add_comment").Reconcile.Check(context.Background(), reconcile(atlassian.JiraApp, "add_comment", commentIdentity))
		wantClass(t, err, atlassian.ClassNotFound, 404)
	})
	t.Run("too many pages", func(t *testing.T) {
		pages := map[string]route{}
		for i := 0; i <= atlassian.MaxReconcilePages; i++ {
			pages[itoa(i)] = route{status: 200, body: `{"startAt":` + itoa(i) + `,"maxResults":1,"total":1000,"comments":[{"id":"1","body":null}]}`}
		}
		srv := newAPIServer(t, map[string]route{listCommentsPath: commentPages(pages)})
		c, _ := newJira(t, srv, connectors.Bounds{})
		_, err := toolNamed(t, c, "add_comment").Reconcile.Check(context.Background(), reconcile(atlassian.JiraApp, "add_comment", commentIdentity))
		if err == nil || !strings.Contains(err.Error(), "cannot tell yet") {
			t.Fatalf("Check err = %v, want cannot tell yet", err)
		}
	})
	t.Run("needs the issue key", func(t *testing.T) {
		c, _ := newJira(t, newAPIServer(t, nil), connectors.Bounds{})
		_, err := toolNamed(t, c, "add_comment").Reconcile.Check(context.Background(), reconcile(atlassian.JiraApp, "add_comment", map[string]string{"project": "MOCK"}))
		if !errors.Is(err, atlassian.ErrNotReconcilable) {
			t.Errorf("err = %v, want ErrNotReconcilable", err)
		}
	})
}

func itoa(i int) string { return string(rune('0' + i)) }

// --- jira.transition_issue --------------------------------------------------------------

const transitionPath = "POST " + jiraBase + "/issue/MOCK-42/transitions"

func TestTransitionIssue(t *testing.T) {
	srv := newAPIServer(t, map[string]route{transitionPath: {status: 204, body: ""}})
	c, _ := newJira(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), write(atlassian.JiraApp, "transition_issue", map[string]any{"key": "MOCK-42", "transition_id": "31"}))
	if err != nil {
		t.Fatalf("transition_issue: %v", err)
	}
	done, ok := res.Content.(atlassian.Transitioned)
	if !ok || done.Issue != "MOCK-42" || done.TransitionID != "31" {
		t.Errorf("content = %#v", res.Content)
	}
	tool := toolNamed(t, c, "transition_issue")
	if ids := tool.ResultIDs(res); ids["issue"] != "MOCK-42" || ids["transition_id"] != "31" || len(ids) != 2 {
		t.Errorf("ResultIDs = %v", ids)
	}
	if tool.Reconcile.Kind != connectors.ReconcileNone || tool.Reconcile.Check != nil {
		t.Errorf("transition_issue must declare Reconcile none: %+v", tool.Reconcile)
	}
	body := jsonBody(t, srv.Last(t, transitionPath))
	if tr, _ := body["transition"].(map[string]any); tr["id"] != "31" {
		t.Errorf("body = %v", body)
	}
}

func TestTransitionIssueAcceptsANumericID(t *testing.T) {
	srv := newAPIServer(t, map[string]route{transitionPath: {status: 204, body: ""}})
	c, _ := newJira(t, srv, connectors.Bounds{})
	if _, err := c.Call(context.Background(), write(atlassian.JiraApp, "transition_issue", map[string]any{"key": "MOCK-42", "transition_id": 31})); err != nil {
		t.Fatal(err)
	}
	if tr, _ := jsonBody(t, srv.Last(t, transitionPath))["transition"].(map[string]any); tr["id"] != "31" {
		t.Errorf("transition = %v", tr)
	}
}

func TestTransitionIssueValidationAndErrors(t *testing.T) {
	t.Run("validation", func(t *testing.T) {
		srv := newAPIServer(t, nil)
		c, _ := newJira(t, srv, connectors.Bounds{})
		for name, args := range map[string]map[string]any{
			"missing transition": {"key": "MOCK-42"},
			"bad transition":     {"key": "MOCK-42", "transition_id": "thirty one"},
			"bad key":            {"key": "x", "transition_id": "31"},
		} {
			t.Run(name, func(t *testing.T) {
				_, err := c.Call(context.Background(), write(atlassian.JiraApp, "transition_issue", args))
				wantClass(t, err, atlassian.ClassInvalidArgument, 0)
			})
		}
		if n := len(srv.Requests()); n != 0 {
			t.Errorf("%d requests sent for invalid arguments", n)
		}
	})
	cases := writeErrorCases(route{status: 204, body: ""})
	// A 204 has no body to misread; drop the unreadable-reply case.
	cases = cases[:len(cases)-1]
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{transitionPath: tc.rt})
			c := newWriter(t, atlassian.JiraApp, srv)
			res, err := c.Call(context.Background(), write(atlassian.JiraApp, "transition_issue", map[string]any{"key": "MOCK-42", "transition_id": "31"}))
			checkWriteError(t, "jira", tc, res, err)
		})
	}
}

// --- confluence.create_page --------------------------------------------------------------

const (
	spacesPath     = "GET " + wikiBase + "/api/v2/spaces"
	createPagePath = "POST " + wikiBase + "/api/v2/pages"
	spacePagesPath = "GET " + wikiBase + "/api/v2/spaces/98765/pages"
)

func TestCreatePageToolMetadata(t *testing.T) {
	conf, _ := newConfluence(t, newAPIServer(t, nil), connectors.Bounds{})
	var names []string
	for _, tool := range conf.Tools() {
		if tool.Kind == connectors.KindWrite {
			names = append(names, tool.Name)
		}
	}
	wantEqual(t, "confluence writes", names, []string{"create_page", "update_page", "add_page_comment", "add_page_labels"})
	checkMetadata(t, metadataCase{
		app: atlassian.ConfluenceApp, tool: "create_page", required: []string{"space_key", "title", "body"},
		props:    []string{"space_key", "title", "body", "parent_id"},
		args:     map[string]any{"space_key": "DOCS", "title": "secret", "body": "<p>secret</p>", "parent_id": "12000"},
		identity: map[string]string{"space": "DOCS"},
		scopes:   []string{"write:page:confluence", "read:space:confluence"},
	})
	tool := toolNamed(t, conf, "create_page")
	if tool.Reconcile.Kind != connectors.ReconcileMarker || tool.Reconcile.Check == nil || tool.ResultIDs == nil {
		t.Errorf("create_page reconcile = %+v", tool.Reconcile)
	}
	srv := newAPIServer(t, nil)
	if _, err := conf.Call(context.Background(), call(atlassian.ConfluenceApp, "create_page", map[string]any{"space_key": "DOCS", "title": "t", "body": "b"})); !errors.Is(err, atlassian.ErrMissingOperation) {
		t.Errorf("create_page without an operation id: err = %v", err)
	}
	if len(srv.Requests()) != 0 {
		t.Error("a request was sent without an operation id")
	}
}

func TestCreatePage(t *testing.T) {
	srv := newAPIServer(t, map[string]route{spacesPath: {status: 200, body: "spaces_docs.json"}, createPagePath: {status: 200, body: "created_page.json"}})
	c, tk := newConfluence(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), write(atlassian.ConfluenceApp, "create_page", map[string]any{
		"space_key": "DOCS", "title": "Release checklist", "body": "<p>Check everything.</p>", "parent_id": "12000",
	}))
	if err != nil {
		t.Fatalf("create_page: %v", err)
	}
	created, ok := res.Content.(atlassian.CreatedPage)
	if !ok || created.ID != "12400" || created.SpaceID != "98765" || created.Space != "DOCS" || created.URL != siteURL+"/wiki/spaces/DOCS/pages/12400/Release+checklist" {
		t.Errorf("content = %#v", res.Content)
	}
	ids := toolNamed(t, c, "create_page").ResultIDs(res)
	if ids["id"] != "12400" || ids["url"] != created.URL || len(ids) != 2 {
		t.Errorf("ResultIDs = %v", ids)
	}
	if q := query(t, srv, wikiBase+"/api/v2/spaces"); q.Get("keys") != "DOCS" {
		t.Errorf("space lookup query = %v", q)
	}
	body := jsonBody(t, srv.Last(t, createPagePath))
	if body["spaceId"] != "98765" || body["title"] != "Release checklist" || body["parentId"] != "12000" || body["status"] != "current" {
		t.Errorf("body = %v", body)
	}
	pb, _ := body["body"].(map[string]any)
	if pb["representation"] != "storage" || pb["value"] != "<p>Check everything.</p>\n<p>"+marker+"</p>" {
		t.Errorf("page body = %v, want the storage body followed by the marker paragraph", pb)
	}
	if len(tk.calls) != 1 {
		t.Errorf("token source calls = %v, want one for both requests", tk.calls)
	}
}

func TestCreatePagePlainTextBodyIsWrapped(t *testing.T) {
	srv := newAPIServer(t, map[string]route{spacesPath: {status: 200, body: "spaces_docs.json"}, createPagePath: {status: 200, body: "created_page.json"}})
	c, _ := newConfluence(t, srv, connectors.Bounds{})
	if _, err := c.Call(context.Background(), write(atlassian.ConfluenceApp, "create_page", map[string]any{"space_key": "DOCS", "title": "t", "body": "Just text & more"})); err != nil {
		t.Fatal(err)
	}
	body := jsonBody(t, srv.Last(t, createPagePath))
	pb, _ := body["body"].(map[string]any)
	if pb["value"] != "<p>Just text &amp; more</p>\n<p>"+marker+"</p>" {
		t.Errorf("page body = %q", pb["value"])
	}
	if _, ok := body["parentId"]; ok {
		t.Errorf("parentId sent when none given: %v", body)
	}
}

func TestCreatePageValidation(t *testing.T) {
	srv := newAPIServer(t, nil)
	c, _ := newConfluence(t, srv, connectors.Bounds{})
	for name, args := range map[string]map[string]any{
		"missing title":  {"space_key": "DOCS", "body": "b"},
		"missing body":   {"space_key": "DOCS", "title": "t"},
		"bad space key":  {"space_key": "no spaces", "title": "t", "body": "b"},
		"bad parent id":  {"space_key": "DOCS", "title": "t", "body": "b", "parent_id": "abc"},
		"body not a str": {"space_key": "DOCS", "title": "t", "body": 1},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := c.Call(context.Background(), write(atlassian.ConfluenceApp, "create_page", args))
			wantClass(t, err, atlassian.ClassInvalidArgument, 0)
		})
	}
	if n := len(srv.Requests()); n != 0 {
		t.Errorf("%d requests sent for invalid arguments", n)
	}
}

func TestCreatePageSpaceLookupFailuresAreKnown(t *testing.T) {
	t.Run("unknown space", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{spacesPath: {status: 200, body: "spaces_empty.json"}})
		c, _ := newConfluence(t, srv, connectors.Bounds{})
		_, err := c.Call(context.Background(), write(atlassian.ConfluenceApp, "create_page", map[string]any{"space_key": "DOCS", "title": "t", "body": "b"}))
		wantClass(t, err, atlassian.ClassNotFound, 0)
		if errors.Is(err, connectors.ErrOutcomeUnknown) || srv.Count(createPagePath) != 0 {
			t.Errorf("err = %v, create requests = %d; a failed lookup is a known outcome and creates nothing", err, srv.Count(createPagePath))
		}
	})
	t.Run("5xx on the lookup", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{spacesPath: {status: 503, body: ""}})
		c, _ := newConfluence(t, srv, connectors.Bounds{})
		res, err := c.Call(context.Background(), write(atlassian.ConfluenceApp, "create_page", map[string]any{"space_key": "DOCS", "title": "t", "body": "b"}))
		wantClass(t, err, atlassian.ClassUnavailable, 503)
		if errors.Is(err, connectors.ErrOutcomeUnknown) || res.Unavailable {
			t.Errorf("res = %+v err = %v; the lookup failing before the write is known and never Unavailable", res, err)
		}
	})
}

func TestCreatePageErrors(t *testing.T) {
	cases := writeErrorCases(route{status: 200, body: "created_page.json"})
	cases[0].rt = route{status: 400, body: "error_confluence_title_exists.json"}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{spacesPath: {status: 200, body: "spaces_docs.json"}, createPagePath: tc.rt})
			c := newWriter(t, atlassian.ConfluenceApp, srv)
			res, err := c.Call(context.Background(), write(atlassian.ConfluenceApp, "create_page", map[string]any{"space_key": "DOCS", "title": "t", "body": "b"}))
			checkWriteError(t, "confluence", tc, res, err)
			if tc.name == "400 invalid argument" && !strings.Contains(err.Error(), "already exists") {
				t.Errorf("err = %v, want Confluence's message", err)
			}
		})
	}
}

// --- reconciliation: confluence.create_page -------------------------------------------

var (
	pageIdentity = map[string]string{"space": "DOCS"}
	markerCQL    = `space = "DOCS" AND type = page AND text ~ "\"` + marker + `\""`
)

func pageRoutes(hit route, spacePages map[string]route) map[string]route {
	routes := map[string]route{contentSearchPath: hit}
	if spacePages != nil {
		routes[spacesPath] = route{status: 200, body: "spaces_docs.json"}
		routes[spacePagesPath] = route{pageParam: "cursor", pages: spacePages}
	}
	return routes
}

func TestCheckPageFoundBySearch(t *testing.T) {
	srv := newAPIServer(t, pageRoutes(route{status: 200, body: "content_search_marker_hit.json"}, nil))
	c, tk := newConfluence(t, srv, connectors.Bounds{})
	res, err := toolNamed(t, c, "create_page").Reconcile.Check(context.Background(), reconcile(atlassian.ConfluenceApp, "create_page", pageIdentity))
	wantFound(t, res, err, "12400")
	q := query(t, srv, wikiBase+"/rest/api/content/search")
	if q.Get("cql") != markerCQL || !strings.Contains(q.Get("expand"), "body.storage") {
		t.Errorf("query = %v", q)
	}
	if len(tk.calls) != 1 || tk.calls[0] != alice+"/"+acct {
		t.Errorf("token source calls = %v", tk.calls)
	}
	if len(srv.Requests()) != 1 {
		t.Error("the fallback listing ran although the search found the page")
	}
}

func TestCheckPageFallsBackToTheSpacePages(t *testing.T) {
	pages := map[string]route{"": {status: 200, body: "space_pages_page1.json"}, "CURSOR2": {status: 200, body: "space_pages_page2.json"}}
	for name, hit := range map[string]route{
		"hit without the marker": {status: 200, body: "content_search_hit_without_marker.json"},
		"search error":           {status: 500, body: ""},
		"search miss":            {status: 200, body: "content_search_empty.json"},
	} {
		t.Run(name, func(t *testing.T) {
			srv := newAPIServer(t, pageRoutes(hit, pages))
			c, _ := newConfluence(t, srv, connectors.Bounds{})
			res, err := toolNamed(t, c, "create_page").Reconcile.Check(context.Background(), reconcile(atlassian.ConfluenceApp, "create_page", pageIdentity))
			wantFound(t, res, err, "12400")
			q := query(t, srv, wikiBase+"/api/v2/spaces/98765/pages")
			if q.Get("cursor") != "CURSOR2" || q.Get("sort") != "-created-date" || q.Get("body-format") != "storage" || q.Get("limit") != "100" {
				t.Errorf("last listing query = %v", q)
			}
		})
	}
}

func TestCheckPageNotFoundAndCannotTell(t *testing.T) {
	t.Run("not found at the end of the space", func(t *testing.T) {
		srv := newAPIServer(t, pageRoutes(route{status: 200, body: "content_search_empty.json"},
			map[string]route{"": {status: 200, body: "space_pages_page1.json"}, "CURSOR2": {status: 200, body: "space_pages_last_without_marker.json"}}))
		c, _ := newConfluence(t, srv, connectors.Bounds{})
		res, err := toolNamed(t, c, "create_page").Reconcile.Check(context.Background(), reconcile(atlassian.ConfluenceApp, "create_page", pageIdentity))
		wantNotFound(t, res, err)
	})
	t.Run("space gone is cannot tell", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{contentSearchPath: {status: 200, body: "content_search_empty.json"}, spacesPath: {status: 200, body: "spaces_empty.json"}})
		c, _ := newConfluence(t, srv, connectors.Bounds{})
		_, err := toolNamed(t, c, "create_page").Reconcile.Check(context.Background(), reconcile(atlassian.ConfluenceApp, "create_page", pageIdentity))
		wantClass(t, err, atlassian.ClassNotFound, 0)
	})
	t.Run("listing error", func(t *testing.T) {
		srv := newAPIServer(t, pageRoutes(route{status: 200, body: "content_search_empty.json"}, map[string]route{"": {status: 502, body: ""}}))
		c, _ := newConfluence(t, srv, connectors.Bounds{})
		_, err := toolNamed(t, c, "create_page").Reconcile.Check(context.Background(), reconcile(atlassian.ConfluenceApp, "create_page", pageIdentity))
		wantClass(t, err, atlassian.ClassUnavailable, 502)
	})
	t.Run("too many pages", func(t *testing.T) {
		pages := map[string]route{}
		for i := 0; i <= atlassian.MaxReconcilePages; i++ {
			cursor := ""
			if i > 0 {
				cursor = "C" + itoa(i)
			}
			pages[cursor] = route{status: 200, body: `{"results":[{"id":"1","body":{"storage":{"value":""}}}],"_links":{"next":"/wiki/api/v2/spaces/98765/pages?cursor=C` + itoa(i+1) + `"}}`}
		}
		srv := newAPIServer(t, pageRoutes(route{status: 200, body: "content_search_empty.json"}, pages))
		c, _ := newConfluence(t, srv, connectors.Bounds{})
		_, err := toolNamed(t, c, "create_page").Reconcile.Check(context.Background(), reconcile(atlassian.ConfluenceApp, "create_page", pageIdentity))
		if err == nil || !strings.Contains(err.Error(), "cannot tell yet") {
			t.Fatalf("Check err = %v, want cannot tell yet", err)
		}
		if n := srv.Count(spacePagesPath); n != atlassian.MaxReconcilePages {
			t.Errorf("listing requests = %d, want %d", n, atlassian.MaxReconcilePages)
		}
	})
	t.Run("needs the space", func(t *testing.T) {
		c, _ := newConfluence(t, newAPIServer(t, nil), connectors.Bounds{})
		_, err := toolNamed(t, c, "create_page").Reconcile.Check(context.Background(), reconcile(atlassian.ConfluenceApp, "create_page", map[string]string{}))
		if !errors.Is(err, atlassian.ErrNotReconcilable) {
			t.Errorf("err = %v, want ErrNotReconcilable", err)
		}
	})
}
