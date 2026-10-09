package github_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/github"
)

// --- tool metadata ----------------------------------------------------------

func TestWriteToolsMetadata(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	tools := map[string]connectors.Tool{}
	var order []string
	for _, tool := range c.Tools() {
		tools[tool.Name] = tool
		if tool.Kind == connectors.KindWrite {
			order = append(order, tool.Name)
		}
	}
	wantOrder := []string{"create_issue", "add_issue_comment", "create_pull_request", "create_branch"}
	if strings.Join(order, ",") != strings.Join(wantOrder, ",") {
		t.Fatalf("write tools = %v, want %v", order, wantOrder)
	}
	type schema struct {
		Type       string                    `json:"type"`
		Properties map[string]map[string]any `json:"properties"`
		Required   []string                  `json:"required"`
		Additional *bool                     `json:"additionalProperties"`
	}
	cases := []struct {
		tool      string
		kind      connectors.ReconcileKind
		scopes    []string
		required  []string
		props     []string
		args      map[string]any
		identity  map[string]string
		resultIDs []string
	}{
		{
			tool: "create_issue", kind: connectors.ReconcileMarker, scopes: []string{"issues:write"},
			required: []string{"owner", "repo", "title"}, props: []string{"owner", "repo", "title", "body", "labels", "assignees"},
			args:     map[string]any{"owner": "Example-Org", "repo": "Widgets", "title": "secret title", "body": "secret body"},
			identity: map[string]string{"owner": "example-org", "repo": "example-org/widgets", "org": "example-org"},
		},
		{
			tool: "add_issue_comment", kind: connectors.ReconcileMarker, scopes: []string{"issues:write"},
			required: []string{"owner", "repo", "number", "body"}, props: []string{"owner", "repo", "number", "body"},
			args:     map[string]any{"owner": "example-org", "repo": "widgets", "number": 42, "body": "secret body"},
			identity: map[string]string{"owner": "example-org", "repo": "example-org/widgets", "org": "example-org", "number": "42"},
		},
		{
			tool: "create_pull_request", kind: connectors.ReconcileMarker, scopes: []string{"pull_requests:write"},
			required: []string{"owner", "repo", "title", "head", "base"}, props: []string{"owner", "repo", "title", "head", "base", "body", "draft"},
			args:     map[string]any{"owner": "example-org", "repo": "widgets", "title": "secret", "head": "Feature/Thing", "base": "main", "body": "secret body"},
			identity: map[string]string{"owner": "example-org", "repo": "example-org/widgets", "org": "example-org", "branch": "Feature/Thing", "base": "main"},
		},
		{
			tool: "create_branch", kind: connectors.ReconcileStableID, scopes: []string{"contents:write"},
			required: []string{"owner", "repo", "branch"}, props: []string{"owner", "repo", "branch", "from_branch"},
			args:     map[string]any{"owner": "example-org", "repo": "widgets", "branch": "Feature/Thing", "from_branch": "main"},
			identity: map[string]string{"owner": "example-org", "repo": "example-org/widgets", "org": "example-org", "branch": "Feature/Thing"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			tool, ok := tools[tc.tool]
			if !ok {
				t.Fatalf("tool %s not declared", tc.tool)
			}
			if tool.Kind != connectors.KindWrite {
				t.Errorf("Kind = %q, want write", tool.Kind)
			}
			if tool.Reconcile.Kind != tc.kind || tool.Reconcile.Check == nil {
				t.Errorf("Reconcile = kind %q check %v, want kind %q with a Check", tool.Reconcile.Kind, tool.Reconcile.Check != nil, tc.kind)
			}
			if tool.ResultIDs == nil {
				t.Error("ResultIDs is nil")
			}
			if strings.Join(tool.RequiredScopes, ",") != strings.Join(tc.scopes, ",") {
				t.Errorf("RequiredScopes = %v, want %v", tool.RequiredScopes, tc.scopes)
			}
			if tool.Bounds.MaxPageSize != 0 || tool.Bounds.MaxResultBytes <= 0 {
				t.Errorf("Bounds = %+v, want no page size and a result bound", tool.Bounds)
			}
			if strings.TrimSpace(tool.Description) == "" {
				t.Error("empty description")
			}
			var s schema
			if err := json.Unmarshal(tool.InputSchema, &s); err != nil {
				t.Fatalf("schema: %v", err)
			}
			if s.Type != "object" || s.Additional == nil || *s.Additional {
				t.Errorf("schema must be a closed object: %s", tool.InputSchema)
			}
			if strings.Join(s.Required, ",") != strings.Join(tc.required, ",") {
				t.Errorf("required = %v, want %v", s.Required, tc.required)
			}
			for _, p := range tc.props {
				if s.Properties[p] == nil {
					t.Errorf("property %q missing", p)
				} else if d, _ := s.Properties[p]["description"].(string); strings.TrimSpace(d) == "" {
					t.Errorf("property %q has no description", p)
				}
			}
			if len(s.Properties) != len(tc.props) {
				t.Errorf("properties = %d, want %d: %s", len(s.Properties), len(tc.props), tool.InputSchema)
			}
			got := tool.ResourceIdentity(tc.args)
			if len(got) != len(tc.identity) {
				t.Errorf("ResourceIdentity = %v, want %v", got, tc.identity)
			}
			for k, v := range tc.identity {
				if got[k] != v {
					t.Errorf("ResourceIdentity[%s] = %q, want %q (all: %v)", k, got[k], v, got)
				}
			}
			for _, v := range got {
				if strings.Contains(v, "secret") {
					t.Errorf("ResourceIdentity leaks argument content: %v", got)
				}
			}
			if id := tool.ResourceIdentity(nil); id == nil || len(id) != 0 {
				t.Errorf("ResourceIdentity(nil) = %v, want empty map", id)
			}
		})
	}
}

// --- write helpers ------------------------------------------------------------

const opID = "0f1e2d3c-4b5a-4968-8777-66554433aa11"

// marker is the hidden HTML comment every marker-reconciled write embeds.
const marker = "<!-- mcp-gateway op:" + opID + " -->"

// write builds a write call under the ledger operation opID.
func write(tool string, args map[string]any) connectors.Call { //nolint:unparam // the other writes' tests use it too

	c := call(tool, args)
	c.OperationID = opID
	return c
}

// jsonBody decodes a recorded request body.
func jsonBody(t *testing.T, r recorded) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(r.Body), &m); err != nil {
		t.Fatalf("request body %q: %v", r.Body, err)
	}
	return m
}

// writeErrorCases are the vendor answers every write maps the same way.
func writeErrorCases() []struct {
	name    string
	rt      route
	class   string
	status  int
	unknown bool
	rateLim bool
} {
	return []struct {
		name    string
		rt      route
		class   string
		status  int
		unknown bool
		rateLim bool
	}{
		{name: "422 invalid argument", rt: route{status: 422, body: "error_validation.json"}, class: github.ClassInvalidArgument, status: 422},
		{name: "403 forbidden", rt: route{status: 403, body: "error_forbidden.json"}, class: github.ClassForbidden, status: 403},
		{name: "404 not found", rt: route{status: 404, body: "error_not_found.json"}, class: github.ClassNotFound, status: 404},
		{name: "401 reconnect", rt: route{status: 401, body: "error_bad_credentials.json"}, class: github.ClassReconnectRequired, status: 401},
		{name: "429 rate limited", rt: route{status: 429, body: "error_secondary_rate_limit.json", headers: map[string]string{"Retry-After": "7"}}, rateLim: true},
		{name: "500 outcome unknown", rt: route{status: 500, body: "error_server.json"}, unknown: true},
		{name: "502 outcome unknown", rt: route{status: 502, body: "error_server.json"}, unknown: true},
		{name: "timeout outcome unknown", rt: route{status: 201, body: "created_issue.json", delay: 2 * time.Second}, unknown: true},
	}
}

// checkWriteError asserts the outcome of one writeErrorCases entry.
func checkWriteError(t *testing.T, tc struct {
	name    string
	rt      route
	class   string
	status  int
	unknown bool
	rateLim bool
}, res connectors.Result, err error) {
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
		if !errors.As(err, &rl) || rl.App != "github" || rl.RetryAfter != 7*time.Second {
			t.Fatalf("err = %v (%T), want *connectors.RateLimited of 7s", err, err)
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

// --- create_issue -------------------------------------------------------------------

const createIssuePath = "POST /repos/example-org/widgets/issues"

func TestCreateIssue(t *testing.T) {
	srv := newAPIServer(t, map[string]route{createIssuePath: {status: 201, body: "created_issue.json"}})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), write("create_issue", map[string]any{
		"owner": "example-org", "repo": "widgets", "title": "Add a retry to the uploader",
		"body": "The uploader gives up on the first timeout.", "labels": []any{"bug"}, "assignees": []any{"hubot"},
	}))
	if err != nil {
		t.Fatalf("create_issue: %v", err)
	}
	created, ok := res.Content.(github.CreatedIssue)
	if !ok || created.Number != 57 || created.ID != 2001 || created.URL != "https://github.example.test/example-org/widgets/issues/57" || created.Repo != "example-org/widgets" {
		t.Errorf("content = %#v", res.Content)
	}
	if res.Empty || res.Partial || res.Unavailable {
		t.Errorf("markers = %+v", res)
	}
	tool := toolNamed(t, c, "create_issue")
	ids := tool.ResultIDs(res)
	if ids["number"] != "57" || ids["id"] != "2001" || ids["url"] != created.URL || len(ids) != 3 {
		t.Errorf("ResultIDs = %v", ids)
	}
	if tool.ResultIDs(connectors.Result{}) != nil {
		t.Error("ResultIDs of an empty result should be nil")
	}
	body := jsonBody(t, srv.Last(t, createIssuePath))
	if body["title"] != "Add a retry to the uploader" {
		t.Errorf("title = %v", body["title"])
	}
	if got := body["body"]; got != "The uploader gives up on the first timeout.\n\n"+marker {
		t.Errorf("body = %q, want the text followed by the marker", got)
	}
	if fmt.Sprint(body["labels"]) != "[bug]" || fmt.Sprint(body["assignees"]) != "[hubot]" {
		t.Errorf("labels/assignees = %v / %v", body["labels"], body["assignees"])
	}
	if len(tk.calls) != 1 || tk.calls[0] != alice+"/"+acct {
		t.Errorf("token source calls = %v", tk.calls)
	}
}

func TestCreateIssueWithoutBodyCarriesOnlyTheMarker(t *testing.T) {
	srv := newAPIServer(t, map[string]route{createIssuePath: {status: 201, body: "created_issue.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	if _, err := c.Call(context.Background(), write(github.ToolCreateIssue, map[string]any{"owner": "example-org", "repo": "widgets", "title": "t"})); err != nil {
		t.Fatal(err)
	}
	body := jsonBody(t, srv.Last(t, createIssuePath))
	if body["body"] != marker {
		t.Errorf("body = %q, want just the marker", body["body"])
	}
	if _, ok := body["labels"]; ok {
		t.Errorf("labels sent when none given: %v", body)
	}
}

func TestCreateIssueValidation(t *testing.T) {
	srv := newAPIServer(t, nil)
	c, _ := newConnector(t, srv, connectors.Bounds{})
	cases := map[string]map[string]any{
		"missing title": {"owner": "example-org", "repo": "widgets"},
		"blank title":   {"owner": "example-org", "repo": "widgets", "title": "  "},
		"bad owner":     {"owner": "", "repo": "widgets", "title": "t"},
		"bad labels":    {"owner": "example-org", "repo": "widgets", "title": "t", "labels": "bug"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := c.Call(context.Background(), write("create_issue", args))
			wantClass(t, err, github.ClassInvalidArgument, 0)
		})
	}
	if n := len(srv.Requests()); n != 0 {
		t.Errorf("%d requests sent for invalid arguments", n)
	}
}

func TestWritesRequireAnOperationID(t *testing.T) {
	srv := newAPIServer(t, nil)
	c, tk := newConnector(t, srv, connectors.Bounds{})
	for _, tool := range []string{"create_issue", "add_issue_comment", "create_pull_request", "create_branch"} {
		_, err := c.Call(context.Background(), call(tool, map[string]any{"owner": "example-org", "repo": "widgets", "title": "t", "number": 1, "body": "b", "head": "h", "base": "b", "branch": "x"}))
		if !errors.Is(err, github.ErrMissingOperation) {
			t.Errorf("%s without an operation id: err = %v, want ErrMissingOperation", tool, err)
		}
	}
	if len(srv.Requests()) != 0 || len(tk.calls) != 0 {
		t.Errorf("requests = %d, token calls = %v; want none", len(srv.Requests()), tk.calls)
	}
}

func TestCreateIssueErrors(t *testing.T) {
	for _, tc := range writeErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{createIssuePath: tc.rt})
			c, err := github.New(github.Options{Tokens: (&tokens{}).source, BaseURL: srv.URL + "/", Timeout: 300 * time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			res, err := c.Call(context.Background(), write("create_issue", map[string]any{"owner": "example-org", "repo": "widgets", "title": "t"}))
			checkWriteError(t, tc, res, err)
		})
	}
}

func TestCreateIssueConnectionLostIsUnknown(t *testing.T) {
	srv := newAPIServer(t, nil)
	c, _ := newConnector(t, srv, connectors.Bounds{})
	srv.Close()
	res, err := c.Call(context.Background(), write("create_issue", map[string]any{"owner": "example-org", "repo": "widgets", "title": "t"}))
	if !errors.Is(err, connectors.ErrOutcomeUnknown) || res.Unavailable {
		t.Fatalf("res = %+v err = %v, want ErrOutcomeUnknown (never Unavailable for a write)", res, err)
	}
}

// toolNamed returns the connector's tool by short name.
func toolNamed(t *testing.T, c *github.Connector, name string) connectors.Tool { //nolint:unparam // the other writes' tests use it too
	t.Helper()
	for _, tool := range c.Tools() {
		if tool.Name == name {
			return tool
		}
	}
	t.Fatalf("tool %s not declared", name)
	return connectors.Tool{}
}

// --- reconciliation: create_issue ------------------------------------------------------

const (
	searchPath = "GET /search/issues"
	userPath   = "GET /user"
	issuesPath = "GET /repos/example-org/widgets/issues"
)

// reconcile builds the input the ledger's reconciler hands to Check:
// the principal and account, the operation id and the stored resource
// identity; never arguments.
func reconcile(tool string, identity map[string]string) connectors.ReconcileInput { //nolint:unparam // the other writes' tests use it too
	return connectors.ReconcileInput{
		Call:             connectors.Call{Principal: connectors.Principal{UserID: alice, TokenID: "tok"}, Tool: "github." + tool, Account: acct, OperationID: opID},
		OperationID:      opID,
		ResourceIdentity: identity,
	}
}

var issueIdentity = map[string]string{"owner": "example-org", "repo": "example-org/widgets", "org": "example-org"}

// byCreatorPages is the paginated fallback listing: page 1 without the
// marker (and a next page), page 2 with it.
func byCreatorPages(last string) route {
	return route{pages: map[string]route{
		"1": {status: 200, body: "issues_by_creator_page1.json", headers: map[string]string{"Link": `<https://api.github.example.test/repos/example-org/widgets/issues?page=2>; rel="next", <https://api.github.example.test/repos/example-org/widgets/issues?page=2>; rel="last"`}},
		"2": {status: 200, body: last},
	}}
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

func TestCheckIssueFoundBySearch(t *testing.T) {
	srv := newAPIServer(t, map[string]route{searchPath: {status: 200, body: "search_marker_hit.json"}})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	res, err := toolNamed(t, c, "create_issue").Reconcile.Check(context.Background(), reconcile("create_issue", issueIdentity))
	wantFound(t, res, err, "57")
	q := query(t, srv, "/search/issues")
	if got := q.Get("q"); got != `repo:example-org/widgets "mcp-gateway op:`+opID+`" in:body` {
		t.Errorf("q = %q", got)
	}
	if len(tk.calls) != 1 || tk.calls[0] != alice+"/"+acct {
		t.Errorf("token source calls = %v", tk.calls)
	}
	if srv.Count(userPath) != 0 || srv.Count(issuesPath) != 0 {
		t.Error("the fallback listing ran although the search found the issue")
	}
}

func TestCheckIssueSearchHitWithoutMarkerIsNotTrusted(t *testing.T) {
	// The search index answered with an issue that does not carry this
	// operation's marker (another operation's issue): the fallback decides.
	srv := newAPIServer(t, map[string]route{
		searchPath: {status: 200, body: "search_issues.json"},
		userPath:   {status: 200, body: "user.json"},
		issuesPath: byCreatorPages("issues_by_creator_page2.json"),
	})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := toolNamed(t, c, "create_issue").Reconcile.Check(context.Background(), reconcile("create_issue", issueIdentity))
	wantFound(t, res, err, "57")
}

func TestCheckIssueFallsBackToListingByCreator(t *testing.T) {
	for name, search := range map[string]route{
		"search empty": {status: 200, body: "search_issues_empty.json"},
		"search 500":   {status: 500, body: "error_server.json"},
		"search 403":   {status: 403, body: "error_forbidden.json"},
	} {
		t.Run(name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{
				searchPath: search,
				userPath:   {status: 200, body: "user.json"},
				issuesPath: byCreatorPages("issues_by_creator_page2.json"),
			})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := toolNamed(t, c, "create_issue").Reconcile.Check(context.Background(), reconcile("create_issue", issueIdentity))
			wantFound(t, res, err, "57")
			q := query(t, srv, "/repos/example-org/widgets/issues")
			if q.Get("creator") != "octocat" || q.Get("state") != "all" || q.Get("sort") != "created" || q.Get("direction") != "desc" {
				t.Errorf("listing query = %v, want creator=octocat state=all sort=created direction=desc", q)
			}
			if n := srv.Count(issuesPath); n != 2 {
				t.Errorf("listing requests = %d, want 2 (the marker is on page 2)", n)
			}
		})
	}
}

func TestCheckIssueNotFound(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		searchPath: {status: 200, body: "search_issues_empty.json"},
		userPath:   {status: 200, body: "user.json"},
		issuesPath: byCreatorPages("[]"),
	})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := toolNamed(t, c, "create_issue").Reconcile.Check(context.Background(), reconcile("create_issue", issueIdentity))
	wantNotFound(t, res, err)
}

func TestCheckIssueCannotTell(t *testing.T) {
	cases := map[string]map[string]route{
		"listing 500": {
			searchPath: {status: 200, body: "search_issues_empty.json"},
			userPath:   {status: 200, body: "user.json"},
			issuesPath: {status: 500, body: "error_server.json"},
		},
		"listing 401": {
			searchPath: {status: 200, body: "search_issues_empty.json"},
			userPath:   {status: 401, body: "error_bad_credentials.json"},
		},
		"listing rate limited": {
			searchPath: {status: 200, body: "search_issues_empty.json"},
			userPath:   {status: 200, body: "user.json"},
			issuesPath: {status: 429, body: "error_secondary_rate_limit.json", headers: map[string]string{"Retry-After": "3"}},
		},
		"too many pages": {
			searchPath: {status: 200, body: "search_issues_empty.json"},
			userPath:   {status: 200, body: "user.json"},
			issuesPath: {status: 200, body: "issues_by_creator_page1.json", headers: map[string]string{"Link": `<https://api.github.example.test/repos/example-org/widgets/issues?page=99>; rel="next"`}},
		},
	}
	for name, routes := range cases {
		t.Run(name, func(t *testing.T) {
			srv := newAPIServer(t, routes)
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := toolNamed(t, c, "create_issue").Reconcile.Check(context.Background(), reconcile("create_issue", issueIdentity))
			if err == nil {
				t.Fatalf("Check = %+v, want an error (cannot tell yet)", res)
			}
			if name == "too many pages" && srv.Count(issuesPath) > 5 {
				t.Errorf("listing requests = %d, want at most 5", srv.Count(issuesPath))
			}
		})
	}
}

func TestCheckIssueNeedsIdentityAndOperation(t *testing.T) {
	srv := newAPIServer(t, nil)
	c, _ := newConnector(t, srv, connectors.Bounds{})
	check := toolNamed(t, c, "create_issue").Reconcile.Check
	if _, err := check(context.Background(), reconcile("create_issue", map[string]string{"owner": "example-org"})); err == nil {
		t.Error("Check without a repo in the identity succeeded")
	}
	in := reconcile("create_issue", issueIdentity)
	in.OperationID, in.Call.OperationID = "", ""
	if _, err := check(context.Background(), in); err == nil {
		t.Error("Check without an operation id succeeded")
	}
	if n := len(srv.Requests()); n != 0 {
		t.Errorf("%d requests sent", n)
	}
}
