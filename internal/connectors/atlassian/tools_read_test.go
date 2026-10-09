package atlassian_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/atlassian"
)

// --- tool metadata ----------------------------------------------------------

type schemaShape struct {
	Type       string                    `json:"type"`
	Properties map[string]map[string]any `json:"properties"`
	Required   []string                  `json:"required"`
	Additional *bool                     `json:"additionalProperties"`
}

type metadataCase struct {
	app, tool string
	required  []string
	props     []string
	args      map[string]any
	identity  map[string]string
	scopes    []string
	page      bool
}

func checkMetadata(t *testing.T, tc metadataCase) {
	t.Helper()
	c, _ := newConnector(t, tc.app, newAPIServer(t, nil), connectors.Bounds{})
	tool := toolNamed(t, c, tc.tool)
	var s schemaShape
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
	if tc.page {
		if tool.Bounds.MaxPageSize <= 0 || tool.Bounds.MaxPageSize > 100 {
			t.Errorf("MaxPageSize = %d, want 1..100", tool.Bounds.MaxPageSize)
		}
	} else if tool.Bounds.MaxPageSize != 0 {
		t.Errorf("MaxPageSize = %d for a tool that does not paginate", tool.Bounds.MaxPageSize)
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
	if strings.Join(tool.RequiredScopes, ",") != strings.Join(tc.scopes, ",") {
		t.Errorf("RequiredScopes = %v, want %v", tool.RequiredScopes, tc.scopes)
	}
	if strings.TrimSpace(tool.Description) == "" {
		t.Error("empty description")
	}
}

func TestReadToolsMetadata(t *testing.T) {
	cases := []metadataCase{
		{
			app: atlassian.JiraApp, tool: "search_issues", required: []string{"jql"}, props: []string{"jql", "max_results", "fields", "next_page_token"},
			args:     map[string]any{"jql": `project = mock AND text ~ "secret"`, "max_results": 5},
			identity: map[string]string{"project": "MOCK"},
			scopes:   []string{"read:jira-work"}, page: true,
		},
		{
			app: atlassian.JiraApp, tool: "get_issue", required: []string{"key"}, props: []string{"key", "fields"},
			args:     map[string]any{"key": "mock-42"},
			identity: map[string]string{"project": "MOCK", "issue": "MOCK-42"},
			scopes:   []string{"read:jira-work"},
		},
		{
			app: atlassian.JiraApp, tool: "list_transitions", required: []string{"key"}, props: []string{"key"},
			args:     map[string]any{"key": "MOCK-42"},
			identity: map[string]string{"project": "MOCK", "issue": "MOCK-42"},
			scopes:   []string{"read:jira-work"},
		},
		{
			app: atlassian.ConfluenceApp, tool: "search", required: []string{"cql"}, props: []string{"cql", "limit", "start"},
			args:     map[string]any{"cql": `space = "DOCS" AND text ~ "secret"`, "limit": 5},
			identity: map[string]string{"space": "DOCS"},
			scopes:   []string{"search:confluence"}, page: true,
		},
		{
			app: atlassian.ConfluenceApp, tool: "get_page", required: []string{"id"}, props: []string{"id"},
			args:     map[string]any{"id": "123456"},
			identity: map[string]string{"page": "123456"},
			scopes:   []string{"read:page:confluence"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.app+"."+tc.tool, func(t *testing.T) { checkMetadata(t, tc) })
	}
}

func TestProjectFromJQL(t *testing.T) {
	c, _ := newJira(t, newAPIServer(t, nil), connectors.Bounds{})
	tool := toolNamed(t, c, "search_issues")
	cases := map[string]string{
		"project = MOCK":                         "MOCK",
		"project=mock order by created":          "MOCK",
		`project = "My Proj" AND status = Done`:  "",
		`project = "MOCK" AND status = Done`:     "MOCK",
		"project = 'MOCK'":                       "MOCK",
		"status = Done AND project = ABC_1":      "ABC_1",
		"project in (MOCK, OTHER)":               "",
		"project != MOCK":                        "",
		"text ~ \"project = MOCK\"":              "",
		"summary ~ foo":                          "",
		"issuetype = Bug AND Project = mock":     "MOCK",
		"project = MOCK OR project = OTHER":      "",
		"projectType = software":                 "",
		"project = 10001":                        "",
		"project in (MOCK) AND project = OTHER":  "",
		"assignee = currentUser() and project=X": "X",
	}
	for jql, want := range cases {
		got := tool.ResourceIdentity(map[string]any{"jql": jql})
		if got["project"] != want {
			t.Errorf("project of %q = %q, want %q", jql, got["project"], want)
		}
		if want == "" && len(got) != 0 {
			t.Errorf("identity of %q = %v, want empty", jql, got)
		}
	}
}

// --- error classes shared by every tool ------------------------------------------

func TestErrorClasses(t *testing.T) {
	cases := []struct {
		name   string
		rt     route
		class  string
		status int
		// unavailable means a Result{Unavailable} and no error.
		unavailable bool
		// retryAfter > 0 means a *connectors.RateLimited of that wait.
		retryAfter time.Duration
	}{
		{name: "400 invalid argument", rt: route{status: 400, body: "error_bad_jql.json"}, class: atlassian.ClassInvalidArgument, status: 400},
		{name: "401 reconnect", rt: route{status: 401, body: "error_unauthorized.json"}, class: atlassian.ClassReconnectRequired, status: 401},
		{name: "403 forbidden", rt: route{status: 403, body: "error_forbidden.json"}, class: atlassian.ClassForbidden, status: 403},
		{name: "404 not found", rt: route{status: 404, body: "error_not_found.json"}, class: atlassian.ClassNotFound, status: 404},
		{name: "409 vendor error", rt: route{status: 409, body: `{"errorMessages":["conflict"]}`}, class: atlassian.ClassVendorError, status: 409},
		{name: "500 unavailable", rt: route{status: 500, body: "error_server.json"}, unavailable: true},
		{name: "503 unavailable", rt: route{status: 503, body: ""}, unavailable: true},
		{name: "429 with Retry-After", rt: route{status: 429, body: "error_rate_limit.json", headers: map[string]string{"Retry-After": "37"}}, retryAfter: 37 * time.Second},
		{name: "429 without Retry-After", rt: route{status: 429, body: "error_rate_limit.json"}, retryAfter: atlassian.DefaultRetryAfter},
		{name: "200 malformed json", rt: route{status: 200, body: `{"issues": [`}, class: atlassian.ClassVendorError, status: 200},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"GET " + jiraBase + "/search/jql": tc.rt})
			c, _ := newJira(t, srv, connectors.Bounds{})
			res, err := c.Call(context.Background(), call(atlassian.JiraApp, "search_issues", map[string]any{"jql": "project = MOCK"}))
			switch {
			case tc.unavailable:
				if err != nil || !res.Unavailable || res.Content != nil {
					t.Fatalf("res = %+v err = %v, want Unavailable without content", res, err)
				}
			case tc.retryAfter > 0:
				var rl *connectors.RateLimited
				if !errors.As(err, &rl) {
					t.Fatalf("err = %v (%T), want *connectors.RateLimited", err, err)
				}
				if rl.App != "jira" {
					t.Errorf("App = %q, want jira", rl.App)
				}
				if rl.RetryAfter != tc.retryAfter {
					t.Errorf("RetryAfter = %s, want %s", rl.RetryAfter, tc.retryAfter)
				}
			default:
				wantClass(t, err, tc.class, tc.status)
				if strings.Contains(err.Error(), testToken) {
					t.Errorf("error message leaks the token: %q", err.Error())
				}
			}
		})
	}
}

func TestErrorMessageCarriesTheVendorMessage(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET " + jiraBase + "/search/jql": {status: 400, body: "error_bad_jql.json"}})
	c, _ := newJira(t, srv, connectors.Bounds{})
	_, err := c.Call(context.Background(), call(atlassian.JiraApp, "search_issues", map[string]any{"jql": "project MOCK"}))
	if err == nil || !strings.Contains(err.Error(), "Error in the JQL Query") {
		t.Errorf("err = %v, want Jira's errorMessages in the text", err)
	}
}

func TestNetworkFailureIsUnavailable(t *testing.T) {
	srv := newAPIServer(t, nil)
	c, _ := newJira(t, srv, connectors.Bounds{})
	srv.Close()
	res, err := c.Call(context.Background(), call(atlassian.JiraApp, "search_issues", map[string]any{"jql": "project = MOCK"}))
	if err != nil || !res.Unavailable {
		t.Fatalf("res = %+v err = %v, want Unavailable", res, err)
	}
}

func TestCancelledContextIsAnError(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET " + jiraBase + "/search/jql": {status: 200, body: "search_issues.json"}})
	c, _ := newJira(t, srv, connectors.Bounds{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := c.Call(ctx, call(atlassian.JiraApp, "search_issues", map[string]any{"jql": "project = MOCK"}))
	if !errors.Is(err, context.Canceled) || res.Unavailable {
		t.Fatalf("res = %+v err = %v, want context.Canceled", res, err)
	}
}

// --- jira.search_issues ---------------------------------------------------------

const searchPath = "GET " + jiraBase + "/search/jql"

type issuePage struct {
	Issues []struct {
		Key       string   `json:"key"`
		ID        string   `json:"id"`
		Summary   string   `json:"summary"`
		Status    string   `json:"status"`
		IssueType string   `json:"issue_type"`
		Priority  string   `json:"priority"`
		Assignee  string   `json:"assignee"`
		Reporter  string   `json:"reporter"`
		Labels    []string `json:"labels"`
		Created   string   `json:"created"`
		Updated   string   `json:"updated"`
		URL       string   `json:"url"`
		Project   string   `json:"project"`
	} `json:"issues"`
	MaxResults    int    `json:"max_results"`
	HasMore       bool   `json:"has_more"`
	NextPageToken string `json:"next_page_token"`
	Truncated     bool   `json:"truncated"`
}

// Prototype counterpart: test_jira_mock_server_lists_and_calls_tools
// (search_issues is listed and "project = MOCK" returns MOCK-1).
func TestSearchIssues(t *testing.T) {
	srv := newAPIServer(t, map[string]route{searchPath: {status: 200, body: "search_issues.json"}})
	c, tk := newJira(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call(atlassian.JiraApp, "search_issues", map[string]any{"jql": "project = MOCK"}))
	if err != nil {
		t.Fatalf("search_issues: %v", err)
	}
	var page issuePage
	decode(t, res, &page)
	if len(page.Issues) != 2 || page.HasMore || page.NextPageToken != "" || page.MaxResults != 10 {
		t.Errorf("page = %+v", page)
	}
	first := page.Issues[0]
	if first.Key != "MOCK-1" || first.ID != "10001" || first.Summary != "Mock issue from JQL search" || first.Status != "To Do" ||
		first.IssueType != "Task" || first.Priority != "Medium" || first.Assignee != "Alice Example" || first.Reporter != "Bob Example" ||
		first.Project != "MOCK" || first.URL != siteURL+"/browse/MOCK-1" || first.Created != "2026-10-01T10:00:00Z" {
		t.Errorf("issue = %+v", first)
	}
	if strings.Join(first.Labels, ",") != "bug,backend" {
		t.Errorf("labels = %v", first.Labels)
	}
	second := page.Issues[1]
	if second.Key != "MOCK-2" || second.Priority != "" || second.Assignee != "" || len(second.Labels) != 0 {
		t.Errorf("issue without priority/assignee = %+v", second)
	}
	if res.Empty || res.Partial || res.Unavailable {
		t.Errorf("markers = empty %v partial %v unavailable %v", res.Empty, res.Partial, res.Unavailable)
	}
	q := query(t, srv, jiraBase+"/search/jql")
	if q.Get("jql") != "project = MOCK" || q.Get("maxResults") != "10" || q.Get("nextPageToken") != "" {
		t.Errorf("query = %v", q)
	}
	if f := q.Get("fields"); !strings.Contains(f, "summary") || !strings.Contains(f, "status") || !strings.Contains(f, "project") {
		t.Errorf("fields = %q, want the default field set", f)
	}
	if len(tk.calls) != 1 || tk.calls[0] != alice+"/"+acct {
		t.Errorf("token source calls = %v", tk.calls)
	}
	req := srv.Requests()[0]
	if ua := req.Header.Get("User-Agent"); !strings.Contains(ua, "mcp-gateway") {
		t.Errorf("User-Agent = %q", ua)
	}
	if req.Header.Get("Accept") != "application/json" {
		t.Errorf("Accept = %q", req.Header.Get("Accept"))
	}
}

func TestSearchIssuesFieldsSubsetAndPaging(t *testing.T) {
	srv := newAPIServer(t, map[string]route{searchPath: {status: 200, body: "search_issues_more.json"}})
	c, _ := newJira(t, srv, connectors.Bounds{MaxPageSize: 20})
	res, err := c.Call(context.Background(), call(atlassian.JiraApp, "search_issues", map[string]any{
		"jql": "project = MOCK", "max_results": 1, "fields": []any{"summary", "status"}, "next_page_token": "CAEaAggB",
	}))
	if err != nil {
		t.Fatalf("search_issues: %v", err)
	}
	var page issuePage
	decode(t, res, &page)
	if !page.HasMore || page.NextPageToken != "CAEaAggD" || page.MaxResults != 1 || len(page.Issues) != 1 {
		t.Errorf("page = %+v", page)
	}
	if res.Partial {
		t.Error("a page with more pages after it is not Partial")
	}
	q := query(t, srv, jiraBase+"/search/jql")
	if q.Get("fields") != "summary,status" || q.Get("maxResults") != "1" || q.Get("nextPageToken") != "CAEaAggB" {
		t.Errorf("query = %v", q)
	}
	if page.Issues[0].Priority != "" || page.Issues[0].Assignee != "" {
		t.Errorf("fields outside the subset came back filled: %+v", page.Issues[0])
	}
}

func TestSearchIssuesClampedIsPartial(t *testing.T) {
	srv := newAPIServer(t, map[string]route{searchPath: {status: 200, body: "search_issues.json"}})
	c, _ := newJira(t, srv, connectors.Bounds{MaxPageSize: 10})
	res, err := c.Call(context.Background(), call(atlassian.JiraApp, "search_issues", map[string]any{"jql": "project = MOCK", "max_results": 500}))
	if err != nil {
		t.Fatal(err)
	}
	var page issuePage
	decode(t, res, &page)
	if !res.Partial || page.MaxResults != 10 {
		t.Errorf("res = %+v page = %+v, want Partial with max_results clamped to 10", res, page)
	}
	if got := query(t, srv, jiraBase+"/search/jql").Get("maxResults"); got != "10" {
		t.Errorf("sent maxResults = %q, want 10", got)
	}
}

func TestSearchIssuesTruncatedToBounds(t *testing.T) {
	srv := newAPIServer(t, map[string]route{searchPath: {status: 200, body: "search_issues.json"}})
	c, _ := newJira(t, srv, connectors.Bounds{MaxResultBytes: 400})
	res, err := c.Call(context.Background(), call(atlassian.JiraApp, "search_issues", map[string]any{"jql": "project = MOCK"}))
	if err != nil {
		t.Fatal(err)
	}
	var page issuePage
	decode(t, res, &page)
	if !res.Partial || !page.Truncated || len(page.Issues) != 1 {
		t.Errorf("res = %+v page = %+v, want one issue left and truncated", res, page)
	}
}

func TestSearchIssuesEmpty(t *testing.T) {
	srv := newAPIServer(t, map[string]route{searchPath: {status: 200, body: "search_issues_empty.json"}})
	c, _ := newJira(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call(atlassian.JiraApp, "search_issues", map[string]any{"jql": "project = NOTHING"}))
	if err != nil {
		t.Fatal(err)
	}
	var page issuePage
	decode(t, res, &page)
	if !res.Empty || res.Partial || len(page.Issues) != 0 || page.Issues == nil {
		t.Errorf("res = %+v issues = %v (want Empty with an empty issues array)", res, page.Issues)
	}
}

func TestSearchIssuesValidation(t *testing.T) {
	srv := newAPIServer(t, nil)
	c, _ := newJira(t, srv, connectors.Bounds{})
	cases := map[string]map[string]any{
		"missing jql":      {},
		"blank jql":        {"jql": "  "},
		"zero max_results": {"jql": "project = MOCK", "max_results": 0},
		"bad max_results":  {"jql": "project = MOCK", "max_results": "lots"},
		"unknown field":    {"jql": "project = MOCK", "fields": []any{"customfield_10001"}},
		"fields not array": {"jql": "project = MOCK", "fields": "summary"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := c.Call(context.Background(), call(atlassian.JiraApp, "search_issues", args))
			wantClass(t, err, atlassian.ClassInvalidArgument, 0)
		})
	}
	if n := len(srv.Requests()); n != 0 {
		t.Errorf("%d requests sent for invalid arguments", n)
	}
}
