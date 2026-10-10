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

// --- jira.get_issue ------------------------------------------------------------------

const issuePath = "GET " + jiraBase + "/issue/MOCK-42"

type issueDetail struct {
	Key         string   `json:"key"`
	ID          string   `json:"id"`
	Summary     string   `json:"summary"`
	Description string   `json:"description"`
	Status      string   `json:"status"`
	IssueType   string   `json:"issue_type"`
	Priority    string   `json:"priority"`
	Assignee    string   `json:"assignee"`
	Reporter    string   `json:"reporter"`
	Labels      []string `json:"labels"`
	Components  []string `json:"components"`
	Resolution  string   `json:"resolution"`
	Created     string   `json:"created"`
	Updated     string   `json:"updated"`
	URL         string   `json:"url"`
	Project     string   `json:"project"`
	Truncated   bool     `json:"truncated"`
}

func TestGetIssue(t *testing.T) {
	srv := newAPIServer(t, map[string]route{issuePath: {status: 200, body: "issue.json"}})
	c, _ := newJira(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call(atlassian.JiraApp, "get_issue", map[string]any{"key": "mock-42"}))
	if err != nil {
		t.Fatalf("get_issue: %v", err)
	}
	var is issueDetail
	decode(t, res, &is)
	if is.Key != "MOCK-42" || is.ID != "10042" || is.Summary != "Uploader gives up on the first timeout" || is.Status != "In Progress" ||
		is.IssueType != "Bug" || is.Priority != "High" || is.Assignee != "Alice Example" || is.Reporter != "Bob Example" ||
		is.Resolution != "" || is.Project != "MOCK" || is.URL != siteURL+"/browse/MOCK-42" || is.Updated != "2026-10-05T16:45:12Z" || is.Truncated {
		t.Errorf("issue = %+v", is)
	}
	if strings.Join(is.Components, ",") != "uploader,api" || strings.Join(is.Labels, ",") != "bug" {
		t.Errorf("components/labels = %v / %v", is.Components, is.Labels)
	}
	want := "The uploader retries never.\nfirst item\nsecond item\nline one\nline two\n please look"
	if is.Description != want {
		t.Errorf("description = %q, want %q (ADF flattened to text)", is.Description, want)
	}
	if res.Empty || res.Partial || res.Unavailable {
		t.Errorf("markers = %+v", res)
	}
	q := query(t, srv, jiraBase+"/issue/MOCK-42")
	if f := q.Get("fields"); !strings.Contains(f, "description") || !strings.Contains(f, "components") {
		t.Errorf("fields = %q, want the detail field set", f)
	}
}

func TestGetIssuePlainStringDescription(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET " + jiraBase + "/issue/MOCK-43": {status: 200, body: "issue_v2_description.json"}})
	c, _ := newJira(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call(atlassian.JiraApp, "get_issue", map[string]any{"key": "MOCK-43"}))
	if err != nil {
		t.Fatal(err)
	}
	var is issueDetail
	decode(t, res, &is)
	if is.Description != "A plain string description" || is.Priority != "" || is.Assignee != "" {
		t.Errorf("issue = %+v", is)
	}
}

func TestGetIssueFieldsSubset(t *testing.T) {
	srv := newAPIServer(t, map[string]route{issuePath: {status: 200, body: "issue.json"}})
	c, _ := newJira(t, srv, connectors.Bounds{})
	if _, err := c.Call(context.Background(), call(atlassian.JiraApp, "get_issue", map[string]any{"key": "MOCK-42", "fields": []any{"summary", "description"}})); err != nil {
		t.Fatal(err)
	}
	if got := query(t, srv, jiraBase+"/issue/MOCK-42").Get("fields"); got != "summary,description" {
		t.Errorf("fields = %q", got)
	}
}

func TestGetIssueTruncatesTheDescription(t *testing.T) {
	srv := newAPIServer(t, map[string]route{issuePath: {status: 200, body: "issue.json"}})
	c, _ := newJira(t, srv, connectors.Bounds{MaxResultBytes: 450})
	res, err := c.Call(context.Background(), call(atlassian.JiraApp, "get_issue", map[string]any{"key": "MOCK-42"}))
	if err != nil {
		t.Fatal(err)
	}
	var is issueDetail
	decode(t, res, &is)
	if !res.Partial || !is.Truncated || is.Summary == "" || len(is.Description) >= len("The uploader retries never.\nfirst item\nsecond item\nline one\nline two\n please look") {
		t.Errorf("res = %+v issue = %+v, want the description cut and the rest kept", res, is)
	}
	if n := encodedSize(t, res.Content); n > 450 {
		t.Errorf("encoded size = %d, want <= 450", n)
	}
}

func encodedSize(t *testing.T, v any) int {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return len(b)
}

func TestGetIssueErrors(t *testing.T) {
	cases := []struct {
		name   string
		rt     route
		class  string
		status int
	}{
		{"404", route{status: 404, body: "error_not_found.json"}, atlassian.ClassNotFound, 404},
		{"401", route{status: 401, body: "error_unauthorized.json"}, atlassian.ClassReconnectRequired, 401},
		{"403", route{status: 403, body: "error_forbidden.json"}, atlassian.ClassForbidden, 403},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{issuePath: tc.rt})
			c, _ := newJira(t, srv, connectors.Bounds{})
			_, err := c.Call(context.Background(), call(atlassian.JiraApp, "get_issue", map[string]any{"key": "MOCK-42"}))
			wantClass(t, err, tc.class, tc.status)
		})
	}
	t.Run("5xx unavailable", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{issuePath: {status: 502, body: "error_server.json"}})
		c, _ := newJira(t, srv, connectors.Bounds{})
		res, err := c.Call(context.Background(), call(atlassian.JiraApp, "get_issue", map[string]any{"key": "MOCK-42"}))
		if err != nil || !res.Unavailable {
			t.Fatalf("res = %+v err = %v", res, err)
		}
	})
	t.Run("429", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{issuePath: {status: 429, body: "error_rate_limit.json", headers: map[string]string{"Retry-After": "5"}}})
		c, _ := newJira(t, srv, connectors.Bounds{})
		_, err := c.Call(context.Background(), call(atlassian.JiraApp, "get_issue", map[string]any{"key": "MOCK-42"}))
		var rl *connectors.RateLimited
		if !errors.As(err, &rl) || rl.RetryAfter != 5*time.Second {
			t.Fatalf("err = %v, want RateLimited 5s", err)
		}
	})
}

func TestGetIssueValidation(t *testing.T) {
	srv := newAPIServer(t, nil)
	c, _ := newJira(t, srv, connectors.Bounds{})
	for name, args := range map[string]map[string]any{
		"missing key":   {},
		"not a key":     {"key": "42"},
		"path escape":   {"key": "MOCK-42/../../x"},
		"unknown field": {"key": "MOCK-42", "fields": []any{"nope"}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := c.Call(context.Background(), call(atlassian.JiraApp, "get_issue", args))
			wantClass(t, err, atlassian.ClassInvalidArgument, 0)
		})
	}
	if n := len(srv.Requests()); n != 0 {
		t.Errorf("%d requests sent for invalid arguments", n)
	}
}

// --- jira.list_transitions ------------------------------------------------------------

const transitionsPath = "GET " + jiraBase + "/issue/MOCK-42/transitions"

type transitionsOut struct {
	Issue       string `json:"issue"`
	Transitions []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		To   string `json:"to"`
	} `json:"transitions"`
}

func TestListTransitions(t *testing.T) {
	srv := newAPIServer(t, map[string]route{transitionsPath: {status: 200, body: "transitions.json"}})
	c, _ := newJira(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call(atlassian.JiraApp, "list_transitions", map[string]any{"key": "MOCK-42"}))
	if err != nil {
		t.Fatalf("list_transitions: %v", err)
	}
	var out transitionsOut
	decode(t, res, &out)
	if out.Issue != "MOCK-42" || len(out.Transitions) != 3 {
		t.Fatalf("out = %+v", out)
	}
	if tr := out.Transitions[1]; tr.ID != "21" || tr.Name != "In Progress" || tr.To != "In Progress" {
		t.Errorf("transition = %+v", tr)
	}
	if res.Empty || res.Partial {
		t.Errorf("markers = %+v", res)
	}
}

func TestListTransitionsEmptyAndErrors(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{transitionsPath: {status: 200, body: "transitions_empty.json"}})
		c, _ := newJira(t, srv, connectors.Bounds{})
		res, err := c.Call(context.Background(), call(atlassian.JiraApp, "list_transitions", map[string]any{"key": "MOCK-42"}))
		if err != nil || !res.Empty {
			t.Fatalf("res = %+v err = %v, want Empty", res, err)
		}
		var out transitionsOut
		decode(t, res, &out)
		if out.Transitions == nil || len(out.Transitions) != 0 {
			t.Errorf("transitions = %v, want an empty array", out.Transitions)
		}
	})
	t.Run("404", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{transitionsPath: {status: 404, body: "error_not_found.json"}})
		c, _ := newJira(t, srv, connectors.Bounds{})
		_, err := c.Call(context.Background(), call(atlassian.JiraApp, "list_transitions", map[string]any{"key": "MOCK-42"}))
		wantClass(t, err, atlassian.ClassNotFound, 404)
	})
	t.Run("invalid key", func(t *testing.T) {
		c, _ := newJira(t, newAPIServer(t, nil), connectors.Bounds{})
		_, err := c.Call(context.Background(), call(atlassian.JiraApp, "list_transitions", map[string]any{"key": "nope"}))
		wantClass(t, err, atlassian.ClassInvalidArgument, 0)
	})
}

// --- confluence.search ------------------------------------------------------------------

const contentSearchPath = "GET " + wikiBase + "/rest/api/content/search"

type contentPage struct {
	Results []struct {
		ID           string `json:"id"`
		Type         string `json:"type"`
		Status       string `json:"status"`
		Title        string `json:"title"`
		Space        string `json:"space"`
		URL          string `json:"url"`
		LastModified string `json:"last_modified"`
	} `json:"results"`
	Start     int  `json:"start"`
	Limit     int  `json:"limit"`
	Size      int  `json:"size"`
	HasMore   bool `json:"has_more"`
	Truncated bool `json:"truncated"`
}

// Prototype counterpart: test_confluence_mock_server_lists_and_calls_tools
// (the search tool is listed and "type=page" returns "Mock Confluence page").
func TestConfluenceSearch(t *testing.T) {
	srv := newAPIServer(t, map[string]route{contentSearchPath: {status: 200, body: "content_search.json"}})
	c, tk := newConfluence(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call(atlassian.ConfluenceApp, "search", map[string]any{"cql": "type=page"}))
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	var page contentPage
	decode(t, res, &page)
	if len(page.Results) != 2 || page.HasMore || page.Start != 0 || page.Limit != 10 || page.Size != 2 {
		t.Errorf("page = %+v", page)
	}
	first := page.Results[0]
	if first.ID != "12345" || first.Title != "Mock Confluence page" || first.Type != "page" || first.Status != "current" || first.Space != "DOCS" ||
		first.URL != siteURL+"/wiki/spaces/DOCS/pages/12345/Mock+Confluence+page" || first.LastModified != "2026-10-03T09:15:00Z" {
		t.Errorf("result = %+v", first)
	}
	if page.Results[1].Type != "blogpost" {
		t.Errorf("second = %+v", page.Results[1])
	}
	if res.Empty || res.Partial || res.Unavailable {
		t.Errorf("markers = %+v", res)
	}
	q := query(t, srv, wikiBase+"/rest/api/content/search")
	if q.Get("cql") != "type=page" || q.Get("limit") != "10" || q.Get("start") != "0" || !strings.Contains(q.Get("expand"), "space") {
		t.Errorf("query = %v", q)
	}
	if len(tk.calls) != 1 || tk.calls[0] != alice+"/"+acct {
		t.Errorf("token source calls = %v", tk.calls)
	}
}

func TestConfluenceSearchPagingClampAndTruncation(t *testing.T) {
	t.Run("has_more from the next link", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{contentSearchPath: {status: 200, body: "content_search_more.json"}})
		c, _ := newConfluence(t, srv, connectors.Bounds{})
		res, err := c.Call(context.Background(), call(atlassian.ConfluenceApp, "search", map[string]any{"cql": "type=page", "limit": 1, "start": 5}))
		if err != nil {
			t.Fatal(err)
		}
		var page contentPage
		decode(t, res, &page)
		if !page.HasMore || page.Start != 5 || page.Limit != 1 || res.Partial {
			t.Errorf("res = %+v page = %+v", res, page)
		}
		q := query(t, srv, wikiBase+"/rest/api/content/search")
		if q.Get("limit") != "1" || q.Get("start") != "5" {
			t.Errorf("query = %v", q)
		}
	})
	t.Run("clamped is partial", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{contentSearchPath: {status: 200, body: "content_search.json"}})
		c, _ := newConfluence(t, srv, connectors.Bounds{MaxPageSize: 10})
		res, err := c.Call(context.Background(), call(atlassian.ConfluenceApp, "search", map[string]any{"cql": "type=page", "limit": 500}))
		if err != nil {
			t.Fatal(err)
		}
		var page contentPage
		decode(t, res, &page)
		if !res.Partial || page.Limit != 10 || query(t, srv, wikiBase+"/rest/api/content/search").Get("limit") != "10" {
			t.Errorf("res = %+v page = %+v", res, page)
		}
	})
	t.Run("truncated to the bounds", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{contentSearchPath: {status: 200, body: "content_search.json"}})
		c, _ := newConfluence(t, srv, connectors.Bounds{MaxResultBytes: 300})
		res, err := c.Call(context.Background(), call(atlassian.ConfluenceApp, "search", map[string]any{"cql": "type=page"}))
		if err != nil {
			t.Fatal(err)
		}
		var page contentPage
		decode(t, res, &page)
		if !res.Partial || !page.Truncated || len(page.Results) != 1 {
			t.Errorf("res = %+v page = %+v", res, page)
		}
	})
}

func TestConfluenceSearchEmptyAndErrors(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{contentSearchPath: {status: 200, body: "content_search_empty.json"}})
		c, _ := newConfluence(t, srv, connectors.Bounds{})
		res, err := c.Call(context.Background(), call(atlassian.ConfluenceApp, "search", map[string]any{"cql": "type=page AND title = nothing"}))
		if err != nil || !res.Empty || res.Partial {
			t.Fatalf("res = %+v err = %v, want Empty", res, err)
		}
		var page contentPage
		decode(t, res, &page)
		if page.Results == nil {
			t.Error("results should be an empty array, not null")
		}
	})
	t.Run("400 bad cql carries the message", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{contentSearchPath: {status: 400, body: "error_confluence_bad_cql.json"}})
		c, _ := newConfluence(t, srv, connectors.Bounds{})
		_, err := c.Call(context.Background(), call(atlassian.ConfluenceApp, "search", map[string]any{"cql": "type==page"}))
		wantClass(t, err, atlassian.ClassInvalidArgument, 400)
		if !strings.Contains(err.Error(), "Could not parse cql") {
			t.Errorf("err = %v, want Confluence's message", err)
		}
	})
	t.Run("429 is rate limited under the confluence app", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{contentSearchPath: {status: 429, body: "", headers: map[string]string{"Retry-After": "12"}}})
		c, _ := newConfluence(t, srv, connectors.Bounds{})
		_, err := c.Call(context.Background(), call(atlassian.ConfluenceApp, "search", map[string]any{"cql": "type=page"}))
		var rl *connectors.RateLimited
		if !errors.As(err, &rl) || rl.App != "confluence" || rl.RetryAfter != 12*time.Second {
			t.Fatalf("err = %v, want RateLimited confluence 12s", err)
		}
	})
	t.Run("5xx unavailable", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{contentSearchPath: {status: 500, body: ""}})
		c, _ := newConfluence(t, srv, connectors.Bounds{})
		res, err := c.Call(context.Background(), call(atlassian.ConfluenceApp, "search", map[string]any{"cql": "type=page"}))
		if err != nil || !res.Unavailable {
			t.Fatalf("res = %+v err = %v", res, err)
		}
	})
	t.Run("validation", func(t *testing.T) {
		srv := newAPIServer(t, nil)
		c, _ := newConfluence(t, srv, connectors.Bounds{})
		for name, args := range map[string]map[string]any{
			"missing cql":    {},
			"zero limit":     {"cql": "type=page", "limit": 0},
			"negative start": {"cql": "type=page", "start": -1},
		} {
			_, err := c.Call(context.Background(), call(atlassian.ConfluenceApp, "search", args))
			if err == nil {
				t.Errorf("%s: no error", name)
				continue
			}
			wantClass(t, err, atlassian.ClassInvalidArgument, 0)
		}
		if n := len(srv.Requests()); n != 0 {
			t.Errorf("%d requests sent for invalid arguments", n)
		}
	})
}

func TestSpaceFromCQL(t *testing.T) {
	c, _ := newConfluence(t, newAPIServer(t, nil), connectors.Bounds{})
	tool := toolNamed(t, c, "search")
	for cql, want := range map[string]string{
		"space = DOCS AND type = page":                    "DOCS",
		`space="DOCS"`:                                    "DOCS",
		"space = ~alice":                                  "~alice",
		"space in (DOCS, ENG)":                            "",
		"space = DOCS OR space = ENG":                     "",
		`text ~ "space = DOCS"`:                           "",
		"type = page":                                     "",
		"space.key = DOCS":                                "",
		"ancestor = 123 and space = eng order by created": "eng",
	} {
		if got := tool.ResourceIdentity(map[string]any{"cql": cql})["space"]; got != want {
			t.Errorf("space of %q = %q, want %q", cql, got, want)
		}
	}
}

// --- confluence.get_page ------------------------------------------------------------------

const pagePath = "GET " + wikiBase + "/api/v2/pages/12345"

type pageOut struct {
	ID         string `json:"id"`
	Title      string `json:"title"`
	Status     string `json:"status"`
	SpaceID    string `json:"space_id"`
	ParentID   string `json:"parent_id"`
	Version    int    `json:"version"`
	BodyFormat string `json:"body_format"`
	Body       string `json:"body"`
	URL        string `json:"url"`
	CreatedAt  string `json:"created_at"`
	Truncated  bool   `json:"truncated"`
}

func TestGetPage(t *testing.T) {
	srv := newAPIServer(t, map[string]route{pagePath: {status: 200, body: "page.json"}})
	c, _ := newConfluence(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call(atlassian.ConfluenceApp, "get_page", map[string]any{"id": "12345"}))
	if err != nil {
		t.Fatalf("get_page: %v", err)
	}
	var p pageOut
	decode(t, res, &p)
	if p.ID != "12345" || p.Title != "Mock Confluence page" || p.Status != "current" || p.SpaceID != "98765" || p.ParentID != "12000" ||
		p.Version != 3 || p.BodyFormat != "storage" || !strings.HasPrefix(p.Body, "<p>Mock Confluence page body</p>") ||
		p.URL != siteURL+"/wiki/spaces/DOCS/pages/12345/Mock+Confluence+page" || p.CreatedAt != "2026-09-30T12:00:00Z" || p.Truncated {
		t.Errorf("page = %+v", p)
	}
	if res.Empty || res.Partial || res.Unavailable {
		t.Errorf("markers = %+v", res)
	}
	if got := query(t, srv, wikiBase+"/api/v2/pages/12345").Get("body-format"); got != "storage" {
		t.Errorf("body-format = %q", got)
	}
}

func TestGetPageTruncatesTheBody(t *testing.T) {
	srv := newAPIServer(t, map[string]route{pagePath: {status: 200, body: "page.json"}})
	c, _ := newConfluence(t, srv, connectors.Bounds{MaxResultBytes: 300})
	res, err := c.Call(context.Background(), call(atlassian.ConfluenceApp, "get_page", map[string]any{"id": "12345"}))
	if err != nil {
		t.Fatal(err)
	}
	var p pageOut
	decode(t, res, &p)
	if !res.Partial || !p.Truncated || p.Title == "" || len(p.Body) >= len("<p>Mock Confluence page body</p><ul><li>one</li><li>two</li></ul>") {
		t.Errorf("res = %+v page = %+v, want the body cut and the rest kept", res, p)
	}
	if n := encodedSize(t, res.Content); n > 300 {
		t.Errorf("encoded size = %d", n)
	}
}

func TestGetPageErrorsAndValidation(t *testing.T) {
	t.Run("404 with confluence message", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{"GET " + wikiBase + "/api/v2/pages/99999": {status: 404, body: "error_confluence_not_found.json"}})
		c, _ := newConfluence(t, srv, connectors.Bounds{})
		_, err := c.Call(context.Background(), call(atlassian.ConfluenceApp, "get_page", map[string]any{"id": "99999"}))
		wantClass(t, err, atlassian.ClassNotFound, 404)
		if !strings.Contains(err.Error(), "No content found") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("401 reconnect", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{pagePath: {status: 401, body: "error_unauthorized.json"}})
		c, _ := newConfluence(t, srv, connectors.Bounds{})
		_, err := c.Call(context.Background(), call(atlassian.ConfluenceApp, "get_page", map[string]any{"id": "12345"}))
		wantClass(t, err, atlassian.ClassReconnectRequired, 401)
	})
	t.Run("403 forbidden", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{pagePath: {status: 403, body: ""}})
		c, _ := newConfluence(t, srv, connectors.Bounds{})
		_, err := c.Call(context.Background(), call(atlassian.ConfluenceApp, "get_page", map[string]any{"id": "12345"}))
		wantClass(t, err, atlassian.ClassForbidden, 403)
	})
	t.Run("validation", func(t *testing.T) {
		srv := newAPIServer(t, nil)
		c, _ := newConfluence(t, srv, connectors.Bounds{})
		for _, args := range []map[string]any{{}, {"id": "abc"}, {"id": "12/../x"}, {"id": 12345}} {
			_, err := c.Call(context.Background(), call(atlassian.ConfluenceApp, "get_page", args))
			if err == nil {
				t.Errorf("%v: no error", args)
				continue
			}
			wantClass(t, err, atlassian.ClassInvalidArgument, 0)
		}
		if n := len(srv.Requests()); n != 0 {
			t.Errorf("%d requests sent for invalid arguments", n)
		}
	})
}
