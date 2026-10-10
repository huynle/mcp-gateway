package github_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/github"
)

const (
	alice = "user-alice"
	acct  = "0b7f7a2e-1c7e-4c2a-9a39-2d2a6c0f9b11"
)

// tokens is the TokenSourceFunc of the tests: every call records who asked
// for which connection and gets the fixture token, unless fail is set.
type tokens struct {
	calls []string
	fail  error
}

func (tk *tokens) source(_ context.Context, userID, connectionID string) oauth2.TokenSource {
	tk.calls = append(tk.calls, userID+"/"+connectionID)
	if tk.fail != nil {
		return failingSource{err: tk.fail}
	}
	return oauth2.StaticTokenSource(&oauth2.Token{AccessToken: testToken})
}

type failingSource struct{ err error }

func (f failingSource) Token() (*oauth2.Token, error) { return nil, f.err }

// newConnector builds a connector against the fixture server.
func newConnector(t *testing.T, srv *apiServer, bounds connectors.Bounds) (*github.Connector, *tokens) {
	t.Helper()
	tk := &tokens{}
	c, err := github.New(github.Options{Tokens: tk.source, BaseURL: srv.URL + "/", Bounds: bounds})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, tk
}

func call(tool string, args map[string]any) connectors.Call {
	if args == nil {
		args = map[string]any{}
	}
	return connectors.Call{Principal: connectors.Principal{UserID: alice, TokenID: "tok"}, Tool: "github." + tool, Account: acct, Args: args}
}

// decode marshals a result's content and decodes it into v.
func decode(t *testing.T, res connectors.Result, v any) {
	t.Helper()
	raw, err := json.Marshal(res.Content)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
}

func wantClass(t *testing.T, err error, class string, status int) {
	t.Helper()
	var ghErr *github.Error
	if !errors.As(err, &ghErr) {
		t.Fatalf("err = %v (%T), want *github.Error class %s", err, err, class)
	}
	if ghErr.Class != class || ghErr.Status != status {
		t.Fatalf("err = class %s status %d (%v), want class %s status %d", ghErr.Class, ghErr.Status, err, class, status)
	}
}

func query(t *testing.T, srv *apiServer, path string) url.Values {
	t.Helper()
	reqs := srv.Requests()
	for i := len(reqs) - 1; i >= 0; i-- {
		if reqs[i].URL.Path == path {
			return reqs[i].URL.Query()
		}
	}
	t.Fatalf("no request to %s (saw %d requests)", path, len(reqs))
	return nil
}

// --- tool metadata ----------------------------------------------------------

func TestToolsStartWithTheFiveReads(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	if c.App() != "github" {
		t.Errorf("App() = %q", c.App())
	}
	var names []string
	for _, tool := range c.Tools() {
		if tool.Kind != connectors.KindRead {
			continue
		}
		names = append(names, tool.Name)
		if tool.Reconcile.Kind != "" || tool.ResultIDs != nil {
			t.Errorf("%s: a read must not declare reconciliation or ResultIDs", tool.Name)
		}
		if tool.Bounds.MaxResultBytes <= 0 {
			t.Errorf("%s: MaxResultBytes = %d", tool.Name, tool.Bounds.MaxResultBytes)
		}
	}
	want := []string{"get_me", "search_issues", "get_issue", "get_pull_request", "list_pull_request_files"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("read tools = %v, want %v", names, want)
	}
	if got := len(c.Tools()); got != len(want)+4 {
		t.Errorf("Tools() = %d tools, want the %d reads and 4 writes", got, len(want))
	}
}

func TestToolSchemasAndIdentity(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	tools := map[string]connectors.Tool{}
	for _, tool := range c.Tools() {
		tools[tool.Name] = tool
	}
	type schema struct {
		Type       string                    `json:"type"`
		Properties map[string]map[string]any `json:"properties"`
		Required   []string                  `json:"required"`
		Additional *bool                     `json:"additionalProperties"`
	}
	cases := []struct {
		tool     string
		required []string
		props    []string
		args     map[string]any
		identity map[string]string
		scopes   []string
		page     bool
	}{
		{tool: "get_me", args: map[string]any{}, identity: map[string]string{}},
		{
			tool: "search_issues", required: []string{"q"}, props: []string{"q", "owner", "repo", "sort", "order", "page", "per_page"},
			args:     map[string]any{"q": "is:open label:bug", "owner": "Example-Org", "repo": "widgets"},
			identity: map[string]string{"owner": "example-org", "repo": "example-org/widgets", "org": "example-org"},
			page:     true,
		},
		{
			tool: "get_issue", required: []string{"owner", "repo", "number"}, props: []string{"owner", "repo", "number"},
			args:     map[string]any{"owner": "example-org", "repo": "widgets", "number": 42},
			identity: map[string]string{"owner": "example-org", "repo": "example-org/widgets", "org": "example-org", "number": "42"},
			scopes:   []string{"issues:read"},
		},
		{
			tool: "get_pull_request", required: []string{"owner", "repo", "number"}, props: []string{"owner", "repo", "number"},
			args:     map[string]any{"owner": "example-org", "repo": "widgets", "number": float64(43)},
			identity: map[string]string{"owner": "example-org", "repo": "example-org/widgets", "org": "example-org", "number": "43"},
			scopes:   []string{"pull_requests:read"},
		},
		{
			tool: "list_pull_request_files", required: []string{"owner", "repo", "number"}, props: []string{"owner", "repo", "number", "page", "per_page"},
			args:     map[string]any{"owner": "example-org", "repo": "widgets", "number": "43"},
			identity: map[string]string{"owner": "example-org", "repo": "example-org/widgets", "org": "example-org", "number": "43"},
			scopes:   []string{"pull_requests:read"},
			page:     true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			tool, ok := tools[tc.tool]
			if !ok {
				t.Fatalf("tool %s not declared", tc.tool)
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
			if tc.page {
				if s.Properties["per_page"]["type"] != "integer" || s.Properties["page"]["type"] != "integer" {
					t.Errorf("page/per_page must be integers: %s", tool.InputSchema)
				}
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
			if id := tool.ResourceIdentity(nil); id == nil || len(id) != 0 {
				t.Errorf("ResourceIdentity(nil) = %v, want empty map", id)
			}
			if strings.Join(tool.RequiredScopes, ",") != strings.Join(tc.scopes, ",") {
				t.Errorf("RequiredScopes = %v, want %v", tool.RequiredScopes, tc.scopes)
			}
		})
	}
}

func TestNewRequiresTokens(t *testing.T) {
	if _, err := github.New(github.Options{}); err == nil {
		t.Error("New without Tokens succeeded")
	}
	if _, err := github.New(github.Options{Tokens: (&tokens{}).source, BaseURL: "not a url"}); err == nil {
		t.Error("New with a bad BaseURL succeeded")
	}
}

// --- get_me -------------------------------------------------------------------

func TestGetMe(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /user": {status: 200, body: "user.json"}})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call("get_me", nil))
	if err != nil {
		t.Fatalf("get_me: %v", err)
	}
	var me struct {
		Login      string `json:"login"`
		ID         int64  `json:"id"`
		Name       string `json:"name"`
		ProfileURL string `json:"profile_url"`
	}
	decode(t, res, &me)
	if me.Login != "octocat" || me.ID != 583231 || me.Name != "The Octocat" || me.ProfileURL == "" {
		t.Errorf("get_me = %+v", me)
	}
	if res.Empty || res.Partial || res.Unavailable {
		t.Errorf("markers = empty %v partial %v unavailable %v", res.Empty, res.Partial, res.Unavailable)
	}
	if len(tk.calls) != 1 || tk.calls[0] != alice+"/"+acct {
		t.Errorf("token source calls = %v, want [%s/%s]", tk.calls, alice, acct)
	}
	if ua := srv.Requests()[0].Header.Get("User-Agent"); !strings.Contains(ua, "mcp-gateway") {
		t.Errorf("User-Agent = %q", ua)
	}
}

func TestCallWithoutAccount(t *testing.T) {
	c, tk := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	in := call("get_me", nil)
	in.Account = ""
	_, err := c.Call(context.Background(), in)
	wantClass(t, err, github.ClassNoAccount, 0)
	if len(tk.calls) != 0 {
		t.Errorf("token source consulted without an account: %v", tk.calls)
	}
}

func TestCallNeedsReconnectFromTokenSource(t *testing.T) {
	c, tk := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	tk.fail = connections.ErrNeedsReconnect
	_, err := c.Call(context.Background(), call("get_me", nil))
	wantClass(t, err, github.ClassReconnectRequired, 0)
	if !errors.Is(err, connections.ErrNeedsReconnect) {
		t.Errorf("err %v does not wrap ErrNeedsReconnect", err)
	}
}

func TestUnknownTool(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	if _, err := c.Call(context.Background(), call("nope", nil)); !errors.Is(err, connectors.ErrUnknownTool) {
		t.Errorf("err = %v, want ErrUnknownTool", err)
	}
}

// --- error classes shared by every tool ------------------------------------------

func TestErrorClasses(t *testing.T) {
	reset := strconv.FormatInt(time.Now().Add(90*time.Second).Unix(), 10)
	cases := []struct {
		name   string
		rt     route
		class  string
		status int
		// unavailable means a Result{Unavailable} and no error.
		unavailable bool
		// retryAfter > 0 means a *connectors.RateLimited of about that wait.
		retryAfter time.Duration
	}{
		{name: "401 reconnect", rt: route{status: 401, body: "error_bad_credentials.json"}, class: github.ClassReconnectRequired, status: 401},
		{name: "403 forbidden", rt: route{status: 403, body: "error_forbidden.json"}, class: github.ClassForbidden, status: 403},
		{name: "404 not found", rt: route{status: 404, body: "error_not_found.json"}, class: github.ClassNotFound, status: 404},
		{name: "500 unavailable", rt: route{status: 500, body: "error_server.json"}, unavailable: true},
		{name: "502 unavailable", rt: route{status: 502, body: "error_server.json"}, unavailable: true},
		{
			name:       "403 primary rate limit",
			rt:         route{status: 403, body: "error_rate_limit.json", headers: map[string]string{"X-RateLimit-Limit": "5000", "X-RateLimit-Remaining": "0", "X-RateLimit-Reset": reset}},
			retryAfter: 90 * time.Second,
		},
		{
			name:       "429 secondary rate limit",
			rt:         route{status: 429, body: "error_secondary_rate_limit.json", headers: map[string]string{"Retry-After": "37"}},
			retryAfter: 37 * time.Second,
		},
		{
			name:       "403 secondary rate limit without Retry-After",
			rt:         route{status: 403, body: "error_secondary_rate_limit.json"},
			retryAfter: github.DefaultRetryAfter,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"GET /repos/example-org/widgets/issues/42": tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := c.Call(context.Background(), call("get_issue", map[string]any{"owner": "example-org", "repo": "widgets", "number": 42}))
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
				if rl.App != "github" {
					t.Errorf("App = %q", rl.App)
				}
				if d := rl.RetryAfter - tc.retryAfter; d < -2*time.Second || d > 2*time.Second {
					t.Errorf("RetryAfter = %s, want about %s", rl.RetryAfter, tc.retryAfter)
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

func TestNetworkFailureIsUnavailable(t *testing.T) {
	srv := newAPIServer(t, nil)
	c, _ := newConnector(t, srv, connectors.Bounds{})
	srv.Close()
	res, err := c.Call(context.Background(), call("get_me", nil))
	if err != nil || !res.Unavailable {
		t.Fatalf("res = %+v err = %v, want Unavailable", res, err)
	}
}

func TestCancelledContextIsAnError(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /user": {status: 200, body: "user.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := c.Call(ctx, call("get_me", nil))
	if !errors.Is(err, context.Canceled) || res.Unavailable {
		t.Fatalf("res = %+v err = %v, want context.Canceled", res, err)
	}
}

// --- search_issues ------------------------------------------------------------

type searchPage struct {
	TotalCount        int  `json:"total_count"`
	IncompleteResults bool `json:"incomplete_results"`
	Page              int  `json:"page"`
	PerPage           int  `json:"per_page"`
	HasMore           bool `json:"has_more"`
	Truncated         bool `json:"truncated"`
	Items             []struct {
		Number        int      `json:"number"`
		Title         string   `json:"title"`
		State         string   `json:"state"`
		URL           string   `json:"url"`
		Repo          string   `json:"repo"`
		IsPullRequest bool     `json:"is_pull_request"`
		Labels        []string `json:"labels"`
		User          string   `json:"user"`
	} `json:"items"`
}

func TestSearchIssues(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /search/issues": {status: 200, body: "search_issues.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call("search_issues", map[string]any{"q": "empty password", "owner": "example-org", "repo": "widgets", "sort": "updated", "order": "desc"}))
	if err != nil {
		t.Fatalf("search_issues: %v", err)
	}
	var page searchPage
	decode(t, res, &page)
	if page.TotalCount != 2 || len(page.Items) != 2 || page.HasMore || page.Page != 1 {
		t.Errorf("page = %+v", page)
	}
	first := page.Items[0]
	if first.Number != 42 || first.Title == "" || first.State != "open" || first.Repo != "example-org/widgets" || first.URL == "" || first.IsPullRequest || first.User != "octocat" {
		t.Errorf("item = %+v", first)
	}
	if len(first.Labels) != 2 || first.Labels[0] != "bug" {
		t.Errorf("labels = %v", first.Labels)
	}
	if !page.Items[1].IsPullRequest {
		t.Error("second item should be flagged as a pull request")
	}
	if res.Empty || res.Partial || res.Unavailable {
		t.Errorf("markers = empty %v partial %v unavailable %v", res.Empty, res.Partial, res.Unavailable)
	}
	q := query(t, srv, "/search/issues")
	if got := q.Get("q"); got != "repo:example-org/widgets empty password" {
		t.Errorf("q = %q", got)
	}
	if q.Get("sort") != "updated" || q.Get("order") != "desc" {
		t.Errorf("sort/order = %q/%q", q.Get("sort"), q.Get("order"))
	}
	if q.Get("per_page") != "30" || q.Get("page") != "1" {
		t.Errorf("per_page/page = %q/%q, want 30/1 by default", q.Get("per_page"), q.Get("page"))
	}
}

func TestSearchIssuesKeepsExplicitRepoQualifier(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /search/issues": {status: 200, body: "search_issues.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	if _, err := c.Call(context.Background(), call("search_issues", map[string]any{"q": "repo:other/thing bug", "owner": "example-org", "repo": "widgets"})); err != nil {
		t.Fatal(err)
	}
	if got := query(t, srv, "/search/issues").Get("q"); got != "repo:other/thing bug" {
		t.Errorf("q = %q, want the harness's own repo: qualifier kept", got)
	}
}

func TestSearchIssuesRequiresQuery(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	_, err := c.Call(context.Background(), call("search_issues", map[string]any{"q": "  "}))
	wantClass(t, err, github.ClassInvalidArgument, 0)
}

func TestSearchIssuesEmpty(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /search/issues": {status: 200, body: "search_issues_empty.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call("search_issues", map[string]any{"q": "nothing"}))
	if err != nil {
		t.Fatal(err)
	}
	var page searchPage
	decode(t, res, &page)
	if !res.Empty || res.Partial || len(page.Items) != 0 || page.Items == nil {
		t.Errorf("res = %+v items = %v (want Empty with an empty items array)", res, page.Items)
	}
}

func TestSearchIssuesIncompleteIsPartial(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /search/issues": {status: 200, body: "search_issues_incomplete.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call("search_issues", map[string]any{"q": "slow"}))
	if err != nil {
		t.Fatal(err)
	}
	var page searchPage
	decode(t, res, &page)
	if !res.Partial || res.Empty || !page.IncompleteResults || len(page.Items) != 1 {
		t.Errorf("res = %+v page = %+v, want Partial (GitHub timed out)", res, page)
	}
}

func TestSearchIssuesPagination(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /search/issues": {status: 200, body: "search_issues.json", headers: map[string]string{
		"Link": `<https://api.github.example.test/search/issues?q=x&page=3>; rel="next", <https://api.github.example.test/search/issues?q=x&page=9>; rel="last"`,
	}}})
	c, _ := newConnector(t, srv, connectors.Bounds{MaxPageSize: 10})
	t.Run("within bounds", func(t *testing.T) {
		res, err := c.Call(context.Background(), call("search_issues", map[string]any{"q": "x", "page": 2, "per_page": 5}))
		if err != nil {
			t.Fatal(err)
		}
		var page searchPage
		decode(t, res, &page)
		if page.Page != 2 || page.PerPage != 5 || !page.HasMore {
			t.Errorf("page = %+v, want page 2 per_page 5 has_more", page)
		}
		if res.Partial {
			t.Error("a page with more pages after it is not Partial")
		}
		q := query(t, srv, "/search/issues")
		if q.Get("page") != "2" || q.Get("per_page") != "5" {
			t.Errorf("sent page/per_page = %q/%q", q.Get("page"), q.Get("per_page"))
		}
	})
	t.Run("clamped to MaxPageSize is partial", func(t *testing.T) {
		res, err := c.Call(context.Background(), call("search_issues", map[string]any{"q": "x", "per_page": 500}))
		if err != nil {
			t.Fatal(err)
		}
		var page searchPage
		decode(t, res, &page)
		if !res.Partial || page.PerPage != 10 {
			t.Errorf("res = %+v page = %+v, want Partial with per_page clamped to 10", res, page)
		}
		if got := query(t, srv, "/search/issues").Get("per_page"); got != "10" {
			t.Errorf("sent per_page = %q, want 10", got)
		}
	})
	t.Run("invalid page", func(t *testing.T) {
		_, err := c.Call(context.Background(), call("search_issues", map[string]any{"q": "x", "page": 0}))
		wantClass(t, err, github.ClassInvalidArgument, 0)
		_, err = c.Call(context.Background(), call("search_issues", map[string]any{"q": "x", "per_page": "lots"}))
		wantClass(t, err, github.ClassInvalidArgument, 0)
	})
}

func TestSearchIssuesTruncatedToResultBytes(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /search/issues": {status: 200, body: "search_issues.json"}})
	// Both items are about 700 bytes together; one fits in 600.
	c, _ := newConnector(t, srv, connectors.Bounds{MaxResultBytes: 600})
	res, err := c.Call(context.Background(), call("search_issues", map[string]any{"q": "x"}))
	if err != nil {
		t.Fatal(err)
	}
	var page searchPage
	decode(t, res, &page)
	raw, _ := json.Marshal(res.Content)
	if !res.Partial || !page.Truncated || len(page.Items) != 1 || len(raw) > 600 {
		t.Errorf("res partial=%v truncated=%v items=%d bytes=%d, want Partial, truncated, 1 item, <= 600 bytes", res.Partial, page.Truncated, len(page.Items), len(raw))
	}
}

// --- get_issue -------------------------------------------------------------------

func TestGetIssue(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /repos/example-org/widgets/issues/42": {status: 200, body: "issue.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call("get_issue", map[string]any{"owner": "example-org", "repo": "widgets", "number": 42}))
	if err != nil {
		t.Fatalf("get_issue: %v", err)
	}
	var issue struct {
		Number    int      `json:"number"`
		Title     string   `json:"title"`
		Body      string   `json:"body"`
		State     string   `json:"state"`
		URL       string   `json:"url"`
		Repo      string   `json:"repo"`
		User      string   `json:"user"`
		Labels    []string `json:"labels"`
		Assignees []string `json:"assignees"`
		Milestone string   `json:"milestone"`
		Comments  int      `json:"comments"`
		CreatedAt string   `json:"created_at"`
	}
	decode(t, res, &issue)
	if issue.Number != 42 || issue.State != "open" || issue.Repo != "example-org/widgets" || issue.User != "octocat" || issue.Milestone != "v1.0" || issue.Comments != 3 || !strings.Contains(issue.Body, "Expected") || issue.CreatedAt != "2024-03-01T10:00:00Z" {
		t.Errorf("issue = %+v", issue)
	}
	if len(issue.Labels) != 1 || len(issue.Assignees) != 1 || issue.Assignees[0] != "hubot" {
		t.Errorf("labels/assignees = %v/%v", issue.Labels, issue.Assignees)
	}
	if res.Empty || res.Partial || res.Unavailable {
		t.Errorf("markers = %+v", res)
	}
}

func TestGetIssueArguments(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	for name, args := range map[string]map[string]any{
		"missing number":  {"owner": "example-org", "repo": "widgets"},
		"zero number":     {"owner": "example-org", "repo": "widgets", "number": 0},
		"fractional":      {"owner": "example-org", "repo": "widgets", "number": 1.5},
		"missing owner":   {"repo": "widgets", "number": 1},
		"owner with path": {"owner": "example-org/x", "repo": "widgets", "number": 1},
		"repo with space": {"owner": "example-org", "repo": "wid gets", "number": 1},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := c.Call(context.Background(), call("get_issue", args))
			wantClass(t, err, github.ClassInvalidArgument, 0)
		})
	}
}

func TestGetIssueBodyTruncatedToResultBytes(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /repos/example-org/widgets/issues/42": {status: 200, body: "issue.json"}})
	// The issue without its body is about 380 bytes; 420 leaves room for
	// part of the body only.
	const fullBody = "Steps: leave the password empty and submit.\n\nExpected: a validation message."
	c, _ := newConnector(t, srv, connectors.Bounds{MaxResultBytes: 420})
	res, err := c.Call(context.Background(), call("get_issue", map[string]any{"owner": "example-org", "repo": "widgets", "number": 42}))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(res.Content)
	var issue struct {
		Body      string `json:"body"`
		Truncated bool   `json:"truncated"`
	}
	decode(t, res, &issue)
	if !res.Partial || !issue.Truncated || len(raw) > 420 || issue.Body == "" || !strings.HasPrefix(fullBody, issue.Body) {
		t.Errorf("partial=%v truncated=%v bytes=%d body=%q, want Partial, truncated, <= 420 bytes with a prefix of the body", res.Partial, issue.Truncated, len(raw), issue.Body)
	}
}

// --- get_pull_request ------------------------------------------------------------

func TestGetPullRequest(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /repos/example-org/widgets/pulls/43": {status: 200, body: "pull.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call("get_pull_request", map[string]any{"owner": "example-org", "repo": "widgets", "number": 43}))
	if err != nil {
		t.Fatalf("get_pull_request: %v", err)
	}
	var pr struct {
		Number         int    `json:"number"`
		Title          string `json:"title"`
		State          string `json:"state"`
		Draft          bool   `json:"draft"`
		Merged         bool   `json:"merged"`
		MergeableState string `json:"mergeable_state"`
		URL            string `json:"url"`
		Repo           string `json:"repo"`
		User           string `json:"user"`
		Head           struct {
			Ref  string `json:"ref"`
			SHA  string `json:"sha"`
			Repo string `json:"repo"`
		} `json:"head"`
		Base struct {
			Ref string `json:"ref"`
		} `json:"base"`
		RequestedReviewers []string `json:"requested_reviewers"`
		Additions          int      `json:"additions"`
		ChangedFiles       int      `json:"changed_files"`
	}
	decode(t, res, &pr)
	if pr.Number != 43 || pr.State != "open" || pr.Merged || pr.MergeableState != "clean" || pr.Repo != "example-org/widgets" || pr.User != "hubot" || pr.URL == "" {
		t.Errorf("pr = %+v", pr)
	}
	if pr.Head.Ref != "fix/empty-password" || pr.Head.Repo != "example-org/widgets" || pr.Base.Ref != "main" || len(pr.Head.SHA) != 40 {
		t.Errorf("head/base = %+v / %+v", pr.Head, pr.Base)
	}
	if len(pr.RequestedReviewers) != 1 || pr.Additions != 12 || pr.ChangedFiles != 2 {
		t.Errorf("reviewers/additions/changed = %v/%d/%d", pr.RequestedReviewers, pr.Additions, pr.ChangedFiles)
	}
}

func TestGetPullRequestNotFound(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /repos/example-org/widgets/pulls/9": {status: 404, body: "error_not_found.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	_, err := c.Call(context.Background(), call("get_pull_request", map[string]any{"owner": "example-org", "repo": "widgets", "number": 9}))
	wantClass(t, err, github.ClassNotFound, 404)
}

// --- list_pull_request_files -----------------------------------------------------

type filesPage struct {
	Page    int  `json:"page"`
	PerPage int  `json:"per_page"`
	HasMore bool `json:"has_more"`
	Files   []struct {
		Filename         string `json:"filename"`
		Status           string `json:"status"`
		Additions        int    `json:"additions"`
		Deletions        int    `json:"deletions"`
		Changes          int    `json:"changes"`
		Patch            string `json:"patch"`
		PreviousFilename string `json:"previous_filename"`
		PatchTruncated   bool   `json:"patch_truncated"`
	} `json:"files"`
}

func TestListPullRequestFiles(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /repos/example-org/widgets/pulls/43/files": {status: 200, body: "pull_files.json", headers: map[string]string{
		"Link": `<https://api.github.example.test/repos/example-org/widgets/pulls/43/files?page=2>; rel="next"`,
	}}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call("list_pull_request_files", map[string]any{"owner": "example-org", "repo": "widgets", "number": 43}))
	if err != nil {
		t.Fatalf("list_pull_request_files: %v", err)
	}
	var page filesPage
	decode(t, res, &page)
	if len(page.Files) != 2 || !page.HasMore || page.Page != 1 || page.PerPage != 30 {
		t.Errorf("page = %+v", page)
	}
	f := page.Files[0]
	if f.Filename != "internal/auth/login.go" || f.Status != "modified" || f.Additions != 10 || f.Deletions != 3 || f.Changes != 13 || !strings.HasPrefix(f.Patch, "@@") {
		t.Errorf("file = %+v", f)
	}
	if res.Empty || res.Partial || res.Unavailable {
		t.Errorf("markers = %+v", res)
	}
	q := query(t, srv, "/repos/example-org/widgets/pulls/43/files")
	if q.Get("per_page") != "30" || q.Get("page") != "1" {
		t.Errorf("per_page/page = %q/%q", q.Get("per_page"), q.Get("page"))
	}
}

func TestListPullRequestFilesEmpty(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /repos/example-org/widgets/pulls/43/files": {status: 200, body: "[]"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call("list_pull_request_files", map[string]any{"owner": "example-org", "repo": "widgets", "number": 43}))
	if err != nil {
		t.Fatal(err)
	}
	var page filesPage
	decode(t, res, &page)
	if !res.Empty || page.Files == nil || len(page.Files) != 0 {
		t.Errorf("res = %+v files = %v, want Empty with an empty files array", res, page.Files)
	}
}

func TestListPullRequestFilesTruncatesPatchesThenFiles(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /repos/example-org/widgets/pulls/43/files": {status: 200, body: "pull_files.json"}})
	t.Run("patches dropped first", func(t *testing.T) {
		c, _ := newConnector(t, srv, connectors.Bounds{MaxResultBytes: 450})
		res, err := c.Call(context.Background(), call("list_pull_request_files", map[string]any{"owner": "example-org", "repo": "widgets", "number": 43}))
		if err != nil {
			t.Fatal(err)
		}
		var page filesPage
		decode(t, res, &page)
		raw, _ := json.Marshal(res.Content)
		if !res.Partial || len(page.Files) != 2 || len(raw) > 450 {
			t.Fatalf("partial=%v files=%d bytes=%d, want Partial with both files kept under 450 bytes", res.Partial, len(page.Files), len(raw))
		}
		if page.Files[0].Patch != "" || !page.Files[0].PatchTruncated {
			t.Errorf("first file = %+v, want its patch dropped and flagged", page.Files[0])
		}
	})
	t.Run("then files", func(t *testing.T) {
		c, _ := newConnector(t, srv, connectors.Bounds{MaxResultBytes: 250})
		res, err := c.Call(context.Background(), call("list_pull_request_files", map[string]any{"owner": "example-org", "repo": "widgets", "number": 43}))
		if err != nil {
			t.Fatal(err)
		}
		var page filesPage
		decode(t, res, &page)
		raw, _ := json.Marshal(res.Content)
		if !res.Partial || len(page.Files) != 1 || len(raw) > 250 {
			t.Errorf("partial=%v files=%d bytes=%d, want Partial with one file under 250 bytes", res.Partial, len(page.Files), len(raw))
		}
	})
}

func TestListPullRequestFilesRateLimited(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /repos/example-org/widgets/pulls/43/files": {status: 429, body: "error_secondary_rate_limit.json", headers: map[string]string{"Retry-After": "5"}}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	_, err := c.Call(context.Background(), call("list_pull_request_files", map[string]any{"owner": "example-org", "repo": "widgets", "number": 43}))
	var rl *connectors.RateLimited
	if !errors.As(err, &rl) || rl.RetryAfter != 5*time.Second {
		t.Fatalf("err = %v, want RateLimited 5s", err)
	}
}

// --- HTTP client plumbing ----------------------------------------------------------

func TestCustomHTTPClientIsUsed(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /user": {status: 200, body: "user.json"}})
	seen := false
	rt := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		seen = true
		return http.DefaultTransport.RoundTrip(r)
	})
	c, err := github.New(github.Options{Tokens: (&tokens{}).source, BaseURL: srv.URL + "/", HTTPClient: &http.Client{Transport: rt}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Call(context.Background(), call("get_me", nil)); err != nil {
		t.Fatal(err)
	}
	if !seen {
		t.Error("the configured HTTP client's transport was not used")
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Security review kwcbub3k: the vendor's message is relayed to the
// model only when it is a short, plain client-error hint; markup, URLs,
// internal hostnames and anything a 5xx says stay behind the class.
func TestVendorMessageIsAHintNeverABody(t *testing.T) {
	const soup = `Validation Failed: see https://api.vendor.internal/docs token=ghp_9f8e7d6c5b4a39281716151413121110aaBBcc`
	cases := []struct {
		name   string
		status int
		body   string
		want   []string // substrings of the message
		absent []string
	}{
		{"422 plain hint", 422, `{"message":"Validation Failed: title is required"}`, []string{"GitHub rejected the request (Validation Failed: title is required)"}, nil},
		{"422 with a URL is dropped", 422, `{"message":"` + soup + `"}`, []string{"GitHub rejected the request (http 422)"}, []string{"vendor.internal", "ghp_", "Validation"}},
		{"422 with markup is dropped", 422, `{"message":"<html>upstream internal-api.vendor.internal</html>"}`, []string{"GitHub rejected the request"}, []string{"<", "vendor.internal"}},
		{"422 long message is cut", 422, `{"message":"` + strings.Repeat("x", 300) + `"}`, []string{"(" + strings.Repeat("x", 120) + "…)"}, []string{strings.Repeat("x", 121)}},
		{"422 multi-line is one line", 422, `{"message":"first\n\tsecond   third"}`, []string{"(first second third)"}, []string{"\n", "\t"}},
		{"422 token in text is redacted", 422, `{"message":"bad token=ghp_9f8e7d6c5b4a39281716151413121110aaBBcc here"}`, []string{"[REDACTED]"}, []string{"ghp_9f8e"}},
		{"403 hint kept", 403, `{"message":"Resource not accessible by integration"}`, []string{"(Resource not accessible by integration)"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"POST /repos/example-org/widgets/issues": {status: tc.status, body: tc.body}})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			_, err := c.Call(context.Background(), write("create_issue", map[string]any{"owner": "example-org", "repo": "widgets", "title": "t"}))
			if err == nil {
				t.Fatal("no error")
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q lacks %q", err.Error(), want)
				}
			}
			for _, absent := range tc.absent {
				if strings.Contains(err.Error(), absent) {
					t.Errorf("error %q carries %q", err.Error(), absent)
				}
			}
		})
	}
	// A 5xx on a write: the class only, whatever the body says.
	srv := newAPIServer(t, map[string]route{"POST /repos/example-org/widgets/issues": {status: 503, body: `{"message":"` + soup + `"}`}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	_, err := c.Call(context.Background(), write("create_issue", map[string]any{"owner": "example-org", "repo": "widgets", "title": "t"}))
	if err == nil || strings.Contains(err.Error(), "vendor.internal") || strings.Contains(err.Error(), "Validation") {
		t.Errorf("5xx write error = %v, want the class only", err)
	}
}
