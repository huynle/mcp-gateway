package atlassian_test

import (
	"context"
	"errors"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/atlassian"
	"github.com/huynle/mcp-gateway/internal/connectors/connectortest"
)

func TestJiraPassesContract(t *testing.T) {
	c, err := atlassian.New(atlassian.JiraApp, atlassian.Options{Tokens: (&tokens{}).source, Sites: (&sites{}).source})
	if err != nil {
		t.Fatal(err)
	}
	connectortest.ContractTest(t, c)
}

func TestConfluencePassesContract(t *testing.T) {
	c, err := atlassian.New(atlassian.ConfluenceApp, atlassian.Options{Tokens: (&tokens{}).source, Sites: (&sites{}).source})
	if err != nil {
		t.Fatal(err)
	}
	connectortest.ContractTest(t, c)
}

func TestDefaultBounds(t *testing.T) {
	for _, app := range []string{atlassian.JiraApp, atlassian.ConfluenceApp} {
		c, err := atlassian.New(app, atlassian.Options{Tokens: (&tokens{}).source, Sites: (&sites{}).source})
		if err != nil {
			t.Fatal(err)
		}
		for _, tool := range c.Tools() {
			if tool.Bounds.MaxResultBytes != connectors.DefaultMaxResultBytes {
				t.Errorf("%s.%s: MaxResultBytes = %d, want the package default %d", app, tool.Name, tool.Bounds.MaxResultBytes, connectors.DefaultMaxResultBytes)
			}
			if tool.Bounds.MaxPageSize != 0 && tool.Bounds.MaxPageSize != connectors.DefaultMaxPageSize {
				t.Errorf("%s.%s: MaxPageSize = %d, want 0 or the default %d", app, tool.Name, tool.Bounds.MaxPageSize, connectors.DefaultMaxPageSize)
			}
		}
	}
}

func TestNewValidatesOptions(t *testing.T) {
	ok := atlassian.Options{Tokens: (&tokens{}).source, Sites: (&sites{}).source}
	if _, err := atlassian.New(atlassian.JiraApp, atlassian.Options{Sites: ok.Sites}); err == nil {
		t.Error("New without Tokens succeeded")
	}
	if _, err := atlassian.New(atlassian.JiraApp, atlassian.Options{Tokens: ok.Tokens}); err == nil {
		t.Error("New without Sites succeeded")
	}
	if _, err := atlassian.New("bitbucket", ok); err == nil {
		t.Error("New with an unknown app succeeded")
	}
	bad := ok
	bad.BaseURL = "not a url"
	if _, err := atlassian.New(atlassian.JiraApp, bad); err == nil {
		t.Error("New with a bad BaseURL succeeded")
	}
}

func TestAppsAndToolNames(t *testing.T) {
	jira, _ := newJira(t, newAPIServer(t, nil), connectors.Bounds{})
	conf, _ := newConfluence(t, newAPIServer(t, nil), connectors.Bounds{})
	if jira.App() != "jira" || conf.App() != "confluence" {
		t.Errorf("App() = %q / %q", jira.App(), conf.App())
	}
	names := func(c *atlassian.Connector, kind connectors.Kind) []string {
		var out []string
		for _, tool := range c.Tools() {
			if tool.Kind == kind {
				out = append(out, tool.Name)
			}
			if tool.App != c.App() {
				t.Errorf("%s declared under app %q", tool.Name, tool.App)
			}
		}
		return out
	}
	wantEqual(t, "jira reads", names(jira, connectors.KindRead), []string{"search_issues", "get_issue", "list_transitions",
		"get_current_user", "list_projects", "list_issue_types", "get_create_fields", "get_issue_comments", "get_issue_changelog",
		"list_issue_links", "list_link_types", "list_worklogs", "get_watchers", "search_users", "list_assignable_users",
		"list_project_versions", "list_project_components", "list_boards", "list_sprints", "get_sprint_issues"})
	wantEqual(t, "confluence reads", names(conf, connectors.KindRead), []string{"search", "get_page"})
}

func wantEqual(t *testing.T, what string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s = %v, want %v", what, got, want)
		return
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("%s = %v, want %v", what, got, want)
			return
		}
	}
}

func TestCallWithoutAccount(t *testing.T) {
	c, tk := newJira(t, newAPIServer(t, nil), connectors.Bounds{})
	in := call(atlassian.JiraApp, "search_issues", map[string]any{"jql": "project = MOCK"})
	in.Account = ""
	_, err := c.Call(context.Background(), in)
	wantClass(t, err, atlassian.ClassNoAccount, 0)
	if len(tk.calls) != 0 {
		t.Errorf("token source consulted without an account: %v", tk.calls)
	}
}

func TestCallNeedsReconnectFromTokenSource(t *testing.T) {
	c, tk := newJira(t, newAPIServer(t, nil), connectors.Bounds{})
	tk.fail = connections.ErrNeedsReconnect
	_, err := c.Call(context.Background(), call(atlassian.JiraApp, "search_issues", map[string]any{"jql": "project = MOCK"}))
	wantClass(t, err, atlassian.ClassReconnectRequired, 0)
	if !errors.Is(err, connections.ErrNeedsReconnect) {
		t.Errorf("err %v does not wrap ErrNeedsReconnect", err)
	}
}

func TestCallSiteLookupFailure(t *testing.T) {
	srv := newAPIServer(t, nil)
	st := &sites{fail: errors.New("boom")}
	c, err := atlassian.New(atlassian.JiraApp, atlassian.Options{Tokens: (&tokens{}).source, Sites: st.source, BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Call(context.Background(), call(atlassian.JiraApp, "search_issues", map[string]any{"jql": "project = MOCK"}))
	wantClass(t, err, atlassian.ClassVendorError, 0)
	if len(srv.Requests()) != 0 {
		t.Error("a request was sent without a site")
	}
	if len(st.calls) != 1 || st.calls[0] != alice+"/"+acct {
		t.Errorf("site source calls = %v", st.calls)
	}
}

func TestUnknownTool(t *testing.T) {
	c, _ := newJira(t, newAPIServer(t, nil), connectors.Bounds{})
	if _, err := c.Call(context.Background(), call(atlassian.JiraApp, "nope", nil)); !errors.Is(err, connectors.ErrUnknownTool) {
		t.Errorf("err = %v, want ErrUnknownTool", err)
	}
	// A Confluence tool name is unknown to the Jira connector and vice versa.
	if _, err := c.Call(context.Background(), call(atlassian.ConfluenceApp, "search", nil)); !errors.Is(err, connectors.ErrUnknownTool) {
		t.Errorf("err = %v, want ErrUnknownTool for a confluence tool on the jira connector", err)
	}
}
