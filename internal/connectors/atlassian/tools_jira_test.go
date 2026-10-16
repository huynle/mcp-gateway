package atlassian_test

import (
	"context"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/atlassian"
)

// The Jira reads added after the v1 set (Rovo MCP / mcp-atlassian gap
// closing): projects and their metadata, comments, changelog, links,
// worklogs, watchers, users, and the agile boards and sprints.

const agileBase = "/ex/jira/" + cloudID + "/rest/agile/1.0"

func TestJiraMoreReadToolsMetadata(t *testing.T) {
	work := []string{"read:jira-work"}
	user := []string{"read:jira-user"}
	issue := map[string]any{"key": "mock-42"}
	issueID := map[string]string{"project": "MOCK", "issue": "MOCK-42"}
	project := map[string]any{"project_key": "mock"}
	projectID := map[string]string{"project": "MOCK"}
	cases := []metadataCase{
		{app: atlassian.JiraApp, tool: "get_current_user", props: []string{}, args: map[string]any{}, identity: map[string]string{}, scopes: user},
		{
			app: atlassian.JiraApp, tool: "list_projects", props: []string{"query", "max_results", "start_at"},
			args: map[string]any{"query": "secret"}, identity: map[string]string{}, scopes: work, page: true,
		},
		{
			app: atlassian.JiraApp, tool: "list_issue_types", required: []string{"project_key"}, props: []string{"project_key", "max_results", "start_at"},
			args: project, identity: projectID, scopes: work, page: true,
		},
		{
			app: atlassian.JiraApp, tool: "get_create_fields", required: []string{"project_key", "issue_type_id"},
			props: []string{"project_key", "issue_type_id", "max_results", "start_at"},
			args:  map[string]any{"project_key": "MOCK", "issue_type_id": "10001"}, identity: projectID, scopes: work, page: true,
		},
		{
			app: atlassian.JiraApp, tool: "get_issue_comments", required: []string{"key"}, props: []string{"key", "max_results", "start_at"},
			args: issue, identity: issueID, scopes: work, page: true,
		},
		{
			app: atlassian.JiraApp, tool: "get_issue_changelog", required: []string{"key"}, props: []string{"key", "max_results", "start_at"},
			args: issue, identity: issueID, scopes: work, page: true,
		},
		{app: atlassian.JiraApp, tool: "list_issue_links", required: []string{"key"}, props: []string{"key"}, args: issue, identity: issueID, scopes: work},
		{app: atlassian.JiraApp, tool: "list_link_types", props: []string{}, args: map[string]any{}, identity: map[string]string{}, scopes: work},
		{
			app: atlassian.JiraApp, tool: "list_worklogs", required: []string{"key"}, props: []string{"key", "max_results", "start_at"},
			args: issue, identity: issueID, scopes: work, page: true,
		},
		{app: atlassian.JiraApp, tool: "get_watchers", required: []string{"key"}, props: []string{"key"}, args: issue, identity: issueID, scopes: work},
		{
			app: atlassian.JiraApp, tool: "search_users", required: []string{"query"}, props: []string{"query", "max_results", "start_at"},
			args: map[string]any{"query": "secret@example.test"}, identity: map[string]string{}, scopes: user, page: true,
		},
		{
			app: atlassian.JiraApp, tool: "list_assignable_users", props: []string{"project_key", "key", "query", "max_results", "start_at"},
			args: map[string]any{"key": "MOCK-42", "query": "secret"}, identity: issueID, scopes: user, page: true,
		},
		{app: atlassian.JiraApp, tool: "list_project_versions", required: []string{"project_key"}, props: []string{"project_key"}, args: project, identity: projectID, scopes: work},
		{app: atlassian.JiraApp, tool: "list_project_components", required: []string{"project_key"}, props: []string{"project_key"}, args: project, identity: projectID, scopes: work},
		{
			app: atlassian.JiraApp, tool: "list_boards", props: []string{"project_key", "name", "type", "max_results", "start_at"},
			args: map[string]any{"project_key": "mock", "name": "secret"}, identity: projectID,
			scopes: []string{"read:board-scope:jira-software", "read:project:jira"}, page: true,
		},
		{
			app: atlassian.JiraApp, tool: "list_sprints", required: []string{"board_id"}, props: []string{"board_id", "state", "max_results", "start_at"},
			args: map[string]any{"board_id": 7}, identity: map[string]string{"board": "7"},
			scopes: []string{"read:sprint:jira-software"}, page: true,
		},
		{
			app: atlassian.JiraApp, tool: "get_sprint_issues", required: []string{"sprint_id"}, props: []string{"sprint_id", "jql", "max_results", "start_at"},
			args: map[string]any{"sprint_id": "12", "jql": `text ~ "secret"`}, identity: map[string]string{"sprint": "12"},
			scopes: []string{"read:sprint:jira-software", "read:issue-details:jira", "read:jql:jira"}, page: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) { checkMetadata(t, tc) })
	}
}

func TestGetCurrentUser(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET " + jiraBase + "/myself": {status: 200, body: `{"accountId":"5b10ac8d82e05b22cc7d4ef5","displayName":"Alice Example","emailAddress":"alice@example.test","timeZone":"Europe/Berlin","active":true,"accountType":"atlassian"}`}})
	c, _ := newJira(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call(atlassian.JiraApp, "get_current_user", nil))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	decode(t, res, &got)
	if got["account_id"] != "5b10ac8d82e05b22cc7d4ef5" || got["display_name"] != "Alice Example" || got["email"] != "alice@example.test" || got["time_zone"] != "Europe/Berlin" || got["active"] != true {
		t.Errorf("user = %v", got)
	}
}

func TestListProjects(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET " + jiraBase + "/project/search": {status: 200, body: `{"startAt":0,"maxResults":2,"total":3,"isLast":false,
		"values":[{"id":"10000","key":"MOCK","name":"Mock project","projectTypeKey":"software","style":"classic"},{"id":"10001","key":"OPS","name":"Operations","projectTypeKey":"service_desk","style":"next-gen"}]}`}})
	c, _ := newJira(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call(atlassian.JiraApp, "list_projects", map[string]any{"query": "mo", "max_results": 2, "start_at": 0}))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Projects []struct{ ID, Key, Name, Type, Style string } `json:"projects"`
		StartAt  int                                           `json:"start_at"`
		Max      int                                           `json:"max_results"`
		Total    int                                           `json:"total"`
		HasMore  bool                                          `json:"has_more"`
	}
	decode(t, res, &got)
	if len(got.Projects) != 2 || got.Projects[0].Key != "MOCK" || got.Projects[1].Type != "service_desk" || got.Projects[1].Style != "next-gen" {
		t.Errorf("projects = %+v", got.Projects)
	}
	if !got.HasMore || got.Total != 3 || got.Max != 2 {
		t.Errorf("page = %+v", got)
	}
	q := query(t, srv, jiraBase+"/project/search")
	if q.Get("query") != "mo" || q.Get("maxResults") != "2" || q.Get("startAt") != "0" || q.Get("orderBy") != "key" {
		t.Errorf("query = %v", q)
	}
}

func TestListProjectsEmptyClampedAndErrors(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET " + jiraBase + "/project/search": {status: 200, body: `{"startAt":0,"maxResults":5,"total":0,"isLast":true,"values":[]}`}})
	c, _ := newJira(t, srv, connectors.Bounds{MaxPageSize: 5})
	res, err := c.Call(context.Background(), call(atlassian.JiraApp, "list_projects", map[string]any{"max_results": 50}))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Empty || !res.Partial {
		t.Errorf("res = %+v, want empty and partial (clamped)", res)
	}
	if q := query(t, srv, jiraBase+"/project/search"); q.Get("maxResults") != "5" {
		t.Errorf("maxResults = %q, want the clamp 5", q.Get("maxResults"))
	}
	if _, err := c.Call(context.Background(), call(atlassian.JiraApp, "list_projects", map[string]any{"start_at": -1})); err == nil {
		t.Error("negative start_at accepted")
	}
	srv = newAPIServer(t, map[string]route{"GET " + jiraBase + "/project/search": {status: 403, body: "error_forbidden.json"}})
	c, _ = newJira(t, srv, connectors.Bounds{})
	_, err = c.Call(context.Background(), call(atlassian.JiraApp, "list_projects", nil))
	wantClass(t, err, atlassian.ClassForbidden, 403)
}

func TestListIssueTypes(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET " + jiraBase + "/issue/createmeta/MOCK/issuetypes": {status: 200, body: `{"startAt":0,"maxResults":10,"total":2,
		"issueTypes":[{"id":"10001","name":"Task","description":"A task","subtask":false},{"id":"10003","name":"Sub-task","subtask":true}]}`}})
	c, _ := newJira(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call(atlassian.JiraApp, "list_issue_types", map[string]any{"project_key": "mock"}))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Project    string `json:"project"`
		IssueTypes []struct {
			ID, Name, Description string
			Subtask               bool
		} `json:"issue_types"`
		HasMore bool `json:"has_more"`
	}
	decode(t, res, &got)
	if got.Project != "MOCK" || len(got.IssueTypes) != 2 || got.IssueTypes[0].ID != "10001" || got.IssueTypes[0].Name != "Task" || !got.IssueTypes[1].Subtask || got.HasMore {
		t.Errorf("issue types = %+v", got)
	}
	if _, err := c.Call(context.Background(), call(atlassian.JiraApp, "list_issue_types", map[string]any{"project_key": "not a key"})); err == nil {
		t.Error("bad project_key accepted")
	}
}

func TestGetCreateFields(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET " + jiraBase + "/issue/createmeta/MOCK/issuetypes/10001": {status: 200, body: `{"startAt":0,"maxResults":10,"total":3,"fields":[
		{"fieldId":"summary","key":"summary","name":"Summary","required":true,"schema":{"type":"string","system":"summary"},"operations":["set"],"hasDefaultValue":false},
		{"fieldId":"priority","key":"priority","name":"Priority","required":false,"schema":{"type":"priority"},"allowedValues":[{"id":"1","name":"Highest"},{"id":"3","name":"Medium"}],"hasDefaultValue":true},
		{"fieldId":"customfield_10010","key":"customfield_10010","name":"Team","required":false,"schema":{"type":"array","items":"option","custom":"com.atlassian.jira.plugin.system.customfieldtypes:multiselect"},"allowedValues":[{"id":"20","value":"Platform"}]}]}`}})
	c, _ := newJira(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call(atlassian.JiraApp, "get_create_fields", map[string]any{"project_key": "MOCK", "issue_type_id": "10001"}))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Project     string `json:"project"`
		IssueTypeID string `json:"issue_type_id"`
		Fields      []struct {
			ID            string   `json:"id"`
			Name          string   `json:"name"`
			Required      bool     `json:"required"`
			Type          string   `json:"type"`
			Items         string   `json:"items"`
			Custom        string   `json:"custom"`
			AllowedValues []string `json:"allowed_values"`
			HasDefault    bool     `json:"has_default"`
		} `json:"fields"`
	}
	decode(t, res, &got)
	if got.Project != "MOCK" || got.IssueTypeID != "10001" || len(got.Fields) != 3 {
		t.Fatalf("fields = %+v", got)
	}
	if f := got.Fields[0]; f.ID != "summary" || !f.Required || f.Type != "string" {
		t.Errorf("summary = %+v", f)
	}
	if f := got.Fields[1]; strings.Join(f.AllowedValues, ",") != "Highest,Medium" || !f.HasDefault {
		t.Errorf("priority = %+v", f)
	}
	if f := got.Fields[2]; f.Type != "array" || f.Items != "option" || !strings.HasSuffix(f.Custom, "multiselect") || strings.Join(f.AllowedValues, ",") != "Platform" {
		t.Errorf("team = %+v", f)
	}
	for _, bad := range []map[string]any{{"project_key": "MOCK"}, {"project_key": "MOCK", "issue_type_id": "../x"}} {
		if _, err := c.Call(context.Background(), call(atlassian.JiraApp, "get_create_fields", bad)); err == nil {
			t.Errorf("args %v accepted", bad)
		}
	}
}

func TestGetIssueComments(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET " + jiraBase + "/issue/MOCK-42/comment": {status: 200, body: `{"startAt":0,"maxResults":2,"total":5,"comments":[
		{"id":"20001","author":{"accountId":"a1","displayName":"Alice Example"},"body":{"type":"doc","version":1,"content":[{"type":"paragraph","content":[{"type":"text","text":"First"}]}]},"created":"2026-10-01T10:00:00.000+0000","updated":"2026-10-01T10:05:00.000+0000"},
		{"id":"20002","author":{"accountId":"b2","displayName":"Bob Example"},"body":{"type":"doc","version":1,"content":[{"type":"paragraph","content":[{"type":"text","text":"Second"}]}]},"created":"2026-10-02T10:00:00.000+0000"}]}`}})
	c, _ := newJira(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call(atlassian.JiraApp, "get_issue_comments", map[string]any{"key": "mock-42", "max_results": 2}))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Issue    string `json:"issue"`
		Comments []struct {
			ID, Author, Body, Created, Updated, URL string
		} `json:"comments"`
		Total   int  `json:"total"`
		HasMore bool `json:"has_more"`
	}
	decode(t, res, &got)
	if got.Issue != "MOCK-42" || len(got.Comments) != 2 || !got.HasMore || got.Total != 5 {
		t.Fatalf("comments = %+v", got)
	}
	if cm := got.Comments[0]; cm.ID != "20001" || cm.Author != "Alice Example" || cm.Body != "First" || cm.Created != "2026-10-01T10:00:00Z" || cm.URL != siteURL+"/browse/MOCK-42?focusedCommentId=20001" {
		t.Errorf("comment = %+v", cm)
	}
	q := query(t, srv, jiraBase+"/issue/MOCK-42/comment")
	if q.Get("orderBy") != "-created" || q.Get("maxResults") != "2" || q.Get("startAt") != "0" {
		t.Errorf("query = %v", q)
	}
}

func TestGetIssueCommentsTruncatesALongBody(t *testing.T) {
	long := strings.Repeat("x", 4000)
	srv := newAPIServer(t, map[string]route{"GET " + jiraBase + "/issue/MOCK-42/comment": {status: 200, body: `{"startAt":0,"maxResults":10,"total":1,"comments":[
		{"id":"20001","body":{"type":"doc","version":1,"content":[{"type":"paragraph","content":[{"type":"text","text":"` + long + `"}]}]}}]}`}})
	c, _ := newJira(t, srv, connectors.Bounds{MaxResultBytes: 1000})
	res, err := c.Call(context.Background(), call(atlassian.JiraApp, "get_issue_comments", map[string]any{"key": "MOCK-42"}))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Partial || encodedSize(t, res.Content) > 1000 {
		t.Errorf("partial = %v, size = %d; want partial within 1000", res.Partial, encodedSize(t, res.Content))
	}
}

func TestGetIssueChangelog(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET " + jiraBase + "/issue/MOCK-42/changelog": {status: 200, body: `{"startAt":0,"maxResults":10,"total":1,"histories":[
		{"id":"30001","author":{"displayName":"Alice Example"},"created":"2026-10-01T10:00:00.000+0000","items":[
			{"field":"status","fieldtype":"jira","fromString":"To Do","toString":"In Progress"},{"field":"assignee","fromString":null,"toString":"Bob Example"}]}]}`}})
	c, _ := newJira(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call(atlassian.JiraApp, "get_issue_changelog", map[string]any{"key": "MOCK-42"}))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Issue     string `json:"issue"`
		Histories []struct {
			ID, Author, Created string
			Items               []struct{ Field, From, To string }
		} `json:"histories"`
		HasMore bool `json:"has_more"`
	}
	decode(t, res, &got)
	if got.Issue != "MOCK-42" || len(got.Histories) != 1 || got.HasMore {
		t.Fatalf("changelog = %+v", got)
	}
	h := got.Histories[0]
	if h.ID != "30001" || h.Author != "Alice Example" || h.Created != "2026-10-01T10:00:00Z" || len(h.Items) != 2 {
		t.Fatalf("history = %+v", h)
	}
	if it := h.Items[0]; it.Field != "status" || it.From != "To Do" || it.To != "In Progress" {
		t.Errorf("item = %+v", it)
	}
	if it := h.Items[1]; it.From != "" || it.To != "Bob Example" {
		t.Errorf("item = %+v", it)
	}
}

func TestListIssueLinks(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET " + jiraBase + "/issue/MOCK-42": {status: 200, body: `{"id":"10042","key":"MOCK-42","fields":{"issuelinks":[
		{"id":"40001","type":{"name":"Blocks","inward":"is blocked by","outward":"blocks"},"outwardIssue":{"key":"MOCK-7","fields":{"summary":"Blocked one","status":{"name":"To Do"}}}},
		{"id":"40002","type":{"name":"Relates","inward":"relates to","outward":"relates to"},"inwardIssue":{"key":"OPS-1","fields":{"summary":"Other","status":{"name":"Done"}}}}]}}`}})
	c, _ := newJira(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call(atlassian.JiraApp, "list_issue_links", map[string]any{"key": "MOCK-42"}))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Issue string `json:"issue"`
		Links []struct {
			ID, Type, Direction, Relation, Issue, Summary, Status, URL string
		} `json:"links"`
	}
	decode(t, res, &got)
	if got.Issue != "MOCK-42" || len(got.Links) != 2 {
		t.Fatalf("links = %+v", got)
	}
	if l := got.Links[0]; l.ID != "40001" || l.Type != "Blocks" || l.Direction != "outward" || l.Relation != "blocks" || l.Issue != "MOCK-7" || l.Summary != "Blocked one" || l.Status != "To Do" || l.URL != siteURL+"/browse/MOCK-7" {
		t.Errorf("link = %+v", l)
	}
	if l := got.Links[1]; l.Direction != "inward" || l.Relation != "relates to" || l.Issue != "OPS-1" {
		t.Errorf("link = %+v", l)
	}
	if q := query(t, srv, jiraBase+"/issue/MOCK-42"); q.Get("fields") != "issuelinks" {
		t.Errorf("fields = %q", q.Get("fields"))
	}
}

func TestListLinkTypes(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET " + jiraBase + "/issueLinkType": {status: 200, body: `{"issueLinkTypes":[{"id":"10000","name":"Blocks","inward":"is blocked by","outward":"blocks"}]}`}})
	c, _ := newJira(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call(atlassian.JiraApp, "list_link_types", nil))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		LinkTypes []struct{ ID, Name, Inward, Outward string } `json:"link_types"`
	}
	decode(t, res, &got)
	if len(got.LinkTypes) != 1 || got.LinkTypes[0].Name != "Blocks" || got.LinkTypes[0].Inward != "is blocked by" || got.LinkTypes[0].Outward != "blocks" {
		t.Errorf("link types = %+v", got)
	}
}

func TestListWorklogs(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET " + jiraBase + "/issue/MOCK-42/worklog": {status: 200, body: `{"startAt":0,"maxResults":10,"total":1,"worklogs":[
		{"id":"50001","author":{"displayName":"Alice Example"},"timeSpent":"1h 30m","timeSpentSeconds":5400,"started":"2026-10-01T09:00:00.000+0000",
		 "comment":{"type":"doc","version":1,"content":[{"type":"paragraph","content":[{"type":"text","text":"Pairing"}]}]}}]}`}})
	c, _ := newJira(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call(atlassian.JiraApp, "list_worklogs", map[string]any{"key": "MOCK-42"}))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Issue    string `json:"issue"`
		Worklogs []struct {
			ID               string `json:"id"`
			Author           string `json:"author"`
			TimeSpent        string `json:"time_spent"`
			TimeSpentSeconds int    `json:"time_spent_seconds"`
			Started          string `json:"started"`
			Comment          string `json:"comment"`
		} `json:"worklogs"`
	}
	decode(t, res, &got)
	if len(got.Worklogs) != 1 {
		t.Fatalf("worklogs = %+v", got)
	}
	if w := got.Worklogs[0]; w.ID != "50001" || w.Author != "Alice Example" || w.TimeSpent != "1h 30m" || w.TimeSpentSeconds != 5400 || w.Started != "2026-10-01T09:00:00Z" || w.Comment != "Pairing" {
		t.Errorf("worklog = %+v", w)
	}
}

func TestGetWatchers(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET " + jiraBase + "/issue/MOCK-42/watchers": {status: 200, body: `{"isWatching":true,"watchCount":2,"watchers":[{"accountId":"a1","displayName":"Alice Example"},{"accountId":"b2","displayName":"Bob Example"}]}`}})
	c, _ := newJira(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call(atlassian.JiraApp, "get_watchers", map[string]any{"key": "MOCK-42"}))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Issue      string `json:"issue"`
		IsWatching bool   `json:"is_watching"`
		WatchCount int    `json:"watch_count"`
		Watchers   []struct {
			AccountID   string `json:"account_id"`
			DisplayName string `json:"display_name"`
		} `json:"watchers"`
	}
	decode(t, res, &got)
	if !got.IsWatching || got.WatchCount != 2 || len(got.Watchers) != 2 || got.Watchers[1].AccountID != "b2" || got.Watchers[1].DisplayName != "Bob Example" {
		t.Errorf("watchers = %+v", got)
	}
}

func TestSearchUsers(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET " + jiraBase + "/user/search": {status: 200, body: `[
		{"accountId":"a1","displayName":"Alice Example","emailAddress":"alice@example.test","active":true,"accountType":"atlassian"},
		{"accountId":"b2","displayName":"Bob Example","active":false,"accountType":"app"}]`}})
	c, _ := newJira(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call(atlassian.JiraApp, "search_users", map[string]any{"query": "example", "max_results": 2}))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Users []struct {
			AccountID   string `json:"account_id"`
			DisplayName string `json:"display_name"`
			Email       string `json:"email"`
			Active      bool   `json:"active"`
			AccountType string `json:"account_type"`
		} `json:"users"`
		HasMore bool `json:"has_more"`
	}
	decode(t, res, &got)
	if len(got.Users) != 2 || got.Users[0].Email != "alice@example.test" || !got.Users[0].Active || got.Users[1].AccountType != "app" || got.Users[1].Active {
		t.Errorf("users = %+v", got)
	}
	if !got.HasMore {
		t.Error("a full page should report has_more")
	}
	q := query(t, srv, jiraBase+"/user/search")
	if q.Get("query") != "example" || q.Get("maxResults") != "2" {
		t.Errorf("query = %v", q)
	}
	if _, err := c.Call(context.Background(), call(atlassian.JiraApp, "search_users", map[string]any{"query": " "})); err == nil {
		t.Error("blank query accepted")
	}
}

func TestListAssignableUsers(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET " + jiraBase + "/user/assignable/search": {status: 200, body: `[{"accountId":"a1","displayName":"Alice Example","active":true}]`}})
	c, _ := newJira(t, srv, connectors.Bounds{})
	if _, err := c.Call(context.Background(), call(atlassian.JiraApp, "list_assignable_users", map[string]any{"key": "mock-42", "query": "ali"})); err != nil {
		t.Fatal(err)
	}
	q := query(t, srv, jiraBase+"/user/assignable/search")
	if q.Get("issueKey") != "MOCK-42" || q.Get("query") != "ali" || q.Has("project") {
		t.Errorf("query = %v", q)
	}
	res, err := c.Call(context.Background(), call(atlassian.JiraApp, "list_assignable_users", map[string]any{"project_key": "mock"}))
	if err != nil {
		t.Fatal(err)
	}
	if q := query(t, srv, jiraBase+"/user/assignable/search"); q.Get("project") != "MOCK" || q.Has("issueKey") {
		t.Errorf("query = %v", q)
	}
	if res.Empty {
		t.Error("one user is not empty")
	}
	if _, err := c.Call(context.Background(), call(atlassian.JiraApp, "list_assignable_users", nil)); err == nil {
		t.Error("neither key nor project_key accepted")
	}
}

func TestListProjectVersionsAndComponents(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		"GET " + jiraBase + "/project/MOCK/versions":   {status: 200, body: `[{"id":"10100","name":"1.0","description":"First","released":true,"archived":false,"releaseDate":"2026-09-30","overdue":false},{"id":"10101","name":"1.1","released":false}]`},
		"GET " + jiraBase + "/project/MOCK/components": {status: 200, body: `[{"id":"10200","name":"API","description":"The API","lead":{"displayName":"Alice Example"}}]`},
	})
	c, _ := newJira(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call(atlassian.JiraApp, "list_project_versions", map[string]any{"project_key": "mock"}))
	if err != nil {
		t.Fatal(err)
	}
	var versions struct {
		Project  string `json:"project"`
		Versions []struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			Released    bool   `json:"released"`
			ReleaseDate string `json:"release_date"`
		} `json:"versions"`
	}
	decode(t, res, &versions)
	if versions.Project != "MOCK" || len(versions.Versions) != 2 || !versions.Versions[0].Released || versions.Versions[0].ReleaseDate != "2026-09-30" || versions.Versions[1].Released {
		t.Errorf("versions = %+v", versions)
	}
	res, err = c.Call(context.Background(), call(atlassian.JiraApp, "list_project_components", map[string]any{"project_key": "MOCK"}))
	if err != nil {
		t.Fatal(err)
	}
	var comps struct {
		Components []struct{ ID, Name, Description, Lead string } `json:"components"`
	}
	decode(t, res, &comps)
	if len(comps.Components) != 1 || comps.Components[0].Name != "API" || comps.Components[0].Lead != "Alice Example" {
		t.Errorf("components = %+v", comps)
	}
}

func TestListBoards(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET " + agileBase + "/board": {status: 200, body: `{"startAt":0,"maxResults":10,"total":1,"isLast":true,"values":[
		{"id":7,"name":"MOCK board","type":"scrum","location":{"projectKey":"MOCK","projectName":"Mock project"}}]}`}})
	c, _ := newJira(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call(atlassian.JiraApp, "list_boards", map[string]any{"project_key": "mock", "type": "scrum", "name": "MOCK"}))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Boards []struct {
			ID      int    `json:"id"`
			Name    string `json:"name"`
			Type    string `json:"type"`
			Project string `json:"project"`
		} `json:"boards"`
		HasMore bool `json:"has_more"`
	}
	decode(t, res, &got)
	if len(got.Boards) != 1 || got.Boards[0].ID != 7 || got.Boards[0].Type != "scrum" || got.Boards[0].Project != "MOCK" || got.HasMore {
		t.Errorf("boards = %+v", got)
	}
	q := query(t, srv, agileBase+"/board")
	if q.Get("projectKeyOrId") != "MOCK" || q.Get("type") != "scrum" || q.Get("name") != "MOCK" {
		t.Errorf("query = %v", q)
	}
	if _, err := c.Call(context.Background(), call(atlassian.JiraApp, "list_boards", map[string]any{"type": "bogus"})); err == nil {
		t.Error("bad board type accepted")
	}
}

func TestListSprints(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET " + agileBase + "/board/7/sprint": {status: 200, body: `{"startAt":0,"maxResults":10,"isLast":false,"values":[
		{"id":12,"name":"Sprint 12","state":"active","startDate":"2026-10-01T09:00:00.000Z","endDate":"2026-10-15T09:00:00.000Z","goal":"Ship it"}]}`}})
	c, _ := newJira(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call(atlassian.JiraApp, "list_sprints", map[string]any{"board_id": 7, "state": "active"}))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		BoardID int `json:"board_id"`
		Sprints []struct {
			ID        int    `json:"id"`
			Name      string `json:"name"`
			State     string `json:"state"`
			StartDate string `json:"start_date"`
			EndDate   string `json:"end_date"`
			Goal      string `json:"goal"`
		} `json:"sprints"`
		HasMore bool `json:"has_more"`
	}
	decode(t, res, &got)
	if got.BoardID != 7 || len(got.Sprints) != 1 || got.Sprints[0].ID != 12 || got.Sprints[0].State != "active" || got.Sprints[0].StartDate != "2026-10-01T09:00:00Z" || got.Sprints[0].Goal != "Ship it" || !got.HasMore {
		t.Errorf("sprints = %+v", got)
	}
	if q := query(t, srv, agileBase+"/board/7/sprint"); q.Get("state") != "active" {
		t.Errorf("query = %v", q)
	}
	for _, bad := range []map[string]any{{"board_id": 0}, {"board_id": "x"}, {"board_id": 7, "state": "done"}} {
		if _, err := c.Call(context.Background(), call(atlassian.JiraApp, "list_sprints", bad)); err == nil {
			t.Errorf("args %v accepted", bad)
		}
	}
}

func TestGetSprintIssues(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET " + agileBase + "/sprint/12/issue": {status: 200, body: `{"startAt":0,"maxResults":10,"total":11,"issues":[
		{"id":"10001","key":"MOCK-1","fields":{"summary":"In the sprint","status":{"name":"In Progress"},"assignee":{"displayName":"Alice Example"}}}]}`}})
	c, _ := newJira(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call(atlassian.JiraApp, "get_sprint_issues", map[string]any{"sprint_id": "12", "jql": "assignee = currentUser()"}))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		SprintID int `json:"sprint_id"`
		Issues   []struct {
			Key, Summary, Status, Assignee, URL string
		} `json:"issues"`
		Total   int  `json:"total"`
		HasMore bool `json:"has_more"`
	}
	decode(t, res, &got)
	if got.SprintID != 12 || len(got.Issues) != 1 || got.Issues[0].Key != "MOCK-1" || got.Issues[0].Status != "In Progress" || got.Issues[0].URL != siteURL+"/browse/MOCK-1" || !got.HasMore || got.Total != 11 {
		t.Errorf("sprint issues = %+v", got)
	}
	q := query(t, srv, agileBase+"/sprint/12/issue")
	if q.Get("jql") != "assignee = currentUser()" || !strings.Contains(q.Get("fields"), "summary") {
		t.Errorf("query = %v", q)
	}
}

func TestJiraMoreReadsUnavailableAndNotFound(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		"GET " + jiraBase + "/issue/MOCK-42/changelog": {status: 503},
		"GET " + jiraBase + "/issue/MOCK-42/worklog":   {status: 404, body: "error_not_found.json"},
	})
	c, _ := newJira(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call(atlassian.JiraApp, "get_issue_changelog", map[string]any{"key": "MOCK-42"}))
	if err != nil || !res.Unavailable {
		t.Errorf("changelog 503: res = %+v err = %v, want Unavailable", res, err)
	}
	_, err = c.Call(context.Background(), call(atlassian.JiraApp, "list_worklogs", map[string]any{"key": "MOCK-42"}))
	wantClass(t, err, atlassian.ClassNotFound, 404)
}
