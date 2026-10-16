package atlassian_test

import (
	"context"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/atlassian"
)

// The last gaps with the Rovo MCP server: remote links, a user by id,
// project statuses, saved filters and the pages of a space.

func TestGapToolsMetadata(t *testing.T) {
	work := []string{"read:jira-work"}
	issue := map[string]any{"key": "mock-42"}
	issueID := map[string]string{"project": "MOCK", "issue": "MOCK-42"}
	for _, tc := range []metadataCase{
		{app: atlassian.JiraApp, tool: "list_remote_links", required: []string{"key"}, props: []string{"key"}, args: issue, identity: issueID, scopes: work},
		{
			app: atlassian.JiraApp, tool: "get_user", required: []string{"account_id"}, props: []string{"account_id"},
			args: map[string]any{"account_id": "a1"}, identity: map[string]string{}, scopes: []string{"read:jira-user"},
		},
		{
			app: atlassian.JiraApp, tool: "list_project_statuses", required: []string{"project_key"}, props: []string{"project_key"},
			args: map[string]any{"project_key": "mock"}, identity: map[string]string{"project": "MOCK"}, scopes: work,
		},
		{
			app: atlassian.JiraApp, tool: "list_filters", props: []string{"name", "max_results", "start_at"},
			args: map[string]any{"name": "secret"}, identity: map[string]string{}, scopes: work, page: true,
		},
		{
			app: atlassian.JiraApp, tool: "add_remote_link", required: []string{"key", "url", "title"}, props: []string{"key", "url", "title", "summary"},
			args: map[string]any{"key": "mock-42", "url": "https://example.test/secret", "title": "secret"}, identity: issueID, scopes: []string{"write:jira-work"},
		},
		{
			app: atlassian.ConfluenceApp, tool: "list_space_pages", required: []string{"space_key"}, props: []string{"space_key", "depth", "limit", "cursor"},
			args: map[string]any{"space_key": "DOCS"}, identity: map[string]string{"space": "DOCS"},
			scopes: []string{"read:page:confluence", "read:space:confluence"}, page: true,
		},
	} {
		t.Run(tc.tool, func(t *testing.T) { checkMetadata(t, tc) })
	}
	c, _ := newJira(t, newAPIServer(t, nil), connectors.Bounds{})
	if tool := toolNamed(t, c, "add_remote_link"); tool.Kind != connectors.KindWrite || tool.Reconcile.Kind != connectors.ReconcileMarker || tool.ResultIDs == nil {
		t.Errorf("add_remote_link kind %q reconcile %q", tool.Kind, tool.Reconcile.Kind)
	}
}

func TestListRemoteLinks(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET " + jiraBase + "/issue/MOCK-42/remotelink": {status: 200, body: `[
		{"id":10000,"globalId":"system=https://docs.example.test/page","relationship":"mentioned in","application":{"name":"Confluence","type":"com.atlassian.confluence"},
		 "object":{"url":"https://docs.example.test/page","title":"Design doc","summary":"The design"}},
		{"id":10001,"application":{},"object":{"url":"https://example.test/pr/1","title":"PR 1"}}]`}})
	c, _ := newJira(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call(atlassian.JiraApp, "list_remote_links", map[string]any{"key": "mock-42"}))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Issue string `json:"issue"`
		Links []struct {
			ID                                             int
			Title, URL, Summary, Relationship, Application string
		} `json:"links"`
	}
	decode(t, res, &got)
	if got.Issue != "MOCK-42" || len(got.Links) != 2 || got.Links[0].ID != 10000 || got.Links[0].Application != "Confluence" ||
		got.Links[0].Relationship != "mentioned in" || got.Links[1].URL != "https://example.test/pr/1" {
		t.Errorf("links = %+v", got)
	}
	if _, err := c.Call(context.Background(), call(atlassian.JiraApp, "list_remote_links", map[string]any{"key": "../x"})); err == nil {
		t.Error("a bad key accepted")
	}
}

func TestGetUser(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET " + jiraBase + "/user": {status: 200, body: `{"accountId":"a1","displayName":"Bob","active":true,"accountType":"atlassian"}`}})
	c, _ := newJira(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call(atlassian.JiraApp, "get_user", map[string]any{"account_id": "a1"}))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	decode(t, res, &got)
	if got["account_id"] != "a1" || got["display_name"] != "Bob" {
		t.Errorf("user = %v", got)
	}
	if q := query(t, srv, jiraBase+"/user"); q.Get("accountId") != "a1" {
		t.Errorf("query = %v", q)
	}
	if _, err := c.Call(context.Background(), call(atlassian.JiraApp, "get_user", map[string]any{"account_id": "a b"})); err == nil {
		t.Error("a bad account id accepted")
	}
	srv = newAPIServer(t, map[string]route{"GET " + jiraBase + "/user": {status: 404, body: `{"errorMessages":["no user"]}`}})
	c, _ = newJira(t, srv, connectors.Bounds{})
	_, err = c.Call(context.Background(), call(atlassian.JiraApp, "get_user", map[string]any{"account_id": "zz"}))
	wantClass(t, err, atlassian.ClassNotFound, 404)
}

func TestListProjectStatuses(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET " + jiraBase + "/project/MOCK/statuses": {status: 200, body: `[
		{"name":"Task","subtask":false,"statuses":[{"id":"1","name":"To Do","statusCategory":{"name":"To Do"}},{"id":"3","name":"In Review","statusCategory":{"name":"In Progress"}}]},
		{"name":"Sub-task","subtask":true,"statuses":[{"id":"1","name":"To Do","statusCategory":{"name":"To Do"}}]}]`}})
	c, _ := newJira(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call(atlassian.JiraApp, "list_project_statuses", map[string]any{"project_key": "mock"}))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Project    string `json:"project"`
		IssueTypes []struct {
			IssueType string `json:"issue_type"`
			Subtask   bool
			Statuses  []struct{ ID, Name, Category string }
		} `json:"issue_types"`
	}
	decode(t, res, &got)
	if got.Project != "MOCK" || len(got.IssueTypes) != 2 || got.IssueTypes[0].Statuses[1].Name != "In Review" ||
		got.IssueTypes[0].Statuses[1].Category != "In Progress" || !got.IssueTypes[1].Subtask {
		t.Errorf("statuses = %+v", got)
	}
}

func TestListFilters(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET " + jiraBase + "/filter/search": {status: 200, body: `{"startAt":0,"maxResults":2,"total":3,"isLast":false,
		"values":[{"id":"10000","name":"My open","jql":"assignee = currentUser()","favourite":true,"owner":{"displayName":"Alice"}},{"id":"10001","name":"Team"}]}`}})
	c, _ := newJira(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call(atlassian.JiraApp, "list_filters", map[string]any{"name": "my", "max_results": 2}))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Filters []struct {
			ID, Name, Owner, JQL string
			Favourite            bool
		} `json:"filters"`
		HasMore bool `json:"has_more"`
	}
	decode(t, res, &got)
	if len(got.Filters) != 2 || got.Filters[0].JQL != "assignee = currentUser()" || !got.Filters[0].Favourite || got.Filters[0].Owner != "Alice" || !got.HasMore {
		t.Errorf("filters = %+v", got)
	}
	q := query(t, srv, jiraBase+"/filter/search")
	if q.Get("filterName") != "my" || q.Get("maxResults") != "2" || q.Get("expand") != "description,favourite,jql,owner" {
		t.Errorf("query = %v", q)
	}
}

const remoteLinkPath = jiraBase + "/issue/MOCK-42/remotelink"

func TestAddRemoteLinkAndCheck(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		"POST " + remoteLinkPath: {status: 201, body: `{"id":10050,"self":"x"}`},
		"GET " + remoteLinkPath:  {status: 200, body: `[{"id":10049,"globalId":"other","object":{"url":"u","title":"t"}},{"id":10050,"globalId":"` + marker + `","object":{"url":"u","title":"t"}}]`},
	})
	c, _ := newJira(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), write(atlassian.JiraApp, "add_remote_link", map[string]any{
		"key": "mock-42", "url": "https://example.test/pr/7", "title": "PR 7", "summary": "Fixes it"}))
	if err != nil {
		t.Fatal(err)
	}
	body := jsonBody(t, srv.Last(t, "POST "+remoteLinkPath))
	obj, _ := body["object"].(map[string]any)
	if body["globalId"] != marker || obj["url"] != "https://example.test/pr/7" || obj["title"] != "PR 7" || obj["summary"] != "Fixes it" {
		t.Errorf("body = %v", body)
	}
	if ids := toolNamed(t, c, "add_remote_link").ResultIDs(res); ids["id"] != "10050" || ids["issue"] != "MOCK-42" {
		t.Errorf("ResultIDs = %v", ids)
	}
	check := toolNamed(t, c, "add_remote_link").Reconcile.Check
	r, err := check(context.Background(), reconcile(atlassian.JiraApp, "add_remote_link", map[string]string{"issue": "MOCK-42"}))
	wantFound(t, r, err, "10050")
	srv2 := newAPIServer(t, map[string]route{"GET " + remoteLinkPath: {status: 200, body: `[]`}})
	c2, _ := newJira(t, srv2, connectors.Bounds{})
	r, err = toolNamed(t, c2, "add_remote_link").Reconcile.Check(context.Background(), reconcile(atlassian.JiraApp, "add_remote_link", map[string]string{"issue": "MOCK-42"}))
	wantNotFound(t, r, err)
	for _, args := range []map[string]any{
		{"key": "MOCK-42", "url": "javascript:alert(1)", "title": "x"},
		{"key": "MOCK-42", "url": "https://example.test", "title": ""},
		{"key": "MOCK-42", "url": "ftp://example.test/f", "title": "x"},
	} {
		if _, err := c.Call(context.Background(), write(atlassian.JiraApp, "add_remote_link", args)); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
}

func TestListSpacePages(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		"GET " + v2 + "/spaces": {status: 200, body: "spaces_docs.json"},
		"GET " + v2 + "/spaces/98765/pages": {status: 200, body: `{"results":[{"id":"1","title":"Home","status":"current","spaceId":"98765"},
			{"id":"2","title":"Child","status":"current","spaceId":"98765","parentId":"1","position":3}],"_links":{"next":"/wiki/api/v2/spaces/98765/pages?cursor=n2"}}`},
	})
	c, _ := newConfluence(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call(atlassian.ConfluenceApp, "list_space_pages", map[string]any{"space_key": "DOCS", "depth": "root", "limit": 2}))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Space string `json:"space"`
		Pages []struct {
			ID, Title string
			ParentID  string `json:"parent_id"`
		} `json:"pages"`
		HasMore    bool   `json:"has_more"`
		NextCursor string `json:"next_cursor"`
	}
	decode(t, res, &got)
	if got.Space != "DOCS" || len(got.Pages) != 2 || got.Pages[1].ParentID != "1" || !got.HasMore || got.NextCursor != "n2" {
		t.Errorf("pages = %+v", got)
	}
	if q := query(t, srv, v2+"/spaces/98765/pages"); q.Get("depth") != "root" || q.Get("limit") != "2" {
		t.Errorf("query = %v", q)
	}
	for _, args := range []map[string]any{{"space_key": "../x"}, {"space_key": "DOCS", "depth": "deep"}} {
		if _, err := c.Call(context.Background(), call(atlassian.ConfluenceApp, "list_space_pages", args)); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
}
