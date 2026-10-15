package atlassian_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/atlassian"
)

// The Jira writes added after the v1 set.

func TestJiraMoreWriteToolsMetadata(t *testing.T) {
	work := []string{"write:jira-work"}
	cases := []struct {
		metadataCase
		kind connectors.ReconcileKind
	}{
		{metadataCase{
			app: atlassian.JiraApp, tool: "update_issue", required: []string{"key"},
			props: []string{"key", "summary", "description", "labels", "priority", "fields"},
			args:  map[string]any{"key": "mock-42", "summary": "secret"}, identity: map[string]string{"project": "MOCK", "issue": "MOCK-42"}, scopes: work,
		}, connectors.ReconcileNone},
		{metadataCase{
			app: atlassian.JiraApp, tool: "assign_issue", required: []string{"key"}, props: []string{"key", "account_id"},
			args:     map[string]any{"key": "MOCK-42", "account_id": "5b10ac8d82e05b22cc7d4ef5"},
			identity: map[string]string{"project": "MOCK", "issue": "MOCK-42", "assignee": "5b10ac8d82e05b22cc7d4ef5"}, scopes: work,
		}, connectors.ReconcileStableID},
		{metadataCase{
			app: atlassian.JiraApp, tool: "edit_comment", required: []string{"key", "comment_id", "body"}, props: []string{"key", "comment_id", "body"},
			args:     map[string]any{"key": "MOCK-42", "comment_id": "20001", "body": "secret"},
			identity: map[string]string{"project": "MOCK", "issue": "MOCK-42", "comment": "20001"}, scopes: work,
		}, connectors.ReconcileMarker},
		{metadataCase{
			app: atlassian.JiraApp, tool: "add_worklog", required: []string{"key", "time_spent"}, props: []string{"key", "time_spent", "started", "comment"},
			args: map[string]any{"key": "MOCK-42", "time_spent": "1h", "comment": "secret"}, identity: map[string]string{"project": "MOCK", "issue": "MOCK-42"}, scopes: work,
		}, connectors.ReconcileMarker},
		{metadataCase{
			app: atlassian.JiraApp, tool: "link_issues", required: []string{"link_type", "inward_key", "outward_key"}, props: []string{"link_type", "inward_key", "outward_key"},
			args:     map[string]any{"link_type": "Blocks", "inward_key": "mock-1", "outward_key": "ops-2"},
			identity: map[string]string{"project": "MOCK", "issue": "MOCK-1", "linked_issue": "OPS-2", "link_type": "Blocks"}, scopes: work,
		}, connectors.ReconcileStableID},
		{metadataCase{
			app: atlassian.JiraApp, tool: "add_watcher", required: []string{"key", "account_id"}, props: []string{"key", "account_id"},
			args:     map[string]any{"key": "MOCK-42", "account_id": "557058:0b7f7a2e-1c7e-4c2a"},
			identity: map[string]string{"project": "MOCK", "issue": "MOCK-42", "watcher": "557058:0b7f7a2e-1c7e-4c2a"}, scopes: work,
		}, connectors.ReconcileStableID},
		{metadataCase{
			app: atlassian.JiraApp, tool: "remove_watcher", required: []string{"key", "account_id"}, props: []string{"key", "account_id"},
			args:     map[string]any{"key": "MOCK-42", "account_id": "a1"},
			identity: map[string]string{"project": "MOCK", "issue": "MOCK-42", "watcher": "a1"}, scopes: work,
		}, connectors.ReconcileStableID},
		{metadataCase{
			app: atlassian.JiraApp, tool: "add_issues_to_sprint", required: []string{"sprint_id", "keys"}, props: []string{"sprint_id", "keys"},
			args:     map[string]any{"sprint_id": 12, "keys": []any{"mock-1", "MOCK-2"}},
			identity: map[string]string{"sprint": "12", "issues": "MOCK-1,MOCK-2"}, scopes: []string{"write:sprint:jira-software"},
		}, connectors.ReconcileStableID},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			checkMetadata(t, tc.metadataCase)
			c, _ := newJira(t, newAPIServer(t, nil), connectors.Bounds{})
			tool := toolNamed(t, c, tc.tool)
			if tool.Kind != connectors.KindWrite || tool.Reconcile.Kind != tc.kind || tool.ResultIDs == nil {
				t.Errorf("kind %q reconcile %q resultIDs %v", tool.Kind, tool.Reconcile.Kind, tool.ResultIDs != nil)
			}
		})
	}
}

func TestJiraMoreWritesRequireAnOperationID(t *testing.T) {
	srv := newAPIServer(t, nil)
	c, _ := newJira(t, srv, connectors.Bounds{})
	for _, tool := range []string{"update_issue", "assign_issue", "edit_comment", "add_worklog", "link_issues", "add_watcher", "remove_watcher", "add_issues_to_sprint"} {
		if _, err := c.Call(context.Background(), call(atlassian.JiraApp, tool, map[string]any{"key": "MOCK-1"})); !errors.Is(err, atlassian.ErrMissingOperation) {
			t.Errorf("%s: err = %v, want ErrMissingOperation", tool, err)
		}
	}
	if len(srv.Requests()) != 0 {
		t.Error("requests sent without an operation id")
	}
}

func TestCreateIssueExtraFields(t *testing.T) {
	srv := newAPIServer(t, map[string]route{createIssuePath: {status: 201, body: "created_issue.json"}})
	c, _ := newJira(t, srv, connectors.Bounds{})
	_, err := c.Call(context.Background(), write(atlassian.JiraApp, "create_issue", map[string]any{
		"project_key": "MOCK", "issue_type": "Sub-task", "summary": "t", "parent_key": "mock-7", "priority": "High", "assignee_account_id": "a1",
		"fields": map[string]any{"customfield_10010": []any{map[string]any{"value": "Platform"}}, "description": "overridden", "summary": "overridden"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	fields, _ := jsonBody(t, srv.Last(t, createIssuePath))["fields"].(map[string]any)
	if p, _ := fields["parent"].(map[string]any); p["key"] != "MOCK-7" {
		t.Errorf("parent = %v", fields["parent"])
	}
	if p, _ := fields["priority"].(map[string]any); p["name"] != "High" {
		t.Errorf("priority = %v", fields["priority"])
	}
	if a, _ := fields["assignee"].(map[string]any); a["accountId"] != "a1" {
		t.Errorf("assignee = %v", fields["assignee"])
	}
	if cf, _ := fields["customfield_10010"].([]any); len(cf) != 1 {
		t.Errorf("custom field = %v", fields["customfield_10010"])
	}
	if fields["summary"] != "t" {
		t.Errorf("summary = %v: the explicit argument must win over fields", fields["summary"])
	}
	if got := adfParagraphs(t, fields["description"]); len(got) != 1 || got[0] != marker {
		t.Errorf("description = %q: the marker must survive a fields override", got)
	}
	if _, err := c.Call(context.Background(), write(atlassian.JiraApp, "create_issue", map[string]any{"project_key": "MOCK", "issue_type": "Task", "summary": "t", "fields": "x"})); err == nil {
		t.Error("non-object fields accepted")
	}
}

const updateIssuePath = "PUT " + jiraBase + "/issue/MOCK-42"

func TestUpdateIssue(t *testing.T) {
	srv := newAPIServer(t, map[string]route{updateIssuePath: {status: 204}})
	c, _ := newJira(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), write(atlassian.JiraApp, "update_issue", map[string]any{
		"key": "mock-42", "summary": "New title", "description": "Line one", "labels": []any{"a", "b"}, "priority": "Low",
		"fields": map[string]any{"customfield_10011": 3},
	}))
	if err != nil {
		t.Fatal(err)
	}
	body := jsonBody(t, srv.Last(t, updateIssuePath))
	fields, _ := body["fields"].(map[string]any)
	if fields["summary"] != "New title" || fields["customfield_10011"] != float64(3) {
		t.Errorf("fields = %v", fields)
	}
	if got := adfParagraphs(t, fields["description"]); strings.Join(got, "|") != "Line one" {
		t.Errorf("description = %q (no marker on an update)", got)
	}
	if p, _ := fields["priority"].(map[string]any); p["name"] != "Low" {
		t.Errorf("priority = %v", fields["priority"])
	}
	var got struct {
		Issue   string   `json:"issue"`
		Updated []string `json:"updated"`
		URL     string   `json:"url"`
	}
	decode(t, res, &got)
	if got.Issue != "MOCK-42" || strings.Join(got.Updated, ",") != "customfield_10011,description,labels,priority,summary" || got.URL != siteURL+"/browse/MOCK-42" {
		t.Errorf("result = %+v", got)
	}
	if ids := toolNamed(t, c, "update_issue").ResultIDs(res); ids["issue"] != "MOCK-42" {
		t.Errorf("ResultIDs = %v", ids)
	}
	if _, err := c.Call(context.Background(), write(atlassian.JiraApp, "update_issue", map[string]any{"key": "MOCK-42"})); err == nil {
		t.Error("an update without fields accepted")
	}
}

func TestUpdateIssueErrors(t *testing.T) {
	for _, tc := range writeErrorCases(route{status: 204}) {
		if strings.HasPrefix(tc.name, "unreadable") {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{updateIssuePath: tc.rt})
			c := newWriter(t, atlassian.JiraApp, srv)
			res, err := c.Call(context.Background(), write(atlassian.JiraApp, "update_issue", map[string]any{"key": "MOCK-42", "summary": "s"}))
			checkWriteError(t, "jira", tc, res, err)
		})
	}
}

const assignPath = "PUT " + jiraBase + "/issue/MOCK-42/assignee"

func TestAssignIssueAndCheck(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		assignPath:                           {status: 204},
		"GET " + jiraBase + "/issue/MOCK-42": {status: 200, body: `{"key":"MOCK-42","fields":{"assignee":{"accountId":"a1","displayName":"Alice Example"}}}`},
	})
	c, _ := newJira(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), write(atlassian.JiraApp, "assign_issue", map[string]any{"key": "MOCK-42", "account_id": "a1"}))
	if err != nil {
		t.Fatal(err)
	}
	if b := jsonBody(t, srv.Last(t, assignPath)); b["accountId"] != "a1" {
		t.Errorf("body = %v", b)
	}
	if ids := toolNamed(t, c, "assign_issue").ResultIDs(res); ids["issue"] != "MOCK-42" || ids["assignee"] != "a1" {
		t.Errorf("ResultIDs = %v", ids)
	}
	check := toolNamed(t, c, "assign_issue").Reconcile.Check
	r, err := check(context.Background(), reconcile(atlassian.JiraApp, "assign_issue", map[string]string{"issue": "MOCK-42", "assignee": "a1"}))
	wantFound(t, r, err, "MOCK-42")
	r, err = check(context.Background(), reconcile(atlassian.JiraApp, "assign_issue", map[string]string{"issue": "MOCK-42", "assignee": "b2"}))
	wantNotFound(t, r, err)
	if _, err := check(context.Background(), reconcile(atlassian.JiraApp, "assign_issue", map[string]string{"issue": "MOCK-42"})); !errors.Is(err, atlassian.ErrNotReconcilable) {
		t.Errorf("err = %v, want ErrNotReconcilable", err)
	}
}

func TestAssignIssueUnassigns(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		assignPath:                           {status: 204},
		"GET " + jiraBase + "/issue/MOCK-42": {status: 200, body: `{"key":"MOCK-42","fields":{"assignee":null}}`},
	})
	c, _ := newJira(t, srv, connectors.Bounds{})
	tool := toolNamed(t, c, "assign_issue")
	if id := tool.ResourceIdentity(map[string]any{"key": "MOCK-42"}); id["assignee"] != "unassigned" {
		t.Errorf("identity = %v", id)
	}
	if _, err := c.Call(context.Background(), write(atlassian.JiraApp, "assign_issue", map[string]any{"key": "MOCK-42"})); err != nil {
		t.Fatal(err)
	}
	if b := srv.Last(t, assignPath).Body; strings.TrimSpace(b) != `{"accountId":null}` {
		t.Errorf("body = %s", b)
	}
	r, err := tool.Reconcile.Check(context.Background(), reconcile(atlassian.JiraApp, "assign_issue", map[string]string{"issue": "MOCK-42", "assignee": "unassigned"}))
	wantFound(t, r, err, "MOCK-42")
	if _, err := c.Call(context.Background(), write(atlassian.JiraApp, "assign_issue", map[string]any{"key": "MOCK-42", "account_id": "bad id!"})); err == nil {
		t.Error("bad account id accepted")
	}
}

const editCommentPath = "PUT " + jiraBase + "/issue/MOCK-42/comment/20001"

func TestEditCommentAndCheck(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		editCommentPath: {status: 200, body: `{"id":"20001"}`},
		"GET " + jiraBase + "/issue/MOCK-42/comment/20001": {status: 200, body: `{"id":"20001","body":{"type":"doc","version":1,"content":[{"type":"paragraph","content":[{"type":"text","text":"` + marker + `"}]}]}}`},
	})
	c, _ := newJira(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), write(atlassian.JiraApp, "edit_comment", map[string]any{"key": "MOCK-42", "comment_id": "20001", "body": "Fixed text"}))
	if err != nil {
		t.Fatal(err)
	}
	if got := adfParagraphs(t, jsonBody(t, srv.Last(t, editCommentPath))["body"]); strings.Join(got, "|") != "Fixed text|"+marker {
		t.Errorf("body = %q", got)
	}
	if ids := toolNamed(t, c, "edit_comment").ResultIDs(res); ids["id"] != "20001" || ids["url"] == "" {
		t.Errorf("ResultIDs = %v", ids)
	}
	r, err := toolNamed(t, c, "edit_comment").Reconcile.Check(context.Background(), reconcile(atlassian.JiraApp, "edit_comment", map[string]string{"issue": "MOCK-42", "comment": "20001"}))
	wantFound(t, r, err, "20001")
}

const addWorklogPath = "POST " + jiraBase + "/issue/MOCK-42/worklog"

func TestAddWorklogAndCheck(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		addWorklogPath: {status: 201, body: `{"id":"50009","timeSpent":"1h 30m"}`},
		"GET " + jiraBase + "/issue/MOCK-42/worklog": {pageParam: "startAt", pages: map[string]route{
			"0": {status: 200, body: `{"startAt":0,"maxResults":1,"total":2,"worklogs":[{"id":"50001","comment":null}]}`},
			"1": {status: 200, body: `{"startAt":1,"maxResults":1,"total":2,"worklogs":[{"id":"50009","comment":{"type":"doc","version":1,"content":[{"type":"paragraph","content":[{"type":"text","text":"` + marker + `"}]}]}}]}`},
		}},
	})
	c, _ := newJira(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), write(atlassian.JiraApp, "add_worklog", map[string]any{"key": "MOCK-42", "time_spent": "1h 30m", "started": "2026-10-01T09:00:00Z", "comment": "Pairing"}))
	if err != nil {
		t.Fatal(err)
	}
	body := jsonBody(t, srv.Last(t, addWorklogPath))
	if body["timeSpent"] != "1h 30m" || body["started"] != "2026-10-01T09:00:00.000+0000" {
		t.Errorf("body = %v", body)
	}
	if got := adfParagraphs(t, body["comment"]); strings.Join(got, "|") != "Pairing|"+marker {
		t.Errorf("comment = %q", got)
	}
	if ids := toolNamed(t, c, "add_worklog").ResultIDs(res); ids["id"] != "50009" || ids["issue"] != "MOCK-42" {
		t.Errorf("ResultIDs = %v", ids)
	}
	r, err := toolNamed(t, c, "add_worklog").Reconcile.Check(context.Background(), reconcile(atlassian.JiraApp, "add_worklog", map[string]string{"issue": "MOCK-42"}))
	wantFound(t, r, err, "50009")
	for _, bad := range []map[string]any{{"key": "MOCK-42"}, {"key": "MOCK-42", "time_spent": "1h", "started": "yesterday"}} {
		if _, err := c.Call(context.Background(), write(atlassian.JiraApp, "add_worklog", bad)); err == nil {
			t.Errorf("args %v accepted", bad)
		}
	}
}

func TestAddWorklogCheckNotFound(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET " + jiraBase + "/issue/MOCK-42/worklog": {status: 200, body: `{"startAt":0,"maxResults":100,"total":1,"worklogs":[{"id":"50001"}]}`}})
	c, _ := newJira(t, srv, connectors.Bounds{})
	r, err := toolNamed(t, c, "add_worklog").Reconcile.Check(context.Background(), reconcile(atlassian.JiraApp, "add_worklog", map[string]string{"issue": "MOCK-42"}))
	wantNotFound(t, r, err)
}

const linkPath = "POST " + jiraBase + "/issueLink"

func TestLinkIssuesAndCheck(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		linkPath: {status: 201},
		"GET " + jiraBase + "/issue/MOCK-1": {status: 200, body: `{"key":"MOCK-1","fields":{"issuelinks":[
			{"id":"40009","type":{"name":"Blocks"},"outwardIssue":{"key":"OPS-2"}}]}}`},
	})
	c, _ := newJira(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), write(atlassian.JiraApp, "link_issues", map[string]any{"link_type": "Blocks", "inward_key": "mock-1", "outward_key": "OPS-2"}))
	if err != nil {
		t.Fatal(err)
	}
	body := jsonBody(t, srv.Last(t, linkPath))
	in, _ := body["inwardIssue"].(map[string]any)
	out, _ := body["outwardIssue"].(map[string]any)
	typ, _ := body["type"].(map[string]any)
	if in["key"] != "MOCK-1" || out["key"] != "OPS-2" || typ["name"] != "Blocks" {
		t.Errorf("body = %v", body)
	}
	if ids := toolNamed(t, c, "link_issues").ResultIDs(res); ids["inward_key"] != "MOCK-1" || ids["outward_key"] != "OPS-2" {
		t.Errorf("ResultIDs = %v", ids)
	}
	check := toolNamed(t, c, "link_issues").Reconcile.Check
	r, err := check(context.Background(), reconcile(atlassian.JiraApp, "link_issues", map[string]string{"issue": "MOCK-1", "linked_issue": "OPS-2", "link_type": "Blocks"}))
	wantFound(t, r, err, "40009")
	r, err = check(context.Background(), reconcile(atlassian.JiraApp, "link_issues", map[string]string{"issue": "MOCK-1", "linked_issue": "OPS-3", "link_type": "Blocks"}))
	wantNotFound(t, r, err)
	if _, err := c.Call(context.Background(), write(atlassian.JiraApp, "link_issues", map[string]any{"link_type": "Blocks", "inward_key": "MOCK-1", "outward_key": "MOCK-1"})); err == nil {
		t.Error("a self link accepted")
	}
}

const watchersPath = jiraBase + "/issue/MOCK-42/watchers"

func TestAddAndRemoveWatcher(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		"POST " + watchersPath:   {status: 204},
		"DELETE " + watchersPath: {status: 204},
		"GET " + watchersPath:    {status: 200, body: `{"watchCount":1,"watchers":[{"accountId":"a1"}]}`},
	})
	c, _ := newJira(t, srv, connectors.Bounds{})
	if _, err := c.Call(context.Background(), write(atlassian.JiraApp, "add_watcher", map[string]any{"key": "MOCK-42", "account_id": "a1"})); err != nil {
		t.Fatal(err)
	}
	if b := strings.TrimSpace(srv.Last(t, "POST "+watchersPath).Body); b != `"a1"` {
		t.Errorf("body = %s, want the JSON string account id", b)
	}
	res, err := c.Call(context.Background(), write(atlassian.JiraApp, "remove_watcher", map[string]any{"key": "MOCK-42", "account_id": "b2"}))
	if err != nil {
		t.Fatal(err)
	}
	if q := srv.Last(t, "DELETE "+watchersPath).URL.Query(); q.Get("accountId") != "b2" {
		t.Errorf("query = %v", q)
	}
	if ids := toolNamed(t, c, "remove_watcher").ResultIDs(res); ids["issue"] != "MOCK-42" || ids["watcher"] != "b2" {
		t.Errorf("ResultIDs = %v", ids)
	}
	add, rm := toolNamed(t, c, "add_watcher").Reconcile.Check, toolNamed(t, c, "remove_watcher").Reconcile.Check
	r, err := add(context.Background(), reconcile(atlassian.JiraApp, "add_watcher", map[string]string{"issue": "MOCK-42", "watcher": "a1"}))
	wantFound(t, r, err, "MOCK-42")
	r, err = add(context.Background(), reconcile(atlassian.JiraApp, "add_watcher", map[string]string{"issue": "MOCK-42", "watcher": "b2"}))
	wantNotFound(t, r, err)
	r, err = rm(context.Background(), reconcile(atlassian.JiraApp, "remove_watcher", map[string]string{"issue": "MOCK-42", "watcher": "b2"}))
	wantFound(t, r, err, "MOCK-42")
	r, err = rm(context.Background(), reconcile(atlassian.JiraApp, "remove_watcher", map[string]string{"issue": "MOCK-42", "watcher": "a1"}))
	wantNotFound(t, r, err)
}

const sprintIssuesPath = "POST " + agileBase + "/sprint/12/issue"

func TestAddIssuesToSprintAndCheck(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		sprintIssuesPath:                        {status: 204},
		"GET " + agileBase + "/sprint/12/issue": {status: 200, body: `{"startAt":0,"maxResults":50,"total":2,"issues":[{"key":"MOCK-1"},{"key":"MOCK-2"}]}`},
	})
	c, _ := newJira(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), write(atlassian.JiraApp, "add_issues_to_sprint", map[string]any{"sprint_id": 12, "keys": []any{"mock-1", "MOCK-2"}}))
	if err != nil {
		t.Fatal(err)
	}
	if issues, _ := jsonBody(t, srv.Last(t, sprintIssuesPath))["issues"].([]any); len(issues) != 2 || issues[0] != "MOCK-1" {
		t.Errorf("body issues = %v", issues)
	}
	if ids := toolNamed(t, c, "add_issues_to_sprint").ResultIDs(res); ids["sprint_id"] != "12" || ids["issues"] != "MOCK-1,MOCK-2" {
		t.Errorf("ResultIDs = %v", ids)
	}
	check := toolNamed(t, c, "add_issues_to_sprint").Reconcile.Check
	r, err := check(context.Background(), reconcile(atlassian.JiraApp, "add_issues_to_sprint", map[string]string{"sprint": "12", "issues": "MOCK-1,MOCK-2"}))
	wantFound(t, r, err, "12")
	if q := query(t, srv, agileBase+"/sprint/12/issue"); q.Get("jql") != "key in (MOCK-1,MOCK-2)" {
		t.Errorf("check jql = %q", q.Get("jql"))
	}
	r, err = check(context.Background(), reconcile(atlassian.JiraApp, "add_issues_to_sprint", map[string]string{"sprint": "12", "issues": "MOCK-1,MOCK-3"}))
	wantNotFound(t, r, err)
	for _, bad := range []map[string]any{{"sprint_id": 12}, {"sprint_id": 12, "keys": []any{"nope"}}, {"keys": []any{"MOCK-1"}}} {
		if _, err := c.Call(context.Background(), write(atlassian.JiraApp, "add_issues_to_sprint", bad)); err == nil {
			t.Errorf("args %v accepted", bad)
		}
	}
}
