package github_test

import (
	"context"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/github"
)

func TestIssueToolsMetadata(t *testing.T) {
	or := []string{"owner", "repo"}
	n42 := withArgs(map[string]any{"number": 42})
	ident42 := identityWith(map[string]string{"number": "42"})
	checkTools(t, []toolMeta{
		{name: "list_issues", kind: connectors.KindRead, scopes: []string{"issues:read"}, required: or, paged: true,
			props: []string{"owner", "repo", "state", "labels", "assignee", "creator", "mentioned", "since", "sort", "direction", "page", "per_page"},
			args:  ownerRepo, identity: repoIdentity},
		{name: "list_issue_comments", kind: connectors.KindRead, scopes: []string{"issues:read"}, required: []string{"owner", "repo", "number"}, paged: true,
			props: []string{"owner", "repo", "number", "since", "page", "per_page"}, args: n42, identity: ident42},
		{name: "update_issue", kind: connectors.KindWrite, scopes: []string{"issues:write"}, required: []string{"owner", "repo", "number"},
			props:     []string{"owner", "repo", "number", "title", "body", "state", "state_reason", "labels", "assignees", "milestone"},
			reconcile: connectors.ReconcileNone, args: withArgs(map[string]any{"number": 42, "title": "secret", "body": "secret"}), identity: ident42},
	})
}

func TestListIssues(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /repos/example-org/widgets/issues": {status: 200, headers: nextLink("/repos/example-org/widgets/issues"), body: `[
		{"number":42,"title":"Bug","state":"open","html_url":"https://github.example.test/i/42","repository_url":"https://api.github.example.test/repos/example-org/widgets","user":{"login":"octocat"},"labels":[{"name":"bug"}]},
		{"number":43,"title":"PR","state":"open","pull_request":{"url":"x"},"user":{"login":"hubot"}}]`}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call("list_issues", withArgs(map[string]any{"state": "all", "labels": []any{"bug", "p1"}, "assignee": "octocat", "since": "2026-01-01T00:00:00Z", "sort": "updated", "direction": "asc"})))
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		HasMore bool `json:"has_more"`
		Items   []struct {
			Number        int      `json:"number"`
			Repo          string   `json:"repo"`
			Labels        []string `json:"labels"`
			IsPullRequest bool     `json:"is_pull_request"`
		} `json:"items"`
	}
	decode(t, res, &p)
	if !p.HasMore || len(p.Items) != 2 || p.Items[0].Number != 42 || p.Items[0].Repo != "example-org/widgets" || p.Items[0].Labels[0] != "bug" || !p.Items[1].IsPullRequest || p.Items[1].Repo != "example-org/widgets" {
		t.Errorf("issues = %+v", p)
	}
	q := query(t, srv, "/repos/example-org/widgets/issues")
	if q.Get("state") != "all" || q.Get("labels") != "bug,p1" || q.Get("assignee") != "octocat" || q.Get("since") == "" || q.Get("sort") != "updated" || q.Get("direction") != "asc" {
		t.Errorf("query = %v", q)
	}
}

func TestListIssueComments(t *testing.T) {
	long := strings.Repeat("words ", 3000)
	srv := newAPIServer(t, map[string]route{"GET /repos/example-org/widgets/issues/42/comments": {status: 200, body: `[
		{"id":1,"body":"` + long + `","user":{"login":"octocat"},"html_url":"https://github.example.test/c/1","created_at":"2026-01-02T03:04:05Z"},
		{"id":2,"body":"second","user":{"login":"hubot"}}]`}})
	c, _ := newConnector(t, srv, connectors.Bounds{MaxResultBytes: 4096})
	res, err := c.Call(context.Background(), call("list_issue_comments", withArgs(map[string]any{"number": 42})))
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		Truncated bool `json:"truncated"`
		Items     []struct {
			ID            int64  `json:"id"`
			User          string `json:"user"`
			Body          string `json:"body"`
			BodyTruncated bool   `json:"body_truncated"`
		} `json:"items"`
	}
	decode(t, res, &p)
	if !p.Truncated || !res.Partial || len(p.Items) != 1 || p.Items[0].ID != 1 || !p.Items[0].BodyTruncated || p.Items[0].User != "octocat" {
		t.Errorf("comments = %+v", p)
	}
}

const patchIssuePath = "PATCH /repos/example-org/widgets/issues/42"

func TestUpdateIssue(t *testing.T) {
	srv := newAPIServer(t, map[string]route{patchIssuePath: {status: 200, body: "issue.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), write("update_issue", withArgs(map[string]any{
		"number": 42, "state": "closed", "state_reason": "not_planned", "labels": []any{}, "assignees": []any{"octocat"}, "title": "New title", "milestone": 3,
	})))
	if err != nil {
		t.Fatal(err)
	}
	body := jsonBody(t, srv.Last(t, patchIssuePath))
	labels, ok := body["labels"].([]any)
	if body["state"] != "closed" || body["state_reason"] != "not_planned" || !ok || len(labels) != 0 || body["title"] != "New title" || body["milestone"] != float64(3) {
		t.Errorf("request = %v", body)
	}
	if _, ok := body["body"]; ok {
		t.Errorf("body sent though not given: %v", body)
	}
	if ids := toolNamed(t, c, "update_issue").ResultIDs(res); ids["number"] != "42" || ids["url"] == "" {
		t.Errorf("ResultIDs = %v", ids)
	}
}

func TestUpdateIssueValidationAndErrors(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	for _, args := range []map[string]any{
		withArgs(map[string]any{"number": 42}),
		withArgs(map[string]any{"number": 42, "state": "deleted"}),
		withArgs(map[string]any{"number": 42, "state_reason": "bored"}),
	} {
		if _, err := c.Call(context.Background(), write("update_issue", args)); err == nil {
			t.Errorf("args %v accepted", args)
		}
	}
	for _, tc := range writeErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{patchIssuePath: tc.rt})
			res, err := shortTimeout(t, srv).Call(context.Background(), write("update_issue", withArgs(map[string]any{"number": 42, "title": "x"})))
			checkWriteError(t, tc, res, err)
		})
	}
	_ = github.ToolUpdateIssue
}
