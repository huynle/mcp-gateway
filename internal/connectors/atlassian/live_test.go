//go:build live

package atlassian_test

import (
	"context"
	"os"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/atlassian"
)

// liveConnector builds a connector for app against api.atlassian.com
// with the token in ATLASSIAN_LIVE_TOKEN (an OAuth 2.0 (3LO) access
// token of a dedicated test account) and the site in
// ATLASSIAN_LIVE_CLOUD_ID (the cloud id from accessible-resources;
// ATLASSIAN_LIVE_SITE_URL, optional, fills the links in results). The
// tests are behind the "live" build tag and skipped without the
// variables, so CI never runs them:
//
//	ATLASSIAN_LIVE_TOKEN=... ATLASSIAN_LIVE_CLOUD_ID=... go test -tags live -run Live ./internal/connectors/atlassian/
func liveConnector(t *testing.T, app string) *atlassian.Connector {
	t.Helper()
	token, cloudID := os.Getenv("ATLASSIAN_LIVE_TOKEN"), os.Getenv("ATLASSIAN_LIVE_CLOUD_ID")
	if token == "" || cloudID == "" {
		t.Skip("ATLASSIAN_LIVE_TOKEN or ATLASSIAN_LIVE_CLOUD_ID is unset")
	}
	c, err := atlassian.New(app, atlassian.Options{
		Tokens: func(context.Context, string, string) oauth2.TokenSource {
			return oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
		},
		Sites: func(context.Context, string, string) (atlassian.Site, error) {
			return atlassian.Site{CloudID: cloudID, URL: os.Getenv("ATLASSIAN_LIVE_SITE_URL")}, nil
		},
		Timeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestLiveSearchIssues runs jira.search_issues against the live site
// (the token needs read:jira-work) with a query every site answers.
func TestLiveSearchIssues(t *testing.T) {
	c := liveConnector(t, atlassian.JiraApp)
	res, err := c.Call(context.Background(), connectors.Call{
		Principal: connectors.Principal{UserID: "live"}, Tool: "jira." + atlassian.ToolSearchIssues, Account: "live-account",
		Args: map[string]any{"jql": "ORDER BY created DESC", "max_results": 3},
	})
	if err != nil {
		t.Fatalf("search_issues: %v", err)
	}
	page, ok := res.Content.(atlassian.IssuePage)
	if !ok {
		t.Fatalf("content = %#v", res.Content)
	}
	if res.Unavailable || res.Partial {
		t.Errorf("markers = %+v", res)
	}
	t.Logf("%d issues (empty %v, has_more %v)", len(page.Issues), res.Empty, page.HasMore)
}

// TestLiveConfluenceSearch runs confluence.search against the live site
// (the token needs search:confluence).
func TestLiveConfluenceSearch(t *testing.T) {
	c := liveConnector(t, atlassian.ConfluenceApp)
	res, err := c.Call(context.Background(), connectors.Call{
		Principal: connectors.Principal{UserID: "live"}, Tool: "confluence." + atlassian.ToolSearch, Account: "live-account",
		Args: map[string]any{"cql": "type = page ORDER BY created DESC", "limit": 3},
	})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	page, ok := res.Content.(atlassian.ContentPage)
	if !ok {
		t.Fatalf("content = %#v", res.Content)
	}
	if res.Unavailable || res.Partial {
		t.Errorf("markers = %+v", res)
	}
	t.Logf("%d results (empty %v, has_more %v)", len(page.Results), res.Empty, page.HasMore)
}

// TestLiveCreateIssueAndReconcile creates an issue in the project named
// by ATLASSIAN_LIVE_PROJECT (the token needs write:jira-work there; the
// issue type is ATLASSIAN_LIVE_ISSUE_TYPE, "Task" by default) under a
// fresh operation id, then runs create_issue's reconciliation check from
// the resource identity alone, as the ledger's reconciler would, and
// expects it to find the issue by its marker. The issue is left in place
// (deleting needs an extra scope); its summary says it is a test.
func TestLiveCreateIssueAndReconcile(t *testing.T) {
	project := os.Getenv("ATLASSIAN_LIVE_PROJECT")
	if project == "" {
		t.Skip("ATLASSIAN_LIVE_PROJECT is unset")
	}
	issueType := os.Getenv("ATLASSIAN_LIVE_ISSUE_TYPE")
	if issueType == "" {
		issueType = "Task"
	}
	c := liveConnector(t, atlassian.JiraApp)
	ctx := context.Background()
	opID := connectors.NewAccountID()
	args := map[string]any{"project_key": project, "issue_type": issueType, "summary": "mcp-gateway live test " + opID[:8], "description": "Created by the gateway's live test; safe to close."}
	res, err := c.Call(ctx, connectors.Call{
		Principal: connectors.Principal{UserID: "live"}, Tool: "jira." + atlassian.ToolCreateIssue, Account: "live-account", OperationID: opID, Args: args,
	})
	if err != nil {
		t.Fatalf("create_issue: %v", err)
	}
	created, ok := res.Content.(atlassian.CreatedIssue)
	if !ok || created.Key == "" {
		t.Fatalf("create_issue content = %#v", res.Content)
	}
	t.Logf("created %s", created.Key)

	var tool connectors.Tool
	for _, tl := range c.Tools() {
		if tl.Name == atlassian.ToolCreateIssue {
			tool = tl
		}
	}
	in := connectors.ReconcileInput{
		Call:             connectors.Call{Principal: connectors.Principal{UserID: "live"}, Tool: tool.FullName(), Account: "live-account", OperationID: opID},
		OperationID:      opID,
		ResourceIdentity: tool.ResourceIdentity(args),
	}
	// The search index lags; the fallback listing decides at once, but
	// allow a few attempts for eventual consistency of the listing too.
	var out connectors.ReconcileResult
	for attempt := 0; attempt < 3; attempt++ {
		out, err = tool.Reconcile.Check(ctx, in)
		if err == nil && out.Outcome == connectors.ReconcileFound {
			break
		}
		time.Sleep(3 * time.Second)
	}
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if out.Outcome != connectors.ReconcileFound || out.ResourceID != created.Key {
		t.Fatalf("Check = %+v, want found %s", out, created.Key)
	}
}
