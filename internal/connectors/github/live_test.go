//go:build live

package github_test

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	gh "github.com/google/go-github/v90/github"
	"golang.org/x/oauth2"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/github"
)

// TestLiveGetMe hits api.github.com with the token in GITHUB_LIVE_TOKEN
// (a dedicated test account's GitHub App user token or a fine-grained
// personal access token with no permissions; get_me needs none). It is
// behind the "live" build tag and skipped without the variable, so CI
// never runs it:
//
//	GITHUB_LIVE_TOKEN=ghu_... go test -tags live -run Live ./internal/connectors/github/
func TestLiveGetMe(t *testing.T) {
	token := os.Getenv("GITHUB_LIVE_TOKEN")
	if token == "" {
		t.Skip("GITHUB_LIVE_TOKEN is unset")
	}
	c, err := github.New(github.Options{
		Tokens: func(context.Context, string, string) oauth2.TokenSource {
			return oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
		},
		Timeout: 20 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Call(context.Background(), connectors.Call{
		Principal: connectors.Principal{UserID: "live"}, Tool: "github." + github.ToolGetMe, Account: "live-account", Args: map[string]any{},
	})
	if err != nil {
		t.Fatalf("get_me: %v", err)
	}
	me, ok := res.Content.(github.User)
	if !ok || me.Login == "" || me.ID == 0 {
		t.Fatalf("get_me content = %#v, want a user with login and id", res.Content)
	}
	if res.Unavailable || res.Partial || res.Empty {
		t.Errorf("markers = %+v", res)
	}
	t.Logf("authenticated as %s (id %d)", me.Login, me.ID)
}

// TestLiveCreateIssueAndReconcile creates an issue in GITHUB_LIVE_REPO
// ("owner/name"; the token needs Issues: write there) under a fresh
// operation id, then runs create_issue's reconciliation check from the
// resource identity alone, as the ledger's reconciler would, and expects
// it to find the issue by its hidden marker. The issue is closed
// afterwards (best effort). Behind the "live" build tag and skipped
// without both variables, so CI never runs it:
//
//	GITHUB_LIVE_TOKEN=ghu_... GITHUB_LIVE_REPO=owner/name go test -tags live -run Live ./internal/connectors/github/
func TestLiveCreateIssueAndReconcile(t *testing.T) {
	token, repoFull := os.Getenv("GITHUB_LIVE_TOKEN"), os.Getenv("GITHUB_LIVE_REPO")
	if token == "" || repoFull == "" {
		t.Skip("GITHUB_LIVE_TOKEN or GITHUB_LIVE_REPO is unset")
	}
	owner, repo, ok := strings.Cut(repoFull, "/")
	if !ok || owner == "" || repo == "" {
		t.Fatalf("GITHUB_LIVE_REPO = %q, want owner/name", repoFull)
	}
	c, err := github.New(github.Options{
		Tokens: func(context.Context, string, string) oauth2.TokenSource {
			return oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
		},
		Timeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	opID := connectors.NewAccountID()
	args := map[string]any{"owner": owner, "repo": repo, "title": "mcp-gateway live test " + opID[:8], "body": "Created by the gateway's live test; safe to close."}
	res, err := c.Call(ctx, connectors.Call{
		Principal: connectors.Principal{UserID: "live"}, Tool: "github." + github.ToolCreateIssue, Account: "live-account", OperationID: opID, Args: args,
	})
	if err != nil {
		t.Fatalf("create_issue: %v", err)
	}
	created, ok := res.Content.(github.CreatedIssue)
	if !ok || created.Number == 0 {
		t.Fatalf("create_issue content = %#v", res.Content)
	}
	t.Logf("created %s", created.URL)
	t.Cleanup(func() {
		client, err := gh.NewClient(gh.WithAuthToken(token))
		if err != nil {
			t.Logf("closing the live issue: %v", err)
			return
		}
		if _, _, err := client.Issues.Update(ctx, owner, repo, created.Number, gh.UpdateIssueRequest{State: gh.Ptr("closed")}); err != nil {
			t.Logf("closing the live issue: %v", err)
		}
	})

	var tool connectors.Tool
	for _, tl := range c.Tools() {
		if tl.Name == github.ToolCreateIssue {
			tool = tl
		}
	}
	in := connectors.ReconcileInput{
		Call:             connectors.Call{Principal: connectors.Principal{UserID: "live"}, Tool: tool.FullName(), Account: "live-account", OperationID: opID},
		OperationID:      opID,
		ResourceIdentity: tool.ResourceIdentity(args),
	}
	// The search index lags; the fallback listing decides at once, so
	// one check is enough, but allow a couple of attempts for eventual
	// consistency of the list endpoint itself.
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
	if out.Outcome != connectors.ReconcileFound || out.ResourceID != strconv.Itoa(created.Number) {
		t.Fatalf("Check = %+v, want found #%d", out, created.Number)
	}
}
