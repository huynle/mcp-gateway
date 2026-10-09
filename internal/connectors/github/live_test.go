//go:build live

package github_test

import (
	"context"
	"os"
	"testing"
	"time"

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
