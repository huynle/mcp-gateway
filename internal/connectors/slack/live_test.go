//go:build live

package slack_test

import (
	"context"
	"os"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/slack"
)

// liveConnector builds a connector over the user token in
// SLACK_LIVE_USER_TOKEN (a dedicated test workspace's xoxp- token with
// the scopes of docs/vendor-apps.md section 2.2), skipping without it.
// The live tests are behind the "live" build tag, so CI never runs
// them:
//
//	SLACK_LIVE_USER_TOKEN=xoxp-... go test -tags live -run Live ./internal/connectors/slack/
func liveConnector(t *testing.T, marker bool) *slack.Connector {
	t.Helper()
	token := os.Getenv("SLACK_LIVE_USER_TOKEN")
	if token == "" {
		t.Skip("SLACK_LIVE_USER_TOKEN is unset")
	}
	c, err := slack.New(slack.Options{
		Tokens: func(context.Context, string, string) oauth2.TokenSource {
			return oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
		},
		Timeout: 20 * time.Second, MarkerReconcile: marker,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func liveCall(tool string, args map[string]any) connectors.Call {
	return connectors.Call{Principal: connectors.Principal{UserID: "live"}, Tool: "slack." + tool, Account: "live-account", Args: args}
}

// TestLiveListChannels lists the test user's channels against slack.com.
func TestLiveListChannels(t *testing.T) {
	c := liveConnector(t, false)
	res, err := c.Call(context.Background(), liveCall(slack.ToolListChannels, map[string]any{"limit": 5}))
	if err != nil {
		t.Fatalf("list_channels: %v", err)
	}
	page, ok := res.Content.(slack.ChannelsPage)
	if !ok {
		t.Fatalf("content = %#v", res.Content)
	}
	if res.Unavailable {
		t.Fatal("unavailable")
	}
	t.Logf("%d channels (has_more %v)", len(page.Channels), page.HasMore)
}

// TestLivePostAndReconcile posts to SLACK_LIVE_CHANNEL (a dedicated test
// channel the token's user is a member of, by name or id) under a fresh
// operation id with marker reconciliation on, runs post_message's check
// from the resource identity alone, as the ledger's reconciler would,
// and expects it to find the message by its metadata; then adds a
// reaction to it and runs add_reaction's stable-id check. Skipped
// without both variables; never run in CI. The messages stay in the
// test channel (a user token cannot delete them without chat:write
// delete rights; the channel is dedicated to this).
//
//	SLACK_LIVE_USER_TOKEN=xoxp-... SLACK_LIVE_CHANNEL=#gateway-tests go test -tags live -run Live ./internal/connectors/slack/
func TestLivePostAndReconcile(t *testing.T) {
	channel := os.Getenv("SLACK_LIVE_CHANNEL")
	if channel == "" {
		t.Skip("SLACK_LIVE_CHANNEL is unset")
	}
	c := liveConnector(t, true)
	ctx := context.Background()
	opID := connectors.NewAccountID()
	args := map[string]any{"channel": channel, "text": "mcp-gateway live test " + opID[:8] + " (safe to ignore)"}
	call := liveCall(slack.ToolPostMessage, args)
	call.OperationID = opID
	res, err := c.Call(ctx, call)
	if err != nil {
		t.Fatalf("post_message: %v", err)
	}
	posted, ok := res.Content.(slack.PostedMessage)
	if !ok || posted.TS == "" {
		t.Fatalf("post_message content = %#v", res.Content)
	}
	t.Logf("posted %s in %s", posted.TS, posted.Channel)

	var post, react connectors.Tool
	for _, tl := range c.Tools() {
		switch tl.Name {
		case slack.ToolPostMessage:
			post = tl
		case slack.ToolAddReaction:
			react = tl
		}
	}
	in := connectors.ReconcileInput{
		Call:             connectors.Call{Principal: connectors.Principal{UserID: "live"}, Tool: post.FullName(), Account: "live-account", OperationID: opID},
		OperationID:      opID,
		ResourceIdentity: post.ResourceIdentity(args),
	}
	var out connectors.ReconcileResult
	for attempt := 0; attempt < 3; attempt++ {
		out, err = post.Reconcile.Check(ctx, in)
		if err == nil && out.Outcome == connectors.ReconcileFound {
			break
		}
		time.Sleep(3 * time.Second)
	}
	if err != nil {
		t.Fatalf("post_message Check: %v", err)
	}
	if out.Outcome != connectors.ReconcileFound || out.ResourceID != posted.TS {
		t.Fatalf("post_message Check = %+v, want found %s (Slack kept the metadata?)", out, posted.TS)
	}

	rargs := map[string]any{"channel": posted.Channel, "timestamp": posted.TS, "name": "white_check_mark"}
	rcall := liveCall(slack.ToolAddReaction, rargs)
	rcall.OperationID = connectors.NewAccountID()
	if _, err := c.Call(ctx, rcall); err != nil {
		t.Fatalf("add_reaction: %v", err)
	}
	rin := connectors.ReconcileInput{
		Call:             connectors.Call{Principal: connectors.Principal{UserID: "live"}, Tool: react.FullName(), Account: "live-account", OperationID: rcall.OperationID},
		OperationID:      rcall.OperationID,
		ResourceIdentity: react.ResourceIdentity(rargs),
	}
	rout, err := react.Reconcile.Check(ctx, rin)
	if err != nil {
		t.Fatalf("add_reaction Check: %v", err)
	}
	if rout.Outcome != connectors.ReconcileFound || rout.ResourceID != posted.TS {
		t.Fatalf("add_reaction Check = %+v, want found %s", rout, posted.TS)
	}
}
