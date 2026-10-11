package slack_test

import (
	"context"
	"errors"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors/slack"
)

// A user id (or <@U...> mention) as the channel opens the direct message
// with that user (conversations.open) and posts there as the connected
// user: the way to leave a note to yourself.
func TestPostMessageToUserOpensTheDirectMessage(t *testing.T) {
	for _, target := range []string{"U0SELF0001", "<@U0SELF0001>", "u0self0001"} {
		t.Run(target, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{
				"conversations.open": {body: `{"ok": true, "channel": {"id": "D0SELFDM01"}}`},
				"chat.postMessage":   {body: "chat_post_message.json"},
			})
			c, _ := newConnector(t, srv, slack.Options{})
			if _, err := c.Call(context.Background(), write("post_message", map[string]any{"channel": target, "text": "note to self"})); err != nil {
				t.Fatalf("post_message: %v", err)
			}
			open := srv.Last(t, "conversations.open").Form
			if open.Get("users") != "U0SELF0001" || open.Get("return_im") != "true" {
				t.Errorf("conversations.open form = %v", redactForm(open))
			}
			if got := srv.Last(t, "chat.postMessage").Form.Get("channel"); got != "D0SELFDM01" {
				t.Errorf("posted to %q, want the DM D0SELFDM01", got)
			}
			if n := srv.Count("users.conversations"); n != 0 {
				t.Errorf("users.conversations requests = %d, want 0 (a user id is not a channel name)", n)
			}
		})
	}
}

// Without im:write Slack refuses conversations.open: a known refusal,
// nothing is posted.
func TestPostMessageToUserWithoutIMWriteIsForbidden(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		"conversations.open": {body: `{"ok": false, "error": "missing_scope", "needed": "im:write", "provided": "chat:write"}`},
		"chat.postMessage":   {body: "chat_post_message.json"},
	})
	c, _ := newConnector(t, srv, slack.Options{})
	_, err := c.Call(context.Background(), write("post_message", map[string]any{"channel": "U0SELF0001", "text": "note to self"}))
	var se *slack.Error
	if !errors.As(err, &se) || se.Class != slack.ClassForbidden {
		t.Fatalf("err = %v, want class %s", err, slack.ClassForbidden)
	}
	if n := srv.Count("chat.postMessage"); n != 0 {
		t.Errorf("chat.postMessage requests = %d, want 0", n)
	}
}

// Policy sees a direct message as dm:<user>: no channel name a name rule
// could match, and no channel id for the identity resolver to look up.
func TestDirectMessageResourceIdentity(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), slack.Options{})
	for _, tool := range []string{"post_message", "reply_in_thread"} {
		got := toolNamed(t, c, tool).ResourceIdentity(map[string]any{"channel": "<@U0SELF0001>", "thread_ts": "1700004000.000100"})
		if got["channel"] != "dm:U0SELF0001" || got["dm_user"] != "U0SELF0001" || got["channel_id"] != "" || got["channel_name"] != "" {
			t.Errorf("%s identity = %v", tool, got)
		}
		out, err := c.ResolveIdentity(context.Background(), call(tool, nil), got)
		if err != nil || out["channel"] != "dm:U0SELF0001" {
			t.Errorf("%s ResolveIdentity = %v, %v; want it unchanged", tool, out, err)
		}
	}
	// A channel id still resolves as before.
	if got := toolNamed(t, c, "post_message").ResourceIdentity(map[string]any{"channel": "C0ENGGEN01"}); got["channel_id"] != "C0ENGGEN01" {
		t.Errorf("channel identity = %v", got)
	}
}
