package slack_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/slack"
)

// identityOf runs post_message's resource-identity hook over a channel
// argument: what the policy stage hands ResolveIdentity.
func identityOf(t *testing.T, c *slack.Connector, channel string) map[string]string {
	t.Helper()
	for _, tool := range c.Tools() {
		if tool.Name == slack.ToolPostMessage {
			return tool.ResourceIdentity(map[string]any{"channel": channel, "text": "x"})
		}
	}
	t.Fatal("post_message not declared")
	return nil
}

// resolveRoutes is the two-page conversations listing the fixture
// server answers (eng-general and eng-leads on page 1, random on page 2).
func resolveRoutes() map[string]route {
	return map[string]route{"users.conversations": {byCursor: map[string]route{
		"":                     {body: "users_conversations_page1.json"},
		"dXNlcjpVMEc5V0ZYTlo=": {body: "users_conversations_page2.json"},
	}}}
}

// TestResolveIdentityChannelID: a channel given by id is resolved to
// its name through the account's conversations listing (walking the
// pages; public, private and group-DM conversations): channel becomes
// the lower-cased name, channel_id stays, the input map is untouched.
func TestResolveIdentityChannelID(t *testing.T) {
	srv := newAPIServer(t, resolveRoutes())
	c, tk := newConnector(t, srv, slack.Options{})
	var r connectors.IdentityResolver = c

	in := identityOf(t, c, "c0random01")
	before := map[string]string{"channel": "C0RANDOM01", "channel_id": "C0RANDOM01"}
	if !reflect.DeepEqual(in, before) {
		t.Fatalf("hook identity = %v", in)
	}
	out, err := r.ResolveIdentity(context.Background(), call("post_message", map[string]any{"channel": "c0random01"}), in)
	if err != nil {
		t.Fatalf("ResolveIdentity: %v", err)
	}
	if want := map[string]string{"channel": "random", "channel_id": "C0RANDOM01"}; !reflect.DeepEqual(out, want) {
		t.Errorf("resolved = %v, want %v", out, want)
	}
	if !reflect.DeepEqual(in, before) {
		t.Errorf("input mutated: %v", in)
	}
	if n := srv.Count("users.conversations"); n != 2 {
		t.Errorf("users.conversations requests = %d, want 2 (random is on page 2)", n)
	}
	form := srv.Last(t, "users.conversations").Form
	if types := form.Get("types"); !strings.Contains(types, "public_channel") || !strings.Contains(types, "private_channel") || !strings.Contains(types, "mpim") {
		t.Errorf("types = %q, want public, private and mpim conversations", types)
	}
	if form.Get("limit") != "200" {
		t.Errorf("limit = %q, want 200", form.Get("limit"))
	}
	if len(tk.calls) != 1 || tk.calls[0] != alice+"/"+acct {
		t.Errorf("token source calls = %v, want the call's account", tk.calls)
	}
}

// TestResolveIdentityMentionIgnoresItsName: the <#C...|name> form is
// resolved by its id; the name in the mention is what the harness
// typed and is never trusted.
func TestResolveIdentityMentionIgnoresItsName(t *testing.T) {
	srv := newAPIServer(t, resolveRoutes())
	c, _ := newConnector(t, srv, slack.Options{})
	in := identityOf(t, c, "<#C0ENGGEN01|eng-deploys>")
	out, err := c.ResolveIdentity(context.Background(), call("post_message", nil), in)
	if err != nil {
		t.Fatalf("ResolveIdentity: %v", err)
	}
	if want := map[string]string{"channel": "eng-general", "channel_id": "C0ENGGEN01"}; !reflect.DeepEqual(out, want) {
		t.Errorf("resolved = %v, want %v", out, want)
	}
}

// TestResolveIdentityNothingToResolve: a name, no channel at all, and
// a direct-message id (an IM has no name a rule could be written
// against) come back unchanged without any Slack request.
func TestResolveIdentityNothingToResolve(t *testing.T) {
	srv := newAPIServer(t, resolveRoutes())
	c, tk := newConnector(t, srv, slack.Options{})
	for _, tc := range []struct {
		name string
		in   map[string]string
	}{
		{"by name", identityOf(t, c, "#Eng-General")},
		{"no channel", map[string]string{}},
		{"nil", nil},
		{"direct message", identityOf(t, c, "D0ALICE001")},
	} {
		out, err := c.ResolveIdentity(context.Background(), call("post_message", nil), tc.in)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if !reflect.DeepEqual(out, tc.in) {
			t.Errorf("%s: resolved = %v, want unchanged %v", tc.name, out, tc.in)
		}
	}
	if n := srv.Count("users.conversations"); n != 0 {
		t.Errorf("users.conversations requests = %d, want 0", n)
	}
	if len(tk.calls) != 0 {
		t.Errorf("token fetched %d times for nothing to resolve", len(tk.calls))
	}
}

// TestResolveIdentityCachesPerAccount: a second resolution of the same
// id for the same account answers from the cache (no request); another
// account lists its own conversations.
func TestResolveIdentityCachesPerAccount(t *testing.T) {
	srv := newAPIServer(t, resolveRoutes())
	c, _ := newConnector(t, srv, slack.Options{})
	in := identityOf(t, c, "C0ENGGEN01")
	first := call("post_message", nil)
	for i := 0; i < 3; i++ {
		out, err := c.ResolveIdentity(context.Background(), first, in)
		if err != nil || out["channel"] != "eng-general" {
			t.Fatalf("call %d: out=%v err=%v", i, out, err)
		}
	}
	if n := srv.Count("users.conversations"); n != 1 {
		t.Errorf("users.conversations requests = %d, want 1 (cached)", n)
	}
	other := first
	other.Account = "2c9d1f44-5a6b-4c7d-8e9f-0a1b2c3d4e5f"
	if _, err := c.ResolveIdentity(context.Background(), other, in); err != nil {
		t.Fatal(err)
	}
	if n := srv.Count("users.conversations"); n != 2 {
		t.Errorf("users.conversations requests = %d, want 2 (another account is not served from the first's cache)", n)
	}
	// A miss is not cached: the next call asks again.
	missing := identityOf(t, c, "C0NOWHERE1")
	for i := 0; i < 2; i++ {
		if _, err := c.ResolveIdentity(context.Background(), first, missing); err == nil {
			t.Fatalf("call %d: unknown id resolved", i)
		}
	}
	if n := srv.Count("users.conversations"); n != 6 {
		t.Errorf("users.conversations requests = %d, want 6 (two misses walk both pages each)", n)
	}
}

// TestResolveIdentityFailures: an id the account cannot see is
// not_found; a Slack error and a failing token source are errors too
// (never a silent fall-through to the raw id); the walk is bounded by
// MaxResolvePages.
func TestResolveIdentityFailures(t *testing.T) {
	srv := newAPIServer(t, resolveRoutes())
	c, _ := newConnector(t, srv, slack.Options{})
	in := identityOf(t, c, "C0NOWHERE1")
	out, err := c.ResolveIdentity(context.Background(), call("post_message", nil), in)
	var se *slack.Error
	if !errors.As(err, &se) || se.Class != slack.ClassNotFound || out != nil {
		t.Errorf("unknown id: out=%v err=%v, want not_found", out, err)
	}

	srv2 := newAPIServer(t, map[string]route{"users.conversations": {body: "error_invalid_auth.json"}})
	c2, _ := newConnector(t, srv2, slack.Options{})
	if _, err := c2.ResolveIdentity(context.Background(), call("post_message", nil), in); !errors.As(err, &se) || se.Class != slack.ClassReconnectRequired {
		t.Errorf("invalid_auth: err = %v, want reconnect_required", err)
	}

	srv3 := newAPIServer(t, resolveRoutes())
	c3, tk := newConnector(t, srv3, slack.Options{})
	tk.fail = errors.New("no token")
	if _, err := c3.ResolveIdentity(context.Background(), call("post_message", nil), in); err == nil {
		t.Error("failing token source: resolved anyway")
	}

	// Bounded: a listing that never ends stops after MaxResolvePages.
	endless := map[string]route{"users.conversations": {body: `{"ok":true,"channels":[{"id":"C0ENGGEN01","name":"eng-general","is_channel":true}],"response_metadata":{"next_cursor":"more"}}`}}
	srv4 := newAPIServer(t, endless)
	c4, _ := newConnector(t, srv4, slack.Options{})
	if _, err := c4.ResolveIdentity(context.Background(), call("post_message", nil), in); !errors.As(err, &se) || se.Class != slack.ClassNotFound {
		t.Errorf("endless listing: err = %v, want not_found", err)
	}
	if n := srv4.Count("users.conversations"); n != slack.MaxResolvePages {
		t.Errorf("endless listing walked %d pages, want %d", n, slack.MaxResolvePages)
	}
}
