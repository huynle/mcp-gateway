package slack_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/slack"
)

const conversationsWithDMs = `{"ok":true,"channels":[` +
	`{"id":"C0ENGGEN01","name":"eng-general","is_channel":true,"is_member":true},` +
	`{"id":"D0BOBDM001","is_im":true,"user":"U0BOB00001","created":1700000000},` +
	`{"id":"G0GROUPDM1","name":"mpdm-alice--bob--carol-1","is_mpim":true,"is_group":true,"is_private":true}` +
	`],"response_metadata":{"next_cursor":""}}`

func TestListConversationsMetadata(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), slack.Options{})
	checkToolCases(t, c, []toolCase{{
		tool: "list_conversations", kind: connectors.KindRead, scopes: []string{"channels:read", "groups:read"},
		props: []string{"types", "limit", "cursor", "exclude_archived"}, args: map[string]any{"types": "im"}, identity: map[string]string{},
	}})
}

// accountsWith is an account source where the test account granted scopes.
func accountsWith(scopes ...string) connectors.AccountSource {
	src := connectors.NewStaticAccountSource()
	src.Add(alice, connectors.Account{ID: acct, App: "slack", Label: connectors.LabelPersonal, Scopes: scopes})
	return src
}

func TestListConversationsDefaultTypesFollowGrantedScopes(t *testing.T) {
	cases := []struct {
		name     string
		accounts connectors.AccountSource
		want     string
	}{
		{"no account source", nil, "public_channel,private_channel"},
		{"all four read scopes", accountsWith("channels:read", "groups:read", "im:read", "mpim:read", "chat:write"), "public_channel,private_channel,im,mpim"},
		{"no mpim:read", accountsWith("channels:read", "groups:read", "IM:READ"), "public_channel,private_channel,im"},
		{"no scopes recorded", accountsWith(), "public_channel,private_channel"},
		{"account unknown", connectors.NewStaticAccountSource(), "public_channel,private_channel"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"users.conversations": {body: conversationsWithDMs}})
			c, _ := newConnector(t, srv, slack.Options{Accounts: tc.accounts})
			res, err := c.Call(context.Background(), call("list_conversations", nil))
			if err != nil {
				t.Fatal(err)
			}
			if got := srv.Last(t, "users.conversations").Form.Get("types"); got != tc.want {
				t.Errorf("types = %q, want %q", got, tc.want)
			}
			var page slack.ConversationsPage
			decode(t, res, &page)
			if len(page.Conversations) != 3 {
				t.Fatalf("page = %+v", page)
			}
			im := page.Conversations[1]
			if !im.IsIM || im.User != "U0BOB00001" || im.ID != "D0BOBDM001" || !im.IsMember {
				t.Errorf("im = %+v", im)
			}
			if mp := page.Conversations[2]; !mp.IsMpIM || mp.Name != "mpdm-alice--bob--carol-1" {
				t.Errorf("mpim = %+v", mp)
			}
		})
	}
}

func TestListConversationsExplicitTypes(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"users.conversations": {body: conversationsWithDMs}})
	c, _ := newConnector(t, srv, slack.Options{})
	if _, err := c.Call(context.Background(), call("list_conversations", map[string]any{"types": "IM, mpim", "limit": 5, "exclude_archived": false})); err != nil {
		t.Fatal(err)
	}
	f := srv.Last(t, "users.conversations").Form
	if f.Get("types") != "im,mpim" || f.Get("limit") != "5" || f.Get("exclude_archived") == "true" {
		t.Errorf("form = %v", redactForm(f))
	}
	_, err := c.Call(context.Background(), call("list_conversations", map[string]any{"types": "im,dm"}))
	wantClass(t, err, slack.ClassInvalidArgument)
	srv2 := newAPIServer(t, map[string]route{"users.conversations": {body: "error_missing_scope.json"}})
	c2, _ := newConnector(t, srv2, slack.Options{})
	_, err = c2.Call(context.Background(), call("list_conversations", map[string]any{"types": "im"}))
	wantClass(t, err, slack.ClassForbidden)
}

// list_channels is unchanged: it never asks for DMs, whatever was granted.
func TestListChannelsStaysChannelsOnly(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"users.conversations": {body: "users_conversations_page2.json"}})
	c, _ := newConnector(t, srv, slack.Options{Accounts: accountsWith("channels:read", "groups:read", "im:read", "mpim:read")})
	if _, err := c.Call(context.Background(), call("list_channels", nil)); err != nil {
		t.Fatal(err)
	}
	if got := srv.Last(t, "users.conversations").Form.Get("types"); got != "public_channel,private_channel" {
		t.Errorf("types = %q", got)
	}
}

// History and threads of a DM (D...) or group DM (G...) are read by id,
// with no name resolution; Slack enforces im:history / mpim:history.
func TestDirectMessageHistoryAndThreadByID(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		"conversations.history": {body: "conversations_history.json"},
		"conversations.replies": {body: "conversations_replies.json"},
	})
	c, _ := newConnector(t, srv, slack.Options{})
	if _, err := c.Call(context.Background(), call("read_channel_history", map[string]any{"channel": "D0BOBDM001"})); err != nil {
		t.Fatalf("history: %v", err)
	}
	if got := srv.Last(t, "conversations.history").Form.Get("channel"); got != "D0BOBDM001" {
		t.Errorf("history channel = %q", got)
	}
	if _, err := c.Call(context.Background(), call("get_thread", map[string]any{"channel": "G0GROUPDM1", "thread_ts": "1700002000.000100"})); err != nil {
		t.Fatalf("thread: %v", err)
	}
	if got := srv.Last(t, "conversations.replies").Form.Get("channel"); got != "G0GROUPDM1" {
		t.Errorf("replies channel = %q", got)
	}
	if n := srv.Count("users.conversations"); n != 0 {
		t.Errorf("users.conversations requests = %d, want 0", n)
	}
	srv2 := newAPIServer(t, map[string]route{"conversations.history": {body: "error_missing_scope.json"}})
	c2, _ := newConnector(t, srv2, slack.Options{})
	_, err := c2.Call(context.Background(), call("read_channel_history", map[string]any{"channel": "D0BOBDM001"}))
	wantClass(t, err, slack.ClassForbidden)
}

// An id that is not among the account's conversations is asked about
// directly (conversations.info): a public channel the account is not a
// member of resolves to its name (so join_channel by id meets name
// rules), a group DM to mpim:<id> (no name a rule could match), and
// a DM id never needs a request; an id Slack does not know stays an
// error (fail closed).
func TestResolveIdentityFallsBackToConversationInfo(t *testing.T) {
	cases := []struct {
		name, id, info, want string
		err                  bool
	}{
		{"non-member public channel", "C0PUBLIC01", channelBody(`"id":"C0PUBLIC01","name":"Announcements","is_channel":true`), "announcements", false},
		{"group DM", "G0GROUPDM1", channelBody(`"id":"G0GROUPDM1","name":"mpdm-alice--bob-1","is_mpim":true,"is_group":true`), "mpim:G0GROUPDM1", false},
		{"unknown", "C0NOWHERE1", `{"ok":false,"error":"channel_not_found"}`, "", true},
		{"nameless", "C0NONAME01", channelBody(`"id":"C0NONAME01"`), "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			routes := resolveRoutes()
			routes["conversations.info"] = route{body: tc.info}
			srv := newAPIServer(t, routes)
			c, _ := newConnector(t, srv, slack.Options{})
			in := identityOf(t, c, tc.id)
			out, err := c.ResolveIdentity(context.Background(), call("join_channel", nil), in)
			if tc.err {
				var se *slack.Error
				if !errors.As(err, &se) || se.Class != slack.ClassNotFound || out != nil {
					t.Fatalf("out=%v err=%v, want not_found", out, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if want := map[string]string{"channel": tc.want, "channel_id": tc.id}; !reflect.DeepEqual(out, want) {
				t.Errorf("resolved = %v, want %v", out, want)
			}
			if f := srv.Last(t, "conversations.info").Form; f.Get("channel") != tc.id {
				t.Errorf("info form = %v", redactForm(f))
			}
			// A hit is cached like a listing hit.
			if _, err := c.ResolveIdentity(context.Background(), call("join_channel", nil), in); err != nil || srv.Count("conversations.info") != 1 {
				t.Errorf("second resolution: err=%v info requests=%d, want cached", err, srv.Count("conversations.info"))
			}
		})
	}
}
