package slack_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/slack"
)

// sha returns the hex SHA-256 the topic / purpose / status identities carry.
func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// channelBody is a conversations.* answer carrying one channel object.
func channelBody(fields string) string {
	return `{"ok":true,"channel":{` + fields + `}}`
}

// runWrite calls a write tool against a fixture server with routes.
func runWrite(t *testing.T, routes map[string]route, tool string, args map[string]any) (connectors.Result, error, *apiServer, *slack.Connector) {
	t.Helper()
	srv := newAPIServer(t, routes)
	c, _ := newConnector(t, srv, slack.Options{})
	res, err := c.Call(context.Background(), write(tool, args))
	return res, err, srv, c
}

// --- metadata -----------------------------------------------------------------------

type toolCase struct {
	tool     string
	kind     connectors.Kind
	rec      connectors.ReconcileKind
	scopes   []string
	required []string
	props    []string
	args     map[string]any
	identity map[string]string
}

func checkToolCases(t *testing.T, c *slack.Connector, cases []toolCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			tool := toolNamed(t, c, tc.tool)
			if tool.Kind != tc.kind {
				t.Errorf("Kind = %q, want %q", tool.Kind, tc.kind)
			}
			if tool.Reconcile.Kind != tc.rec {
				t.Errorf("Reconcile.Kind = %q, want %q", tool.Reconcile.Kind, tc.rec)
			}
			if tc.kind == connectors.KindWrite {
				if (tool.Reconcile.Check != nil) != (tc.rec != connectors.ReconcileNone) {
					t.Errorf("Reconcile.Check present = %v for kind %q", tool.Reconcile.Check != nil, tc.rec)
				}
				if tool.ResultIDs == nil {
					t.Error("ResultIDs is nil")
				} else if tool.ResultIDs(connectors.Result{}) != nil {
					t.Error("ResultIDs of an empty result should be nil")
				}
			} else if tool.ResultIDs != nil || tool.Reconcile.Kind != "" {
				t.Error("a read declares ResultIDs or reconciliation")
			}
			if fmt.Sprint(tool.RequiredScopes) != fmt.Sprint(tc.scopes) {
				t.Errorf("RequiredScopes = %v, want %v", tool.RequiredScopes, tc.scopes)
			}
			if tool.Bounds.MaxResultBytes <= 0 {
				t.Errorf("Bounds = %+v", tool.Bounds)
			}
			checkSchema(t, tool, tc.required, tc.props)
			checkIdentity(t, tool, tc.args, tc.identity)
		})
	}
}

func TestChannelToolsMetadata(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), slack.Options{})
	w, s := connectors.KindWrite, connectors.ReconcileStableID
	byID := map[string]string{"channel": "C0ENGGEN01", "channel_id": "C0ENGGEN01"}
	with := func(extra map[string]string) map[string]string {
		out := map[string]string{"channel": "C0ENGGEN01", "channel_id": "C0ENGGEN01"}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}
	cw := []string{"channels:write"}
	checkToolCases(t, c, []toolCase{
		{tool: "create_channel", kind: w, rec: s, scopes: cw, required: []string{"name"}, props: []string{"name", "is_private"},
			args:     map[string]any{"name": "#Eng-New", "is_private": true},
			identity: map[string]string{"channel": "eng-new", "channel_name": "eng-new", "is_private": "true"}},
		{tool: "rename_channel", kind: w, rec: s, scopes: cw, required: []string{"channel", "name"}, props: []string{"channel", "name"},
			args: map[string]any{"channel": "C0ENGGEN01", "name": "Eng-Renamed"}, identity: with(map[string]string{"new_name": "eng-renamed"})},
		{tool: "archive_channel", kind: w, rec: s, scopes: cw, required: []string{"channel"}, props: []string{"channel"},
			args: map[string]any{"channel": "C0ENGGEN01"}, identity: byID},
		{tool: "unarchive_channel", kind: w, rec: s, scopes: cw, required: []string{"channel"}, props: []string{"channel"},
			args: map[string]any{"channel": "C0ENGGEN01"}, identity: byID},
		{tool: "set_channel_topic", kind: w, rec: s, scopes: cw, required: []string{"channel", "topic"}, props: []string{"channel", "topic"},
			args: map[string]any{"channel": "C0ENGGEN01", "topic": "secret topic"}, identity: with(map[string]string{"topic_sha256": sha("secret topic")})},
		{tool: "set_channel_purpose", kind: w, rec: s, scopes: cw, required: []string{"channel", "purpose"}, props: []string{"channel", "purpose"},
			args: map[string]any{"channel": "C0ENGGEN01", "purpose": "secret purpose"}, identity: with(map[string]string{"purpose_sha256": sha("secret purpose")})},
		{tool: "join_channel", kind: w, rec: s, scopes: cw, required: []string{"channel"}, props: []string{"channel"},
			args: map[string]any{"channel": "#Eng-General"}, identity: map[string]string{"channel": "eng-general", "channel_name": "eng-general"}},
		{tool: "leave_channel", kind: w, rec: s, scopes: cw, required: []string{"channel"}, props: []string{"channel"},
			args: map[string]any{"channel": "C0ENGGEN01"}, identity: byID},
		{tool: "invite_to_channel", kind: w, rec: s, scopes: cw, required: []string{"channel", "users"}, props: []string{"channel", "users"},
			args:     map[string]any{"channel": "C0ENGGEN01", "users": []any{"<@u0carol001>", "U0BOB00001", "U0BOB00001"}},
			identity: with(map[string]string{"users": "U0BOB00001,U0CAROL001"})},
		{tool: "remove_from_channel", kind: w, rec: s, scopes: cw, required: []string{"channel", "user"}, props: []string{"channel", "user"},
			args: map[string]any{"channel": "C0ENGGEN01", "user": "U0BOB00001"}, identity: with(map[string]string{"user": "U0BOB00001"})},
	})
}

// --- create_channel ---------------------------------------------------------------------

func TestCreateChannel(t *testing.T) {
	res, err, srv, c := runWrite(t, map[string]route{
		"conversations.create": {body: channelBody(`"id":"C0NEWCHAN1","name":"eng-new","is_private":true,"is_channel":true`)},
	}, "create_channel", map[string]any{"name": "#Eng-New", "is_private": true})
	if err != nil {
		t.Fatalf("create_channel: %v", err)
	}
	got, ok := res.Content.(slack.ChannelChange)
	if !ok || got.Channel != "C0NEWCHAN1" || got.Name != "eng-new" || !got.IsPrivate || got.Action != "created" {
		t.Errorf("content = %#v", res.Content)
	}
	form := srv.Last(t, "conversations.create").Form
	if form.Get("name") != "eng-new" || form.Get("is_private") != "true" {
		t.Errorf("form = %v", redactForm(form))
	}
	ids := toolNamed(t, c, "create_channel").ResultIDs(res)
	if ids["channel"] != "C0NEWCHAN1" || ids["name"] != "eng-new" {
		t.Errorf("ResultIDs = %v", ids)
	}
}

func TestCreateChannelRejectsBadNames(t *testing.T) {
	for _, name := range []any{"", "Eng New", "eng/new", 42, "a-name-that-is-way-too-long-for-slack-because-slack-caps-channel-names-at-eighty-chars"} {
		_, err, srv, _ := runWrite(t, nil, "create_channel", map[string]any{"name": name})
		wantClass(t, err, slack.ClassInvalidArgument)
		if len(srv.Requests()) != 0 {
			t.Errorf("%v: request sent for an invalid name", name)
		}
	}
	_, err, _, _ := runWrite(t, nil, "create_channel", map[string]any{"name": "ok", "is_private": "yes"})
	wantClass(t, err, slack.ClassInvalidArgument)
}

func TestCreateChannelErrors(t *testing.T) {
	cases := map[string]string{
		"name_taken":            slack.ClassConflict,
		"invalid_name_specials": slack.ClassInvalidArgument,
		"restricted_action":     slack.ClassForbidden,
		"missing_scope":         slack.ClassForbidden,
	}
	for code, class := range cases {
		_, err, _, _ := runWrite(t, map[string]route{"conversations.create": {body: `{"ok":false,"error":"` + code + `"}`}}, "create_channel", map[string]any{"name": "eng-new"})
		wantClass(t, err, class)
		if errors.Is(err, connectors.ErrOutcomeUnknown) {
			t.Errorf("%s: a Slack answer is a known outcome", code)
		}
	}
	_, err, _, _ := runWrite(t, map[string]route{"conversations.create": {body: "error_fatal.json"}}, "create_channel", map[string]any{"name": "eng-new"})
	if !errors.Is(err, connectors.ErrOutcomeUnknown) {
		t.Errorf("fatal_error: err = %v, want ErrOutcomeUnknown", err)
	}
}

func TestCreateChannelCheck(t *testing.T) {
	newChan := `{"ok":true,"channels":[{"id":"C0NEWCHAN1","name":"eng-new","is_channel":true}],"response_metadata":{"next_cursor":""}}`
	in := reconcile("create_channel", map[string]string{"channel": "eng-new", "channel_name": "eng-new"})
	srv := newAPIServer(t, map[string]route{"users.conversations": {body: newChan}})
	c, _ := newConnector(t, srv, slack.Options{})
	res, err := toolNamed(t, c, "create_channel").Reconcile.Check(context.Background(), in)
	wantFound(t, res, err, "C0NEWCHAN1")

	srv2 := newAPIServer(t, resolveRoutes())
	c2, _ := newConnector(t, srv2, slack.Options{})
	res, err = toolNamed(t, c2, "create_channel").Reconcile.Check(context.Background(), in)
	wantNotFound(t, res, err)

	endless := map[string]route{"users.conversations": {body: `{"ok":true,"channels":[{"id":"C0ENGGEN01","name":"eng-general"}],"response_metadata":{"next_cursor":"more"}}`}}
	c3, _ := newConnector(t, newAPIServer(t, endless), slack.Options{})
	if _, err := toolNamed(t, c3, "create_channel").Reconcile.Check(context.Background(), in); err == nil {
		t.Error("bounded walk without the channel: want cannot tell yet")
	}
	if _, err := toolNamed(t, c3, "create_channel").Reconcile.Check(context.Background(), reconcile("create_channel", map[string]string{})); !errors.Is(err, slack.ErrNotReconcilable) {
		t.Errorf("no name: err = %v, want ErrNotReconcilable", err)
	}
}

// --- rename / archive / unarchive / topic / purpose ---------------------------------------

func TestRenameChannelByName(t *testing.T) {
	res, err, srv, c := runWrite(t, map[string]route{
		"users.conversations":  {body: "users_conversations_page1.json"},
		"conversations.rename": {body: channelBody(`"id":"C0ENGGEN01","name":"eng-renamed"`)},
	}, "rename_channel", map[string]any{"channel": "#eng-general", "name": "Eng-Renamed"})
	if err != nil {
		t.Fatalf("rename_channel: %v", err)
	}
	got := res.Content.(slack.ChannelChange)
	if got.Channel != "C0ENGGEN01" || got.Name != "eng-renamed" || got.Action != "renamed" {
		t.Errorf("content = %+v", got)
	}
	form := srv.Last(t, "conversations.rename").Form
	if form.Get("channel") != "C0ENGGEN01" || form.Get("name") != "eng-renamed" {
		t.Errorf("form = %v", redactForm(form))
	}
	if ids := toolNamed(t, c, "rename_channel").ResultIDs(res); ids["channel"] != "C0ENGGEN01" || ids["name"] != "eng-renamed" {
		t.Errorf("ResultIDs = %v", ids)
	}
	_, err, _, _ = runWrite(t, map[string]route{"conversations.rename": {body: `{"ok":false,"error":"name_taken"}`}}, "rename_channel", map[string]any{"channel": "C0ENGGEN01", "name": "random"})
	wantClass(t, err, slack.ClassConflict)
}

func TestRenameChannelCheck(t *testing.T) {
	byID := reconcile("rename_channel", map[string]string{"channel": "general", "channel_id": "C0ENGGEN01", "new_name": "eng-renamed"})
	renamed := map[string]route{"conversations.info": {body: channelBody(`"id":"C0ENGGEN01","name":"eng-renamed"`)}}
	c, _ := newConnector(t, newAPIServer(t, renamed), slack.Options{})
	res, err := toolNamed(t, c, "rename_channel").Reconcile.Check(context.Background(), byID)
	wantFound(t, res, err, "C0ENGGEN01")

	old := map[string]route{"conversations.info": {body: channelBody(`"id":"C0ENGGEN01","name":"eng-general"`)}}
	c2, _ := newConnector(t, newAPIServer(t, old), slack.Options{})
	res, err = toolNamed(t, c2, "rename_channel").Reconcile.Check(context.Background(), byID)
	wantNotFound(t, res, err)

	// By old name: the old name no longer resolves, the new one does.
	byName := reconcile("rename_channel", map[string]string{"channel": "eng-old", "channel_name": "eng-old", "new_name": "eng-general"})
	c3, _ := newConnector(t, newAPIServer(t, map[string]route{
		"users.conversations": {byCursor: map[string]route{"": {body: "users_conversations_page1.json"}, "dXNlcjpVMEc5V0ZYTlo=": {body: "users_conversations_page2.json"}}},
		"conversations.info":  {body: channelBody(`"id":"C0ENGGEN01","name":"eng-general"`)},
	}), slack.Options{})
	res, err = toolNamed(t, c3, "rename_channel").Reconcile.Check(context.Background(), byName)
	wantFound(t, res, err, "C0ENGGEN01")

	if _, err := toolNamed(t, c, "rename_channel").Reconcile.Check(context.Background(), reconcile("rename_channel", map[string]string{"channel_id": "C0ENGGEN01"})); !errors.Is(err, slack.ErrNotReconcilable) {
		t.Errorf("no new name: err = %v", err)
	}
}

func TestArchiveAndUnarchive(t *testing.T) {
	res, err, srv, c := runWrite(t, map[string]route{"conversations.archive": {body: "ok.json"}}, "archive_channel", map[string]any{"channel": "C0ENGGEN01"})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Content.(slack.ChannelChange); got.Channel != "C0ENGGEN01" || got.Action != "archived" || got.Already {
		t.Errorf("content = %+v", got)
	}
	if srv.Last(t, "conversations.archive").Form.Get("channel") != "C0ENGGEN01" {
		t.Error("archive sent the wrong channel")
	}
	if ids := toolNamed(t, c, "archive_channel").ResultIDs(res); ids["channel"] != "C0ENGGEN01" || len(ids) != 1 {
		t.Errorf("ResultIDs = %v", ids)
	}
	res, err, _, _ = runWrite(t, map[string]route{"conversations.archive": {body: `{"ok":false,"error":"already_archived"}`}}, "archive_channel", map[string]any{"channel": "C0ENGGEN01"})
	if err != nil || !res.Content.(slack.ChannelChange).Already {
		t.Errorf("already_archived: res=%+v err=%v, want success already", res, err)
	}
	_, err, _, _ = runWrite(t, map[string]route{"conversations.archive": {body: `{"ok":false,"error":"cant_archive_general"}`}}, "archive_channel", map[string]any{"channel": "C0ENGGEN01"})
	wantClass(t, err, slack.ClassForbidden)

	res, err, _, _ = runWrite(t, map[string]route{"conversations.unarchive": {body: "ok.json"}}, "unarchive_channel", map[string]any{"channel": "C0RANDOM01"})
	if err != nil || res.Content.(slack.ChannelChange).Action != "unarchived" {
		t.Errorf("unarchive: res=%+v err=%v", res, err)
	}
	res, err, _, _ = runWrite(t, map[string]route{"conversations.unarchive": {body: `{"ok":false,"error":"not_archived"}`}}, "unarchive_channel", map[string]any{"channel": "C0RANDOM01"})
	if err != nil || !res.Content.(slack.ChannelChange).Already {
		t.Errorf("not_archived: res=%+v err=%v, want success already", res, err)
	}
}

func TestArchiveChecks(t *testing.T) {
	in := reconcile("archive_channel", map[string]string{"channel": "eng-general", "channel_id": "C0ENGGEN01"})
	for _, tc := range []struct {
		tool, body string
		found      bool
	}{
		{"archive_channel", `"id":"C0ENGGEN01","is_archived":true`, true},
		{"archive_channel", `"id":"C0ENGGEN01","is_archived":false`, false},
		{"unarchive_channel", `"id":"C0ENGGEN01","is_archived":false`, true},
		{"unarchive_channel", `"id":"C0ENGGEN01","is_archived":true`, false},
	} {
		c, _ := newConnector(t, newAPIServer(t, map[string]route{"conversations.info": {body: channelBody(tc.body)}}), slack.Options{})
		res, err := toolNamed(t, c, tc.tool).Reconcile.Check(context.Background(), in)
		if tc.found {
			wantFound(t, res, err, "C0ENGGEN01")
		} else {
			wantNotFound(t, res, err)
		}
	}
	c, _ := newConnector(t, newAPIServer(t, map[string]route{"conversations.info": {body: "error_channel_not_found.json"}}), slack.Options{})
	if _, err := toolNamed(t, c, "archive_channel").Reconcile.Check(context.Background(), in); err == nil {
		t.Error("channel_not_found: want cannot tell yet")
	}
}

func TestSetTopicAndPurpose(t *testing.T) {
	res, err, srv, _ := runWrite(t, map[string]route{"conversations.setTopic": {body: channelBody(`"id":"C0ENGGEN01","topic":{"value":"Deploys at 5"}`)}},
		"set_channel_topic", map[string]any{"channel": "C0ENGGEN01", "topic": "Deploys at 5"})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Content.(slack.ChannelChange); got.Topic != "Deploys at 5" || got.Action != "topic_set" {
		t.Errorf("content = %+v", got)
	}
	if srv.Last(t, "conversations.setTopic").Form.Get("topic") != "Deploys at 5" {
		t.Error("topic not sent")
	}
	res, err, srv, _ = runWrite(t, map[string]route{"conversations.setPurpose": {body: channelBody(`"id":"C0ENGGEN01","purpose":{"value":"Ship it"}`)}},
		"set_channel_purpose", map[string]any{"channel": "C0ENGGEN01", "purpose": "Ship it"})
	if err != nil || res.Content.(slack.ChannelChange).Purpose != "Ship it" || srv.Last(t, "conversations.setPurpose").Form.Get("purpose") != "Ship it" {
		t.Errorf("purpose: res=%+v err=%v", res, err)
	}
	// An empty topic clears it; a missing one is an argument error.
	if _, err, _, _ := runWrite(t, map[string]route{"conversations.setTopic": {body: channelBody(`"id":"C0ENGGEN01"`)}}, "set_channel_topic", map[string]any{"channel": "C0ENGGEN01", "topic": ""}); err != nil {
		t.Errorf("empty topic: %v", err)
	}
	_, err, _, _ = runWrite(t, nil, "set_channel_topic", map[string]any{"channel": "C0ENGGEN01"})
	wantClass(t, err, slack.ClassInvalidArgument)
	_, err, _, _ = runWrite(t, map[string]route{"conversations.setTopic": {body: `{"ok":false,"error":"too_long"}`}}, "set_channel_topic", map[string]any{"channel": "C0ENGGEN01", "topic": "x"})
	wantClass(t, err, slack.ClassInvalidArgument)
}

func TestTopicAndPurposeChecks(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, map[string]route{"conversations.info": {body: channelBody(`"id":"C0ENGGEN01","topic":{"value":"Deploys at 5"},"purpose":{"value":"Ship it"}`)}}), slack.Options{})
	topic := toolNamed(t, c, "set_channel_topic").Reconcile.Check
	res, err := topic(context.Background(), reconcile("set_channel_topic", map[string]string{"channel_id": "C0ENGGEN01", "topic_sha256": sha("Deploys at 5")}))
	wantFound(t, res, err, "C0ENGGEN01")
	res, err = topic(context.Background(), reconcile("set_channel_topic", map[string]string{"channel_id": "C0ENGGEN01", "topic_sha256": sha("other")}))
	wantNotFound(t, res, err)
	purpose := toolNamed(t, c, "set_channel_purpose").Reconcile.Check
	res, err = purpose(context.Background(), reconcile("set_channel_purpose", map[string]string{"channel_id": "C0ENGGEN01", "purpose_sha256": sha("Ship it")}))
	wantFound(t, res, err, "C0ENGGEN01")
	if _, err := purpose(context.Background(), reconcile("set_channel_purpose", map[string]string{"channel_id": "C0ENGGEN01"})); !errors.Is(err, slack.ErrNotReconcilable) {
		t.Errorf("no hash: err = %v", err)
	}
}

// --- join / leave ---------------------------------------------------------------------------

func TestJoinChannelByNameAmongPublicChannels(t *testing.T) {
	list := `{"ok":true,"channels":[{"id":"C0PUBLIC01","name":"announcements","is_channel":true}],"response_metadata":{"next_cursor":""}}`
	res, err, srv, c := runWrite(t, map[string]route{
		"conversations.list": {body: list},
		"conversations.join": {body: channelBody(`"id":"C0PUBLIC01","name":"announcements"`)},
	}, "join_channel", map[string]any{"channel": "#announcements"})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Content.(slack.ChannelChange); got.Channel != "C0PUBLIC01" || got.Name != "announcements" || got.Action != "joined" || got.Already {
		t.Errorf("content = %+v", got)
	}
	if form := srv.Last(t, "conversations.list").Form; form.Get("types") != "public_channel" || form.Get("exclude_archived") != "true" {
		t.Errorf("list form = %v", redactForm(form))
	}
	if srv.Last(t, "conversations.join").Form.Get("channel") != "C0PUBLIC01" {
		t.Error("join sent the wrong channel")
	}
	if ids := toolNamed(t, c, "join_channel").ResultIDs(res); ids["channel"] != "C0PUBLIC01" {
		t.Errorf("ResultIDs = %v", ids)
	}
	res, err, _, _ = runWrite(t, map[string]route{"conversations.join": {body: `{"ok":true,"channel":{"id":"C0PUBLIC01"},"warning":"already_in_channel"}`}}, "join_channel", map[string]any{"channel": "C0PUBLIC01"})
	if err != nil || !res.Content.(slack.ChannelChange).Already {
		t.Errorf("already_in_channel: res=%+v err=%v", res, err)
	}
	_, err, _, _ = runWrite(t, map[string]route{"conversations.list": {body: `{"ok":true,"channels":[],"response_metadata":{"next_cursor":""}}`}}, "join_channel", map[string]any{"channel": "#nowhere"})
	wantClass(t, err, slack.ClassNotFound)
}

func TestLeaveChannel(t *testing.T) {
	res, err, _, _ := runWrite(t, map[string]route{"conversations.leave": {body: "ok.json"}}, "leave_channel", map[string]any{"channel": "C0ENGGEN01"})
	if err != nil || res.Content.(slack.ChannelChange).Action != "left" || res.Content.(slack.ChannelChange).Already {
		t.Errorf("leave: res=%+v err=%v", res, err)
	}
	res, err, _, _ = runWrite(t, map[string]route{"conversations.leave": {body: `{"ok":true,"not_in_channel":true}`}}, "leave_channel", map[string]any{"channel": "C0ENGGEN01"})
	if err != nil || !res.Content.(slack.ChannelChange).Already {
		t.Errorf("not_in_channel: res=%+v err=%v", res, err)
	}
	_, err, _, _ = runWrite(t, map[string]route{"conversations.leave": {body: `{"ok":false,"error":"cant_leave_general"}`}}, "leave_channel", map[string]any{"channel": "C0ENGGEN01"})
	wantClass(t, err, slack.ClassForbidden)
}

func TestJoinLeaveChecks(t *testing.T) {
	in := reconcile("join_channel", map[string]string{"channel_id": "C0PUBLIC01"})
	member := map[string]route{"conversations.info": {body: channelBody(`"id":"C0PUBLIC01","is_member":true`)}}
	notMember := map[string]route{"conversations.info": {body: channelBody(`"id":"C0PUBLIC01","is_member":false`)}}
	c, _ := newConnector(t, newAPIServer(t, member), slack.Options{})
	res, err := toolNamed(t, c, "join_channel").Reconcile.Check(context.Background(), in)
	wantFound(t, res, err, "C0PUBLIC01")
	res, err = toolNamed(t, c, "leave_channel").Reconcile.Check(context.Background(), in)
	wantNotFound(t, res, err)
	c2, _ := newConnector(t, newAPIServer(t, notMember), slack.Options{})
	res, err = toolNamed(t, c2, "leave_channel").Reconcile.Check(context.Background(), in)
	wantFound(t, res, err, "C0PUBLIC01")
	res, err = toolNamed(t, c2, "join_channel").Reconcile.Check(context.Background(), in)
	wantNotFound(t, res, err)
	// By name: resolved among public channels when the account is not a member.
	byName := reconcile("join_channel", map[string]string{"channel": "announcements", "channel_name": "announcements"})
	c3, _ := newConnector(t, newAPIServer(t, map[string]route{
		"users.conversations": {body: "users_conversations_empty.json"},
		"conversations.list":  {body: `{"ok":true,"channels":[{"id":"C0PUBLIC01","name":"announcements"}],"response_metadata":{"next_cursor":""}}`},
		"conversations.info":  {body: channelBody(`"id":"C0PUBLIC01","is_member":false`)},
	}), slack.Options{})
	res, err = toolNamed(t, c3, "join_channel").Reconcile.Check(context.Background(), byName)
	wantNotFound(t, res, err)
}

// --- invite / remove -------------------------------------------------------------------------

func TestInviteToChannel(t *testing.T) {
	res, err, srv, c := runWrite(t, map[string]route{"conversations.invite": {body: channelBody(`"id":"C0ENGGEN01"`)}},
		"invite_to_channel", map[string]any{"channel": "C0ENGGEN01", "users": []any{"U0BOB00001", "<@U0CAROL001>", "u0bob00001"}})
	if err != nil {
		t.Fatal(err)
	}
	got := res.Content.(slack.ChannelChange)
	if got.Channel != "C0ENGGEN01" || got.Action != "invited" || fmt.Sprint(got.Users) != "[U0BOB00001 U0CAROL001]" {
		t.Errorf("content = %+v", got)
	}
	if form := srv.Last(t, "conversations.invite").Form; form.Get("users") != "U0BOB00001,U0CAROL001" || form.Get("channel") != "C0ENGGEN01" {
		t.Errorf("form = %v", redactForm(form))
	}
	if ids := toolNamed(t, c, "invite_to_channel").ResultIDs(res); ids["users"] != "U0BOB00001,U0CAROL001" || ids["channel"] != "C0ENGGEN01" {
		t.Errorf("ResultIDs = %v", ids)
	}
	// Bad arguments: no users, not an array, a name, more than 30.
	many := make([]any, 31)
	for i := range many {
		many[i] = fmt.Sprintf("U0USER%04d", i)
	}
	for _, users := range []any{nil, []any{}, "U0BOB00001", []any{"bob"}, many} {
		_, err, srv, _ := runWrite(t, nil, "invite_to_channel", map[string]any{"channel": "C0ENGGEN01", "users": users})
		wantClass(t, err, slack.ClassInvalidArgument)
		if len(srv.Requests()) != 0 {
			t.Errorf("users %v: request sent", users)
		}
	}
	// already_in_channel is a success for a single user, a known failure for several.
	res, err, _, _ = runWrite(t, map[string]route{"conversations.invite": {body: `{"ok":false,"error":"already_in_channel"}`}}, "invite_to_channel", map[string]any{"channel": "C0ENGGEN01", "users": []any{"U0BOB00001"}})
	if err != nil || !res.Content.(slack.ChannelChange).Already {
		t.Errorf("already_in_channel (one user): res=%+v err=%v", res, err)
	}
	_, err, _, _ = runWrite(t, map[string]route{"conversations.invite": {body: `{"ok":false,"error":"already_in_channel"}`}}, "invite_to_channel", map[string]any{"channel": "C0ENGGEN01", "users": []any{"U0BOB00001", "U0CAROL001"}})
	wantClass(t, err, slack.ClassInvalidArgument)
	_, err, _, _ = runWrite(t, map[string]route{"conversations.invite": {body: `{"ok":false,"error":"cant_invite_self"}`}}, "invite_to_channel", map[string]any{"channel": "C0ENGGEN01", "users": []any{"U0ALICE001"}})
	wantClass(t, err, slack.ClassInvalidArgument)
}

func TestRemoveFromChannel(t *testing.T) {
	res, err, srv, c := runWrite(t, map[string]route{"conversations.kick": {body: "ok.json"}}, "remove_from_channel", map[string]any{"channel": "C0ENGGEN01", "user": "<@U0BOB00001>"})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Content.(slack.ChannelChange); got.Action != "removed" || got.User != "U0BOB00001" {
		t.Errorf("content = %+v", got)
	}
	if form := srv.Last(t, "conversations.kick").Form; form.Get("user") != "U0BOB00001" || form.Get("channel") != "C0ENGGEN01" {
		t.Errorf("form = %v", redactForm(form))
	}
	if ids := toolNamed(t, c, "remove_from_channel").ResultIDs(res); ids["user"] != "U0BOB00001" {
		t.Errorf("ResultIDs = %v", ids)
	}
	_, err, _, _ = runWrite(t, map[string]route{"conversations.kick": {body: `{"ok":false,"error":"cant_kick_self"}`}}, "remove_from_channel", map[string]any{"channel": "C0ENGGEN01", "user": "U0ALICE001"})
	wantClass(t, err, slack.ClassInvalidArgument)
	_, err, _, _ = runWrite(t, nil, "remove_from_channel", map[string]any{"channel": "C0ENGGEN01", "user": "bob"})
	wantClass(t, err, slack.ClassInvalidArgument)
}

func TestMembershipChecks(t *testing.T) {
	members := map[string]route{"conversations.members": {byCursor: map[string]route{
		"":      {body: `{"ok":true,"members":["U0ALICE001","U0BOB00001"],"response_metadata":{"next_cursor":"p2"}}`},
		"p2":    {body: `{"ok":true,"members":["U0CAROL001"],"response_metadata":{"next_cursor":""}}`},
		"other": {body: "{}"},
	}}}
	c, _ := newConnector(t, newAPIServer(t, members), slack.Options{})
	invite := toolNamed(t, c, "invite_to_channel").Reconcile.Check
	res, err := invite(context.Background(), reconcile("invite_to_channel", map[string]string{"channel_id": "C0ENGGEN01", "users": "U0BOB00001,U0CAROL001"}))
	wantFound(t, res, err, "C0ENGGEN01")
	res, err = invite(context.Background(), reconcile("invite_to_channel", map[string]string{"channel_id": "C0ENGGEN01", "users": "U0BOB00001,U0DAVE0001"}))
	wantNotFound(t, res, err)
	remove := toolNamed(t, c, "remove_from_channel").Reconcile.Check
	res, err = remove(context.Background(), reconcile("remove_from_channel", map[string]string{"channel_id": "C0ENGGEN01", "user": "U0DAVE0001"}))
	wantFound(t, res, err, "C0ENGGEN01")
	res, err = remove(context.Background(), reconcile("remove_from_channel", map[string]string{"channel_id": "C0ENGGEN01", "user": "U0CAROL001"}))
	wantNotFound(t, res, err)
	if _, err := remove(context.Background(), reconcile("remove_from_channel", map[string]string{"channel_id": "C0ENGGEN01"})); !errors.Is(err, slack.ErrNotReconcilable) {
		t.Errorf("no user: err = %v", err)
	}
	endless := map[string]route{"conversations.members": {body: `{"ok":true,"members":["U0ALICE001"],"response_metadata":{"next_cursor":"more"}}`}}
	c2, _ := newConnector(t, newAPIServer(t, endless), slack.Options{})
	if _, err := toolNamed(t, c2, "remove_from_channel").Reconcile.Check(context.Background(), reconcile("remove_from_channel", map[string]string{"channel_id": "C0ENGGEN01", "user": "U0DAVE0001"})); err == nil {
		t.Error("bounded member walk: want cannot tell yet")
	}
}

// Every new channel write maps an unreachable Slack to an unknown outcome
// and requires the ledger's operation id.
func TestChannelWritesShared(t *testing.T) {
	cases := map[string]struct {
		method string
		args   map[string]any
	}{
		"rename_channel":      {"conversations.rename", map[string]any{"channel": "C0ENGGEN01", "name": "x"}},
		"archive_channel":     {"conversations.archive", map[string]any{"channel": "C0ENGGEN01"}},
		"unarchive_channel":   {"conversations.unarchive", map[string]any{"channel": "C0ENGGEN01"}},
		"set_channel_topic":   {"conversations.setTopic", map[string]any{"channel": "C0ENGGEN01", "topic": "t"}},
		"set_channel_purpose": {"conversations.setPurpose", map[string]any{"channel": "C0ENGGEN01", "purpose": "p"}},
		"join_channel":        {"conversations.join", map[string]any{"channel": "C0ENGGEN01"}},
		"leave_channel":       {"conversations.leave", map[string]any{"channel": "C0ENGGEN01"}},
		"invite_to_channel":   {"conversations.invite", map[string]any{"channel": "C0ENGGEN01", "users": []any{"U0BOB00001"}}},
		"remove_from_channel": {"conversations.kick", map[string]any{"channel": "C0ENGGEN01", "user": "U0BOB00001"}},
	}
	for tool, tc := range cases {
		t.Run(tool, func(t *testing.T) {
			_, err, _, _ := runWrite(t, map[string]route{tc.method: {status: 502}}, tool, tc.args)
			if !errors.Is(err, connectors.ErrOutcomeUnknown) {
				t.Errorf("502: err = %v, want ErrOutcomeUnknown", err)
			}
			_, err, _, _ = runWrite(t, map[string]route{tc.method: {body: "error_channel_not_found.json"}}, tool, tc.args)
			wantClass(t, err, slack.ClassNotFound)
			srv := newAPIServer(t, nil)
			c, _ := newConnector(t, srv, slack.Options{})
			if _, err := c.Call(context.Background(), call(tool, tc.args)); !errors.Is(err, slack.ErrMissingOperation) {
				t.Errorf("without an operation id: %v", err)
			}
		})
	}
}
