package slack_test

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/slack"
)

const msgTS = "1700003000.000200"

func TestMessageToolsMetadata(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), slack.Options{})
	w, r := connectors.KindWrite, connectors.KindRead
	chat, pinsW, pinsR := []string{"chat:write"}, []string{"pins:write"}, []string{"pins:read"}
	with := func(extra map[string]string) map[string]string {
		out := map[string]string{"channel": "C0ENGGEN01", "channel_id": "C0ENGGEN01"}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}
	checkToolCases(t, c, []toolCase{
		{tool: "update_message", kind: w, rec: connectors.ReconcileNone, scopes: chat, required: []string{"channel", "ts", "text"}, props: []string{"channel", "ts", "text"},
			args: map[string]any{"channel": "C0ENGGEN01", "ts": msgTS, "text": "secret"}, identity: with(map[string]string{"ts": msgTS})},
		{tool: "delete_message", kind: w, rec: connectors.ReconcileStableID, scopes: chat, required: []string{"channel", "ts"}, props: []string{"channel", "ts"},
			args: map[string]any{"channel": "C0ENGGEN01", "ts": msgTS}, identity: with(map[string]string{"ts": msgTS})},
		{tool: "schedule_message", kind: w, rec: connectors.ReconcileNone, scopes: chat, required: []string{"channel", "text", "post_at"}, props: []string{"channel", "text", "post_at", "thread_ts"},
			args:     map[string]any{"channel": "C0ENGGEN01", "text": "secret", "post_at": "2030-01-02T03:04:05Z", "thread_ts": msgTS},
			identity: with(map[string]string{"post_at": "1893553445", "thread_ts": msgTS})},
		{tool: "list_scheduled_messages", kind: r, scopes: chat, props: []string{"channel", "limit", "cursor"},
			args: map[string]any{"channel": "C0ENGGEN01"}, identity: with(nil)},
		{tool: "delete_scheduled_message", kind: w, rec: connectors.ReconcileNone, scopes: chat, required: []string{"channel", "scheduled_message_id"}, props: []string{"channel", "scheduled_message_id"},
			args: map[string]any{"channel": "C0ENGGEN01", "scheduled_message_id": "Q1298393284"}, identity: with(map[string]string{"scheduled_message_id": "Q1298393284"})},
		{tool: "pin_message", kind: w, rec: connectors.ReconcileStableID, scopes: pinsW, required: []string{"channel", "timestamp"}, props: []string{"channel", "timestamp"},
			args: map[string]any{"channel": "C0ENGGEN01", "timestamp": msgTS}, identity: with(map[string]string{"timestamp": msgTS})},
		{tool: "unpin_message", kind: w, rec: connectors.ReconcileStableID, scopes: pinsW, required: []string{"channel", "timestamp"}, props: []string{"channel", "timestamp"},
			args: map[string]any{"channel": "C0ENGGEN01", "timestamp": msgTS}, identity: with(map[string]string{"timestamp": msgTS})},
		{tool: "list_pins", kind: r, scopes: pinsR, required: []string{"channel"}, props: []string{"channel"},
			args: map[string]any{"channel": "C0ENGGEN01"}, identity: with(nil)},
	})
}

// --- update / delete ----------------------------------------------------------------

func TestUpdateMessage(t *testing.T) {
	res, err, srv, c := runWrite(t, map[string]route{"chat.update": {body: `{"ok":true,"channel":"C0ENGGEN01","ts":"` + msgTS + `","text":"fixed"}`}},
		"update_message", map[string]any{"channel": "C0ENGGEN01", "ts": msgTS, "text": "fixed"})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Content.(slack.MessageChange); got.Channel != "C0ENGGEN01" || got.TS != msgTS || got.Action != "updated" {
		t.Errorf("content = %+v", got)
	}
	if form := srv.Last(t, "chat.update").Form; form.Get("ts") != msgTS || form.Get("text") != "fixed" || form.Get("channel") != "C0ENGGEN01" {
		t.Errorf("form = %v", redactForm(form))
	}
	if ids := toolNamed(t, c, "update_message").ResultIDs(res); ids["channel"] != "C0ENGGEN01" || ids["ts"] != msgTS {
		t.Errorf("ResultIDs = %v", ids)
	}
	for code, class := range map[string]string{"cant_update_message": slack.ClassForbidden, "edit_window_closed": slack.ClassForbidden, "message_not_found": slack.ClassNotFound, "msg_too_long": slack.ClassInvalidArgument} {
		_, err, _, _ := runWrite(t, map[string]route{"chat.update": {body: `{"ok":false,"error":"` + code + `"}`}}, "update_message", map[string]any{"channel": "C0ENGGEN01", "ts": msgTS, "text": "x"})
		wantClass(t, err, class)
	}
	_, err, _, _ = runWrite(t, map[string]route{"chat.update": {status: 500}}, "update_message", map[string]any{"channel": "C0ENGGEN01", "ts": msgTS, "text": "x"})
	if !errors.Is(err, connectors.ErrOutcomeUnknown) {
		t.Errorf("500: %v", err)
	}
	_, err, _, _ = runWrite(t, nil, "update_message", map[string]any{"channel": "C0ENGGEN01", "ts": "yesterday", "text": "x"})
	wantClass(t, err, slack.ClassInvalidArgument)
}

func TestDeleteMessage(t *testing.T) {
	res, err, srv, c := runWrite(t, map[string]route{
		"users.conversations": {body: "users_conversations_page1.json"},
		"chat.delete":         {body: `{"ok":true,"channel":"C0ENGGEN01","ts":"` + msgTS + `"}`},
	}, "delete_message", map[string]any{"channel": "#eng-general", "ts": msgTS})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Content.(slack.MessageChange); got.Channel != "C0ENGGEN01" || got.TS != msgTS || got.Action != "deleted" {
		t.Errorf("content = %+v", got)
	}
	if form := srv.Last(t, "chat.delete").Form; form.Get("ts") != msgTS || form.Get("channel") != "C0ENGGEN01" {
		t.Errorf("form = %v", redactForm(form))
	}
	if ids := toolNamed(t, c, "delete_message").ResultIDs(res); ids["ts"] != msgTS {
		t.Errorf("ResultIDs = %v", ids)
	}
	_, err, _, _ = runWrite(t, map[string]route{"chat.delete": {body: `{"ok":false,"error":"cant_delete_message"}`}}, "delete_message", map[string]any{"channel": "C0ENGGEN01", "ts": msgTS})
	wantClass(t, err, slack.ClassForbidden)
}

func TestDeleteMessageCheck(t *testing.T) {
	in := reconcile("delete_message", map[string]string{"channel_id": "C0ENGGEN01", "ts": msgTS})
	cases := []struct {
		name  string
		rt    route
		found bool
		err   bool
	}{
		{"still there", route{body: `{"ok":true,"messages":[{"type":"message","ts":"` + msgTS + `","text":"hi"}],"has_more":false}`}, false, false},
		{"tombstone", route{body: `{"ok":true,"messages":[{"type":"message","subtype":"tombstone","ts":"` + msgTS + `","text":"This message was deleted."}],"has_more":false}`}, true, false},
		{"gone", route{body: "error_message_not_found.json"}, true, false},
		{"thread gone", route{body: "error_thread_not_found.json"}, true, false},
		{"other message", route{body: `{"ok":true,"messages":[{"type":"message","ts":"1700009999.000100"}],"has_more":false}`}, true, false},
		{"channel gone", route{body: "error_channel_not_found.json"}, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"conversations.replies": tc.rt})
			c, _ := newConnector(t, srv, slack.Options{})
			res, err := toolNamed(t, c, "delete_message").Reconcile.Check(context.Background(), in)
			switch {
			case tc.err:
				if err == nil {
					t.Errorf("want cannot tell yet, got %+v", res)
				}
			case tc.found:
				wantFound(t, res, err, msgTS)
			default:
				wantNotFound(t, res, err)
			}
			if f := srv.Last(t, "conversations.replies").Form; f.Get("ts") != msgTS || f.Get("channel") != "C0ENGGEN01" {
				t.Errorf("form = %v", redactForm(f))
			}
		})
	}
	c, _ := newConnector(t, newAPIServer(t, nil), slack.Options{})
	if _, err := toolNamed(t, c, "delete_message").Reconcile.Check(context.Background(), reconcile("delete_message", map[string]string{"channel_id": "C0ENGGEN01"})); !errors.Is(err, slack.ErrNotReconcilable) {
		t.Errorf("no ts: %v", err)
	}
}

// --- scheduled messages -------------------------------------------------------------------

func TestScheduleMessage(t *testing.T) {
	routes := map[string]route{"chat.scheduleMessage": {body: `{"ok":true,"channel":"C0ENGGEN01","scheduled_message_id":"Q1298393284","post_at":1893553445}`}}
	res, err, srv, c := runWrite(t, routes, "schedule_message", map[string]any{"channel": "C0ENGGEN01", "text": "Standup!", "post_at": "2030-01-02T03:04:05Z", "thread_ts": msgTS})
	if err != nil {
		t.Fatal(err)
	}
	got := res.Content.(slack.ScheduledMessage)
	if got.Channel != "C0ENGGEN01" || got.ID != "Q1298393284" || got.PostAt != "2030-01-02T03:04:05Z" || got.ThreadTS != msgTS {
		t.Errorf("content = %+v", got)
	}
	form := srv.Last(t, "chat.scheduleMessage").Form
	if form.Get("post_at") != "1893553445" || form.Get("text") != "Standup!" || form.Get("thread_ts") != msgTS || form.Get("channel") != "C0ENGGEN01" {
		t.Errorf("form = %v", redactForm(form))
	}
	if ids := toolNamed(t, c, "schedule_message").ResultIDs(res); ids["scheduled_message_id"] != "Q1298393284" || ids["channel"] != "C0ENGGEN01" {
		t.Errorf("ResultIDs = %v", ids)
	}
	// Unix seconds as a number or a numeric string.
	future := time.Now().Add(time.Hour).Unix()
	for _, at := range []any{float64(future), strconv.FormatInt(future, 10)} {
		_, err, srv, _ := runWrite(t, routes, "schedule_message", map[string]any{"channel": "C0ENGGEN01", "text": "x", "post_at": at})
		if err != nil || srv.Last(t, "chat.scheduleMessage").Form.Get("post_at") != strconv.FormatInt(future, 10) {
			t.Errorf("post_at %v: err = %v", at, err)
		}
	}
	for _, at := range []any{nil, "tomorrow", "2030-01-02", -5, true} {
		_, err, srv, _ := runWrite(t, nil, "schedule_message", map[string]any{"channel": "C0ENGGEN01", "text": "x", "post_at": at})
		wantClass(t, err, slack.ClassInvalidArgument)
		if len(srv.Requests()) != 0 {
			t.Errorf("post_at %v: request sent", at)
		}
	}
	for _, code := range []string{"time_in_past", "time_too_far", "invalid_time"} {
		_, err, _, _ := runWrite(t, map[string]route{"chat.scheduleMessage": {body: `{"ok":false,"error":"` + code + `"}`}}, "schedule_message", map[string]any{"channel": "C0ENGGEN01", "text": "x", "post_at": "2030-01-02T03:04:05Z"})
		wantClass(t, err, slack.ClassInvalidArgument)
	}
}

func TestListScheduledMessages(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"chat.scheduledMessages.list": {body: `{"ok":true,"scheduled_messages":[` +
		`{"id":"Q1298393284","channel_id":"C0ENGGEN01","post_at":1893553445,"date_created":1700000000,"text":"Standup!"}],` +
		`"response_metadata":{"next_cursor":"next1"}}`}})
	c, _ := newConnector(t, srv, slack.Options{})
	res, err := c.Call(context.Background(), call("list_scheduled_messages", map[string]any{"channel": "C0ENGGEN01", "limit": 10}))
	if err != nil {
		t.Fatal(err)
	}
	var page slack.ScheduledPage
	decode(t, res, &page)
	if len(page.Messages) != 1 || page.Messages[0].ID != "Q1298393284" || page.Messages[0].PostAt != "2030-01-02T03:04:05Z" ||
		page.Messages[0].Text != "Standup!" || page.NextCursor != "next1" || !page.HasMore {
		t.Errorf("page = %+v", page)
	}
	if f := srv.Last(t, "chat.scheduledMessages.list").Form; f.Get("channel") != "C0ENGGEN01" || f.Get("limit") != "10" {
		t.Errorf("form = %v", redactForm(f))
	}
	// Without a channel: every channel's scheduled messages; empty marks Empty.
	srv2 := newAPIServer(t, map[string]route{"chat.scheduledMessages.list": {body: `{"ok":true,"scheduled_messages":[],"response_metadata":{"next_cursor":""}}`}})
	c2, _ := newConnector(t, srv2, slack.Options{})
	res, err = c2.Call(context.Background(), call("list_scheduled_messages", nil))
	if err != nil || !res.Empty {
		t.Errorf("empty: res=%+v err=%v", res, err)
	}
	if f := srv2.Last(t, "chat.scheduledMessages.list").Form; f.Has("channel") {
		t.Errorf("channel sent without one: %v", redactForm(f))
	}
	srv3 := newAPIServer(t, map[string]route{"chat.scheduledMessages.list": {status: 503}})
	c3, _ := newConnector(t, srv3, slack.Options{})
	if res, err := c3.Call(context.Background(), call("list_scheduled_messages", nil)); err != nil || !res.Unavailable {
		t.Errorf("503: res=%+v err=%v, want unavailable", res, err)
	}
}

func TestDeleteScheduledMessage(t *testing.T) {
	res, err, srv, c := runWrite(t, map[string]route{"chat.deleteScheduledMessage": {body: "ok.json"}},
		"delete_scheduled_message", map[string]any{"channel": "C0ENGGEN01", "scheduled_message_id": "Q1298393284"})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Content.(slack.ScheduledMessage); got.ID != "Q1298393284" || got.Channel != "C0ENGGEN01" || got.Action != "deleted" {
		t.Errorf("content = %+v", got)
	}
	if f := srv.Last(t, "chat.deleteScheduledMessage").Form; f.Get("scheduled_message_id") != "Q1298393284" || f.Get("channel") != "C0ENGGEN01" {
		t.Errorf("form = %v", redactForm(f))
	}
	if ids := toolNamed(t, c, "delete_scheduled_message").ResultIDs(res); ids["scheduled_message_id"] != "Q1298393284" {
		t.Errorf("ResultIDs = %v", ids)
	}
	_, err, _, _ = runWrite(t, map[string]route{"chat.deleteScheduledMessage": {body: `{"ok":false,"error":"invalid_scheduled_message_id"}`}},
		"delete_scheduled_message", map[string]any{"channel": "C0ENGGEN01", "scheduled_message_id": "Q1298393284"})
	wantClass(t, err, slack.ClassNotFound)
	_, err, _, _ = runWrite(t, nil, "delete_scheduled_message", map[string]any{"channel": "C0ENGGEN01", "scheduled_message_id": "not an id"})
	wantClass(t, err, slack.ClassInvalidArgument)
}

// --- pins -------------------------------------------------------------------------------

func TestPinAndUnpin(t *testing.T) {
	res, err, srv, c := runWrite(t, map[string]route{"pins.add": {body: "ok.json"}}, "pin_message", map[string]any{"channel": "C0ENGGEN01", "timestamp": msgTS})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Content.(slack.PinChange); got.Channel != "C0ENGGEN01" || got.Timestamp != msgTS || got.Action != "pinned" || got.Already {
		t.Errorf("content = %+v", got)
	}
	if f := srv.Last(t, "pins.add").Form; f.Get("channel") != "C0ENGGEN01" || f.Get("timestamp") != msgTS {
		t.Errorf("form = %v", redactForm(f))
	}
	if ids := toolNamed(t, c, "pin_message").ResultIDs(res); ids["timestamp"] != msgTS || ids["channel"] != "C0ENGGEN01" {
		t.Errorf("ResultIDs = %v", ids)
	}
	res, err, _, _ = runWrite(t, map[string]route{"pins.add": {body: `{"ok":false,"error":"already_pinned"}`}}, "pin_message", map[string]any{"channel": "C0ENGGEN01", "timestamp": msgTS})
	if err != nil || !res.Content.(slack.PinChange).Already {
		t.Errorf("already_pinned: res=%+v err=%v", res, err)
	}
	res, err, _, _ = runWrite(t, map[string]route{"pins.remove": {body: "ok.json"}}, "unpin_message", map[string]any{"channel": "C0ENGGEN01", "timestamp": msgTS})
	if err != nil || res.Content.(slack.PinChange).Action != "unpinned" {
		t.Errorf("unpin: res=%+v err=%v", res, err)
	}
	for _, code := range []string{"not_pinned", "no_pin"} {
		res, err, _, _ = runWrite(t, map[string]route{"pins.remove": {body: `{"ok":false,"error":"` + code + `"}`}}, "unpin_message", map[string]any{"channel": "C0ENGGEN01", "timestamp": msgTS})
		if err != nil || !res.Content.(slack.PinChange).Already {
			t.Errorf("%s: res=%+v err=%v", code, res, err)
		}
	}
	_, err, _, _ = runWrite(t, map[string]route{"pins.add": {body: `{"ok":false,"error":"too_many_pins"}`}}, "pin_message", map[string]any{"channel": "C0ENGGEN01", "timestamp": msgTS})
	wantClass(t, err, slack.ClassInvalidArgument)
	_, err, _, _ = runWrite(t, map[string]route{"pins.add": {body: "error_fatal.json"}}, "pin_message", map[string]any{"channel": "C0ENGGEN01", "timestamp": msgTS})
	if !errors.Is(err, connectors.ErrOutcomeUnknown) {
		t.Errorf("fatal: %v", err)
	}
}

const pinsBody = `{"ok":true,"items":[` +
	`{"type":"message","channel":"C0ENGGEN01","created":1700005000,"created_by":"U0ALICE001","message":{"type":"message","ts":"` + msgTS + `","user":"U0BOB00001","text":"Deploy checklist"}},` +
	`{"type":"file","channel":"C0ENGGEN01","created":1700005100,"file":{"id":"F0FILE0001","name":"runbook.pdf","title":"Runbook"}}]}`

func TestPinChecks(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, map[string]route{"pins.list": {body: pinsBody}}), slack.Options{})
	pinned := reconcile("pin_message", map[string]string{"channel_id": "C0ENGGEN01", "timestamp": msgTS})
	other := reconcile("pin_message", map[string]string{"channel_id": "C0ENGGEN01", "timestamp": "1700009999.000100"})
	res, err := toolNamed(t, c, "pin_message").Reconcile.Check(context.Background(), pinned)
	wantFound(t, res, err, msgTS)
	res, err = toolNamed(t, c, "pin_message").Reconcile.Check(context.Background(), other)
	wantNotFound(t, res, err)
	res, err = toolNamed(t, c, "unpin_message").Reconcile.Check(context.Background(), other)
	wantFound(t, res, err, "1700009999.000100")
	res, err = toolNamed(t, c, "unpin_message").Reconcile.Check(context.Background(), pinned)
	wantNotFound(t, res, err)
	if _, err := toolNamed(t, c, "pin_message").Reconcile.Check(context.Background(), reconcile("pin_message", map[string]string{"channel_id": "C0ENGGEN01"})); !errors.Is(err, slack.ErrNotReconcilable) {
		t.Errorf("no timestamp: %v", err)
	}
}

func TestListPins(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"pins.list": {body: pinsBody}})
	c, _ := newConnector(t, srv, slack.Options{})
	res, err := c.Call(context.Background(), call("list_pins", map[string]any{"channel": "C0ENGGEN01"}))
	if err != nil {
		t.Fatal(err)
	}
	var page slack.PinsPage
	decode(t, res, &page)
	if page.Channel != "C0ENGGEN01" || len(page.Pins) != 2 {
		t.Fatalf("page = %+v", page)
	}
	if p := page.Pins[0]; p.Type != "message" || p.TS != msgTS || p.User != "U0BOB00001" || p.Text != "Deploy checklist" || p.Time == "" {
		t.Errorf("message pin = %+v", p)
	}
	if p := page.Pins[1]; p.Type != "file" || p.FileID != "F0FILE0001" || p.FileName != "runbook.pdf" || p.Title != "Runbook" {
		t.Errorf("file pin = %+v", p)
	}
	srv2 := newAPIServer(t, map[string]route{"pins.list": {body: `{"ok":true,"items":[]}`}})
	c2, _ := newConnector(t, srv2, slack.Options{})
	if res, err := c2.Call(context.Background(), call("list_pins", map[string]any{"channel": "C0ENGGEN01"})); err != nil || !res.Empty {
		t.Errorf("empty: res=%+v err=%v", res, err)
	}
	srv3 := newAPIServer(t, map[string]route{"pins.list": {body: "error_missing_scope.json"}})
	c3, _ := newConnector(t, srv3, slack.Options{})
	_, err = c3.Call(context.Background(), call("list_pins", map[string]any{"channel": "C0ENGGEN01"}))
	wantClass(t, err, slack.ClassForbidden)
}

func TestListPinsTruncated(t *testing.T) {
	items := ""
	for i := 0; i < 50; i++ {
		if i > 0 {
			items += ","
		}
		items += fmt.Sprintf(`{"type":"message","channel":"C0ENGGEN01","message":{"ts":"1700003000.%06d","text":"%0200d"}}`, i, i)
	}
	srv := newAPIServer(t, map[string]route{"pins.list": {body: `{"ok":true,"items":[` + items + `]}`}})
	c, _ := newConnector(t, srv, slack.Options{Bounds: connectors.Bounds{MaxResultBytes: 2048}})
	res, err := c.Call(context.Background(), call("list_pins", map[string]any{"channel": "C0ENGGEN01"}))
	if err != nil {
		t.Fatal(err)
	}
	var page slack.PinsPage
	decode(t, res, &page)
	if !res.Partial || !page.Truncated || len(page.Pins) == 0 || len(page.Pins) >= 50 {
		t.Errorf("partial=%v truncated=%v pins=%d", res.Partial, page.Truncated, len(page.Pins))
	}
}
