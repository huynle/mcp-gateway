package slack_test

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/slack"
)

func TestProfileToolsMetadata(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), slack.Options{})
	w, r, s := connectors.KindWrite, connectors.KindRead, connectors.ReconcileStableID
	checkToolCases(t, c, []toolCase{
		{tool: "set_status", kind: w, rec: s, scopes: []string{"users.profile:write"}, props: []string{"text", "emoji", "expiration"},
			args:     map[string]any{"text": "secret meeting", "emoji": "calendar", "expiration": 30},
			identity: map[string]string{"status_text_sha256": sha("secret meeting"), "status_emoji": ":calendar:"}},
		{tool: "clear_status", kind: w, rec: s, scopes: []string{"users.profile:write"}, props: []string{}, args: map[string]any{}, identity: map[string]string{}},
		{tool: "get_dnd", kind: r, scopes: []string{"dnd:read"}, props: []string{}, args: map[string]any{}, identity: map[string]string{}},
		{tool: "set_dnd", kind: w, rec: s, scopes: []string{"dnd:write"}, required: []string{"minutes"}, props: []string{"minutes"},
			args: map[string]any{"minutes": 60}, identity: map[string]string{"minutes": "60"}},
		{tool: "end_dnd", kind: w, rec: s, scopes: []string{"dnd:write"}, props: []string{}, args: map[string]any{}, identity: map[string]string{}},
	})
}

func TestSetStatus(t *testing.T) {
	res, err, srv, c := runWrite(t, map[string]route{"users.profile.set": {body: "ok.json"}}, "set_status",
		map[string]any{"text": "In a meeting", "emoji": ":calendar:", "expiration": "2030-01-02T03:04:05Z"})
	if err != nil {
		t.Fatal(err)
	}
	got := res.Content.(slack.Status)
	if got.Text != "In a meeting" || got.Emoji != ":calendar:" || got.Expiration != "2030-01-02T03:04:05Z" || got.Action != "set" {
		t.Errorf("content = %+v", got)
	}
	profile := srv.Last(t, "users.profile.set").Form.Get("profile")
	if profile != `{"status_text":"In a meeting","status_emoji":":calendar:","status_expiration":1893553445}` {
		t.Errorf("profile = %s", profile)
	}
	if ids := toolNamed(t, c, "set_status").ResultIDs(res); ids["status"] != "set" {
		t.Errorf("ResultIDs = %v", ids)
	}
	// Minutes from now.
	before := time.Now().Add(30 * time.Minute).Unix()
	res, err, _, _ = runWrite(t, map[string]route{"users.profile.set": {body: "ok.json"}}, "set_status", map[string]any{"text": "Lunch", "expiration": 30})
	if err != nil {
		t.Fatal(err)
	}
	exp, perr := time.Parse(time.RFC3339, res.Content.(slack.Status).Expiration)
	if perr != nil || exp.Unix() < before-1 || exp.Unix() > before+5 {
		t.Errorf("expiration = %q, want ~30 minutes from now", res.Content.(slack.Status).Expiration)
	}
	for name, args := range map[string]map[string]any{
		"nothing":        {},
		"bad emoji":      {"text": "x", "emoji": "not an emoji!"},
		"bad expiration": {"text": "x", "expiration": "later"},
		"neg minutes":    {"text": "x", "expiration": -1},
		"too long":       {"text": string(make([]byte, 101))},
	} {
		_, err, srv, _ := runWrite(t, nil, "set_status", args)
		if wantClassOK(err, slack.ClassInvalidArgument) == false || len(srv.Requests()) != 0 {
			t.Errorf("%s: err = %v, requests = %d", name, err, len(srv.Requests()))
		}
	}
	_, err, _, _ = runWrite(t, map[string]route{"users.profile.set": {body: "error_fatal.json"}}, "set_status", map[string]any{"text": "x"})
	if !errors.Is(err, connectors.ErrOutcomeUnknown) {
		t.Errorf("fatal: %v", err)
	}
}

func wantClassOK(err error, class string) bool {
	var se *slack.Error
	return errors.As(err, &se) && se.Class == class
}

func TestClearStatus(t *testing.T) {
	res, err, srv, c := runWrite(t, map[string]route{"users.profile.set": {body: "ok.json"}}, "clear_status", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Content.(slack.Status); got.Action != "cleared" {
		t.Errorf("content = %+v", got)
	}
	if p := srv.Last(t, "users.profile.set").Form.Get("profile"); p != `{"status_text":"","status_emoji":"","status_expiration":0}` {
		t.Errorf("profile = %s", p)
	}
	if ids := toolNamed(t, c, "clear_status").ResultIDs(res); ids["status"] != "cleared" {
		t.Errorf("ResultIDs = %v", ids)
	}
}

func usersInfoStatus(text, emoji string) route {
	return route{body: `{"ok":true,"user":{"id":"U0ALICE001","profile":{"status_text":"` + text + `","status_emoji":"` + emoji + `"}}}`}
}

func TestStatusChecks(t *testing.T) {
	set := reconcile("set_status", map[string]string{"status_text_sha256": sha("In a meeting"), "status_emoji": ":calendar:"})
	for _, tc := range []struct {
		name, text, emoji string
		tool              string
		in                connectors.ReconcileInput
		found             bool
	}{
		{"set: matches", "In a meeting", ":calendar:", "set_status", set, true},
		{"set: other text", "Lunch", ":calendar:", "set_status", set, false},
		{"set: other emoji", "In a meeting", ":pizza:", "set_status", set, false},
		{"clear: empty", "", "", "clear_status", reconcile("clear_status", map[string]string{}), true},
		{"clear: still set", "Lunch", "", "clear_status", reconcile("clear_status", map[string]string{}), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"auth.test": {body: "auth_test_user.json"}, "users.info": usersInfoStatus(tc.text, tc.emoji)})
			c, _ := newConnector(t, srv, slack.Options{})
			res, err := toolNamed(t, c, tc.tool).Reconcile.Check(context.Background(), tc.in)
			if tc.found {
				wantFound(t, res, err, "U0ALICE001")
			} else {
				wantNotFound(t, res, err)
			}
			if srv.Last(t, "users.info").Form.Get("user") != "U0ALICE001" {
				t.Error("users.info not asked for the account's own user")
			}
		})
	}
	c, _ := newConnector(t, newAPIServer(t, nil), slack.Options{})
	if _, err := toolNamed(t, c, "set_status").Reconcile.Check(context.Background(), reconcile("set_status", map[string]string{})); !errors.Is(err, slack.ErrNotReconcilable) {
		t.Errorf("no hash: %v", err)
	}
}

const dndInfo = `{"ok":true,"dnd_enabled":true,"next_dnd_start_ts":1893553445,"next_dnd_end_ts":1893582245,"snooze_enabled":true,"snooze_endtime":1893553445,"snooze_remaining":1200}`

func TestGetDND(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"dnd.info": {body: dndInfo}})
	c, _ := newConnector(t, srv, slack.Options{})
	res, err := c.Call(context.Background(), call("get_dnd", nil))
	if err != nil {
		t.Fatal(err)
	}
	var got slack.DND
	decode(t, res, &got)
	if !got.DNDEnabled || !got.SnoozeEnabled || got.SnoozeEnd != "2030-01-02T03:04:05Z" || got.SnoozeRemainingSeconds != 1200 || got.NextStart != "2030-01-02T03:04:05Z" {
		t.Errorf("dnd = %+v", got)
	}
	if srv.Last(t, "dnd.info").Form.Has("user") {
		t.Error("dnd.info asked for another user")
	}
}

func TestSetAndEndDND(t *testing.T) {
	res, err, srv, c := runWrite(t, map[string]route{"dnd.setSnooze": {body: `{"ok":true,"snooze_enabled":true,"snooze_endtime":1893553445,"snooze_remaining":3600}`}}, "set_dnd", map[string]any{"minutes": 60})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Content.(slack.DND); !got.SnoozeEnabled || got.SnoozeEnd != "2030-01-02T03:04:05Z" || got.Action != "snoozed" {
		t.Errorf("content = %+v", got)
	}
	if srv.Last(t, "dnd.setSnooze").Form.Get("num_minutes") != "60" {
		t.Error("num_minutes not sent")
	}
	if ids := toolNamed(t, c, "set_dnd").ResultIDs(res); ids["snooze_end"] != "2030-01-02T03:04:05Z" {
		t.Errorf("ResultIDs = %v", ids)
	}
	for _, m := range []any{0, -1, 1.5, "soon", slack.MaxSnoozeMinutes + 1} {
		_, err, srv, _ := runWrite(t, nil, "set_dnd", map[string]any{"minutes": m})
		if !wantClassOK(err, slack.ClassInvalidArgument) || len(srv.Requests()) != 0 {
			t.Errorf("minutes %v: err = %v", m, err)
		}
	}
	res, err, _, c = runWrite(t, map[string]route{"dnd.endSnooze": {body: `{"ok":true,"dnd_enabled":true,"snooze_enabled":false}`}}, "end_dnd", nil)
	if err != nil || res.Content.(slack.DND).SnoozeEnabled || res.Content.(slack.DND).Action != "ended" {
		t.Errorf("end_dnd: res=%+v err=%v", res, err)
	}
	if ids := toolNamed(t, c, "end_dnd").ResultIDs(res); ids["dnd"] != "ended" {
		t.Errorf("ResultIDs = %v", ids)
	}
	res, err, _, _ = runWrite(t, map[string]route{"dnd.endSnooze": {body: `{"ok":false,"error":"snooze_not_active"}`}}, "end_dnd", nil)
	if err != nil || !res.Content.(slack.DND).Already {
		t.Errorf("snooze_not_active: res=%+v err=%v", res, err)
	}
}

func TestDNDChecks(t *testing.T) {
	on := map[string]route{"dnd.info": {body: dndInfo}}
	off := map[string]route{"dnd.info": {body: `{"ok":true,"dnd_enabled":true,"snooze_enabled":false}`}}
	for _, tc := range []struct {
		tool   string
		routes map[string]route
		found  bool
	}{
		{"set_dnd", on, true}, {"set_dnd", off, false}, {"end_dnd", off, true}, {"end_dnd", on, false},
	} {
		c, _ := newConnector(t, newAPIServer(t, tc.routes), slack.Options{})
		res, err := toolNamed(t, c, tc.tool).Reconcile.Check(context.Background(), reconcile(tc.tool, map[string]string{"minutes": strconv.Itoa(60)}))
		if tc.found {
			wantFound(t, res, err, "dnd")
		} else {
			wantNotFound(t, res, err)
		}
	}
	c, _ := newConnector(t, newAPIServer(t, map[string]route{"dnd.info": {body: "error_missing_scope.json"}}), slack.Options{})
	if _, err := toolNamed(t, c, "set_dnd").Reconcile.Check(context.Background(), reconcile("set_dnd", nil)); err == nil {
		t.Error("missing_scope: want cannot tell yet")
	}
}
