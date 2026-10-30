package google_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

// Increment 4: the Workspace-only event types (out of office, working
// location, focus time) on the primary calendar.

var workspaceEventTools = []string{"calendar.set_out_of_office", "calendar.set_working_location", "calendar.create_focus_time"}

func TestWorkspaceEventDeclarations(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	for _, full := range workspaceEventTools {
		tool := declared(t, c, full, connectors.KindWrite, []string{google.ScopeCalendarEvents}, connectors.ReconcileStableID)
		id := tool.ResourceIdentity(map[string]any{
			"summary": "secret", "decline_message": "secret", "label": "secret", "start": "2026-10-12T09:00:00Z", "end": "2026-10-12T10:00:00Z",
		})
		if id["calendar_id"] != "primary" || len(id) != 1 {
			t.Errorf("%s identity = %v, want only calendar_id primary (never the text)", full, id)
		}
		if !strings.Contains(tool.Description, "Google Workspace") {
			t.Errorf("%s description does not say it is Google Workspace only: %q", full, tool.Description)
		}
	}
}

func TestSetOutOfOffice(t *testing.T) {
	srv := newAPIServer(t, map[string]route{createEventPath: {status: 200, body: "created_out_of_office.json"}})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("calendar.set_out_of_office", map[string]any{
		"start": "2026-10-12T00:00:00-07:00", "end": "2026-10-17T00:00:00-07:00", "time_zone": "America/Los_Angeles",
		"decline_message": "Away this week.",
	}))
	if err != nil {
		t.Fatalf("set_out_of_office: %v", err)
	}
	if len(tk.calls) != 1 {
		t.Errorf("token calls = %v", tk.calls)
	}
	req := srv.Last(t, createEventPath)
	body := bodyOf(t, req)
	if body["id"] != wantEventID || body["eventType"] != "outOfOffice" || body["summary"] != "Out of office" {
		t.Errorf("body = %s, want the derived id, eventType outOfOffice and the default summary", req.Body)
	}
	props, _ := body["outOfOfficeProperties"].(map[string]any)
	if props["autoDeclineMode"] != "declineAllConflictingInvitations" || props["declineMessage"] != "Away this week." {
		t.Errorf("outOfOfficeProperties = %v, want the all_conflicting default and the message", props)
	}
	start, _ := body["start"].(map[string]any)
	if start["dateTime"] != "2026-10-12T00:00:00-07:00" || start["timeZone"] != "America/Los_Angeles" {
		t.Errorf("start = %v", start)
	}
	if got := req.URL.Query().Get("sendUpdates"); got != "" && got != "none" {
		t.Errorf("sendUpdates = %q", got)
	}
	created, ok := res.Content.(google.CreatedEvent)
	if !ok || created.ID != wantEventID || created.EventType != "outOfOffice" || created.CalendarID != "primary" {
		t.Errorf("content = %#v", res.Content)
	}
	if ids := toolOf(t, c, "calendar.set_out_of_office").ResultIDs(res); ids["id"] != wantEventID || ids["url"] == "" {
		t.Errorf("ResultIDs = %v", ids)
	}

	// Explicit modes and summary.
	for mode, want := range map[string]string{"none": "declineNone", "all_conflicting": "declineAllConflictingInvitations", "only_new_conflicting": "declineOnlyNewConflictingInvitations"} {
		if _, err := run(t, c, write("calendar.set_out_of_office", map[string]any{
			"start": "2026-10-12T00:00:00Z", "end": "2026-10-13T00:00:00Z", "decline_mode": mode, "summary": "Vacation",
		})); err != nil {
			t.Fatal(err)
		}
		body := bodyOf(t, srv.Last(t, createEventPath))
		props, _ := body["outOfOfficeProperties"].(map[string]any)
		if props["autoDeclineMode"] != want || body["summary"] != "Vacation" {
			t.Errorf("decline_mode %s: body = %v, want %s", mode, body, want)
		}
	}
}

func TestSetWorkingLocation(t *testing.T) {
	srv := newAPIServer(t, map[string]route{createEventPath: {status: 200, body: "created_working_location.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("calendar.set_working_location", map[string]any{"date": "2026-10-12", "type": "home"}))
	if err != nil {
		t.Fatalf("set_working_location: %v", err)
	}
	req := srv.Last(t, createEventPath)
	body := bodyOf(t, req)
	if body["id"] != wantEventID || body["eventType"] != "workingLocation" || body["visibility"] != "public" || body["transparency"] != "transparent" {
		t.Errorf("body = %s, want eventType workingLocation, public and transparent", req.Body)
	}
	start, _ := body["start"].(map[string]any)
	end, _ := body["end"].(map[string]any)
	if start["date"] != "2026-10-12" || end["date"] != "2026-10-13" {
		t.Errorf("all-day date = %v .. %v, want 2026-10-12 .. 2026-10-13", start, end)
	}
	props, _ := body["workingLocationProperties"].(map[string]any)
	if props["type"] != "homeOffice" {
		t.Errorf("workingLocationProperties = %v", props)
	}
	if _, ok := props["homeOffice"].(map[string]any); !ok {
		t.Errorf("homeOffice must be sent (an empty object): %v", props)
	}
	if created, _ := res.Content.(google.CreatedEvent); created.ID != wantEventID || created.EventType != "workingLocation" {
		t.Errorf("content = %#v", res.Content)
	}

	for _, tc := range []struct {
		args               map[string]any
		wantType, field    string
		wantLabel          string
		wantStart, wantEnd string
	}{
		{map[string]any{"date": "2026-10-12", "type": "office", "label": "HQ Building 2"}, "officeLocation", "officeLocation", "HQ Building 2", "", ""},
		{map[string]any{"start": "2026-10-12T09:00:00-07:00", "end": "2026-10-12T13:00:00-07:00", "type": "custom", "label": "Cafe"}, "customLocation", "customLocation", "Cafe", "2026-10-12T09:00:00-07:00", "2026-10-12T13:00:00-07:00"},
	} {
		if _, err := run(t, c, write("calendar.set_working_location", tc.args)); err != nil {
			t.Fatal(err)
		}
		body := bodyOf(t, srv.Last(t, createEventPath))
		props, _ := body["workingLocationProperties"].(map[string]any)
		loc, _ := props[tc.field].(map[string]any)
		if props["type"] != tc.wantType || loc["label"] != tc.wantLabel {
			t.Errorf("%v: workingLocationProperties = %v", tc.args, props)
		}
		if tc.wantStart != "" {
			start, _ := body["start"].(map[string]any)
			end, _ := body["end"].(map[string]any)
			if start["dateTime"] != tc.wantStart || end["dateTime"] != tc.wantEnd {
				t.Errorf("%v: times = %v .. %v", tc.args, start, end)
			}
		}
	}
}

func TestCreateFocusTime(t *testing.T) {
	srv := newAPIServer(t, map[string]route{createEventPath: {status: 200, body: "created_focus_time.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("calendar.create_focus_time", map[string]any{
		"start": "2026-10-12T09:00:00-07:00", "end": "2026-10-12T11:00:00-07:00", "chat_status": "doNotDisturb",
	}))
	if err != nil {
		t.Fatalf("create_focus_time: %v", err)
	}
	req := srv.Last(t, createEventPath)
	body := bodyOf(t, req)
	if body["id"] != wantEventID || body["eventType"] != "focusTime" || body["summary"] != "Focus time" {
		t.Errorf("body = %s", req.Body)
	}
	props, _ := body["focusTimeProperties"].(map[string]any)
	if props["autoDeclineMode"] != "declineOnlyNewConflictingInvitations" || props["chatStatus"] != "doNotDisturb" {
		t.Errorf("focusTimeProperties = %v, want the only_new_conflicting default and doNotDisturb", props)
	}
	if created, _ := res.Content.(google.CreatedEvent); created.EventType != "focusTime" {
		t.Errorf("content = %#v", res.Content)
	}
	if _, err := run(t, c, write("calendar.create_focus_time", map[string]any{
		"start": "2026-10-12T09:00:00Z", "end": "2026-10-12T11:00:00Z", "decline_mode": "all_conflicting", "decline_message": "Heads down", "summary": "Deep work",
	})); err != nil {
		t.Fatal(err)
	}
	body = bodyOf(t, srv.Last(t, createEventPath))
	props, _ = body["focusTimeProperties"].(map[string]any)
	if props["autoDeclineMode"] != "declineAllConflictingInvitations" || props["declineMessage"] != "Heads down" || body["summary"] != "Deep work" {
		t.Errorf("body = %v", body)
	}
	if _, ok := props["chatStatus"]; ok {
		t.Errorf("chatStatus sent without chat_status: %v", props)
	}
}

func TestWorkspaceEventArguments(t *testing.T) {
	c, tk := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	timed := map[string]any{"start": "2026-10-12T09:00:00Z", "end": "2026-10-12T10:00:00Z"}
	with := func(base map[string]any, change map[string]any) map[string]any {
		out := map[string]any{}
		for k, v := range base {
			out[k] = v
		}
		for k, v := range change {
			if v == nil {
				delete(out, k)
			} else {
				out[k] = v
			}
		}
		return out
	}
	cases := map[string]struct {
		tool string
		args map[string]any
	}{
		"ooo missing start":           {"calendar.set_out_of_office", with(timed, map[string]any{"start": nil})},
		"ooo missing end":             {"calendar.set_out_of_office", with(timed, map[string]any{"end": nil})},
		"ooo date start":              {"calendar.set_out_of_office", with(timed, map[string]any{"start": "2026-10-12"})},
		"ooo end before start":        {"calendar.set_out_of_office", with(timed, map[string]any{"end": "2026-10-12T08:00:00Z"})},
		"ooo bad decline_mode":        {"calendar.set_out_of_office", with(timed, map[string]any{"decline_mode": "always"})},
		"ooo message without decline": {"calendar.set_out_of_office", with(timed, map[string]any{"decline_mode": "none", "decline_message": "x"})},
		"ooo summary not string":      {"calendar.set_out_of_office", with(timed, map[string]any{"summary": 5})},
		"wl missing type":             {"calendar.set_working_location", map[string]any{"date": "2026-10-12"}},
		"wl bad type":                 {"calendar.set_working_location", map[string]any{"date": "2026-10-12", "type": "beach"}},
		"wl custom without label":     {"calendar.set_working_location", map[string]any{"date": "2026-10-12", "type": "custom"}},
		"wl home with label":          {"calendar.set_working_location", map[string]any{"date": "2026-10-12", "type": "home", "label": "x"}},
		"wl no date nor times":        {"calendar.set_working_location", map[string]any{"type": "home"}},
		"wl date and times":           {"calendar.set_working_location", with(timed, map[string]any{"date": "2026-10-12", "type": "home"})},
		"wl bad date":                 {"calendar.set_working_location", map[string]any{"date": "12/10/2026", "type": "home"}},
		"wl only start":               {"calendar.set_working_location", map[string]any{"start": "2026-10-12T09:00:00Z", "type": "home"}},
		"wl end before start":         {"calendar.set_working_location", with(timed, map[string]any{"end": "2026-10-12T08:00:00Z", "type": "home"})},
		"focus missing start":         {"calendar.create_focus_time", with(timed, map[string]any{"start": nil})},
		"focus end before start":      {"calendar.create_focus_time", with(timed, map[string]any{"end": "2026-10-12T08:00:00Z"})},
		"focus bad chat_status":       {"calendar.create_focus_time", with(timed, map[string]any{"chat_status": "busy"})},
		"focus bad decline_mode":      {"calendar.create_focus_time", with(timed, map[string]any{"decline_mode": "x"})},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := run(t, c, write(tc.tool, tc.args))
			wantClass(t, err, google.ClassInvalidArgument, 0)
		})
	}
	if len(tk.calls) != 0 {
		t.Errorf("token calls for invalid arguments = %d", len(tk.calls))
	}
	for _, full := range workspaceEventTools {
		cl := call(full, map[string]any{"start": "2026-10-12T09:00:00Z", "end": "2026-10-12T10:00:00Z", "type": "home"})
		if _, err := run(t, c, cl); !errors.Is(err, google.ErrMissingOperation) {
			t.Errorf("%s without an operation id: err = %v, want ErrMissingOperation", full, err)
		}
	}
}

func TestWorkspaceEventErrors(t *testing.T) {
	args := map[string]map[string]any{
		"calendar.set_out_of_office":    {"start": "2026-10-12T09:00:00Z", "end": "2026-10-12T10:00:00Z"},
		"calendar.set_working_location": {"date": "2026-10-12", "type": "home"},
		"calendar.create_focus_time":    {"start": "2026-10-12T09:00:00Z", "end": "2026-10-12T10:00:00Z"},
	}
	for _, full := range workspaceEventTools {
		for _, tc := range writeErrorCases("created_focus_time.json") {
			t.Run(full+" "+tc.name, func(t *testing.T) {
				srv := newAPIServer(t, map[string]route{createEventPath: tc.rt})
				res, err := run(t, shortTimeout(t, srv), write(full, args[full]))
				checkWriteError(t, tc, res, err)
			})
		}
	}
}

func TestCheckWorkspaceEvents(t *testing.T) {
	for _, full := range workspaceEventTools {
		for name, tc := range map[string]struct {
			rt   route
			want string
		}{
			"found":     {route{status: 200, body: "created_focus_time.json"}, "found"},
			"not found": {route{status: 404, body: "error_not_found.json"}, "not_found"},
			"gone":      {route{status: 410, body: "error_not_found.json"}, "not_found"},
			"500":       {route{status: 500, body: "error_server.json"}, "cannot"},
		} {
			t.Run(full+" "+name, func(t *testing.T) {
				srv := newAPIServer(t, map[string]route{checkEventPath: tc.rt})
				c, _ := newConnector(t, srv, connectors.Bounds{})
				tool, in := reconcileInput(t, c, full, map[string]any{"summary": "secret"})
				out, err := tool.Reconcile.Check(context.Background(), in)
				wantOutcome(t, out, err, tc.want, wantEventID)
			})
		}
	}
}
