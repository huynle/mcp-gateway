package google_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

// Increment 5: the full Calendar API (recurring instances, quick add,
// move, secondary calendars, the calendar list, sharing, colors and
// settings) and the event fields create_event / update_event gained.

const (
	instancesPath    = "GET /calendar/v3/calendars/primary/events/evt_standup/instances"
	aclPath          = "/calendar/v3/calendars/primary/acl"
	bobRulePath      = "/calendar/v3/calendars/primary/acl/user:bob@example.test"
	colorsPath       = "GET /calendar/v3/colors"
	settingsPath     = "GET /calendar/v3/users/me/settings"
	quickAddPath     = "POST /calendar/v3/calendars/primary/events/quickAdd"
	movePath         = "POST /calendar/v3/calendars/primary/events/evt_standup_001/move"
	calendarsPath    = "POST /calendar/v3/calendars"
	teamCalendar     = "team@group.calendar.example.test"
	teamCalendarPath = "/calendar/v3/calendars/" + teamCalendar
	clearPath        = "POST /calendar/v3/calendars/primary/clear"
	calListPath      = "/calendar/v3/users/me/calendarList"
	teamEntryPath    = calListPath + "/" + teamCalendar
	primaryEventsGet = "GET /calendar/v3/calendars/primary/events"

	scopeCalendarCalendars = "https://www.googleapis.com/auth/calendar.calendars"
	scopeCalendarAcls      = "https://www.googleapis.com/auth/calendar.acls"
	scopeCalendarAclsRO    = "https://www.googleapis.com/auth/calendar.acls.readonly"
	scopeCalendarSettingRO = "https://www.googleapis.com/auth/calendar.settings.readonly"
	scopeCalendarEvents    = "https://www.googleapis.com/auth/calendar.events"
	scopeCalendarEventsRO  = "https://www.googleapis.com/auth/calendar.events.readonly"
	scopeCalendarFull      = "https://www.googleapis.com/auth/calendar"
	scopeCalendarRO        = "https://www.googleapis.com/auth/calendar.readonly"
)

func TestCalendarFullDeclarations(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	r, w := connectors.KindRead, connectors.KindWrite
	declared(t, c, "calendar.list_instances", r, []string{scopeCalendarEventsRO}, "")
	declared(t, c, "calendar.list_acl", r, []string{scopeCalendarAclsRO}, "")
	declared(t, c, "calendar.get_colors", r, []string{scopeCalendarListReadonly}, "")
	declared(t, c, "calendar.get_settings", r, []string{scopeCalendarSettingRO}, "")
	declared(t, c, "calendar.quick_add", w, []string{scopeCalendarEvents}, connectors.ReconcileNone)
	declared(t, c, "calendar.move_event", w, []string{scopeCalendarEvents}, connectors.ReconcileStableID)
	declared(t, c, "calendar.create_calendar", w, []string{scopeCalendarCalendars}, connectors.ReconcileNone)
	declared(t, c, "calendar.update_calendar", w, []string{scopeCalendarCalendars}, connectors.ReconcileNone)
	declared(t, c, "calendar.delete_calendar", w, []string{scopeCalendarCalendars}, connectors.ReconcileStableID)
	declared(t, c, "calendar.clear_calendar", w, []string{scopeCalendarCalendars}, connectors.ReconcileStableID)
	declared(t, c, "calendar.subscribe_calendar", w, []string{scopeCalendarList}, connectors.ReconcileStableID)
	declared(t, c, "calendar.unsubscribe_calendar", w, []string{scopeCalendarList}, connectors.ReconcileStableID)
	declared(t, c, "calendar.update_calendar_list_entry", w, []string{scopeCalendarList}, connectors.ReconcileNone)
	declared(t, c, "calendar.share_calendar", w, []string{scopeCalendarAcls}, connectors.ReconcileStableID)
	declared(t, c, "calendar.update_acl", w, []string{scopeCalendarAcls}, connectors.ReconcileStableID)
	declared(t, c, "calendar.unshare_calendar", w, []string{scopeCalendarAcls}, connectors.ReconcileStableID)

	// Identities never carry content: no text, summary or full address.
	id := toolOf(t, c, "calendar.quick_add").ResourceIdentity(map[string]any{"text": "Lunch with bob@example.test tomorrow"})
	if len(id) != 1 || id["calendar_id"] != "primary" {
		t.Errorf("quick_add identity = %v", id)
	}
	id = toolOf(t, c, "calendar.create_calendar").ResourceIdentity(map[string]any{"summary": "Secret project"})
	if len(id) != 0 {
		t.Errorf("create_calendar identity = %v", id)
	}
	id = toolOf(t, c, "calendar.move_event").ResourceIdentity(map[string]any{"event_id": "e1", "destination": "Team@Group.Calendar.Example.Test"})
	if id["calendar_id"] != "primary" || id["event_id"] != "e1" || id["destination"] != teamCalendar || id["destination_domain"] != "group.calendar.example.test" {
		t.Errorf("move_event identity = %v", id)
	}
	id = toolOf(t, c, "calendar.share_calendar").ResourceIdentity(map[string]any{"role": "writer", "email": "Bob@Example.Test"})
	if id["role"] != "writer" || id["type"] != "user" || id["grantee_domain"] != "example.test" || id["rule_key"] != google.ACLRuleKey("user:bob@example.test") {
		t.Errorf("share_calendar identity = %v", id)
	}
	for k, v := range id {
		if strings.Contains(v, "bob") {
			t.Errorf("share_calendar identity %s = %q carries the address", k, v)
		}
	}
	id = toolOf(t, c, "calendar.unshare_calendar").ResourceIdentity(map[string]any{"rule_id": "user:bob@example.test"})
	if id["type"] != "user" || id["grantee_domain"] != "example.test" || id["rule_key"] != google.ACLRuleKey("user:bob@example.test") || strings.Contains(strings.Join(mapValues(id), ","), "bob") {
		t.Errorf("unshare_calendar identity = %v", id)
	}
	id = toolOf(t, c, "calendar.share_calendar").ResourceIdentity(map[string]any{"role": "reader", "type": "default"})
	if id["type"] != "default" || id["rule_key"] != google.ACLRuleKey("default") {
		t.Errorf("share_calendar default identity = %v", id)
	}
}

func mapValues(m map[string]string) []string {
	var out []string
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

func TestCalendarFullScopeImplications(t *testing.T) {
	for _, tc := range []struct {
		granted, required string
		want              bool
	}{
		{scopeCalendarFull, scopeCalendarCalendars, true},
		{scopeCalendarFull, scopeCalendarAcls, true},
		{scopeCalendarFull, scopeCalendarAclsRO, true},
		{scopeCalendarFull, scopeCalendarSettingRO, true},
		{scopeCalendarAcls, scopeCalendarAclsRO, true},
		{scopeCalendarRO, scopeCalendarSettingRO, true},
		{scopeCalendarRO, scopeCalendarAclsRO, false}, // acl.list does not accept calendar.readonly
		{scopeCalendarRO, scopeCalendarCalendars, false},
		{scopeCalendarEvents, scopeCalendarCalendars, false},
		{scopeCalendarCalendars, scopeCalendarEvents, false},
	} {
		if got := google.Grants([]string{tc.granted}, tc.required); got != tc.want {
			t.Errorf("Grants(%s, %s) = %v, want %v", tc.granted, tc.required, got, tc.want)
		}
	}
}

func TestListInstances(t *testing.T) {
	srv := newAPIServer(t, map[string]route{instancesPath: {status: 200, body: "events_list.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("calendar.list_instances", map[string]any{"event_id": "evt_standup", "time_min": "2026-10-01T00:00:00Z", "max_results": 5}))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		EventID string `json:"event_id"`
		HasMore bool   `json:"has_more"`
		Items   []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	decode(t, res, &out)
	if out.EventID != "evt_standup" || !out.HasMore || len(out.Items) == 0 || out.Items[0].ID != "evt_standup_001" {
		t.Errorf("out = %+v", out)
	}
	q := query(t, srv, strings.TrimPrefix(instancesPath, "GET "))
	if q.Get("maxResults") != "5" || q.Get("timeMin") != "2026-10-01T00:00:00Z" {
		t.Errorf("query = %v", q)
	}
	for _, args := range []map[string]any{{}, {"event_id": "a/b"}, {"event_id": "e", "time_min": "soon"}} {
		_, err := run(t, c, call("calendar.list_instances", args))
		wantClass(t, err, google.ClassInvalidArgument, 0)
	}
	for _, tc := range readErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{instancesPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := run(t, c, call("calendar.list_instances", map[string]any{"event_id": "evt_standup"}))
			checkReadError(t, tc, res, err)
		})
	}
}

func TestListACL(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET " + aclPath: {status: 200, body: "acl_list.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("calendar.list_acl", nil))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		CalendarID string `json:"calendar_id"`
		Items      []struct {
			RuleID     string `json:"rule_id"`
			Role       string `json:"role"`
			ScopeType  string `json:"scope_type"`
			ScopeValue string `json:"scope_value"`
		} `json:"items"`
	}
	decode(t, res, &out)
	if out.CalendarID != "primary" || len(out.Items) != 4 || out.Items[1].RuleID != "user:bob@example.test" || out.Items[1].Role != "reader" ||
		out.Items[2].ScopeType != "domain" || out.Items[2].ScopeValue != "example.test" {
		t.Errorf("out = %+v", out)
	}
	for _, tc := range readErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"GET " + aclPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := run(t, c, call("calendar.list_acl", nil))
			checkReadError(t, tc, res, err)
		})
	}
}

func TestGetColorsAndSettings(t *testing.T) {
	srv := newAPIServer(t, map[string]route{colorsPath: {status: 200, body: "calendar_colors.json"}, settingsPath: {status: 200, body: "calendar_settings.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("calendar.get_colors", nil))
	if err != nil {
		t.Fatal(err)
	}
	var colors struct {
		Calendar []struct{ ID, Background, Foreground string } `json:"calendar"`
		Event    []struct{ ID, Background string }             `json:"event"`
	}
	decode(t, res, &colors)
	if len(colors.Calendar) != 3 || colors.Calendar[0].ID != "1" || colors.Calendar[1].ID != "2" || colors.Calendar[2].ID != "10" ||
		colors.Calendar[0].Background != "#ac725e" || len(colors.Event) != 2 || colors.Event[1].ID != "11" {
		t.Errorf("colors = %+v", colors)
	}
	res, err = run(t, c, call("calendar.get_settings", nil))
	if err != nil {
		t.Fatal(err)
	}
	var settings struct {
		Items []struct{ ID, Value string } `json:"items"`
	}
	decode(t, res, &settings)
	if len(settings.Items) != 3 || settings.Items[0].ID != "timezone" || settings.Items[0].Value != "America/Los_Angeles" {
		t.Errorf("settings = %+v", settings)
	}
	for _, tc := range readErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{colorsPath: tc.rt, settingsPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := run(t, c, call("calendar.get_colors", nil))
			checkReadError(t, tc, res, err)
			res, err = run(t, c, call("calendar.get_settings", nil))
			checkReadError(t, tc, res, err)
		})
	}
}

func TestQuickAdd(t *testing.T) {
	srv := newAPIServer(t, map[string]route{quickAddPath: {status: 200, body: "event_quick_added.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("calendar.quick_add", map[string]any{"text": "Lunch with Bob tomorrow noon", "send_updates": "all"}))
	if err != nil {
		t.Fatal(err)
	}
	if ids := toolOf(t, c, "calendar.quick_add").ResultIDs(res); ids["id"] != "quickadd0001" || ids["url"] == "" {
		t.Errorf("ResultIDs = %v", ids)
	}
	q := query(t, srv, strings.TrimPrefix(quickAddPath, "POST "))
	if q.Get("text") != "Lunch with Bob tomorrow noon" || q.Get("sendUpdates") != "all" {
		t.Errorf("query = %v", q)
	}
	for _, args := range []map[string]any{{}, {"text": " "}, {"text": "x", "send_updates": "everyone"}} {
		_, err := run(t, c, write("calendar.quick_add", args))
		wantClass(t, err, google.ClassInvalidArgument, 0)
	}
}

func TestMoveEvent(t *testing.T) {
	srv := newAPIServer(t, map[string]route{movePath: {status: 200, body: "event_moved.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("calendar.move_event", map[string]any{"event_id": "evt_standup_001", "destination": teamCalendar}))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		ID         string `json:"id"`
		CalendarID string `json:"calendar_id"`
	}
	decode(t, res, &out)
	if out.ID != "evt_standup_001" || out.CalendarID != teamCalendar {
		t.Errorf("out = %+v", out)
	}
	if q := query(t, srv, strings.TrimPrefix(movePath, "POST ")); q.Get("destination") != teamCalendar || q.Get("sendUpdates") != "none" {
		t.Errorf("query = %v", q)
	}
	for _, args := range []map[string]any{{"event_id": "e"}, {"destination": teamCalendar}, {"event_id": "e", "destination": "primary"}} {
		_, err := run(t, c, write("calendar.move_event", args))
		wantClass(t, err, google.ClassInvalidArgument, 0)
	}
	args := map[string]any{"event_id": "evt_standup_001", "destination": teamCalendar}
	destGet := "GET " + teamCalendarPath + "/events/evt_standup_001"
	srcGet := "GET " + standupPath
	for name, tc := range map[string]struct {
		dest, src route
		want      string
	}{
		"in destination":    {route{status: 200, body: "event_moved.json"}, route{status: 404, body: "error_not_found.json"}, "found"},
		"still in source":   {route{status: 404, body: "error_not_found.json"}, route{status: 200, body: "event.json"}, "not_found"},
		"gone from both":    {route{status: 404, body: "error_not_found.json"}, route{status: 404, body: "error_not_found.json"}, "cannot"},
		"destination 500":   {route{status: 500, body: "error_server.json"}, route{status: 200, body: "event.json"}, "cannot"},
		"cancelled in dest": {route{status: 200, body: "event_cancelled.json"}, route{status: 200, body: "event.json"}, "cannot"},
	} {
		t.Run("check "+name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{destGet: tc.dest, srcGet: tc.src})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, "calendar.move_event", args)
			out, err := tool.Reconcile.Check(context.Background(), in)
			wantOutcome(t, out, err, tc.want, "evt_standup_001")
		})
	}
}

func TestCreateUpdateDeleteCalendar(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		calendarsPath:                {status: 200, body: "calendar_created.json"},
		"PATCH " + teamCalendarPath:  {status: 200, body: "calendar_created.json"},
		"DELETE " + teamCalendarPath: {status: 204, body: ""},
	})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("calendar.create_calendar", map[string]any{"summary": "Project X", "description": "Milestones", "time_zone": "Europe/Berlin"}))
	if err != nil {
		t.Fatal(err)
	}
	if ids := toolOf(t, c, "calendar.create_calendar").ResultIDs(res); ids["id"] != "c_0123abcd@group.calendar.example.test" {
		t.Errorf("ResultIDs = %v", ids)
	}
	if b := bodyOf(t, srv.Last(t, calendarsPath)); b["summary"] != "Project X" || b["timeZone"] != "Europe/Berlin" || b["description"] != "Milestones" {
		t.Errorf("insert body = %v", b)
	}
	if _, err := run(t, c, write("calendar.create_calendar", map[string]any{"summary": " "})); err == nil {
		t.Error("blank summary accepted")
	}

	if _, err := run(t, c, write("calendar.update_calendar", map[string]any{"calendar_id": teamCalendar, "summary": "Team 2", "description": ""})); err != nil {
		t.Fatal(err)
	}
	if b := bodyOf(t, srv.Last(t, "PATCH "+teamCalendarPath)); b["summary"] != "Team 2" || b["description"] != "" {
		t.Errorf("patch body = %v", b)
	}
	for _, args := range []map[string]any{{"calendar_id": teamCalendar}, {"calendar_id": teamCalendar, "summary": " "}} {
		_, err := run(t, c, write("calendar.update_calendar", args))
		wantClass(t, err, google.ClassInvalidArgument, 0)
	}

	res, err = run(t, c, write("calendar.delete_calendar", map[string]any{"calendar_id": teamCalendar}))
	if err != nil {
		t.Fatal(err)
	}
	if ids := toolOf(t, c, "calendar.delete_calendar").ResultIDs(res); ids["id"] != teamCalendar {
		t.Errorf("ResultIDs = %v", ids)
	}
	for _, args := range []map[string]any{{}, {"calendar_id": "primary"}, {"calendar_id": "PRIMARY"}} {
		_, err := run(t, c, write("calendar.delete_calendar", args))
		wantClass(t, err, google.ClassInvalidArgument, 0)
	}
	for name, tc := range map[string]struct {
		rt   route
		want string
	}{
		"404":     {route{status: 404, body: "error_not_found.json"}, "found"},
		"present": {route{status: 200, body: "calendar_created.json"}, "not_found"},
		"500":     {route{status: 500, body: "error_server.json"}, "cannot"},
	} {
		t.Run("check "+name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"GET " + teamCalendarPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, "calendar.delete_calendar", map[string]any{"calendar_id": teamCalendar})
			out, err := tool.Reconcile.Check(context.Background(), in)
			wantOutcome(t, out, err, tc.want, teamCalendar)
		})
	}
}

func TestClearCalendar(t *testing.T) {
	srv := newAPIServer(t, map[string]route{clearPath: {status: 204, body: ""}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("calendar.clear_calendar", nil))
	if err != nil {
		t.Fatal(err)
	}
	if ids := toolOf(t, c, "calendar.clear_calendar").ResultIDs(res); ids["id"] != "primary" {
		t.Errorf("ResultIDs = %v", ids)
	}
	_, err = run(t, c, write("calendar.clear_calendar", map[string]any{"calendar_id": teamCalendar}))
	wantClass(t, err, google.ClassInvalidArgument, 0)
	for name, tc := range map[string]struct {
		rt   route
		want string
	}{
		"empty":  {route{status: 200, body: "events_list_empty.json"}, "found"},
		"events": {route{status: 200, body: "events_list.json"}, "cannot"},
		"500":    {route{status: 500, body: "error_server.json"}, "cannot"},
	} {
		t.Run("check "+name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{primaryEventsGet: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, "calendar.clear_calendar", nil)
			out, err := tool.Reconcile.Check(context.Background(), in)
			wantOutcome(t, out, err, tc.want, "primary")
		})
	}
}

func TestCalendarListEntries(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		"POST " + calListPath:     {status: 200, body: "calendar_list_entry.json"},
		"DELETE " + teamEntryPath: {status: 204, body: ""},
		"PATCH " + teamEntryPath:  {status: 200, body: "calendar_list_entry.json"},
	})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("calendar.subscribe_calendar", map[string]any{"calendar_id": teamCalendar, "color_id": "7"}))
	if err != nil {
		t.Fatal(err)
	}
	if ids := toolOf(t, c, "calendar.subscribe_calendar").ResultIDs(res); ids["id"] != teamCalendar {
		t.Errorf("ResultIDs = %v", ids)
	}
	if b := bodyOf(t, srv.Last(t, "POST "+calListPath)); b["id"] != teamCalendar || b["colorId"] != "7" {
		t.Errorf("insert body = %v", b)
	}
	if _, err := run(t, c, write("calendar.unsubscribe_calendar", map[string]any{"calendar_id": teamCalendar})); err != nil {
		t.Fatal(err)
	}
	if srv.Count("DELETE "+teamEntryPath) != 1 {
		t.Error("no calendarList.delete")
	}
	_, err = run(t, c, write("calendar.unsubscribe_calendar", map[string]any{"calendar_id": "primary"}))
	wantClass(t, err, google.ClassInvalidArgument, 0)

	if _, err := run(t, c, write("calendar.update_calendar_list_entry", map[string]any{
		"calendar_id": teamCalendar, "hidden": true, "selected": false, "summary_override": "Mine", "default_reminders": []any{"popup:10", "email:60"},
	})); err != nil {
		t.Fatal(err)
	}
	b := bodyOf(t, srv.Last(t, "PATCH "+teamEntryPath))
	if b["hidden"] != true || b["selected"] != false || b["summaryOverride"] != "Mine" {
		t.Errorf("patch body = %v", b)
	}
	if rem, _ := b["defaultReminders"].([]any); len(rem) != 2 || rem[1].(map[string]any)["method"] != "email" || rem[1].(map[string]any)["minutes"] != float64(60) {
		t.Errorf("defaultReminders = %v", b["defaultReminders"])
	}
	for _, args := range []map[string]any{
		{"calendar_id": teamCalendar},
		{"calendar_id": teamCalendar, "color_id": "99"},
		{"calendar_id": teamCalendar, "default_reminders": []any{"sms:10"}},
		{"calendar_id": teamCalendar, "default_reminders": []any{"popup:-1"}},
	} {
		_, err := run(t, c, write("calendar.update_calendar_list_entry", args))
		wantClass(t, err, google.ClassInvalidArgument, 0)
	}

	for name, tc := range map[string]struct {
		tool string
		rt   route
		want string
	}{
		"subscribed":       {"calendar.subscribe_calendar", route{status: 200, body: "calendar_list_entry.json"}, "found"},
		"not subscribed":   {"calendar.subscribe_calendar", route{status: 404, body: "error_not_found.json"}, "not_found"},
		"subscribe 500":    {"calendar.subscribe_calendar", route{status: 500, body: "error_server.json"}, "cannot"},
		"unsubscribed":     {"calendar.unsubscribe_calendar", route{status: 404, body: "error_not_found.json"}, "found"},
		"still subscribed": {"calendar.unsubscribe_calendar", route{status: 200, body: "calendar_list_entry.json"}, "not_found"},
	} {
		t.Run("check "+name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"GET " + teamEntryPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, tc.tool, map[string]any{"calendar_id": teamCalendar})
			out, err := tool.Reconcile.Check(context.Background(), in)
			wantOutcome(t, out, err, tc.want, teamCalendar)
		})
	}
}

func TestShareCalendar(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		"POST " + aclPath:       {status: 200, body: "acl_rule.json"},
		"PATCH " + bobRulePath:  {status: 200, body: "acl_rule.json"},
		"DELETE " + bobRulePath: {status: 204, body: ""},
	})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("calendar.share_calendar", map[string]any{"role": "writer", "email": "bob@example.test", "send_notifications": false}))
	if err != nil {
		t.Fatal(err)
	}
	if ids := toolOf(t, c, "calendar.share_calendar").ResultIDs(res); ids["rule_id"] != "user:bob@example.test" || ids["calendar_id"] != "primary" {
		t.Errorf("ResultIDs = %v", ids)
	}
	b := bodyOf(t, srv.Last(t, "POST "+aclPath))
	scope, _ := b["scope"].(map[string]any)
	if b["role"] != "writer" || scope["type"] != "user" || scope["value"] != "bob@example.test" {
		t.Errorf("insert body = %v", b)
	}
	if q := query(t, srv, aclPath); q.Get("sendNotifications") != "false" {
		t.Errorf("query = %v", q)
	}
	if _, err := run(t, c, write("calendar.share_calendar", map[string]any{"role": "freeBusyReader", "type": "domain", "domain": "example.test"})); err != nil {
		t.Fatal(err)
	}
	if b := bodyOf(t, srv.Last(t, "POST "+aclPath)); b["scope"].(map[string]any)["value"] != "example.test" {
		t.Errorf("domain body = %v", b)
	}
	for _, args := range []map[string]any{
		{"email": "bob@example.test"},
		{"role": "admin", "email": "bob@example.test"},
		{"role": "reader"},
		{"role": "reader", "email": "not an address"},
		{"role": "reader", "type": "domain"},
		{"role": "reader", "type": "domain", "domain": "bad domain"},
		{"role": "reader", "type": "default", "email": "bob@example.test"},
		{"role": "reader", "type": "robot", "email": "bob@example.test"},
	} {
		_, err := run(t, c, write("calendar.share_calendar", args))
		wantClass(t, err, google.ClassInvalidArgument, 0)
	}

	if _, err := run(t, c, write("calendar.update_acl", map[string]any{"rule_id": "user:bob@example.test", "role": "writer"})); err != nil {
		t.Fatal(err)
	}
	if b := bodyOf(t, srv.Last(t, "PATCH "+bobRulePath)); b["role"] != "writer" {
		t.Errorf("patch body = %v", b)
	}
	if _, err := run(t, c, write("calendar.unshare_calendar", map[string]any{"rule_id": "user:bob@example.test"})); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		tool string
		args map[string]any
	}{
		{"calendar.update_acl", map[string]any{"rule_id": "user:bob@example.test"}},
		{"calendar.update_acl", map[string]any{"role": "reader"}},
		{"calendar.update_acl", map[string]any{"rule_id": "user:bob@example.test", "role": "boss"}},
		{"calendar.unshare_calendar", map[string]any{}},
		{"calendar.unshare_calendar", map[string]any{"rule_id": "user/x"}},
	} {
		_, err := run(t, c, write(tc.tool, tc.args))
		wantClass(t, err, google.ClassInvalidArgument, 0)
	}

	shareArgs := map[string]any{"role": "writer", "email": "bob@example.test"}
	for name, tc := range map[string]struct {
		tool string
		args map[string]any
		rt   route
		want string
	}{
		"shared":            {"calendar.share_calendar", shareArgs, route{status: 200, body: "acl_list_writer.json"}, "found"},
		"other role":        {"calendar.share_calendar", shareArgs, route{status: 200, body: "acl_list.json"}, "not_found"},
		"absent":            {"calendar.share_calendar", shareArgs, route{status: 200, body: "acl_list_owner_only.json"}, "not_found"},
		"list 500":          {"calendar.share_calendar", shareArgs, route{status: 500, body: "error_server.json"}, "cannot"},
		"updated":           {"calendar.update_acl", map[string]any{"rule_id": "user:bob@example.test", "role": "writer"}, route{status: 200, body: "acl_list_writer.json"}, "found"},
		"not updated":       {"calendar.update_acl", map[string]any{"rule_id": "user:bob@example.test", "role": "writer"}, route{status: 200, body: "acl_list.json"}, "not_found"},
		"unshared":          {"calendar.unshare_calendar", map[string]any{"rule_id": "user:bob@example.test"}, route{status: 200, body: "acl_list_owner_only.json"}, "found"},
		"still shared":      {"calendar.unshare_calendar", map[string]any{"rule_id": "user:bob@example.test"}, route{status: 200, body: "acl_list.json"}, "not_found"},
		"default role none": {"calendar.unshare_calendar", map[string]any{"rule_id": "default"}, route{status: 200, body: "acl_list.json"}, "found"},
	} {
		t.Run("check "+name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"GET " + aclPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, tc.tool, tc.args)
			out, err := tool.Reconcile.Check(context.Background(), in)
			id := "user:bob@example.test"
			switch {
			case tc.args["rule_id"] == "default":
				id = "default"
			case name == "unshared":
				// A removed rule is named by its key: the identity never
				// holds the grantee's address.
				id = google.ACLRuleKey("user:bob@example.test")
			}
			wantOutcome(t, out, err, tc.want, id)
		})
	}
	t.Run("check bounded pages", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{"GET " + aclPath: {pages: map[string]route{
			"1": {status: 200, body: "acl_list_more.json"}, "acl-more": {status: 200, body: "acl_list_more.json"},
		}}})
		c, _ := newConnector(t, srv, connectors.Bounds{})
		tool, in := reconcileInput(t, c, "calendar.share_calendar", shareArgs)
		out, err := tool.Reconcile.Check(context.Background(), in)
		wantCannotTell(t, out, err)
		if n := srv.Count("GET " + aclPath); n != google.MaxReconcilePages {
			t.Errorf("listed %d pages, want %d", n, google.MaxReconcilePages)
		}
	})
}

// TestCalendarFullWriteErrors runs the write error table over every new
// Calendar write.
func TestCalendarFullWriteErrors(t *testing.T) {
	for _, w := range []struct {
		tool, path, okBody string
		args               map[string]any
	}{
		{"calendar.quick_add", quickAddPath, "event_quick_added.json", map[string]any{"text": "Lunch"}},
		{"calendar.move_event", movePath, "event_moved.json", map[string]any{"event_id": "evt_standup_001", "destination": teamCalendar}},
		{"calendar.create_calendar", calendarsPath, "calendar_created.json", map[string]any{"summary": "X"}},
		{"calendar.update_calendar", "PATCH " + teamCalendarPath, "calendar_created.json", map[string]any{"calendar_id": teamCalendar, "summary": "X"}},
		{"calendar.delete_calendar", "DELETE " + teamCalendarPath, "", map[string]any{"calendar_id": teamCalendar}},
		{"calendar.clear_calendar", clearPath, "", nil},
		{"calendar.subscribe_calendar", "POST " + calListPath, "calendar_list_entry.json", map[string]any{"calendar_id": teamCalendar}},
		{"calendar.unsubscribe_calendar", "DELETE " + teamEntryPath, "", map[string]any{"calendar_id": teamCalendar}},
		{"calendar.update_calendar_list_entry", "PATCH " + teamEntryPath, "calendar_list_entry.json", map[string]any{"calendar_id": teamCalendar, "hidden": true}},
		{"calendar.share_calendar", "POST " + aclPath, "acl_rule.json", map[string]any{"role": "reader", "email": "bob@example.test"}},
		{"calendar.update_acl", "PATCH " + bobRulePath, "acl_rule.json", map[string]any{"rule_id": "user:bob@example.test", "role": "reader"}},
		{"calendar.unshare_calendar", "DELETE " + bobRulePath, "", map[string]any{"rule_id": "user:bob@example.test"}},
	} {
		for _, tc := range writeErrorCases(w.okBody) {
			t.Run(w.tool+" "+tc.name, func(t *testing.T) {
				srv := newAPIServer(t, map[string]route{w.path: tc.rt})
				res, err := run(t, shortTimeout(t, srv), write(w.tool, w.args))
				checkWriteError(t, tc, res, err)
			})
		}
		t.Run(w.tool+" needs the operation id", func(t *testing.T) {
			c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
			_, err := run(t, c, call(w.tool, w.args))
			if err == nil {
				t.Fatal("write without an operation id accepted")
			}
		})
	}
}

func TestCreateEventFullFields(t *testing.T) {
	srv := newAPIServer(t, map[string]route{createEventPath: {status: 200, body: "event_recurring.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	_, err := run(t, c, write("calendar.create_event", map[string]any{
		"summary": "Weekly review", "start": "2026-10-12T10:00:00-07:00", "end": "2026-10-12T11:00:00-07:00", "time_zone": "America/Los_Angeles",
		"recurrence": []any{"RRULE:FREQ=WEEKLY;BYDAY=MO;COUNT=10"}, "reminders": []any{"popup:10"}, "color_id": "5", "visibility": "private",
		"transparency": "transparent", "attachments": []any{"https://drive.google.com/open?id=file_abc"}, "guests_can_modify": true,
		"guests_can_see_other_guests": false,
	}))
	if err != nil {
		t.Fatal(err)
	}
	r := srv.Last(t, createEventPath)
	b := bodyOf(t, r)
	if rec, _ := b["recurrence"].([]any); len(rec) != 1 || rec[0] != "RRULE:FREQ=WEEKLY;BYDAY=MO;COUNT=10" {
		t.Errorf("recurrence = %v", b["recurrence"])
	}
	rem, _ := b["reminders"].(map[string]any)
	if rem["useDefault"] != false || len(rem["overrides"].([]any)) != 1 {
		t.Errorf("reminders = %v", b["reminders"])
	}
	if b["colorId"] != "5" || b["visibility"] != "private" || b["transparency"] != "transparent" || b["guestsCanModify"] != true || b["guestsCanSeeOtherGuests"] != false {
		t.Errorf("body = %v", b)
	}
	if att, _ := b["attachments"].([]any); len(att) != 1 || att[0].(map[string]any)["fileUrl"] != "https://drive.google.com/open?id=file_abc" {
		t.Errorf("attachments = %v", b["attachments"])
	}
	if r.URL.Query().Get("supportsAttachments") != "true" {
		t.Errorf("supportsAttachments missing: %v", r.URL.Query())
	}
	if b["id"] != google.EventID(opID) {
		t.Errorf("event id = %v", b["id"])
	}
	for _, extra := range []map[string]any{
		{"recurrence": []any{"FREQ=WEEKLY"}},
		{"reminders": []any{"popup:ten"}},
		{"reminders": []any{"popup:10"}, "use_default_reminders": true},
		{"reminders": []any{"popup:1", "popup:2", "popup:3", "popup:4", "popup:5", "popup:6"}},
		{"color_id": "0"},
		{"visibility": "secret"},
		{"transparency": "clear"},
		{"attachments": []any{"https://example.test/file"}},
	} {
		args := map[string]any{"summary": "x", "start": "2026-10-12", "end": "2026-10-13"}
		for k, v := range extra {
			args[k] = v
		}
		_, err := run(t, c, write("calendar.create_event", args))
		wantClass(t, err, google.ClassInvalidArgument, 0)
	}
	if n := srv.Count(createEventPath); n != 1 {
		t.Errorf("invalid calls reached Google: %d inserts", n)
	}
}

func TestUpdateEventFullFields(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET " + standupPath: {status: 200, body: "event.json"}, "PATCH " + standupPath: {status: 200, body: "event.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	if _, err := run(t, c, write("calendar.update_event", map[string]any{"event_id": "evt_standup_001", "recurrence": []any{}, "use_default_reminders": true, "color_id": "11"})); err != nil {
		t.Fatal(err)
	}
	b := bodyOf(t, srv.Last(t, "PATCH "+standupPath))
	if rec, ok := b["recurrence"].([]any); !ok || len(rec) != 0 {
		t.Errorf("recurrence not cleared: %v", b)
	}
	if rem, _ := b["reminders"].(map[string]any); rem["useDefault"] != true {
		t.Errorf("reminders = %v", b["reminders"])
	}
	if b["colorId"] != "11" {
		t.Errorf("body = %v", b)
	}
	ext, _ := b["extendedProperties"].(map[string]any)
	if priv, _ := ext["private"].(map[string]any); priv["mcp-gateway-op"] != opID {
		t.Errorf("marker missing: %v", b)
	}
}

func TestGetEventShowsRecurrenceAndAttachments(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /calendar/v3/calendars/primary/events/n8cek7dlhn61olmq3cco8a95d1rd4tdf": {status: 200, body: "event_recurring.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("calendar.get_event", map[string]any{"event_id": "n8cek7dlhn61olmq3cco8a95d1rd4tdf"}))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Recurrence  []string `json:"recurrence"`
		ColorID     string   `json:"color_id"`
		Visibility  string   `json:"visibility"`
		Attachments []struct {
			Title string `json:"title"`
			URL   string `json:"url"`
		} `json:"attachments"`
	}
	decode(t, res, &out)
	if !slices.Equal(out.Recurrence, []string{"RRULE:FREQ=WEEKLY;BYDAY=MO;COUNT=10"}) || out.ColorID != "5" || out.Visibility != "private" ||
		len(out.Attachments) != 1 || out.Attachments[0].Title != "Agenda" {
		t.Errorf("out = %+v", out)
	}
}
