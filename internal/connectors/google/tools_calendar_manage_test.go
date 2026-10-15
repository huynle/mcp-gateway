package google_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

// Calendar management tools: list_calendars, free_busy, update_event,
// delete_event, respond_to_event.

const (
	calendarListPath = "GET /calendar/v3/users/me/calendarList"
	freeBusyPath     = "POST /calendar/v3/freeBusy"
	standupPath      = "/calendar/v3/calendars/primary/events/evt_standup_001"

	scopeCalendarListReadonly   = "https://www.googleapis.com/auth/calendar.calendarlist.readonly"
	scopeCalendarList           = "https://www.googleapis.com/auth/calendar.calendarlist"
	scopeCalendarFreeBusy       = "https://www.googleapis.com/auth/calendar.freebusy"
	scopeCalendarEventsFreeBusy = "https://www.googleapis.com/auth/calendar.events.freebusy"
)

// declared asserts a tool's kind, required scopes and reconciliation.
func declared(t *testing.T, c *google.Connector, full string, kind connectors.Kind, scopes []string, rec connectors.ReconcileKind) connectors.Tool {
	t.Helper()
	tool := toolOf(t, c, full)
	if tool.Kind != kind {
		t.Errorf("%s: Kind = %s, want %s", full, tool.Kind, kind)
	}
	if strings.Join(tool.RequiredScopes, " ") != strings.Join(scopes, " ") {
		t.Errorf("%s: RequiredScopes = %v, want %v", full, tool.RequiredScopes, scopes)
	}
	if kind == connectors.KindWrite {
		if tool.Reconcile.Kind != rec || (tool.Reconcile.Check == nil) != (rec == connectors.ReconcileNone) || tool.ResultIDs == nil {
			t.Errorf("%s: reconcile %s check %v resultIDs %v, want %s", full, tool.Reconcile.Kind, tool.Reconcile.Check != nil, tool.ResultIDs != nil, rec)
		}
	}
	var schema struct {
		AdditionalProperties *bool `json:"additionalProperties"`
	}
	if err := json.Unmarshal(tool.InputSchema, &schema); err != nil || schema.AdditionalProperties == nil || *schema.AdditionalProperties {
		t.Errorf("%s: schema must be closed (additionalProperties false): %s", full, tool.InputSchema)
	}
	return tool
}

// wantOutcome asserts a Check result: "found" (with id), "not_found",
// or anything else for "cannot tell yet".
func wantOutcome(t *testing.T, out connectors.ReconcileResult, err error, want, id string) {
	t.Helper()
	switch want {
	case "found":
		wantFound(t, out, err, id)
	case "not_found":
		wantNotFound(t, out, err)
	default:
		wantCannotTell(t, out, err)
	}
}

// bodyOf decodes a recorded request's JSON body.
func bodyOf(t *testing.T, r recorded) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(r.Body), &m); err != nil {
		t.Fatalf("%s %s body %q: %v", r.Method, r.URL.Path, r.Body, err)
	}
	return m
}

func TestCalendarManageDeclarations(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	r, w := connectors.KindRead, connectors.KindWrite
	declared(t, c, "calendar.list_calendars", r, []string{scopeCalendarListReadonly}, "")
	declared(t, c, "calendar.free_busy", r, []string{scopeCalendarFreeBusy}, "")
	declared(t, c, "calendar.update_event", w, []string{google.ScopeCalendarEvents}, connectors.ReconcileMarker)
	declared(t, c, "calendar.delete_event", w, []string{google.ScopeCalendarEvents}, connectors.ReconcileStableID)
	declared(t, c, "calendar.respond_to_event", w, []string{google.ScopeCalendarEvents}, connectors.ReconcileStableID)

	id := toolOf(t, c, "calendar.respond_to_event").ResourceIdentity(map[string]any{"calendar_id": "Primary", "event_id": "e1", "response": "accepted", "comment": "secret"})
	if id["calendar_id"] != "primary" || id["event_id"] != "e1" || id["response"] != "accepted" || len(id) != 3 {
		t.Errorf("respond_to_event identity = %v", id)
	}
	fb := toolOf(t, c, "calendar.free_busy").ResourceIdentity(map[string]any{"calendar_ids": []any{"Bob@Example.test", "primary", "carol@other.test"}})
	if fb["calendar_ids"] != "bob@example.test,carol@other.test,primary" || fb["domains"] != "example.test,other.test" {
		t.Errorf("free_busy identity = %v", fb)
	}
	if id := toolOf(t, c, "calendar.update_event").ResourceIdentity(map[string]any{"event_id": "e1", "summary": "secret"}); id["event_id"] != "e1" || len(id) != 2 {
		t.Errorf("update_event identity = %v (never the content)", id)
	}
}

func TestCalendarManageScopeImplication(t *testing.T) {
	for _, tc := range []struct {
		granted, required string
		want              bool
	}{
		{google.ScopeCalendarReadonly, scopeCalendarListReadonly, true},
		{google.ScopeCalendar, scopeCalendarListReadonly, true},
		{scopeCalendarList, scopeCalendarListReadonly, true},
		{google.ScopeCalendarEventsReadonly, scopeCalendarListReadonly, false},
		{google.ScopeCalendarReadonly, scopeCalendarFreeBusy, true},
		{google.ScopeCalendar, scopeCalendarFreeBusy, true},
		{scopeCalendarEventsFreeBusy, scopeCalendarFreeBusy, true},
		{google.ScopeCalendarEvents, scopeCalendarFreeBusy, false},
	} {
		if got := google.Grants([]string{tc.granted}, tc.required); got != tc.want {
			t.Errorf("Grants(%s, %s) = %v, want %v", tc.granted, tc.required, got, tc.want)
		}
	}
}

func TestListCalendars(t *testing.T) {
	srv := newAPIServer(t, map[string]route{calendarListPath: {status: 200, body: "calendar_list.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("calendar.list_calendars", map[string]any{"show_hidden": true, "max_results": 5, "page_token": "p1"}))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Items []struct {
			ID, Summary, Description, TimeZone, AccessRole string
			Primary, Hidden                                bool
		} `json:"items"`
		HasMore       bool   `json:"has_more"`
		NextPageToken string `json:"next_page_token"`
	}
	decode(t, res, &out)
	raw, _ := json.Marshal(res.Content)
	if !strings.Contains(string(raw), `"access_role":"owner"`) || !strings.Contains(string(raw), `"time_zone":"America/Los_Angeles"`) {
		t.Errorf("content %s lacks access_role / time_zone", raw)
	}
	if len(out.Items) != 2 || out.Items[0].ID != "alice@example.test" || !out.Items[0].Primary || !out.Items[1].Hidden || out.Items[1].Description != "Shared team calendar" {
		t.Errorf("items = %+v", out.Items)
	}
	if !out.HasMore || out.NextPageToken != "cal-page-2" || res.Empty || res.Partial {
		t.Errorf("page = %+v, res = %+v", out, res)
	}
	q := query(t, srv, "/calendar/v3/users/me/calendarList")
	if q.Get("showHidden") != "true" || q.Get("maxResults") != "5" || q.Get("pageToken") != "p1" {
		t.Errorf("query = %v", q)
	}

	empty := newAPIServer(t, map[string]route{calendarListPath: {status: 200, body: "calendar_list_empty.json"}})
	c2, _ := newConnector(t, empty, connectors.Bounds{})
	res, err = run(t, c2, call("calendar.list_calendars", map[string]any{"max_results": 500}))
	if err != nil || !res.Empty || !res.Partial {
		t.Errorf("empty clamped list: res = %+v, err = %v", res, err)
	}
	for _, tc := range readErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{calendarListPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := run(t, c, call("calendar.list_calendars", nil))
			checkReadError(t, tc, res, err)
		})
	}
}

func TestFreeBusy(t *testing.T) {
	srv := newAPIServer(t, map[string]route{freeBusyPath: {status: 200, body: "freebusy.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("calendar.free_busy", map[string]any{
		"time_min": "2026-10-09T00:00:00Z", "time_max": "2026-10-10T00:00:00Z", "calendar_ids": []any{"primary", "bob@example.test"}, "time_zone": "UTC",
	}))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		TimeMin   string `json:"time_min"`
		TimeMax   string `json:"time_max"`
		Calendars []struct {
			ID   string `json:"id"`
			Busy []struct {
				Start, End string
			} `json:"busy"`
			Errors []string `json:"errors"`
		} `json:"calendars"`
	}
	decode(t, res, &out)
	if out.TimeMin != "2026-10-09T00:00:00Z" || len(out.Calendars) != 2 {
		t.Fatalf("out = %+v", out)
	}
	if out.Calendars[0].ID != "primary" || len(out.Calendars[0].Busy) != 2 || out.Calendars[0].Busy[0].Start != "2026-10-09T16:30:00Z" {
		t.Errorf("primary = %+v", out.Calendars[0])
	}
	if out.Calendars[1].ID != "bob@example.test" || len(out.Calendars[1].Errors) != 1 || out.Calendars[1].Errors[0] != "notFound" {
		t.Errorf("bob = %+v", out.Calendars[1])
	}
	if !res.Partial {
		t.Error("a calendar Google could not read makes the result partial")
	}
	body := bodyOf(t, srv.Last(t, freeBusyPath))
	items, _ := body["items"].([]any)
	if body["timeMin"] != "2026-10-09T00:00:00Z" || body["timeZone"] != "UTC" || len(items) != 2 {
		t.Errorf("request body = %v", body)
	}

	bad := []map[string]any{
		{"time_max": "2026-10-10T00:00:00Z"},
		{"time_min": "2026-10-09T00:00:00Z"},
		{"time_min": "2026-10-10T00:00:00Z", "time_max": "2026-10-09T00:00:00Z"},
		{"time_min": "2026-10-09T00:00:00Z", "time_max": "2026-10-10T00:00:00Z", "calendar_ids": []any{"a/b"}},
		{"time_min": "2026-10-09T00:00:00Z", "time_max": "2026-10-10T00:00:00Z", "calendar_ids": manyIDs(51)},
	}
	for _, args := range bad {
		_, err := run(t, c, call("calendar.free_busy", args))
		wantClass(t, err, google.ClassInvalidArgument, 0)
	}
	// Default: the primary calendar.
	_, err = run(t, c, call("calendar.free_busy", map[string]any{"time_min": "2026-10-09T00:00:00Z", "time_max": "2026-10-10T00:00:00Z"}))
	if err != nil {
		t.Fatal(err)
	}
	items, _ = bodyOf(t, srv.Last(t, freeBusyPath))["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["id"] != "primary" {
		t.Errorf("default items = %v", items)
	}
}

func manyIDs(n int) []any {
	out := make([]any, n)
	for i := range out {
		out[i] = fmt.Sprintf("user%d@example.test", i)
	}
	return out
}

func TestUpdateEvent(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		"GET " + standupPath:   {status: 200, body: "event_marked_other.json"},
		"PATCH " + standupPath: {status: 200, body: "event_marked.json"},
	})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("calendar.update_event", map[string]any{
		"event_id": "evt_standup_001", "summary": "Standup (moved)", "start": "2026-10-09T10:00:00-07:00", "end": "2026-10-09T10:15:00-07:00",
		"location": "", "attendees": []any{"bob@example.test"}, "send_updates": "all",
	}))
	if err != nil {
		t.Fatal(err)
	}
	ids := toolOf(t, c, "calendar.update_event").ResultIDs(res)
	if ids["id"] != "evt_standup_001" {
		t.Errorf("ResultIDs = %v", ids)
	}
	patch := srv.Last(t, "PATCH "+standupPath)
	if patch.URL.Query().Get("sendUpdates") != "all" {
		t.Errorf("sendUpdates = %q", patch.URL.Query().Get("sendUpdates"))
	}
	body := bodyOf(t, patch)
	if body["summary"] != "Standup (moved)" || body["location"] != "" {
		t.Errorf("patch body = %v (summary and the cleared location)", body)
	}
	if _, ok := body["description"]; ok {
		t.Errorf("patch body sends description although it was not given: %v", body)
	}
	start, _ := body["start"].(map[string]any)
	if start["dateTime"] != "2026-10-09T10:00:00-07:00" {
		t.Errorf("start = %v", start)
	}
	ext, _ := body["extendedProperties"].(map[string]any)
	private, _ := ext["private"].(map[string]any)
	if private["mcp-gateway-op"] != opID {
		t.Errorf("private properties = %v, want the operation marker", private)
	}
	att, _ := body["attendees"].([]any)
	if len(att) != 1 || att[0].(map[string]any)["email"] != "bob@example.test" {
		t.Errorf("attendees = %v", att)
	}

	for _, args := range []map[string]any{
		{"event_id": "evt_standup_001"},
		{"summary": "x"},
		{"event_id": "evt_standup_001", "start": "tomorrow"},
		{"event_id": "evt_standup_001", "start": "2026-10-10", "end": "2026-10-10T10:00:00Z"},
		{"event_id": "evt_standup_001", "start": "2026-10-11", "end": "2026-10-10"},
		{"event_id": "evt_standup_001", "summary": "x", "send_updates": "everyone"},
		{"event_id": "evt_standup_001", "attendees": []any{"not an address"}},
	} {
		_, err := run(t, c, write("calendar.update_event", args))
		wantClass(t, err, google.ClassInvalidArgument, 0)
	}
	for _, tc := range writeErrorCases("event_marked.json") {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"GET " + standupPath: {status: 200, body: "event.json"}, "PATCH " + standupPath: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("calendar.update_event", map[string]any{"event_id": "evt_standup_001", "summary": "x"}))
			checkWriteError(t, tc, res, err)
		})
	}
	// The lookup before the patch is a read: a failure is a known outcome.
	look := newAPIServer(t, map[string]route{"GET " + standupPath: {status: 500, body: "error_server.json"}})
	cl, _ := newConnector(t, look, connectors.Bounds{})
	if _, err := run(t, cl, write("calendar.update_event", map[string]any{"event_id": "evt_standup_001", "summary": "x"})); err == nil || errors.Is(err, connectors.ErrOutcomeUnknown) {
		t.Errorf("lookup failure: err = %v, want a known outcome", err)
	}
	if look.Count("PATCH "+standupPath) != 0 {
		t.Error("nothing is patched when the lookup failed")
	}
}

func TestCheckUpdateEvent(t *testing.T) {
	args := map[string]any{"event_id": "evt_standup_001", "summary": "x"}
	for name, tc := range map[string]struct {
		rt   route
		want string
	}{
		"marker is ours":    {route{status: 200, body: "event_marked.json"}, "found"},
		"no marker":         {route{status: 200, body: "event.json"}, "not_found"},
		"another operation": {route{status: 200, body: "event_marked_other.json"}, "cannot"},
		"404":               {route{status: 404, body: "error_not_found.json"}, "cannot"},
		"500":               {route{status: 500, body: "error_server.json"}, "cannot"},
	} {
		t.Run(name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"GET " + standupPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, "calendar.update_event", args)
			out, err := tool.Reconcile.Check(context.Background(), in)
			wantOutcome(t, out, err, tc.want, "evt_standup_001")
		})
	}
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	tool, in := reconcileInput(t, c, "calendar.update_event", args)
	delete(in.ResourceIdentity, "event_id")
	if _, err := tool.Reconcile.Check(context.Background(), in); !errors.Is(err, google.ErrNotReconcilable) {
		t.Errorf("without event_id: err = %v, want ErrNotReconcilable", err)
	}
}

func TestDeleteEvent(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"DELETE " + standupPath: {status: 204, body: ""}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("calendar.delete_event", map[string]any{"event_id": "evt_standup_001", "send_updates": "externalOnly"}))
	if err != nil {
		t.Fatal(err)
	}
	if ids := toolOf(t, c, "calendar.delete_event").ResultIDs(res); ids["id"] != "evt_standup_001" {
		t.Errorf("ResultIDs = %v", ids)
	}
	if got := srv.Last(t, "DELETE "+standupPath).URL.Query().Get("sendUpdates"); got != "externalOnly" {
		t.Errorf("sendUpdates = %q", got)
	}
	_, err = run(t, c, write("calendar.delete_event", map[string]any{}))
	wantClass(t, err, google.ClassInvalidArgument, 0)
	for _, tc := range writeErrorCases("") {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"DELETE " + standupPath: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("calendar.delete_event", map[string]any{"event_id": "evt_standup_001"}))
			checkWriteError(t, tc, res, err)
		})
	}
	for name, tc := range map[string]struct {
		rt   route
		want string
	}{
		"gone 410":  {route{status: 410, body: "error_not_found.json"}, "found"},
		"gone 404":  {route{status: 404, body: "error_not_found.json"}, "found"},
		"cancelled": {route{status: 200, body: "event_cancelled.json"}, "found"},
		"present":   {route{status: 200, body: "event.json"}, "not_found"},
		"500":       {route{status: 500, body: "error_server.json"}, "cannot"},
	} {
		t.Run("check "+name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"GET " + standupPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, "calendar.delete_event", map[string]any{"event_id": "evt_standup_001"})
			out, err := tool.Reconcile.Check(context.Background(), in)
			wantOutcome(t, out, err, tc.want, "evt_standup_001")
		})
	}
}

func TestRespondToEvent(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		"GET " + standupPath:   {status: 200, body: "event_invited.json"},
		"PATCH " + standupPath: {status: 200, body: "event_invited_accepted.json"},
	})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("calendar.respond_to_event", map[string]any{"event_id": "evt_standup_001", "response": "accepted", "comment": "see you"}))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		ID, Response string
	}
	decode(t, res, &out)
	if out.ID != "evt_standup_001" || out.Response != "accepted" {
		t.Errorf("out = %+v", out)
	}
	body := bodyOf(t, srv.Last(t, "PATCH "+standupPath))
	att, _ := body["attendees"].([]any)
	if len(att) != 2 {
		t.Fatalf("attendees = %v: the whole list must be sent", att)
	}
	self := att[1].(map[string]any)
	if self["email"] != "alice@example.test" || self["responseStatus"] != "accepted" || self["comment"] != "see you" {
		t.Errorf("self = %v", self)
	}
	if other := att[0].(map[string]any); other["responseStatus"] != "accepted" || other["email"] != "carol@example.test" {
		t.Errorf("other attendee changed: %v", other)
	}

	_, err = run(t, c, write("calendar.respond_to_event", map[string]any{"event_id": "evt_standup_001", "response": "maybe"}))
	wantClass(t, err, google.ClassInvalidArgument, 0)
	noSelf := newAPIServer(t, map[string]route{"GET " + standupPath: {status: 200, body: "created_event.json"}})
	c3, _ := newConnector(t, noSelf, connectors.Bounds{})
	_, err = run(t, c3, write("calendar.respond_to_event", map[string]any{"event_id": "evt_standup_001", "response": "declined"}))
	wantClass(t, err, google.ClassInvalidArgument, 0)
	if noSelf.Count("PATCH "+standupPath) != 0 {
		t.Error("nothing is patched when the account is not an attendee")
	}

	for name, tc := range map[string]struct {
		rt   route
		want string
	}{
		"responded":     {route{status: 200, body: "event_invited_accepted.json"}, "found"},
		"not responded": {route{status: 200, body: "event_invited.json"}, "not_found"},
		"500":           {route{status: 500, body: "error_server.json"}, "cannot"},
	} {
		t.Run("check "+name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"GET " + standupPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, "calendar.respond_to_event", map[string]any{"event_id": "evt_standup_001", "response": "accepted"})
			out, err := tool.Reconcile.Check(context.Background(), in)
			wantOutcome(t, out, err, tc.want, "evt_standup_001")
		})
	}
}
