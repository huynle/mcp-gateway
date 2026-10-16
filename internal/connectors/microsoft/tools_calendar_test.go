package microsoft_test

import (
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/microsoft"
)

func TestCalendarToolsMetadata(t *testing.T) {
	r, w := connectors.KindRead, connectors.KindWrite
	checkMeta(t, []toolMeta{
		{tool: "calendar_list_calendars", kind: r, scopes: []string{"Calendars.Read"}, identity: map[string]string{}},
		{tool: "calendar_get_event", kind: r, scopes: []string{"Calendars.Read"}, required: []string{"event_id"},
			args: map[string]any{"event_id": "e-1"}, identity: map[string]string{"event": "e-1"}},
		{tool: "calendar_find_meeting_times", kind: r, scopes: []string{"Calendars.Read.Shared"}, required: []string{"attendees", "start", "end"},
			args: map[string]any{"attendees": []any{"secret@example.test"}}, identity: map[string]string{"calendar": "default"}},
		{tool: "calendar_update_event", kind: w, reconcile: connectors.ReconcileNone, scopes: []string{"Calendars.ReadWrite"}, required: []string{"event_id"},
			args: map[string]any{"event_id": "e-1", "subject": "secret"}, identity: map[string]string{"event": "e-1"}},
		{tool: "calendar_delete_event", kind: w, reconcile: connectors.ReconcileStableID, scopes: []string{"Calendars.ReadWrite"}, required: []string{"event_id"},
			args: map[string]any{"event_id": "e-1"}, identity: map[string]string{"event": "e-1"}},
		{tool: "calendar_respond_event", kind: w, reconcile: connectors.ReconcileStableID, scopes: []string{"Calendars.ReadWrite"}, required: []string{"event_id", "response"},
			args: map[string]any{"event_id": "e-1", "response": "decline", "comment": "secret"}, identity: map[string]string{"event": "e-1", "response": "decline"}},
	})
}

func TestCalendarListCalendarsAndGetEvent(t *testing.T) {
	_, res := mustRun(t, map[string]route{"GET /v1.0/me/calendars": {status: 200, body: `{"value":[{"id":"cal-1","name":"Calendar","isDefaultCalendar":true,"canEdit":true,"owner":{"name":"Alice","address":"alice@example.test"}}]}`}},
		"calendar_list_calendars", nil, false)
	var cals struct {
		Items []struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			IsDefault bool   `json:"is_default"`
			CanEdit   bool   `json:"can_edit"`
			Owner     string `json:"owner"`
		} `json:"items"`
	}
	decode(t, res, &cals)
	if len(cals.Items) != 1 || !cals.Items[0].IsDefault || cals.Items[0].Owner != "alice@example.test" {
		t.Errorf("calendars = %+v", cals)
	}

	srv, res := mustRun(t, map[string]route{"GET /v1.0/me/events/e-1": {status: 200, body: `{"id":"e-1","subject":"Review",
		"start":{"dateTime":"2026-10-10T14:00:00","timeZone":"UTC"},"end":{"dateTime":"2026-10-10T15:00:00","timeZone":"UTC"},
		"body":{"contentType":"text","content":"Agenda"},"responseStatus":{"response":"notResponded"},
		"onlineMeeting":{"joinUrl":"https://teams.example.test/join"},
		"attendees":[{"emailAddress":{"name":"Bob","address":"bob@example.test"},"type":"required","status":{"response":"accepted"}}]}`}},
		"calendar_get_event", map[string]any{"event_id": "e-1"}, false)
	var ev struct {
		Subject, Body, Response string
		JoinURL                 string `json:"join_url"`
		Attendees               []struct{ Address, Type, Response string }
	}
	decode(t, res, &ev)
	if ev.Subject != "Review" || ev.Body != "Agenda" || ev.Response != "notResponded" || ev.JoinURL == "" || len(ev.Attendees) != 1 || ev.Attendees[0].Response != "accepted" {
		t.Errorf("event = %+v", ev)
	}
	if p := srv.Last(t, "GET /v1.0/me/events/e-1").Header.Get("Prefer"); !strings.Contains(p, "text") || !strings.Contains(p, "UTC") {
		t.Errorf("Prefer = %q, want text body and UTC", p)
	}
	_, _, err := run(t, map[string]route{"GET /v1.0/me/events/e-1": {status: 404, body: "error_item_not_found.json"}}, "calendar_get_event", map[string]any{"event_id": "e-1"}, false)
	wantClass(t, err, microsoft.ClassNotFound, 404)
}

func TestCalendarFindMeetingTimes(t *testing.T) {
	path := "POST /v1.0/me/findMeetingTimes"
	srv, res := mustRun(t, map[string]route{path: {status: 200, body: `{"emptySuggestionsReason":"","meetingTimeSuggestions":[
		{"confidence":100,"organizerAvailability":"free","meetingTimeSlot":{"start":{"dateTime":"2026-10-12T15:00:00","timeZone":"UTC"},"end":{"dateTime":"2026-10-12T15:30:00","timeZone":"UTC"}},
		 "attendeeAvailability":[{"attendee":{"emailAddress":{"address":"bob@example.test"}},"availability":"free"}]}]}`}},
		"calendar_find_meeting_times", map[string]any{"attendees": []any{"bob@example.test"}, "start": "2026-10-12T09:00:00Z", "end": "2026-10-12T17:00:00Z", "duration_minutes": 30}, false)
	b := jsonBody(t, srv.Last(t, path))
	if b["meetingDuration"] != "PT30M" {
		t.Errorf("meetingDuration = %v", b["meetingDuration"])
	}
	if att, _ := b["attendees"].([]any); len(att) != 1 {
		t.Errorf("attendees = %v", b["attendees"])
	}
	var out struct {
		Items []struct {
			Start, End string
			Confidence float64
			Attendees  []struct{ Address, Availability string }
		} `json:"items"`
	}
	decode(t, res, &out)
	if len(out.Items) != 1 || out.Items[0].Start != "2026-10-12T15:00:00" || out.Items[0].Attendees[0].Availability != "free" {
		t.Errorf("out = %+v", out)
	}
	_, res = mustRun(t, map[string]route{path: {status: 200, body: `{"emptySuggestionsReason":"AttendeesUnavailable","meetingTimeSuggestions":[]}`}},
		"calendar_find_meeting_times", map[string]any{"attendees": []any{"bob@example.test"}, "start": "2026-10-12T09:00:00Z", "end": "2026-10-12T17:00:00Z"}, false)
	var empty struct {
		Reason string `json:"empty_reason"`
	}
	decode(t, res, &empty)
	if !res.Empty || empty.Reason != "AttendeesUnavailable" {
		t.Errorf("empty = %+v %+v", res, empty)
	}
	wantInvalid(t, "calendar_find_meeting_times", map[string]any{"attendees": []any{"bob@example.test"}, "start": "2026-10-12T09:00:00Z", "end": "2026-10-12T08:00:00Z"}, false)
	wantInvalid(t, "calendar_find_meeting_times", map[string]any{"attendees": []any{"bob@example.test"}, "start": "2026-10-12T09:00:00Z", "end": "2026-10-12T17:00:00Z", "duration_minutes": 0}, false)
}

func TestCalendarFindMeetingTimesIsWorkOnly(t *testing.T) {
	srv := newAPIServer(t, nil)
	c, _ := newConnectorWithScopes(t, srv, connectors.Bounds{}, []string{"User.Read", "Calendars.ReadWrite"})
	_, err := c.Call(t.Context(), call("calendar_find_meeting_times", map[string]any{"attendees": []any{"b@example.test"}, "start": "2026-10-12T09:00:00Z", "end": "2026-10-12T17:00:00Z"}))
	wantClass(t, err, microsoft.ClassScopeRequired, 0)
	if !strings.Contains(err.Error(), "personal") {
		t.Errorf("message %q should say personal accounts cannot grant it", err)
	}
}

func TestCalendarUpdateEvent(t *testing.T) {
	path := "PATCH /v1.0/me/events/e-1"
	srv, res := mustRun(t, map[string]route{path: {status: 200, body: `{"id":"e-1","webLink":"https://outlook.example.test/e-1"}`}},
		"calendar_update_event", map[string]any{"event_id": "e-1", "subject": "Moved", "start": "2026-10-10T16:00:00", "end": "2026-10-10T17:00:00", "time_zone": "Europe/Paris"}, true)
	b := jsonBody(t, srv.Last(t, path))
	start, _ := b["start"].(map[string]any)
	if b["subject"] != "Moved" || start["dateTime"] != "2026-10-10T16:00:00" || start["timeZone"] != "Europe/Paris" {
		t.Errorf("patch = %v", b)
	}
	if _, ok := b["attendees"]; ok {
		t.Error("attendees sent although not given")
	}
	if ids := toolNamed(t, mustConnector(t), "calendar_update_event").ResultIDs(res); ids["id"] != "e-1" {
		t.Errorf("ResultIDs = %v", ids)
	}
	wantInvalid(t, "calendar_update_event", map[string]any{"event_id": "e-1"}, true)
	wantInvalid(t, "calendar_update_event", map[string]any{"event_id": "e-1", "start": "2026-10-10T16:00:00"}, true)
	runWriteErrorCases(t, path, route{status: 200, body: `{"id":"e-1"}`}, "calendar_update_event", map[string]any{"event_id": "e-1", "location": "Room 2"})
}

func TestCalendarDeleteAndRespond(t *testing.T) {
	srv, _ := mustRun(t, map[string]route{"DELETE /v1.0/me/events/e-1": {status: 204}}, "calendar_delete_event", map[string]any{"event_id": "e-1"}, true)
	if srv.Count("DELETE /v1.0/me/events/e-1") != 1 {
		t.Error("no DELETE")
	}
	get := "GET /v1.0/me/events/e-1"
	got, err := check(t, map[string]route{get: {status: 404, body: "error_item_not_found.json"}}, "calendar_delete_event", map[string]string{"event": "e-1"})
	wantFound(t, got, err, "e-1")
	got, err = check(t, map[string]route{get: {status: 200, body: `{"id":"e-1"}`}}, "calendar_delete_event", map[string]string{"event": "e-1"})
	wantNotFound(t, got, err)

	srv, _ = mustRun(t, map[string]route{"POST /v1.0/me/events/e-1/tentativelyAccept": {status: 202}}, "calendar_respond_event",
		map[string]any{"event_id": "e-1", "response": "tentative", "comment": "Maybe", "send_response": false}, true)
	b := jsonBody(t, srv.Last(t, "POST /v1.0/me/events/e-1/tentativelyAccept"))
	if b["comment"] != "Maybe" || b["sendResponse"] != false {
		t.Errorf("respond body = %v", b)
	}
	got, err = check(t, map[string]route{get: {status: 200, body: `{"id":"e-1","responseStatus":{"response":"accepted"}}`}}, "calendar_respond_event", map[string]string{"event": "e-1", "response": "accept"})
	wantFound(t, got, err, "e-1")
	got, err = check(t, map[string]route{get: {status: 200, body: `{"id":"e-1","responseStatus":{"response":"notResponded"}}`}}, "calendar_respond_event", map[string]string{"event": "e-1", "response": "accept"})
	wantNotFound(t, got, err)
	got, err = check(t, map[string]route{get: {status: 404, body: "error_item_not_found.json"}}, "calendar_respond_event", map[string]string{"event": "e-1", "response": "decline"})
	wantFound(t, got, err, "e-1")
	if _, err := check(t, map[string]route{get: {status: 404, body: "error_item_not_found.json"}}, "calendar_respond_event", map[string]string{"event": "e-1", "response": "accept"}); err == nil {
		t.Error("an accepted event that vanished cannot tell")
	}
	wantInvalid(t, "calendar_respond_event", map[string]any{"event_id": "e-1", "response": "maybe"}, true)
	runWriteErrorCases(t, "POST /v1.0/me/events/e-1/decline", route{status: 202}, "calendar_respond_event", map[string]any{"event_id": "e-1", "response": "decline"})
}
