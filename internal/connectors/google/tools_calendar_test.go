package google_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

const (
	listEventsPath = "GET /calendar/v3/calendars/primary/events"
	getEventPath   = "GET /calendar/v3/calendars/primary/events/evt_standup_001"
)

func TestListEvents(t *testing.T) {
	srv := newAPIServer(t, map[string]route{listEventsPath: {status: 200, body: "events_list.json"}})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("calendar.list_events", map[string]any{
		"time_min": "2026-10-09T00:00:00Z", "time_max": "2026-10-12T00:00:00Z", "q": "standup", "max_results": 10,
	}))
	if err != nil {
		t.Fatalf("list_events: %v", err)
	}
	if res.Empty || res.Partial || res.Unavailable {
		t.Errorf("markers = %+v", res)
	}
	if len(tk.calls) != 1 || tk.calls[0] != alice+"/"+acct {
		t.Errorf("token source calls = %v, want one for %s/%s", tk.calls, alice, acct)
	}
	q := query(t, srv, "/calendar/v3/calendars/primary/events")
	for k, want := range map[string]string{
		"singleEvents": "true", "orderBy": "startTime", "timeMin": "2026-10-09T00:00:00Z", "timeMax": "2026-10-12T00:00:00Z",
		"q": "standup", "maxResults": "10",
	} {
		if got := q.Get(k); got != want {
			t.Errorf("query %s = %q, want %q", k, got, want)
		}
	}
	var page google.EventsPage
	decode(t, res, &page)
	if page.CalendarID != "primary" || page.TimeZone != "America/Los_Angeles" || !page.HasMore || page.NextPageToken != "page-two" {
		t.Errorf("page meta = %+v", page)
	}
	if len(page.Items) != 2 {
		t.Fatalf("items = %d, want 2", len(page.Items))
	}
	first := page.Items[0]
	if first.ID != "evt_standup_001" || first.Summary != "Team standup" || first.Start != "2026-10-09T09:30:00-07:00" || first.End != "2026-10-09T09:45:00-07:00" ||
		first.AllDay || first.Status != "confirmed" || first.Organizer != "alice@example.test" || first.Location != "Room 4" ||
		first.URL != "https://www.google.com/calendar/event?eid=evt_standup_001" || first.MeetingURL != "https://meet.google.com/abc-defg-hij" ||
		first.RecurringEventID != "evt_standup" || len(first.Attendees) != 2 || first.Attendees[1].Email != "bob@example.test" ||
		first.Attendees[1].ResponseStatus != "needsAction" || !first.Attendees[1].Optional || first.Attendees[1].Name != "Bob" {
		t.Errorf("first event = %+v", first)
	}
	second := page.Items[1]
	if !second.AllDay || second.Start != "2026-10-10" || second.End != "2026-10-11" || second.Status != "tentative" || second.Organizer != "carol@example.test" {
		t.Errorf("all-day event = %+v", second)
	}
	// Descriptions are listed; the harness gets get_event for the full text.
	if first.Description != "Daily sync." {
		t.Errorf("description = %q", first.Description)
	}
}

func TestListEventsDefaultsAndClamp(t *testing.T) {
	srv := newAPIServer(t, map[string]route{listEventsPath: {status: 200, body: "events_list.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{MaxPageSize: 20})
	before := time.Now().UTC().Add(-time.Second)
	res, err := run(t, c, call("calendar.list_events", map[string]any{"max_results": 500}))
	if err != nil {
		t.Fatalf("list_events: %v", err)
	}
	if !res.Partial {
		t.Error("a clamped max_results should mark the result partial")
	}
	q := query(t, srv, "/calendar/v3/calendars/primary/events")
	if got := q.Get("maxResults"); got != "20" {
		t.Errorf("maxResults = %q, want clamped 20", got)
	}
	// Without time bounds the listing starts now (never the whole past).
	tm, err := time.Parse(time.RFC3339, q.Get("timeMin"))
	if err != nil || tm.Before(before) || tm.After(time.Now().Add(time.Minute)) {
		t.Errorf("timeMin = %q (%v), want about now", q.Get("timeMin"), err)
	}
	if q.Get("timeMax") != "" {
		t.Errorf("timeMax = %q, want unset", q.Get("timeMax"))
	}
	// The default page size is the package default under the bound.
	srv2 := newAPIServer(t, map[string]route{listEventsPath: {status: 200, body: "events_list.json"}})
	c2, _ := newConnector(t, srv2, connectors.Bounds{})
	if _, err := run(t, c2, call("calendar.list_events", nil)); err != nil {
		t.Fatal(err)
	}
	if got := query(t, srv2, "/calendar/v3/calendars/primary/events").Get("maxResults"); got != "25" {
		t.Errorf("default maxResults = %q, want 25", got)
	}
}

func TestListEventsOtherCalendarAndPageToken(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		"GET /calendar/v3/calendars/team@example.test/events": {status: 200, body: "events_list_empty.json"},
	})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("calendar.list_events", map[string]any{"calendar_id": "Team@example.test", "page_token": "page-two", "time_min": "2026-10-09T00:00:00Z"}))
	if err != nil {
		t.Fatalf("list_events: %v", err)
	}
	if !res.Empty || res.Partial {
		t.Errorf("markers = %+v, want Empty", res)
	}
	var page google.EventsPage
	decode(t, res, &page)
	if page.CalendarID != "team@example.test" || page.HasMore || len(page.Items) != 0 {
		t.Errorf("page = %+v", page)
	}
	if got := query(t, srv, "/calendar/v3/calendars/team@example.test/events").Get("pageToken"); got != "page-two" {
		t.Errorf("pageToken = %q", got)
	}
}

func TestListEventsRejectsBadArguments(t *testing.T) {
	c, tk := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	for name, args := range map[string]map[string]any{
		"bad time_min":    {"time_min": "yesterday"},
		"bad time_max":    {"time_max": "2026-13-45"},
		"max_results 0":   {"max_results": 0},
		"max_results str": {"max_results": "lots"},
		"min after max":   {"time_min": "2026-10-12T00:00:00Z", "time_max": "2026-10-09T00:00:00Z"},
		"calendar slash":  {"calendar_id": "a/b"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := run(t, c, call("calendar.list_events", args))
			wantClass(t, err, google.ClassInvalidArgument, 0)
		})
	}
	if len(tk.calls) != 0 {
		t.Errorf("token source called %d times for invalid arguments, want 0", len(tk.calls))
	}
}

func TestListEventsErrors(t *testing.T) {
	for _, tc := range readErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{listEventsPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := run(t, c, call("calendar.list_events", nil))
			checkReadError(t, tc, res, err)
		})
	}
	t.Run("network", func(t *testing.T) {
		srv := newAPIServer(t, nil)
		c, _ := newConnector(t, srv, connectors.Bounds{})
		srv.Close()
		res, err := run(t, c, call("calendar.list_events", nil))
		if err != nil || !res.Unavailable {
			t.Errorf("res = %+v, err = %v; want Unavailable", res, err)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{listEventsPath: {status: 200, body: "events_list.json", delay: 2 * time.Second}})
		c, err := google.New(google.Options{Tokens: (&tokens{}).source, BaseURL: srv.URL + "/", Timeout: 200 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		res, err := run(t, c, call("calendar.list_events", nil))
		if err == nil || !strings.Contains(err.Error(), "deadline") {
			t.Errorf("res = %+v, err = %v; want a deadline error", res, err)
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{listEventsPath: {status: 200, body: "events_list.json", delay: 2 * time.Second}})
		c, _ := newConnector(t, srv, connectors.Bounds{})
		ctx, cancel := context.WithCancel(context.Background())
		go func() { time.Sleep(50 * time.Millisecond); cancel() }()
		_, err := appOf(t, c, google.AppCalendar).Call(ctx, call("calendar.list_events", nil))
		if err == nil || !strings.Contains(err.Error(), "cancel") {
			t.Errorf("err = %v, want a cancellation", err)
		}
	})
}

func TestListEventsTruncatesToBounds(t *testing.T) {
	srv := newAPIServer(t, map[string]route{listEventsPath: {status: 200, body: "events_list.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{MaxResultBytes: 1100})
	res, err := run(t, c, call("calendar.list_events", nil))
	if err != nil {
		t.Fatal(err)
	}
	var page google.EventsPage
	decode(t, res, &page)
	if !res.Partial || !page.Truncated || len(page.Items) != 1 {
		t.Errorf("res = %+v page = %+v, want one item and truncated", res, page)
	}
	if b, _ := json.Marshal(res.Content); len(b) > 1100 {
		t.Errorf("result is %d bytes, over the bound", len(b))
	}
}

func TestGetEvent(t *testing.T) {
	srv := newAPIServer(t, map[string]route{getEventPath: {status: 200, body: "event.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("calendar.get_event", map[string]any{"event_id": "evt_standup_001"}))
	if err != nil {
		t.Fatalf("get_event: %v", err)
	}
	var ev google.Event
	decode(t, res, &ev)
	if ev.ID != "evt_standup_001" || ev.CalendarID != "primary" || !strings.Contains(ev.Description, "- blockers") || ev.Created != "2026-09-01T08:00:00Z" ||
		ev.Updated != "2026-10-01T08:00:00Z" || ev.MeetingURL != "https://meet.google.com/abc-defg-hij" || len(ev.Attendees) != 2 {
		t.Errorf("event = %+v", ev)
	}
	if res.Partial || res.Empty || ev.Truncated {
		t.Errorf("markers = %+v truncated %v", res, ev.Truncated)
	}
}

func TestGetEventTruncatesDescription(t *testing.T) {
	srv := newAPIServer(t, map[string]route{getEventPath: {status: 200, body: "event.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{MaxResultBytes: 600})
	res, err := run(t, c, call("calendar.get_event", map[string]any{"event_id": "evt_standup_001"}))
	if err != nil {
		t.Fatal(err)
	}
	var ev google.Event
	decode(t, res, &ev)
	if !res.Partial || !ev.Truncated || strings.Contains(ev.Description, "- plans") || ev.ID != "evt_standup_001" {
		t.Errorf("res = %+v event = %+v, want a cut description and everything else kept", res, ev)
	}
}

func TestGetEventArgumentsAndErrors(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	for name, args := range map[string]map[string]any{
		"missing id": {},
		"blank id":   {"event_id": "  "},
		"id slash":   {"event_id": "a/b"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := run(t, c, call("calendar.get_event", args))
			wantClass(t, err, google.ClassInvalidArgument, 0)
		})
	}
	for _, tc := range readErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{getEventPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := run(t, c, call("calendar.get_event", map[string]any{"event_id": "evt_standup_001"}))
			checkReadError(t, tc, res, err)
		})
	}
}

func TestCalendarResourceIdentity(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	list := toolOf(t, c, "calendar.list_events")
	if got := list.ResourceIdentity(map[string]any{}); got["calendar_id"] != "primary" || got["domain"] != "" {
		t.Errorf("identity(default) = %v, want calendar_id primary and no domain", got)
	}
	if got := list.ResourceIdentity(map[string]any{"calendar_id": "Team@Example.test", "q": "secret text"}); got["calendar_id"] != "team@example.test" || got["domain"] != "example.test" || len(got) != 2 {
		t.Errorf("identity(team) = %v, want calendar_id and domain only", got)
	}
	get := toolOf(t, c, "calendar.get_event")
	if got := get.ResourceIdentity(map[string]any{"event_id": "evt_1"}); got["calendar_id"] != "primary" || got["event_id"] != "evt_1" {
		t.Errorf("identity(get) = %v", got)
	}
	if list.RequiredScopes[0] != google.ScopeCalendarEventsReadonly || get.RequiredScopes[0] != google.ScopeCalendarEventsReadonly {
		t.Errorf("scopes = %v / %v", list.RequiredScopes, get.RequiredScopes)
	}
	var schema struct {
		Properties map[string]map[string]any `json:"properties"`
		Required   []string                  `json:"required"`
	}
	if err := json.Unmarshal(get.InputSchema, &schema); err != nil || schema.Properties["event_id"] == nil || len(schema.Required) != 1 || schema.Required[0] != "event_id" {
		t.Errorf("get_event schema = %s (%v)", get.InputSchema, err)
	}
}
