package google_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

// Increment 4: add_meet_link on calendar.create_event and
// calendar.update_event.

// meetRequest is the conferenceData.createRequest of a request body.
func meetRequest(t *testing.T, r recorded) (requestID, solution string, ok bool) {
	t.Helper()
	body := bodyOf(t, r)
	conf, _ := body["conferenceData"].(map[string]any)
	if conf == nil {
		return "", "", false
	}
	create, _ := conf["createRequest"].(map[string]any)
	key, _ := create["conferenceSolutionKey"].(map[string]any)
	requestID, _ = create["requestId"].(string)
	solution, _ = key["type"].(string)
	return requestID, solution, true
}

func TestMeetRequestID(t *testing.T) {
	id := google.MeetRequestID(opID)
	if id == "" || id != google.MeetRequestID(opID) {
		t.Fatalf("MeetRequestID = %q, want a stable non-empty id", id)
	}
	if id == google.MeetRequestID("another-op") {
		t.Error("different operations must give different request ids")
	}
	if id != "mcpgw-"+google.EventID(opID) {
		t.Errorf("MeetRequestID = %q, want mcpgw-<EventID(op)> (never the operation id itself)", id)
	}
}

func TestMeetLinkSchema(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	for _, full := range []string{"calendar.create_event", "calendar.update_event"} {
		var schema struct {
			Properties map[string]struct {
				Type string `json:"type"`
			} `json:"properties"`
		}
		if err := json.Unmarshal(toolOf(t, c, full).InputSchema, &schema); err != nil {
			t.Fatal(err)
		}
		if schema.Properties["add_meet_link"].Type != "boolean" {
			t.Errorf("%s: add_meet_link = %+v, want a boolean property", full, schema.Properties["add_meet_link"])
		}
		if id := toolOf(t, c, full).ResourceIdentity(map[string]any{"event_id": "e1", "add_meet_link": true}); id["add_meet_link"] != "" {
			t.Errorf("%s identity = %v", full, id)
		}
	}
}

func TestCreateEventWithMeetLink(t *testing.T) {
	srv := newAPIServer(t, map[string]route{createEventPath: {status: 200, body: "created_event_meet.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("calendar.create_event", map[string]any{
		"summary": "Gateway review", "start": "2026-10-10T10:00:00-07:00", "end": "2026-10-10T11:00:00-07:00", "add_meet_link": true,
	}))
	if err != nil {
		t.Fatalf("create_event: %v", err)
	}
	req := srv.Last(t, createEventPath)
	if got := req.URL.Query().Get("conferenceDataVersion"); got != "1" {
		t.Errorf("conferenceDataVersion = %q, want 1 (Google ignores createRequest otherwise)", got)
	}
	requestID, solution, ok := meetRequest(t, req)
	if !ok || requestID != google.MeetRequestID(opID) || solution != "hangoutsMeet" {
		t.Errorf("createRequest = %q %q (present %v), want %q hangoutsMeet: %s", requestID, solution, ok, google.MeetRequestID(opID), req.Body)
	}
	if bodyOf(t, req)["id"] != wantEventID {
		t.Errorf("the event id is still the operation's: %s", req.Body)
	}
	created, ok := res.Content.(google.CreatedEvent)
	if !ok || created.MeetURL != "https://meet.google.com/xyz-abcd-efg" || created.MeetStatus != "success" {
		t.Errorf("content = %#v, want meet_url and meet_status success", res.Content)
	}
	ids := toolOf(t, c, "calendar.create_event").ResultIDs(res)
	if ids["id"] != wantEventID || ids["meet_url"] != created.MeetURL {
		t.Errorf("ResultIDs = %v, want id and meet_url", ids)
	}
	if toolOf(t, c, "calendar.create_event").Reconcile.Kind != connectors.ReconcileStableID {
		t.Error("create_event keeps its stable-id reconciliation")
	}
}

func TestCreateEventMeetLinkPendingAndAbsent(t *testing.T) {
	srv := newAPIServer(t, map[string]route{createEventPath: {status: 200, body: "created_event_meet_pending.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("calendar.create_event", map[string]any{"summary": "Offsite", "start": "2026-10-10", "end": "2026-10-11", "add_meet_link": true}))
	if err != nil {
		t.Fatal(err)
	}
	created, _ := res.Content.(google.CreatedEvent)
	if created.MeetURL != "" || created.MeetStatus != "pending" {
		t.Errorf("content = %#v, want no meet_url yet and meet_status pending", res.Content)
	}
	if ids := toolOf(t, c, "calendar.create_event").ResultIDs(res); len(ids) != 2 {
		t.Errorf("ResultIDs = %v, want just id and url without a link", ids)
	}

	plain := newAPIServer(t, map[string]route{createEventPath: {status: 200, body: "created_event.json"}})
	c2, _ := newConnector(t, plain, connectors.Bounds{})
	for _, args := range []map[string]any{
		{"summary": "x", "start": "2026-10-10", "end": "2026-10-11"},
		{"summary": "x", "start": "2026-10-10", "end": "2026-10-11", "add_meet_link": false},
	} {
		if _, err := run(t, c2, write("calendar.create_event", args)); err != nil {
			t.Fatal(err)
		}
		req := plain.Last(t, createEventPath)
		if req.URL.Query().Has("conferenceDataVersion") {
			t.Errorf("conferenceDataVersion sent without add_meet_link: %s", req.URL.RawQuery)
		}
		if _, _, ok := meetRequest(t, req); ok {
			t.Errorf("conferenceData sent without add_meet_link: %s", req.Body)
		}
	}

	c3, tk := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	_, err = run(t, c3, write("calendar.create_event", map[string]any{"summary": "x", "start": "2026-10-10", "end": "2026-10-11", "add_meet_link": "yes"}))
	wantClass(t, err, google.ClassInvalidArgument, 0)
	_, err = run(t, c3, write("calendar.update_event", map[string]any{"event_id": "evt_standup_001", "add_meet_link": "yes"}))
	wantClass(t, err, google.ClassInvalidArgument, 0)
	_, err = run(t, c3, write("calendar.update_event", map[string]any{"event_id": "evt_standup_001", "add_meet_link": false}))
	wantClass(t, err, google.ClassInvalidArgument, 0)
	if len(tk.calls) != 0 {
		t.Errorf("token calls for invalid arguments = %d", len(tk.calls))
	}
}

func TestUpdateEventAddsMeetLink(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		"GET " + standupPath:   {status: 200, body: "created_event.json"}, // no conference yet
		"PATCH " + standupPath: {status: 200, body: "event_marked.json"},
	})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("calendar.update_event", map[string]any{"event_id": "evt_standup_001", "add_meet_link": true}))
	if err != nil {
		t.Fatalf("update_event with only add_meet_link: %v", err)
	}
	patch := srv.Last(t, "PATCH "+standupPath)
	if got := patch.URL.Query().Get("conferenceDataVersion"); got != "1" {
		t.Errorf("conferenceDataVersion = %q, want 1", got)
	}
	requestID, solution, ok := meetRequest(t, patch)
	if !ok || requestID != google.MeetRequestID(opID) || solution != "hangoutsMeet" {
		t.Errorf("createRequest = %q %q: %s", requestID, solution, patch.Body)
	}
	ext, _ := bodyOf(t, patch)["extendedProperties"].(map[string]any)
	private, _ := ext["private"].(map[string]any)
	if private["mcp-gateway-op"] != opID {
		t.Errorf("private properties = %v, want the operation marker still set (reconciliation)", private)
	}
	created, _ := res.Content.(google.CreatedEvent)
	if created.MeetURL != "https://meet.google.com/abc-defg-hij" {
		t.Errorf("content = %#v, want meet_url", res.Content)
	}
	if toolOf(t, c, "calendar.update_event").Reconcile.Kind != connectors.ReconcileMarker {
		t.Error("update_event keeps its marker reconciliation")
	}
	if f := srv.Last(t, "GET "+standupPath).URL.Query().Get("fields"); !strings.Contains(f, "hangoutLink") || !strings.Contains(f, "extendedProperties") {
		t.Errorf("lookup fields = %q, want the marker and the existing Meet", f)
	}

	// An event that already has a Meet keeps it: no new conference.
	has := newAPIServer(t, map[string]route{
		"GET " + standupPath:   {status: 200, body: "event.json"},
		"PATCH " + standupPath: {status: 200, body: "event_marked.json"},
	})
	ch, _ := newConnector(t, has, connectors.Bounds{})
	res, err = run(t, ch, write("calendar.update_event", map[string]any{"event_id": "evt_standup_001", "add_meet_link": true}))
	if err != nil {
		t.Fatal(err)
	}
	patch = has.Last(t, "PATCH "+standupPath)
	if _, _, ok := meetRequest(t, patch); ok {
		t.Errorf("a new conference was requested for an event that has one: %s", patch.Body)
	}
	if created, _ := res.Content.(google.CreatedEvent); created.MeetURL != "https://meet.google.com/abc-defg-hij" {
		t.Errorf("content = %#v, want the existing meet_url", res.Content)
	}

	// Without add_meet_link the patch carries no conference data.
	if _, err := run(t, c, write("calendar.update_event", map[string]any{"event_id": "evt_standup_001", "summary": "x"})); err != nil {
		t.Fatal(err)
	}
	patch = srv.Last(t, "PATCH "+standupPath)
	if patch.URL.Query().Has("conferenceDataVersion") {
		t.Errorf("conferenceDataVersion sent without add_meet_link: %s", patch.URL.RawQuery)
	}
	if _, _, ok := meetRequest(t, patch); ok {
		t.Errorf("conferenceData sent without add_meet_link: %s", patch.Body)
	}
}
