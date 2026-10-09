package google_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

// writeErrorCases are the vendor answers every write maps the same way.
func writeErrorCases(okBody string) []struct {
	name    string
	rt      route
	class   string
	status  int
	unknown bool
	rateLim bool
} {
	return []struct {
		name    string
		rt      route
		class   string
		status  int
		unknown bool
		rateLim bool
	}{
		{name: "400 invalid argument", rt: route{status: 400, body: "error_bad_request.json"}, class: google.ClassInvalidArgument, status: 400},
		{name: "403 forbidden", rt: route{status: 403, body: "error_forbidden.json"}, class: google.ClassForbidden, status: 403},
		{name: "403 scope", rt: route{status: 403, body: "error_insufficient_scope.json"}, class: google.ClassScopeRequired, status: 403},
		{name: "404 not found", rt: route{status: 404, body: "error_not_found.json"}, class: google.ClassNotFound, status: 404},
		{name: "401 reconnect", rt: route{status: 401, body: "error_unauthorized.json"}, class: google.ClassReconnectRequired, status: 401},
		{name: "409 conflict", rt: route{status: 409, body: "error_conflict.json"}, class: google.ClassConflict, status: 409},
		{name: "429 rate limited", rt: route{status: 429, body: "error_rate_limit_429.json", headers: map[string]string{"Retry-After": "7"}}, rateLim: true},
		{name: "500 outcome unknown", rt: route{status: 500, body: "error_server.json"}, unknown: true},
		{name: "502 outcome unknown", rt: route{status: 502, body: "error_server.json"}, unknown: true},
		{name: "timeout outcome unknown", rt: route{status: 200, body: okBody, delay: 2 * time.Second}, unknown: true},
	}
}

// checkWriteError asserts the outcome of one writeErrorCases entry.
func checkWriteError(t *testing.T, tc struct {
	name    string
	rt      route
	class   string
	status  int
	unknown bool
	rateLim bool
}, res connectors.Result, err error) {
	t.Helper()
	switch {
	case tc.unknown:
		if !errors.Is(err, connectors.ErrOutcomeUnknown) {
			t.Fatalf("err = %v (%T), want ErrOutcomeUnknown", err, err)
		}
		if res.Unavailable || res.Content != nil {
			t.Errorf("res = %+v, want an empty result with the error", res)
		}
	case tc.rateLim:
		var rl *connectors.RateLimited
		if !errors.As(err, &rl) || rl.App != google.Vendor || rl.RetryAfter != 7*time.Second {
			t.Fatalf("err = %v (%T), want *connectors.RateLimited of 7s", err, err)
		}
	default:
		wantClass(t, err, tc.class, tc.status)
		if errors.Is(err, connectors.ErrOutcomeUnknown) {
			t.Errorf("a vendor answer of %d is a known outcome, got ErrOutcomeUnknown", tc.status)
		}
	}
	if err != nil && strings.Contains(err.Error(), testToken) {
		t.Errorf("error message leaks the token: %q", err.Error())
	}
}

// shortTimeout builds a connector whose calls time out quickly.
func shortTimeout(t *testing.T, srv *apiServer) *google.Connector {
	t.Helper()
	c, err := google.New(google.Options{Tokens: (&tokens{}).source, BaseURL: srv.URL + "/", Timeout: 300 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestWritesDeclareReconciliationAndNeedAnOperationID(t *testing.T) {
	c, tk := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	want := map[string]connectors.ReconcileKind{
		"calendar.create_event": connectors.ReconcileStableID,
		"tasks.create":          connectors.ReconcileMarker,
		"gmail.send":            connectors.ReconcileMarker,
		"gmail.create_draft":    connectors.ReconcileMarker,
	}
	for full, kind := range want {
		tool := toolOf(t, c, full)
		if tool.Kind != connectors.KindWrite || tool.Reconcile.Kind != kind || tool.Reconcile.Check == nil || tool.ResultIDs == nil {
			t.Errorf("%s: kind %s reconcile %s check %v resultIDs %v", full, tool.Kind, tool.Reconcile.Kind, tool.Reconcile.Check != nil, tool.ResultIDs != nil)
		}
		if _, err := run(t, c, call(full, map[string]any{"summary": "x", "title": "x", "start": "2026-10-10", "end": "2026-10-11", "to": "a@b.test", "subject": "s", "body": "b"})); !errors.Is(err, google.ErrMissingOperation) {
			t.Errorf("%s without an operation id: err = %v, want ErrMissingOperation", full, err)
		}
	}
	if len(tk.calls) != 0 {
		t.Errorf("token source called %d times, want 0", len(tk.calls))
	}
}

// --- calendar.create_event -----------------------------------------------------------

const (
	createEventPath = "POST /calendar/v3/calendars/primary/events"
	wantEventID     = "n8cek7dlhn61olmq3cco8a95d1rd4tdf"
)

func TestEventIDIsDeterministicBase32Hex(t *testing.T) {
	id := google.EventID(opID)
	if id != wantEventID {
		t.Errorf("EventID(%s) = %q, want %q", opID, id, wantEventID)
	}
	if !regexp.MustCompile(`^[a-v0-9]{32}$`).MatchString(id) {
		t.Errorf("EventID = %q is not 32 chars of base32hex a-v0-9", id)
	}
	if google.EventID("another-op") == id {
		t.Error("different operations must give different ids")
	}
}

func TestCreateEvent(t *testing.T) {
	srv := newAPIServer(t, map[string]route{createEventPath: {status: 200, body: "created_event.json"}})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("calendar.create_event", map[string]any{
		"summary": "Gateway review", "start": "2026-10-10T10:00:00-07:00", "end": "2026-10-10T11:00:00-07:00", "time_zone": "America/Los_Angeles",
		"description": "Agenda in the doc.", "location": "Room 4", "attendees": []any{"bob@example.test", " "}, "send_updates": "all",
	}))
	if err != nil {
		t.Fatalf("create_event: %v", err)
	}
	if len(tk.calls) != 1 {
		t.Errorf("token calls = %v", tk.calls)
	}
	req := srv.Last(t, createEventPath)
	if got := req.URL.Query().Get("sendUpdates"); got != "all" {
		t.Errorf("sendUpdates = %q", got)
	}
	var body struct {
		ID          string `json:"id"`
		Summary     string `json:"summary"`
		Description string `json:"description"`
		Location    string `json:"location"`
		Start, End  struct {
			DateTime string `json:"dateTime"`
			Date     string `json:"date"`
			TimeZone string `json:"timeZone"`
		}
		Attendees []struct {
			Email string `json:"email"`
		} `json:"attendees"`
	}
	if err := json.Unmarshal([]byte(req.Body), &body); err != nil {
		t.Fatal(err)
	}
	if body.ID != wantEventID || body.Summary != "Gateway review" || body.Description != "Agenda in the doc." || body.Location != "Room 4" ||
		body.Start.DateTime != "2026-10-10T10:00:00-07:00" || body.Start.TimeZone != "America/Los_Angeles" || body.End.DateTime != "2026-10-10T11:00:00-07:00" ||
		body.Start.Date != "" || len(body.Attendees) != 1 || body.Attendees[0].Email != "bob@example.test" {
		t.Errorf("request body = %s", req.Body)
	}
	created, ok := res.Content.(google.CreatedEvent)
	if !ok || created.ID != wantEventID || created.CalendarID != "primary" || created.URL == "" || created.Start != "2026-10-10T10:00:00-07:00" {
		t.Errorf("content = %#v", res.Content)
	}
	tool := toolOf(t, c, "calendar.create_event")
	ids := tool.ResultIDs(res)
	if ids["id"] != wantEventID || ids["url"] != created.URL || len(ids) != 2 {
		t.Errorf("ResultIDs = %v", ids)
	}
	if tool.ResultIDs(connectors.Result{Content: "junk"}) != nil {
		t.Error("ResultIDs of a foreign result should be nil")
	}
	if got := tool.ResourceIdentity(map[string]any{"calendar_id": "Team@example.test", "summary": "secret"}); got["calendar_id"] != "team@example.test" || got["domain"] != "example.test" || len(got) != 2 {
		t.Errorf("identity = %v", got)
	}
	if tool.RequiredScopes[0] != google.ScopeCalendarEvents {
		t.Errorf("scopes = %v", tool.RequiredScopes)
	}
}

func TestCreateEventAllDayAndDefaults(t *testing.T) {
	srv := newAPIServer(t, map[string]route{createEventPath: {status: 200, body: "created_event.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	if _, err := run(t, c, write("calendar.create_event", map[string]any{"summary": "Offsite", "start": "2026-10-10", "end": "2026-10-11"})); err != nil {
		t.Fatalf("create_event: %v", err)
	}
	req := srv.Last(t, createEventPath)
	if got := req.URL.Query().Get("sendUpdates"); got != "none" {
		t.Errorf("default sendUpdates = %q, want none (attendees are not emailed unless asked)", got)
	}
	var body map[string]any
	_ = json.Unmarshal([]byte(req.Body), &body)
	start, _ := body["start"].(map[string]any)
	end, _ := body["end"].(map[string]any)
	if start["date"] != "2026-10-10" || end["date"] != "2026-10-11" || start["dateTime"] != nil {
		t.Errorf("all-day body = %s", req.Body)
	}
	if _, ok := body["attendees"]; ok {
		t.Errorf("attendees present without any: %s", req.Body)
	}
}

func TestCreateEventArguments(t *testing.T) {
	c, tk := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	ok := map[string]any{"summary": "x", "start": "2026-10-10T10:00:00Z", "end": "2026-10-10T11:00:00Z"}
	for name, change := range map[string]map[string]any{
		"missing summary":    {"summary": ""},
		"missing start":      {"start": nil},
		"missing end":        {"end": nil},
		"bad start":          {"start": "tomorrow"},
		"end before start":   {"end": "2026-10-10T09:00:00Z"},
		"mixed date kinds":   {"start": "2026-10-10"},
		"bad attendee":       {"attendees": []any{"not-an-address"}},
		"attendees not list": {"attendees": 5},
		"bad send_updates":   {"send_updates": "everyone"},
		"calendar slash":     {"calendar_id": "a/b"},
	} {
		t.Run(name, func(t *testing.T) {
			args := map[string]any{}
			for k, v := range ok {
				args[k] = v
			}
			for k, v := range change {
				if v == nil {
					delete(args, k)
				} else {
					args[k] = v
				}
			}
			_, err := run(t, c, write("calendar.create_event", args))
			wantClass(t, err, google.ClassInvalidArgument, 0)
		})
	}
	if len(tk.calls) != 0 {
		t.Errorf("token calls for invalid arguments = %d", len(tk.calls))
	}
}

func TestCreateEventErrors(t *testing.T) {
	for _, tc := range writeErrorCases("created_event.json") {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{createEventPath: tc.rt})
			c := shortTimeout(t, srv)
			res, err := run(t, c, write("calendar.create_event", map[string]any{"summary": "x", "start": "2026-10-10", "end": "2026-10-11"}))
			checkWriteError(t, tc, res, err)
		})
	}
	t.Run("dropped connection is unknown", func(t *testing.T) {
		srv := newAPIServer(t, nil)
		c, _ := newConnector(t, srv, connectors.Bounds{})
		srv.Close()
		res, err := run(t, c, write("calendar.create_event", map[string]any{"summary": "x", "start": "2026-10-10", "end": "2026-10-11"}))
		if !errors.Is(err, connectors.ErrOutcomeUnknown) || res.Unavailable {
			t.Errorf("res = %+v err = %v, want ErrOutcomeUnknown (never Unavailable for a write)", res, err)
		}
	})
}

// --- tasks.create ----------------------------------------------------------------------

const createTaskPath = "POST /tasks/v1/lists/@default/tasks"

func TestCreateTask(t *testing.T) {
	srv := newAPIServer(t, map[string]route{createTaskPath: {status: 200, body: "created_task.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("tasks.create", map[string]any{"title": "Write the report", "notes": "Due before the offsite.\n", "due": "2026-10-10"}))
	if err != nil {
		t.Fatalf("tasks.create: %v", err)
	}
	req := srv.Last(t, createTaskPath)
	var body struct {
		Title, Notes, Due string
	}
	if err := json.Unmarshal([]byte(req.Body), &body); err != nil {
		t.Fatal(err)
	}
	if body.Title != "Write the report" || body.Notes != "Due before the offsite.\n\n"+google.TaskMarker(opID) || body.Due != "2026-10-10T00:00:00Z" {
		t.Errorf("request body = %s", req.Body)
	}
	created, ok := res.Content.(google.CreatedTask)
	if !ok || created.ID != "task_new_001" || created.Tasklist != "@default" || created.URL != "https://tasks.google.com/task/task_new_001" {
		t.Errorf("content = %#v", res.Content)
	}
	tool := toolOf(t, c, "tasks.create")
	if ids := tool.ResultIDs(res); ids["id"] != "task_new_001" || ids["url"] != created.URL {
		t.Errorf("ResultIDs = %v", ids)
	}
	if got := tool.ResourceIdentity(map[string]any{"title": "secret"}); got["tasklist"] != "@default" || len(got) != 1 {
		t.Errorf("identity = %v", got)
	}
	if tool.RequiredScopes[0] != google.ScopeTasks {
		t.Errorf("scopes = %v", tool.RequiredScopes)
	}
	if google.TaskMarker(opID) != "[mcp-gateway op:"+opID+"]" {
		t.Errorf("TaskMarker = %q", google.TaskMarker(opID))
	}
}

func TestCreateTaskWithoutNotesAndArguments(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"POST /tasks/v1/lists/MTIzNDU/tasks": {status: 200, body: "created_task.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	if _, err := run(t, c, write("tasks.create", map[string]any{"tasklist": "MTIzNDU", "title": "t", "due": "2026-10-10T15:00:00+02:00"})); err != nil {
		t.Fatal(err)
	}
	var body struct{ Notes, Due string }
	_ = json.Unmarshal([]byte(srv.Last(t, "POST /tasks/v1/lists/MTIzNDU/tasks").Body), &body)
	if body.Notes != google.TaskMarker(opID) || body.Due != "2026-10-10T00:00:00Z" {
		t.Errorf("body = %+v, want just the marker and the due date at midnight UTC", body)
	}
	for name, args := range map[string]map[string]any{
		"missing title": {"notes": "n"},
		"bad due":       {"title": "t", "due": "next week"},
		"bad tasklist":  {"title": "t", "tasklist": "a b"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := run(t, c, write("tasks.create", args))
			wantClass(t, err, google.ClassInvalidArgument, 0)
		})
	}
}

func TestCreateTaskErrors(t *testing.T) {
	for _, tc := range writeErrorCases("created_task.json") {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{createTaskPath: tc.rt})
			c := shortTimeout(t, srv)
			res, err := run(t, c, write("tasks.create", map[string]any{"title": "t"}))
			checkWriteError(t, tc, res, err)
		})
	}
}

// --- gmail.send / gmail.create_draft -----------------------------------------------------

const (
	sendPath        = "POST /gmail/v1/users/me/messages/send"
	createDraftPath = "POST /gmail/v1/users/me/drafts"
	replyTargetPath = "GET /gmail/v1/users/me/messages/18f1a2b3c4d5e6f7"
)

// rawMessage decodes the raw field of a send / draft request body.
func rawMessage(t *testing.T, body string, draft bool) string {
	t.Helper()
	var req struct {
		Raw      string `json:"raw"`
		ThreadID string `json:"threadId"`
		Message  struct {
			Raw      string `json:"raw"`
			ThreadID string `json:"threadId"`
		} `json:"message"`
	}
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatalf("request body %s: %v", body, err)
	}
	raw := req.Raw
	if draft {
		raw = req.Message.Raw
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(raw, "="))
	if err != nil {
		t.Fatalf("raw is not base64url: %v", err)
	}
	return string(b)
}

func threadOf(t *testing.T, body string, draft bool) string {
	t.Helper()
	var req struct {
		ThreadID string `json:"threadId"`
		Message  struct {
			ThreadID string `json:"threadId"`
		} `json:"message"`
	}
	_ = json.Unmarshal([]byte(body), &req)
	if draft {
		return req.Message.ThreadID
	}
	return req.ThreadID
}

func TestSend(t *testing.T) {
	srv := newAPIServer(t, map[string]route{sendPath: {status: 200, body: "sent_message.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("gmail.send", map[string]any{
		"to": []any{"Bob <bob@example.test>", "carol@other.test"}, "cc": "dave@example.test", "subject": "Gateway review – Friday", "body": "Hi all,\n\nSee you Friday.\n",
	}))
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	req := srv.Last(t, sendPath)
	raw := rawMessage(t, req.Body, false)
	headers, body, _ := strings.Cut(raw, "\r\n\r\n")
	for _, want := range []string{
		"To: Bob <bob@example.test>, carol@other.test", "Cc: dave@example.test", "Message-ID: " + google.MessageID(opID),
		"MIME-Version: 1.0", "Content-Type: text/plain; charset=UTF-8",
	} {
		if !strings.Contains(headers, want+"\r\n") {
			t.Errorf("headers lack %q:\n%s", want, headers)
		}
	}
	if !strings.Contains(headers, "Subject: =?utf-8?") && !strings.Contains(headers, "Subject: Gateway review – Friday") {
		t.Errorf("subject not present: %s", headers)
	}
	if strings.Contains(headers, "In-Reply-To") || threadOf(t, req.Body, false) != "" {
		t.Errorf("a fresh message must not reference a thread: %s / %q", headers, req.Body)
	}
	if decoded := decodeTransfer(t, headers, body); decoded != "Hi all,\r\n\r\nSee you Friday.\r\n" && decoded != "Hi all,\n\nSee you Friday.\n" {
		t.Errorf("body = %q", decoded)
	}
	sent, ok := res.Content.(google.SentMessage)
	if !ok || sent.ID != "18f9sent0001" || sent.ThreadID != "18f9thread001" || sent.MessageID != google.MessageID(opID) {
		t.Errorf("content = %#v", res.Content)
	}
	tool := toolOf(t, c, "gmail.send")
	if ids := tool.ResultIDs(res); ids["id"] != "18f9sent0001" || ids["thread_id"] != "18f9thread001" || ids["message_id"] != google.MessageID(opID) {
		t.Errorf("ResultIDs = %v", ids)
	}
	if got := tool.ResourceIdentity(map[string]any{"to": []any{"Bob <bob@example.test>", "carol@other.test"}, "cc": "dave@example.test", "subject": "secret"}); got["recipient_domains"] != "example.test,other.test" || len(got) != 1 {
		t.Errorf("identity = %v", got)
	}
	if tool.RequiredScopes[0] != google.ScopeGmailSend {
		t.Errorf("scopes = %v", tool.RequiredScopes)
	}
	if google.MessageID(opID) != "<op-"+opID+"@mcp-gateway>" {
		t.Errorf("MessageID = %q", google.MessageID(opID))
	}
}

// decodeTransfer undoes the Content-Transfer-Encoding of a body.
func decodeTransfer(t *testing.T, headers, body string) string {
	t.Helper()
	switch {
	case strings.Contains(headers, "Content-Transfer-Encoding: base64"):
		b, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", ""), "\n", ""))
		if err != nil {
			t.Fatalf("base64 body: %v", err)
		}
		return string(b)
	default:
		return body
	}
}

func TestSendReplyLooksUpTheThread(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		replyTargetPath: {status: 200, body: "reply_target_metadata.json"},
		sendPath:        {status: 200, body: "sent_message.json"},
	})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	_, err := run(t, c, write("gmail.send", map[string]any{"to": "bob@example.test", "subject": "Re: Gateway review", "body": "Yes.", "in_reply_to": "18f1a2b3c4d5e6f7"}))
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if got := query(t, srv, "/gmail/v1/users/me/messages/18f1a2b3c4d5e6f7").Get("format"); got != "metadata" {
		t.Errorf("lookup format = %q", got)
	}
	req := srv.Last(t, sendPath)
	headers, _, _ := strings.Cut(rawMessage(t, req.Body, false), "\r\n\r\n")
	if !strings.Contains(headers, "In-Reply-To: <abc123@example.test>\r\n") || !strings.Contains(headers, "References: <root@example.test> <abc123@example.test>\r\n") {
		t.Errorf("reply headers:\n%s", headers)
	}
	if threadOf(t, req.Body, false) != "18f1a2b3c4d5e6f0" {
		t.Errorf("threadId = %q", threadOf(t, req.Body, false))
	}
	// The lookup is a read: its failure is a known outcome and nothing is sent.
	srv2 := newAPIServer(t, map[string]route{replyTargetPath: {status: 404, body: "error_not_found.json"}})
	c2, _ := newConnector(t, srv2, connectors.Bounds{})
	_, err = run(t, c2, write("gmail.send", map[string]any{"to": "bob@example.test", "subject": "s", "body": "b", "in_reply_to": "18f1a2b3c4d5e6f7"}))
	wantClass(t, err, google.ClassNotFound, 404)
	if errors.Is(err, connectors.ErrOutcomeUnknown) || srv2.Count(sendPath) != 0 {
		t.Errorf("err = %v, sends = %d; want a known failure and no send", err, srv2.Count(sendPath))
	}
}

func TestSendArguments(t *testing.T) {
	c, tk := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	for name, args := range map[string]map[string]any{
		"missing to":       {"subject": "s", "body": "b"},
		"bad to":           {"to": "nobody", "subject": "s", "body": "b"},
		"bad cc":           {"to": "a@b.test", "cc": []any{"x"}, "subject": "s", "body": "b"},
		"missing subject":  {"to": "a@b.test", "body": "b"},
		"missing body":     {"to": "a@b.test", "subject": "s"},
		"bad in_reply_to":  {"to": "a@b.test", "subject": "s", "body": "b", "in_reply_to": "a/b"},
		"header injection": {"to": "a@b.test", "subject": "s\r\nBcc: x@y.test", "body": "b"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := run(t, c, write("gmail.send", args))
			wantClass(t, err, google.ClassInvalidArgument, 0)
			_, err = run(t, c, write("gmail.create_draft", args))
			wantClass(t, err, google.ClassInvalidArgument, 0)
		})
	}
	if len(tk.calls) != 0 {
		t.Errorf("token calls for invalid arguments = %d", len(tk.calls))
	}
}

func TestSendErrors(t *testing.T) {
	for _, tc := range writeErrorCases("sent_message.json") {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{sendPath: tc.rt})
			c := shortTimeout(t, srv)
			res, err := run(t, c, write("gmail.send", map[string]any{"to": "a@b.test", "subject": "s", "body": "b"}))
			checkWriteError(t, tc, res, err)
		})
	}
}

func TestCreateDraft(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		replyTargetPath: {status: 200, body: "reply_target_metadata.json"},
		createDraftPath: {status: 200, body: "created_draft.json"},
	})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("gmail.create_draft", map[string]any{"to": "bob@example.test", "bcc": "me@example.test", "subject": "Draft", "body": "Later.", "in_reply_to": "18f1a2b3c4d5e6f7"}))
	if err != nil {
		t.Fatalf("create_draft: %v", err)
	}
	req := srv.Last(t, createDraftPath)
	headers, _, _ := strings.Cut(rawMessage(t, req.Body, true), "\r\n\r\n")
	if !strings.Contains(headers, "Message-ID: "+google.MessageID(opID)+"\r\n") || !strings.Contains(headers, "Bcc: me@example.test\r\n") || !strings.Contains(headers, "In-Reply-To: <abc123@example.test>\r\n") {
		t.Errorf("draft headers:\n%s", headers)
	}
	if threadOf(t, req.Body, true) != "18f1a2b3c4d5e6f0" {
		t.Errorf("threadId = %q", threadOf(t, req.Body, true))
	}
	created, ok := res.Content.(google.CreatedDraft)
	if !ok || created.ID != "r-7788990011223344556" || created.MessageID != "18f9draft0001" || created.RFC822ID != google.MessageID(opID) {
		t.Errorf("content = %#v", res.Content)
	}
	tool := toolOf(t, c, "gmail.create_draft")
	if ids := tool.ResultIDs(res); ids["id"] != created.ID || ids["message_id"] != "18f9draft0001" || ids["rfc822_message_id"] != google.MessageID(opID) {
		t.Errorf("ResultIDs = %v", ids)
	}
	if tool.RequiredScopes[0] != google.ScopeGmailCompose {
		t.Errorf("scopes = %v", tool.RequiredScopes)
	}
	for _, tc := range writeErrorCases("created_draft.json") {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{createDraftPath: tc.rt})
			c := shortTimeout(t, srv)
			res, err := run(t, c, write("gmail.create_draft", map[string]any{"to": "a@b.test", "subject": "s", "body": "b"}))
			checkWriteError(t, tc, res, err)
		})
	}
}

// Context cancellation during a write is an unknown outcome too.
func TestWriteCancelledIsUnknown(t *testing.T) {
	srv := newAPIServer(t, map[string]route{sendPath: {status: 200, body: "sent_message.json", delay: 2 * time.Second}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	_, err := appOf(t, c, google.AppGmail).Call(ctx, write("gmail.send", map[string]any{"to": "a@b.test", "subject": "s", "body": "b"}))
	if !errors.Is(err, connectors.ErrOutcomeUnknown) {
		t.Errorf("err = %v, want ErrOutcomeUnknown", err)
	}
}
