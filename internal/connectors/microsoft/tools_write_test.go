package microsoft_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/microsoft"
)

// --- tool metadata ----------------------------------------------------------

func TestWriteToolsMetadata(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	tools := map[string]connectors.Tool{}
	var order []string
	for _, tool := range c.Tools() {
		tools[tool.Name] = tool
		if tool.Kind == connectors.KindWrite {
			order = append(order, tool.Name)
		}
	}
	wantOrder := []string{"mail_send", "calendar_create_event", "drive_create_folder", "teams_post_channel_message"}
	if len(order) < len(wantOrder) || strings.Join(order[:len(wantOrder)], ",") != strings.Join(wantOrder, ",") {
		t.Fatalf("write tools = %v, want them to start with %v", order, wantOrder)
	}
	type schema struct {
		Type       string                    `json:"type"`
		Properties map[string]map[string]any `json:"properties"`
		Required   []string                  `json:"required"`
		Additional *bool                     `json:"additionalProperties"`
	}
	cases := []struct {
		tool     string
		kind     connectors.ReconcileKind
		scopes   []string
		required []string
		props    []string
		args     map[string]any
		identity map[string]string
	}{
		{
			tool: "mail_send", kind: connectors.ReconcileMarker, scopes: []string{"Mail.Send"},
			required: []string{"to", "subject", "body"}, props: []string{"to", "subject", "body", "cc", "content_type"},
			args:     map[string]any{"to": []any{"secret@example.test"}, "subject": "secret subject", "body": "secret body"},
			identity: map[string]string{"mailbox": "me"},
		},
		{
			tool: "calendar_create_event", kind: connectors.ReconcileStableID, scopes: []string{"Calendars.ReadWrite"},
			required: []string{"subject", "start", "end"}, props: []string{"subject", "start", "end", "time_zone", "attendees", "body", "location", "calendar_id"},
			args:     map[string]any{"subject": "secret", "start": "2026-10-10T14:00:00", "end": "2026-10-10T15:00:00", "calendar_id": "cal-2"},
			identity: map[string]string{"calendar": "cal-2"},
		},
		{
			tool: "drive_create_folder", kind: connectors.ReconcileMarker, scopes: []string{"Files.ReadWrite"},
			required: []string{"name"}, props: []string{"name", "parent_id", "drive_id"},
			args:     map[string]any{"name": "Q4 planning", "parent_id": "01DRIVE-root", "drive_id": "b!drive-1"},
			identity: map[string]string{"drive": "b!drive-1", "parent": "01DRIVE-root", "folder": "Q4 planning"},
		},
		{
			tool: "teams_post_channel_message", kind: connectors.ReconcileNone, scopes: []string{"ChannelMessage.Send"},
			required: []string{"team_id", "channel_id", "content"}, props: []string{"team_id", "channel_id", "content", "content_type"},
			args:     map[string]any{"team_id": "team-1", "channel_id": "19:chan-general@thread.tacv2", "content": "secret"},
			identity: map[string]string{"team": "team-1", "channel": "19:chan-general@thread.tacv2"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			tool, ok := tools[tc.tool]
			if !ok {
				t.Fatalf("tool %s not declared", tc.tool)
			}
			if tool.Kind != connectors.KindWrite {
				t.Errorf("Kind = %q, want write", tool.Kind)
			}
			if tool.Reconcile.Kind != tc.kind {
				t.Errorf("Reconcile.Kind = %q, want %q", tool.Reconcile.Kind, tc.kind)
			}
			if (tc.kind == connectors.ReconcileNone) != (tool.Reconcile.Check == nil) {
				t.Errorf("Reconcile.Check present = %v for kind %q", tool.Reconcile.Check != nil, tc.kind)
			}
			if tool.ResultIDs == nil {
				t.Error("ResultIDs is nil")
			}
			if strings.Join(tool.RequiredScopes, ",") != strings.Join(tc.scopes, ",") {
				t.Errorf("RequiredScopes = %v, want %v", tool.RequiredScopes, tc.scopes)
			}
			if tool.Bounds.MaxPageSize != 0 || tool.Bounds.MaxResultBytes <= 0 {
				t.Errorf("Bounds = %+v, want no page size and a result bound", tool.Bounds)
			}
			if strings.TrimSpace(tool.Description) == "" {
				t.Error("empty description")
			}
			var s schema
			if err := json.Unmarshal(tool.InputSchema, &s); err != nil {
				t.Fatalf("schema: %v", err)
			}
			if s.Type != "object" || s.Additional == nil || *s.Additional {
				t.Errorf("schema must be a closed object: %s", tool.InputSchema)
			}
			if strings.Join(s.Required, ",") != strings.Join(tc.required, ",") {
				t.Errorf("required = %v, want %v", s.Required, tc.required)
			}
			for _, p := range tc.props {
				if s.Properties[p] == nil {
					t.Errorf("property %q missing", p)
				} else if d, _ := s.Properties[p]["description"].(string); strings.TrimSpace(d) == "" {
					t.Errorf("property %q has no description", p)
				}
			}
			if len(s.Properties) != len(tc.props) {
				t.Errorf("properties = %d, want %d: %s", len(s.Properties), len(tc.props), tool.InputSchema)
			}
			got := tool.ResourceIdentity(tc.args)
			if len(got) != len(tc.identity) {
				t.Errorf("ResourceIdentity = %v, want %v", got, tc.identity)
			}
			for k, v := range tc.identity {
				if got[k] != v {
					t.Errorf("ResourceIdentity[%s] = %q, want %q (all: %v)", k, got[k], v, got)
				}
			}
			for _, v := range got {
				if strings.Contains(v, "secret") {
					t.Errorf("ResourceIdentity leaks argument content: %v", got)
				}
			}
			if id := tool.ResourceIdentity(nil); id == nil {
				t.Errorf("ResourceIdentity(nil) = nil, want a map")
			}
		})
	}
}

// --- write helpers ------------------------------------------------------------

const opID = "0f1e2d3c-4b5a-4968-8777-66554433aa11"

// internetMessageID is the deterministic id mail_send gives the message.
const internetMessageID = "<op-" + opID + "@mcp-gateway>"

// write builds a write call under the ledger operation opID.
func write(tool string, args map[string]any) connectors.Call {
	c := call(tool, args)
	c.OperationID = opID
	return c
}

// jsonBody decodes a recorded request body.
func jsonBody(t *testing.T, r recorded) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(r.Body), &m); err != nil {
		t.Fatalf("request body %q: %v", r.Body, err)
	}
	return m
}

// toolNamed returns the connector's tool by short name.
func toolNamed(t *testing.T, c *microsoft.Connector, name string) connectors.Tool {
	t.Helper()
	for _, tool := range c.Tools() {
		if tool.Name == name {
			return tool
		}
	}
	t.Fatalf("tool %s not declared", name)
	return connectors.Tool{}
}

type writeErrorCase struct {
	name    string
	rt      route
	class   string
	status  int
	unknown bool
	rateLim bool
}

// writeErrorCases are the vendor answers every write maps the same way.
func writeErrorCases(success route) []writeErrorCase {
	delayed := success
	delayed.delay = 2 * time.Second
	return []writeErrorCase{
		{name: "400 invalid argument", rt: route{status: 400, body: "error_invalid_request.json"}, class: microsoft.ClassInvalidArgument, status: 400},
		{name: "403 forbidden", rt: route{status: 403, body: "error_access_denied.json"}, class: microsoft.ClassForbidden, status: 403},
		{name: "404 not found", rt: route{status: 404, body: "error_item_not_found.json"}, class: microsoft.ClassNotFound, status: 404},
		{name: "401 reconnect", rt: route{status: 401, body: "error_invalid_token.json"}, class: microsoft.ClassReconnectRequired, status: 401},
		{name: "429 throttled", rt: route{status: 429, body: "error_throttled.json", headers: map[string]string{"Retry-After": "7"}}, rateLim: true},
		{name: "500 outcome unknown", rt: route{status: 500, body: "error_server.json"}, unknown: true},
		{name: "503 outcome unknown", rt: route{status: 503, body: "error_server.json"}, unknown: true},
		{name: "timeout outcome unknown", rt: delayed, unknown: true},
	}
}

// checkWriteError asserts the outcome of one writeErrorCases entry.
func checkWriteError(t *testing.T, tc writeErrorCase, res connectors.Result, err error) {
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
		if !errors.As(err, &rl) || rl.App != "microsoft" || rl.RetryAfter != 7*time.Second {
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

// runWriteErrorCases runs the error table for one write.
func runWriteErrorCases(t *testing.T, methodPath string, success route, tool string, args map[string]any) {
	t.Helper()
	for _, tc := range writeErrorCases(success) {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{methodPath: tc.rt})
			src := connectors.NewStaticAccountSource()
			src.Add(alice, connectors.Account{ID: acct, App: microsoft.App, Scopes: workScopes})
			c, err := microsoft.New(microsoft.Options{Tokens: (&tokens{}).source, Accounts: src, BaseURL: srv.URL + "/v1.0/", Timeout: 300 * time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			res, err := c.Call(context.Background(), write(tool, args))
			checkWriteError(t, tc, res, err)
		})
	}
}

func TestWritesRequireAnOperationID(t *testing.T) {
	srv := newAPIServer(t, nil)
	c, tk := newConnector(t, srv, connectors.Bounds{})
	for _, tool := range []string{"mail_send", "calendar_create_event", "drive_create_folder", "teams_post_channel_message"} {
		_, err := c.Call(context.Background(), call(tool, map[string]any{"to": []any{"a@example.test"}, "subject": "s", "body": "b", "start": "2026-10-10T14:00:00Z", "end": "2026-10-10T15:00:00Z", "name": "n", "team_id": "t", "channel_id": "c", "content": "x"}))
		if !errors.Is(err, microsoft.ErrMissingOperation) {
			t.Errorf("%s without an operation id: err = %v, want ErrMissingOperation", tool, err)
		}
	}
	if len(srv.Requests()) != 0 || len(tk.calls) != 0 {
		t.Errorf("requests = %d, token calls = %v; want none", len(srv.Requests()), tk.calls)
	}
}

// --- mail_send ------------------------------------------------------------------------

const sendMailPath = "POST /v1.0/me/sendMail"

var sendMailOK = route{status: 202}

func TestMailSend(t *testing.T) {
	srv := newAPIServer(t, map[string]route{sendMailPath: sendMailOK})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), write("mail_send", map[string]any{
		"to": []any{"bob@example.test", "Carol Example <carol@example.test>"}, "cc": []any{"dave@example.test"},
		"subject": "Q3 budget: approved", "body": "Looks good, ship it.",
	}))
	if err != nil {
		t.Fatalf("mail_send: %v", err)
	}
	sent, ok := res.Content.(microsoft.SentMail)
	if !ok || sent.InternetMessageID != internetMessageID {
		t.Errorf("content = %#v, want the deterministic internet message id", res.Content)
	}
	if res.Empty || res.Partial || res.Unavailable {
		t.Errorf("markers = %+v", res)
	}
	tool := toolNamed(t, c, "mail_send")
	ids := tool.ResultIDs(res)
	if ids["internet_message_id"] != internetMessageID || len(ids) != 1 {
		t.Errorf("ResultIDs = %v", ids)
	}
	if tool.ResultIDs(connectors.Result{}) != nil {
		t.Error("ResultIDs of an empty result should be nil")
	}
	body := jsonBody(t, srv.Last(t, sendMailPath))
	msg, _ := body["message"].(map[string]any)
	if msg == nil {
		t.Fatalf("body = %v", body)
	}
	if msg["subject"] != "Q3 budget: approved" || msg["internetMessageId"] != internetMessageID {
		t.Errorf("subject/internetMessageId = %v / %v", msg["subject"], msg["internetMessageId"])
	}
	if b, _ := msg["body"].(map[string]any); b["contentType"] != "Text" || b["content"] != "Looks good, ship it." {
		t.Errorf("body = %v", msg["body"])
	}
	if body["saveToSentItems"] != true {
		t.Errorf("saveToSentItems = %v, want true (the sent copy is what the reconciler finds)", body["saveToSentItems"])
	}
	headers, _ := msg["internetMessageHeaders"].([]any)
	if len(headers) != 1 || fmt.Sprint(headers[0]) != fmt.Sprint(map[string]any{"name": "x-mcp-gateway-op", "value": opID}) {
		t.Errorf("internetMessageHeaders = %v", headers)
	}
	to, _ := msg["toRecipients"].([]any)
	cc, _ := msg["ccRecipients"].([]any)
	if len(to) != 2 || len(cc) != 1 {
		t.Fatalf("to/cc = %v / %v", to, cc)
	}
	if fmt.Sprint(to[1]) != fmt.Sprint(map[string]any{"emailAddress": map[string]any{"address": "carol@example.test", "name": "Carol Example"}}) {
		t.Errorf("second recipient = %v, want name and address parsed", to[1])
	}
	if fmt.Sprint(cc[0]) != fmt.Sprint(map[string]any{"emailAddress": map[string]any{"address": "dave@example.test"}}) {
		t.Errorf("cc = %v", cc[0])
	}
	if len(tk.calls) != 1 || tk.calls[0] != alice+"/"+acct {
		t.Errorf("token source calls = %v", tk.calls)
	}
}

func TestMailSendHTMLAndValidation(t *testing.T) {
	srv := newAPIServer(t, map[string]route{sendMailPath: sendMailOK})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	if _, err := c.Call(context.Background(), write("mail_send", map[string]any{"to": []any{"bob@example.test"}, "subject": "s", "body": "<b>hi</b>", "content_type": "html"})); err != nil {
		t.Fatal(err)
	}
	msg, _ := jsonBody(t, srv.Last(t, sendMailPath))["message"].(map[string]any)
	if b, _ := msg["body"].(map[string]any); b["contentType"] != "HTML" {
		t.Errorf("body = %v", msg["body"])
	}
	if _, ok := msg["ccRecipients"]; ok {
		t.Errorf("ccRecipients sent when none given: %v", msg)
	}
	before := len(srv.Requests())
	cases := map[string]map[string]any{
		"missing to":      {"subject": "s", "body": "b"},
		"empty to":        {"to": []any{}, "subject": "s", "body": "b"},
		"bad address":     {"to": []any{"not an address"}, "subject": "s", "body": "b"},
		"to not an array": {"to": "bob@example.test", "subject": "s", "body": "b"},
		"blank subject":   {"to": []any{"bob@example.test"}, "subject": " ", "body": "b"},
		"missing body":    {"to": []any{"bob@example.test"}, "subject": "s"},
		"bad type":        {"to": []any{"bob@example.test"}, "subject": "s", "body": "b", "content_type": "markdown"},
		"too many":        {"to": tooMany(), "subject": "s", "body": "b"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := c.Call(context.Background(), write("mail_send", args))
			wantClass(t, err, microsoft.ClassInvalidArgument, 0)
		})
	}
	if n := len(srv.Requests()) - before; n != 0 {
		t.Errorf("%d requests sent for invalid arguments", n)
	}
}

func tooMany() []any {
	var out []any
	for i := 0; i < 501; i++ {
		out = append(out, fmt.Sprintf("u%d@example.test", i))
	}
	return out
}

func TestMailSendErrors(t *testing.T) {
	runWriteErrorCases(t, sendMailPath, sendMailOK, "mail_send", map[string]any{"to": []any{"bob@example.test"}, "subject": "s", "body": "b"})
}

func TestMailSendConnectionLostIsUnknown(t *testing.T) {
	srv := newAPIServer(t, nil)
	c, _ := newConnector(t, srv, connectors.Bounds{})
	srv.Close()
	res, err := c.Call(context.Background(), write("mail_send", map[string]any{"to": []any{"bob@example.test"}, "subject": "s", "body": "b"}))
	if !errors.Is(err, connectors.ErrOutcomeUnknown) || res.Unavailable {
		t.Fatalf("res = %+v err = %v, want ErrOutcomeUnknown (never Unavailable for a write)", res, err)
	}
}

// --- calendar_create_event ------------------------------------------------------------

const createEventPath = "POST /v1.0/me/events"

var createEventOK = route{status: 201, body: "created_event.json"}

func TestCalendarCreateEvent(t *testing.T) {
	srv := newAPIServer(t, map[string]route{createEventPath: createEventOK})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), write("calendar_create_event", map[string]any{
		"subject": "Design review", "start": "2026-10-10T14:00:00", "end": "2026-10-10T15:00:00", "time_zone": "Europe/Paris",
		"attendees": []any{"bob@example.test", "Carol Example <carol@example.test>"}, "body": "Agenda: the new flow.", "location": "Room 4",
	}))
	if err != nil {
		t.Fatalf("calendar_create_event: %v", err)
	}
	created, ok := res.Content.(microsoft.CreatedEvent)
	if !ok || created.ID != "AAMkAGE1-evt-new" || created.TransactionID != opID || created.WebLink == "" {
		t.Errorf("content = %#v", res.Content)
	}
	ids := toolNamed(t, c, "calendar_create_event").ResultIDs(res)
	if ids["id"] != "AAMkAGE1-evt-new" || ids["web_link"] != created.WebLink || ids["transaction_id"] != opID || len(ids) != 3 {
		t.Errorf("ResultIDs = %v", ids)
	}
	body := jsonBody(t, srv.Last(t, createEventPath))
	if body["subject"] != "Design review" || body["transactionId"] != opID {
		t.Errorf("subject/transactionId = %v / %v", body["subject"], body["transactionId"])
	}
	if s, _ := body["start"].(map[string]any); s["dateTime"] != "2026-10-10T14:00:00" || s["timeZone"] != "Europe/Paris" {
		t.Errorf("start = %v", body["start"])
	}
	if e, _ := body["end"].(map[string]any); e["dateTime"] != "2026-10-10T15:00:00" || e["timeZone"] != "Europe/Paris" {
		t.Errorf("end = %v", body["end"])
	}
	att, _ := body["attendees"].([]any)
	if len(att) != 2 || fmt.Sprint(att[1]) != fmt.Sprint(map[string]any{"emailAddress": map[string]any{"address": "carol@example.test", "name": "Carol Example"}, "type": "required"}) {
		t.Errorf("attendees = %v", att)
	}
	if b, _ := body["body"].(map[string]any); b["contentType"] != "Text" || b["content"] != "Agenda: the new flow." {
		t.Errorf("body = %v", body["body"])
	}
	if l, _ := body["location"].(map[string]any); l["displayName"] != "Room 4" {
		t.Errorf("location = %v", body["location"])
	}
}

func TestCalendarCreateEventDefaultsAndCalendar(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"POST /v1.0/me/calendars/cal-2/events": createEventOK})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	if _, err := c.Call(context.Background(), write("calendar_create_event", map[string]any{"subject": "s", "start": "2026-10-10T14:00:00Z", "end": "2026-10-10T15:00:00Z", "calendar_id": "cal-2"})); err != nil {
		t.Fatal(err)
	}
	body := jsonBody(t, srv.Last(t, "POST /v1.0/me/calendars/cal-2/events"))
	if s, _ := body["start"].(map[string]any); s["dateTime"] != "2026-10-10T14:00:00" || s["timeZone"] != "UTC" {
		t.Errorf("start = %v, want UTC with the Z stripped", body["start"])
	}
	for _, k := range []string{"attendees", "body", "location"} {
		if _, ok := body[k]; ok {
			t.Errorf("%s sent when not given: %v", k, body)
		}
	}
	cases := map[string]map[string]any{
		"missing subject": {"start": "2026-10-10T14:00:00Z", "end": "2026-10-10T15:00:00Z"},
		"bad start":       {"subject": "s", "start": "soon", "end": "2026-10-10T15:00:00Z"},
		"end before":      {"subject": "s", "start": "2026-10-10T15:00:00Z", "end": "2026-10-10T14:00:00Z"},
		"bad attendee":    {"subject": "s", "start": "2026-10-10T14:00:00Z", "end": "2026-10-10T15:00:00Z", "attendees": []any{"nobody"}},
		"bad time zone":   {"subject": "s", "start": "2026-10-10T14:00:00Z", "end": "2026-10-10T15:00:00Z", "time_zone": "Mars/Olympus"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := c.Call(context.Background(), write("calendar_create_event", args))
			wantClass(t, err, microsoft.ClassInvalidArgument, 0)
		})
	}
}

func TestCalendarCreateEventErrors(t *testing.T) {
	runWriteErrorCases(t, createEventPath, createEventOK, "calendar_create_event", map[string]any{"subject": "s", "start": "2026-10-10T14:00:00Z", "end": "2026-10-10T15:00:00Z"})
}

// --- drive_create_folder ----------------------------------------------------------------

const createFolderPath = "POST /v1.0/me/drive/root/children"

var createFolderOK = route{status: 201, body: "created_folder.json"}

func TestDriveCreateFolder(t *testing.T) {
	srv := newAPIServer(t, map[string]route{createFolderPath: createFolderOK})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), write("drive_create_folder", map[string]any{"name": "Q4 planning"}))
	if err != nil {
		t.Fatalf("drive_create_folder: %v", err)
	}
	created, ok := res.Content.(microsoft.CreatedFolder)
	if !ok || created.ID != "01DRIVE-folder-new" || created.Name != "Q4 planning" || created.WebURL == "" || created.DriveID != "b!drive-1" || created.ParentID != "01DRIVE-root" {
		t.Errorf("content = %#v", res.Content)
	}
	ids := toolNamed(t, c, "drive_create_folder").ResultIDs(res)
	if ids["id"] != "01DRIVE-folder-new" || ids["web_url"] != created.WebURL || len(ids) != 2 {
		t.Errorf("ResultIDs = %v", ids)
	}
	body := jsonBody(t, srv.Last(t, createFolderPath))
	if body["name"] != "Q4 planning" || body["@microsoft.graph.conflictBehavior"] != "fail" {
		t.Errorf("body = %v, want the name and conflictBehavior fail", body)
	}
	if f, ok := body["folder"].(map[string]any); !ok || len(f) != 0 {
		t.Errorf("folder facet = %v", body["folder"])
	}
}

func TestDriveCreateFolderParentDriveAndValidation(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"POST /v1.0/drives/b!drive-1/items/01DRIVE-folder-finance/children": createFolderOK})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	if _, err := c.Call(context.Background(), write("drive_create_folder", map[string]any{"name": "Q4 planning", "parent_id": "01DRIVE-folder-finance", "drive_id": "b!drive-1"})); err != nil {
		t.Fatal(err)
	}
	cases := map[string]map[string]any{
		"missing name":    {},
		"name with slash": {"name": "a/b"},
		"name with colon": {"name": "a:b"},
		"dot name":        {"name": ".."},
		"bad parent":      {"name": "ok", "parent_id": "a/b"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := c.Call(context.Background(), write("drive_create_folder", args))
			wantClass(t, err, microsoft.ClassInvalidArgument, 0)
		})
	}
}

func TestDriveCreateFolderConflictIsInvalidArgument(t *testing.T) {
	srv := newAPIServer(t, map[string]route{createFolderPath: {status: 409, body: "error_name_exists.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	_, err := c.Call(context.Background(), write("drive_create_folder", map[string]any{"name": "Q4 planning"}))
	wantClass(t, err, microsoft.ClassInvalidArgument, 409)
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("message %q should say the name exists", err.Error())
	}
}

func TestDriveCreateFolderErrors(t *testing.T) {
	runWriteErrorCases(t, createFolderPath, createFolderOK, "drive_create_folder", map[string]any{"name": "Q4 planning"})
}

// --- teams_post_channel_message ----------------------------------------------------------

const postMessagePath = "POST /v1.0/teams/team-1/channels/19:chan-general@thread.tacv2/messages"

var postMessageOK = route{status: 201, body: "posted_message.json"}

func TestTeamsPostChannelMessage(t *testing.T) {
	srv := newAPIServer(t, map[string]route{postMessagePath: postMessageOK})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), write("teams_post_channel_message", map[string]any{"team_id": "team-1", "channel_id": "19:chan-general@thread.tacv2", "content": "Deploy done."}))
	if err != nil {
		t.Fatalf("teams_post_channel_message: %v", err)
	}
	posted, ok := res.Content.(microsoft.PostedMessage)
	if !ok || posted.ID != "1728390000003" || posted.WebURL == "" || posted.TeamID != "team-1" || posted.ChannelID != "19:chan-general@thread.tacv2" {
		t.Errorf("content = %#v", res.Content)
	}
	ids := toolNamed(t, c, "teams_post_channel_message").ResultIDs(res)
	if ids["id"] != "1728390000003" || ids["web_url"] != posted.WebURL || len(ids) != 2 {
		t.Errorf("ResultIDs = %v", ids)
	}
	body := jsonBody(t, srv.Last(t, postMessagePath))
	if b, _ := body["body"].(map[string]any); b["content"] != "Deploy done." || b["contentType"] != "text" {
		t.Errorf("body = %v", body)
	}
	for name, args := range map[string]map[string]any{
		"missing content": {"team_id": "team-1", "channel_id": "c"},
		"bad channel":     {"team_id": "team-1", "channel_id": "a/b", "content": "x"},
		"bad type":        {"team_id": "team-1", "channel_id": "c", "content": "x", "content_type": "markdown"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := c.Call(context.Background(), write("teams_post_channel_message", args))
			wantClass(t, err, microsoft.ClassInvalidArgument, 0)
		})
	}
}

func TestTeamsPostChannelMessageErrors(t *testing.T) {
	runWriteErrorCases(t, postMessagePath, postMessageOK, "teams_post_channel_message", map[string]any{"team_id": "team-1", "channel_id": "19:chan-general@thread.tacv2", "content": "x"})
}

// --- reconciliation -------------------------------------------------------------------------

// reconcile builds the input the ledger's reconciler hands to Check:
// the principal and account, the operation id and the stored resource
// identity; never arguments.
func reconcile(tool string, identity map[string]string) connectors.ReconcileInput {
	return connectors.ReconcileInput{
		Call:             connectors.Call{Principal: connectors.Principal{UserID: alice, TokenID: "tok"}, Tool: "microsoft." + tool, Account: acct, OperationID: opID},
		OperationID:      opID,
		ResourceIdentity: identity,
	}
}

func wantFound(t *testing.T, res connectors.ReconcileResult, err error, id string) {
	t.Helper()
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if res.Outcome != connectors.ReconcileFound || res.ResourceID != id {
		t.Fatalf("Check = %+v, want found %s", res, id)
	}
}

func wantNotFound(t *testing.T, res connectors.ReconcileResult, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if res.Outcome != connectors.ReconcileNotFound || res.ResourceID != "" {
		t.Fatalf("Check = %+v, want not_found", res)
	}
}

func TestCheckMail(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{"GET /v1.0/me/messages": {status: 200, body: "messages_by_internet_id.json"}})
		c, tk := newConnector(t, srv, connectors.Bounds{})
		res, err := toolNamed(t, c, "mail_send").Reconcile.Check(context.Background(), reconcile("mail_send", map[string]string{"mailbox": "me"}))
		wantFound(t, res, err, "AAMkAGE1-sent-1")
		q := query(t, srv, "/v1.0/me/messages")
		if got := q.Get("$filter"); got != "internetMessageId eq '"+internetMessageID+"'" {
			t.Errorf("$filter = %q", got)
		}
		if q.Get("$select") == "" || strings.Contains(q.Get("$select"), "body") {
			t.Errorf("$select = %q, want ids only", q.Get("$select"))
		}
		if len(tk.calls) != 1 || tk.calls[0] != alice+"/"+acct {
			t.Errorf("token source calls = %v", tk.calls)
		}
	})
	t.Run("not found", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{"GET /v1.0/me/messages": {status: 200, body: "messages_empty.json"}})
		c, _ := newConnector(t, srv, connectors.Bounds{})
		res, err := toolNamed(t, c, "mail_send").Reconcile.Check(context.Background(), reconcile("mail_send", map[string]string{}))
		wantNotFound(t, res, err)
	})
	t.Run("hit without the id is not trusted", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{"GET /v1.0/me/messages": {status: 200, body: "messages.json"}})
		c, _ := newConnector(t, srv, connectors.Bounds{})
		res, err := toolNamed(t, c, "mail_send").Reconcile.Check(context.Background(), reconcile("mail_send", map[string]string{}))
		wantNotFound(t, res, err)
	})
	t.Run("cannot tell", func(t *testing.T) {
		for name, rt := range map[string]route{"500": {status: 500, body: "error_server.json"}, "401": {status: 401, body: "error_invalid_token.json"}, "429": {status: 429, body: "error_throttled.json"}} {
			t.Run(name, func(t *testing.T) {
				srv := newAPIServer(t, map[string]route{"GET /v1.0/me/messages": rt})
				c, _ := newConnector(t, srv, connectors.Bounds{})
				if _, err := toolNamed(t, c, "mail_send").Reconcile.Check(context.Background(), reconcile("mail_send", map[string]string{})); err == nil {
					t.Error("Check succeeded on a vendor failure")
				}
			})
		}
	})
	t.Run("not reconcilable", func(t *testing.T) {
		c, tk := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
		in := reconcile("mail_send", map[string]string{})
		in.OperationID, in.Call.OperationID = "", ""
		if _, err := toolNamed(t, c, "mail_send").Reconcile.Check(context.Background(), in); !errors.Is(err, microsoft.ErrNotReconcilable) {
			t.Errorf("err = %v, want ErrNotReconcilable", err)
		}
		in = reconcile("mail_send", map[string]string{})
		in.Call.Account = ""
		if _, err := toolNamed(t, c, "mail_send").Reconcile.Check(context.Background(), in); !errors.Is(err, microsoft.ErrNotReconcilable) {
			t.Errorf("err = %v, want ErrNotReconcilable", err)
		}
		if len(tk.calls) != 0 {
			t.Errorf("token fetched for an unreconcilable input: %v", tk.calls)
		}
	})
}

func TestCheckEvent(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{"GET /v1.0/me/events": {status: 200, body: "events_by_transaction.json"}})
		c, _ := newConnector(t, srv, connectors.Bounds{})
		res, err := toolNamed(t, c, "calendar_create_event").Reconcile.Check(context.Background(), reconcile("calendar_create_event", map[string]string{"calendar": "default"}))
		wantFound(t, res, err, "AAMkAGE1-evt-new")
		if got := query(t, srv, "/v1.0/me/events").Get("$filter"); got != "transactionId eq '"+opID+"'" {
			t.Errorf("$filter = %q", got)
		}
	})
	t.Run("found in another calendar", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{"GET /v1.0/me/calendars/cal-2/events": {status: 200, body: "events_by_transaction.json"}})
		c, _ := newConnector(t, srv, connectors.Bounds{})
		res, err := toolNamed(t, c, "calendar_create_event").Reconcile.Check(context.Background(), reconcile("calendar_create_event", map[string]string{"calendar": "cal-2"}))
		wantFound(t, res, err, "AAMkAGE1-evt-new")
	})
	t.Run("not found", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{"GET /v1.0/me/events": {status: 200, body: "events_empty.json"}})
		c, _ := newConnector(t, srv, connectors.Bounds{})
		res, err := toolNamed(t, c, "calendar_create_event").Reconcile.Check(context.Background(), reconcile("calendar_create_event", nil))
		wantNotFound(t, res, err)
	})
	t.Run("hit with another transaction id is not trusted", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{"GET /v1.0/me/events": {status: 200, body: `{"value":[{"id":"other","transactionId":"someone-else"}]}`}})
		c, _ := newConnector(t, srv, connectors.Bounds{})
		res, err := toolNamed(t, c, "calendar_create_event").Reconcile.Check(context.Background(), reconcile("calendar_create_event", nil))
		wantNotFound(t, res, err)
	})
	t.Run("cannot tell", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{"GET /v1.0/me/events": {status: 503, body: "error_server.json"}})
		c, _ := newConnector(t, srv, connectors.Bounds{})
		if _, err := toolNamed(t, c, "calendar_create_event").Reconcile.Check(context.Background(), reconcile("calendar_create_event", nil)); err == nil {
			t.Error("Check succeeded on a vendor failure")
		}
	})
}

func TestCheckFolder(t *testing.T) {
	childrenPath := "GET /v1.0/me/drive/root/children"
	pages := func(last string) route {
		return route{pages: map[string]route{"1": {status: 200, body: "children_page1.json"}, "page2": {status: 200, body: last}}}
	}
	identity := map[string]string{"drive": "me", "parent": "root", "folder": "Q4 planning"}
	t.Run("found on a later page, case-insensitively, folders only", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{childrenPath: pages("children_page2_hit.json")})
		c, _ := newConnector(t, srv, connectors.Bounds{})
		res, err := toolNamed(t, c, "drive_create_folder").Reconcile.Check(context.Background(), reconcile("drive_create_folder", identity))
		wantFound(t, res, err, "01DRIVE-folder-new")
		if n := srv.Count(childrenPath); n != 2 {
			t.Errorf("children requests = %d, want 2 pages", n)
		}
		if got := query(t, srv, "/v1.0/me/drive/root/children").Get("$select"); got != "" && !strings.Contains(got, "folder") {
			t.Errorf("$select = %q", got)
		}
	})
	t.Run("not found at the end of the list", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{childrenPath: pages("children_page2_miss.json")})
		c, _ := newConnector(t, srv, connectors.Bounds{})
		res, err := toolNamed(t, c, "drive_create_folder").Reconcile.Check(context.Background(), reconcile("drive_create_folder", identity))
		wantNotFound(t, res, err)
	})
	t.Run("another drive and parent", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{"GET /v1.0/drives/b!drive-1/items/01DRIVE-folder-finance/children": {status: 200, body: "children_page2_hit.json"}})
		c, _ := newConnector(t, srv, connectors.Bounds{})
		res, err := toolNamed(t, c, "drive_create_folder").Reconcile.Check(context.Background(), reconcile("drive_create_folder", map[string]string{"drive": "b!drive-1", "parent": "01DRIVE-folder-finance", "folder": "Q4 planning"}))
		wantFound(t, res, err, "01DRIVE-folder-new")
	})
	t.Run("too many pages is cannot tell", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{childrenPath: {status: 200, body: `{"@odata.nextLink":"https://graph.example.test/v1.0/me/drive/root/children?$skiptoken=1","value":[{"id":"x","name":"Other","folder":{}}]}`}})
		c, _ := newConnector(t, srv, connectors.Bounds{})
		_, err := toolNamed(t, c, "drive_create_folder").Reconcile.Check(context.Background(), reconcile("drive_create_folder", identity))
		if err == nil || !strings.Contains(err.Error(), "cannot tell") {
			t.Errorf("err = %v, want cannot tell yet", err)
		}
		if n := srv.Count(childrenPath); n != microsoft.MaxReconcilePages {
			t.Errorf("children requests = %d, want MaxReconcilePages %d", n, microsoft.MaxReconcilePages)
		}
	})
	t.Run("404 is cannot tell", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{childrenPath: {status: 404, body: "error_item_not_found.json"}})
		c, _ := newConnector(t, srv, connectors.Bounds{})
		if _, err := toolNamed(t, c, "drive_create_folder").Reconcile.Check(context.Background(), reconcile("drive_create_folder", identity)); err == nil {
			t.Error("Check succeeded on a 404 (the account may have lost access)")
		}
	})
	t.Run("missing folder name", func(t *testing.T) {
		c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
		if _, err := toolNamed(t, c, "drive_create_folder").Reconcile.Check(context.Background(), reconcile("drive_create_folder", map[string]string{"drive": "me"})); !errors.Is(err, microsoft.ErrNotReconcilable) {
			t.Errorf("err = %v, want ErrNotReconcilable", err)
		}
	})
}
