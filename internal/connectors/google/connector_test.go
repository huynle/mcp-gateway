package google_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/connectortest"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

func TestNewRequiresTokens(t *testing.T) {
	if _, err := google.New(google.Options{}); err == nil {
		t.Fatal("New without Tokens should fail")
	}
	if _, err := google.New(google.Options{Tokens: (&tokens{}).source, BaseURL: "not a url"}); err == nil {
		t.Fatal("New with a relative BaseURL should fail")
	}
}

func TestAppsAndToolNames(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	var apps []string
	for _, a := range c.Apps() {
		apps = append(apps, a.App())
	}
	if strings.Join(apps, ",") != strings.Join(google.Apps, ",") {
		t.Errorf("Apps() = %v, want %v", apps, google.Apps)
	}
	want := map[string][]string{
		google.AppCalendar: {"list_events", "get_event", "create_event"},
		google.AppTasks:    {"list", "create"},
		google.AppGmail:    {"search", "get_message", "list_labels", "send", "create_draft"},
	}
	for app, names := range want {
		var got []string
		for _, tool := range appOf(t, c, app).Tools() {
			got = append(got, tool.Name)
			if tool.App != app {
				t.Errorf("%s.%s: App = %q", app, tool.Name, tool.App)
			}
			if tool.Bounds.MaxResultBytes != connectors.DefaultMaxResultBytes {
				t.Errorf("%s.%s: MaxResultBytes = %d, want the package default", app, tool.Name, tool.Bounds.MaxResultBytes)
			}
			if len(tool.RequiredScopes) == 0 {
				t.Errorf("%s.%s: no RequiredScopes (scope gating needs one)", app, tool.Name)
			}
		}
		if strings.Join(got, ",") != strings.Join(names, ",") {
			t.Errorf("%s tools = %v, want %v", app, got, names)
		}
	}
}

func TestEveryAppPassesContract(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	for _, a := range c.Apps() {
		t.Run(a.App(), func(t *testing.T) { connectortest.ContractTest(t, a) })
	}
}

func TestCallRefusesUnknownToolAndMissingAccount(t *testing.T) {
	c, tk := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	cal := appOf(t, c, google.AppCalendar)
	if _, err := cal.Call(context.Background(), call("calendar.nope", nil)); !errors.Is(err, connectors.ErrUnknownTool) {
		t.Errorf("unknown tool: err = %v, want ErrUnknownTool", err)
	}
	// A tool of another app is unknown to this one.
	if _, err := cal.Call(context.Background(), call("tasks.list", nil)); !errors.Is(err, connectors.ErrUnknownTool) {
		t.Errorf("other app's tool: err = %v, want ErrUnknownTool", err)
	}
	cl := call("calendar.list_events", nil)
	cl.Account = ""
	_, err := cal.Call(context.Background(), cl)
	wantClass(t, err, google.ClassNoAccount, 0)
	if len(tk.calls) != 0 {
		t.Errorf("token source called %d times before validation, want 0", len(tk.calls))
	}
}

func TestCallTokenFailureIsReconnectOrUnavailable(t *testing.T) {
	srv := newAPIServer(t, nil)
	tk := &tokens{fail: errors.New("boom")}
	c, err := google.New(google.Options{Tokens: tk.source, BaseURL: srv.URL + "/"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := run(t, c, call("calendar.list_events", nil))
	if err != nil || !res.Unavailable {
		t.Errorf("read with a failing token source: res = %+v, err = %v; want Unavailable", res, err)
	}
	if n := len(srv.Requests()); n != 0 {
		t.Errorf("requests = %d, want none without a token", n)
	}
}

// --- scopes ---------------------------------------------------------------------

func TestGrantsAppliesScopeImplication(t *testing.T) {
	cases := []struct {
		granted  []string
		required string
		want     bool
	}{
		{[]string{google.ScopeCalendarEventsReadonly}, google.ScopeCalendarEventsReadonly, true},
		{[]string{google.ScopeCalendarEvents}, google.ScopeCalendarEventsReadonly, true},
		{[]string{google.ScopeCalendar}, google.ScopeCalendarEventsReadonly, true},
		{[]string{google.ScopeCalendar}, google.ScopeCalendarEvents, true},
		{[]string{google.ScopeCalendarReadonly}, google.ScopeCalendarEvents, false},
		{[]string{google.ScopeCalendarEventsReadonly}, google.ScopeCalendarEvents, false},
		{[]string{google.ScopeTasks}, google.ScopeTasksReadonly, true},
		{[]string{google.ScopeTasksReadonly}, google.ScopeTasks, false},
		{[]string{google.ScopeMail}, google.ScopeGmailCompose, true},
		{[]string{google.ScopeGmailModify}, google.ScopeGmailReadonly, true},
		{[]string{google.ScopeGmailModify}, google.ScopeGmailSend, true},
		{[]string{google.ScopeGmailCompose}, google.ScopeGmailSend, true},
		{[]string{google.ScopeGmailSend}, google.ScopeGmailCompose, false},
		{[]string{google.ScopeGmailReadonly}, google.ScopeGmailLabels, true},
		{[]string{google.ScopeGmailLabels}, google.ScopeGmailReadonly, false},
		{[]string{"openid", "https://www.googleapis.com/auth/userinfo.email"}, google.ScopeGmailReadonly, false},
		{nil, google.ScopeGmailReadonly, false},
	}
	for _, tc := range cases {
		if got := google.Grants(tc.granted, tc.required); got != tc.want {
			t.Errorf("Grants(%v, %s) = %v, want %v", tc.granted, tc.required, got, tc.want)
		}
	}
}

// With an account source, a tool whose scope the account did not grant
// (granular consent) is blocked before any request; tools of the scopes
// it did grant keep working.
func TestDeclinedScopeBlocksToolBeforeAnyRequest(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		"GET /calendar/v3/calendars/primary/events": {status: 200, body: "events_list.json"},
	})
	const declined = "7c1d2e3f-4a5b-4c6d-8e9f-0a1b2c3d4e5f"
	accounts := connectors.NewStaticAccountSource()
	for _, app := range google.Apps {
		accounts.Add(alice, connectors.Account{
			ID: acct, App: app, Label: connectors.LabelCompany, DisplayName: "alice@example.test",
			Scopes: []string{"openid", "https://www.googleapis.com/auth/userinfo.email", google.ScopeCalendarEvents, google.ScopeTasks},
		})
		accounts.Add(alice, connectors.Account{
			ID: declined, App: app, Label: connectors.LabelPersonal, DisplayName: "alice@gmail.test",
			Scopes: []string{"openid", "https://www.googleapis.com/auth/userinfo.email", google.ScopeTasks},
		})
	}
	c, err := google.New(google.Options{Tokens: (&tokens{}).source, BaseURL: srv.URL + "/", Accounts: accounts})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, c, call("calendar.list_events", nil)); err != nil {
		t.Fatalf("calendar.list_events with the calendar scope: %v", err)
	}
	for _, name := range []string{"calendar.list_events", "calendar.get_event"} {
		cl := call(name, map[string]any{"event_id": "evt_standup_001"})
		cl.Account = declined
		_, err := run(t, c, cl)
		wantClass(t, err, google.ClassScopeRequired, 0)
		if !strings.Contains(err.Error(), "grant more access") {
			t.Errorf("%s: message %q should tell the user to grant more access", name, err.Error())
		}
	}
	if got := srv.Count("GET /calendar/v3/calendars/primary/events"); got != 1 {
		t.Errorf("calendar list requests = %d, want 1 (the declined account is blocked before any request)", got)
	}
}

// Without recorded scopes (older rows, static sources) nothing is blocked
// locally: Google decides and a 403 insufficientPermissions is reported as
// scope_required.
func TestUnknownScopesAreNotBlockedLocally(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		"GET /calendar/v3/calendars/primary/events": {status: 403, body: "error_insufficient_scope.json"},
	})
	accounts := connectors.NewStaticAccountSource()
	accounts.Add(alice, connectors.Account{ID: acct, App: google.AppCalendar, Label: connectors.LabelPersonal})
	c, err := google.New(google.Options{Tokens: (&tokens{}).source, BaseURL: srv.URL + "/", Accounts: accounts})
	if err != nil {
		t.Fatal(err)
	}
	_, err = run(t, c, call("calendar.list_events", nil))
	wantClass(t, err, google.ClassScopeRequired, 403)
}
