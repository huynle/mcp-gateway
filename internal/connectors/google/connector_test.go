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
		google.AppDrive:    {"search", "get_file_metadata", "create_folder"},
		google.AppDocs:     {"get_text", "create", "append_text"},
		google.AppSheets:   {"read_range", "append_rows"},
		google.AppContacts: {"search"},
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
		// Increment 2: Drive, Docs, Sheets, Contacts (the methods' accepted
		// scope lists: drive covers every Drive, Docs and Sheets scope;
		// drive.readonly covers the read-only ones).
		{[]string{google.ScopeDrive}, google.ScopeDriveFile, true},
		{[]string{google.ScopeDrive}, google.ScopeDriveMetadataReadonly, true},
		{[]string{google.ScopeDrive}, google.ScopeDocuments, true},
		{[]string{google.ScopeDrive}, google.ScopeSpreadsheetsReadonly, true},
		{[]string{google.ScopeDriveReadonly}, google.ScopeDriveMetadataReadonly, true},
		{[]string{google.ScopeDriveReadonly}, google.ScopeDocumentsReadonly, true},
		{[]string{google.ScopeDriveReadonly}, google.ScopeSpreadsheetsReadonly, true},
		{[]string{google.ScopeDriveReadonly}, google.ScopeDriveFile, false},
		{[]string{google.ScopeDriveReadonly}, google.ScopeDocuments, false},
		{[]string{google.ScopeDriveMetadata}, google.ScopeDriveMetadataReadonly, true},
		{[]string{google.ScopeDriveMetadataReadonly}, google.ScopeDriveReadonly, false},
		{[]string{google.ScopeDriveFile}, google.ScopeDriveMetadataReadonly, false},
		{[]string{google.ScopeDriveFile}, google.ScopeDocuments, false},
		{[]string{google.ScopeDocuments}, google.ScopeDocumentsReadonly, true},
		{[]string{google.ScopeDocumentsReadonly}, google.ScopeDocuments, false},
		{[]string{google.ScopeSpreadsheets}, google.ScopeSpreadsheetsReadonly, true},
		{[]string{google.ScopeSpreadsheetsReadonly}, google.ScopeSpreadsheets, false},
		{[]string{google.ScopeContacts}, google.ScopeContactsReadonly, true},
		{[]string{google.ScopeContactsReadonly}, google.ScopeContacts, false},
		{[]string{google.ScopeContacts}, google.ScopeDriveFile, false},
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

// PerFile says which required scopes drive.file stands in for: the
// Drive, Docs and Sheets methods accept it, limited to the files the
// gateway created or the user opened with it, so an account that granted
// only drive.file may run those tools on that subset (Google decides per
// file). Contacts and the increment-1 scopes are not Drive files.
func TestPerFileScopes(t *testing.T) {
	for scope, want := range map[string]bool{
		google.ScopeDriveMetadataReadonly: true, google.ScopeDriveReadonly: true, google.ScopeDriveFile: true,
		google.ScopeDocumentsReadonly: true, google.ScopeDocuments: true,
		google.ScopeSpreadsheetsReadonly: true, google.ScopeSpreadsheets: true,
		google.ScopeDrive: false, google.ScopeContactsReadonly: false, google.ScopeGmailReadonly: false, google.ScopeCalendarEvents: false,
	} {
		if got := google.PerFile(scope); got != want {
			t.Errorf("PerFile(%s) = %v, want %v", scope, got, want)
		}
	}
	if !google.GrantsOrPerFile([]string{google.ScopeDriveFile}, google.ScopeDocumentsReadonly) {
		t.Error("drive.file should admit documents.readonly per file")
	}
	if google.GrantsOrPerFile([]string{google.ScopeDriveFile}, google.ScopeContactsReadonly) {
		t.Error("drive.file must not admit contacts.readonly")
	}
	if google.GrantsOrPerFile([]string{google.ScopeDriveReadonly}, google.ScopeDriveFile) {
		t.Error("drive.readonly must not admit drive.file (it cannot create)")
	}
	if !google.GrantsOrPerFile([]string{google.ScopeDriveReadonly}, google.ScopeDriveMetadataReadonly) {
		t.Error("GrantsOrPerFile must still apply the implication table")
	}
}

// Increment 2: an account that declined the Drive, Docs, Sheets or
// Contacts scope is blocked on that app's tools before any request while
// the apps whose scopes it granted keep working; an account that granted
// only drive.file is admitted to the Drive, Docs and Sheets tools (Google
// decides per file) but not to Contacts.
func TestDeclinedIncrement2ScopeBlocksOnlyThatApp(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		listFilesPath:                        {status: 200, body: "files_list_empty.json"},
		getDocPath:                           {status: 200, body: "document.json"},
		getValuesPath:                        {status: 200, body: "values_get.json"},
		searchContactsPath:                   {status: 200, body: "contacts_search.json"},
		"GET /drive/v3/files/" + newFolderID: {status: 200, body: "created_folder.json"},
	})
	const (
		driveOnly   = "7c1d2e3f-4a5b-4c6d-8e9f-0a1b2c3d4e5f"
		perFileOnly = "8d2e3f4a-5b6c-4d7e-9f0a-1b2c3d4e5f6a"
	)
	accounts := connectors.NewStaticAccountSource()
	for _, app := range google.Apps {
		accounts.Add(alice, connectors.Account{ID: acct, App: app, Label: connectors.LabelCompany, Scopes: []string{
			google.ScopeDriveMetadataReadonly, google.ScopeDocumentsReadonly, google.ScopeSpreadsheetsReadonly, google.ScopeContactsReadonly, google.ScopeDriveFile,
		}})
		accounts.Add(alice, connectors.Account{ID: driveOnly, App: app, Label: connectors.LabelCompany, Scopes: []string{google.ScopeDriveMetadataReadonly}})
		accounts.Add(alice, connectors.Account{ID: perFileOnly, App: app, Label: connectors.LabelPersonal, Scopes: []string{google.ScopeDriveFile}})
	}
	c, err := google.New(google.Options{Tokens: (&tokens{}).source, BaseURL: srv.URL + "/", Accounts: accounts})
	if err != nil {
		t.Fatal(err)
	}
	calls := map[string]map[string]any{
		"drive.search":        nil,
		"docs.get_text":       {"document_id": docID},
		"sheets.read_range":   {"spreadsheet_id": sheetID, "range": sheetRange},
		"contacts.search":     {"query": "bob"},
		"drive.create_folder": {"name": "x"},
	}
	for name, args := range calls {
		if _, err := run(t, c, call(name, args)); err != nil && !errors.Is(err, google.ErrMissingOperation) {
			t.Errorf("%s with every scope: %v", name, err)
		}
	}
	before := len(srv.Requests())
	for name, args := range calls {
		cl := call(name, args)
		cl.Account = driveOnly
		_, err := run(t, c, cl)
		if name == "drive.search" {
			if err != nil {
				t.Errorf("%s with the drive scope: %v", name, err)
			}
			continue
		}
		if errors.Is(err, google.ErrMissingOperation) {
			continue // writes are refused before the gate without a ledger operation
		}
		wantClass(t, err, google.ClassScopeRequired, 0)
	}
	if got := len(srv.Requests()) - before; got != 1 {
		t.Errorf("requests for the drive-only account = %d, want 1 (declined apps are blocked before any request)", got)
	}
	for name, args := range calls {
		cl := call(name, args)
		cl.Account = perFileOnly
		_, err := run(t, c, cl)
		switch {
		case name == "contacts.search":
			wantClass(t, err, google.ClassScopeRequired, 0)
		case errors.Is(err, google.ErrMissingOperation):
		case err != nil:
			t.Errorf("%s with drive.file only: %v (per-file admission)", name, err)
		}
	}
}
