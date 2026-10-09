//go:build live

package google_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"google.golang.org/api/calendar/v3"
	"google.golang.org/api/drive/v3"
	"google.golang.org/api/option"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

// liveConnector builds the connector over the token in GOOGLE_LIVE_TOKEN
// (an OAuth access token of a dedicated test account; the scopes it
// carries decide which tests run). Behind the "live" build tag and
// skipped without the variable, so CI never runs it:
//
//	GOOGLE_LIVE_TOKEN=ya29.... go test -tags live -run Live ./internal/connectors/google/
func liveConnector(t *testing.T) (*google.Connector, string) {
	t.Helper()
	token := os.Getenv("GOOGLE_LIVE_TOKEN")
	if token == "" {
		t.Skip("GOOGLE_LIVE_TOKEN is unset")
	}
	c, err := google.New(google.Options{
		Tokens: func(context.Context, string, string) oauth2.TokenSource {
			return oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
		},
		Timeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c, token
}

func liveCall(full string, args map[string]any) connectors.Call {
	return connectors.Call{Principal: connectors.Principal{UserID: "live"}, Tool: full, Account: "live-account", Args: args}
}

// TestLiveCalendarListEvents lists the primary calendar's next events
// (needs calendar.events.readonly or broader).
func TestLiveCalendarListEvents(t *testing.T) {
	c, _ := liveConnector(t)
	res, err := c.Calendar().Call(context.Background(), liveCall("calendar.list_events", map[string]any{"max_results": 5}))
	if err != nil {
		t.Fatalf("list_events: %v", err)
	}
	page, ok := res.Content.(google.EventsPage)
	if !ok || res.Unavailable {
		t.Fatalf("content = %#v markers %+v", res.Content, res)
	}
	t.Logf("%d events (empty=%v, has_more=%v)", len(page.Items), res.Empty, page.HasMore)
}

// TestLiveGmailListLabels lists the mailbox's labels (needs gmail.labels,
// gmail.readonly or broader).
func TestLiveGmailListLabels(t *testing.T) {
	c, _ := liveConnector(t)
	res, err := c.Gmail().Call(context.Background(), liveCall("gmail.list_labels", map[string]any{}))
	if err != nil {
		t.Fatalf("list_labels: %v", err)
	}
	labels, ok := res.Content.(google.Labels)
	if !ok || len(labels.Items) == 0 {
		t.Fatalf("content = %#v", res.Content)
	}
	t.Logf("%d labels", len(labels.Items))
}

// TestLiveCreateEventAndReconcile creates an event on the primary
// calendar under a fresh operation id (needs calendar.events and
// GOOGLE_LIVE_WRITE=1), runs create_event's check from the resource
// identity alone, as the ledger's reconciler would, and expects it to
// find the event by its deterministic id; the event is deleted
// afterwards (best effort).
func TestLiveCreateEventAndReconcile(t *testing.T) {
	c, token := liveConnector(t)
	if os.Getenv("GOOGLE_LIVE_WRITE") != "1" {
		t.Skip("GOOGLE_LIVE_WRITE is not 1")
	}
	ctx := context.Background()
	opID := connectors.NewAccountID()
	start := time.Now().Add(48 * time.Hour).Truncate(time.Hour)
	args := map[string]any{
		"summary": "mcp-gateway live test " + opID[:8], "start": start.Format(time.RFC3339), "end": start.Add(30 * time.Minute).Format(time.RFC3339),
		"description": "Created by the gateway's live test; safe to delete.",
	}
	cl := liveCall("calendar.create_event", args)
	cl.OperationID = opID
	res, err := c.Calendar().Call(ctx, cl)
	if err != nil {
		t.Fatalf("create_event: %v", err)
	}
	created, ok := res.Content.(google.CreatedEvent)
	if !ok || created.ID != google.EventID(opID) {
		t.Fatalf("create_event content = %#v", res.Content)
	}
	t.Logf("created %s", created.URL)
	t.Cleanup(func() {
		svc, err := calendar.NewService(ctx, option.WithTokenSource(oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})))
		if err == nil {
			err = svc.Events.Delete("primary", created.ID).Do()
		}
		if err != nil {
			t.Logf("deleting the live event: %v", err)
		}
	})
	var tool connectors.Tool
	for _, tl := range c.Calendar().Tools() {
		if tl.Name == google.ToolCreateEvent {
			tool = tl
		}
	}
	in := connectors.ReconcileInput{
		Call:             connectors.Call{Principal: connectors.Principal{UserID: "live"}, Tool: tool.FullName(), Account: "live-account", OperationID: opID},
		OperationID:      opID,
		ResourceIdentity: tool.ResourceIdentity(args),
	}
	out, err := tool.Reconcile.Check(ctx, in)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if out.Outcome != connectors.ReconcileFound || out.ResourceID != created.ID {
		t.Fatalf("Check = %+v, want found %s", out, created.ID)
	}
}

// --- increment 2 ------------------------------------------------------------------------

// TestLiveDriveSearch lists a few files of My Drive (needs
// drive.metadata.readonly or broader; with drive.file only, the files the
// gateway created).
func TestLiveDriveSearch(t *testing.T) {
	c, _ := liveConnector(t)
	res, err := c.Drive().Call(context.Background(), liveCall("drive.search", map[string]any{"max_results": 5}))
	if err != nil {
		t.Fatalf("drive.search: %v", err)
	}
	page, ok := res.Content.(google.FilesPage)
	if !ok || res.Unavailable {
		t.Fatalf("content = %#v markers %+v", res.Content, res)
	}
	t.Logf("%d files (empty=%v, has_more=%v)", len(page.Items), res.Empty, page.HasMore)
}

// TestLiveContactsSearch searches the contacts for GOOGLE_LIVE_CONTACT_QUERY
// (default "a"; needs contacts.readonly). The People API's search cache
// can be cold: an empty answer is logged, not failed.
func TestLiveContactsSearch(t *testing.T) {
	c, _ := liveConnector(t)
	q := os.Getenv("GOOGLE_LIVE_CONTACT_QUERY")
	if q == "" {
		q = "a"
	}
	res, err := c.Contacts().Call(context.Background(), liveCall("contacts.search", map[string]any{"query": q, "max_results": 3}))
	if err != nil {
		t.Fatalf("contacts.search: %v", err)
	}
	page, ok := res.Content.(google.ContactsPage)
	if !ok || res.Unavailable {
		t.Fatalf("content = %#v markers %+v", res.Content, res)
	}
	t.Logf("%d contacts (empty=%v)", len(page.Items), res.Empty)
}

// TestLiveDocsAndSheetsReads reads the document GOOGLE_LIVE_DOCUMENT_ID
// (needs documents.readonly) and the range GOOGLE_LIVE_SHEET_RANGE
// ("<spreadsheet id>!<A1 range>", e.g. 1abc!Sheet1!A1:C5; needs
// spreadsheets.readonly); each half is skipped without its variable.
func TestLiveDocsAndSheetsReads(t *testing.T) {
	c, _ := liveConnector(t)
	ctx := context.Background()
	if id := os.Getenv("GOOGLE_LIVE_DOCUMENT_ID"); id != "" {
		res, err := c.Docs().Call(ctx, liveCall("docs.get_text", map[string]any{"document_id": id}))
		if err != nil {
			t.Fatalf("docs.get_text: %v", err)
		}
		doc, ok := res.Content.(google.DocumentContent)
		if !ok || res.Unavailable {
			t.Fatalf("content = %#v markers %+v", res.Content, res)
		}
		t.Logf("document %q: %d characters (truncated=%v)", doc.Title, doc.Characters, doc.Truncated)
	} else {
		t.Log("GOOGLE_LIVE_DOCUMENT_ID is unset; docs.get_text skipped")
	}
	if spec := os.Getenv("GOOGLE_LIVE_SHEET_RANGE"); spec != "" {
		id, rng, ok := strings.Cut(spec, "!")
		if !ok {
			t.Fatalf("GOOGLE_LIVE_SHEET_RANGE = %q, want <spreadsheet id>!<range>", spec)
		}
		res, err := c.Sheets().Call(ctx, liveCall("sheets.read_range", map[string]any{"spreadsheet_id": id, "range": rng, "max_rows": 5}))
		if err != nil {
			t.Fatalf("sheets.read_range: %v", err)
		}
		values, ok := res.Content.(google.RangeValues)
		if !ok || res.Unavailable {
			t.Fatalf("content = %#v markers %+v", res.Content, res)
		}
		t.Logf("range %s: %d rows (empty=%v)", values.Range, values.RowCount, res.Empty)
	} else {
		t.Log("GOOGLE_LIVE_SHEET_RANGE is unset; sheets.read_range skipped")
	}
}

// TestLiveCreateFolderAndReconcile creates a folder in My Drive under a
// fresh operation id (needs drive.file and GOOGLE_LIVE_WRITE=1), runs
// create_folder's check from the resource identity alone, as the
// ledger's reconciler would, and expects it to find the folder by its
// appProperties marker; the folder is deleted afterwards (best effort).
func TestLiveCreateFolderAndReconcile(t *testing.T) {
	c, token := liveConnector(t)
	if os.Getenv("GOOGLE_LIVE_WRITE") != "1" {
		t.Skip("GOOGLE_LIVE_WRITE is not 1")
	}
	ctx := context.Background()
	opID := connectors.NewAccountID()
	args := map[string]any{"name": "mcp-gateway live test " + opID[:8]}
	cl := liveCall("drive.create_folder", args)
	cl.OperationID = opID
	res, err := c.Drive().Call(ctx, cl)
	if err != nil {
		t.Fatalf("create_folder: %v", err)
	}
	created, ok := res.Content.(google.CreatedFolder)
	if !ok || created.ID == "" {
		t.Fatalf("create_folder content = %#v", res.Content)
	}
	t.Logf("created %s", created.URL)
	t.Cleanup(func() {
		svc, err := drive.NewService(ctx, option.WithTokenSource(oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})))
		if err == nil {
			err = svc.Files.Delete(created.ID).SupportsAllDrives(true).Do()
		}
		if err != nil {
			t.Logf("deleting the live folder: %v", err)
		}
	})
	var tool connectors.Tool
	for _, tl := range c.Drive().Tools() {
		if tl.Name == google.ToolCreateFolder {
			tool = tl
		}
	}
	in := connectors.ReconcileInput{
		Call:             connectors.Call{Principal: connectors.Principal{UserID: "live"}, Tool: tool.FullName(), Account: "live-account", OperationID: opID},
		OperationID:      opID,
		ResourceIdentity: tool.ResourceIdentity(args),
	}
	out, err := tool.Reconcile.Check(ctx, in)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if out.Outcome != connectors.ReconcileFound || out.ResourceID != created.ID {
		t.Fatalf("Check = %+v, want found %s", out, created.ID)
	}
}
