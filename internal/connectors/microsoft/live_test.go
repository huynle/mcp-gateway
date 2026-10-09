//go:build live

package microsoft_test

import (
	"context"
	"os"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/microsoft"
)

// liveConnector builds a connector against graph.microsoft.com with the
// delegated access token in MS_LIVE_TOKEN (a dedicated test account's
// token with at least Mail.Read; Calendars.ReadWrite for the create
// test). No account source: Graph decides on scopes.
func liveConnector(t *testing.T) *microsoft.Connector {
	t.Helper()
	token := os.Getenv("MS_LIVE_TOKEN")
	if token == "" {
		t.Skip("MS_LIVE_TOKEN is unset")
	}
	c, err := microsoft.New(microsoft.Options{
		Tokens: func(context.Context, string, string) oauth2.TokenSource {
			return oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
		},
		Timeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestLiveMailSearch lists the newest messages of the live mailbox.
// Behind the "live" build tag and skipped without the variable, so CI
// never runs it:
//
//	MS_LIVE_TOKEN=eyJ... go test -tags live -run Live ./internal/connectors/microsoft/
func TestLiveMailSearch(t *testing.T) {
	c := liveConnector(t)
	res, err := c.Call(context.Background(), connectors.Call{
		Principal: connectors.Principal{UserID: "live"}, Tool: "microsoft." + microsoft.ToolMailSearch, Account: "live-account", Args: map[string]any{"top": 3},
	})
	if err != nil {
		t.Fatalf("mail_search: %v", err)
	}
	page, ok := res.Content.(microsoft.MailPage)
	if !ok {
		t.Fatalf("content = %#v", res.Content)
	}
	if res.Unavailable {
		t.Fatalf("markers = %+v", res)
	}
	t.Logf("%d messages (empty=%v has_more=%v)", len(page.Items), res.Empty, page.HasMore)
}

// TestLiveCreateEventAndReconcile creates an event under a fresh
// operation id (transactionId), then runs calendar_create_event's
// reconciliation check from the resource identity alone, as the ledger's
// reconciler would, and expects it to find the event by its
// transactionId. The event is left in place (named after the operation
// id; delete it by hand). Needs Calendars.ReadWrite and
// MS_LIVE_WRITE=1 as well, so a read-only token never creates anything:
//
//	MS_LIVE_TOKEN=eyJ... MS_LIVE_WRITE=1 go test -tags live -run Live ./internal/connectors/microsoft/
func TestLiveCreateEventAndReconcile(t *testing.T) {
	if os.Getenv("MS_LIVE_WRITE") != "1" {
		t.Skip("MS_LIVE_WRITE is not 1")
	}
	c := liveConnector(t)
	ctx := context.Background()
	opID := connectors.NewAccountID()
	start := time.Now().Add(48 * time.Hour).Truncate(time.Hour)
	args := map[string]any{
		"subject": "mcp-gateway live test " + opID[:8], "start": start.UTC().Format(time.RFC3339), "end": start.Add(30 * time.Minute).UTC().Format(time.RFC3339),
		"body": "Created by the gateway's live test; safe to delete.",
	}
	res, err := c.Call(ctx, connectors.Call{
		Principal: connectors.Principal{UserID: "live"}, Tool: "microsoft." + microsoft.ToolCalendarCreateEvent, Account: "live-account", OperationID: opID, Args: args,
	})
	if err != nil {
		t.Fatalf("calendar_create_event: %v", err)
	}
	created, ok := res.Content.(microsoft.CreatedEvent)
	if !ok || created.ID == "" {
		t.Fatalf("content = %#v", res.Content)
	}
	t.Logf("created %s", created.WebLink)

	var tool connectors.Tool
	for _, tl := range c.Tools() {
		if tl.Name == microsoft.ToolCalendarCreateEvent {
			tool = tl
		}
	}
	in := connectors.ReconcileInput{
		Call:             connectors.Call{Principal: connectors.Principal{UserID: "live"}, Tool: tool.FullName(), Account: "live-account", OperationID: opID},
		OperationID:      opID,
		ResourceIdentity: tool.ResourceIdentity(args),
	}
	var out connectors.ReconcileResult
	for attempt := 0; attempt < 3; attempt++ {
		out, err = tool.Reconcile.Check(ctx, in)
		if err == nil && out.Outcome == connectors.ReconcileFound {
			break
		}
		time.Sleep(3 * time.Second)
	}
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if out.Outcome != connectors.ReconcileFound || out.ResourceID != created.ID {
		t.Fatalf("Check = %+v, want found %s", out, created.ID)
	}
}
