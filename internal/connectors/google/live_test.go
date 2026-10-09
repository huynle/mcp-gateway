//go:build live

package google_test

import (
	"context"
	"os"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"google.golang.org/api/calendar/v3"
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
