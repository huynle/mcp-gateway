package google_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

// reconcileInput builds what the ledger's reconciler hands Check: the
// call without arguments, the operation id and the resource identity the
// tool produced for the original arguments (decision enlsy40f).
func reconcileInput(t *testing.T, c *google.Connector, full string, args map[string]any) (connectors.Tool, connectors.ReconcileInput) {
	t.Helper()
	tool := toolOf(t, c, full)
	return tool, connectors.ReconcileInput{
		Call:             connectors.Call{Principal: connectors.Principal{UserID: alice}, Tool: full, Account: acct, OperationID: opID},
		OperationID:      opID,
		ResourceIdentity: tool.ResourceIdentity(args),
	}
}

func wantFound(t *testing.T, out connectors.ReconcileResult, err error, id string) {
	t.Helper()
	if err != nil || out.Outcome != connectors.ReconcileFound || out.ResourceID != id {
		t.Fatalf("Check = %+v, %v; want found %s", out, err, id)
	}
}

func wantNotFound(t *testing.T, out connectors.ReconcileResult, err error) {
	t.Helper()
	if err != nil || out.Outcome != connectors.ReconcileNotFound || out.ResourceID != "" {
		t.Fatalf("Check = %+v, %v; want not_found", out, err)
	}
}

func wantCannotTell(t *testing.T, out connectors.ReconcileResult, err error) {
	t.Helper()
	if err == nil || out.Outcome != "" {
		t.Fatalf("Check = %+v, %v; want an error (cannot tell yet)", out, err)
	}
	if strings.Contains(err.Error(), testToken) {
		t.Errorf("error leaks the token: %v", err)
	}
}

// --- calendar.create_event: stable id --------------------------------------------------

const checkEventPath = "GET /calendar/v3/calendars/primary/events/" + wantEventID

func TestCheckEvent(t *testing.T) {
	args := map[string]any{"summary": "x", "start": "2026-10-10", "end": "2026-10-11"}
	t.Run("found", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{checkEventPath: {status: 200, body: "created_event.json"}})
		c, tk := newConnector(t, srv, connectors.Bounds{})
		tool, in := reconcileInput(t, c, "calendar.create_event", args)
		out, err := tool.Reconcile.Check(context.Background(), in)
		wantFound(t, out, err, wantEventID)
		if len(tk.calls) != 1 || tk.calls[0] != alice+"/"+acct {
			t.Errorf("token calls = %v", tk.calls)
		}
	})
	t.Run("another calendar from the identity", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{"GET /calendar/v3/calendars/team@example.test/events/" + wantEventID: {status: 200, body: "created_event.json"}})
		c, _ := newConnector(t, srv, connectors.Bounds{})
		tool, in := reconcileInput(t, c, "calendar.create_event", map[string]any{"calendar_id": "Team@example.test", "summary": "x", "start": "2026-10-10", "end": "2026-10-11"})
		out, err := tool.Reconcile.Check(context.Background(), in)
		wantFound(t, out, err, wantEventID)
	})
	for name, rt := range map[string]route{"404": {status: 404, body: "error_not_found.json"}, "410": {status: 410, body: "error_not_found.json"}} {
		t.Run("not found "+name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{checkEventPath: rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, "calendar.create_event", args)
			out, err := tool.Reconcile.Check(context.Background(), in)
			wantNotFound(t, out, err)
		})
	}
	for name, rt := range map[string]route{
		"500": {status: 500, body: "error_server.json"}, "401": {status: 401, body: "error_unauthorized.json"},
		"403": {status: 403, body: "error_forbidden.json"}, "429": {status: 429, body: "error_rate_limit_429.json"},
	} {
		t.Run("cannot tell "+name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{checkEventPath: rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, "calendar.create_event", args)
			out, err := tool.Reconcile.Check(context.Background(), in)
			wantCannotTell(t, out, err)
		})
	}
	t.Run("missing identity or operation", func(t *testing.T) {
		c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
		tool, in := reconcileInput(t, c, "calendar.create_event", args)
		in.ResourceIdentity = map[string]string{}
		if _, err := tool.Reconcile.Check(context.Background(), in); !errors.Is(err, google.ErrNotReconcilable) {
			t.Errorf("without calendar_id: err = %v, want ErrNotReconcilable", err)
		}
		_, in = reconcileInput(t, c, "calendar.create_event", args)
		in.OperationID, in.Call.OperationID = "", ""
		if _, err := tool.Reconcile.Check(context.Background(), in); !errors.Is(err, google.ErrNotReconcilable) {
			t.Errorf("without operation id: err = %v, want ErrNotReconcilable", err)
		}
		_, in = reconcileInput(t, c, "calendar.create_event", args)
		in.Call.Account = ""
		if _, err := tool.Reconcile.Check(context.Background(), in); !errors.Is(err, google.ErrNotReconcilable) {
			t.Errorf("without account: err = %v, want ErrNotReconcilable", err)
		}
	})
}

// --- tasks.create: marker -----------------------------------------------------------------

func TestCheckTask(t *testing.T) {
	args := map[string]any{"title": "x"}
	t.Run("found on a later page", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{listTasksPath: {pages: map[string]route{
			"1":             {status: 200, body: "tasks_check_page1.json"},
			"tasks-check-2": {status: 200, body: "tasks_check_page2.json"},
		}}})
		c, _ := newConnector(t, srv, connectors.Bounds{})
		tool, in := reconcileInput(t, c, "tasks.create", args)
		out, err := tool.Reconcile.Check(context.Background(), in)
		wantFound(t, out, err, "task_new_001")
		q := query(t, srv, "/tasks/v1/lists/@default/tasks")
		if q.Get("showCompleted") != "true" || q.Get("showHidden") != "true" || q.Get("maxResults") != "100" {
			t.Errorf("listing query = %v, want every task, 100 per page", q)
		}
	})
	t.Run("not found at the end of the list", func(t *testing.T) {
		// page1 carries a next page token; the second page is empty and
		// final, so the list ends without the marker.
		srv := newAPIServer(t, map[string]route{listTasksPath: {pages: map[string]route{
			"1":             {status: 200, body: "tasks_check_page1.json"},
			"tasks-check-2": {status: 200, body: "tasks_list_empty.json"},
		}}})
		c, _ := newConnector(t, srv, connectors.Bounds{})
		tool, in := reconcileInput(t, c, "tasks.create", args)
		out, err := tool.Reconcile.Check(context.Background(), in)
		wantNotFound(t, out, err)
	})
	t.Run("another tasklist from the identity", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{"GET /tasks/v1/lists/MTIzNDU/tasks": {status: 200, body: "tasks_check_page2.json"}})
		c, _ := newConnector(t, srv, connectors.Bounds{})
		tool, in := reconcileInput(t, c, "tasks.create", map[string]any{"tasklist": "MTIzNDU", "title": "x"})
		out, err := tool.Reconcile.Check(context.Background(), in)
		wantFound(t, out, err, "task_new_001")
	})
	t.Run("too many pages is cannot tell", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{listTasksPath: {pages: map[string]route{
			"1": {status: 200, body: "tasks_check_more.json"}, "again": {status: 200, body: "tasks_check_more.json"},
		}}})
		c, _ := newConnector(t, srv, connectors.Bounds{})
		tool, in := reconcileInput(t, c, "tasks.create", args)
		out, err := tool.Reconcile.Check(context.Background(), in)
		wantCannotTell(t, out, err)
		if n := srv.Count(listTasksPath); n != google.MaxReconcilePages {
			t.Errorf("listed %d pages, want %d", n, google.MaxReconcilePages)
		}
	})
	t.Run("listing error is cannot tell", func(t *testing.T) {
		for name, rt := range map[string]route{"404": {status: 404, body: "error_not_found.json"}, "500": {status: 500, body: "error_server.json"}} {
			srv := newAPIServer(t, map[string]route{listTasksPath: rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, "tasks.create", args)
			out, err := tool.Reconcile.Check(context.Background(), in)
			if err == nil {
				t.Errorf("%s: Check = %+v, want an error", name, out)
			}
		}
	})
	t.Run("missing identity", func(t *testing.T) {
		c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
		tool, in := reconcileInput(t, c, "tasks.create", args)
		in.ResourceIdentity = map[string]string{}
		if _, err := tool.Reconcile.Check(context.Background(), in); !errors.Is(err, google.ErrNotReconcilable) {
			t.Errorf("err = %v, want ErrNotReconcilable", err)
		}
	})
}

// --- gmail.send: rfc822msgid --------------------------------------------------------------

const (
	sentScanMetadataHit   = "GET /gmail/v1/users/me/messages/18f9sent0001"
	sentScanMetadataOther = "GET /gmail/v1/users/me/messages/18f9other0001"
)

func TestCheckSent(t *testing.T) {
	args := map[string]any{"to": "bob@example.test", "subject": "s", "body": "b"}
	search := "rfc822msgid:op-" + opID + "@mcp-gateway"
	t.Run("found by search", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{listMessagesPath: {byQuery: map[string]route{search: {status: 200, body: "messages_list_marker_hit.json"}}}})
		c, _ := newConnector(t, srv, connectors.Bounds{})
		tool, in := reconcileInput(t, c, "gmail.send", args)
		out, err := tool.Reconcile.Check(context.Background(), in)
		wantFound(t, out, err, "18f9sent0001")
		q := query(t, srv, "/gmail/v1/users/me/messages")
		if q.Get("includeSpamTrash") != "true" {
			t.Errorf("search query = %v, want includeSpamTrash", q)
		}
	})
	t.Run("found by scanning recent sent mail", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{
			listMessagesPath: {byQuery: map[string]route{
				search: {status: 200, body: "messages_list_empty.json"},
				"":     {status: 200, body: "messages_list_sent_scan.json"},
			}},
			sentScanMetadataOther: {status: 200, body: "message_metadata_sent_other.json"},
			sentScanMetadataHit:   {status: 200, body: "message_metadata_sent_hit.json"},
		})
		c, _ := newConnector(t, srv, connectors.Bounds{})
		tool, in := reconcileInput(t, c, "gmail.send", args)
		out, err := tool.Reconcile.Check(context.Background(), in)
		wantFound(t, out, err, "18f9sent0001")
		reqs := srv.Requests()
		var scan recorded
		for _, r := range reqs {
			if r.URL.Path == "/gmail/v1/users/me/messages" && r.URL.Query().Get("q") == "" {
				scan = r
			}
		}
		if scan.Request == nil || strings.Join(scan.URL.Query()["labelIds"], ",") != "SENT" || scan.URL.Query().Get("maxResults") == "" {
			t.Errorf("scan listing = %v, want labelIds=SENT and a bounded maxResults", scan)
		}
	})
	t.Run("not found after search and scan", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{
			listMessagesPath: {byQuery: map[string]route{
				search: {status: 200, body: "messages_list_empty.json"},
				"":     {status: 200, body: `{"messages":[{"id":"18f9other0001","threadId":"18f9other0001"}],"resultSizeEstimate":1}`},
			}},
			sentScanMetadataOther: {status: 200, body: "message_metadata_sent_other.json"},
		})
		c, _ := newConnector(t, srv, connectors.Bounds{})
		tool, in := reconcileInput(t, c, "gmail.send", args)
		out, err := tool.Reconcile.Check(context.Background(), in)
		wantNotFound(t, out, err)
	})
	t.Run("search error is cannot tell", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{listMessagesPath: {status: 500, body: "error_server.json"}})
		c, _ := newConnector(t, srv, connectors.Bounds{})
		tool, in := reconcileInput(t, c, "gmail.send", args)
		out, err := tool.Reconcile.Check(context.Background(), in)
		wantCannotTell(t, out, err)
	})
	t.Run("scan metadata error is cannot tell", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{
			listMessagesPath: {byQuery: map[string]route{
				search: {status: 200, body: "messages_list_empty.json"},
				"":     {status: 200, body: "messages_list_sent_scan.json"},
			}},
			sentScanMetadataOther: {status: 500, body: "error_server.json"},
		})
		c, _ := newConnector(t, srv, connectors.Bounds{})
		tool, in := reconcileInput(t, c, "gmail.send", args)
		out, err := tool.Reconcile.Check(context.Background(), in)
		wantCannotTell(t, out, err)
	})
	t.Run("missing operation id", func(t *testing.T) {
		c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
		tool, in := reconcileInput(t, c, "gmail.send", args)
		in.OperationID, in.Call.OperationID = "", ""
		if _, err := tool.Reconcile.Check(context.Background(), in); !errors.Is(err, google.ErrNotReconcilable) {
			t.Errorf("err = %v, want ErrNotReconcilable", err)
		}
	})
}

// --- gmail.create_draft: rfc822msgid over drafts --------------------------------------------

const (
	listDraftsPath  = "GET /gmail/v1/users/me/drafts"
	draftHitPath    = "GET /gmail/v1/users/me/drafts/r-7788990011223344556"
	draftOtherPath  = "GET /gmail/v1/users/me/drafts/r-1"
	wantDraftFoundA = "r-7788990011223344556"
)

func TestCheckDraft(t *testing.T) {
	args := map[string]any{"to": "bob@example.test", "subject": "s", "body": "b"}
	search := "rfc822msgid:op-" + opID + "@mcp-gateway"
	t.Run("found by search", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{listDraftsPath: {byQuery: map[string]route{search: {status: 200, body: "drafts_list_hit.json"}}}})
		c, _ := newConnector(t, srv, connectors.Bounds{})
		tool, in := reconcileInput(t, c, "gmail.create_draft", args)
		out, err := tool.Reconcile.Check(context.Background(), in)
		wantFound(t, out, err, wantDraftFoundA)
	})
	t.Run("found by scanning drafts", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{
			listDraftsPath: {byQuery: map[string]route{
				search: {status: 200, body: `{"resultSizeEstimate":0}`},
				"":     {status: 200, body: "drafts_list_scan.json"},
			}},
			draftOtherPath: {status: 200, body: "draft_metadata_other.json"},
			draftHitPath:   {status: 200, body: "draft_metadata_hit.json"},
		})
		c, _ := newConnector(t, srv, connectors.Bounds{})
		tool, in := reconcileInput(t, c, "gmail.create_draft", args)
		out, err := tool.Reconcile.Check(context.Background(), in)
		wantFound(t, out, err, wantDraftFoundA)
		if got := query(t, srv, "/gmail/v1/users/me/drafts/r-1").Get("format"); got != "metadata" {
			t.Errorf("draft lookup format = %q", got)
		}
	})
	t.Run("not found", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{
			listDraftsPath: {byQuery: map[string]route{
				search: {status: 200, body: `{"resultSizeEstimate":0}`},
				"":     {status: 200, body: `{"drafts":[{"id":"r-1","message":{"id":"18f9d1","threadId":"18f9d1"}}],"resultSizeEstimate":1}`},
			}},
			draftOtherPath: {status: 200, body: "draft_metadata_other.json"},
		})
		c, _ := newConnector(t, srv, connectors.Bounds{})
		tool, in := reconcileInput(t, c, "gmail.create_draft", args)
		out, err := tool.Reconcile.Check(context.Background(), in)
		wantNotFound(t, out, err)
	})
	t.Run("listing error is cannot tell", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{listDraftsPath: {status: 401, body: "error_unauthorized.json"}})
		c, _ := newConnector(t, srv, connectors.Bounds{})
		tool, in := reconcileInput(t, c, "gmail.create_draft", args)
		out, err := tool.Reconcile.Check(context.Background(), in)
		wantCannotTell(t, out, err)
	})
}
