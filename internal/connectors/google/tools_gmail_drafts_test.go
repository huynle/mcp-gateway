package google_test

import (
	"context"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

// Increment 5: drafts (get_draft, update_draft, delete_draft) and the
// profile.

const (
	draftID          = "r-7788990011223344556"
	draftPath        = gm + "drafts/" + draftID
	getDraftPath     = "GET " + draftPath
	putDraftPath     = "PUT " + draftPath
	uploadPutDraft   = "PUT /upload" + draftPath
	deleteDraftPath  = "DELETE " + draftPath
	profilePath      = "GET " + gm + "profile"
	updateDraftCheck = draftPath
)

func TestGmailDraftsDeclarations(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	r, w := connectors.KindRead, connectors.KindWrite
	declared(t, c, "gmail.get_draft", r, []string{google.ScopeGmailReadonly}, "")
	declared(t, c, "gmail.get_profile", r, []string{google.ScopeGmailReadonly}, "")
	upd := declared(t, c, "gmail.update_draft", w, []string{google.ScopeGmailCompose}, connectors.ReconcileMarker)
	declared(t, c, "gmail.delete_draft", w, []string{google.ScopeGmailCompose}, connectors.ReconcileStableID)
	id := upd.ResourceIdentity(map[string]any{"draft_id": draftID, "to": "bob@example.test", "subject": "secret", "body": "secret",
		"attachments": []any{map[string]any{"filename": "a.txt", "content": "secret"}}})
	if id["draft_id"] != draftID || id["recipient_domains"] != "example.test" || id["attachments"] != "1" || len(id) != 3 {
		t.Errorf("update_draft identity = %v", id)
	}
	if !strings.Contains(string(upd.InputSchema), `"attachments"`) {
		t.Error("update_draft schema lacks attachments")
	}
}

func TestGetDraft(t *testing.T) {
	srv := newAPIServer(t, map[string]route{getDraftPath: {status: 200, body: "draft_full.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("gmail.get_draft", map[string]any{"draft_id": draftID}))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		DraftID string `json:"draft_id"`
		Message struct {
			ID          string `json:"id"`
			Subject     string `json:"subject"`
			Body        string `json:"body"`
			Attachments []struct {
				Filename string `json:"filename"`
			} `json:"attachments"`
			BodyTruncated bool `json:"body_truncated"`
		} `json:"message"`
	}
	decode(t, res, &out)
	if out.DraftID != draftID || out.Message.ID != "18f9draft0001" || out.Message.Subject != "Gateway review" ||
		!strings.Contains(out.Message.Body, "Friday") || len(out.Message.Attachments) != 1 {
		t.Errorf("out = %+v", out)
	}
	if q := query(t, srv, draftPath); q.Get("format") != "full" {
		t.Errorf("format = %q", q.Get("format"))
	}
	if id := toolOf(t, c, "gmail.get_draft").ResourceIdentity(map[string]any{"draft_id": draftID}); id["draft_id"] != draftID || len(id) != 1 {
		t.Errorf("identity = %v", id)
	}
	c2, _ := newConnector(t, srv, connectors.Bounds{MaxResultBytes: 620})
	res, err = run(t, c2, call("gmail.get_draft", map[string]any{"draft_id": draftID}))
	if err != nil {
		t.Fatal(err)
	}
	decode(t, res, &out)
	if !res.Partial || !out.Message.BodyTruncated || encodedSizeOf(t, res) > 620 {
		t.Errorf("bounded: partial %v, out %+v, size %d", res.Partial, out, encodedSizeOf(t, res))
	}
	_, err = run(t, c, call("gmail.get_draft", map[string]any{}))
	wantClass(t, err, google.ClassInvalidArgument, 0)
	for _, tc := range readErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{getDraftPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := run(t, c, call("gmail.get_draft", map[string]any{"draft_id": draftID}))
			checkReadError(t, tc, res, err)
		})
	}
}

func TestGetProfile(t *testing.T) {
	srv := newAPIServer(t, map[string]route{profilePath: {status: 200, body: "gmail_profile.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("gmail.get_profile", nil))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		EmailAddress  string `json:"email_address"`
		MessagesTotal int64  `json:"messages_total"`
		ThreadsTotal  int64  `json:"threads_total"`
		HistoryID     string `json:"history_id"`
	}
	decode(t, res, &out)
	if out.EmailAddress != "alice@example.test" || out.MessagesTotal != 12873 || out.ThreadsTotal != 9021 || out.HistoryID != "4471993" {
		t.Errorf("out = %+v", out)
	}
	if res.Empty || res.Partial {
		t.Errorf("res = %+v", res)
	}
	for _, tc := range readErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{profilePath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := run(t, c, call("gmail.get_profile", nil))
			checkReadError(t, tc, res, err)
		})
	}
}

func TestUpdateDraft(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		putDraftPath:    {status: 200, body: "created_draft.json"},
		uploadPutDraft:  {status: 200, body: "created_draft.json"},
		replyTargetPath: {status: 200, body: "reply_target_metadata.json"},
	})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("gmail.update_draft", map[string]any{"draft_id": draftID, "to": "bob@example.test", "subject": "New", "body": "Rewritten.", "in_reply_to": "18f1a2b3c4d5e6f7"}))
	if err != nil {
		t.Fatalf("update_draft: %v", err)
	}
	req := srv.Last(t, putDraftPath)
	if b := bodyOf(t, req); b["id"] != draftID {
		t.Errorf("body = %v, want the draft id", b)
	}
	headers, _, _ := strings.Cut(rawMessage(t, req.Body, true), "\r\n\r\n")
	if !strings.Contains(headers, "Message-ID: "+google.MessageID(opID)+"\r\n") || !strings.Contains(headers, "In-Reply-To: <abc123@example.test>\r\n") {
		t.Errorf("headers:\n%s", headers)
	}
	if threadOf(t, req.Body, true) != "18f1a2b3c4d5e6f0" {
		t.Errorf("threadId = %q", threadOf(t, req.Body, true))
	}
	d, ok := res.Content.(google.CreatedDraft)
	if !ok || d.ID != draftID || d.RFC822ID != google.MessageID(opID) {
		t.Errorf("content = %#v", res.Content)
	}
	if ids := toolOf(t, c, "gmail.update_draft").ResultIDs(res); ids["id"] != draftID {
		t.Errorf("ResultIDs = %v", ids)
	}

	// With attachments: uploaded.
	if _, err := run(t, c, write("gmail.update_draft", map[string]any{"draft_id": draftID, "to": "bob@example.test", "subject": "s", "body": "b",
		"attachments": []any{map[string]any{"filename": "a.txt", "content": "hi"}}})); err != nil {
		t.Fatal(err)
	}
	meta, msg := uploaded(t, srv.Last(t, uploadPutDraft))
	if meta["id"] != draftID {
		t.Errorf("upload metadata = %v", meta)
	}
	if parts := mimeParts(t, msg); len(parts) != 2 || parts[1].filename != "a.txt" {
		t.Errorf("parts = %+v", parts)
	}

	tk.calls = nil
	for name, args := range map[string]map[string]any{
		"no draft":   {"to": "a@b.test", "subject": "s", "body": "b"},
		"bad draft":  {"draft_id": "a/b", "to": "a@b.test", "subject": "s", "body": "b"},
		"no to":      {"draft_id": draftID, "subject": "s", "body": "b"},
		"no body":    {"draft_id": draftID, "to": "a@b.test", "subject": "s"},
		"bad attach": {"draft_id": draftID, "to": "a@b.test", "subject": "s", "body": "b", "attachments": []any{"x"}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := run(t, c, write("gmail.update_draft", args))
			wantClass(t, err, google.ClassInvalidArgument, 0)
		})
	}
	if len(tk.calls) != 0 {
		t.Errorf("token calls for invalid arguments = %d", len(tk.calls))
	}
	for _, tc := range writeErrorCases("created_draft.json") {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{putDraftPath: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("gmail.update_draft", map[string]any{"draft_id": draftID, "to": "a@b.test", "subject": "s", "body": "b"}))
			checkWriteError(t, tc, res, err)
		})
	}
	args := map[string]any{"draft_id": draftID, "to": "a@b.test", "subject": "s", "body": "b"}
	for name, tc := range map[string]struct {
		rt   route
		want string
	}{
		"marker present": {route{status: 200, body: "draft_metadata_hit.json"}, "found"},
		"other content":  {route{status: 200, body: "draft_metadata_other.json"}, "not_found"},
		"draft gone":     {route{status: 404, body: "error_not_found.json"}, "cannot"},
		"500":            {route{status: 500, body: "error_server.json"}, "cannot"},
	} {
		t.Run("check "+name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"GET " + updateDraftCheck: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, "gmail.update_draft", args)
			out, err := tool.Reconcile.Check(context.Background(), in)
			wantOutcome(t, out, err, tc.want, draftID)
			if tc.want == "found" && query(t, srv, draftPath).Get("format") != "metadata" {
				t.Error("check must read the headers only")
			}
		})
	}
}

func TestDeleteDraft(t *testing.T) {
	srv := newAPIServer(t, map[string]route{deleteDraftPath: {status: 204}})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("gmail.delete_draft", map[string]any{"draft_id": draftID}))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		DraftID string `json:"draft_id"`
		Deleted bool   `json:"deleted"`
	}
	decode(t, res, &out)
	if out.DraftID != draftID || !out.Deleted {
		t.Errorf("out = %+v", out)
	}
	if ids := toolOf(t, c, "gmail.delete_draft").ResultIDs(res); ids["draft_id"] != draftID {
		t.Errorf("ResultIDs = %v", ids)
	}
	tk.calls = nil
	_, err = run(t, c, write("gmail.delete_draft", map[string]any{}))
	wantClass(t, err, google.ClassInvalidArgument, 0)
	if len(tk.calls) != 0 {
		t.Error("token fetched for invalid arguments")
	}
	for _, tc := range writeErrorCases("") {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{deleteDraftPath: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("gmail.delete_draft", map[string]any{"draft_id": draftID}))
			checkWriteError(t, tc, res, err)
		})
	}
	for name, tc := range map[string]struct {
		rt   route
		want string
	}{
		"gone":        {route{status: 404, body: "error_not_found.json"}, "found"},
		"still there": {route{status: 200, body: "draft_metadata_hit.json"}, "not_found"},
		"500":         {route{status: 500, body: "error_server.json"}, "cannot"},
		"403":         {route{status: 403, body: "error_forbidden.json"}, "cannot"},
	} {
		t.Run("check "+name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{getDraftPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, "gmail.delete_draft", map[string]any{"draft_id": draftID})
			out, err := tool.Reconcile.Check(context.Background(), in)
			wantOutcome(t, out, err, tc.want, draftID)
		})
	}
}
