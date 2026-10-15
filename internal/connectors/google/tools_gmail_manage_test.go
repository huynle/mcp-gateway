package google_test

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

// Gmail management: get_thread, list_drafts, get_attachment,
// modify_labels, trash, send_draft.

const (
	gm            = "/gmail/v1/users/me/"
	threadPath    = "GET " + gm + "threads/18f1a2b3c4d5e6f0"
	msgPath       = "GET " + gm + "messages/18f1a2b3c4d5e6f7"
	attachPath    = "GET " + gm + "messages/18f1a2b3c4d5e6f7/attachments/ANGjdJ8example"
	modifyMsgPath = "POST " + gm + "messages/18f1a2b3c4d5e6f7/modify"
	modifyThrPath = "POST " + gm + "threads/18f1a2b3c4d5e6f0/modify"
	trashMsgPath  = "POST " + gm + "messages/18f1a2b3c4d5e6f7/trash"
	trashThrPath  = "POST " + gm + "threads/18f1a2b3c4d5e6f0/trash"
	sendDraftPath = "POST " + gm + "drafts/send"
	draft1Path    = "GET " + gm + "drafts/r-1"
)

func TestGmailManageDeclarations(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	r, w := connectors.KindRead, connectors.KindWrite
	declared(t, c, "gmail.get_thread", r, []string{google.ScopeGmailReadonly}, "")
	declared(t, c, "gmail.list_drafts", r, []string{google.ScopeGmailReadonly}, "")
	att := declared(t, c, "gmail.get_attachment", r, []string{google.ScopeGmailReadonly}, "")
	if att.Bounds.MaxResultBytes < google.MaxDownloadBytes*4/3 {
		t.Errorf("get_attachment MaxResultBytes = %d, too small for a %d-byte download in base64", att.Bounds.MaxResultBytes, google.MaxDownloadBytes)
	}
	declared(t, c, "gmail.modify_labels", w, []string{google.ScopeGmailModify}, connectors.ReconcileStableID)
	declared(t, c, "gmail.trash", w, []string{google.ScopeGmailModify}, connectors.ReconcileStableID)
	declared(t, c, "gmail.send_draft", w, []string{google.ScopeGmailCompose}, connectors.ReconcileStableID)
	id := toolOf(t, c, "gmail.modify_labels").ResourceIdentity(map[string]any{"thread_id": "t1", "add_label_ids": []any{"STARRED", "IMPORTANT"}, "remove_label_ids": []any{"INBOX"}})
	if id["thread_id"] != "t1" || id["add_labels"] != "IMPORTANT,STARRED" || id["remove_labels"] != "INBOX" {
		t.Errorf("modify_labels identity = %v", id)
	}
}

func TestGetThread(t *testing.T) {
	srv := newAPIServer(t, map[string]route{threadPath: {status: 200, body: "thread_full.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("gmail.get_thread", map[string]any{"thread_id": "18f1a2b3c4d5e6f0"}))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		ID       string `json:"id"`
		Messages []struct {
			ID, Subject, Body string
		} `json:"messages"`
	}
	decode(t, res, &out)
	if out.ID != "18f1a2b3c4d5e6f0" || len(out.Messages) != 2 || !strings.Contains(out.Messages[0].Body, "gateway review") || out.Messages[1].Subject != "Gateway review" {
		t.Errorf("out = %+v", out)
	}
	if q := query(t, srv, "/gmail/v1/users/me/threads/18f1a2b3c4d5e6f0"); q.Get("format") != "full" {
		t.Errorf("format = %q", q.Get("format"))
	}
	// Small bounds: the oldest bodies are cut first.
	c2, _ := newConnector(t, srv, connectors.Bounds{MaxResultBytes: 1200})
	res, err = run(t, c2, call("gmail.get_thread", map[string]any{"thread_id": "18f1a2b3c4d5e6f0"}))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Partial || encodedSizeOf(t, res) > 1200 {
		t.Errorf("bounded thread: partial %v, size %d", res.Partial, encodedSizeOf(t, res))
	}
	for _, tc := range readErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{threadPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := run(t, c, call("gmail.get_thread", map[string]any{"thread_id": "18f1a2b3c4d5e6f0"}))
			checkReadError(t, tc, res, err)
		})
	}
}

func TestListDrafts(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		listDraftsPath: {status: 200, body: "drafts_list_scan.json"},
		draft1Path:     {status: 200, body: "draft_metadata_plain.json"},
		draftHitPath:   {status: 200, body: "draft_metadata_hit.json"},
	})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("gmail.list_drafts", map[string]any{"q": "subject:plan"}))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Items []struct {
			DraftID   string `json:"draft_id"`
			MessageID string `json:"message_id"`
			Subject   string `json:"subject"`
			To        string `json:"to"`
		} `json:"items"`
	}
	decode(t, res, &out)
	if len(out.Items) != 2 || out.Items[0].DraftID != "r-1" || out.Items[0].Subject != "Plan" || out.Items[0].To != "bob@example.test" || out.Items[1].MessageID != "18f9draft0001" {
		t.Errorf("out = %+v", out)
	}
	if q := query(t, srv, "/gmail/v1/users/me/drafts"); q.Get("q") != "subject:plan" {
		t.Errorf("q = %q", q.Get("q"))
	}
}

func TestGetAttachment(t *testing.T) {
	for name, tc := range map[string]struct {
		body, encoding, content string
	}{
		"text":   {"attachment_text.json", "text", "name,amount\nrent,1200\n"},
		"binary": {"attachment_binary.json", "base64", base64.StdEncoding.EncodeToString([]byte("\x89PNG\r\n\x1a\n\x00\x00binary"))},
	} {
		t.Run(name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{attachPath: {status: 200, body: tc.body}})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := run(t, c, call("gmail.get_attachment", map[string]any{"message_id": "18f1a2b3c4d5e6f7", "attachment_id": "ANGjdJ8example"}))
			if err != nil {
				t.Fatal(err)
			}
			var out struct {
				Size              int64
				Encoding, Content string
			}
			decode(t, res, &out)
			if out.Encoding != tc.encoding || out.Content != tc.content {
				t.Errorf("out = %+v", out)
			}
		})
	}
	srv := newAPIServer(t, map[string]route{attachPath: {status: 200, body: "attachment_huge.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	_, err := run(t, c, call("gmail.get_attachment", map[string]any{"message_id": "18f1a2b3c4d5e6f7", "attachment_id": "ANGjdJ8example"}))
	wantClass(t, err, google.ClassInvalidArgument, 0)
	_, err = run(t, c, call("gmail.get_attachment", map[string]any{"message_id": "18f1a2b3c4d5e6f7"}))
	wantClass(t, err, google.ClassInvalidArgument, 0)
}

func TestModifyLabels(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		modifyMsgPath: {status: 200, body: "message_minimal_starred.json"},
		modifyThrPath: {status: 200, body: `{"id":"18f1a2b3c4d5e6f0"}`},
	})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("gmail.modify_labels", map[string]any{"message_id": "18f1a2b3c4d5e6f7", "add_label_ids": []any{"STARRED"}, "remove_label_ids": []any{"INBOX", "UNREAD"}}))
	if err != nil {
		t.Fatal(err)
	}
	if ids := toolOf(t, c, "gmail.modify_labels").ResultIDs(res); ids["id"] != "18f1a2b3c4d5e6f7" {
		t.Errorf("ResultIDs = %v", ids)
	}
	body := bodyOf(t, srv.Last(t, modifyMsgPath))
	if add, _ := body["addLabelIds"].([]any); len(add) != 1 || add[0] != "STARRED" {
		t.Errorf("body = %v", body)
	}
	if _, err := run(t, c, write("gmail.modify_labels", map[string]any{"thread_id": "18f1a2b3c4d5e6f0", "remove_label_ids": []any{"INBOX"}})); err != nil {
		t.Fatal(err)
	}
	for _, args := range []map[string]any{
		{"message_id": "m"},
		{"add_label_ids": []any{"STARRED"}},
		{"message_id": "m", "thread_id": "t", "add_label_ids": []any{"STARRED"}},
		{"message_id": "m", "add_label_ids": []any{"STARRED"}, "remove_label_ids": []any{"STARRED"}},
	} {
		_, err := run(t, c, write("gmail.modify_labels", args))
		wantClass(t, err, google.ClassInvalidArgument, 0)
	}
	for _, tc := range writeErrorCases("message_minimal_starred.json") {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{modifyMsgPath: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("gmail.modify_labels", map[string]any{"message_id": "18f1a2b3c4d5e6f7", "add_label_ids": []any{"STARRED"}}))
			checkWriteError(t, tc, res, err)
		})
	}
	args := map[string]any{"message_id": "18f1a2b3c4d5e6f7", "add_label_ids": []any{"STARRED"}, "remove_label_ids": []any{"INBOX"}}
	for name, tc := range map[string]struct {
		path, body, want string
		args             map[string]any
	}{
		"message applied":     {msgPath, "message_minimal_starred.json", "found", args},
		"message not applied": {msgPath, "message_minimal_inbox.json", "not_found", args},
		"thread applied":      {threadPath, "thread_minimal_starred.json", "found", map[string]any{"thread_id": "18f1a2b3c4d5e6f0", "add_label_ids": []any{"STARRED"}}},
		"thread mixed":        {threadPath, "thread_minimal_mixed.json", "not_found", map[string]any{"thread_id": "18f1a2b3c4d5e6f0", "remove_label_ids": []any{"INBOX"}}},
		"500":                 {msgPath, "error_server.json", "cannot", args},
	} {
		t.Run("check "+name, func(t *testing.T) {
			status := 200
			if tc.body == "error_server.json" {
				status = 500
			}
			srv := newAPIServer(t, map[string]route{tc.path: {status: status, body: tc.body}})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, "gmail.modify_labels", tc.args)
			out, err := tool.Reconcile.Check(context.Background(), in)
			id := "18f1a2b3c4d5e6f7"
			if tc.path == threadPath {
				id = "18f1a2b3c4d5e6f0"
			}
			wantOutcome(t, out, err, tc.want, id)
		})
	}
}

func TestTrash(t *testing.T) {
	srv := newAPIServer(t, map[string]route{trashMsgPath: {status: 200, body: "message_minimal_trash.json"}, trashThrPath: {status: 200, body: `{"id":"18f1a2b3c4d5e6f0"}`}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	if _, err := run(t, c, write("gmail.trash", map[string]any{"message_id": "18f1a2b3c4d5e6f7"})); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, c, write("gmail.trash", map[string]any{"thread_id": "18f1a2b3c4d5e6f0"})); err != nil {
		t.Fatal(err)
	}
	_, err := run(t, c, write("gmail.trash", map[string]any{}))
	wantClass(t, err, google.ClassInvalidArgument, 0)
	for name, tc := range map[string]struct{ body, want string }{
		"trashed": {"message_minimal_trash.json", "found"},
		"inbox":   {"message_minimal_inbox.json", "not_found"},
	} {
		t.Run("check "+name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{msgPath: {status: 200, body: tc.body}})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, "gmail.trash", map[string]any{"message_id": "18f1a2b3c4d5e6f7"})
			out, err := tool.Reconcile.Check(context.Background(), in)
			wantOutcome(t, out, err, tc.want, "18f1a2b3c4d5e6f7")
		})
	}
}

func TestSendDraft(t *testing.T) {
	srv := newAPIServer(t, map[string]route{sendDraftPath: {status: 200, body: "draft_sent.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("gmail.send_draft", map[string]any{"draft_id": "r-1"}))
	if err != nil {
		t.Fatal(err)
	}
	ids := toolOf(t, c, "gmail.send_draft").ResultIDs(res)
	if ids["id"] != "18fsent01" || ids["thread_id"] != "18f9d1" {
		t.Errorf("ResultIDs = %v", ids)
	}
	if body := bodyOf(t, srv.Last(t, sendDraftPath)); body["id"] != "r-1" {
		t.Errorf("body = %v", body)
	}
	for _, tc := range writeErrorCases("draft_sent.json") {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{sendDraftPath: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("gmail.send_draft", map[string]any{"draft_id": "r-1"}))
			checkWriteError(t, tc, res, err)
		})
	}
	for name, tc := range map[string]struct {
		rt   route
		want string
	}{
		"still a draft": {route{status: 200, body: "draft_metadata_plain.json"}, "not_found"},
		"gone":          {route{status: 404, body: "error_not_found.json"}, "cannot"},
	} {
		t.Run("check "+name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{draft1Path: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, "gmail.send_draft", map[string]any{"draft_id": "r-1"})
			out, err := tool.Reconcile.Check(context.Background(), in)
			wantOutcome(t, out, err, tc.want, "")
		})
	}
}
