package microsoft_test

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/microsoft"
)

func TestMailToolsMetadata(t *testing.T) {
	r, w := connectors.KindRead, connectors.KindWrite
	checkMeta(t, []toolMeta{
		{tool: "mail_list_folders", kind: r, scopes: []string{"Mail.Read"}, identity: map[string]string{}},
		{tool: "mail_list_attachments", kind: r, scopes: []string{"Mail.Read"}, required: []string{"message_id"},
			args: map[string]any{"message_id": "m-1"}, identity: map[string]string{"message": "m-1"}},
		{tool: "mail_get_attachment", kind: r, scopes: []string{"Mail.Read"}, required: []string{"message_id", "attachment_id"},
			args: map[string]any{"message_id": "m-1", "attachment_id": "a-1"}, identity: map[string]string{"message": "m-1", "attachment": "a-1"}},
		{tool: "mail_create_draft", kind: w, reconcile: connectors.ReconcileMarker, scopes: []string{"Mail.ReadWrite"}, required: []string{"subject", "body"},
			args: map[string]any{"subject": "secret", "body": "secret"}, identity: map[string]string{"mailbox": "me"}},
		{tool: "mail_send_draft", kind: w, reconcile: connectors.ReconcileStableID, scopes: []string{"Mail.Send"}, required: []string{"message_id"},
			args: map[string]any{"message_id": "d-1"}, identity: map[string]string{"message": "d-1"}},
		{tool: "mail_reply", kind: w, reconcile: connectors.ReconcileNone, scopes: []string{"Mail.Send"}, required: []string{"message_id", "comment"},
			args: map[string]any{"message_id": "m-1", "comment": "secret"}, identity: map[string]string{"message": "m-1"}},
		{tool: "mail_forward", kind: w, reconcile: connectors.ReconcileNone, scopes: []string{"Mail.Send"}, required: []string{"message_id", "to"},
			args: map[string]any{"message_id": "m-1", "to": []any{"secret@example.test"}}, identity: map[string]string{"message": "m-1"}},
		{tool: "mail_move", kind: w, reconcile: connectors.ReconcileNone, scopes: []string{"Mail.ReadWrite"}, required: []string{"message_id", "destination"},
			args: map[string]any{"message_id": "m-1", "destination": "Archive"}, identity: map[string]string{"message": "m-1", "folder": "archive"}},
		{tool: "mail_mark_read", kind: w, reconcile: connectors.ReconcileStableID, scopes: []string{"Mail.ReadWrite"}, required: []string{"message_id"},
			args: map[string]any{"message_id": "m-1", "is_read": false}, identity: map[string]string{"message": "m-1", "is_read": "false"}},
		{tool: "mail_delete", kind: w, reconcile: connectors.ReconcileStableID, scopes: []string{"Mail.ReadWrite"}, required: []string{"message_id"},
			args: map[string]any{"message_id": "m-1"}, identity: map[string]string{"message": "m-1"}},
	})
}

func TestMailListFolders(t *testing.T) {
	srv, res := mustRun(t, map[string]route{"GET /v1.0/me/mailFolders": {status: 200, body: `{"value":[
		{"id":"f-1","displayName":"Inbox","parentFolderId":"root","totalItemCount":10,"unreadItemCount":2,"childFolderCount":1}],
		"@odata.nextLink":"https://graph.example.test/v1.0/me/mailFolders?$skiptoken=2"}`}}, "mail_list_folders", map[string]any{"top": 5}, false)
	var out struct {
		HasMore bool `json:"has_more"`
		Items   []struct {
			ID     string `json:"id"`
			Name   string `json:"display_name"`
			Unread int    `json:"unread_count"`
			Total  int    `json:"total_count"`
		} `json:"items"`
	}
	decode(t, res, &out)
	if !out.HasMore || len(out.Items) != 1 || out.Items[0].Name != "Inbox" || out.Items[0].Unread != 2 || out.Items[0].Total != 10 {
		t.Errorf("out = %+v", out)
	}
	if q := query(t, srv, "/v1.0/me/mailFolders"); q.Get("$top") != "5" {
		t.Errorf("$top = %q", q.Get("$top"))
	}
	_, res = mustRun(t, map[string]route{"GET /v1.0/me/mailFolders": {status: 200, body: `{"value":[]}`}}, "mail_list_folders", nil, false)
	if !res.Empty {
		t.Error("empty folder list not marked Empty")
	}
	srv, res, err := run(t, map[string]route{"GET /v1.0/me/mailFolders": {status: 503, body: "error_server.json"}}, "mail_list_folders", nil, false)
	if err != nil || !res.Unavailable {
		t.Errorf("5xx: res %+v err %v, want Unavailable", res, err)
	}
	_ = srv
}

func TestMailListAttachments(t *testing.T) {
	srv, res := mustRun(t, map[string]route{"GET /v1.0/me/messages/m-1/attachments": {status: 200, body: `{"value":[
		{"id":"a-1","name":"report.pdf","contentType":"application/pdf","size":1234,"isInline":false}]}`}},
		"mail_list_attachments", map[string]any{"message_id": "m-1"}, false)
	var out struct {
		Items []struct {
			ID, Name, ContentType string
			Size                  int64
		} `json:"items"`
	}
	decode(t, res, &out)
	if len(out.Items) != 1 || out.Items[0].Name != "report.pdf" || out.Items[0].Size != 1234 {
		t.Errorf("out = %+v", out)
	}
	if sel := query(t, srv, "/v1.0/me/messages/m-1/attachments").Get("$select"); strings.Contains(sel, "contentBytes") || sel == "" {
		t.Errorf("$select = %q, want metadata only", sel)
	}
	wantInvalid(t, "mail_list_attachments", map[string]any{"message_id": "../me"}, false)
}

func TestMailGetAttachment(t *testing.T) {
	meta := "GET /v1.0/me/messages/m-1/attachments/a-1"
	value := "GET /v1.0/me/messages/m-1/attachments/a-1/$value"
	t.Run("text", func(t *testing.T) {
		_, res := mustRun(t, map[string]route{
			meta:  {status: 200, body: `{"id":"a-1","name":"notes.txt","contentType":"text/plain","size":11}`},
			value: {status: 200, body: "attachment_notes.txt"},
		}, "mail_get_attachment", map[string]any{"message_id": "m-1", "attachment_id": "a-1"}, false)
		var out struct {
			Name, Encoding, Content string
			Size                    int64
		}
		decode(t, res, &out)
		if out.Name != "notes.txt" || out.Encoding != "text" || out.Content != "hello notes" {
			t.Errorf("out = %+v", out)
		}
	})
	t.Run("binary is base64", func(t *testing.T) {
		_, res := mustRun(t, map[string]route{
			meta:  {status: 200, body: `{"id":"a-1","name":"logo.png","contentType":"image/png","size":4}`},
			value: {status: 200, body: "attachment_logo.bin"},
		}, "mail_get_attachment", map[string]any{"message_id": "m-1", "attachment_id": "a-1"}, false)
		var out struct{ Encoding, Content string }
		decode(t, res, &out)
		if out.Encoding != "base64" || out.Content != base64.StdEncoding.EncodeToString([]byte("\x89PNG")) {
			t.Errorf("out = %+v", out)
		}
	})
	t.Run("too large is refused before download", func(t *testing.T) {
		srv, _, err := run(t, map[string]route{
			meta: {status: 200, body: fmt.Sprintf(`{"id":"a-1","name":"big.zip","contentType":"application/zip","size":%d}`, microsoft.MaxContentBytes+1)},
		}, "mail_get_attachment", map[string]any{"message_id": "m-1", "attachment_id": "a-1"}, false)
		wantClass(t, err, microsoft.ClassInvalidArgument, 0)
		if srv.Count(value) != 0 {
			t.Error("downloaded an attachment over the cap")
		}
	})
	t.Run("not found", func(t *testing.T) {
		_, _, err := run(t, map[string]route{meta: {status: 404, body: "error_item_not_found.json"}},
			"mail_get_attachment", map[string]any{"message_id": "m-1", "attachment_id": "a-1"}, false)
		wantClass(t, err, microsoft.ClassNotFound, 404)
	})
	wantInvalid(t, "mail_get_attachment", map[string]any{"message_id": "m-1"}, false)
}

func TestMailCreateDraft(t *testing.T) {
	path := "POST /v1.0/me/messages"
	srv, res := mustRun(t, map[string]route{path: {status: 201, body: `{"id":"d-1","webLink":"https://outlook.example.test/d-1"}`}},
		"mail_create_draft", map[string]any{"to": []any{"bob@example.test"}, "subject": "Draft", "body": "Hi"}, true)
	body := jsonBody(t, srv.Last(t, path))
	if body["internetMessageId"] != internetMessageID || body["subject"] != "Draft" {
		t.Errorf("body = %v", body)
	}
	if to, _ := body["toRecipients"].([]any); len(to) != 1 {
		t.Errorf("toRecipients = %v", body["toRecipients"])
	}
	ids := toolNamed(t, mustConnector(t), "mail_create_draft").ResultIDs(res)
	if ids["id"] != "d-1" || ids["internet_message_id"] != internetMessageID {
		t.Errorf("ResultIDs = %v", ids)
	}
	got, err := check(t, map[string]route{"GET /v1.0/me/messages": {status: 200, body: `{"value":[{"id":"d-1","internetMessageId":"` + internetMessageID + `"}]}`}},
		"mail_create_draft", map[string]string{"mailbox": "me"})
	wantFound(t, got, err, "d-1")
	wantInvalid(t, "mail_create_draft", map[string]any{"subject": "s"}, true)
}

func TestMailSendDraft(t *testing.T) {
	path := "POST /v1.0/me/messages/d-1/send"
	srv, res := mustRun(t, map[string]route{path: {status: 202}}, "mail_send_draft", map[string]any{"message_id": "d-1"}, true)
	if srv.Count(path) != 1 || toolNamed(t, mustConnector(t), "mail_send_draft").ResultIDs(res)["message_id"] != "d-1" {
		t.Errorf("res = %+v", res)
	}
	get := "GET /v1.0/me/messages/d-1"
	got, err := check(t, map[string]route{get: {status: 200, body: `{"id":"d-1","isDraft":false}`}}, "mail_send_draft", map[string]string{"message": "d-1"})
	wantFound(t, got, err, "d-1")
	got, err = check(t, map[string]route{get: {status: 200, body: `{"id":"d-1","isDraft":true}`}}, "mail_send_draft", map[string]string{"message": "d-1"})
	wantNotFound(t, got, err)
	if _, err := check(t, map[string]route{get: {status: 404, body: "error_item_not_found.json"}}, "mail_send_draft", map[string]string{"message": "d-1"}); err == nil {
		t.Error("a vanished draft must be cannot-tell")
	}
	runWriteErrorCases(t, path, route{status: 202}, "mail_send_draft", map[string]any{"message_id": "d-1"})
}

func TestMailReplyAndForward(t *testing.T) {
	srv, _ := mustRun(t, map[string]route{"POST /v1.0/me/messages/m-1/reply": {status: 202}}, "mail_reply", map[string]any{"message_id": "m-1", "comment": "Thanks!"}, true)
	if b := jsonBody(t, srv.Last(t, "POST /v1.0/me/messages/m-1/reply")); b["comment"] != "Thanks!" {
		t.Errorf("reply body = %v", b)
	}
	srv, _ = mustRun(t, map[string]route{"POST /v1.0/me/messages/m-1/replyAll": {status: 202}}, "mail_reply", map[string]any{"message_id": "m-1", "comment": "All", "reply_all": true}, true)
	if srv.Count("POST /v1.0/me/messages/m-1/replyAll") != 1 {
		t.Error("reply_all did not use replyAll")
	}
	srv, _ = mustRun(t, map[string]route{"POST /v1.0/me/messages/m-1/forward": {status: 202}}, "mail_forward", map[string]any{"message_id": "m-1", "to": []any{"Bob <bob@example.test>"}, "comment": "FYI"}, true)
	b := jsonBody(t, srv.Last(t, "POST /v1.0/me/messages/m-1/forward"))
	if to, _ := b["toRecipients"].([]any); len(to) != 1 || b["comment"] != "FYI" {
		t.Errorf("forward body = %v", b)
	}
	wantInvalid(t, "mail_forward", map[string]any{"message_id": "m-1", "to": []any{}}, true)
	wantInvalid(t, "mail_reply", map[string]any{"message_id": "m-1", "comment": strings.Repeat("x", 1<<20+1)}, true)
}

func TestMailMoveMarkReadDelete(t *testing.T) {
	srv, res := mustRun(t, map[string]route{"POST /v1.0/me/messages/m-1/move": {status: 201, body: `{"id":"m-1-moved"}`}}, "mail_move", map[string]any{"message_id": "m-1", "destination": "Archive"}, true)
	if b := jsonBody(t, srv.Last(t, "POST /v1.0/me/messages/m-1/move")); b["destinationId"] != "archive" {
		t.Errorf("move body = %v", b)
	}
	if ids := toolNamed(t, mustConnector(t), "mail_move").ResultIDs(res); ids["id"] != "m-1-moved" {
		t.Errorf("ResultIDs = %v", ids)
	}
	wantInvalid(t, "mail_move", map[string]any{"message_id": "m-1"}, true)

	srv, _ = mustRun(t, map[string]route{"PATCH /v1.0/me/messages/m-1": {status: 200, body: `{"id":"m-1","isRead":true}`}}, "mail_mark_read", map[string]any{"message_id": "m-1"}, true)
	if b := jsonBody(t, srv.Last(t, "PATCH /v1.0/me/messages/m-1")); b["isRead"] != true || len(b) != 1 {
		t.Errorf("patch body = %v (is_read defaults to true)", b)
	}
	get := "GET /v1.0/me/messages/m-1"
	got, err := check(t, map[string]route{get: {status: 200, body: `{"id":"m-1","isRead":false}`}}, "mail_mark_read", map[string]string{"message": "m-1", "is_read": "false"})
	wantFound(t, got, err, "m-1")
	got, err = check(t, map[string]route{get: {status: 200, body: `{"id":"m-1","isRead":true}`}}, "mail_mark_read", map[string]string{"message": "m-1", "is_read": "false"})
	wantNotFound(t, got, err)

	srv, _ = mustRun(t, map[string]route{"DELETE /v1.0/me/messages/m-1": {status: 204}}, "mail_delete", map[string]any{"message_id": "m-1"}, true)
	if srv.Count("DELETE /v1.0/me/messages/m-1") != 1 {
		t.Error("no DELETE sent")
	}
	got, err = check(t, map[string]route{get: {status: 404, body: "error_item_not_found.json"}}, "mail_delete", map[string]string{"message": "m-1"})
	wantFound(t, got, err, "m-1")
	got, err = check(t, map[string]route{get: {status: 200, body: `{"id":"m-1"}`}}, "mail_delete", map[string]string{"message": "m-1"})
	wantNotFound(t, got, err)
	if _, err := check(t, nil, "mail_delete", map[string]string{}); err == nil {
		t.Error("check without a message id must fail")
	}
	runWriteErrorCases(t, "DELETE /v1.0/me/messages/m-1", route{status: 204}, "mail_delete", map[string]any{"message_id": "m-1"})
}
