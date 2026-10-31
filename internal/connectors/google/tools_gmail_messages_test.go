package google_test

import (
	"context"
	"mime"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

// Increment 5: message management (forward, untrash, delete,
// batch_modify_labels).

const (
	untrashMsgPath  = "POST " + gm + "messages/18f1a2b3c4d5e6f7/untrash"
	untrashThrPath  = "POST " + gm + "threads/18f1a2b3c4d5e6f0/untrash"
	deleteMsgPath   = "DELETE " + gm + "messages/18f1a2b3c4d5e6f7"
	deleteThrPath   = "DELETE " + gm + "threads/18f1a2b3c4d5e6f0"
	batchModifyPath = "POST " + gm + "messages/batchModify"
	htmlMsgPath     = "GET " + gm + "messages/18f1a2b3c4d5e6f9"
)

func TestGmailMessagesDeclarations(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	w := connectors.KindWrite
	fwd := declared(t, c, "gmail.forward", w, []string{google.ScopeGmailReadonly, google.ScopeGmailSend}, connectors.ReconcileMarker)
	declared(t, c, "gmail.untrash", w, []string{google.ScopeGmailModify}, connectors.ReconcileStableID)
	declared(t, c, "gmail.delete", w, []string{google.ScopeMail}, connectors.ReconcileStableID)
	batch := declared(t, c, "gmail.batch_modify_labels", w, []string{google.ScopeGmailModify}, connectors.ReconcileNone)

	id := fwd.ResourceIdentity(map[string]any{"message_id": "m1", "to": []any{"Bob <bob@example.test>"}, "bcc": "x@other.test", "note": "secret"})
	if id["message_id"] != "m1" || id["recipient_domains"] != "example.test,other.test" || len(id) != 2 {
		t.Errorf("forward identity = %v", id)
	}
	id = batch.ResourceIdentity(map[string]any{"message_ids": []any{"m3", "m1", "m2", "m1"}, "add_label_ids": []any{"STARRED", "Label_1"}, "remove_label_ids": "INBOX"})
	if id["message_count"] != "3" || id["add_labels"] != "Label_1,STARRED" || id["remove_labels"] != "INBOX" || len(id) != 3 {
		t.Errorf("batch identity = %v (count of unique ids and sorted labels; never the ids: they do not fit the audit bounds)", id)
	}
}

func TestUntrash(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		untrashMsgPath: {status: 200, body: "message_minimal_inbox.json"},
		untrashThrPath: {status: 200, body: `{"id":"18f1a2b3c4d5e6f0"}`},
	})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("gmail.untrash", map[string]any{"message_id": "18f1a2b3c4d5e6f7"}))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		ID, Target string
		Labels     []string
	}
	decode(t, res, &out)
	if out.ID != "18f1a2b3c4d5e6f7" || out.Target != "message" || strings.Join(out.Labels, ",") != "INBOX,UNREAD" {
		t.Errorf("out = %+v", out)
	}
	if ids := toolOf(t, c, "gmail.untrash").ResultIDs(res); ids["id"] != "18f1a2b3c4d5e6f7" || ids["target"] != "message" {
		t.Errorf("ResultIDs = %v", ids)
	}
	if _, err := run(t, c, write("gmail.untrash", map[string]any{"thread_id": "18f1a2b3c4d5e6f0"})); err != nil || srv.Count(untrashThrPath) != 1 {
		t.Fatalf("thread untrash: %v", err)
	}
	tk.calls = nil
	for _, args := range []map[string]any{{}, {"message_id": "a", "thread_id": "b"}, {"message_id": "a/b"}} {
		_, err := run(t, c, write("gmail.untrash", args))
		wantClass(t, err, google.ClassInvalidArgument, 0)
	}
	if len(tk.calls) != 0 {
		t.Errorf("token calls for invalid arguments = %d", len(tk.calls))
	}
	for _, tc := range writeErrorCases("message_minimal_inbox.json") {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{untrashMsgPath: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("gmail.untrash", map[string]any{"message_id": "18f1a2b3c4d5e6f7"}))
			checkWriteError(t, tc, res, err)
		})
	}
	msg := map[string]any{"message_id": "18f1a2b3c4d5e6f7"}
	for name, tc := range map[string]struct {
		path string
		rt   route
		args map[string]any
		want string
	}{
		"restored":        {msgPath, route{status: 200, body: "message_minimal_inbox.json"}, msg, "found"},
		"still in trash":  {msgPath, route{status: 200, body: "message_minimal_trash.json"}, msg, "not_found"},
		"thread restored": {threadPath, route{status: 200, body: "thread_minimal_starred.json"}, map[string]any{"thread_id": "18f1a2b3c4d5e6f0"}, "found"},
		"404":             {msgPath, route{status: 404, body: "error_not_found.json"}, msg, "cannot"},
		"500":             {msgPath, route{status: 500, body: "error_server.json"}, msg, "cannot"},
	} {
		t.Run("check "+name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{tc.path: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, "gmail.untrash", tc.args)
			out, err := tool.Reconcile.Check(context.Background(), in)
			id := "18f1a2b3c4d5e6f7"
			if tc.args["thread_id"] != nil {
				id = "18f1a2b3c4d5e6f0"
			}
			wantOutcome(t, out, err, tc.want, id)
		})
	}
}

func TestDeletePermanently(t *testing.T) {
	srv := newAPIServer(t, map[string]route{deleteMsgPath: {status: 204}, deleteThrPath: {status: 204}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("gmail.delete", map[string]any{"message_id": "18f1a2b3c4d5e6f7"}))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		ID, Target string
		Deleted    bool
	}
	decode(t, res, &out)
	if out.ID != "18f1a2b3c4d5e6f7" || out.Target != "message" || !out.Deleted {
		t.Errorf("out = %+v", out)
	}
	if ids := toolOf(t, c, "gmail.delete").ResultIDs(res); ids["id"] != "18f1a2b3c4d5e6f7" || ids["target"] != "message" {
		t.Errorf("ResultIDs = %v", ids)
	}
	if _, err := run(t, c, write("gmail.delete", map[string]any{"thread_id": "18f1a2b3c4d5e6f0"})); err != nil || srv.Count(deleteThrPath) != 1 {
		t.Fatalf("thread delete: %v", err)
	}
	_, err = run(t, c, write("gmail.delete", map[string]any{}))
	wantClass(t, err, google.ClassInvalidArgument, 0)
	for _, tc := range writeErrorCases("") {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{deleteMsgPath: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("gmail.delete", map[string]any{"message_id": "18f1a2b3c4d5e6f7"}))
			checkWriteError(t, tc, res, err)
		})
	}
	msg := map[string]any{"message_id": "18f1a2b3c4d5e6f7"}
	for name, tc := range map[string]struct {
		path string
		rt   route
		args map[string]any
		want string
	}{
		"gone":          {msgPath, route{status: 404, body: "error_not_found.json"}, msg, "found"},
		"still there":   {msgPath, route{status: 200, body: "message_minimal_trash.json"}, msg, "not_found"},
		"thread gone":   {threadPath, route{status: 404, body: "error_not_found.json"}, map[string]any{"thread_id": "18f1a2b3c4d5e6f0"}, "found"},
		"thread exists": {threadPath, route{status: 200, body: "thread_minimal_starred.json"}, map[string]any{"thread_id": "18f1a2b3c4d5e6f0"}, "not_found"},
		"500":           {msgPath, route{status: 500, body: "error_server.json"}, msg, "cannot"},
		"401":           {msgPath, route{status: 401, body: "error_unauthorized.json"}, msg, "cannot"},
	} {
		t.Run("check "+name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{tc.path: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, "gmail.delete", tc.args)
			out, err := tool.Reconcile.Check(context.Background(), in)
			id := "18f1a2b3c4d5e6f7"
			if tc.args["thread_id"] != nil {
				id = "18f1a2b3c4d5e6f0"
			}
			wantOutcome(t, out, err, tc.want, id)
		})
	}
}

func TestBatchModifyLabels(t *testing.T) {
	srv := newAPIServer(t, map[string]route{batchModifyPath: {status: 204}})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("gmail.batch_modify_labels", map[string]any{
		"message_ids": []any{"m1", "m2", "m1"}, "add_label_ids": []any{"Label_1"}, "remove_label_ids": []any{"INBOX", "UNREAD"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	body := bodyOf(t, srv.Last(t, batchModifyPath))
	if ids, _ := body["ids"].([]any); len(ids) != 2 || ids[0] != "m1" || ids[1] != "m2" {
		t.Errorf("ids = %v, want the unique ids in order", body["ids"])
	}
	if add, _ := body["addLabelIds"].([]any); len(add) != 1 || add[0] != "Label_1" {
		t.Errorf("body = %v", body)
	}
	if rm, _ := body["removeLabelIds"].([]any); len(rm) != 2 {
		t.Errorf("body = %v", body)
	}
	var out struct {
		MessageCount   int      `json:"message_count"`
		AddLabelIDs    []string `json:"add_label_ids"`
		RemoveLabelIDs []string `json:"remove_label_ids"`
	}
	decode(t, res, &out)
	if out.MessageCount != 2 || len(out.AddLabelIDs) != 1 || len(out.RemoveLabelIDs) != 2 {
		t.Errorf("out = %+v", out)
	}
	if ids := toolOf(t, c, "gmail.batch_modify_labels").ResultIDs(res); ids["message_count"] != "2" {
		t.Errorf("ResultIDs = %v", ids)
	}
	tk.calls = nil
	tooMany := make([]any, 1001)
	for i := range tooMany {
		tooMany[i] = "m" + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + strings.Repeat("y", i/26)
	}
	for name, args := range map[string]map[string]any{
		"no ids":          {"add_label_ids": []any{"STARRED"}},
		"no labels":       {"message_ids": []any{"m1"}},
		"bad id":          {"message_ids": []any{"a/b"}, "add_label_ids": []any{"STARRED"}},
		"both add+remove": {"message_ids": []any{"m1"}, "add_label_ids": []any{"STARRED"}, "remove_label_ids": []any{"STARRED"}},
		"too many":        {"message_ids": tooMany, "add_label_ids": []any{"STARRED"}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := run(t, c, write("gmail.batch_modify_labels", args))
			wantClass(t, err, google.ClassInvalidArgument, 0)
		})
	}
	if len(tk.calls) != 0 {
		t.Errorf("token calls for invalid arguments = %d", len(tk.calls))
	}
	for _, tc := range writeErrorCases("") {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{batchModifyPath: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("gmail.batch_modify_labels", map[string]any{"message_ids": []any{"m1"}, "add_label_ids": []any{"STARRED"}}))
			checkWriteError(t, tc, res, err)
		})
	}
}

func TestForward(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		msgPath:        {status: 200, body: "message_full.json"},
		attachPath:     {status: 200, body: "attachment_text.json"},
		uploadSendPath: {status: 200, body: "sent_message.json"},
	})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("gmail.forward", map[string]any{"message_id": "18f1a2b3c4d5e6f7", "to": "dave@other.test", "note": "FYI, see below."}))
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	if len(tk.calls) != 1 {
		t.Errorf("token calls = %v", tk.calls)
	}
	if got := query(t, srv, "/gmail/v1/users/me/messages/18f1a2b3c4d5e6f7").Get("format"); got != "full" {
		t.Errorf("original read with format %q, want full", got)
	}
	meta, msg := uploaded(t, srv.Last(t, uploadSendPath))
	if meta["threadId"] != "18f1a2b3c4d5e6f0" {
		t.Errorf("metadata = %v, want the original's thread", meta)
	}
	h := msg.Header
	if h.Get("To") != "dave@other.test" || h.Get("Message-ID") != google.MessageID(opID) || h.Get("In-Reply-To") != "<abc123@example.test>" {
		t.Errorf("headers = %v", h)
	}
	if subj, _ := new(mime.WordDecoder).DecodeHeader(h.Get("Subject")); subj != "Fwd: Gateway review" {
		t.Errorf("subject = %q", subj)
	}
	parts := mimeParts(t, msg)
	if len(parts) != 2 {
		t.Fatalf("parts = %+v, want the body and the original's attachment", parts)
	}
	body := parts[0].body
	for _, want := range []string{"FYI, see below.", "---------- Forwarded message ---------", "From: Bob Example <bob@example.test>", "Subject: Gateway review", "To: alice@example.test", "The gateway review is on Friday at 10."} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %q:\n%s", want, body)
		}
	}
	if !strings.HasPrefix(parts[0].contentType, "text/plain") {
		t.Errorf("body type = %q", parts[0].contentType)
	}
	if parts[1].filename != "agenda.pdf" || !strings.HasPrefix(parts[1].contentType, "application/pdf") || parts[1].body != "name,amount\nrent,1200\n" {
		t.Errorf("attachment = %+v", parts[1])
	}
	if sent, ok := res.Content.(google.SentMessage); !ok || sent.ID != "18f9sent0001" || sent.MessageID != google.MessageID(opID) {
		t.Errorf("content = %#v", res.Content)
	}
	if ids := toolOf(t, c, "gmail.forward").ResultIDs(res); ids["id"] != "18f9sent0001" {
		t.Errorf("ResultIDs = %v", ids)
	}

	// Without attachments: a plain raw send, no attachment download.
	srv2 := newAPIServer(t, map[string]route{msgPath: {status: 200, body: "message_full.json"}, sendPath: {status: 200, body: "sent_message.json"}})
	c2, _ := newConnector(t, srv2, connectors.Bounds{})
	if _, err := run(t, c2, write("gmail.forward", map[string]any{"message_id": "18f1a2b3c4d5e6f7", "to": "dave@other.test", "include_attachments": false})); err != nil {
		t.Fatal(err)
	}
	raw := rawMessage(t, srv2.Last(t, sendPath).Body, false)
	if strings.Contains(raw, "multipart/mixed") || srv2.Count(attachPath) != 0 {
		t.Errorf("include_attachments false still attached:\n%s", raw)
	}

	// An HTML-only original is forwarded as HTML, the note escaped.
	srv3 := newAPIServer(t, map[string]route{htmlMsgPath: {status: 200, body: "message_full_html_only.json"}, sendPath: {status: 200, body: "sent_message.json"}})
	c3, _ := newConnector(t, srv3, connectors.Bounds{})
	if _, err := run(t, c3, write("gmail.forward", map[string]any{"message_id": "18f1a2b3c4d5e6f9", "to": "dave@other.test", "note": "<b>me</b>"})); err != nil {
		t.Fatal(err)
	}
	headers, encoded, _ := strings.Cut(rawMessage(t, srv3.Last(t, sendPath).Body, false), "\r\n\r\n")
	html := decodeTransfer(t, headers, encoded)
	if !strings.Contains(headers, "Content-Type: text/html") || !strings.Contains(html, "&lt;b&gt;me&lt;/b&gt;") || !strings.Contains(html, "<b>Friday</b>") || !strings.Contains(html, "Forwarded message") {
		t.Errorf("html forward:\n%s\n%s", headers, html)
	}
}

func TestForwardFailures(t *testing.T) {
	c, tk := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	for name, args := range map[string]map[string]any{
		"no message": {"to": "a@b.test"},
		"bad id":     {"message_id": "a/b", "to": "a@b.test"},
		"no to":      {"message_id": "m1"},
		"bad to":     {"message_id": "m1", "to": "nobody"},
		"bad note":   {"message_id": "m1", "to": "a@b.test", "note": 5},
		"bad flag":   {"message_id": "m1", "to": "a@b.test", "include_attachments": "yes"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := run(t, c, write("gmail.forward", args))
			wantClass(t, err, google.ClassInvalidArgument, 0)
		})
	}
	if len(tk.calls) != 0 {
		t.Errorf("token calls for invalid arguments = %d", len(tk.calls))
	}
	args := map[string]any{"message_id": "18f1a2b3c4d5e6f7", "to": "a@b.test"}

	// Reading the original is a read: a known outcome, nothing sent.
	srv := newAPIServer(t, map[string]route{msgPath: {status: 404, body: "error_not_found.json"}})
	_, err := run(t, shortTimeout(t, srv), write("gmail.forward", args))
	wantClass(t, err, google.ClassNotFound, 404)
	// So is downloading an attachment.
	srv = newAPIServer(t, map[string]route{msgPath: {status: 200, body: "message_full.json"}, attachPath: {status: 500, body: "error_server.json"}})
	_, err = run(t, shortTimeout(t, srv), write("gmail.forward", args))
	wantClass(t, err, google.ClassUnavailable, 500)
	if srv.Count(uploadSendPath)+srv.Count(sendPath) != 0 {
		t.Error("sent after a failed read")
	}
	// Attachments over the bound are refused before any download.
	huge := `{"id":"18f1a2b3c4d5e6f7","threadId":"t1","payload":{"mimeType":"multipart/mixed","headers":[{"name":"Subject","value":"big"}],"parts":[` +
		`{"mimeType":"text/plain","body":{"size":2,"data":"aGk"}},{"mimeType":"application/zip","filename":"big.zip","body":{"attachmentId":"ANGjdJ8example","size":6291456}}]}}`
	srv = newAPIServer(t, map[string]route{msgPath: {status: 200, body: huge}})
	_, err = run(t, shortTimeout(t, srv), write("gmail.forward", args))
	wantClass(t, err, google.ClassInvalidArgument, 0)
	if srv.Count(attachPath) != 0 {
		t.Error("downloaded an attachment over the bound")
	}

	for _, tc := range writeErrorCases("sent_message.json") {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{msgPath: {status: 200, body: "message_full.json"}, sendPath: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("gmail.forward", map[string]any{"message_id": "18f1a2b3c4d5e6f7", "to": "a@b.test", "include_attachments": false}))
			checkWriteError(t, tc, res, err)
		})
	}

	// The check is send's: the Message-ID marker.
	srv = newAPIServer(t, map[string]route{"GET " + gm + "messages": {status: 200, byQuery: map[string]route{
		"rfc822msgid:" + strings.Trim(google.MessageID(opID), "<>"): {status: 200, body: "messages_list_marker_hit.json"},
	}}})
	c, _ = newConnector(t, srv, connectors.Bounds{})
	tool, in := reconcileInput(t, c, "gmail.forward", args)
	out, err := tool.Reconcile.Check(context.Background(), in)
	if err != nil || out.Outcome != connectors.ReconcileFound {
		t.Errorf("check = %+v, %v", out, err)
	}
}
