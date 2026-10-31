package google_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

// Increment 5: attachments on gmail.send and gmail.create_draft (and
// update_draft): a message with attachments is uploaded as
// message/rfc822 (uploadType=multipart), one request.

const (
	uploadSendPath  = "POST /upload/gmail/v1/users/me/messages/send"
	uploadDraftPath = "POST /upload/gmail/v1/users/me/drafts"
)

// uploaded splits a multipart upload request into its JSON metadata and
// the RFC 822 message it carries.
func uploaded(t *testing.T, r recorded) (meta map[string]any, msg *mail.Message) {
	t.Helper()
	if got := r.URL.Query().Get("uploadType"); got != "multipart" {
		t.Errorf("uploadType = %q, want multipart", got)
	}
	_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("upload Content-Type %q: %v", r.Header.Get("Content-Type"), err)
	}
	mr := multipart.NewReader(strings.NewReader(r.Body), params["boundary"])
	for i := 0; ; i++ {
		p, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("upload part %d: %v", i, err)
		}
		b, _ := io.ReadAll(p)
		switch i {
		case 0:
			if err := json.Unmarshal(b, &meta); err != nil {
				t.Fatalf("upload metadata %q: %v", b, err)
			}
		case 1:
			if ct := p.Header.Get("Content-Type"); ct != "message/rfc822" {
				t.Errorf("media Content-Type = %q, want message/rfc822", ct)
			}
			if msg, err = mail.ReadMessage(strings.NewReader(string(b))); err != nil {
				t.Fatalf("media is not a message: %v\n%s", err, b)
			}
		}
	}
	if msg == nil {
		t.Fatal("upload carries no message")
	}
	return meta, msg
}

// mimeParts returns the parts of a multipart message, decoded.
type mimePart struct {
	contentType, disposition, filename, body string
}

func mimeParts(t *testing.T, msg *mail.Message) []mimePart {
	t.Helper()
	mt, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/mixed" {
		t.Fatalf("Content-Type = %q (%v), want multipart/mixed", msg.Header.Get("Content-Type"), err)
	}
	var out []mimePart
	mr := multipart.NewReader(msg.Body, params["boundary"])
	for {
		p, err := mr.NextRawPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(p)
		if p.Header.Get("Content-Transfer-Encoding") == "base64" {
			if b, err = base64.StdEncoding.DecodeString(strings.NewReplacer("\r", "", "\n", "").Replace(string(b))); err != nil {
				t.Fatalf("part body is not base64: %v", err)
			}
		}
		disp, dparams, _ := mime.ParseMediaType(p.Header.Get("Content-Disposition"))
		out = append(out, mimePart{contentType: p.Header.Get("Content-Type"), disposition: disp, filename: dparams["filename"], body: string(b)})
	}
	return out
}

var attachmentArgs = []any{
	map[string]any{"filename": "report.csv", "content": "name,amount\nrent,1200\n"},
	map[string]any{"filename": "logo.png", "mime_type": "image/png", "content": base64.StdEncoding.EncodeToString([]byte("\x89PNG\r\n\x1a\n\x00binary")), "content_encoding": "base64"},
	map[string]any{"filename": "Überblick.txt", "content": "ä"},
}

func TestSendWithAttachments(t *testing.T) {
	srv := newAPIServer(t, map[string]route{uploadSendPath: {status: 200, body: "sent_message.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("gmail.send", map[string]any{
		"to": "bob@example.test", "cc": "carol@example.test", "bcc": "dave@other.test", "subject": "Numbers", "body": "See attached.", "attachments": attachmentArgs,
	}))
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if srv.Count(sendPath) != 0 {
		t.Error("a message with attachments must be uploaded, not sent as raw")
	}
	_, msg := uploaded(t, srv.Last(t, uploadSendPath))
	if msg.Header.Get("Message-ID") != google.MessageID(opID) || msg.Header.Get("Cc") != "carol@example.test" || msg.Header.Get("Bcc") != "dave@other.test" {
		t.Errorf("headers = %v", msg.Header)
	}
	parts := mimeParts(t, msg)
	if len(parts) != 4 {
		t.Fatalf("parts = %+v, want the body and three attachments", parts)
	}
	if !strings.HasPrefix(parts[0].contentType, "text/plain") || parts[0].body != "See attached." || parts[0].disposition == "attachment" {
		t.Errorf("body part = %+v", parts[0])
	}
	want := []mimePart{
		{contentType: "text/csv", disposition: "attachment", filename: "report.csv", body: "name,amount\nrent,1200\n"},
		{contentType: "image/png", disposition: "attachment", filename: "logo.png", body: "\x89PNG\r\n\x1a\n\x00binary"},
		{contentType: "text/plain", disposition: "attachment", filename: "Überblick.txt", body: "ä"},
	}
	for i, w := range want {
		got := parts[i+1]
		if !strings.HasPrefix(got.contentType, w.contentType) || got.disposition != w.disposition || got.filename != w.filename || got.body != w.body {
			t.Errorf("attachment %d = %+v, want %+v", i, got, w)
		}
	}
	if sent, ok := res.Content.(google.SentMessage); !ok || sent.ID != "18f9sent0001" {
		t.Errorf("content = %#v", res.Content)
	}
	tool := toolOf(t, c, "gmail.send")
	id := tool.ResourceIdentity(map[string]any{"to": "bob@example.test", "attachments": attachmentArgs})
	if id["recipient_domains"] != "example.test" || id["attachments"] != "3" || len(id) != 2 {
		t.Errorf("identity = %v, want recipient_domains and the attachment count", id)
	}
	for _, v := range id {
		if strings.Contains(v, "report") || strings.Contains(v, "rent") {
			t.Errorf("identity carries content: %v", id)
		}
	}
}

func TestCreateDraftWithAttachmentsInThread(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		replyTargetPath: {status: 200, body: "reply_target_metadata.json"},
		uploadDraftPath: {status: 200, body: "created_draft.json"},
	})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("gmail.create_draft", map[string]any{
		"to": "bob@example.test", "subject": "Re: numbers", "body": "Draft.", "in_reply_to": "18f1a2b3c4d5e6f7",
		"attachments": []any{map[string]any{"filename": "a.txt", "content": "hello"}},
	}))
	if err != nil {
		t.Fatalf("create_draft: %v", err)
	}
	meta, msg := uploaded(t, srv.Last(t, uploadDraftPath))
	if m, _ := meta["message"].(map[string]any); m == nil || m["threadId"] != "18f1a2b3c4d5e6f0" {
		t.Errorf("metadata = %v, want message.threadId of the replied message", meta)
	}
	if msg.Header.Get("In-Reply-To") != "<abc123@example.test>" || msg.Header.Get("Message-ID") != google.MessageID(opID) {
		t.Errorf("headers = %v", msg.Header)
	}
	if parts := mimeParts(t, msg); len(parts) != 2 || parts[1].filename != "a.txt" || parts[1].body != "hello" {
		t.Errorf("parts = %+v", parts)
	}
	if d, ok := res.Content.(google.CreatedDraft); !ok || d.ID != "r-7788990011223344556" {
		t.Errorf("content = %#v", res.Content)
	}
	for _, tc := range writeErrorCases("created_draft.json") {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{uploadDraftPath: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("gmail.create_draft", map[string]any{
				"to": "a@b.test", "subject": "s", "body": "b", "attachments": []any{map[string]any{"filename": "a.txt", "content": "x"}},
			}))
			checkWriteError(t, tc, res, err)
		})
	}
}

func TestSendAttachmentErrors(t *testing.T) {
	for _, tc := range writeErrorCases("sent_message.json") {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{uploadSendPath: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("gmail.send", map[string]any{
				"to": "a@b.test", "subject": "s", "body": "b", "attachments": []any{map[string]any{"filename": "a.txt", "content": "x"}},
			}))
			checkWriteError(t, tc, res, err)
		})
	}
}

func TestAttachmentArguments(t *testing.T) {
	c, tk := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	big := strings.Repeat("x", (5<<20)/2+1)
	for name, atts := range map[string]any{
		"not a list":           "a.txt",
		"not an object":        []any{"a.txt"},
		"missing filename":     []any{map[string]any{"content": "x"}},
		"filename line break":  []any{map[string]any{"filename": "a\r\nBcc: x@y.test", "content": "x"}},
		"filename with slash":  []any{map[string]any{"filename": "../a.txt", "content": "x"}},
		"bad encoding":         []any{map[string]any{"filename": "a.txt", "content": "x", "content_encoding": "hex"}},
		"bad base64":           []any{map[string]any{"filename": "a.bin", "content": "!!!", "content_encoding": "base64"}},
		"bad mime type":        []any{map[string]any{"filename": "a.bin", "content": "x", "mime_type": "not a type"}},
		"content not a string": []any{map[string]any{"filename": "a.txt", "content": 5}},
		"unknown field":        []any{map[string]any{"filename": "a.txt", "content": "x", "path": "/etc/passwd"}},
		"over the total":       []any{map[string]any{"filename": "a.txt", "content": big}, map[string]any{"filename": "b.txt", "content": big}},
	} {
		t.Run(name, func(t *testing.T) {
			for _, tool := range []string{"gmail.send", "gmail.create_draft"} {
				_, err := run(t, c, write(tool, map[string]any{"to": "a@b.test", "subject": "s", "body": "b", "attachments": atts}))
				wantClass(t, err, google.ClassInvalidArgument, 0)
			}
		})
	}
	if len(tk.calls) != 0 {
		t.Errorf("token calls for invalid attachments = %d", len(tk.calls))
	}
	// The schema declares the attachments.
	for _, full := range []string{"gmail.send", "gmail.create_draft"} {
		if !strings.Contains(string(toolOf(t, c, full).InputSchema), `"attachments"`) {
			t.Errorf("%s schema lacks attachments", full)
		}
	}
}
