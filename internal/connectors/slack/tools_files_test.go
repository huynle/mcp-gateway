package slack_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/slack"
)

// uploadServer answers the three steps of an upload; the upload URL
// points back at the fixture server (step 2 is not a Web API method).
func uploadServer(t *testing.T, complete route) *apiServer {
	t.Helper()
	routes := map[string]route{"files.completeUploadExternal": complete, "upload/F0FILE0001": {body: ""}}
	srv := newAPIServer(t, routes)
	routes["files.getUploadURLExternal"] = route{body: `{"ok":true,"upload_url":"` + srv.URL + `/api/upload/F0FILE0001","file_id":"F0FILE0001"}`}
	return srv
}

const completeOK = `{"ok":true,"files":[{"id":"F0FILE0001","title":"Notes"}]}`

func TestUploadFileMetadata(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), slack.Options{})
	checkToolCases(t, c, []toolCase{{
		tool: "upload_file", kind: connectors.KindWrite, rec: connectors.ReconcileNone, scopes: []string{"files:write"},
		required: []string{"channel", "filename", "content"},
		props:    []string{"channel", "filename", "content", "content_encoding", "title", "initial_comment", "thread_ts"},
		args:     map[string]any{"channel": "C0ENGGEN01", "filename": "notes.txt", "content": "secret", "title": "secret", "thread_ts": msgTS},
		identity: map[string]string{"channel": "C0ENGGEN01", "channel_id": "C0ENGGEN01", "filename": "notes.txt", "thread_ts": msgTS},
	}})
}

func TestUploadFileText(t *testing.T) {
	srv := uploadServer(t, route{body: completeOK})
	c, _ := newConnector(t, srv, slack.Options{})
	res, err := c.Call(context.Background(), write("upload_file", map[string]any{
		"channel": "C0ENGGEN01", "filename": "notes.txt", "content": "hello world", "title": "Notes", "initial_comment": "FYI", "thread_ts": msgTS,
	}))
	if err != nil {
		t.Fatal(err)
	}
	got := res.Content.(slack.UploadedFile)
	if got.File != "F0FILE0001" || got.Channel != "C0ENGGEN01" || got.Size != 11 || got.ThreadTS != msgTS || got.Title != "Notes" {
		t.Errorf("content = %+v", got)
	}
	if f := srv.Last(t, "files.getUploadURLExternal").Form; f.Get("filename") != "notes.txt" || f.Get("length") != "11" {
		t.Errorf("get url form = %v", redactForm(f))
	}
	up := srv.Last(t, "upload/F0FILE0001")
	if !bytes.Contains(up.Body, []byte("hello world")) || !strings.HasPrefix(up.Header.Get("Content-Type"), "multipart/form-data") {
		t.Errorf("upload body/headers: %q %v", up.Body, up.Header.Get("Content-Type"))
	}
	f := srv.Last(t, "files.completeUploadExternal").Form
	if f.Get("channel_id") != "C0ENGGEN01" || f.Get("initial_comment") != "FYI" || f.Get("thread_ts") != msgTS || !strings.Contains(f.Get("files"), `"F0FILE0001"`) || !strings.Contains(f.Get("files"), `"Notes"`) {
		t.Errorf("complete form = %v", redactForm(f))
	}
	if ids := toolNamed(t, c, "upload_file").ResultIDs(res); ids["file"] != "F0FILE0001" || ids["channel"] != "C0ENGGEN01" {
		t.Errorf("ResultIDs = %v", ids)
	}
}

func TestUploadFileBase64(t *testing.T) {
	raw := []byte{0x89, 'P', 'N', 'G', 0, 1, 2, 3}
	srv := uploadServer(t, route{body: completeOK})
	c, _ := newConnector(t, srv, slack.Options{})
	res, err := c.Call(context.Background(), write("upload_file", map[string]any{
		"channel": "C0ENGGEN01", "filename": "a.png", "content": base64.StdEncoding.EncodeToString(raw), "content_encoding": "base64",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Content.(slack.UploadedFile); got.Size != len(raw) {
		t.Errorf("size = %d", got.Size)
	}
	if !bytes.Contains(srv.Last(t, "upload/F0FILE0001").Body, raw) {
		t.Error("decoded bytes not uploaded")
	}
}

func TestUploadFileValidation(t *testing.T) {
	big := strings.Repeat("x", slack.MaxUploadBytes+1)
	bigB64 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, slack.MaxUploadBytes+1))
	cases := map[string]map[string]any{
		"no content":       {"channel": "C0ENGGEN01", "filename": "a.txt", "content": ""},
		"no filename":      {"channel": "C0ENGGEN01", "content": "x"},
		"path filename":    {"channel": "C0ENGGEN01", "filename": "../etc/passwd", "content": "x"},
		"bad encoding":     {"channel": "C0ENGGEN01", "filename": "a.txt", "content": "x", "content_encoding": "hex"},
		"bad base64":       {"channel": "C0ENGGEN01", "filename": "a.txt", "content": "!!!", "content_encoding": "base64"},
		"too big text":     {"channel": "C0ENGGEN01", "filename": "a.txt", "content": big},
		"too big base64":   {"channel": "C0ENGGEN01", "filename": "a.bin", "content": bigB64, "content_encoding": "base64"},
		"bad thread":       {"channel": "C0ENGGEN01", "filename": "a.txt", "content": "x", "thread_ts": "soon"},
		"content not text": {"channel": "C0ENGGEN01", "filename": "a.txt", "content": 42},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			srv := newAPIServer(t, nil)
			c, _ := newConnector(t, srv, slack.Options{})
			_, err := c.Call(context.Background(), write("upload_file", args))
			wantClass(t, err, slack.ClassInvalidArgument)
			if len(srv.Requests()) != 0 {
				t.Errorf("requests sent: %d", len(srv.Requests()))
			}
		})
	}
}

func TestUploadFileOutcomes(t *testing.T) {
	// Step 1 and 2 failures are known (nothing was shared); step 3 is the write.
	srv := newAPIServer(t, map[string]route{"files.getUploadURLExternal": {body: `{"ok":false,"error":"file_uploads_disabled"}`}})
	c, _ := newConnector(t, srv, slack.Options{})
	_, err := c.Call(context.Background(), write("upload_file", map[string]any{"channel": "C0ENGGEN01", "filename": "a.txt", "content": "x"}))
	wantClass(t, err, slack.ClassForbidden)

	srv2 := newAPIServer(t, map[string]route{"files.getUploadURLExternal": {body: `{"ok":true,"upload_url":"http://evil.example.com/upload","file_id":"F0FILE0001"}`}})
	c2, _ := newConnector(t, srv2, slack.Options{})
	_, err = c2.Call(context.Background(), write("upload_file", map[string]any{"channel": "C0ENGGEN01", "filename": "a.txt", "content": "x"}))
	if err == nil || errors.Is(err, connectors.ErrOutcomeUnknown) || len(srv2.Requests()) != 1 {
		t.Errorf("foreign upload host: err = %v, requests = %d; want a known failure and the token never sent there", err, len(srv2.Requests()))
	}

	srv3 := uploadServer(t, route{body: `{"ok":false,"error":"not_in_channel"}`})
	c3, _ := newConnector(t, srv3, slack.Options{})
	_, err = c3.Call(context.Background(), write("upload_file", map[string]any{"channel": "C0ENGGEN01", "filename": "a.txt", "content": "x"}))
	wantClass(t, err, slack.ClassForbidden)

	srv4 := uploadServer(t, route{status: 502})
	c4, _ := newConnector(t, srv4, slack.Options{})
	_, err = c4.Call(context.Background(), write("upload_file", map[string]any{"channel": "C0ENGGEN01", "filename": "a.txt", "content": "x"}))
	if !errors.Is(err, connectors.ErrOutcomeUnknown) {
		t.Errorf("complete 502: err = %v, want ErrOutcomeUnknown", err)
	}
}
