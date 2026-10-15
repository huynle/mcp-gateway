package microsoft_test

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/microsoft"
)

func TestDriveToolsMetadata(t *testing.T) {
	r, w := connectors.KindRead, connectors.KindWrite
	checkMeta(t, []toolMeta{
		{tool: "drive_list_children", kind: r, scopes: []string{"Files.Read.All"},
			args: map[string]any{"folder_id": "f-1"}, identity: map[string]string{"drive": "me", "parent": "f-1"}},
		{tool: "drive_get_file_content", kind: r, scopes: []string{"Files.Read.All"}, required: []string{"item_id"},
			args: map[string]any{"item_id": "i-1", "drive_id": "b!d"}, identity: map[string]string{"drive": "b!d", "item": "i-1"}},
		{tool: "drive_upload_file", kind: w, reconcile: connectors.ReconcileMarker, scopes: []string{"Files.ReadWrite"}, required: []string{"name", "content"},
			args: map[string]any{"name": "notes.txt", "content": "secret"}, identity: map[string]string{"drive": "me", "parent": "root", "file": "notes.txt"}},
		{tool: "drive_create_share_link", kind: w, reconcile: connectors.ReconcileNone, scopes: []string{"Files.ReadWrite"}, required: []string{"item_id"},
			args: map[string]any{"item_id": "i-1", "type": "edit"}, identity: map[string]string{"drive": "me", "item": "i-1", "link_type": "edit"}},
	})
}

func TestDriveListChildren(t *testing.T) {
	srv, res := mustRun(t, map[string]route{"GET /v1.0/me/drive/items/f-1/children": {status: 200, body: "drive_search.json"}},
		"drive_list_children", map[string]any{"folder_id": "f-1", "top": 3}, false)
	var out struct {
		Items []struct{ ID, Name string } `json:"items"`
	}
	decode(t, res, &out)
	if len(out.Items) == 0 || out.Items[0].ID == "" {
		t.Errorf("out = %+v", out)
	}
	if q := query(t, srv, "/v1.0/me/drive/items/f-1/children"); q.Get("$top") != "3" {
		t.Errorf("$top = %q", q.Get("$top"))
	}
	srv, _ = mustRun(t, map[string]route{"GET /v1.0/drives/b!d/root/children": {status: 200, body: "drive_search_empty.json"}},
		"drive_list_children", map[string]any{"drive_id": "b!d"}, false)
	if srv.Count("GET /v1.0/drives/b!d/root/children") != 1 {
		t.Error("drive root not listed")
	}
}

func TestDriveGetFileContent(t *testing.T) {
	meta := "GET /v1.0/me/drive/items/i-1"
	content := "GET /v1.0/me/drive/items/i-1/content"
	_, res := mustRun(t, map[string]route{
		meta:    {status: 200, body: `{"id":"i-1","name":"notes.txt","size":11,"webUrl":"https://onedrive.example.test/i-1","file":{"mimeType":"text/plain"}}`},
		content: {status: 200, body: "attachment_notes.txt"},
	}, "drive_get_file_content", map[string]any{"item_id": "i-1"}, false)
	var out struct{ Name, Encoding, Content string }
	decode(t, res, &out)
	if out.Name != "notes.txt" || out.Encoding != "text" || out.Content != "hello notes" {
		t.Errorf("out = %+v", out)
	}
	srv, _, err := run(t, map[string]route{
		meta: {status: 200, body: fmt.Sprintf(`{"id":"i-1","name":"big.iso","size":%d,"webUrl":"https://onedrive.example.test/i-1","file":{"mimeType":"application/octet-stream"}}`, microsoft.MaxContentBytes+1)},
	}, "drive_get_file_content", map[string]any{"item_id": "i-1"}, false)
	wantClass(t, err, microsoft.ClassInvalidArgument, 0)
	if !strings.Contains(err.Error(), "https://onedrive.example.test/i-1") || srv.Count(content) != 0 {
		t.Errorf("err %v; downloads %d: want refusal with the web url and no download", err, srv.Count(content))
	}
	_, _, err = run(t, map[string]route{meta: {status: 200, body: `{"id":"i-1","name":"Docs","folder":{"childCount":2}}`}}, "drive_get_file_content", map[string]any{"item_id": "i-1"}, false)
	wantClass(t, err, microsoft.ClassInvalidArgument, 0)
}

func TestDriveUploadFile(t *testing.T) {
	path := "PUT /v1.0/me/drive/items/f-1:/report.bin:/content"
	srv, res := mustRun(t, map[string]route{path: {status: 201, body: `{"id":"new-1","name":"report.bin","size":3,"webUrl":"https://onedrive.example.test/new-1","parentReference":{"driveId":"d1","id":"f-1"}}`}},
		"drive_upload_file", map[string]any{"name": "report.bin", "parent_id": "f-1", "content": base64.StdEncoding.EncodeToString([]byte{1, 2, 3}), "content_encoding": "base64"}, true)
	r := srv.Last(t, path)
	if r.Body != "\x01\x02\x03" || r.URL.Query().Get("@microsoft.graph.conflictBehavior") != "fail" {
		t.Errorf("upload body %q query %v", r.Body, r.URL.Query())
	}
	if ids := toolNamed(t, mustConnector(t), "drive_upload_file").ResultIDs(res); ids["id"] != "new-1" {
		t.Errorf("ResultIDs = %v", ids)
	}
	srv, _ = mustRun(t, map[string]route{"PUT /v1.0/me/drive/root:/a.txt:/content": {status: 201, body: `{"id":"new-2","name":"a.txt"}`}},
		"drive_upload_file", map[string]any{"name": "a.txt", "content": "plain"}, true)
	if srv.Last(t, "PUT /v1.0/me/drive/root:/a.txt:/content").Body != "plain" {
		t.Error("text content not sent as is")
	}
	_, _, err := run(t, map[string]route{"PUT /v1.0/me/drive/root:/a.txt:/content": {status: 409, body: "error_name_exists.json"}}, "drive_upload_file", map[string]any{"name": "a.txt", "content": "x"}, true)
	wantClass(t, err, microsoft.ClassInvalidArgument, 409)
	wantInvalid(t, "drive_upload_file", map[string]any{"name": "a/b.txt", "content": "x"}, true)
	wantInvalid(t, "drive_upload_file", map[string]any{"name": "a.txt", "content": "!!", "content_encoding": "base64"}, true)
	wantInvalid(t, "drive_upload_file", map[string]any{"name": "a.txt", "content": strings.Repeat("x", microsoft.MaxContentBytes+1)}, true)

	children := "GET /v1.0/me/drive/items/f-1/children"
	got, err := check(t, map[string]route{children: {status: 200, body: `{"value":[{"id":"x","name":"REPORT.BIN","file":{}}]}`}}, "drive_upload_file", map[string]string{"drive": "me", "parent": "f-1", "file": "report.bin"})
	wantFound(t, got, err, "x")
	got, err = check(t, map[string]route{children: {status: 200, body: `{"value":[{"id":"x","name":"report.bin","folder":{}}]}`}}, "drive_upload_file", map[string]string{"drive": "me", "parent": "f-1", "file": "report.bin"})
	wantNotFound(t, got, err)
	runWriteErrorCases(t, "PUT /v1.0/me/drive/root:/a.txt:/content", route{status: 201, body: `{"id":"n"}`}, "drive_upload_file", map[string]any{"name": "a.txt", "content": "x"})
}

func TestDriveCreateShareLink(t *testing.T) {
	path := "POST /v1.0/me/drive/items/i-1/createLink"
	srv, res := mustRun(t, map[string]route{path: {status: 201, body: `{"id":"perm-1","link":{"type":"view","scope":"organization","webUrl":"https://share.example.test/s"}}`}},
		"drive_create_share_link", map[string]any{"item_id": "i-1", "scope": "organization"}, true)
	b := jsonBody(t, srv.Last(t, path))
	if b["type"] != "view" || b["scope"] != "organization" {
		t.Errorf("body = %v", b)
	}
	var out struct{ ID, URL, Type, Scope string }
	decode(t, res, &out)
	if out.URL != "https://share.example.test/s" || out.ID != "perm-1" {
		t.Errorf("out = %+v", out)
	}
	wantInvalid(t, "drive_create_share_link", map[string]any{"item_id": "i-1", "type": "owner"}, true)
}
