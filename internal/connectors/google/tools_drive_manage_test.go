package google_test

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

// Drive management: get_content, list_folder, list_permissions,
// list_comments, create_file, update_file, share, add_comment.

const (
	exportPath      = "GET /drive/v3/files/" + fileID + "/export"
	uploadPath      = "POST /upload/drive/v3/files"
	updateFilePath  = "PATCH /drive/v3/files/" + fileID
	permissionsPath = "/drive/v3/files/" + fileID + "/permissions"
	commentsPath    = "/drive/v3/files/" + fileID + "/comments"
	folderID        = "1Folder0000000000000000000000000"
	destID          = "1Dest00000000000000000000000000"
)

func TestDriveManageDeclarations(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	r, w := connectors.KindRead, connectors.KindWrite
	gc := declared(t, c, "drive.get_content", r, []string{google.ScopeDriveReadonly}, "")
	if gc.Bounds.MaxResultBytes != google.MaxDownloadResultBytes {
		t.Errorf("get_content MaxResultBytes = %d", gc.Bounds.MaxResultBytes)
	}
	declared(t, c, "drive.list_folder", r, []string{google.ScopeDriveMetadataReadonly}, "")
	declared(t, c, "drive.list_permissions", r, []string{google.ScopeDriveMetadataReadonly}, "")
	declared(t, c, "drive.list_comments", r, []string{google.ScopeDriveReadonly}, "")
	declared(t, c, "drive.create_file", w, []string{google.ScopeDriveFile}, connectors.ReconcileMarker)
	declared(t, c, "drive.update_file", w, []string{google.ScopeDriveFile}, connectors.ReconcileMarker)
	declared(t, c, "drive.share", w, []string{google.ScopeDriveFile}, connectors.ReconcileNone)
	declared(t, c, "drive.add_comment", w, []string{google.ScopeDriveFile}, connectors.ReconcileNone)
	id := toolOf(t, c, "drive.share").ResourceIdentity(map[string]any{"file_id": fileID, "email": "Carol@Other.test", "role": "writer", "type": "user", "message": "secret"})
	if id["file_id"] != fileID || id["role"] != "writer" || id["type"] != "user" || id["grantee_domain"] != "other.test" || len(id) != 4 {
		t.Errorf("share identity = %v", id)
	}
	id = toolOf(t, c, "drive.update_file").ResourceIdentity(map[string]any{"file_id": fileID, "parent_id": destID, "name": "secret"})
	if id["file_id"] != fileID || id["folder_id"] != destID || len(id) != 2 {
		t.Errorf("update_file identity = %v", id)
	}
}

func TestDriveGetContent(t *testing.T) {
	media := func(meta, content string) map[string]route {
		return map[string]route{getFilePath: {byAlt: map[string]route{"": {status: 200, body: meta}, "media": {status: 200, body: content}}}}
	}
	srv := newAPIServer(t, media("file_text_meta.json", "file_content.txt"))
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("drive.get_content", map[string]any{"file_id": fileID}))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		ID, Name, Encoding, Content string
		MimeType                    string `json:"mime_type"`
		Size                        int
		ExportedAs                  string `json:"exported_as"`
	}
	decode(t, res, &out)
	if out.Encoding != "text" || out.Content != "Meeting notes\nline two\n" || out.Name != "notes.txt" || out.Size != 23 {
		t.Errorf("out = %+v", out)
	}

	srv = newAPIServer(t, media("file_metadata.json", "file_content.txt"))
	c, _ = newConnector(t, srv, connectors.Bounds{})
	res, err = run(t, c, call("drive.get_content", map[string]any{"file_id": fileID}))
	if err != nil {
		t.Fatal(err)
	}
	decode(t, res, &out)
	if out.Encoding != "text" || out.MimeType != "application/pdf" {
		t.Errorf("pdf with text bytes = %+v", out)
	}

	srv = newAPIServer(t, map[string]route{getFilePath: {status: 200, body: "file_gdoc_meta.json"}, exportPath: {status: 200, body: "export_doc.txt"}})
	c, _ = newConnector(t, srv, connectors.Bounds{})
	res, err = run(t, c, call("drive.get_content", map[string]any{"file_id": fileID}))
	if err != nil {
		t.Fatal(err)
	}
	decode(t, res, &out)
	if out.ExportedAs != "text/plain" || out.Content != "Heading\n\nBody of the doc.\n" {
		t.Errorf("export = %+v", out)
	}
	if got := query(t, srv, "/drive/v3/files/"+fileID+"/export").Get("mimeType"); got != "text/plain" {
		t.Errorf("export mimeType = %q", got)
	}
	_, err = run(t, c, call("drive.get_content", map[string]any{"file_id": fileID, "export_mime_type": "application/pdf"}))
	if err != nil {
		t.Fatal(err)
	}
	if got := query(t, srv, "/drive/v3/files/"+fileID+"/export").Get("mimeType"); got != "application/pdf" {
		t.Errorf("explicit export mimeType = %q", got)
	}

	for name, meta := range map[string]string{"too large": "file_huge_meta.json", "not exportable": "file_form_meta.json"} {
		t.Run(name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{getFilePath: {status: 200, body: meta}})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			_, err := run(t, c, call("drive.get_content", map[string]any{"file_id": fileID}))
			wantClass(t, err, google.ClassInvalidArgument, 0)
		})
	}
	for _, tc := range readErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{getFilePath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := run(t, c, call("drive.get_content", map[string]any{"file_id": fileID}))
			checkReadError(t, tc, res, err)
		})
	}
}

func TestDriveListFolder(t *testing.T) {
	srv := newAPIServer(t, map[string]route{listFilesPath: {status: 200, body: "files_list.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("drive.list_folder", map[string]any{"folder_id": folderID}))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		FolderID string `json:"folder_id"`
		Items    []struct{ ID string }
	}
	decode(t, res, &out)
	if out.FolderID != folderID || len(out.Items) == 0 {
		t.Errorf("out = %+v", out)
	}
	q := query(t, srv, "/drive/v3/files")
	if q.Get("q") != "'"+folderID+"' in parents and trashed = false" || q.Get("supportsAllDrives") != "true" || q.Get("includeItemsFromAllDrives") != "true" {
		t.Errorf("query = %v", q)
	}
	if _, err := run(t, c, call("drive.list_folder", nil)); err != nil {
		t.Fatal(err)
	}
	if q := query(t, srv, "/drive/v3/files"); q.Get("q") != "'root' in parents and trashed = false" {
		t.Errorf("root query = %q", q.Get("q"))
	}
	_, err = run(t, c, call("drive.list_folder", map[string]any{"folder_id": "x' or '1"}))
	wantClass(t, err, google.ClassInvalidArgument, 0)
}

func TestDriveListPermissionsAndComments(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET " + permissionsPath: {status: 200, body: "permissions_list.json"}, "GET " + commentsPath: {status: 200, body: "comments_list.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("drive.list_permissions", map[string]any{"file_id": fileID}))
	if err != nil {
		t.Fatal(err)
	}
	var perms struct {
		Items []struct {
			ID, Type, Role string
			Email          string `json:"email"`
		}
		HasMore bool `json:"has_more"`
	}
	decode(t, res, &perms)
	if len(perms.Items) != 2 || perms.Items[0].Email != "bob@example.test" || perms.Items[1].Type != "anyone" || !perms.HasMore {
		t.Errorf("perms = %+v", perms)
	}
	res, err = run(t, c, call("drive.list_comments", map[string]any{"file_id": fileID}))
	if err != nil {
		t.Fatal(err)
	}
	var comments struct {
		Items []struct {
			ID, Content, Author string
			Quoted              string `json:"quoted"`
			Replies             []struct{ Content, Author string }
		}
	}
	decode(t, res, &comments)
	if len(comments.Items) != 1 || comments.Items[0].Author != "Bob" || comments.Items[0].Quoted != "quoted text" || len(comments.Items[0].Replies) != 1 {
		t.Errorf("comments = %+v", comments)
	}
	if q := query(t, srv, "/drive/v3/files/"+fileID+"/comments"); q.Get("fields") == "" {
		t.Error("comments.list needs fields")
	}
}

func TestDriveCreateFile(t *testing.T) {
	srv := newAPIServer(t, map[string]route{uploadPath: {status: 200, body: "created_file.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("drive.create_file", map[string]any{"name": "notes.txt", "content": "hello drive", "mime_type": "text/plain", "parent_id": folderID}))
	if err != nil {
		t.Fatal(err)
	}
	if ids := toolOf(t, c, "drive.create_file").ResultIDs(res); ids["id"] != "1Upload0000000000000000000000000" {
		t.Errorf("ResultIDs = %v", ids)
	}
	up := srv.Last(t, uploadPath)
	if up.URL.Query().Get("uploadType") != "multipart" || !strings.Contains(up.Body, "hello drive") || !strings.Contains(up.Body, `"mcp-gateway-op":"`+opID+`"`) || !strings.Contains(up.Body, folderID) {
		t.Errorf("upload = %s %q", up.URL, up.Body)
	}
	_, err = run(t, c, write("drive.create_file", map[string]any{"name": "img.png", "content": base64.StdEncoding.EncodeToString([]byte("\x89PNG")), "content_encoding": "base64"}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(srv.Last(t, uploadPath).Body, "\x89PNG") {
		t.Error("base64 content must be decoded before upload")
	}
	for _, args := range []map[string]any{
		{"content": "x"},
		{"name": "a", "content": "%%%", "content_encoding": "base64"},
		{"name": "a", "content": "x", "content_encoding": "hex"},
		{"name": "a", "content": strings.Repeat("x", google.MaxDownloadBytes+1)},
	} {
		_, err := run(t, c, write("drive.create_file", args))
		wantClass(t, err, google.ClassInvalidArgument, 0)
	}
	for _, tc := range writeErrorCases("created_file.json") {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{uploadPath: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("drive.create_file", map[string]any{"name": "a", "content": "x"}))
			checkWriteError(t, tc, res, err)
		})
	}
	if toolOf(t, c, "drive.create_file").Reconcile.Check == nil {
		t.Error("create_file reconciles by the Drive marker")
	}
}

func TestDriveUpdateFile(t *testing.T) {
	srv := newAPIServer(t, map[string]route{getFilePath: {status: 200, body: "file_parents.json"}, updateFilePath: {status: 200, body: "file_updated.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("drive.update_file", map[string]any{"file_id": fileID, "name": "Renamed.pdf", "parent_id": destID}))
	if err != nil {
		t.Fatal(err)
	}
	if ids := toolOf(t, c, "drive.update_file").ResultIDs(res); ids["id"] != fileID {
		t.Errorf("ResultIDs = %v", ids)
	}
	up := srv.Last(t, updateFilePath)
	if q := up.URL.Query(); q.Get("addParents") != destID || q.Get("removeParents") != folderID {
		t.Errorf("move query = %v", q)
	}
	body := bodyOf(t, up)
	props, _ := body["appProperties"].(map[string]any)
	if body["name"] != "Renamed.pdf" || props["mcp-gateway-op"] != opID {
		t.Errorf("patch body = %v", body)
	}
	// Rename only: no lookup, no parents.
	before := srv.Count("GET /drive/v3/files/" + fileID)
	if _, err := run(t, c, write("drive.update_file", map[string]any{"file_id": fileID, "name": "x"})); err != nil {
		t.Fatal(err)
	}
	if srv.Count("GET /drive/v3/files/"+fileID) != before || srv.Last(t, updateFilePath).URL.Query().Get("addParents") != "" {
		t.Error("a rename must not look up or move")
	}
	for _, args := range []map[string]any{{"file_id": fileID}, {"name": "x"}, {"file_id": fileID, "name": " "}} {
		_, err := run(t, c, write("drive.update_file", args))
		wantClass(t, err, google.ClassInvalidArgument, 0)
	}
	for name, tc := range map[string]struct{ body, want string }{
		"ours":    {"file_marked.json", "found"},
		"none":    {"file_parents.json", "not_found"},
		"another": {"file_marked_other.json", "cannot"},
	} {
		t.Run("check "+name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{getFilePath: {status: 200, body: tc.body}})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, "drive.update_file", map[string]any{"file_id": fileID, "name": "x"})
			out, err := tool.Reconcile.Check(context.Background(), in)
			wantOutcome(t, out, err, tc.want, fileID)
		})
	}
}

func TestDriveShareAndComment(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"POST " + permissionsPath: {status: 200, body: "created_permission.json"}, "POST " + commentsPath: {status: 200, body: "created_comment.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("drive.share", map[string]any{"file_id": fileID, "email": "carol@other.test", "role": "writer", "message": "fyi"}))
	if err != nil {
		t.Fatal(err)
	}
	if ids := toolOf(t, c, "drive.share").ResultIDs(res); ids["permission_id"] != "perm9" {
		t.Errorf("ResultIDs = %v", ids)
	}
	p := srv.Last(t, "POST "+permissionsPath)
	body := bodyOf(t, p)
	if body["type"] != "user" || body["role"] != "writer" || body["emailAddress"] != "carol@other.test" || p.URL.Query().Get("emailMessage") != "fyi" || p.URL.Query().Get("sendNotificationEmail") != "true" {
		t.Errorf("share = %v %v", body, p.URL.Query())
	}
	if _, err := run(t, c, write("drive.share", map[string]any{"file_id": fileID, "type": "anyone", "role": "reader"})); err != nil {
		t.Fatal(err)
	}
	if body := bodyOf(t, srv.Last(t, "POST "+permissionsPath)); body["type"] != "anyone" || body["emailAddress"] != nil {
		t.Errorf("anyone body = %v", body)
	}
	for _, args := range []map[string]any{
		{"file_id": fileID, "role": "writer"},
		{"file_id": fileID, "email": "x@y.test", "role": "owner"},
		{"file_id": fileID, "email": "nope", "role": "reader"},
		{"file_id": fileID, "type": "domain", "role": "reader"},
		{"file_id": fileID, "type": "anyone", "email": "x@y.test", "role": "reader"},
	} {
		_, err := run(t, c, write("drive.share", args))
		wantClass(t, err, google.ClassInvalidArgument, 0)
	}
	res, err = run(t, c, write("drive.add_comment", map[string]any{"file_id": fileID, "content": "New comment"}))
	if err != nil {
		t.Fatal(err)
	}
	if ids := toolOf(t, c, "drive.add_comment").ResultIDs(res); ids["comment_id"] != "c9" {
		t.Errorf("ResultIDs = %v", ids)
	}
	if body := bodyOf(t, srv.Last(t, "POST "+commentsPath)); body["content"] != "New comment" {
		t.Errorf("comment body = %v", body)
	}
	_, err = run(t, c, write("drive.add_comment", map[string]any{"file_id": fileID}))
	wantClass(t, err, google.ClassInvalidArgument, 0)
}
