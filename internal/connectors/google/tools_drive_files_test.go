package google_test

import (
	"context"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

// Increment 5: Drive file lifecycle: copy_file, trash, untrash, delete,
// empty_trash, create_shortcut, upload_new_version and update_file's
// starred.

const (
	copyFilePath    = "POST /drive/v3/files/" + fileID + "/copy"
	deleteFilePath  = "DELETE /drive/v3/files/" + fileID
	emptyTrashPath  = "DELETE /drive/v3/files/trash"
	uploadVersion   = "PATCH /upload/drive/v3/files/" + fileID
	copiedFileBody  = `{"id":"1Copy000000000000000000000000000","name":"Copy of notes","mimeType":"text/plain","webViewLink":"https://drive.google.com/file/d/1Copy/view","parents":["` + destID + `"]}`
	trashedFileBody = `{"id":"` + fileID + `","name":"notes.txt","trashed":true}`
	activeFileBody  = `{"id":"` + fileID + `","name":"notes.txt","trashed":false}`
	shortcutBody    = `{"id":"1Short00000000000000000000000000","name":"notes.txt","mimeType":"application/vnd.google-apps.shortcut","webViewLink":"https://drive.google.com/file/d/1Short/view","parents":["` + destID + `"]}`
)

func TestDriveFilesDeclarations(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	w := connectors.KindWrite
	declared(t, c, "drive.copy_file", w, []string{google.ScopeDriveFile}, connectors.ReconcileMarker)
	declared(t, c, "drive.trash", w, []string{google.ScopeDriveFile}, connectors.ReconcileStableID)
	declared(t, c, "drive.untrash", w, []string{google.ScopeDriveFile}, connectors.ReconcileStableID)
	declared(t, c, "drive.delete", w, []string{google.ScopeDriveFile}, connectors.ReconcileStableID)
	declared(t, c, "drive.empty_trash", w, []string{google.ScopeDrive}, connectors.ReconcileNone)
	declared(t, c, "drive.create_shortcut", w, []string{google.ScopeDriveFile}, connectors.ReconcileMarker)
	declared(t, c, "drive.upload_new_version", w, []string{google.ScopeDriveFile}, connectors.ReconcileMarker)
	id := toolOf(t, c, "drive.copy_file").ResourceIdentity(map[string]any{"file_id": fileID, "name": "secret", "parent_id": destID})
	if id["file_id"] != fileID || id["folder_id"] != destID || id["drive"] != "my" || len(id) != 3 {
		t.Errorf("copy_file identity = %v", id)
	}
	id = toolOf(t, c, "drive.create_shortcut").ResourceIdentity(map[string]any{"file_id": fileID, "name": "secret", "drive_id": "0Shared"})
	if id["file_id"] != fileID || id["drive"] != "0Shared" || len(id) != 2 {
		t.Errorf("create_shortcut identity = %v", id)
	}
	if id := toolOf(t, c, "drive.empty_trash").ResourceIdentity(nil); id["drive"] != "my" || len(id) != 1 {
		t.Errorf("empty_trash identity = %v", id)
	}
	for _, name := range []string{"drive.trash", "drive.untrash", "drive.delete", "drive.upload_new_version"} {
		if id := toolOf(t, c, name).ResourceIdentity(map[string]any{"file_id": fileID, "content": "secret"}); id["file_id"] != fileID || len(id) != 1 {
			t.Errorf("%s identity = %v", name, id)
		}
	}
}

func TestDriveCopyFile(t *testing.T) {
	srv := newAPIServer(t, map[string]route{copyFilePath: {status: 200, body: copiedFileBody}})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("drive.copy_file", map[string]any{"file_id": fileID, "name": "Copy of notes", "parent_id": destID}))
	if err != nil {
		t.Fatal(err)
	}
	if ids := toolOf(t, c, "drive.copy_file").ResultIDs(res); ids["id"] != "1Copy000000000000000000000000000" || ids["url"] == "" {
		t.Errorf("ResultIDs = %v", ids)
	}
	body := bodyOf(t, srv.Last(t, copyFilePath))
	props, _ := body["appProperties"].(map[string]any)
	parents, _ := body["parents"].([]any)
	if body["name"] != "Copy of notes" || props["mcp-gateway-op"] != opID || len(parents) != 1 || parents[0] != destID {
		t.Errorf("copy body = %v", body)
	}
	if q := srv.Last(t, copyFilePath).URL.Query(); q.Get("supportsAllDrives") != "true" {
		t.Errorf("query = %v", q)
	}
	// Without a name Drive names the copy; without a parent it lands next to the original.
	if _, err := run(t, c, write("drive.copy_file", map[string]any{"file_id": fileID})); err != nil {
		t.Fatal(err)
	}
	if body := bodyOf(t, srv.Last(t, copyFilePath)); body["name"] != nil || body["parents"] != nil {
		t.Errorf("bare copy body = %v", body)
	}
	calls := len(tk.calls)
	for _, args := range []map[string]any{{}, {"file_id": "a/b"}, {"file_id": fileID, "parent_id": "x y"}} {
		_, err := run(t, c, write("drive.copy_file", args))
		wantClass(t, err, google.ClassInvalidArgument, 0)
	}
	if len(tk.calls) != calls {
		t.Error("invalid arguments must not fetch the token")
	}
	for _, tc := range writeErrorCases(copiedFileBody) {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{copyFilePath: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("drive.copy_file", map[string]any{"file_id": fileID}))
			checkWriteError(t, tc, res, err)
		})
	}
}

func TestDriveTrashUntrash(t *testing.T) {
	srv := newAPIServer(t, map[string]route{updateFilePath: {status: 200, body: trashedFileBody}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("drive.trash", map[string]any{"file_id": fileID}))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		ID      string `json:"id"`
		Trashed bool   `json:"trashed"`
	}
	decode(t, res, &out)
	if out.ID != fileID || !out.Trashed {
		t.Errorf("out = %+v", out)
	}
	if ids := toolOf(t, c, "drive.trash").ResultIDs(res); ids["id"] != fileID {
		t.Errorf("ResultIDs = %v", ids)
	}
	if body := bodyOf(t, srv.Last(t, updateFilePath)); body["trashed"] != true || len(body) != 1 {
		t.Errorf("trash body = %v", body)
	}
	srv = newAPIServer(t, map[string]route{updateFilePath: {status: 200, body: activeFileBody}})
	c, _ = newConnector(t, srv, connectors.Bounds{})
	if _, err := run(t, c, write("drive.untrash", map[string]any{"file_id": fileID})); err != nil {
		t.Fatal(err)
	}
	if body := bodyOf(t, srv.Last(t, updateFilePath)); body["trashed"] != false || len(body) != 1 {
		t.Errorf("untrash body = %v", body)
	}
	_, err = run(t, c, write("drive.trash", map[string]any{}))
	wantClass(t, err, google.ClassInvalidArgument, 0)
	for _, tc := range writeErrorCases(trashedFileBody) {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{updateFilePath: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("drive.trash", map[string]any{"file_id": fileID}))
			checkWriteError(t, tc, res, err)
		})
	}
	for _, tc := range []struct {
		tool string
		rt   route
		want string
	}{
		{"drive.trash", route{status: 200, body: trashedFileBody}, "found"},
		{"drive.trash", route{status: 200, body: activeFileBody}, "not_found"},
		{"drive.untrash", route{status: 200, body: activeFileBody}, "found"},
		{"drive.untrash", route{status: 200, body: trashedFileBody}, "not_found"},
		{"drive.trash", route{status: 404, body: "error_not_found.json"}, "cannot_tell"},
		{"drive.untrash", route{status: 500, body: "error_server.json"}, "cannot_tell"},
	} {
		t.Run("check "+tc.tool+" "+tc.want, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{getFilePath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, tc.tool, map[string]any{"file_id": fileID})
			out, err := tool.Reconcile.Check(context.Background(), in)
			wantOutcome(t, out, err, tc.want, fileID)
		})
	}
}

func TestDriveDelete(t *testing.T) {
	srv := newAPIServer(t, map[string]route{deleteFilePath: {status: 204, body: ""}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("drive.delete", map[string]any{"file_id": fileID}))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		ID      string `json:"id"`
		Deleted bool   `json:"deleted"`
	}
	decode(t, res, &out)
	if out.ID != fileID || !out.Deleted {
		t.Errorf("out = %+v", out)
	}
	if ids := toolOf(t, c, "drive.delete").ResultIDs(res); ids["id"] != fileID {
		t.Errorf("ResultIDs = %v", ids)
	}
	if q := srv.Last(t, deleteFilePath).URL.Query(); q.Get("supportsAllDrives") != "true" {
		t.Errorf("query = %v", q)
	}
	for _, tc := range writeErrorCases("") {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{deleteFilePath: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("drive.delete", map[string]any{"file_id": fileID}))
			checkWriteError(t, tc, res, err)
		})
	}
	for _, tc := range []struct {
		rt   route
		want string
	}{
		{route{status: 404, body: "error_not_found.json"}, "found"},
		{route{status: 200, body: activeFileBody}, "not_found"},
		{route{status: 200, body: trashedFileBody}, "not_found"},
		{route{status: 500, body: "error_server.json"}, "cannot_tell"},
		{route{status: 403, body: "error_forbidden.json"}, "cannot_tell"},
	} {
		t.Run("check "+tc.want, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{getFilePath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, "drive.delete", map[string]any{"file_id": fileID})
			out, err := tool.Reconcile.Check(context.Background(), in)
			wantOutcome(t, out, err, tc.want, fileID)
		})
	}
}

func TestDriveEmptyTrash(t *testing.T) {
	srv := newAPIServer(t, map[string]route{emptyTrashPath: {status: 204, body: ""}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("drive.empty_trash", nil))
	if err != nil {
		t.Fatal(err)
	}
	if ids := toolOf(t, c, "drive.empty_trash").ResultIDs(res); ids["drive"] != "my" {
		t.Errorf("ResultIDs = %v", ids)
	}
	if _, err := run(t, c, write("drive.empty_trash", map[string]any{"drive_id": "0SharedDrive"})); err != nil {
		t.Fatal(err)
	}
	if q := srv.Last(t, emptyTrashPath).URL.Query(); q.Get("driveId") != "0SharedDrive" {
		t.Errorf("query = %v", q)
	}
	_, err = run(t, c, write("drive.empty_trash", map[string]any{"drive_id": "a b"}))
	wantClass(t, err, google.ClassInvalidArgument, 0)
	for _, tc := range writeErrorCases("") {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{emptyTrashPath: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("drive.empty_trash", nil))
			checkWriteError(t, tc, res, err)
		})
	}
}

// files.emptyTrash accepts only the full drive scope: drive.file does
// not admit it.
func TestDriveEmptyTrashScopeGate(t *testing.T) {
	srv := newAPIServer(t, map[string]route{emptyTrashPath: {status: 204, body: ""}})
	accounts := connectors.NewStaticAccountSource()
	accounts.Add(alice, connectors.Account{ID: "d5000000-0000-4000-8000-000000000001", App: google.AppDrive, Scopes: []string{google.ScopeDriveFile}})
	accounts.Add(alice, connectors.Account{ID: "d5000000-0000-4000-8000-000000000002", App: google.AppDrive, Scopes: []string{google.ScopeDrive}})
	c, err := google.New(google.Options{Tokens: (&tokens{}).source, BaseURL: srv.URL + "/", Accounts: accounts})
	if err != nil {
		t.Fatal(err)
	}
	cl := write("drive.empty_trash", nil)
	cl.Account = "d5000000-0000-4000-8000-000000000001"
	_, err = run(t, c, cl)
	wantClass(t, err, google.ClassScopeRequired, 0)
	cl.Account = "d5000000-0000-4000-8000-000000000002"
	if _, err := run(t, c, cl); err != nil {
		t.Errorf("drive scope: %v", err)
	}
}

func TestDriveCreateShortcut(t *testing.T) {
	srv := newAPIServer(t, map[string]route{createFilePath: {status: 200, body: shortcutBody}, getFilePath: {status: 200, body: activeFileBody}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("drive.create_shortcut", map[string]any{"file_id": fileID, "parent_id": destID}))
	if err != nil {
		t.Fatal(err)
	}
	if ids := toolOf(t, c, "drive.create_shortcut").ResultIDs(res); ids["id"] != "1Short00000000000000000000000000" {
		t.Errorf("ResultIDs = %v", ids)
	}
	body := bodyOf(t, srv.Last(t, createFilePath))
	props, _ := body["appProperties"].(map[string]any)
	details, _ := body["shortcutDetails"].(map[string]any)
	if body["mimeType"] != "application/vnd.google-apps.shortcut" || details["targetId"] != fileID || body["name"] != "notes.txt" || props["mcp-gateway-op"] != opID {
		t.Errorf("shortcut body = %v", body)
	}
	// With a name, the target is not looked up.
	before := srv.Count("GET /drive/v3/files/" + fileID)
	if _, err := run(t, c, write("drive.create_shortcut", map[string]any{"file_id": fileID, "name": "Link"})); err != nil {
		t.Fatal(err)
	}
	if srv.Count("GET /drive/v3/files/"+fileID) != before || bodyOf(t, srv.Last(t, createFilePath))["name"] != "Link" {
		t.Error("a named shortcut must not look up the target")
	}
	// The lookup failing is a known outcome: nothing was created.
	srv = newAPIServer(t, map[string]route{getFilePath: {status: 500, body: "error_server.json"}})
	_, err = run(t, shortTimeout(t, srv), write("drive.create_shortcut", map[string]any{"file_id": fileID}))
	if err == nil || strings.Contains(err.Error(), "outcome") {
		t.Errorf("lookup failure = %v, want a known outcome", err)
	}
	for _, tc := range writeErrorCases(shortcutBody) {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{createFilePath: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("drive.create_shortcut", map[string]any{"file_id": fileID, "name": "x"}))
			checkWriteError(t, tc, res, err)
		})
	}
}

func TestDriveUploadNewVersion(t *testing.T) {
	srv := newAPIServer(t, map[string]route{uploadVersion: {status: 200, body: "file_updated.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("drive.upload_new_version", map[string]any{"file_id": fileID, "content": "version two", "mime_type": "text/plain"}))
	if err != nil {
		t.Fatal(err)
	}
	if ids := toolOf(t, c, "drive.upload_new_version").ResultIDs(res); ids["id"] != fileID {
		t.Errorf("ResultIDs = %v", ids)
	}
	up := srv.Last(t, uploadVersion)
	if up.URL.Query().Get("uploadType") != "multipart" || !strings.Contains(up.Body, "version two") || !strings.Contains(up.Body, `"mcp-gateway-op":"`+opID+`"`) {
		t.Errorf("upload = %s %q", up.URL, up.Body)
	}
	for _, args := range []map[string]any{
		{"content": "x"},
		{"file_id": fileID},
		{"file_id": fileID, "content": strings.Repeat("x", google.MaxDownloadBytes+1)},
		{"file_id": fileID, "content": "x", "mime_type": "not a type"},
	} {
		_, err := run(t, c, write("drive.upload_new_version", args))
		wantClass(t, err, google.ClassInvalidArgument, 0)
	}
	for _, tc := range writeErrorCases("file_updated.json") {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{uploadVersion: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("drive.upload_new_version", map[string]any{"file_id": fileID, "content": "x"}))
			checkWriteError(t, tc, res, err)
		})
	}
	// The same marker check as update_file.
	srv = newAPIServer(t, map[string]route{getFilePath: {status: 200, body: "file_marked.json"}})
	c, _ = newConnector(t, srv, connectors.Bounds{})
	tool, in := reconcileInput(t, c, "drive.upload_new_version", map[string]any{"file_id": fileID})
	out, err := tool.Reconcile.Check(context.Background(), in)
	wantOutcome(t, out, err, "found", fileID)
}

func TestDriveUpdateFileStarred(t *testing.T) {
	srv := newAPIServer(t, map[string]route{updateFilePath: {status: 200, body: "file_updated.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	if _, err := run(t, c, write("drive.update_file", map[string]any{"file_id": fileID, "starred": true})); err != nil {
		t.Fatal(err)
	}
	if body := bodyOf(t, srv.Last(t, updateFilePath)); body["starred"] != true {
		t.Errorf("star body = %v", body)
	}
	if _, err := run(t, c, write("drive.update_file", map[string]any{"file_id": fileID, "starred": false})); err != nil {
		t.Fatal(err)
	}
	if body := bodyOf(t, srv.Last(t, updateFilePath)); body["starred"] != false {
		t.Errorf("unstar body = %v", body)
	}
	_, err := run(t, c, write("drive.update_file", map[string]any{"file_id": fileID, "starred": "yes"}))
	wantClass(t, err, google.ClassInvalidArgument, 0)
}
