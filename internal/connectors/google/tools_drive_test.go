package google_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

const (
	listFilesPath  = "GET /drive/v3/files"
	createFilePath = "POST /drive/v3/files"
	fileID         = "1gB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV"
	getFilePath    = "GET /drive/v3/files/" + fileID
	newFolderID    = "1NewFolder00000000000000000000000"
)

func TestDriveSearch(t *testing.T) {
	srv := newAPIServer(t, map[string]route{listFilesPath: {status: 200, body: "files_list.json"}})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("drive.search", map[string]any{"q": "name contains 'budget'", "max_results": 10}))
	if err != nil {
		t.Fatalf("drive.search: %v", err)
	}
	if res.Empty || res.Partial || res.Unavailable {
		t.Errorf("markers = %+v", res)
	}
	if len(tk.calls) != 1 {
		t.Errorf("token calls = %v", tk.calls)
	}
	q := query(t, srv, "/drive/v3/files")
	for k, want := range map[string]string{
		"q": "(name contains 'budget') and trashed = false", "pageSize": "10", "corpora": "allDrives", "includeItemsFromAllDrives": "true", "supportsAllDrives": "true",
	} {
		if got := q.Get(k); got != want {
			t.Errorf("query %s = %q, want %q", k, got, want)
		}
	}
	if f := q.Get("fields"); !strings.Contains(f, "files(id,name,mimeType") || strings.Contains(f, "appProperties") {
		t.Errorf("fields = %q: metadata only, never appProperties", f)
	}
	if q.Get("driveId") != "" {
		t.Errorf("query %v names a drive without drive_id", q)
	}
	var page google.FilesPage
	decode(t, res, &page)
	if page.Drive != "all" || !page.HasMore || page.NextPageToken != "files-page-two" || page.MaxResults != 10 || len(page.Items) != 2 {
		t.Fatalf("page = %+v", page)
	}
	first, second := page.Items[0], page.Items[1]
	if first.ID != "1fA0bC1dE2fG3hI4jK5lM6nO7pQ8rS9tU" || first.Name != "Q4 budget" || first.MimeType != "application/vnd.google-apps.spreadsheet" ||
		first.Modified != "2026-10-07T18:30:00Z" || first.Created != "2026-09-01T08:00:00Z" || !strings.HasPrefix(first.URL, "https://docs.google.com/spreadsheets/d/") ||
		len(first.Parents) != 1 || !first.Shared || !first.OwnedByMe || len(first.Owners) != 1 || first.Owners[0] != "alice@example.test" || first.Size != 0 {
		t.Errorf("first = %+v", first)
	}
	if second.ID != fileID || second.Size != 204800 || second.DriveID != "0ASharedDrive00000000PVA" || second.Description != "Scanned design notes from the offsite." || len(second.Owners) != 0 {
		t.Errorf("second = %+v", second)
	}
}

func TestDriveSearchSharedDriveTrashedAndEmpty(t *testing.T) {
	srv := newAPIServer(t, map[string]route{listFilesPath: {status: 200, body: "files_list_empty.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("drive.search", map[string]any{"drive_id": "0ASharedDrive00000000PVA", "include_trashed": true, "page_token": "files-page-two"}))
	if err != nil {
		t.Fatalf("drive.search: %v", err)
	}
	if !res.Empty {
		t.Errorf("markers = %+v, want Empty", res)
	}
	q := query(t, srv, "/drive/v3/files")
	for k, want := range map[string]string{
		"q": "", "pageSize": "25", "corpora": "drive", "driveId": "0ASharedDrive00000000PVA", "includeItemsFromAllDrives": "true", "supportsAllDrives": "true", "pageToken": "files-page-two",
	} {
		if got := q.Get(k); got != want {
			t.Errorf("query %s = %q, want %q", k, got, want)
		}
	}
	var page google.FilesPage
	decode(t, res, &page)
	if page.Drive != "0ASharedDrive00000000PVA" || page.HasMore || len(page.Items) != 0 {
		t.Errorf("page = %+v", page)
	}
	// Without q, trashed files are still filtered out.
	if _, err := run(t, c, call("drive.search", nil)); err != nil {
		t.Fatal(err)
	}
	if got := query(t, srv, "/drive/v3/files").Get("q"); got != "trashed = false" {
		t.Errorf("q without a query = %q, want trashed = false", got)
	}
}

func TestDriveSearchClampAndTruncate(t *testing.T) {
	srv := newAPIServer(t, map[string]route{listFilesPath: {status: 200, body: "files_list.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{MaxPageSize: 5, MaxResultBytes: 500})
	res, err := run(t, c, call("drive.search", map[string]any{"max_results": 99}))
	if err != nil {
		t.Fatal(err)
	}
	var page google.FilesPage
	decode(t, res, &page)
	if !res.Partial || !page.Truncated || len(page.Items) != 1 {
		t.Errorf("res = %+v page = %+v, want clamped+truncated to one item", res, page)
	}
	if got := query(t, srv, "/drive/v3/files").Get("pageSize"); got != "5" {
		t.Errorf("pageSize = %q, want 5", got)
	}
}

func TestDriveSearchArgumentsAndErrors(t *testing.T) {
	c, tk := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	for name, args := range map[string]map[string]any{
		"bad drive_id":        {"drive_id": "a/b"},
		"bad include_trashed": {"include_trashed": "yes"},
		"max_results 0":       {"max_results": 0},
		"q not a string":      {"q": 7},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := run(t, c, call("drive.search", args))
			wantClass(t, err, google.ClassInvalidArgument, 0)
		})
	}
	if len(tk.calls) != 0 {
		t.Errorf("token calls for invalid arguments = %d", len(tk.calls))
	}
	for _, tc := range readErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{listFilesPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := run(t, c, call("drive.search", nil))
			checkReadError(t, tc, res, err)
		})
	}
}

func TestDriveGetFileMetadata(t *testing.T) {
	srv := newAPIServer(t, map[string]route{getFilePath: {status: 200, body: "file_metadata.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("drive.get_file_metadata", map[string]any{"file_id": fileID}))
	if err != nil {
		t.Fatalf("get_file_metadata: %v", err)
	}
	if res.Empty || res.Partial || res.Unavailable {
		t.Errorf("markers = %+v", res)
	}
	q := query(t, srv, "/drive/v3/files/"+fileID)
	if q.Get("supportsAllDrives") != "true" || !strings.Contains(q.Get("fields"), "owners(emailAddress)") {
		t.Errorf("query = %v", q)
	}
	var f google.DriveFile
	decode(t, res, &f)
	if f.ID != fileID || f.Name != "Design notes.pdf" || f.MimeType != "application/pdf" || f.Modified != "2026-09-20T12:00:00Z" || f.Size != 204800 ||
		f.DriveID != "0ASharedDrive00000000PVA" || f.OwnedByMe || !f.Shared || f.Trashed || len(f.Owners) != 2 || f.Owners[1] != "carol@example.test" ||
		!strings.HasPrefix(f.Description, "Scanned design notes") || f.Truncated {
		t.Errorf("file = %+v", f)
	}
	t.Run("description cut to the bounds", func(t *testing.T) {
		c, _ := newConnector(t, srv, connectors.Bounds{MaxResultBytes: 450})
		res, err := run(t, c, call("drive.get_file_metadata", map[string]any{"file_id": fileID}))
		if err != nil {
			t.Fatal(err)
		}
		var f google.DriveFile
		decode(t, res, &f)
		if !res.Partial || !f.Truncated || f.ID != fileID || len(f.Description) >= 300 || encodedSizeOf(t, res) > 450 {
			t.Errorf("res = %+v file = %+v", res, f)
		}
	})
	t.Run("arguments and errors", func(t *testing.T) {
		for name, args := range map[string]map[string]any{"missing": {}, "slash": {"file_id": "a/b"}, "blank": {"file_id": "  "}} {
			_, err := run(t, c, call("drive.get_file_metadata", args))
			if err == nil {
				t.Errorf("%s: no error", name)
				continue
			}
			wantClass(t, err, google.ClassInvalidArgument, 0)
		}
		for _, tc := range readErrorCases() {
			t.Run(tc.name, func(t *testing.T) {
				srv := newAPIServer(t, map[string]route{getFilePath: tc.rt})
				c, _ := newConnector(t, srv, connectors.Bounds{})
				res, err := run(t, c, call("drive.get_file_metadata", map[string]any{"file_id": fileID}))
				checkReadError(t, tc, res, err)
			})
		}
	})
}

// encodedSizeOf is the serialised size of a result's content.
func encodedSizeOf(t *testing.T, res connectors.Result) int {
	t.Helper()
	b, err := json.Marshal(res.Content)
	if err != nil {
		t.Fatal(err)
	}
	return len(b)
}

func TestDriveResourceIdentityAndScopes(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	search := toolOf(t, c, "drive.search")
	if got := search.ResourceIdentity(map[string]any{"q": "secret"}); got["drive"] != "all" || len(got) != 1 {
		t.Errorf("search identity = %v, want drive all (every drive is searched)", got)
	}
	if got := search.ResourceIdentity(map[string]any{"drive_id": "my", "q": "secret"}); got["drive"] != "my" || len(got) != 1 {
		t.Errorf("search identity with drive_id my = %v", got)
	}
	if got := search.ResourceIdentity(map[string]any{"drive_id": " 0ADrive ", "q": "secret"}); got["drive"] != "0ADrive" || len(got) != 1 {
		t.Errorf("search identity with drive = %v", got)
	}
	if search.RequiredScopes[0] != google.ScopeDriveMetadataReadonly || search.Bounds.MaxPageSize == 0 {
		t.Errorf("search tool = %+v", search)
	}
	get := toolOf(t, c, "drive.get_file_metadata")
	if got := get.ResourceIdentity(map[string]any{"file_id": fileID}); got["file_id"] != fileID || len(got) != 1 {
		t.Errorf("get identity = %v", got)
	}
	if got := get.ResourceIdentity(nil); len(got) != 0 {
		t.Errorf("get identity(nil) = %v", got)
	}
	if get.RequiredScopes[0] != google.ScopeDriveMetadataReadonly || get.Bounds.MaxPageSize != 0 {
		t.Errorf("get tool = %+v", get)
	}
	create := toolOf(t, c, "drive.create_folder")
	if got := create.ResourceIdentity(map[string]any{"name": "secret", "parent_id": "1Parent", "drive_id": "0ADrive"}); got["drive"] != "0ADrive" || got["folder_id"] != "1Parent" || len(got) != 2 {
		t.Errorf("create identity = %v", got)
	}
	if got := create.ResourceIdentity(map[string]any{"name": "secret"}); got["drive"] != "my" || len(got) != 1 {
		t.Errorf("create identity(default) = %v", got)
	}
	if create.RequiredScopes[0] != google.ScopeDriveFile || create.Reconcile.Kind != connectors.ReconcileMarker || create.Reconcile.Check == nil || create.ResultIDs == nil {
		t.Errorf("create tool = %+v", create)
	}
}

// --- drive.create_folder ---------------------------------------------------------

func TestDriveMarkerQueryEscapes(t *testing.T) {
	if got := google.DriveMarkerQuery(opID); got != "appProperties has { key='mcp-gateway-op' and value='"+opID+"' }" {
		t.Errorf("DriveMarkerQuery = %q", got)
	}
	if got := google.DriveMarkerQuery(`a'b\c`); !strings.Contains(got, `value='a\'b\\c'`) {
		t.Errorf("DriveMarkerQuery escapes quotes and backslashes: %q", got)
	}
}

func TestCreateFolder(t *testing.T) {
	srv := newAPIServer(t, map[string]route{createFilePath: {status: 200, body: "created_folder.json"}})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("drive.create_folder", map[string]any{"name": "Gateway exports", "parent_id": "1Folder0000000000000000000000000"}))
	if err != nil {
		t.Fatalf("create_folder: %v", err)
	}
	if len(tk.calls) != 1 {
		t.Errorf("token calls = %v", tk.calls)
	}
	req := srv.Last(t, createFilePath)
	if req.URL.Query().Get("supportsAllDrives") != "true" || !strings.Contains(req.URL.Query().Get("fields"), "id") {
		t.Errorf("query = %v", req.URL.Query())
	}
	var body struct {
		Name          string            `json:"name"`
		MimeType      string            `json:"mimeType"`
		Parents       []string          `json:"parents"`
		AppProperties map[string]string `json:"appProperties"`
	}
	if err := json.Unmarshal([]byte(req.Body), &body); err != nil {
		t.Fatal(err)
	}
	if body.Name != "Gateway exports" || body.MimeType != google.MimeFolder || len(body.Parents) != 1 || body.Parents[0] != "1Folder0000000000000000000000000" ||
		body.AppProperties[google.DriveMarkerKey] != opID || len(body.AppProperties) != 1 {
		t.Errorf("request body = %s", req.Body)
	}
	created, ok := res.Content.(google.CreatedFolder)
	if !ok || created.ID != newFolderID || created.URL == "" || created.ParentID != "1Folder0000000000000000000000000" {
		t.Errorf("content = %#v", res.Content)
	}
	tool := toolOf(t, c, "drive.create_folder")
	if ids := tool.ResultIDs(res); ids["id"] != newFolderID || ids["url"] != created.URL || len(ids) != 2 {
		t.Errorf("ResultIDs = %v", ids)
	}
	if tool.ResultIDs(connectors.Result{Content: "junk"}) != nil {
		t.Error("ResultIDs of a foreign result should be nil")
	}
}

func TestCreateFolderInSharedDriveRootAndDefaults(t *testing.T) {
	srv := newAPIServer(t, map[string]route{createFilePath: {status: 200, body: "created_folder.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	if _, err := run(t, c, write("drive.create_folder", map[string]any{"name": "Shared", "drive_id": "0ASharedDrive00000000PVA"})); err != nil {
		t.Fatal(err)
	}
	var body struct {
		Parents []string `json:"parents"`
	}
	if err := json.Unmarshal([]byte(srv.Last(t, createFilePath).Body), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Parents) != 1 || body.Parents[0] != "0ASharedDrive00000000PVA" {
		t.Errorf("parents = %v, want the shared drive as the parent", body.Parents)
	}
	if _, err := run(t, c, write("drive.create_folder", map[string]any{"name": "Root"})); err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal([]byte(srv.Last(t, createFilePath).Body), &root); err != nil {
		t.Fatal(err)
	}
	if _, ok := root["parents"]; ok {
		t.Errorf("request body = %v, want no parents (My Drive root)", root)
	}
}

func TestCreateFolderArgumentsAndErrors(t *testing.T) {
	c, tk := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	for name, args := range map[string]map[string]any{
		"missing name":  {},
		"blank name":    {"name": " "},
		"bad parent_id": {"name": "x", "parent_id": "a b"},
		"bad drive_id":  {"name": "x", "drive_id": "a/b"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := run(t, c, write("drive.create_folder", args))
			wantClass(t, err, google.ClassInvalidArgument, 0)
		})
	}
	if len(tk.calls) != 0 {
		t.Errorf("token calls for invalid arguments = %d", len(tk.calls))
	}
	for _, tc := range writeErrorCases("created_folder.json") {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{createFilePath: tc.rt})
			c := shortTimeout(t, srv)
			res, err := run(t, c, write("drive.create_folder", map[string]any{"name": "x"}))
			checkWriteError(t, tc, res, err)
		})
	}
}

// --- drive.create_folder: marker check -------------------------------------------------

func TestCheckDriveMarker(t *testing.T) {
	args := map[string]any{"name": "x", "parent_id": "1Folder0000000000000000000000000"}
	t.Run("found", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{listFilesPath: {status: 200, body: "files_list_marker_hit.json"}})
		c, tk := newConnector(t, srv, connectors.Bounds{})
		tool, in := reconcileInput(t, c, "drive.create_folder", args)
		out, err := tool.Reconcile.Check(context.Background(), in)
		wantFound(t, out, err, newFolderID)
		if len(tk.calls) != 1 || tk.calls[0] != alice+"/"+acct {
			t.Errorf("token calls = %v", tk.calls)
		}
		q := query(t, srv, "/drive/v3/files")
		if q.Get("q") != google.DriveMarkerQuery(opID) || q.Get("corpora") != "allDrives" || q.Get("includeItemsFromAllDrives") != "true" || q.Get("supportsAllDrives") != "true" {
			t.Errorf("listing query = %v", q)
		}
		if ps := q.Get("pageSize"); ps == "" || ps == "100" {
			t.Errorf("pageSize = %q, want a small bound", ps)
		}
	})
	t.Run("not found", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{listFilesPath: {status: 200, body: "files_list_empty.json"}})
		c, _ := newConnector(t, srv, connectors.Bounds{})
		tool, in := reconcileInput(t, c, "drive.create_folder", args)
		out, err := tool.Reconcile.Check(context.Background(), in)
		wantNotFound(t, out, err)
	})
	for name, rt := range map[string]route{
		"500": {status: 500, body: "error_server.json"}, "401": {status: 401, body: "error_unauthorized.json"},
		"403": {status: 403, body: "error_forbidden.json"}, "404": {status: 404, body: "error_not_found.json"}, "429": {status: 429, body: "error_rate_limit_429.json"},
	} {
		t.Run("cannot tell "+name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{listFilesPath: rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, "drive.create_folder", args)
			out, err := tool.Reconcile.Check(context.Background(), in)
			wantCannotTell(t, out, err)
		})
	}
	t.Run("missing operation or account", func(t *testing.T) {
		c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
		tool, in := reconcileInput(t, c, "drive.create_folder", args)
		in.OperationID, in.Call.OperationID = "", ""
		if _, err := tool.Reconcile.Check(context.Background(), in); !errors.Is(err, google.ErrNotReconcilable) {
			t.Errorf("without operation id: err = %v, want ErrNotReconcilable", err)
		}
		_, in = reconcileInput(t, c, "drive.create_folder", args)
		in.Call.Account = ""
		if _, err := tool.Reconcile.Check(context.Background(), in); !errors.Is(err, google.ErrNotReconcilable) {
			t.Errorf("without account: err = %v, want ErrNotReconcilable", err)
		}
	})
}
