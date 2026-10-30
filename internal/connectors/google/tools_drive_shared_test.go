package google_test

import (
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

// Increment 4: shared drives. drive.list_shared_drives, and drive.search
// over every drive the account can see.

const listDrivesPath = "GET /drive/v3/drives"

func TestDriveSearchAllDrivesMyDriveAndIncomplete(t *testing.T) {
	srv := newAPIServer(t, map[string]route{listFilesPath: {status: 200, body: "files_list_incomplete.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("drive.search", nil))
	if err != nil {
		t.Fatal(err)
	}
	q := query(t, srv, "/drive/v3/files")
	if q.Get("corpora") != "allDrives" || q.Get("includeItemsFromAllDrives") != "true" || q.Get("supportsAllDrives") != "true" || q.Get("driveId") != "" {
		t.Errorf("query = %v, want every drive (corpora allDrives with items from all drives)", q)
	}
	var page struct {
		Drive            string `json:"drive"`
		IncompleteSearch bool   `json:"incomplete_search"`
	}
	decode(t, res, &page)
	if page.Drive != google.DriveAll || !page.IncompleteSearch || !res.Partial {
		t.Errorf("page = %+v, res = %+v; want drive all, incomplete_search and partial", page, res)
	}

	// drive_id "my": My Drive and the files shared with the account only.
	if _, err := run(t, c, call("drive.search", map[string]any{"drive_id": "my"})); err != nil {
		t.Fatal(err)
	}
	q = query(t, srv, "/drive/v3/files")
	if q.Get("corpora") != "user" || q.Get("driveId") != "" || q.Get("includeItemsFromAllDrives") != "" {
		t.Errorf("drive_id my: query = %v, want corpora user", q)
	}
}

func TestListSharedDrives(t *testing.T) {
	srv := newAPIServer(t, map[string]route{listDrivesPath: {status: 200, body: "drives_list.json"}})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("drive.list_shared_drives", map[string]any{"query": "name contains 'Eng'", "max_results": 5, "page_token": "p1"}))
	if err != nil {
		t.Fatalf("list_shared_drives: %v", err)
	}
	if len(tk.calls) != 1 || res.Empty || res.Partial {
		t.Errorf("token calls = %v, res = %+v", tk.calls, res)
	}
	q := query(t, srv, "/drive/v3/drives")
	for k, want := range map[string]string{
		"q": "name contains 'Eng'", "pageSize": "5", "pageToken": "p1", "useDomainAdminAccess": "false",
	} {
		if got := q.Get(k); got != want {
			t.Errorf("query %s = %q, want %q", k, got, want)
		}
	}
	if f := q.Get("fields"); !strings.Contains(f, "drives(") || strings.Contains(f, "capabilities") {
		t.Errorf("fields = %q, want a small drive projection", f)
	}
	var page struct {
		MaxResults    int    `json:"max_results"`
		NextPageToken string `json:"next_page_token"`
		HasMore       bool   `json:"has_more"`
		Items         []struct {
			ID           string   `json:"id"`
			Name         string   `json:"name"`
			Created      string   `json:"created"`
			Hidden       bool     `json:"hidden"`
			Restrictions []string `json:"restrictions"`
		} `json:"items"`
	}
	decode(t, res, &page)
	if page.MaxResults != 5 || !page.HasMore || page.NextPageToken != "drives-page-two" || len(page.Items) != 2 {
		t.Fatalf("page = %+v", page)
	}
	eng, archive := page.Items[0], page.Items[1]
	if eng.ID != "0ASharedDrive00000000PVA" || eng.Name != "Engineering" || eng.Created != "2025-03-01T09:00:00Z" || eng.Hidden ||
		strings.Join(eng.Restrictions, ",") != "admin_managed,domain_users_only,sharing_folders_requires_organizer" {
		t.Errorf("engineering = %+v", eng)
	}
	if archive.ID != "0BArchiveDrive0000000PVA" || !archive.Hidden || len(archive.Restrictions) != 0 {
		t.Errorf("archive = %+v", archive)
	}

	tool := declared(t, c, "drive.list_shared_drives", connectors.KindRead, []string{google.ScopeDriveReadonly}, "")
	if id := tool.ResourceIdentity(map[string]any{"query": "name contains 'secret'"}); len(id) != 0 {
		t.Errorf("identity = %v, want nothing (never the query)", id)
	}
	if tool.Bounds.MaxPageSize == 0 {
		t.Errorf("bounds = %+v, want paged", tool.Bounds)
	}
}

func TestListSharedDrivesEmptyClampedTruncatedAndErrors(t *testing.T) {
	empty := newAPIServer(t, map[string]route{listDrivesPath: {status: 200, body: "drives_list_empty.json"}})
	c, _ := newConnector(t, empty, connectors.Bounds{})
	res, err := run(t, c, call("drive.list_shared_drives", map[string]any{"max_results": 500}))
	if err != nil || !res.Empty || !res.Partial {
		t.Errorf("empty clamped: res = %+v, err = %v", res, err)
	}
	if q := query(t, empty, "/drive/v3/drives"); q.Has("q") || q.Get("pageSize") != "50" {
		t.Errorf("query = %v, want no q and the clamped page size", q)
	}

	full := newAPIServer(t, map[string]route{listDrivesPath: {status: 200, body: "drives_list.json"}})
	small, _ := newConnector(t, full, connectors.Bounds{MaxResultBytes: 300})
	res, err = run(t, small, call("drive.list_shared_drives", nil))
	if err != nil {
		t.Fatal(err)
	}
	var page struct {
		Truncated bool  `json:"truncated"`
		Items     []any `json:"items"`
	}
	decode(t, res, &page)
	if !page.Truncated || !res.Partial || len(page.Items) != 1 {
		t.Errorf("truncated: page = %+v, res = %+v", page, res)
	}

	cl, tk := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	for _, args := range []map[string]any{{"max_results": 0}, {"query": 5}, {"page_token": 7}} {
		_, err := run(t, cl, call("drive.list_shared_drives", args))
		wantClass(t, err, google.ClassInvalidArgument, 0)
	}
	if len(tk.calls) != 0 {
		t.Errorf("token calls for invalid arguments = %d", len(tk.calls))
	}

	for _, tc := range readErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{listDrivesPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := run(t, c, call("drive.list_shared_drives", nil))
			checkReadError(t, tc, res, err)
		})
	}
}

// drives.list accepts only drive and drive.readonly: drive.file does not
// admit it per file, nor does drive.metadata.readonly.
func TestListSharedDrivesScopeGate(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		listDrivesPath: {status: 200, body: "drives_list_empty.json"},
		listFilesPath:  {status: 200, body: "files_list_empty.json"},
	})
	grants := map[string][]string{
		"a1000000-0000-4000-8000-000000000001": {google.ScopeDriveFile},
		"a1000000-0000-4000-8000-000000000002": {google.ScopeDriveMetadataReadonly},
		"a1000000-0000-4000-8000-000000000003": {google.ScopeDriveReadonly},
		"a1000000-0000-4000-8000-000000000004": {google.ScopeDrive},
	}
	accounts := connectors.NewStaticAccountSource()
	for id, scopes := range grants {
		accounts.Add(alice, connectors.Account{ID: id, App: google.AppDrive, Label: connectors.LabelCompany, Scopes: scopes})
	}
	c, err := google.New(google.Options{Tokens: (&tokens{}).source, BaseURL: srv.URL + "/", Accounts: accounts})
	if err != nil {
		t.Fatal(err)
	}
	for id, scopes := range grants {
		cl := call("drive.list_shared_drives", nil)
		cl.Account = id
		_, err := run(t, c, cl)
		if scopes[0] == google.ScopeDriveReadonly || scopes[0] == google.ScopeDrive {
			if err != nil {
				t.Errorf("%v: %v", scopes, err)
			}
			continue
		}
		wantClass(t, err, google.ClassScopeRequired, 0)
	}
	if got := srv.Count(listDrivesPath); got != 2 {
		t.Errorf("requests = %d, want 2 (drive.file and drive.metadata.readonly are blocked before any request)", got)
	}
	// drive.file still admits the per-file tools.
	cl := call("drive.search", nil)
	cl.Account = "a1000000-0000-4000-8000-000000000001"
	if _, err := run(t, c, cl); err != nil {
		t.Errorf("drive.search with drive.file: %v (per-file admission must remain)", err)
	}
}
