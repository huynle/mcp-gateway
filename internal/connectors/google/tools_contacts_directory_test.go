package google_test

import (
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

const (
	searchDirectoryPath = "GET /v1/people:searchDirectoryPeople"
	listDirectoryPath   = "GET /v1/people:listDirectoryPeople"
	directoryReadMask   = "names,emailAddresses,organizations,phoneNumbers"
)

// wantDirectoryRequest checks the sources and read mask every directory
// request carries.
func wantDirectoryRequest(t *testing.T, srv *apiServer, path string) {
	t.Helper()
	q := query(t, srv, path)
	if got := strings.Join(q["sources"], ","); got != "DIRECTORY_SOURCE_TYPE_DOMAIN_PROFILE,DIRECTORY_SOURCE_TYPE_DOMAIN_CONTACT" {
		t.Errorf("sources = %q", got)
	}
	if got := q.Get("readMask"); got != directoryReadMask {
		t.Errorf("readMask = %q, want %q", got, directoryReadMask)
	}
}

func TestSearchDirectory(t *testing.T) {
	srv := newAPIServer(t, map[string]route{searchDirectoryPath: {status: 200, body: "directory_search.json"}})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("contacts.search_directory", map[string]any{"query": "car", "max_results": 5, "page_token": "dir-page-1"}))
	if err != nil {
		t.Fatalf("contacts.search_directory: %v", err)
	}
	if res.Empty || res.Partial || res.Unavailable {
		t.Errorf("markers = %+v", res)
	}
	if len(tk.calls) != 1 {
		t.Errorf("token calls = %v", tk.calls)
	}
	wantDirectoryRequest(t, srv, "/v1/people:searchDirectoryPeople")
	q := query(t, srv, "/v1/people:searchDirectoryPeople")
	if q.Get("query") != "car" || q.Get("pageSize") != "5" || q.Get("pageToken") != "dir-page-1" {
		t.Errorf("query = %v", q)
	}
	var page google.DirectoryPage
	decode(t, res, &page)
	if page.MaxResults != 5 || page.Total != 7 || page.NextPageToken != "dir-page-2" || !page.HasMore || page.Truncated || len(page.Items) != 2 {
		t.Fatalf("page = %+v", page)
	}
	first, second := page.Items[0], page.Items[1]
	if first.ResourceName != "people/104857392018374659201" || first.Name != "Carol Example" || first.GivenName != "Carol" || first.FamilyName != "Example" ||
		strings.Join(first.Emails, ",") != "carol@example.test" || first.Organization != "Example Corp" || first.Title != "Product Manager" ||
		strings.Join(first.Phones, ",") != "+1 555 0100" {
		t.Errorf("first = %+v", first)
	}
	if second.ResourceName != "people/c5550001112223334445" || second.Name != "Carlos Vendor" || strings.Join(second.Emails, ",") != "carlos@vendor.example.test" || len(second.Phones) != 0 {
		t.Errorf("second = %+v", second)
	}
}

func TestListDirectory(t *testing.T) {
	srv := newAPIServer(t, map[string]route{listDirectoryPath: {status: 200, body: "directory_list.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("contacts.list_directory", nil))
	if err != nil {
		t.Fatalf("contacts.list_directory: %v", err)
	}
	if res.Empty || res.Partial {
		t.Errorf("markers = %+v", res)
	}
	wantDirectoryRequest(t, srv, "/v1/people:listDirectoryPeople")
	q := query(t, srv, "/v1/people:listDirectoryPeople")
	if q.Get("pageSize") != "50" || q.Has("pageToken") {
		t.Errorf("query = %v, want the default page and no token", q)
	}
	var page google.DirectoryPage
	decode(t, res, &page)
	if page.MaxResults != 50 || page.HasMore || page.NextPageToken != "" || len(page.Items) != 2 {
		t.Fatalf("page = %+v", page)
	}
	if d := page.Items[1]; d.Name != "Dave Example" || strings.Join(d.Phones, ",") != "+1 555 0101" || d.Organization != "" {
		t.Errorf("second = %+v", d)
	}
}

func TestDirectoryEmptyClampedAndTruncated(t *testing.T) {
	for _, tc := range []struct {
		tool, path string
		args       map[string]any
	}{
		{"contacts.search_directory", searchDirectoryPath, map[string]any{"query": "nobody"}},
		{"contacts.list_directory", listDirectoryPath, map[string]any{}},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			urlPath := strings.TrimPrefix(tc.path, "GET ")
			srv := newAPIServer(t, map[string]route{tc.path: {status: 200, body: "directory_empty.json"}})
			c, _ := newConnector(t, srv, connectors.Bounds{MaxPageSize: 20})
			res, err := run(t, c, call(tc.tool, tc.args))
			if err != nil {
				t.Fatal(err)
			}
			var page google.DirectoryPage
			decode(t, res, &page)
			if !res.Empty || res.Partial || len(page.Items) != 0 || page.Items == nil {
				t.Errorf("res = %+v page = %+v, want Empty with an empty items list", res, page)
			}
			args := map[string]any{"max_results": 99}
			for k, v := range tc.args {
				args[k] = v
			}
			if res, err = run(t, c, call(tc.tool, args)); err != nil {
				t.Fatal(err)
			}
			if got := query(t, srv, urlPath).Get("pageSize"); got != "20" || !res.Partial {
				t.Errorf("pageSize = %q partial = %v, want 20 and Partial", got, res.Partial)
			}

			full := "directory_search.json"
			if tc.tool == "contacts.list_directory" {
				full = "directory_list.json"
			}
			srv = newAPIServer(t, map[string]route{tc.path: {status: 200, body: full}})
			c, _ = newConnector(t, srv, connectors.Bounds{MaxResultBytes: 300})
			if res, err = run(t, c, call(tc.tool, tc.args)); err != nil {
				t.Fatal(err)
			}
			decode(t, res, &page)
			if !res.Partial || !page.Truncated || len(page.Items) != 1 {
				t.Errorf("res = %+v page = %+v, want one item, truncated", res, page)
			}
		})
	}
}

func TestDirectoryArgumentsAndErrors(t *testing.T) {
	c, tk := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	for name, tc := range map[string]struct {
		tool string
		args map[string]any
	}{
		"search missing query":  {"contacts.search_directory", map[string]any{}},
		"search blank query":    {"contacts.search_directory", map[string]any{"query": "  "}},
		"search max_results 0":  {"contacts.search_directory", map[string]any{"query": "car", "max_results": 0}},
		"list max_results -1":   {"contacts.list_directory", map[string]any{"max_results": -1}},
		"list page_token array": {"contacts.list_directory", map[string]any{"page_token": []any{"x"}}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := run(t, c, call(tc.tool, tc.args))
			wantClass(t, err, google.ClassInvalidArgument, 0)
		})
	}
	if len(tk.calls) != 0 {
		t.Errorf("token calls for invalid arguments = %d", len(tk.calls))
	}
	for _, tc := range readErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{searchDirectoryPath: tc.rt, listDirectoryPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := run(t, c, call("contacts.search_directory", map[string]any{"query": "car"}))
			checkReadError(t, tc, res, err)
			res, err = run(t, c, call("contacts.list_directory", nil))
			checkReadError(t, tc, res, err)
		})
	}
}

func TestDirectoryResourceIdentityAndScopes(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	for _, name := range []string{"contacts.search_directory", "contacts.list_directory"} {
		tool := toolOf(t, c, name)
		got := tool.ResourceIdentity(map[string]any{"query": "secret person", "page_token": "tok"})
		if len(got) != 1 || got["source"] != "directory" {
			t.Errorf("%s identity = %v, want only source=directory (never the query)", name, got)
		}
		if len(tool.RequiredScopes) != 1 || tool.RequiredScopes[0] != google.ScopeDirectoryReadonly || tool.Kind != connectors.KindRead || tool.Bounds.MaxPageSize == 0 {
			t.Errorf("%s = %+v", name, tool)
		}
	}
}

// The scope gate names a Workspace-only scope as such: a personal
// (gmail.com) account can never grant it, a Workspace account can through
// grant more access. Other missing scopes keep the plain message.
func TestScopeGateExplainsWorkspaceOnlyScopes(t *testing.T) {
	srv := newAPIServer(t, nil)
	accounts := connectors.NewStaticAccountSource()
	accounts.Add(alice, connectors.Account{ID: acct, App: google.AppContacts, Label: connectors.LabelPersonal, Scopes: []string{"openid", google.ScopeGmailReadonly}})
	c, err := google.New(google.Options{Tokens: (&tokens{}).source, BaseURL: srv.URL + "/", Accounts: accounts})
	if err != nil {
		t.Fatal(err)
	}
	_, err = run(t, c, call("contacts.list_directory", nil))
	wantClass(t, err, google.ClassScopeRequired, 0)
	for _, want := range []string{google.ScopeDirectoryReadonly, "personal Google (gmail.com) accounts cannot grant", "Google Workspace account", "grant more access"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message %q lacks %q", err.Error(), want)
		}
	}
	_, err = run(t, c, call("contacts.list", nil))
	wantClass(t, err, google.ClassScopeRequired, 0)
	if strings.Contains(err.Error(), "Workspace") {
		t.Errorf("message for contacts.readonly %q should not mention Workspace", err.Error())
	}
	if n := len(srv.Requests()); n != 0 {
		t.Errorf("requests = %d, want none", n)
	}
}
