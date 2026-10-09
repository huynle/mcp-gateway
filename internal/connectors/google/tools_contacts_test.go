package google_test

import (
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

const searchContactsPath = "GET /v1/people:searchContacts"

func TestContactsSearch(t *testing.T) {
	srv := newAPIServer(t, map[string]route{searchContactsPath: {status: 200, body: "contacts_search.json"}})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("contacts.search", map[string]any{"query": "bob", "max_results": 5}))
	if err != nil {
		t.Fatalf("contacts.search: %v", err)
	}
	if res.Empty || res.Partial || res.Unavailable {
		t.Errorf("markers = %+v", res)
	}
	if len(tk.calls) != 1 {
		t.Errorf("token calls = %v", tk.calls)
	}
	q := query(t, srv, "/v1/people:searchContacts")
	if q.Get("query") != "bob" || q.Get("pageSize") != "5" || q.Get("readMask") != "names,emailAddresses,organizations" {
		t.Errorf("query = %v", q)
	}
	var page google.ContactsPage
	decode(t, res, &page)
	if page.MaxResults != 5 || page.Truncated || len(page.Items) != 2 {
		t.Fatalf("page = %+v", page)
	}
	first, second := page.Items[0], page.Items[1]
	if first.ResourceName != "people/c1234567890123456789" || first.Name != "Bob Example" || first.GivenName != "Bob" || first.FamilyName != "Example" ||
		strings.Join(first.Emails, ",") != "bob@example.test,bob.example@personal.example.test" || first.Organization != "Example Corp" || first.Title != "Engineer" {
		t.Errorf("first = %+v", first)
	}
	if second.ResourceName != "people/c9876543210987654321" || second.Name != "" || len(second.Emails) != 1 || second.Emails[0] != "bobby@example.test" || second.Organization != "" {
		t.Errorf("second = %+v", second)
	}
}

func TestContactsSearchEmptyDefaultsAndBounds(t *testing.T) {
	srv := newAPIServer(t, map[string]route{searchContactsPath: {status: 200, body: "contacts_search_empty.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("contacts.search", map[string]any{"query": "nobody"}))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Empty {
		t.Errorf("markers = %+v, want Empty", res)
	}
	if got := query(t, srv, "/v1/people:searchContacts").Get("pageSize"); got != "10" {
		t.Errorf("default pageSize = %q, want 10", got)
	}
	var page google.ContactsPage
	decode(t, res, &page)
	if len(page.Items) != 0 || page.MaxResults != 10 {
		t.Errorf("page = %+v", page)
	}
	t.Run("clamped to the API's ceiling", func(t *testing.T) {
		res, err := run(t, c, call("contacts.search", map[string]any{"query": "nobody", "max_results": 99}))
		if err != nil {
			t.Fatal(err)
		}
		if got := query(t, srv, "/v1/people:searchContacts").Get("pageSize"); got != "30" || !res.Partial {
			t.Errorf("pageSize = %q partial = %v, want 30 and Partial", got, res.Partial)
		}
	})
	t.Run("clamped to the bounds", func(t *testing.T) {
		c, _ := newConnector(t, srv, connectors.Bounds{MaxPageSize: 3})
		res, err := run(t, c, call("contacts.search", map[string]any{"query": "nobody", "max_results": 5}))
		if err != nil {
			t.Fatal(err)
		}
		if got := query(t, srv, "/v1/people:searchContacts").Get("pageSize"); got != "3" || !res.Partial {
			t.Errorf("pageSize = %q partial = %v, want 3 and Partial", got, res.Partial)
		}
	})
	t.Run("truncated to the bytes", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{searchContactsPath: {status: 200, body: "contacts_search.json"}})
		c, _ := newConnector(t, srv, connectors.Bounds{MaxResultBytes: 300})
		res, err := run(t, c, call("contacts.search", map[string]any{"query": "bob"}))
		if err != nil {
			t.Fatal(err)
		}
		var page google.ContactsPage
		decode(t, res, &page)
		if !res.Partial || !page.Truncated || len(page.Items) != 1 {
			t.Errorf("res = %+v page = %+v, want one item, truncated", res, page)
		}
	})
}

func TestContactsSearchArgumentsAndErrors(t *testing.T) {
	c, tk := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	for name, args := range map[string]map[string]any{
		"missing query": {},
		"blank query":   {"query": "  "},
		"max_results 0": {"query": "bob", "max_results": 0},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := run(t, c, call("contacts.search", args))
			wantClass(t, err, google.ClassInvalidArgument, 0)
		})
	}
	if len(tk.calls) != 0 {
		t.Errorf("token calls for invalid arguments = %d", len(tk.calls))
	}
	for _, tc := range readErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{searchContactsPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := run(t, c, call("contacts.search", map[string]any{"query": "bob"}))
			checkReadError(t, tc, res, err)
		})
	}
}

func TestContactsResourceIdentityAndScopes(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	search := toolOf(t, c, "contacts.search")
	if got := search.ResourceIdentity(map[string]any{"query": "secret"}); len(got) != 0 {
		t.Errorf("identity = %v, want nothing (never the query)", got)
	}
	if search.RequiredScopes[0] != google.ScopeContactsReadonly || search.Kind != connectors.KindRead || search.Bounds.MaxPageSize == 0 {
		t.Errorf("tool = %+v", search)
	}
}
