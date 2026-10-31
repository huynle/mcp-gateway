package google_test

import (
	"context"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

// Increment 5: the full People API for the account's own contacts:
// contact writes, contact groups and "other contacts".

const (
	createContactPath = "POST /v1/people:createContact"
	bobPath           = "/v1/people/c1234567890"
	updateContactPath = "PATCH /v1/people/c1234567890:updateContact"
	deleteContactPath = "DELETE /v1/people/c1234567890:deleteContact"
	groupsPath        = "/v1/contactGroups"
	friendsPath       = "/v1/contactGroups/friends"
	modifyMembersPath = "POST /v1/contactGroups/friends/members:modify"
	otherContactsPath = "GET /v1/otherContacts"
	otherSearchPath   = "GET /v1/otherContacts:search"
	copyOtherPath     = "POST /v1/otherContacts/c111:copyOtherContactToMyContactsGroup"

	scopeContacts         = "https://www.googleapis.com/auth/contacts"
	scopeContactsRO       = "https://www.googleapis.com/auth/contacts.readonly"
	scopeContactsOtherRO  = "https://www.googleapis.com/auth/contacts.other.readonly"
	contactsMarkerKeyWant = "mcp-gateway-op"
)

func TestContactsFullDeclarations(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	r, w := connectors.KindRead, connectors.KindWrite
	declared(t, c, "contacts.list_groups", r, []string{scopeContactsRO}, "")
	declared(t, c, "contacts.get_group", r, []string{scopeContactsRO}, "")
	declared(t, c, "contacts.list_other_contacts", r, []string{scopeContactsOtherRO}, "")
	declared(t, c, "contacts.search_other_contacts", r, []string{scopeContactsOtherRO}, "")
	declared(t, c, "contacts.create", w, []string{scopeContacts}, connectors.ReconcileMarker)
	declared(t, c, "contacts.update", w, []string{scopeContacts}, connectors.ReconcileMarker)
	declared(t, c, "contacts.delete", w, []string{scopeContacts}, connectors.ReconcileStableID)
	declared(t, c, "contacts.create_group", w, []string{scopeContacts}, connectors.ReconcileMarker)
	declared(t, c, "contacts.update_group", w, []string{scopeContacts}, connectors.ReconcileMarker)
	declared(t, c, "contacts.delete_group", w, []string{scopeContacts}, connectors.ReconcileStableID)
	declared(t, c, "contacts.modify_group_members", w, []string{scopeContacts}, connectors.ReconcileStableID)
	declared(t, c, "contacts.copy_other_contact", w, []string{scopeContactsOtherRO}, connectors.ReconcileNone)

	if id := toolOf(t, c, "contacts.create").ResourceIdentity(map[string]any{"given_name": "Dana", "emails": []any{"dana@example.test"}}); len(id) != 0 {
		t.Errorf("create identity = %v", id)
	}
	if id := toolOf(t, c, "contacts.update").ResourceIdentity(map[string]any{"resource_name": "people/c1", "given_name": "X"}); len(id) != 1 || id["resource_name"] != "people/c1" {
		t.Errorf("update identity = %v", id)
	}
	if id := toolOf(t, c, "contacts.create_group").ResourceIdentity(map[string]any{"name": "Secret"}); len(id) != 0 {
		t.Errorf("create_group identity = %v", id)
	}
	id := toolOf(t, c, "contacts.modify_group_members").ResourceIdentity(map[string]any{
		"group": "contactGroups/friends", "add": []any{"people/c3", "people/c1"}, "remove": []any{"people/c2"},
	})
	if id["group"] != "contactGroups/friends" || id["add_members"] != "people/c1,people/c3" || id["remove_members"] != "people/c2" {
		t.Errorf("modify identity = %v", id)
	}
	if id := toolOf(t, c, "contacts.copy_other_contact").ResourceIdentity(map[string]any{"resource_name": "otherContacts/c111"}); id["resource_name"] != "otherContacts/c111" {
		t.Errorf("copy identity = %v", id)
	}
}

func TestContactsScopeImplications(t *testing.T) {
	if !google.Grants([]string{scopeContacts}, scopeContactsRO) {
		t.Error("contacts must cover contacts.readonly")
	}
	// otherContacts.list and search accept only contacts.other.readonly.
	if google.Grants([]string{scopeContacts}, scopeContactsOtherRO) {
		t.Error("contacts must not cover contacts.other.readonly")
	}
}

func TestCreateContact(t *testing.T) {
	srv := newAPIServer(t, map[string]route{createContactPath: {status: 200, body: "person_created.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("contacts.create", map[string]any{
		"given_name": "Dana", "family_name": "New", "emails": []any{"dana@example.test"}, "phones": []any{"+1 555 0123"},
		"organization": "Acme", "title": "CTO", "notes": "Met at the conference", "addresses": []any{"2 Side St"},
		"birthday": "1985-12-24", "urls": []any{"https://dana.example.test"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if ids := toolOf(t, c, "contacts.create").ResultIDs(res); ids["resource_name"] != "people/c999" {
		t.Errorf("ResultIDs = %v", ids)
	}
	b := bodyOf(t, srv.Last(t, createContactPath))
	name := b["names"].([]any)[0].(map[string]any)
	if name["givenName"] != "Dana" || name["familyName"] != "New" {
		t.Errorf("names = %v", b["names"])
	}
	if b["emailAddresses"].([]any)[0].(map[string]any)["value"] != "dana@example.test" || b["phoneNumbers"].([]any)[0].(map[string]any)["value"] != "+1 555 0123" {
		t.Errorf("body = %v", b)
	}
	org := b["organizations"].([]any)[0].(map[string]any)
	if org["name"] != "Acme" || org["title"] != "CTO" {
		t.Errorf("organizations = %v", b["organizations"])
	}
	if b["biographies"].([]any)[0].(map[string]any)["value"] != "Met at the conference" ||
		b["addresses"].([]any)[0].(map[string]any)["formattedValue"] != "2 Side St" ||
		b["urls"].([]any)[0].(map[string]any)["value"] != "https://dana.example.test" {
		t.Errorf("body = %v", b)
	}
	date := b["birthdays"].([]any)[0].(map[string]any)["date"].(map[string]any)
	if date["year"] != float64(1985) || date["month"] != float64(12) || date["day"] != float64(24) {
		t.Errorf("birthdays = %v", b["birthdays"])
	}
	cd := b["clientData"].([]any)[0].(map[string]any)
	if cd["key"] != contactsMarkerKeyWant || cd["value"] != opID {
		t.Errorf("clientData = %v", b["clientData"])
	}
	for _, args := range []map[string]any{
		{},
		{"notes": "only notes"},
		{"given_name": "x", "emails": []any{"not an address"}},
		{"given_name": "x", "birthday": "24.12.1985"},
		{"given_name": "x", "urls": []any{"javascript:alert(1)"}},
	} {
		_, err := run(t, c, write("contacts.create", args))
		wantClass(t, err, google.ClassInvalidArgument, 0)
	}
	if _, err := run(t, c, write("contacts.create", map[string]any{"given_name": "Ann", "birthday": "--04-02"})); err != nil {
		t.Fatalf("birthday without a year: %v", err)
	}
	date = bodyOf(t, srv.Last(t, createContactPath))["birthdays"].([]any)[0].(map[string]any)["date"].(map[string]any)
	if _, ok := date["year"]; ok || date["month"] != float64(4) || date["day"] != float64(2) {
		t.Errorf("yearless birthday = %v", date)
	}

	for name, tc := range map[string]struct {
		rt   route
		want string
	}{
		"hit":   {route{status: 200, body: "connections_marker_hit.json"}, "found"},
		"miss":  {route{status: 200, body: "connections_marker_miss.json"}, "not_found"},
		"500":   {route{status: 500, body: "error_server.json"}, "cannot"},
		"pages": {route{pages: map[string]route{"1": {status: 200, body: "connections_marker_more.json"}, "conn-more": {status: 200, body: "connections_marker_more.json"}}}, "cannot"},
		"later": {route{pages: map[string]route{"1": {status: 200, body: "connections_marker_more.json"}, "conn-more": {status: 200, body: "connections_marker_hit.json"}}}, "found"},
	} {
		t.Run("check "+name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"GET /v1/people/me/connections": tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, "contacts.create", nil)
			out, err := tool.Reconcile.Check(context.Background(), in)
			wantOutcome(t, out, err, tc.want, "people/c999")
			if q := query(t, srv, "/v1/people/me/connections"); !strings.Contains(q.Get("personFields"), "clientData") {
				t.Errorf("personFields = %q", q.Get("personFields"))
			}
		})
	}
}

func TestUpdateContact(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET " + bobPath: {status: 200, body: "person_full.json"}, updateContactPath: {status: 200, body: "person_marked.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("contacts.update", map[string]any{"resource_name": "people/c1234567890", "family_name": "Changed", "title": "Lead", "emails": []any{"bob@new.example.test"}}))
	if err != nil {
		t.Fatal(err)
	}
	if ids := toolOf(t, c, "contacts.update").ResultIDs(res); ids["resource_name"] != "people/c1234567890" {
		t.Errorf("ResultIDs = %v", ids)
	}
	r := srv.Last(t, updateContactPath)
	fields := strings.Split(r.URL.Query().Get("updatePersonFields"), ",")
	for _, want := range []string{"names", "organizations", "emailAddresses", "clientData"} {
		if !strings.Contains(","+strings.Join(fields, ",")+",", ","+want+",") {
			t.Errorf("updatePersonFields = %v, missing %s", fields, want)
		}
	}
	if strings.Contains(r.URL.Query().Get("updatePersonFields"), "phoneNumbers") {
		t.Errorf("phoneNumbers updated although not given: %v", fields)
	}
	b := bodyOf(t, r)
	if b["etag"] != "%EgUBAi43PRoEAQIFByIM" {
		t.Errorf("etag = %v", b["etag"])
	}
	name := b["names"].([]any)[0].(map[string]any)
	if name["givenName"] != "Bob" || name["familyName"] != "Changed" {
		t.Errorf("names keep the given name: %v", b["names"])
	}
	org := b["organizations"].([]any)[0].(map[string]any)
	if org["name"] != "Example Corp" || org["title"] != "Lead" {
		t.Errorf("organizations keep the name: %v", b["organizations"])
	}
	var keys []string
	for _, d := range b["clientData"].([]any) {
		m := d.(map[string]any)
		keys = append(keys, m["key"].(string)+"="+m["value"].(string))
	}
	if strings.Join(keys, ";") != "other-app=keep;mcp-gateway-op="+opID {
		t.Errorf("clientData = %v", keys)
	}
	for _, args := range []map[string]any{
		{"resource_name": "people/c1234567890"},
		{"given_name": "x"},
		{"resource_name": "people/../x", "given_name": "x"},
		{"resource_name": "people/c1234567890", "phones": []any{}, "emails": []any{"bad"}},
	} {
		_, err := run(t, c, write("contacts.update", args))
		wantClass(t, err, google.ClassInvalidArgument, 0)
	}
	for name, tc := range map[string]struct {
		rt   route
		want string
	}{
		"marked":   {route{status: 200, body: "person_marked.json"}, "found"},
		"unmarked": {route{status: 200, body: "person_unmarked.json"}, "not_found"},
		"other op": {route{status: 200, body: "person_marked_other.json"}, "cannot"},
		"404":      {route{status: 404, body: "error_not_found.json"}, "cannot"},
	} {
		t.Run("check "+name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"GET " + bobPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, "contacts.update", map[string]any{"resource_name": "people/c1234567890"})
			out, err := tool.Reconcile.Check(context.Background(), in)
			wantOutcome(t, out, err, tc.want, "people/c1234567890")
		})
	}
}

func TestDeleteContact(t *testing.T) {
	srv := newAPIServer(t, map[string]route{deleteContactPath: {status: 200, body: "{}"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("contacts.delete", map[string]any{"resource_name": "people/c1234567890"}))
	if err != nil {
		t.Fatal(err)
	}
	if ids := toolOf(t, c, "contacts.delete").ResultIDs(res); ids["resource_name"] != "people/c1234567890" {
		t.Errorf("ResultIDs = %v", ids)
	}
	for name, tc := range map[string]struct {
		rt   route
		want string
	}{
		"404":     {route{status: 404, body: "error_not_found.json"}, "found"},
		"present": {route{status: 200, body: "person.json"}, "not_found"},
		"500":     {route{status: 500, body: "error_server.json"}, "cannot"},
	} {
		t.Run("check "+name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"GET " + bobPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, "contacts.delete", map[string]any{"resource_name": "people/c1234567890"})
			out, err := tool.Reconcile.Check(context.Background(), in)
			wantOutcome(t, out, err, tc.want, "people/c1234567890")
		})
	}
}

func TestGetContactShowsAllFields(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET " + bobPath: {status: 200, body: "person_full.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("contacts.get", map[string]any{"resource_name": "people/c1234567890"}))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Addresses []string `json:"addresses"`
		Birthday  string   `json:"birthday"`
		Notes     string   `json:"notes"`
		URLs      []string `json:"urls"`
		Groups    []string `json:"groups"`
	}
	decode(t, res, &out)
	if len(out.Addresses) != 1 || out.Birthday != "1990-04-02" || out.Notes != "Met at the offsite." || len(out.URLs) != 1 ||
		strings.Join(out.Groups, ",") != "contactGroups/friends,contactGroups/myContacts" {
		t.Errorf("out = %+v", out)
	}
}

func TestContactGroupReads(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET " + groupsPath: {status: 200, body: "contact_groups.json"}, "GET " + friendsPath: {status: 200, body: "contact_group.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("contacts.list_groups", map[string]any{"max_results": 2}))
	if err != nil {
		t.Fatal(err)
	}
	var page struct {
		HasMore bool `json:"has_more"`
		Items   []struct {
			ResourceName string `json:"resource_name"`
			Name         string `json:"name"`
			GroupType    string `json:"group_type"`
			MemberCount  int    `json:"member_count"`
		} `json:"items"`
	}
	decode(t, res, &page)
	if !page.HasMore || len(page.Items) != 2 || page.Items[0].Name != "My Contacts" || page.Items[1].ResourceName != "contactGroups/friends" || page.Items[1].MemberCount != 3 {
		t.Errorf("page = %+v", page)
	}
	if q := query(t, srv, groupsPath); q.Get("pageSize") != "2" {
		t.Errorf("query = %v", q)
	}
	res, err = run(t, c, call("contacts.get_group", map[string]any{"group": "contactGroups/friends"}))
	if err != nil {
		t.Fatal(err)
	}
	var g struct {
		Name    string   `json:"name"`
		Members []string `json:"members"`
	}
	decode(t, res, &g)
	if g.Name != "Friends" || len(g.Members) != 2 {
		t.Errorf("group = %+v", g)
	}
	if q := query(t, srv, friendsPath); q.Get("maxMembers") == "" {
		t.Errorf("maxMembers missing: %v", q)
	}
	_, err = run(t, c, call("contacts.get_group", map[string]any{"group": "friends/x"}))
	wantClass(t, err, google.ClassInvalidArgument, 0)
	for _, tc := range readErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"GET " + groupsPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := run(t, c, call("contacts.list_groups", nil))
			checkReadError(t, tc, res, err)
		})
	}
}

func TestContactGroupWrites(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		"POST " + groupsPath:    {status: 200, body: "contact_group_created.json"},
		"GET " + friendsPath:    {status: 200, body: "contact_group.json"},
		"PUT " + friendsPath:    {status: 200, body: "contact_group_marked.json"},
		"DELETE " + friendsPath: {status: 200, body: "{}"},
		modifyMembersPath:       {status: 200, body: "modify_members_reply.json"},
	})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("contacts.create_group", map[string]any{"name": "Climbing"}))
	if err != nil {
		t.Fatal(err)
	}
	if ids := toolOf(t, c, "contacts.create_group").ResultIDs(res); ids["resource_name"] != "contactGroups/new1" {
		t.Errorf("ResultIDs = %v", ids)
	}
	grp := bodyOf(t, srv.Last(t, "POST "+groupsPath))["contactGroup"].(map[string]any)
	if grp["name"] != "Climbing" || grp["clientData"].([]any)[0].(map[string]any)["value"] != opID {
		t.Errorf("create body = %v", grp)
	}

	if _, err := run(t, c, write("contacts.update_group", map[string]any{"group": "contactGroups/friends", "name": "Pals"})); err != nil {
		t.Fatal(err)
	}
	b := bodyOf(t, srv.Last(t, "PUT "+friendsPath))
	grp = b["contactGroup"].(map[string]any)
	if grp["name"] != "Pals" || grp["etag"] != "%GROUPETAG" || len(grp["clientData"].([]any)) != 2 || !strings.Contains(b["updateGroupFields"].(string), "clientData") {
		t.Errorf("update body = %v", b)
	}

	if _, err := run(t, c, write("contacts.delete_group", map[string]any{"group": "contactGroups/friends", "delete_contacts": true})); err != nil {
		t.Fatal(err)
	}
	if q := query(t, srv, friendsPath); q.Get("deleteContacts") != "true" {
		t.Errorf("delete query = %v", q)
	}

	res, err = run(t, c, write("contacts.modify_group_members", map[string]any{"group": "contactGroups/friends", "add": []any{"people/c3", "people/c404"}, "remove": []any{"people/c2"}}))
	if err != nil {
		t.Fatal(err)
	}
	var mod struct {
		Group          string   `json:"group"`
		NotFound       []string `json:"not_found"`
		CouldNotRemove []string `json:"could_not_remove"`
	}
	decode(t, res, &mod)
	if mod.Group != "contactGroups/friends" || len(mod.NotFound) != 1 || len(mod.CouldNotRemove) != 1 {
		t.Errorf("modify = %+v", mod)
	}
	mb := bodyOf(t, srv.Last(t, modifyMembersPath))
	if len(mb["resourceNamesToAdd"].([]any)) != 2 || mb["resourceNamesToRemove"].([]any)[0] != "people/c2" {
		t.Errorf("modify body = %v", mb)
	}
	if !res.Partial {
		t.Error("a modify with names Google could not handle must be partial")
	}

	for _, tc := range []struct {
		tool string
		args map[string]any
	}{
		{"contacts.create_group", map[string]any{}},
		{"contacts.update_group", map[string]any{"group": "contactGroups/friends"}},
		{"contacts.update_group", map[string]any{"group": "groups/x", "name": "y"}},
		{"contacts.delete_group", map[string]any{}},
		{"contacts.modify_group_members", map[string]any{"group": "contactGroups/friends"}},
		{"contacts.modify_group_members", map[string]any{"group": "contactGroups/friends", "add": []any{"c3"}}},
		{"contacts.modify_group_members", map[string]any{"group": "contactGroups/friends", "add": manyPeople(101)}},
	} {
		_, err := run(t, c, write(tc.tool, tc.args))
		wantClass(t, err, google.ClassInvalidArgument, 0)
	}

	for name, tc := range map[string]struct {
		tool string
		args map[string]any
		rts  map[string]route
		want string
		id   string
	}{
		"create hit":    {"contacts.create_group", nil, map[string]route{"GET " + groupsPath: {status: 200, body: "contact_groups_marker_hit.json"}}, "found", "contactGroups/new1"},
		"create miss":   {"contacts.create_group", nil, map[string]route{"GET " + groupsPath: {status: 200, body: "contact_groups_marker_miss.json"}}, "not_found", ""},
		"update marked": {"contacts.update_group", map[string]any{"group": "contactGroups/friends"}, map[string]route{"GET " + friendsPath: {status: 200, body: "contact_group_marked.json"}}, "found", "contactGroups/friends"},
		"update not":    {"contacts.update_group", map[string]any{"group": "contactGroups/friends"}, map[string]route{"GET " + friendsPath: {status: 200, body: "contact_group.json"}}, "not_found", ""},
		"deleted":       {"contacts.delete_group", map[string]any{"group": "contactGroups/friends"}, map[string]route{"GET " + friendsPath: {status: 404, body: "error_not_found.json"}}, "found", "contactGroups/friends"},
		"not deleted":   {"contacts.delete_group", map[string]any{"group": "contactGroups/friends"}, map[string]route{"GET " + friendsPath: {status: 200, body: "contact_group.json"}}, "not_found", ""},
		"members in": {"contacts.modify_group_members", map[string]any{"group": "contactGroups/friends", "add": []any{"people/c3"}, "remove": []any{"people/c9"}},
			map[string]route{"GET " + friendsPath: {status: 200, body: "contact_group_members_added.json"}}, "found", "contactGroups/friends"},
		"members not": {"contacts.modify_group_members", map[string]any{"group": "contactGroups/friends", "add": []any{"people/c3"}},
			map[string]route{"GET " + friendsPath: {status: 200, body: "contact_group.json"}}, "not_found", ""},
		"removed still": {"contacts.modify_group_members", map[string]any{"group": "contactGroups/friends", "remove": []any{"people/c2"}},
			map[string]route{"GET " + friendsPath: {status: 200, body: "contact_group.json"}}, "not_found", ""},
		"group 500": {"contacts.modify_group_members", map[string]any{"group": "contactGroups/friends", "add": []any{"people/c3"}},
			map[string]route{"GET " + friendsPath: {status: 500, body: "error_server.json"}}, "cannot", ""},
	} {
		t.Run("check "+name, func(t *testing.T) {
			srv := newAPIServer(t, tc.rts)
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, tc.tool, tc.args)
			out, err := tool.Reconcile.Check(context.Background(), in)
			wantOutcome(t, out, err, tc.want, tc.id)
		})
	}
}

func manyPeople(n int) []any {
	out := make([]any, n)
	for i := range out {
		out[i] = "people/c" + strings.Repeat("1", i+1)
	}
	return out
}

func TestOtherContacts(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		otherContactsPath: {status: 200, body: "other_contacts.json"},
		otherSearchPath:   {status: 200, body: "other_contacts_search.json"},
		copyOtherPath:     {status: 200, body: "copied_contact.json"},
	})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("contacts.list_other_contacts", map[string]any{"max_results": 2}))
	if err != nil {
		t.Fatal(err)
	}
	var page struct {
		HasMore bool `json:"has_more"`
		Items   []struct {
			ResourceName string   `json:"resource_name"`
			Emails       []string `json:"emails"`
			Phones       []string `json:"phones"`
		} `json:"items"`
	}
	decode(t, res, &page)
	if !page.HasMore || len(page.Items) != 2 || page.Items[0].ResourceName != "otherContacts/c111" || len(page.Items[1].Phones) != 1 {
		t.Errorf("page = %+v", page)
	}
	if q := query(t, srv, "/v1/otherContacts"); q.Get("readMask") != "names,emailAddresses,phoneNumbers" || q.Get("pageSize") != "2" {
		t.Errorf("query = %v", q)
	}
	res, err = run(t, c, call("contacts.search_other_contacts", map[string]any{"query": "eve"}))
	if err != nil {
		t.Fatal(err)
	}
	decode(t, res, &page)
	if len(page.Items) != 1 || page.Items[0].Emails[0] != "eve@example.test" {
		t.Errorf("search = %+v", page)
	}
	if q := query(t, srv, "/v1/otherContacts:search"); q.Get("query") != "eve" || q.Get("readMask") == "" {
		t.Errorf("query = %v", q)
	}
	_, err = run(t, c, call("contacts.search_other_contacts", nil))
	wantClass(t, err, google.ClassInvalidArgument, 0)

	res, err = run(t, c, write("contacts.copy_other_contact", map[string]any{"resource_name": "otherContacts/c111"}))
	if err != nil {
		t.Fatal(err)
	}
	if ids := toolOf(t, c, "contacts.copy_other_contact").ResultIDs(res); ids["resource_name"] != "people/c777" {
		t.Errorf("ResultIDs = %v", ids)
	}
	if b := bodyOf(t, srv.Last(t, copyOtherPath)); b["copyMask"] != "names,emailAddresses,phoneNumbers" {
		t.Errorf("copy body = %v", b)
	}
	_, err = run(t, c, write("contacts.copy_other_contact", map[string]any{"resource_name": "people/c1"}))
	wantClass(t, err, google.ClassInvalidArgument, 0)
	for _, tc := range readErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{otherContactsPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := run(t, c, call("contacts.list_other_contacts", nil))
			checkReadError(t, tc, res, err)
		})
	}
}

func TestContactsFullWriteErrors(t *testing.T) {
	for _, w := range []struct {
		tool     string
		routes   func(rt route) map[string]route
		okBody   string
		args     map[string]any
		readFail bool
	}{
		{"contacts.create", func(rt route) map[string]route { return map[string]route{createContactPath: rt} }, "person_created.json", map[string]any{"given_name": "x"}, false},
		{"contacts.update", func(rt route) map[string]route {
			return map[string]route{"GET " + bobPath: {status: 200, body: "person_full.json"}, updateContactPath: rt}
		}, "person_marked.json", map[string]any{"resource_name": "people/c1234567890", "notes": "x"}, false},
		{"contacts.delete", func(rt route) map[string]route { return map[string]route{deleteContactPath: rt} }, "{}", map[string]any{"resource_name": "people/c1234567890"}, false},
		{"contacts.create_group", func(rt route) map[string]route { return map[string]route{"POST " + groupsPath: rt} }, "contact_group_created.json", map[string]any{"name": "x"}, false},
		{"contacts.update_group", func(rt route) map[string]route {
			return map[string]route{"GET " + friendsPath: {status: 200, body: "contact_group.json"}, "PUT " + friendsPath: rt}
		}, "contact_group_marked.json", map[string]any{"group": "contactGroups/friends", "name": "x"}, false},
		{"contacts.delete_group", func(rt route) map[string]route { return map[string]route{"DELETE " + friendsPath: rt} }, "{}", map[string]any{"group": "contactGroups/friends"}, false},
		{"contacts.modify_group_members", func(rt route) map[string]route { return map[string]route{modifyMembersPath: rt} }, "{}", map[string]any{"group": "contactGroups/friends", "add": []any{"people/c3"}}, false},
		{"contacts.copy_other_contact", func(rt route) map[string]route { return map[string]route{copyOtherPath: rt} }, "copied_contact.json", map[string]any{"resource_name": "otherContacts/c111"}, false},
	} {
		for _, tc := range writeErrorCases(w.okBody) {
			t.Run(w.tool+" "+tc.name, func(t *testing.T) {
				srv := newAPIServer(t, w.routes(tc.rt))
				res, err := run(t, shortTimeout(t, srv), write(w.tool, w.args))
				checkWriteError(t, tc, res, err)
			})
		}
	}
	// The lookup before update is a read: its failure is a known outcome.
	srv := newAPIServer(t, map[string]route{"GET " + bobPath: {status: 500, body: "error_server.json"}})
	_, err := run(t, shortTimeout(t, srv), write("contacts.update", map[string]any{"resource_name": "people/c1234567890", "notes": "x"}))
	if err == nil || srv.Count(updateContactPath) != 0 {
		t.Fatalf("err = %v, update sent %d times", err, srv.Count(updateContactPath))
	}
}
