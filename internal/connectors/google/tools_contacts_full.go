package google

import (
	"context"
	"fmt"
	"net/mail"
	"regexp"
	"slices"
	"strings"
	"time"

	"google.golang.org/api/people/v1"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Increment 5 (Brain decision 9jfy0gb8): the rest of what the People API
// lets an account do with its own contacts: create, update and delete
// contacts, contact groups (labels) and their members, and "other
// contacts" (people the account interacted with but never saved), which
// can be copied into the contacts. Every new write defaults to Ask
// (migration 00037).

// Contacts tool names (increment 5).
const (
	ToolListContactGroups      = "list_groups"
	ToolGetContactGroup        = "get_group"
	ToolListOtherContacts      = "list_other_contacts"
	ToolSearchOtherContacts    = "search_other_contacts"
	ToolCreateContact          = "create"
	ToolUpdateContact          = "update"
	ToolDeleteContact          = "delete"
	ToolCreateContactGroup     = "create_group"
	ToolUpdateContactGroup     = "update_group"
	ToolDeleteContactGroup     = "delete_group"
	ToolModifyContactGroup     = "modify_group_members"
	ToolCopyOtherContact       = "copy_other_contact"
	otherContactsReadMask      = "names,emailAddresses,phoneNumbers"
	contactMarkerScanPageSize  = 1000
	defaultGroupMembersPerRead = 200
)

// ContactMarkerKey is the clientData key the contact and group writes set
// to the operation id. clientData is arbitrary data People API clients
// attach to a contact or group; Google Contacts does not show it.
const ContactMarkerKey = "mcp-gateway-op"

// Bounds of the contact writes.
const (
	// MaxGroupMembersPerCall bounds the people added plus removed by one
	// modify_group_members (the API takes 1000; the identity lists them).
	MaxGroupMembersPerCall = 100
	// MaxGroupMembersRead is the most member names get_group and the
	// membership check read.
	MaxGroupMembersRead = 1000
	// MaxContactValues bounds each list field of a contact write.
	MaxContactValues = 20
)

var (
	contactGroupRE = regexp.MustCompile(`^contactGroups/[A-Za-z0-9_-]+$`)
	otherContactRE = regexp.MustCompile(`^otherContacts/[A-Za-z0-9_-]+$`)
	birthdayRE     = regexp.MustCompile(`^(\d{4}|-)-(\d{2})-(\d{2})$`)
)

// --- result types -----------------------------------------------------------------

// ContactGroup is one list_groups item; Members is filled by get_group.
type ContactGroup struct {
	ResourceName string   `json:"resource_name"`
	Name         string   `json:"name"`
	GroupType    string   `json:"group_type,omitempty"`
	MemberCount  int64    `json:"member_count"`
	Members      []string `json:"members,omitempty"`
	Truncated    bool     `json:"truncated,omitempty"`
}

// ContactGroupsPage is list_groups's result.
type ContactGroupsPage struct {
	MaxResults    int            `json:"max_results"`
	Total         int64          `json:"total,omitempty"`
	NextPageToken string         `json:"next_page_token,omitempty"`
	HasMore       bool           `json:"has_more"`
	Truncated     bool           `json:"truncated,omitempty"`
	Items         []ContactGroup `json:"items"`
}

// OtherContactsPage is the result of the other-contacts reads.
type OtherContactsPage struct {
	MaxResults    int             `json:"max_results"`
	Total         int64           `json:"total,omitempty"`
	NextPageToken string          `json:"next_page_token,omitempty"`
	HasMore       bool            `json:"has_more"`
	Truncated     bool            `json:"truncated,omitempty"`
	Items         []ContactDetail `json:"items"`
}

// ContactChange is the result of the contact writes.
type ContactChange struct {
	ResourceName string `json:"resource_name"`
	Deleted      bool   `json:"deleted,omitempty"`
}

// ContactGroupChange is the result of the group writes.
type ContactGroupChange struct {
	Group          string   `json:"group"`
	Deleted        bool     `json:"deleted,omitempty"`
	NotFound       []string `json:"not_found,omitempty"`
	CouldNotRemove []string `json:"could_not_remove,omitempty"`
}

func contactChangeResultIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(ContactChange)
	if !ok || v.ResourceName == "" {
		return nil
	}
	return map[string]string{"resource_name": v.ResourceName}
}

func contactGroupChangeResultIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(ContactGroupChange)
	if !ok || v.Group == "" {
		return nil
	}
	return map[string]string{"resource_name": v.Group}
}

// --- declarations ---------------------------------------------------------------------

var (
	contactFieldProperties = []property{
		{"given_name", "string", "First name.", nil},
		{"family_name", "string", "Last name.", nil},
		{"emails", "array", "Email addresses (replace the contact's list on update).", nil},
		{"phones", "array", "Phone numbers (replace the list on update).", nil},
		{"organization", "string", "Company or organization.", nil},
		{"title", "string", "Job title.", nil},
		{"notes", "string", "Notes about the contact (empty clears them on update).", nil},
		{"addresses", "array", "Postal addresses, each as one line of free text (replace the list on update).", nil},
		{"birthday", "string", "Birthday, YYYY-MM-DD, or --MM-DD without a year (empty clears it on update).", nil},
		{"urls", "array", "Web sites, http(s) URLs (replace the list on update).", nil},
	}
	resourceNameProperty = property{"resource_name", "string", "The contact's resource name, people/<id> (from contacts.search, list or get).", nil}
	groupProperty        = property{"group", "string", "The group's resource name, contactGroups/<id> (from list_groups).", nil}
)

func resourceNameIdentity(args map[string]any) map[string]string {
	out := map[string]string{}
	if v, _ := args["resource_name"].(string); strings.TrimSpace(v) != "" {
		out["resource_name"] = strings.TrimSpace(v)
	}
	return out
}

func groupIdentity(args map[string]any) map[string]string {
	out := map[string]string{}
	if v, _ := args["group"].(string); strings.TrimSpace(v) != "" {
		out["group"] = strings.TrimSpace(v)
	}
	return out
}

// modifyMembersIdentity is groupIdentity plus add_members and
// remove_members (sorted, comma-separated resource names: ids).
func modifyMembersIdentity(args map[string]any) map[string]string {
	out := groupIdentity(args)
	for arg, key := range map[string]string{"add": "add_members", "remove": "remove_members"} {
		list, _ := stringList(args, arg)
		var ids []string
		for _, id := range list {
			if resourceNameRE.MatchString(id) && !slices.Contains(ids, id) {
				ids = append(ids, id)
			}
		}
		if len(ids) > 0 {
			slices.Sort(ids)
			out[key] = strings.Join(ids, ",")
		}
	}
	return out
}

func (c *Connector) contactsFullReadTools() []connectors.Tool {
	return []connectors.Tool{
		{
			App: AppContacts, Name: ToolListContactGroups, Kind: connectors.KindRead,
			Description: "List the account's contact groups (labels): resource_name, name, group_type (USER_CONTACT_GROUP or " +
				"SYSTEM_CONTACT_GROUP such as My Contacts, Starred) and member_count. has_more and next_page_token say whether another page exists.",
			InputSchema: objectSchema([]property{
				{"max_results", "integer", "Groups per page (1-100; default 50); clamped to the tool's maximum.", nil},
				pageTokenProperty,
			}, nil),
			RequiredScopes:   []string{ScopeContactsReadonly},
			ResourceIdentity: func(map[string]any) map[string]string { return map[string]string{} },
			Bounds:           c.pagedBounds(),
		},
		{
			App: AppContacts, Name: ToolGetContactGroup, Kind: connectors.KindRead,
			Description: "Get one contact group with its members' resource names (people/<id>; contacts.get reads each). " +
				"max_members (default 200, at most 1000) bounds the members listed.",
			InputSchema: objectSchema([]property{
				groupProperty,
				{"max_members", "integer", "Members to list (1-1000; default 200).", nil},
			}, []string{"group"}),
			RequiredScopes:   []string{ScopeContactsReadonly},
			ResourceIdentity: groupIdentity,
			Bounds:           c.singleBounds(),
		},
		{
			App: AppContacts, Name: ToolListOtherContacts, Kind: connectors.KindRead,
			Description: "List the account's \"other contacts\": people it emailed or met but never saved (resource_name otherContacts/<id>, " +
				"name, emails, phones). copy_other_contact saves one into the contacts.",
			InputSchema: objectSchema([]property{
				{"max_results", "integer", "Contacts per page (1-100; default 50); clamped to the tool's maximum.", nil},
				pageTokenProperty,
			}, nil),
			RequiredScopes:   []string{ScopeContactsOtherReadonly},
			ResourceIdentity: func(map[string]any) map[string]string { return map[string]string{} },
			Bounds:           c.pagedBounds(),
		},
		{
			App: AppContacts, Name: ToolSearchOtherContacts, Kind: connectors.KindRead,
			Description: "Search the account's \"other contacts\" by a name, email or phone prefix (one page of at most 30). " +
				"Like contacts.search, Google's index can be cold the first time: search again a moment later.",
			InputSchema: objectSchema([]property{
				{"query", "string", "Plain-text prefix query.", nil},
				{"max_results", "integer", "Hits to return (1-30; default 10).", nil},
			}, []string{"query"}),
			RequiredScopes:   []string{ScopeContactsOtherReadonly},
			ResourceIdentity: func(map[string]any) map[string]string { return map[string]string{} },
			Bounds:           connectors.Bounds{MaxPageSize: min(c.bounds.MaxPageSize, MaxContactsPerSearch), MaxResultBytes: c.bounds.MaxResultBytes},
		},
	}
}

func (c *Connector) contactsFullReadHandlers() map[string]handler {
	return map[string]handler{
		ToolListContactGroups: c.listContactGroups, ToolGetContactGroup: c.getContactGroup,
		ToolListOtherContacts: c.listOtherContacts, ToolSearchOtherContacts: c.searchOtherContacts,
	}
}

func (c *Connector) contactsFullWriteTools() []connectors.Tool {
	tool := func(name, description string, props []property, required []string, scope string, identity func(map[string]any) map[string]string,
		rec connectors.Reconciliation, ids func(connectors.Result) map[string]string) connectors.Tool {
		return connectors.Tool{
			App: AppContacts, Name: name, Kind: connectors.KindWrite, Description: description,
			InputSchema: objectSchema(props, required), RequiredScopes: []string{scope}, ResourceIdentity: identity,
			Reconcile: rec, ResultIDs: ids, Bounds: c.singleBounds(),
		}
	}
	emptyIdentity := func(map[string]any) map[string]string { return map[string]string{} }
	marker := func(check func(context.Context, connectors.ReconcileInput) (connectors.ReconcileResult, error)) connectors.Reconciliation {
		return connectors.Reconciliation{Kind: connectors.ReconcileMarker, Check: check}
	}
	stable := func(check func(context.Context, connectors.ReconcileInput) (connectors.ReconcileResult, error)) connectors.Reconciliation {
		return connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: check}
	}
	return []connectors.Tool{
		tool(ToolCreateContact,
			"Create a Google contact: at least a name, an email, a phone or an organization; optionally title, notes, addresses, "+
				"birthday and urls. Returns its resource_name.",
			contactFieldProperties, nil, ScopeContacts, emptyIdentity, marker(c.checkContactCreated), contactChangeResultIDs),
		tool(ToolUpdateContact,
			"Change a Google contact: only the fields given change; list fields (emails, phones, addresses, urls) replace the "+
				"contact's list, an empty list removes them. Returns its resource_name.",
			append([]property{resourceNameProperty}, contactFieldProperties...), []string{"resource_name"}, ScopeContacts,
			resourceNameIdentity, marker(c.checkContactUpdated), contactChangeResultIDs),
		tool(ToolDeleteContact, "Delete a Google contact.",
			[]property{resourceNameProperty}, []string{"resource_name"}, ScopeContacts, resourceNameIdentity,
			stable(c.checkContactDeleted), contactChangeResultIDs),
		tool(ToolCreateContactGroup, "Create a contact group (label) with a name. Returns its resource_name.",
			[]property{{"name", "string", "The group's name.", nil}}, []string{"name"}, ScopeContacts, emptyIdentity,
			marker(c.checkGroupCreated), contactGroupChangeResultIDs),
		tool(ToolUpdateContactGroup, "Rename a contact group (system groups such as My Contacts cannot be renamed).",
			[]property{groupProperty, {"name", "string", "The new name.", nil}}, []string{"group", "name"}, ScopeContacts, groupIdentity,
			marker(c.checkGroupUpdated), contactGroupChangeResultIDs),
		tool(ToolDeleteContactGroup,
			"Delete a contact group (label). Its contacts stay unless delete_contacts is true (then they are deleted too). "+
				"System groups cannot be deleted.",
			[]property{groupProperty, {"delete_contacts", "boolean", "Also delete the group's contacts. Default false.", nil}},
			[]string{"group"}, ScopeContacts, groupIdentity, stable(c.checkGroupDeleted), contactGroupChangeResultIDs),
		tool(ToolModifyContactGroup,
			"Add contacts to and remove contacts from a contact group (resource names people/<id>; at most 100 in all). "+
				"contactGroups/starred stars them. not_found lists names Google did not find; could_not_remove those that would lose their last group.",
			[]property{
				groupProperty,
				{"add", "array", "Contacts to add (people/<id>).", nil},
				{"remove", "array", "Contacts to remove (people/<id>).", nil},
			}, []string{"group"}, ScopeContacts, modifyMembersIdentity, stable(c.checkGroupMembers), contactGroupChangeResultIDs),
		tool(ToolCopyOtherContact,
			"Save an \"other contact\" (otherContacts/<id> from list_other_contacts) into the account's contacts (My Contacts): "+
				"its names, emails and phones. Returns the new contact's resource_name. Cannot be verified after an unknown outcome: "+
				"check contacts.search before retrying.",
			[]property{{"resource_name", "string", "The other contact's resource name, otherContacts/<id>.", nil}}, []string{"resource_name"},
			ScopeContactsOtherReadonly, resourceNameIdentity, connectors.Reconciliation{Kind: connectors.ReconcileNone}, contactChangeResultIDs),
	}
}

func (c *Connector) contactsFullWriteHandlers() map[string]handler {
	return map[string]handler{
		ToolCreateContact: c.createContact, ToolUpdateContact: c.updateContact, ToolDeleteContact: c.deleteContact,
		ToolCreateContactGroup: c.createContactGroup, ToolUpdateContactGroup: c.updateContactGroup, ToolDeleteContactGroup: c.deleteContactGroup,
		ToolModifyContactGroup: c.modifyContactGroup, ToolCopyOtherContact: c.copyOtherContact,
	}
}

// --- arguments --------------------------------------------------------------------------

// contactArg reads a people/<id> resource name.
func contactArg(args map[string]any) (string, error) {
	name, err := requiredString(args, "resource_name")
	if err != nil {
		return "", err
	}
	if !resourceNameRE.MatchString(name) {
		return "", invalid("resource_name must look like people/c1234567890")
	}
	return name, nil
}

// groupArg reads a contactGroups/<id> resource name.
func groupArg(args map[string]any) (string, error) {
	name, err := requiredString(args, "group")
	if err != nil {
		return "", err
	}
	if !contactGroupRE.MatchString(name) {
		return "", invalid("group must look like contactGroups/<id> (from list_groups)")
	}
	return name, nil
}

// contactList reads a list field of a contact write (bounded) and checks
// each value with ok.
func contactList(args map[string]any, name string, ok func(string) bool, what string) ([]string, bool, error) {
	if v, given := args[name]; !given || v == nil {
		return nil, false, nil
	}
	list, err := stringList(args, name)
	if err != nil {
		return nil, true, err
	}
	if len(list) > MaxContactValues {
		return nil, true, invalid("%s has %d values; at most %d", name, len(list), MaxContactValues)
	}
	for _, v := range list {
		if ok != nil && !ok(v) {
			return nil, true, invalid("%s must be %s (%q is not)", name, what, v)
		}
	}
	return list, true, nil
}

func isEmailAddress(v string) bool {
	a, err := mail.ParseAddress(v)
	return err == nil && a.Address == v && domainOf(v) != ""
}

func isWebURL(v string) bool {
	return strings.HasPrefix(v, "https://") || strings.HasPrefix(v, "http://")
}

// parseBirthday reads YYYY-MM-DD or --MM-DD.
func parseBirthday(v string) (*people.Date, error) {
	m := birthdayRE.FindStringSubmatch(v)
	if m == nil {
		return nil, invalid("birthday must be YYYY-MM-DD or --MM-DD")
	}
	year := 2000 // a leap year validates 02-29 without a year
	if m[1] != "-" {
		fmt.Sscanf(m[1], "%d", &year) //nolint:errcheck // four digits by the pattern
	}
	t, err := time.Parse("2006-01-02", fmt.Sprintf("%04d-%s-%s", year, m[2], m[3]))
	if err != nil {
		return nil, invalid("birthday must be a real date (YYYY-MM-DD or --MM-DD)")
	}
	d := &people.Date{Month: int64(t.Month()), Day: int64(t.Day())}
	if m[1] != "-" {
		d.Year = int64(t.Year())
	}
	return d, nil
}

// contactFields applies the contact arguments to p (merging names and
// organization parts with current, the contact read before an update)
// and returns the People field names that change.
func contactFields(args map[string]any, p, current *people.Person) ([]string, error) {
	var fields []string
	str := func(name string) (string, bool, error) {
		v, ok := args[name]
		if !ok || v == nil {
			return "", false, nil
		}
		s, err := optionalString(args, name)
		return strings.TrimSpace(s), true, err
	}
	given, hasGiven, err := str("given_name")
	if err != nil {
		return nil, err
	}
	family, hasFamily, err := str("family_name")
	if err != nil {
		return nil, err
	}
	if hasGiven || hasFamily {
		n := &people.Name{GivenName: given, FamilyName: family}
		if current != nil && len(current.Names) > 0 && current.Names[0] != nil {
			if !hasGiven {
				n.GivenName = current.Names[0].GivenName
			}
			if !hasFamily {
				n.FamilyName = current.Names[0].FamilyName
			}
		}
		p.Names, fields = []*people.Name{n}, append(fields, "names")
	}
	org, hasOrg, err := str("organization")
	if err != nil {
		return nil, err
	}
	title, hasTitle, err := str("title")
	if err != nil {
		return nil, err
	}
	if hasOrg || hasTitle {
		o := &people.Organization{Name: org, Title: title}
		if current != nil && len(current.Organizations) > 0 && current.Organizations[0] != nil {
			if !hasOrg {
				o.Name = current.Organizations[0].Name
			}
			if !hasTitle {
				o.Title = current.Organizations[0].Title
			}
		}
		p.Organizations, fields = []*people.Organization{o}, append(fields, "organizations")
	}
	emails, hasEmails, err := contactList(args, "emails", isEmailAddress, "email addresses")
	if err != nil {
		return nil, err
	}
	if hasEmails {
		for _, e := range emails {
			p.EmailAddresses = append(p.EmailAddresses, &people.EmailAddress{Value: e})
		}
		fields = append(fields, "emailAddresses")
	}
	phones, hasPhones, err := contactList(args, "phones", nil, "")
	if err != nil {
		return nil, err
	}
	if hasPhones {
		for _, ph := range phones {
			p.PhoneNumbers = append(p.PhoneNumbers, &people.PhoneNumber{Value: ph})
		}
		fields = append(fields, "phoneNumbers")
	}
	addresses, hasAddresses, err := contactList(args, "addresses", nil, "")
	if err != nil {
		return nil, err
	}
	if hasAddresses {
		for _, a := range addresses {
			p.Addresses = append(p.Addresses, &people.Address{FormattedValue: a})
		}
		fields = append(fields, "addresses")
	}
	urls, hasURLs, err := contactList(args, "urls", isWebURL, "http(s) URLs")
	if err != nil {
		return nil, err
	}
	if hasURLs {
		for _, u := range urls {
			p.Urls = append(p.Urls, &people.Url{Value: u})
		}
		fields = append(fields, "urls")
	}
	if v, ok := args["notes"]; ok && v != nil {
		notes, err := optionalString(args, "notes")
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(notes) != "" {
			p.Biographies = []*people.Biography{{Value: notes, ContentType: "TEXT_PLAIN"}}
		}
		fields = append(fields, "biographies")
	}
	if birthday, has, err := str("birthday"); err != nil {
		return nil, err
	} else if has {
		if birthday != "" {
			d, err := parseBirthday(birthday)
			if err != nil {
				return nil, err
			}
			p.Birthdays = []*people.Birthday{{Date: d}}
		}
		fields = append(fields, "birthdays")
	}
	return fields, nil
}

// withContactMarker returns client data with the operation's marker set
// (replacing an earlier marker, keeping every other entry).
func withContactMarker(current []*people.ClientData, operationID string) []*people.ClientData {
	out := []*people.ClientData{}
	for _, d := range current {
		if d != nil && d.Key != ContactMarkerKey {
			out = append(out, &people.ClientData{Key: d.Key, Value: d.Value})
		}
	}
	return append(out, &people.ClientData{Key: ContactMarkerKey, Value: operationID})
}

func withGroupMarker(current []*people.GroupClientData, operationID string) []*people.GroupClientData {
	out := []*people.GroupClientData{}
	for _, d := range current {
		if d != nil && d.Key != ContactMarkerKey {
			out = append(out, &people.GroupClientData{Key: d.Key, Value: d.Value})
		}
	}
	return append(out, &people.GroupClientData{Key: ContactMarkerKey, Value: operationID})
}

func contactMarker(data []*people.ClientData) string {
	for _, d := range data {
		if d != nil && d.Key == ContactMarkerKey {
			return d.Value
		}
	}
	return ""
}

func groupMarker(data []*people.GroupClientData) string {
	for _, d := range data {
		if d != nil && d.Key == ContactMarkerKey {
			return d.Value
		}
	}
	return ""
}

// --- reads ---------------------------------------------------------------------------------

func toContactGroup(g *people.ContactGroup) ContactGroup {
	name := g.FormattedName
	if name == "" {
		name = g.Name
	}
	return ContactGroup{ResourceName: g.ResourceName, Name: name, GroupType: g.GroupType, MemberCount: g.MemberCount}
}

func (c *Connector) listContactGroups(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	maxResults, pageToken, clamped, err := c.pageArgs(call.Args, connectors.DefaultMaxPageSize)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.people(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	req := svc.ContactGroups.List().Context(ctx).PageSize(int64(maxResults)).GroupFields("name,groupType,memberCount")
	if pageToken != "" {
		req = req.PageToken(pageToken)
	}
	resp, err := req.Do()
	if err := classify("list contact groups", err); err != nil {
		return connectors.Result{}, err
	}
	out := ContactGroupsPage{MaxResults: maxResults, Total: resp.TotalItems, NextPageToken: resp.NextPageToken, HasMore: resp.NextPageToken != "",
		Items: make([]ContactGroup, 0, len(resp.ContactGroups))}
	for _, g := range resp.ContactGroups {
		if g != nil {
			out.Items = append(out.Items, toContactGroup(g))
		}
	}
	res := connectors.Result{Partial: clamped, Empty: len(out.Items) == 0}
	for encodedSize(out) > c.bounds.MaxResultBytes && len(out.Items) > 1 {
		out.Items = out.Items[:len(out.Items)-1]
		out.Truncated, res.Partial = true, true
	}
	res.Content = out
	return res, nil
}

func (c *Connector) getContactGroup(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	group, err := groupArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	maxMembers := defaultGroupMembersPerRead
	if v, ok := call.Args["max_members"]; ok && v != nil {
		if maxMembers, err = toInt(v); err != nil || maxMembers < 1 || maxMembers > MaxGroupMembersRead {
			return connectors.Result{}, invalid("max_members must be an integer from 1 to %d", MaxGroupMembersRead)
		}
	}
	svc, err := cl.people(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	g, err := svc.ContactGroups.Get(group).Context(ctx).MaxMembers(int64(maxMembers)).GroupFields("name,groupType,memberCount").Do()
	if err := classify("get contact group", err); err != nil {
		return connectors.Result{}, err
	}
	out := toContactGroup(g)
	out.Members = append([]string{}, g.MemberResourceNames...)
	res := connectors.Result{Partial: g.MemberCount > int64(len(out.Members))}
	for encodedSize(out) > c.bounds.MaxResultBytes && len(out.Members) > 0 {
		out.Members = out.Members[:len(out.Members)-1]
		out.Truncated, res.Partial = true, true
	}
	res.Content = out
	return res, nil
}

func (c *Connector) otherContactsPage(out OtherContactsPage, list []*people.Person, clamped bool) connectors.Result {
	for _, p := range list {
		if p != nil {
			out.Items = append(out.Items, toContactDetail(p))
		}
	}
	res := connectors.Result{Partial: clamped, Empty: len(out.Items) == 0}
	for encodedSize(out) > c.bounds.MaxResultBytes && len(out.Items) > 1 {
		out.Items = out.Items[:len(out.Items)-1]
		out.Truncated, res.Partial = true, true
	}
	res.Content = out
	return res
}

func (c *Connector) listOtherContacts(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	maxResults, pageToken, clamped, err := c.pageArgs(call.Args, connectors.DefaultMaxPageSize)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.people(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	req := svc.OtherContacts.List().Context(ctx).ReadMask(otherContactsReadMask).PageSize(int64(maxResults))
	if pageToken != "" {
		req = req.PageToken(pageToken)
	}
	resp, err := req.Do()
	if err := classify("list other contacts", err); err != nil {
		return connectors.Result{}, err
	}
	out := OtherContactsPage{MaxResults: maxResults, Total: resp.TotalSize, NextPageToken: resp.NextPageToken, HasMore: resp.NextPageToken != "",
		Items: make([]ContactDetail, 0, len(resp.OtherContacts))}
	return c.otherContactsPage(out, resp.OtherContacts, clamped), nil
}

func (c *Connector) searchOtherContacts(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	q, err := requiredString(call.Args, "query")
	if err != nil {
		return connectors.Result{}, err
	}
	ceiling := min(c.bounds.MaxPageSize, MaxContactsPerSearch)
	maxResults, clamped := min(defaultContactsPerSearch, ceiling), false
	if v, ok := call.Args["max_results"]; ok && v != nil {
		if maxResults, err = toInt(v); err != nil || maxResults < 1 {
			return connectors.Result{}, invalid("max_results must be a positive integer")
		}
		if maxResults > ceiling {
			maxResults, clamped = ceiling, true
		}
	}
	svc, err := cl.people(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	resp, err := svc.OtherContacts.Search().Context(ctx).Query(q).ReadMask(otherContactsReadMask).PageSize(int64(maxResults)).Do()
	if err := classify("search other contacts", err); err != nil {
		return connectors.Result{}, err
	}
	list := make([]*people.Person, 0, len(resp.Results))
	for _, r := range resp.Results {
		if r != nil && r.Person != nil {
			list = append(list, r.Person)
		}
	}
	return c.otherContactsPage(OtherContactsPage{MaxResults: maxResults, Items: make([]ContactDetail, 0, len(list))}, list, clamped), nil
}

// --- writes -------------------------------------------------------------------------------------

func (c *Connector) createContact(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	p := &people.Person{}
	if _, err := contactFields(call.Args, p, nil); err != nil {
		return connectors.Result{}, err
	}
	if len(p.Names) == 0 && len(p.EmailAddresses) == 0 && len(p.PhoneNumbers) == 0 && len(p.Organizations) == 0 {
		return connectors.Result{}, invalid("give at least a name (given_name, family_name), emails, phones or organization")
	}
	p.ClientData = withContactMarker(nil, call.OperationID)
	svc, err := cl.people(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	created, err := svc.People.CreateContact(p).Context(ctx).PersonFields("names").Do()
	if err := classifyWrite("create contact", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: ContactChange{ResourceName: created.ResourceName}}, nil
}

// updateContact reads the contact (a read: its failure is a known
// outcome) for its etag, the name and organization parts kept and its
// client data, then updates the fields given plus the operation's marker.
func (c *Connector) updateContact(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	name, err := contactArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	probe, err := contactFields(call.Args, &people.Person{}, nil) // validates before the token
	if err != nil {
		return connectors.Result{}, err
	}
	if len(probe) == 0 {
		return connectors.Result{}, invalid("nothing to change: give at least one of " +
			"given_name, family_name, emails, phones, organization, title, notes, addresses, birthday or urls")
	}
	svc, err := cl.people(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	current, err := svc.People.Get(name).Context(ctx).PersonFields("names,organizations,clientData").Do()
	if err := classify("look up the contact", err); err != nil {
		return connectors.Result{}, err
	}
	p := &people.Person{Etag: current.Etag}
	fields, err := contactFields(call.Args, p, current)
	if err != nil {
		return connectors.Result{}, err
	}
	p.ClientData = withContactMarker(current.ClientData, call.OperationID)
	fields = append(fields, "clientData")
	updated, err := svc.People.UpdateContact(name, p).Context(ctx).UpdatePersonFields(strings.Join(fields, ",")).PersonFields("names").Do()
	if err := classifyWrite("update contact", err); err != nil {
		return connectors.Result{}, err
	}
	out := ContactChange{ResourceName: updated.ResourceName}
	if out.ResourceName == "" {
		out.ResourceName = name
	}
	return connectors.Result{Content: out}, nil
}

func (c *Connector) deleteContact(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	name, err := contactArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.people(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	_, err = svc.People.DeleteContact(name).Context(ctx).Do()
	if err := classifyWrite("delete contact", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: ContactChange{ResourceName: name, Deleted: true}}, nil
}

func (c *Connector) createContactGroup(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	name, err := requiredString(call.Args, "name")
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.people(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	g, err := svc.ContactGroups.Create(&people.CreateContactGroupRequest{ContactGroup: &people.ContactGroup{
		Name: name, ClientData: withGroupMarker(nil, call.OperationID),
	}}).Context(ctx).Do()
	if err := classifyWrite("create contact group", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: ContactGroupChange{Group: g.ResourceName}}, nil
}

func (c *Connector) updateContactGroup(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	group, err := groupArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	name, err := requiredString(call.Args, "name")
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.people(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	current, err := svc.ContactGroups.Get(group).Context(ctx).MaxMembers(0).GroupFields("name,clientData").Do()
	if err := classify("look up the contact group", err); err != nil {
		return connectors.Result{}, err
	}
	g, err := svc.ContactGroups.Update(group, &people.UpdateContactGroupRequest{
		ContactGroup:      &people.ContactGroup{Etag: current.Etag, Name: name, ClientData: withGroupMarker(current.ClientData, call.OperationID)},
		UpdateGroupFields: "name,clientData",
	}).Context(ctx).Do()
	if err := classifyWrite("rename contact group", err); err != nil {
		return connectors.Result{}, err
	}
	out := ContactGroupChange{Group: g.ResourceName}
	if out.Group == "" {
		out.Group = group
	}
	return connectors.Result{Content: out}, nil
}

func (c *Connector) deleteContactGroup(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	group, err := groupArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	deleteContacts, err := optionalBool(call.Args, "delete_contacts", false)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.people(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	_, err = svc.ContactGroups.Delete(group).Context(ctx).DeleteContacts(deleteContacts).Do()
	if err := classifyWrite("delete contact group", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: ContactGroupChange{Group: group, Deleted: true}}, nil
}

// memberList reads add or remove: people/<id> names.
func memberList(args map[string]any, name string) ([]string, error) {
	list, err := stringList(args, name)
	if err != nil {
		return nil, err
	}
	for _, id := range list {
		if !resourceNameRE.MatchString(id) {
			return nil, invalid("%s must be contact resource names people/<id> (%q is not)", name, id)
		}
	}
	return list, nil
}

func (c *Connector) modifyContactGroup(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	group, err := groupArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	add, err := memberList(call.Args, "add")
	if err != nil {
		return connectors.Result{}, err
	}
	remove, err := memberList(call.Args, "remove")
	if err != nil {
		return connectors.Result{}, err
	}
	if len(add)+len(remove) == 0 {
		return connectors.Result{}, invalid("give add or remove: the contacts to add to or remove from the group")
	}
	if len(add)+len(remove) > MaxGroupMembersPerCall {
		return connectors.Result{}, invalid("at most %d contacts per call (add and remove together)", MaxGroupMembersPerCall)
	}
	svc, err := cl.people(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	resp, err := svc.ContactGroups.Members.Modify(group, &people.ModifyContactGroupMembersRequest{
		ResourceNamesToAdd: add, ResourceNamesToRemove: remove,
	}).Context(ctx).Do()
	if err := classifyWrite("modify contact group members", err); err != nil {
		return connectors.Result{}, err
	}
	out := ContactGroupChange{Group: group, NotFound: resp.NotFoundResourceNames, CouldNotRemove: resp.CanNotRemoveLastContactGroupResourceNames}
	return connectors.Result{Content: out, Partial: len(out.NotFound)+len(out.CouldNotRemove) > 0}, nil
}

func (c *Connector) copyOtherContact(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	name, err := requiredString(call.Args, "resource_name")
	if err != nil {
		return connectors.Result{}, err
	}
	if !otherContactRE.MatchString(name) {
		return connectors.Result{}, invalid("resource_name must look like otherContacts/c1234567890 (from list_other_contacts)")
	}
	svc, err := cl.people(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	p, err := svc.OtherContacts.CopyOtherContactToMyContactsGroup(name, &people.CopyOtherContactToMyContactsGroupRequest{
		CopyMask: otherContactsReadMask,
	}).Context(ctx).Do()
	if err := classifyWrite("copy other contact", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: ContactChange{ResourceName: p.ResourceName}}, nil
}

// --- reconciliation -----------------------------------------------------------------------------

// checkContactCreated is create's marker check: the account's
// connections are listed with their client data (contactMarkerScanPageSize
// per page, at most MaxReconcilePages); the contact carrying the
// operation's marker is found; the end of the list without it is
// not_found; running out of pages or any error is "cannot tell yet".
func (c *Connector) checkContactCreated(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	tg, err := c.target(in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	svc, err := tg.client.people(ctx)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	pageToken := ""
	for page := 1; page <= MaxReconcilePages; page++ {
		req := svc.People.Connections.List("people/me").Context(ctx).PersonFields("clientData").PageSize(contactMarkerScanPageSize)
		if pageToken != "" {
			req = req.PageToken(pageToken)
		}
		resp, err := req.Do()
		if err := classify("reconcile: list contacts", err); err != nil {
			return connectors.ReconcileResult{}, err
		}
		for _, p := range resp.Connections {
			if p != nil && contactMarker(p.ClientData) == tg.operationID {
				return found(p.ResourceName), nil
			}
		}
		if pageToken = resp.NextPageToken; pageToken == "" {
			return notFound, nil
		}
	}
	return connectors.ReconcileResult{}, fmt.Errorf("google: reconcile: more than %d pages of contacts; cannot tell yet", MaxReconcilePages)
}

// identityName reads a resource name the identity holds under key.
func identityName(in connectors.ReconcileInput, key string, re *regexp.Regexp) (string, error) {
	name := strings.TrimSpace(in.ResourceIdentity[key])
	if !re.MatchString(name) {
		return "", fmt.Errorf("%w: resource identity has no %s", ErrNotReconcilable, key)
	}
	return name, nil
}

// checkContactUpdated: the contact's marker equal to the operation id is
// found; no marker is not_found; another operation's marker or the
// contact gone is "cannot tell".
func (c *Connector) checkContactUpdated(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	tg, err := c.target(in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	name, err := identityName(in, "resource_name", resourceNameRE)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	svc, err := tg.client.people(ctx)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	p, err := svc.People.Get(name).Context(ctx).PersonFields("clientData").Do()
	if err := classify("reconcile: get contact", err); err != nil {
		return connectors.ReconcileResult{}, err
	}
	switch contactMarker(p.ClientData) {
	case tg.operationID:
		return found(name), nil
	case "":
		return notFound, nil
	}
	return connectors.ReconcileResult{}, fmt.Errorf("google: reconcile: the contact carries another operation's marker; cannot tell")
}

func (c *Connector) checkContactDeleted(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	tg, err := c.target(in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	name, err := identityName(in, "resource_name", resourceNameRE)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	svc, err := tg.client.people(ctx)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	_, err = svc.People.Get(name).Context(ctx).PersonFields("names").Do()
	if err := classify("reconcile: get contact", err); err != nil {
		if isGone(err) {
			return found(name), nil
		}
		return connectors.ReconcileResult{}, err
	}
	return notFound, nil
}

// checkGroupCreated lists the groups with their client data (bounded) for
// the operation's marker.
func (c *Connector) checkGroupCreated(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	tg, err := c.target(in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	svc, err := tg.client.people(ctx)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	pageToken := ""
	for page := 1; page <= MaxReconcilePages; page++ {
		req := svc.ContactGroups.List().Context(ctx).GroupFields("clientData").PageSize(contactMarkerScanPageSize)
		if pageToken != "" {
			req = req.PageToken(pageToken)
		}
		resp, err := req.Do()
		if err := classify("reconcile: list contact groups", err); err != nil {
			return connectors.ReconcileResult{}, err
		}
		for _, g := range resp.ContactGroups {
			if g != nil && groupMarker(g.ClientData) == tg.operationID {
				return found(g.ResourceName), nil
			}
		}
		if pageToken = resp.NextPageToken; pageToken == "" {
			return notFound, nil
		}
	}
	return connectors.ReconcileResult{}, fmt.Errorf("google: reconcile: more than %d pages of contact groups; cannot tell yet", MaxReconcilePages)
}

// contactGroupTarget fetches the identity's group; gone is a 404/410.
func (c *Connector) contactGroupTarget(ctx context.Context, in connectors.ReconcileInput, fields string, maxMembers int64) (*people.ContactGroup, string, bool, string, error) {
	tg, err := c.target(in)
	if err != nil {
		return nil, "", false, "", err
	}
	group, err := identityName(in, "group", contactGroupRE)
	if err != nil {
		return nil, "", false, "", err
	}
	svc, err := tg.client.people(ctx)
	if err != nil {
		return nil, "", false, "", err
	}
	g, err := svc.ContactGroups.Get(group).Context(ctx).MaxMembers(maxMembers).GroupFields(fields).Do()
	if err := classify("reconcile: get contact group", err); err != nil {
		if isGone(err) {
			return nil, group, true, tg.operationID, nil
		}
		return nil, "", false, "", err
	}
	return g, group, false, tg.operationID, nil
}

func (c *Connector) checkGroupUpdated(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	g, group, gone, opID, err := c.contactGroupTarget(ctx, in, "clientData", 0)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	if gone {
		return connectors.ReconcileResult{}, fmt.Errorf("google: reconcile: the group is gone; cannot tell whether it was renamed")
	}
	switch groupMarker(g.ClientData) {
	case opID:
		return found(group), nil
	case "":
		return notFound, nil
	}
	return connectors.ReconcileResult{}, fmt.Errorf("google: reconcile: the group carries another operation's marker; cannot tell")
}

func (c *Connector) checkGroupDeleted(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	_, group, gone, _, err := c.contactGroupTarget(ctx, in, "name", 0)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	if gone {
		return found(group), nil
	}
	return notFound, nil
}

// checkGroupMembers: every added contact a member and no removed one is
// found; a removed one still listed, or an added one missing from the
// whole member list, is not_found; a group with more members than were
// read (MaxGroupMembersRead) cannot prove the rest ("cannot tell").
func (c *Connector) checkGroupMembers(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	g, group, gone, _, err := c.contactGroupTarget(ctx, in, "memberCount", MaxGroupMembersRead)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	if gone {
		return connectors.ReconcileResult{}, fmt.Errorf("google: reconcile: the group is gone; cannot tell")
	}
	split := func(key string) []string {
		if v := strings.TrimSpace(in.ResourceIdentity[key]); v != "" {
			return strings.Split(v, ",")
		}
		return nil
	}
	add, remove := split("add_members"), split("remove_members")
	complete := g.MemberCount <= int64(len(g.MemberResourceNames))
	for _, id := range remove {
		if slices.Contains(g.MemberResourceNames, id) {
			return notFound, nil
		}
	}
	for _, id := range add {
		if !slices.Contains(g.MemberResourceNames, id) && complete {
			return notFound, nil
		}
	}
	if !complete {
		return connectors.ReconcileResult{}, fmt.Errorf("google: reconcile: the group has more members than were read; cannot tell")
	}
	return found(group), nil
}
