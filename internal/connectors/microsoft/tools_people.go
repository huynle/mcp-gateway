package microsoft

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/microsoft/graph"
)

// Contact and people lookups: the user's Outlook contacts, the people
// they work with (relevance-ranked), and the organization's directory.
const (
	ToolContactsSearch = "contacts_search"
	ToolPeopleSearch   = "people_search"
	ToolUsersSearch    = "users_search"
	contactSelect      = "id,displayName,givenName,surname,emailAddresses,companyName,jobTitle,mobilePhone,businessPhones"
	personSelect       = "id,displayName,scoredEmailAddresses,jobTitle,department,companyName,userPrincipalName"
	userSelect         = "id,displayName,givenName,surname,mail,userPrincipalName"
)

// Person is one contacts_search / people_search / users_search item.
type Person struct {
	ID                string   `json:"id"`
	DisplayName       string   `json:"display_name"`
	Emails            []string `json:"emails,omitempty"`
	Mail              string   `json:"mail,omitempty"`
	UserPrincipalName string   `json:"user_principal_name,omitempty"`
	JobTitle          string   `json:"job_title,omitempty"`
	Department        string   `json:"department,omitempty"`
	Company           string   `json:"company,omitempty"`
	Phones            []string `json:"phones,omitempty"`
}

type graphPerson struct {
	ID                   string              `json:"id"`
	DisplayName          string              `json:"displayName"`
	EmailAddresses       []graphEmailAddress `json:"emailAddresses"`
	ScoredEmailAddresses []graphEmailAddress `json:"scoredEmailAddresses"`
	Mail                 string              `json:"mail"`
	UserPrincipalName    string              `json:"userPrincipalName"`
	JobTitle             string              `json:"jobTitle"`
	Department           string              `json:"department"`
	CompanyName          string              `json:"companyName"`
	MobilePhone          string              `json:"mobilePhone"`
	BusinessPhones       []string            `json:"businessPhones"`
}

func toPerson(g graphPerson) Person {
	out := Person{ID: g.ID, DisplayName: g.DisplayName, Mail: g.Mail, UserPrincipalName: g.UserPrincipalName, JobTitle: g.JobTitle, Department: g.Department, Company: g.CompanyName}
	for _, e := range append(g.EmailAddresses, g.ScoredEmailAddresses...) {
		if e.Address != "" {
			out.Emails = append(out.Emails, e.Address)
		}
	}
	if g.MobilePhone != "" {
		out.Phones = append(out.Phones, g.MobilePhone)
	}
	out.Phones = append(out.Phones, g.BusinessPhones...)
	return out
}

func (c *Connector) peopleDefs() []toolDef {
	paged := connectors.Bounds{MaxPageSize: c.bounds.MaxPageSize, MaxResultBytes: c.bounds.MaxResultBytes}
	return []toolDef{
		{Tool: connectors.Tool{
			App: App, Name: ToolContactsSearch, Kind: connectors.KindRead,
			Description: "Search the user's Outlook contacts: q is the start of a name (display, given or surname) or an exact email " +
				"address; all contacts when omitted. Returns names, emails, company, job title, phones.",
			InputSchema:      objectSchema([]property{{"q", "string", "Name prefix or email address.", nil}, topProperty}, nil),
			RequiredScopes:   []string{ScopeContactsRead},
			ResourceIdentity: identity(),
			Bounds:           paged,
		}, run: c.contactsSearch},
		{Tool: connectors.Tool{
			App: App, Name: ToolPeopleSearch, Kind: connectors.KindRead,
			Description: "Find people the user works or communicates with, ranked by relevance (fuzzy name search with q; the most relevant " +
				"people when omitted). Returns names, emails, job title, department.",
			InputSchema:      objectSchema([]property{{"q", "string", "Name or alias to search for.", nil}, topProperty}, nil),
			RequiredScopes:   []string{ScopePeopleRead},
			ResourceIdentity: identity(),
			Bounds:           paged,
		}, run: c.peopleSearch},
		{Tool: connectors.Tool{
			App: App, Name: ToolUsersSearch, Kind: connectors.KindRead,
			Description: "Search the organization's directory for users whose name or email contains q: id, name, mail, user principal " +
				"name. Work accounts only (User.ReadBasic.All).",
			InputSchema:      objectSchema([]property{{"q", "string", "Name or email text.", nil}, topProperty}, []string{"q"}),
			RequiredScopes:   []string{ScopeUserReadBasicAll},
			ResourceIdentity: identity(),
			Bounds:           paged,
		}, run: c.usersSearch},
	}
}

// searchText reads q without quotes and backslashes (they cannot be
// escaped inside Graph's $search phrases).
func searchText(args map[string]any, required bool) (string, error) {
	q, err := optionalString(args, "q")
	if err != nil {
		return "", err
	}
	q = strings.TrimSpace(strings.NewReplacer(`"`, "", `\`, "").Replace(q))
	if len(q) > maxQueryLength {
		return "", invalid("q is too long")
	}
	if required && q == "" {
		return "", invalid("q is required")
	}
	return q, nil
}

func (c *Connector) contactsSearch(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	q, err := optionalString(call.Args, "q")
	if err != nil {
		return connectors.Result{}, err
	}
	if q = strings.TrimSpace(q); len(q) > maxQueryLength {
		return connectors.Result{}, invalid("q is too long")
	}
	top, clamped, err := c.topArg(call.Args, maxTop)
	if err != nil {
		return connectors.Result{}, err
	}
	query := url.Values{"$top": {strconv.Itoa(top)}, "$select": {contactSelect}}
	switch {
	case strings.Contains(q, "@"):
		query.Set("$filter", "emailAddresses/any(a:a/address eq "+graph.Quote(q)+")")
	case q != "":
		lit := graph.Quote(q)
		query.Set("$filter", "startswith(displayName,"+lit+") or startswith(givenName,"+lit+") or startswith(surname,"+lit+")")
	}
	return listRead(ctx, c, client, "search contacts", "me/contacts", query, nil, top, clamped, toPerson)
}

func (c *Connector) peopleSearch(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	q, err := searchText(call.Args, false)
	if err != nil {
		return connectors.Result{}, err
	}
	top, clamped, err := c.topArg(call.Args, maxTop)
	if err != nil {
		return connectors.Result{}, err
	}
	query := url.Values{"$top": {strconv.Itoa(top)}, "$select": {personSelect}}
	if q != "" {
		query.Set("$search", `"`+q+`"`)
	}
	return listRead(ctx, c, client, "search people", "me/people", query, nil, top, clamped, toPerson)
}

func (c *Connector) usersSearch(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	q, err := searchText(call.Args, true)
	if err != nil {
		return connectors.Result{}, err
	}
	top, clamped, err := c.topArg(call.Args, maxTop)
	if err != nil {
		return connectors.Result{}, err
	}
	query := url.Values{"$top": {strconv.Itoa(top)}, "$select": {userSelect}, "$search": {`"displayName:` + q + `" OR "mail:` + q + `"`}}
	return listRead(ctx, c, client, "search users", "users", query, http.Header{"ConsistencyLevel": {"eventual"}}, top, clamped, toPerson)
}
