package google

import (
	"context"

	"google.golang.org/api/people/v1"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Contacts tool names.
const ToolSearchContacts = "search"

// MaxContactsPerSearch is the People API's own ceiling for
// searchContacts (values above are capped to 30); defaultContactsPerSearch
// is the page when the harness gives none. searchContacts has no page
// token: one page per call.
const (
	MaxContactsPerSearch     = 30
	defaultContactsPerSearch = 10
)

// contactsReadMask is the fields searchContacts asks for: names,
// addresses and organizations, never phone numbers, photos or notes.
const contactsReadMask = "names,emailAddresses,organizations"

// Contact is one contacts.search item.
type Contact struct {
	ResourceName string   `json:"resource_name"`
	Name         string   `json:"name,omitempty"`
	GivenName    string   `json:"given_name,omitempty"`
	FamilyName   string   `json:"family_name,omitempty"`
	Emails       []string `json:"emails,omitempty"`
	Organization string   `json:"organization,omitempty"`
	Title        string   `json:"title,omitempty"`
}

// ContactsPage is search's result (a single page: the People API's
// contact search does not paginate).
type ContactsPage struct {
	MaxResults int       `json:"max_results"`
	Truncated  bool      `json:"truncated,omitempty"`
	Items      []Contact `json:"items"`
}

func toContact(p *people.Person) Contact {
	out := Contact{ResourceName: p.ResourceName}
	for _, n := range p.Names {
		if n == nil {
			continue
		}
		out.Name, out.GivenName, out.FamilyName = n.DisplayName, n.GivenName, n.FamilyName
		break
	}
	for _, e := range p.EmailAddresses {
		if e != nil && e.Value != "" {
			out.Emails = append(out.Emails, e.Value)
		}
	}
	for _, o := range p.Organizations {
		if o == nil {
			continue
		}
		out.Organization, out.Title = o.Name, o.Title
		break
	}
	return out
}

// contactsReadTools declares contacts.search.
func (c *Connector) contactsReadTools() []connectors.Tool {
	return []connectors.Tool{{
		App: AppContacts, Name: ToolSearchContacts, Kind: connectors.KindRead,
		Description: "Search the account's Google Contacts by a name, email address or organization prefix: each hit has resource_name, name, " +
			"emails, organization and title. One page of at most 30 hits; no further pages. Google's contact-search index can be cold " +
			"the first time after a while and answer nothing: search again a moment later.",
		InputSchema: objectSchema([]property{
			{"query", "string", "Plain-text prefix query (\"bob\", \"bob@\", \"example corp\").", nil},
			{"max_results", "integer", "Hits to return (1-30; default 10); clamped to the tool's maximum.", nil},
		}, []string{"query"}),
		RequiredScopes:   []string{ScopeContactsReadonly},
		ResourceIdentity: func(map[string]any) map[string]string { return map[string]string{} },
		Bounds:           connectors.Bounds{MaxPageSize: min(c.bounds.MaxPageSize, MaxContactsPerSearch), MaxResultBytes: c.bounds.MaxResultBytes},
	}}
}

func (c *Connector) contactsReadHandlers() map[string]handler {
	return map[string]handler{ToolSearchContacts: c.searchContacts}
}

func (c *Connector) contactsWriteTools() []connectors.Tool { return nil }

func (c *Connector) contactsWriteHandlers() map[string]handler { return map[string]handler{} }

// --- handlers -------------------------------------------------------------------

func (c *Connector) searchContacts(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
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
	resp, err := svc.People.SearchContacts().Context(ctx).Query(q).ReadMask(contactsReadMask).PageSize(int64(maxResults)).Do()
	if err := classify("search contacts", err); err != nil {
		return connectors.Result{}, err
	}
	out := ContactsPage{MaxResults: maxResults, Items: make([]Contact, 0, len(resp.Results))}
	for _, r := range resp.Results {
		if r != nil && r.Person != nil {
			out.Items = append(out.Items, toContact(r.Person))
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
