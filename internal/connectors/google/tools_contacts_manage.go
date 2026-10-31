package google

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"google.golang.org/api/people/v1"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Contacts read tool names (next to search).
const (
	ToolGetContact   = "get"
	ToolListContacts = "list"
)

// contactGetFields is what contacts.get reads: search's fields plus phone
// numbers and, since increment 5 (contacts.update can change them),
// addresses, birthday, notes, URLs and group memberships; never photos.
const contactGetFields = "names,emailAddresses,organizations,phoneNumbers,addresses,birthdays,biographies,urls,memberships"

// resourceNameRE is the shape of a contact's resource name.
var resourceNameRE = regexp.MustCompile(`^people/[A-Za-z0-9_-]+$`)

// ContactDetail is contacts.get's result.
type ContactDetail struct {
	Contact
	Phones []string `json:"phones,omitempty"`
	// Increment 5: the rest of what contacts.update can change, plus the
	// contact's groups (contactGroups/<id>). Notes are cut to the bounds.
	Addresses []string `json:"addresses,omitempty"`
	Birthday  string   `json:"birthday,omitempty"`
	Notes     string   `json:"notes,omitempty"`
	URLs      []string `json:"urls,omitempty"`
	Groups    []string `json:"groups,omitempty"`
	Truncated bool     `json:"truncated,omitempty"`
}

// ContactsList is contacts.list's result.
type ContactsList struct {
	MaxResults    int       `json:"max_results"`
	Total         int64     `json:"total,omitempty"`
	NextPageToken string    `json:"next_page_token,omitempty"`
	HasMore       bool      `json:"has_more"`
	Truncated     bool      `json:"truncated,omitempty"`
	Items         []Contact `json:"items"`
}

func (c *Connector) contactsManageReadTools() []connectors.Tool {
	return []connectors.Tool{
		{
			App: AppContacts, Name: ToolGetContact, Kind: connectors.KindRead,
			Description: "Get one Google contact by resource_name (people/c..., from contacts.search or contacts.list): name, emails, " +
				"organization, title and phone numbers.",
			InputSchema: objectSchema([]property{
				{"resource_name", "string", "The contact's resource name, people/<id>.", nil},
			}, []string{"resource_name"}),
			RequiredScopes: []string{ScopeContactsReadonly},
			ResourceIdentity: func(args map[string]any) map[string]string {
				out := map[string]string{}
				if v, _ := args["resource_name"].(string); strings.TrimSpace(v) != "" {
					out["resource_name"] = strings.TrimSpace(v)
				}
				return out
			},
			Bounds: c.singleBounds(),
		},
		{
			App: AppContacts, Name: ToolListContacts, Kind: connectors.KindRead,
			Description: "List the account's Google contacts (names, emails, organization, title), in Google's order. " +
				"has_more and next_page_token say whether another page exists (pass page_token).",
			InputSchema: objectSchema([]property{
				{"max_results", "integer", "Contacts per page (1-100; default 50); clamped to the tool's maximum.", nil},
				{"page_token", "string", "Token of the page to fetch (next_page_token of the previous result).", nil},
			}, nil),
			RequiredScopes:   []string{ScopeContactsReadonly},
			ResourceIdentity: func(map[string]any) map[string]string { return map[string]string{} },
			Bounds:           c.pagedBounds(),
		},
	}
}

func (c *Connector) contactsManageReadHandlers() map[string]handler {
	return map[string]handler{ToolGetContact: c.getContact, ToolListContacts: c.listContacts}
}

func (c *Connector) getContact(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	name, err := requiredString(call.Args, "resource_name")
	if err != nil {
		return connectors.Result{}, err
	}
	if !resourceNameRE.MatchString(name) {
		return connectors.Result{}, invalid("resource_name must look like people/c1234567890")
	}
	svc, err := cl.people(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	p, err := svc.People.Get(name).Context(ctx).PersonFields(contactGetFields).Do()
	if err := classify("get contact", err); err != nil {
		return connectors.Result{}, err
	}
	out := toContactDetail(p)
	fitBody(&out.Notes, &out.Truncated, c.bounds.MaxResultBytes, func() any { return out })
	return connectors.Result{Content: out, Partial: out.Truncated}, nil
}

// toContactDetail is toContact plus the phone numbers.
func toContactDetail(p *people.Person) ContactDetail {
	out := ContactDetail{Contact: toContact(p)}
	for _, ph := range p.PhoneNumbers {
		if ph != nil && ph.Value != "" {
			out.Phones = append(out.Phones, ph.Value)
		}
	}
	for _, a := range p.Addresses {
		if a != nil && a.FormattedValue != "" {
			out.Addresses = append(out.Addresses, a.FormattedValue)
		}
	}
	for _, b := range p.Birthdays {
		if b != nil && b.Date != nil && b.Date.Month > 0 {
			if b.Date.Year > 0 {
				out.Birthday = fmt.Sprintf("%04d-%02d-%02d", b.Date.Year, b.Date.Month, b.Date.Day)
			} else {
				out.Birthday = fmt.Sprintf("--%02d-%02d", b.Date.Month, b.Date.Day)
			}
			break
		}
	}
	for _, b := range p.Biographies {
		if b != nil && b.Value != "" {
			out.Notes = b.Value
			break
		}
	}
	for _, u := range p.Urls {
		if u != nil && u.Value != "" {
			out.URLs = append(out.URLs, u.Value)
		}
	}
	for _, m := range p.Memberships {
		if m != nil && m.ContactGroupMembership != nil && m.ContactGroupMembership.ContactGroupResourceName != "" {
			out.Groups = append(out.Groups, m.ContactGroupMembership.ContactGroupResourceName)
		}
	}
	return out
}

func (c *Connector) listContacts(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	maxResults, pageToken, clamped, err := c.pageArgs(call.Args, connectors.DefaultMaxPageSize)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.people(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	req := svc.People.Connections.List("people/me").Context(ctx).PersonFields(contactsReadMask).PageSize(int64(maxResults))
	if pageToken != "" {
		req = req.PageToken(pageToken)
	}
	resp, err := req.Do()
	if err := classify("list contacts", err); err != nil {
		return connectors.Result{}, err
	}
	out := ContactsList{MaxResults: maxResults, Total: resp.TotalPeople, NextPageToken: resp.NextPageToken, HasMore: resp.NextPageToken != "", Items: make([]Contact, 0, len(resp.Connections))}
	for _, p := range resp.Connections {
		if p != nil {
			out.Items = append(out.Items, toContact(p))
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
