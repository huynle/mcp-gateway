package google

import (
	"context"

	"google.golang.org/api/people/v1"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Directory tool names (app contacts; Google Workspace accounts only).
const (
	ToolSearchDirectory = "search_directory"
	ToolListDirectory   = "list_directory"
)

// directoryReadMask is what the directory tools read: names, addresses,
// organizations and phone numbers (contacts.get's fields before
// increment 5), never photos or notes.
const directoryReadMask = "names,emailAddresses,organizations,phoneNumbers"

// directorySources are the directory entries the tools read: the
// domain's user profiles and its shared domain contacts.
var directorySources = []string{"DIRECTORY_SOURCE_TYPE_DOMAIN_PROFILE", "DIRECTORY_SOURCE_TYPE_DOMAIN_CONTACT"}

// DirectoryPage is the result of search_directory and list_directory.
// Total is Google's estimate of the matches (search_directory only).
type DirectoryPage struct {
	MaxResults    int             `json:"max_results"`
	Total         int64           `json:"total,omitempty"`
	NextPageToken string          `json:"next_page_token,omitempty"`
	HasMore       bool            `json:"has_more"`
	Truncated     bool            `json:"truncated,omitempty"`
	Items         []ContactDetail `json:"items"`
}

// directoryIdentity is the resource identity of both directory tools:
// the source only, never the query.
func directoryIdentity(map[string]any) map[string]string {
	return map[string]string{"source": "directory"}
}

func (c *Connector) contactsDirectoryReadTools() []connectors.Tool {
	return []connectors.Tool{
		{
			App: AppContacts, Name: ToolSearchDirectory, Kind: connectors.KindRead,
			Description: "Search the Google Workspace directory (the organization's people and shared domain contacts) by name or " +
				"email address: each hit has resource_name, name, emails, organization, title and phones. Google Workspace accounts " +
				"only. has_more and next_page_token say whether another page exists (pass page_token with the same query).",
			InputSchema: objectSchema([]property{
				{"query", "string", "Plain-text prefix query (\"car\", \"carol@\").", nil},
				{"max_results", "integer", "Hits per page (1-100; default 50); clamped to the tool's maximum.", nil},
				{"page_token", "string", "Token of the page to fetch (next_page_token of the previous result).", nil},
			}, []string{"query"}),
			RequiredScopes:   []string{ScopeDirectoryReadonly},
			ResourceIdentity: directoryIdentity,
			Bounds:           c.pagedBounds(),
		},
		{
			App: AppContacts, Name: ToolListDirectory, Kind: connectors.KindRead,
			Description: "List the Google Workspace directory (the organization's people and shared domain contacts): name, emails, " +
				"organization, title and phones, in Google's order. Google Workspace accounts only. has_more and next_page_token say " +
				"whether another page exists (pass page_token).",
			InputSchema: objectSchema([]property{
				{"max_results", "integer", "People per page (1-100; default 50); clamped to the tool's maximum.", nil},
				{"page_token", "string", "Token of the page to fetch (next_page_token of the previous result).", nil},
			}, nil),
			RequiredScopes:   []string{ScopeDirectoryReadonly},
			ResourceIdentity: directoryIdentity,
			Bounds:           c.pagedBounds(),
		},
	}
}

func (c *Connector) contactsDirectoryReadHandlers() map[string]handler {
	return map[string]handler{ToolSearchDirectory: c.searchDirectory, ToolListDirectory: c.listDirectory}
}

func (c *Connector) searchDirectory(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	q, err := requiredString(call.Args, "query")
	if err != nil {
		return connectors.Result{}, err
	}
	maxResults, pageToken, clamped, err := c.pageArgs(call.Args, connectors.DefaultMaxPageSize)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.people(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	req := svc.People.SearchDirectoryPeople().Context(ctx).Query(q).Sources(directorySources...).ReadMask(directoryReadMask).PageSize(int64(maxResults))
	if pageToken != "" {
		req = req.PageToken(pageToken)
	}
	resp, err := req.Do()
	if err := classify("search directory", err); err != nil {
		return connectors.Result{}, err
	}
	return c.directoryResult(DirectoryPage{MaxResults: maxResults, Total: resp.TotalSize, NextPageToken: resp.NextPageToken}, resp.People, clamped), nil
}

func (c *Connector) listDirectory(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	maxResults, pageToken, clamped, err := c.pageArgs(call.Args, connectors.DefaultMaxPageSize)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.people(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	req := svc.People.ListDirectoryPeople().Context(ctx).Sources(directorySources...).ReadMask(directoryReadMask).PageSize(int64(maxResults))
	if pageToken != "" {
		req = req.PageToken(pageToken)
	}
	resp, err := req.Do()
	if err := classify("list directory", err); err != nil {
		return connectors.Result{}, err
	}
	return c.directoryResult(DirectoryPage{MaxResults: maxResults, NextPageToken: resp.NextPageToken}, resp.People, clamped), nil
}

// directoryResult fills page with the people, sets the markers and fits
// it to the bounds (trailing items dropped, never below one).
func (c *Connector) directoryResult(page DirectoryPage, found []*people.Person, clamped bool) connectors.Result {
	page.HasMore = page.NextPageToken != ""
	page.Items = make([]ContactDetail, 0, len(found))
	for _, p := range found {
		if p != nil {
			page.Items = append(page.Items, toContactDetail(p))
		}
	}
	res := connectors.Result{Partial: clamped, Empty: len(page.Items) == 0}
	for encodedSize(page) > c.bounds.MaxResultBytes && len(page.Items) > 1 {
		page.Items = page.Items[:len(page.Items)-1]
		page.Truncated, res.Partial = true, true
	}
	res.Content = page
	return res
}
