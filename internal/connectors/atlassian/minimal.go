package atlassian

import (
	"encoding/json"
	"strings"
	"time"
)

// The result shapes are flat and small, in the spirit of
// sooperset/mcp-atlassian's simplified dictionaries (design only, no code
// copied; decision 0sod196t): names instead of nested user and status
// objects, a browse url, and the truncation flags the bounds need.

// IssueSummary is one jira.search_issues hit.
type IssueSummary struct {
	Key       string   `json:"key"`
	ID        string   `json:"id"`
	Summary   string   `json:"summary,omitempty"`
	Status    string   `json:"status,omitempty"`
	IssueType string   `json:"issue_type,omitempty"`
	Priority  string   `json:"priority,omitempty"`
	Assignee  string   `json:"assignee,omitempty"`
	Reporter  string   `json:"reporter,omitempty"`
	Labels    []string `json:"labels,omitempty"`
	Created   string   `json:"created,omitempty"`
	Updated   string   `json:"updated,omitempty"`
	URL       string   `json:"url,omitempty"`
	Project   string   `json:"project,omitempty"`
}

// IssuePage is jira.search_issues's result.
type IssuePage struct {
	Issues        []IssueSummary `json:"issues"`
	MaxResults    int            `json:"max_results"`
	HasMore       bool           `json:"has_more"`
	NextPageToken string         `json:"next_page_token,omitempty"`
	Truncated     bool           `json:"truncated,omitempty"`
}

// Issue is jira.get_issue's result.
type Issue struct {
	Key         string   `json:"key"`
	ID          string   `json:"id"`
	Summary     string   `json:"summary,omitempty"`
	Description string   `json:"description,omitempty"`
	Status      string   `json:"status,omitempty"`
	IssueType   string   `json:"issue_type,omitempty"`
	Priority    string   `json:"priority,omitempty"`
	Assignee    string   `json:"assignee,omitempty"`
	Reporter    string   `json:"reporter,omitempty"`
	Labels      []string `json:"labels,omitempty"`
	Components  []string `json:"components,omitempty"`
	Resolution  string   `json:"resolution,omitempty"`
	Created     string   `json:"created,omitempty"`
	Updated     string   `json:"updated,omitempty"`
	URL         string   `json:"url,omitempty"`
	Project     string   `json:"project,omitempty"`
	// Truncated says the description was cut to fit the result bounds.
	Truncated bool `json:"truncated,omitempty"`
}

// Transition is one workflow transition an issue can take.
type Transition struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	To   string `json:"to,omitempty"`
}

// Transitions is jira.list_transitions's result.
type Transitions struct {
	Issue       string       `json:"issue"`
	Transitions []Transition `json:"transitions"`
}

// ContentSummary is one confluence.search hit.
type ContentSummary struct {
	ID           string `json:"id"`
	Type         string `json:"type,omitempty"`
	Status       string `json:"status,omitempty"`
	Title        string `json:"title"`
	Space        string `json:"space,omitempty"`
	URL          string `json:"url,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
}

// ContentPage is confluence.search's result.
type ContentPage struct {
	Results   []ContentSummary `json:"results"`
	Start     int              `json:"start"`
	Limit     int              `json:"limit"`
	Size      int              `json:"size"`
	HasMore   bool             `json:"has_more"`
	Truncated bool             `json:"truncated,omitempty"`
}

// Page is confluence.get_page's result; Body is in Confluence storage
// format (XHTML).
type Page struct {
	ID         string `json:"id"`
	Title      string `json:"title"`
	Status     string `json:"status,omitempty"`
	SpaceID    string `json:"space_id,omitempty"`
	ParentID   string `json:"parent_id,omitempty"`
	Version    int    `json:"version,omitempty"`
	BodyFormat string `json:"body_format,omitempty"`
	Body       string `json:"body,omitempty"`
	URL        string `json:"url,omitempty"`
	CreatedAt  string `json:"created_at,omitempty"`
	// Truncated says the body was cut to fit the result bounds.
	Truncated bool `json:"truncated,omitempty"`
}

// CreatedIssue is jira.create_issue's result: the identifiers of the new
// issue, never its content (the ledger keeps key, id and url).
type CreatedIssue struct {
	Key     string `json:"key"`
	ID      string `json:"id"`
	URL     string `json:"url,omitempty"`
	Project string `json:"project"`
}

// CreatedComment is jira.add_comment's result.
type CreatedComment struct {
	ID    string `json:"id"`
	Issue string `json:"issue"`
	URL   string `json:"url,omitempty"`
}

// Transitioned is jira.transition_issue's result.
type Transitioned struct {
	Issue        string `json:"issue"`
	TransitionID string `json:"transition_id"`
}

// CreatedPage is confluence.create_page's result.
type CreatedPage struct {
	ID      string `json:"id"`
	SpaceID string `json:"space_id,omitempty"`
	URL     string `json:"url,omitempty"`
	Space   string `json:"space"`
}

// --- wire shapes (what Atlassian answers) --------------------------------------------

type named struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	AccountID   string `json:"accountId"`
	Key         string `json:"key"`
	ID          string `json:"id"`
}

func (n *named) label() string {
	if n == nil {
		return ""
	}
	if n.DisplayName != "" {
		return n.DisplayName
	}
	return n.Name
}

type issueFields struct {
	Summary     string          `json:"summary"`
	Description json.RawMessage `json:"description"`
	Status      *named          `json:"status"`
	IssueType   *named          `json:"issuetype"`
	Priority    *named          `json:"priority"`
	Assignee    *named          `json:"assignee"`
	Reporter    *named          `json:"reporter"`
	Resolution  *named          `json:"resolution"`
	Project     *named          `json:"project"`
	Labels      []string        `json:"labels"`
	Components  []named         `json:"components"`
	Created     string          `json:"created"`
	Updated     string          `json:"updated"`
}

type wireIssue struct {
	ID     string      `json:"id"`
	Key    string      `json:"key"`
	Fields issueFields `json:"fields"`
}

type wireSearch struct {
	Issues        []wireIssue `json:"issues"`
	IsLast        *bool       `json:"isLast"`
	NextPageToken string      `json:"nextPageToken"`
}

type wireTransitions struct {
	Transitions []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		To   *named `json:"to"`
	} `json:"transitions"`
}

type wireComment struct {
	ID   string          `json:"id"`
	Body json.RawMessage `json:"body"`
}

type wireComments struct {
	StartAt    int           `json:"startAt"`
	MaxResults int           `json:"maxResults"`
	Total      int           `json:"total"`
	Comments   []wireComment `json:"comments"`
}

// wireSpaceRef is the space of a v1 content result (its id is a number
// there, unlike everywhere else).
type wireSpaceRef struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}

type wireContent struct {
	ID     string        `json:"id"`
	Type   string        `json:"type"`
	Status string        `json:"status"`
	Title  string        `json:"title"`
	Space  *wireSpaceRef `json:"space"`
	Body   *struct {
		Storage *struct {
			Value string `json:"value"`
		} `json:"storage"`
	} `json:"body"`
	Version *struct {
		Number int    `json:"number"`
		When   string `json:"when"`
	} `json:"version"`
	Links map[string]string `json:"_links"`
}

type wireContentSearch struct {
	Results []wireContent     `json:"results"`
	Start   int               `json:"start"`
	Limit   int               `json:"limit"`
	Size    int               `json:"size"`
	Links   map[string]string `json:"_links"`
}

type wirePage struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	Title     string `json:"title"`
	SpaceID   string `json:"spaceId"`
	ParentID  string `json:"parentId"`
	CreatedAt string `json:"createdAt"`
	Version   *struct {
		Number int `json:"number"`
	} `json:"version"`
	Body *struct {
		Storage *struct {
			Representation string `json:"representation"`
			Value          string `json:"value"`
		} `json:"storage"`
	} `json:"body"`
	Links map[string]string `json:"_links"`
}

type wirePages struct {
	Results []wirePage        `json:"results"`
	Links   map[string]string `json:"_links"`
}

type wireSpaces struct {
	Results []struct {
		ID   string `json:"id"`
		Key  string `json:"key"`
		Name string `json:"name"`
	} `json:"results"`
}

// --- converters ---------------------------------------------------------------------

func toIssueSummary(is wireIssue, site Site) IssueSummary {
	f := is.Fields
	return IssueSummary{
		Key: is.Key, ID: is.ID, Summary: f.Summary, Status: f.Status.label(), IssueType: f.IssueType.label(),
		Priority: f.Priority.label(), Assignee: f.Assignee.label(), Reporter: f.Reporter.label(), Labels: f.Labels,
		Created: timestamp(f.Created), Updated: timestamp(f.Updated), URL: browseURL(site, is.Key), Project: projectKey(f.Project),
	}
}

func toIssue(is wireIssue, site Site) Issue {
	f := is.Fields
	out := Issue{
		Key: is.Key, ID: is.ID, Summary: f.Summary, Description: adfText(f.Description), Status: f.Status.label(),
		IssueType: f.IssueType.label(), Priority: f.Priority.label(), Assignee: f.Assignee.label(), Reporter: f.Reporter.label(),
		Labels: f.Labels, Resolution: f.Resolution.label(), Created: timestamp(f.Created), Updated: timestamp(f.Updated),
		URL: browseURL(site, is.Key), Project: projectKey(f.Project),
	}
	for i := range f.Components {
		if n := f.Components[i].label(); n != "" {
			out.Components = append(out.Components, n)
		}
	}
	return out
}

func toContentSummary(ct wireContent, site Site) ContentSummary {
	out := ContentSummary{ID: ct.ID, Type: ct.Type, Status: ct.Status, Title: ct.Title}
	if ct.Space != nil {
		out.Space = ct.Space.Key
	}
	if ct.Version != nil {
		out.LastModified = timestamp(ct.Version.When)
	}
	out.URL = wikiURL(site, ct.Links["webui"])
	return out
}

func toPage(p wirePage, site Site) Page {
	out := Page{ID: p.ID, Title: p.Title, Status: p.Status, SpaceID: p.SpaceID, ParentID: p.ParentID, CreatedAt: timestamp(p.CreatedAt)}
	if p.Version != nil {
		out.Version = p.Version.Number
	}
	if p.Body != nil && p.Body.Storage != nil {
		out.BodyFormat, out.Body = "storage", p.Body.Storage.Value
		if p.Body.Storage.Representation != "" {
			out.BodyFormat = p.Body.Storage.Representation
		}
	}
	out.URL = wikiURL(site, p.Links["webui"])
	return out
}

func projectKey(p *named) string {
	if p == nil {
		return ""
	}
	return p.Key
}

// browseURL is the issue's page on the site, "" when the site URL is
// unknown.
func browseURL(site Site, key string) string {
	if site.URL == "" || key == "" {
		return ""
	}
	return strings.TrimSuffix(site.URL, "/") + "/browse/" + key
}

// wikiURL turns a Confluence webui link ("/spaces/DOCS/pages/123/Title")
// into an absolute URL on the site, "" when either is unknown.
func wikiURL(site Site, webui string) string {
	if site.URL == "" || webui == "" {
		return ""
	}
	if strings.HasPrefix(webui, "http://") || strings.HasPrefix(webui, "https://") {
		return webui
	}
	return strings.TrimSuffix(site.URL, "/") + "/wiki" + "/" + strings.TrimPrefix(webui, "/")
}

// timestamp normalises Atlassian's timestamps (Jira's
// 2006-01-02T15:04:05.000-0700, Confluence's RFC 3339) to RFC 3339 UTC;
// an unreadable value is returned as it came.
func timestamp(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	for _, layout := range []string{"2006-01-02T15:04:05.000-0700", time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.000Z07:00"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	return s
}

// encodedSize is the serialised size of v, the measure the bounds apply to.
func encodedSize(v any) int {
	b, err := json.Marshal(v)
	if err != nil {
		return 0
	}
	return len(b)
}

// fitBody cuts *body (and sets *truncated) until the object returned by
// obj, which must read both through the same pointers, serialises to at
// most max bytes or the body is gone. Everything but the body stays.
func fitBody(body *string, truncated *bool, max int, obj func() any) {
	if encodedSize(obj()) <= max {
		return
	}
	*truncated = true
	for *body != "" {
		size := encodedSize(obj())
		if size <= max {
			return
		}
		cut := len(*body) - (size - max) - 1
		if cut < 0 {
			cut = 0
		}
		for cut > 0 && cut < len(*body) && !isRuneStart((*body)[cut]) {
			cut--
		}
		*body = (*body)[:cut]
	}
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }
