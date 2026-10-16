package atlassian

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// The Confluence tools added to close the gap with Atlassian's Rovo MCP
// server and sooperset/mcp-atlassian: spaces, a page's children,
// comments (footer and inline), attachments (metadata only), labels and
// version history, a page by title; updating a page, adding a footer
// comment or reply, and adding labels. All on the v2 REST API except
// labels' write, which only the v1 API offers.

// More Confluence tool names.
const (
	ToolListSpaces          = "list_spaces"
	ToolGetPageChildren     = "get_page_children"
	ToolGetPageByTitle      = "get_page_by_title"
	ToolGetPageComments     = "get_page_comments"
	ToolListPageAttachments = "list_page_attachments"
	ToolGetPageLabels       = "get_page_labels"
	ToolGetPageHistory      = "get_page_history"
	ToolUpdatePage          = "update_page"
	ToolAddPageComment      = "add_page_comment"
	ToolAddPageLabels       = "add_page_labels"
)

// Granular Confluence scopes of the added tools.
const (
	ScopeCommentRead    = "read:comment:confluence"
	ScopeCommentWrite   = "write:comment:confluence"
	ScopeAttachmentRead = "read:attachment:confluence"
	ScopeLabelRead      = "read:label:confluence"
	ScopeLabelWrite     = "write:label:confluence"
)

// maxLabels bounds the labels of one add_page_labels call.
const maxLabels = 20

var labelRE = regexp.MustCompile(`^[^\s,:]{1,255}$`)

var (
	pageIDProp   = property{"id", "string", "The page id (digits).", nil}
	cursorProps  = []property{{"limit", "integer", "Results per page (1-100); clamped to the tool's maximum.", nil}, {"cursor", "string", "Cursor of the next page, from the previous result.", nil}}
	spaceTypes   = []string{"global", "personal", "collaboration", "knowledge_base"}
	commentKinds = []string{"footer", "inline"}
)

func withCursor(props ...property) []property { return append(props, cursorProps...) }

func (c *Connector) confluenceMoreReadTools() []connectors.Tool {
	paged := connectors.Bounds{MaxPageSize: c.bounds.MaxPageSize, MaxResultBytes: c.bounds.MaxResultBytes}
	single := connectors.Bounds{MaxResultBytes: c.bounds.MaxResultBytes}
	tool := func(name, desc string, props []property, required, scopes []string, b connectors.Bounds) connectors.Tool {
		return connectors.Tool{App: ConfluenceApp, Name: name, Kind: connectors.KindRead, Description: desc, InputSchema: objectSchema(props, required),
			RequiredScopes: scopes, ResourceIdentity: confluenceIdentity, Bounds: b}
	}
	pageRead := []string{ScopePageRead}
	return []connectors.Tool{
		tool(ToolListSpaces, "List the Confluence spaces this account can see: id, key, name, type, status, homepage id and url; "+
			"optionally only some keys or one type. Paginated: pass next_cursor as cursor.",
			withCursor(property{"keys", "array", "Only these space keys.", nil}, property{"type", "string", "Space type.", spaceTypes}),
			nil, []string{ScopeSpaceRead}, paged),
		tool(ToolGetPageChildren, "List the child pages of a Confluence page: id, title, status, position. Paginated with cursor.",
			withCursor(pageIDProp), []string{"id"}, pageRead, paged),
		tool(ToolGetPageByTitle, "Get a Confluence page by its exact title in a space (by key), with its body in storage format, like get_page.",
			[]property{{"space_key", "string", "Key of the space.", nil}, {"title", "string", "Exact page title.", nil}},
			[]string{"space_key", "title"}, []string{ScopePageRead, ScopeSpaceRead}, single),
		tool(ToolGetPageComments, "List the footer (default) or inline comments of a Confluence page: id, author id, created, body (storage format), "+
			"and for inline comments the resolution status and the selected text. Paginated with cursor; long bodies are cut to the result bounds.",
			withCursor(pageIDProp, property{"kind", "string", "footer (default) or inline.", commentKinds}), []string{"id"}, []string{ScopeCommentRead}, paged),
		tool(ToolListPageAttachments, "List the attachments of a Confluence page (metadata only): id, file name, media type, size, comment, created, "+
			"download url. Paginated with cursor.", withCursor(pageIDProp), []string{"id"}, []string{ScopeAttachmentRead}, paged),
		tool(ToolGetPageLabels, "List the labels of a Confluence page: id, name, prefix. Paginated with cursor.",
			withCursor(pageIDProp), []string{"id"}, pageRead, paged),
		tool(ToolGetPageHistory, "List the versions of a Confluence page, newest first: number, author id, message, created, minor edit. Paginated with cursor.",
			withCursor(pageIDProp), []string{"id"}, pageRead, paged),
	}
}

func (c *Connector) confluenceMoreWriteTools() []connectors.Tool {
	single := connectors.Bounds{MaxResultBytes: c.bounds.MaxResultBytes}
	tool := func(name, desc string, props []property, required, scopes []string, identity func(map[string]any) map[string]string,
		rec connectors.Reconciliation, ids func(connectors.Result) map[string]string) connectors.Tool {
		return connectors.Tool{App: ConfluenceApp, Name: name, Kind: connectors.KindWrite, Description: desc, InputSchema: objectSchema(props, required),
			RequiredScopes: scopes, ResourceIdentity: identity, Reconcile: rec, ResultIDs: ids, Bounds: single}
	}
	return []connectors.Tool{
		tool(ToolUpdatePage, "Replace the body of a Confluence page (by id) with storage format (XHTML; plain text is escaped and wrapped in a "+
			"paragraph), optionally with a new title and a version message. Creates the next version; returns id, version and url.",
			[]property{pageIDProp, {"title", "string", "New title (default: keep the current one).", nil},
				{"body", "string", "New body in Confluence storage format, or plain text.", nil}, {"version_message", "string", "Optional version comment.", nil}},
			[]string{"id", "body"}, []string{ScopePageWrite, ScopePageRead}, confluenceIdentity,
			connectors.Reconciliation{Kind: connectors.ReconcileMarker, Check: c.checkUpdatedPage}, mapResultIDs),
		tool(ToolAddPageComment, "Add a footer comment to a Confluence page (by id), or a reply to a footer comment (parent_comment_id), "+
			"in storage format or plain text. Returns the comment's id and url.",
			[]property{pageIDProp, {"body", "string", "Comment body in storage format, or plain text.", nil},
				{"parent_comment_id", "string", "Optional id of the footer comment to reply to.", nil}},
			[]string{"id", "body"}, []string{ScopeCommentWrite, ScopeCommentRead}, pageCommentIdentity,
			connectors.Reconciliation{Kind: connectors.ReconcileMarker, Check: c.checkPageComment}, mapResultIDs),
		tool(ToolAddPageLabels, "Add labels (lower-cased, no spaces) to a Confluence page (by id).",
			[]property{pageIDProp, {"labels", "array", "Label names (1-20).", nil}},
			[]string{"id", "labels"}, []string{ScopeLabelWrite, ScopeLabelRead, ScopePageRead}, pageLabelsIdentity,
			connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkPageLabels}, mapResultIDs),
	}
}

func (c *Connector) confluenceMoreHandlers(write bool) map[string]handler {
	if write {
		return map[string]handler{ToolUpdatePage: c.updatePage, ToolAddPageComment: c.addPageComment, ToolAddPageLabels: c.addPageLabels}
	}
	return map[string]handler{
		ToolListSpaces: c.listSpaces, ToolGetPageChildren: c.getPageChildren, ToolGetPageByTitle: c.getPageByTitle,
		ToolGetPageComments: c.getPageComments, ToolListPageAttachments: c.listPageAttachments,
		ToolGetPageLabels: c.getPageLabels, ToolGetPageHistory: c.getPageHistory,
	}
}

// mapResultIDs returns a write's map[string]string content.
func mapResultIDs(res connectors.Result) map[string]string { return contentMap(res) }

// --- identities ------------------------------------------------------------------------------

func pageCommentIdentity(args map[string]any) map[string]string {
	out := confluenceIdentity(args)
	if p, _ := args["parent_comment_id"].(string); pageIDRE.MatchString(strings.TrimSpace(p)) {
		out["parent_comment"] = strings.TrimSpace(p)
	}
	return out
}

func pageLabelsIdentity(args map[string]any) map[string]string {
	out := confluenceIdentity(args)
	if labels, err := labelsArg(args); err == nil {
		out["labels"] = strings.Join(labels, ",")
	}
	return out
}

// labelsArg reads 1..maxLabels label names, lower-cased.
func labelsArg(args map[string]any) ([]string, error) {
	list, err := stringList(args, "labels")
	if err != nil {
		return nil, err
	}
	if len(list) == 0 || len(list) > maxLabels {
		return nil, invalid("labels must list 1 to %d label names", maxLabels)
	}
	out := make([]string, 0, len(list))
	for _, l := range list {
		l = strings.ToLower(l)
		if !labelRE.MatchString(l) {
			return nil, invalid("labels: %q is not a label name (no spaces, commas or colons)", l)
		}
		out = append(out, l)
	}
	return out, nil
}

// --- shared helpers ---------------------------------------------------------------------------

// CursorPaging is the cursor pagination of the v2 lists.
type CursorPaging struct {
	Limit      int    `json:"limit"`
	HasMore    bool   `json:"has_more"`
	NextCursor string `json:"next_cursor,omitempty"`
	Truncated  bool   `json:"truncated,omitempty"`
}

// cursorArgs reads limit (clamped) and cursor into a query.
func (c *Connector) cursorArgs(args map[string]any) (url.Values, int, bool, error) {
	limit, clamped, err := c.pageSizeArg(args, "limit")
	if err != nil {
		return nil, 0, false, err
	}
	q := url.Values{"limit": {strconv.Itoa(limit)}}
	cursor, err := optionalString(args, "cursor")
	if err != nil {
		return nil, 0, false, err
	}
	if cursor = strings.TrimSpace(cursor); cursor != "" {
		q.Set("cursor", cursor)
	}
	return q, limit, clamped, nil
}

func cursorPaging(limit int, links map[string]string) CursorPaging {
	next := nextCursor(links["next"])
	return CursorPaging{Limit: limit, HasMore: next != "", NextCursor: next}
}

// pageIDArg reads the required page id argument.
func pageIDArg(args map[string]any) (string, error) {
	id, _ := args["id"].(string)
	if id = strings.TrimSpace(id); !pageIDRE.MatchString(id) {
		return "", invalid("id is required: the page id (digits)")
	}
	return id, nil
}

// --- read handlers -----------------------------------------------------------------------------

// SpaceView is one space.
type SpaceView struct {
	ID         string `json:"id"`
	Key        string `json:"key"`
	Name       string `json:"name"`
	Type       string `json:"type,omitempty"`
	Status     string `json:"status,omitempty"`
	HomepageID string `json:"homepage_id,omitempty"`
	URL        string `json:"url,omitempty"`
}

func (c *Connector) listSpaces(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	q, limit, clamped, err := c.cursorArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	keys, err := stringList(call.Args, "keys")
	if err != nil {
		return connectors.Result{}, err
	}
	for _, k := range keys {
		if !spaceKeyRE.MatchString(k) {
			return connectors.Result{}, invalid("keys: %q is not a space key", k)
		}
		q.Add("keys", k)
	}
	typ, err := enumArg(call.Args, "type", strings.Join(spaceTypes, ","))
	if err != nil {
		return connectors.Result{}, err
	}
	if typ != "" {
		q.Set("type", typ)
	}
	var page struct {
		Results []struct {
			ID         string            `json:"id"`
			Key        string            `json:"key"`
			Name       string            `json:"name"`
			Type       string            `json:"type"`
			Status     string            `json:"status"`
			HomepageID string            `json:"homepageId"`
			Links      map[string]string `json:"_links"`
		} `json:"results"`
		Links map[string]string `json:"_links"`
	}
	if err := c.classify("list spaces", s.getJSON(ctx, s.wikiURL("api/v2/spaces", q), &page)); err != nil {
		return connectors.Result{}, err
	}
	out := struct {
		Spaces []SpaceView `json:"spaces"`
		CursorPaging
	}{Spaces: make([]SpaceView, 0, len(page.Results)), CursorPaging: cursorPaging(limit, page.Links)}
	for _, sp := range page.Results {
		out.Spaces = append(out.Spaces, SpaceView{ID: sp.ID, Key: sp.Key, Name: sp.Name, Type: sp.Type, Status: sp.Status, HomepageID: sp.HomepageID, URL: wikiURL(s.site, sp.Links["webui"])})
	}
	out.Truncated = fitList(&out.Spaces, c.bounds.MaxResultBytes, func() any { return out })
	return listResult(out, len(out.Spaces), clamped || out.Truncated), nil
}

// ChildPageView is one child page.
type ChildPageView struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Status   string `json:"status,omitempty"`
	SpaceID  string `json:"space_id,omitempty"`
	Position *int   `json:"position,omitempty"`
}

func (c *Connector) getPageChildren(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	id, err := pageIDArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	q, limit, clamped, err := c.cursorArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	var page struct {
		Results []struct {
			ID            string `json:"id"`
			Title         string `json:"title"`
			Status        string `json:"status"`
			SpaceID       string `json:"spaceId"`
			ChildPosition *int   `json:"childPosition"`
		} `json:"results"`
		Links map[string]string `json:"_links"`
	}
	if err := c.classify("get page children", s.getJSON(ctx, s.wikiURL("api/v2/pages/"+id+"/children", q), &page)); err != nil {
		return connectors.Result{}, err
	}
	out := struct {
		ParentID string          `json:"parent_id"`
		Children []ChildPageView `json:"children"`
		CursorPaging
	}{ParentID: id, Children: make([]ChildPageView, 0, len(page.Results)), CursorPaging: cursorPaging(limit, page.Links)}
	for _, p := range page.Results {
		out.Children = append(out.Children, ChildPageView{ID: p.ID, Title: p.Title, Status: p.Status, SpaceID: p.SpaceID, Position: p.ChildPosition})
	}
	out.Truncated = fitList(&out.Children, c.bounds.MaxResultBytes, func() any { return out })
	return listResult(out, len(out.Children), clamped || out.Truncated), nil
}

func (c *Connector) getPageByTitle(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	space, _ := call.Args["space_key"].(string)
	if space = strings.TrimSpace(space); !spaceKeyRE.MatchString(space) {
		return connectors.Result{}, invalid("space_key is required: a Confluence space key like DOCS")
	}
	title, err := requiredString(call.Args, "title")
	if err != nil {
		return connectors.Result{}, err
	}
	spaceID, err := c.spaceID(ctx, s, space)
	if err != nil {
		return connectors.Result{}, err
	}
	var res wirePages
	q := url.Values{"space-id": {spaceID}, "title": {title}, "body-format": {"storage"}, "limit": {"1"}}
	if err := c.classify("get page by title", s.getJSON(ctx, s.wikiURL("api/v2/pages", q), &res)); err != nil {
		return connectors.Result{}, err
	}
	if len(res.Results) == 0 {
		return connectors.Result{}, &Error{Class: ClassNotFound, Message: "get page by title: no page titled " + strconv.Quote(title) + " in space " + space + ", or this account cannot see it"}
	}
	out := toPage(res.Results[0], s.site)
	fitBody(&out.Body, &out.Truncated, c.bounds.MaxResultBytes, func() any { return out })
	return connectors.Result{Content: out, Partial: out.Truncated}, nil
}

// PageCommentView is one Confluence comment.
type PageCommentView struct {
	ID               string `json:"id"`
	Status           string `json:"status,omitempty"`
	AuthorID         string `json:"author_id,omitempty"`
	CreatedAt        string `json:"created_at,omitempty"`
	Body             string `json:"body"`
	ResolutionStatus string `json:"resolution_status,omitempty"`
	InlineSelection  string `json:"inline_selection,omitempty"`
	URL              string `json:"url,omitempty"`
}

type wireVersionInfo struct {
	Number    int    `json:"number"`
	AuthorID  string `json:"authorId"`
	Message   string `json:"message"`
	CreatedAt string `json:"createdAt"`
	MinorEdit bool   `json:"minorEdit"`
}

type wirePageComment struct {
	ID      string           `json:"id"`
	Status  string           `json:"status"`
	Version *wireVersionInfo `json:"version"`
	Body    *struct {
		Storage *struct {
			Value string `json:"value"`
		} `json:"storage"`
	} `json:"body"`
	ResolutionStatus string `json:"resolutionStatus"`
	Properties       *struct {
		InlineOriginalSelection string `json:"inlineOriginalSelection"`
	} `json:"properties"`
	Links map[string]string `json:"_links"`
}

func (w wirePageComment) storage() string {
	if w.Body == nil || w.Body.Storage == nil {
		return ""
	}
	return w.Body.Storage.Value
}

type wirePageComments struct {
	Results []wirePageComment `json:"results"`
	Links   map[string]string `json:"_links"`
}

func (c *Connector) getPageComments(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	id, err := pageIDArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	kind, err := enumArg(call.Args, "kind", strings.Join(commentKinds, ","))
	if err != nil {
		return connectors.Result{}, err
	}
	if kind == "" {
		kind = "footer"
	}
	q, limit, clamped, err := c.cursorArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	q.Set("body-format", "storage")
	var page wirePageComments
	if err := c.classify("get page comments", s.getJSON(ctx, s.wikiURL("api/v2/pages/"+id+"/"+kind+"-comments", q), &page)); err != nil {
		return connectors.Result{}, err
	}
	out := struct {
		PageID   string            `json:"page_id"`
		Kind     string            `json:"kind"`
		Comments []PageCommentView `json:"comments"`
		CursorPaging
	}{PageID: id, Kind: kind, Comments: make([]PageCommentView, 0, len(page.Results)), CursorPaging: cursorPaging(limit, page.Links)}
	for _, cm := range page.Results {
		v := PageCommentView{ID: cm.ID, Status: cm.Status, Body: cm.storage(), ResolutionStatus: cm.ResolutionStatus, URL: wikiURL(s.site, cm.Links["webui"])}
		if cm.Version != nil {
			v.AuthorID, v.CreatedAt = cm.Version.AuthorID, timestamp(cm.Version.CreatedAt)
		}
		if cm.Properties != nil {
			v.InlineSelection = cm.Properties.InlineOriginalSelection
		}
		out.Comments = append(out.Comments, v)
	}
	out.Truncated = fitList(&out.Comments, c.bounds.MaxResultBytes, func() any { return out })
	if len(out.Comments) == 1 {
		fitBody(&out.Comments[0].Body, &out.Truncated, c.bounds.MaxResultBytes, func() any { return out })
	}
	return listResult(out, len(out.Comments), clamped || out.Truncated), nil
}

// AttachmentView is one attachment's metadata.
type AttachmentView struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	MediaType   string `json:"media_type,omitempty"`
	FileSize    int64  `json:"file_size"`
	Comment     string `json:"comment,omitempty"`
	CreatedAt   string `json:"created_at,omitempty"`
	DownloadURL string `json:"download_url,omitempty"`
	URL         string `json:"url,omitempty"`
}

func (c *Connector) listPageAttachments(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	id, err := pageIDArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	q, limit, clamped, err := c.cursorArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	var page struct {
		Results []struct {
			ID           string `json:"id"`
			Title        string `json:"title"`
			MediaType    string `json:"mediaType"`
			FileSize     int64  `json:"fileSize"`
			Comment      string `json:"comment"`
			CreatedAt    string `json:"createdAt"`
			DownloadLink string `json:"downloadLink"`
			WebuiLink    string `json:"webuiLink"`
		} `json:"results"`
		Links map[string]string `json:"_links"`
	}
	if err := c.classify("list attachments", s.getJSON(ctx, s.wikiURL("api/v2/pages/"+id+"/attachments", q), &page)); err != nil {
		return connectors.Result{}, err
	}
	out := struct {
		PageID      string           `json:"page_id"`
		Attachments []AttachmentView `json:"attachments"`
		CursorPaging
	}{PageID: id, Attachments: make([]AttachmentView, 0, len(page.Results)), CursorPaging: cursorPaging(limit, page.Links)}
	for _, a := range page.Results {
		out.Attachments = append(out.Attachments, AttachmentView{ID: a.ID, Title: a.Title, MediaType: a.MediaType, FileSize: a.FileSize, Comment: a.Comment,
			CreatedAt: timestamp(a.CreatedAt), DownloadURL: wikiURL(s.site, a.DownloadLink), URL: wikiURL(s.site, a.WebuiLink)})
	}
	out.Truncated = fitList(&out.Attachments, c.bounds.MaxResultBytes, func() any { return out })
	return listResult(out, len(out.Attachments), clamped || out.Truncated), nil
}

// LabelView is one label.
type LabelView struct {
	ID     string `json:"id,omitempty"`
	Name   string `json:"name"`
	Prefix string `json:"prefix,omitempty"`
}

type wireLabels struct {
	Results []LabelView       `json:"results"`
	Links   map[string]string `json:"_links"`
}

func (c *Connector) getPageLabels(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	id, err := pageIDArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	q, limit, clamped, err := c.cursorArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	var page wireLabels
	if err := c.classify("get page labels", s.getJSON(ctx, s.wikiURL("api/v2/pages/"+id+"/labels", q), &page)); err != nil {
		return connectors.Result{}, err
	}
	out := struct {
		PageID string      `json:"page_id"`
		Labels []LabelView `json:"labels"`
		CursorPaging
	}{PageID: id, Labels: page.Results, CursorPaging: cursorPaging(limit, page.Links)}
	if out.Labels == nil {
		out.Labels = []LabelView{}
	}
	out.Truncated = fitList(&out.Labels, c.bounds.MaxResultBytes, func() any { return out })
	return listResult(out, len(out.Labels), clamped || out.Truncated), nil
}

// PageVersionView is one page version.
type PageVersionView struct {
	Number    int    `json:"number"`
	AuthorID  string `json:"author_id,omitempty"`
	Message   string `json:"message,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
	MinorEdit bool   `json:"minor_edit"`
}

func (c *Connector) getPageHistory(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	id, err := pageIDArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	q, limit, clamped, err := c.cursorArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	q.Set("sort", "-modified-date")
	var page struct {
		Results []wireVersionInfo `json:"results"`
		Links   map[string]string `json:"_links"`
	}
	if err := c.classify("get page history", s.getJSON(ctx, s.wikiURL("api/v2/pages/"+id+"/versions", q), &page)); err != nil {
		return connectors.Result{}, err
	}
	out := struct {
		PageID   string            `json:"page_id"`
		Versions []PageVersionView `json:"versions"`
		CursorPaging
	}{PageID: id, Versions: make([]PageVersionView, 0, len(page.Results)), CursorPaging: cursorPaging(limit, page.Links)}
	for _, v := range page.Results {
		out.Versions = append(out.Versions, PageVersionView{Number: v.Number, AuthorID: v.AuthorID, Message: v.Message, CreatedAt: timestamp(v.CreatedAt), MinorEdit: v.MinorEdit})
	}
	out.Truncated = fitList(&out.Versions, c.bounds.MaxResultBytes, func() any { return out })
	return listResult(out, len(out.Versions), clamped || out.Truncated), nil
}

// --- write handlers ------------------------------------------------------------------------------

// updatePage reads the page's current version and title (a read: its
// failures are known and nothing is written), then puts the next
// version with the marker paragraph last.
func (c *Connector) updatePage(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	id, err := pageIDArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	body, err := requiredString(call.Args, "body")
	if err != nil {
		return connectors.Result{}, err
	}
	title, err := optionalString(call.Args, "title")
	if err != nil {
		return connectors.Result{}, err
	}
	message, err := optionalString(call.Args, "version_message")
	if err != nil {
		return connectors.Result{}, err
	}
	var cur wirePage
	if err := c.classify("update page: read current version", s.getJSON(ctx, s.wikiURL("api/v2/pages/"+id, nil), &cur)); err != nil {
		return connectors.Result{}, err
	}
	if cur.Version == nil {
		return connectors.Result{}, &Error{Class: ClassVendorError, Message: "update page: Atlassian did not report the page's current version"}
	}
	if title = strings.TrimSpace(title); title == "" {
		title = cur.Title
	}
	version := map[string]any{"number": cur.Version.Number + 1}
	if message = strings.TrimSpace(message); message != "" {
		version["message"] = message
	}
	req := map[string]any{"id": id, "status": "current", "title": title, "version": version,
		"body": map[string]string{"representation": "storage", "value": storageBody(body, call.OperationID)}}
	var updated wirePage
	if err := c.classifyWrite("update page", s.putJSON(ctx, s.wikiURL("api/v2/pages/"+id, nil), req, &updated)); err != nil {
		return connectors.Result{}, err
	}
	n := cur.Version.Number + 1
	if updated.Version != nil && updated.Version.Number > 0 {
		n = updated.Version.Number
	}
	return connectors.Result{Content: map[string]string{"id": id, "version": strconv.Itoa(n), "url": wikiURL(s.site, updated.Links["webui"])}}, nil
}

func (c *Connector) addPageComment(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	id, err := pageIDArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	body, err := requiredString(call.Args, "body")
	if err != nil {
		return connectors.Result{}, err
	}
	parent, err := optionalString(call.Args, "parent_comment_id")
	if err != nil {
		return connectors.Result{}, err
	}
	req := map[string]any{"body": map[string]string{"representation": "storage", "value": storageBody(body, call.OperationID)}}
	if parent = strings.TrimSpace(parent); parent != "" {
		if !pageIDRE.MatchString(parent) {
			return connectors.Result{}, invalid("parent_comment_id must be a comment id (digits)")
		}
		req["parentCommentId"] = parent
	} else {
		req["pageId"] = id
	}
	var created wirePageComment
	if err := c.classifyWrite("add page comment", s.postJSON(ctx, s.wikiURL("api/v2/footer-comments", nil), req, &created)); err != nil {
		return connectors.Result{}, err
	}
	if created.ID == "" {
		return connectors.Result{}, fmt.Errorf("%w: add page comment: Atlassian answered without a comment id", connectors.ErrOutcomeUnknown)
	}
	return connectors.Result{Content: map[string]string{"id": created.ID, "page": id, "url": wikiURL(s.site, created.Links["webui"])}}, nil
}

func (c *Connector) addPageLabels(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	id, err := pageIDArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	labels, err := labelsArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	type label struct {
		Prefix string `json:"prefix"`
		Name   string `json:"name"`
	}
	req := make([]label, 0, len(labels))
	for _, l := range labels {
		req = append(req, label{Prefix: "global", Name: l})
	}
	if err := c.classifyWrite("add labels", s.postJSON(ctx, s.wikiURL("rest/api/content/"+id+"/label", nil), req, nil)); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: map[string]string{"page": id, "labels": strings.Join(labels, ",")}}, nil
}

// --- reconciliation --------------------------------------------------------------------------------

func identityPage(in connectors.ReconcileInput) (string, error) {
	id := in.ResourceIdentity["page"]
	if !pageIDRE.MatchString(id) {
		return "", fmt.Errorf("%w: resource identity has no page id", ErrNotReconcilable)
	}
	return id, nil
}

// checkUpdatedPage: the page's current body carries the marker.
func (c *Connector) checkUpdatedPage(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	id, err := identityPage(in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	tg, err := c.target(ctx, in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	var p wirePage
	if err := c.classify("reconcile: get page", tg.getJSON(ctx, tg.wikiURL("api/v2/pages/"+id, url.Values{"body-format": {"storage"}}), &p)); err != nil {
		return connectors.ReconcileResult{}, err
	}
	if p.Body != nil && p.Body.Storage != nil && hasMarker(p.Body.Storage.Value, tg.operationID) {
		return found(id), nil
	}
	return notFound, nil
}

// checkPageComment walks the page's footer comments (or the parent's
// replies), newest first, bounded by MaxReconcilePages, for the marker.
func (c *Connector) checkPageComment(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	id, err := identityPage(in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	path := "api/v2/pages/" + id + "/footer-comments"
	if p := in.ResourceIdentity["parent_comment"]; p != "" {
		if !pageIDRE.MatchString(p) {
			return connectors.ReconcileResult{}, fmt.Errorf("%w: bad parent comment id", ErrNotReconcilable)
		}
		path = "api/v2/footer-comments/" + p + "/children"
	}
	tg, err := c.target(ctx, in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	cursor := ""
	for page := 1; page <= MaxReconcilePages; page++ {
		q := url.Values{"body-format": {"storage"}, "sort": {"-created-date"}, "limit": {strconv.Itoa(reconcilePageSize)}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var res wirePageComments
		if err := c.classify("reconcile: list comments", tg.getJSON(ctx, tg.wikiURL(path, q), &res)); err != nil {
			return connectors.ReconcileResult{}, err
		}
		for _, cm := range res.Results {
			if cm.ID != "" && hasMarker(cm.storage(), tg.operationID) {
				return found(cm.ID), nil
			}
		}
		if cursor = nextCursor(res.Links["next"]); cursor == "" || len(res.Results) == 0 {
			return notFound, nil
		}
	}
	return connectors.ReconcileResult{}, fmt.Errorf("atlassian: reconcile: more than %d pages of comments on page %s; cannot tell yet", MaxReconcilePages, id)
}

// checkPageLabels: every label of the identity is on the page.
func (c *Connector) checkPageLabels(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	id, err := identityPage(in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	want := in.ResourceIdentity["labels"]
	if want == "" {
		return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no labels", ErrNotReconcilable)
	}
	tg, err := c.target(ctx, in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	have := map[string]bool{}
	cursor := ""
	for page := 1; ; page++ {
		if page > MaxReconcilePages {
			return connectors.ReconcileResult{}, fmt.Errorf("atlassian: reconcile: more than %d pages of labels on page %s; cannot tell yet", MaxReconcilePages, id)
		}
		q := url.Values{"limit": {strconv.Itoa(reconcilePageSize)}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var res wireLabels
		if err := c.classify("reconcile: list labels", tg.getJSON(ctx, tg.wikiURL("api/v2/pages/"+id+"/labels", q), &res)); err != nil {
			return connectors.ReconcileResult{}, err
		}
		for _, l := range res.Results {
			have[strings.ToLower(l.Name)] = true
		}
		if cursor = nextCursor(res.Links["next"]); cursor == "" || len(res.Results) == 0 {
			break
		}
	}
	for _, l := range strings.Split(want, ",") {
		if !have[l] {
			return notFound, nil
		}
	}
	return found(id), nil
}
