package atlassian

import (
	"context"
	"net/url"
	"strconv"
	"strings"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// The last small gaps with Atlassian's Rovo MCP server (v2 tool list):
// an issue's remote (web) links and adding one, a user by account id,
// a project's statuses per issue type, saved filters, and the pages of
// a Confluence space.

// Gap-closing tool names.
const (
	ToolListRemoteLinks      = "list_remote_links"
	ToolAddRemoteLink        = "add_remote_link"
	ToolGetUser              = "get_user"
	ToolListProjectStatuses  = "list_project_statuses"
	ToolListFilters          = "list_filters"
	ToolListSpacePages       = "list_space_pages"
	maxRemoteLinkURL         = 2048
	maxRemoteLinkTitle       = 255
	spacePageDepthValues     = "all,root"
	remoteLinkGlobalIDPrefix = "mcp-gateway op:"
)

func (c *Connector) jiraGapReadTools() []connectors.Tool {
	paged := connectors.Bounds{MaxPageSize: c.bounds.MaxPageSize, MaxResultBytes: c.bounds.MaxResultBytes}
	single := connectors.Bounds{MaxResultBytes: c.bounds.MaxResultBytes}
	work := []string{ScopeJiraRead}
	tool := func(name, desc string, props []property, required []string, scopes []string, b connectors.Bounds) connectors.Tool {
		return connectors.Tool{App: JiraApp, Name: name, Kind: connectors.KindRead, Description: desc, InputSchema: objectSchema(props, required),
			RequiredScopes: scopes, ResourceIdentity: jiraIdentity, Bounds: b}
	}
	return []connectors.Tool{
		tool(ToolListRemoteLinks, "List the remote (web) links of a Jira issue, such as Confluence pages or external URLs: id, title, url, "+
			"summary, relationship and application.", []property{keyProp}, []string{"key"}, work, single),
		tool(ToolGetUser, "Get a Jira user by account id: display name, email (when visible), time zone, active, account type.",
			[]property{{"account_id", "string", "Atlassian account id.", nil}}, []string{"account_id"}, []string{ScopeJiraUser}, single),
		tool(ToolListProjectStatuses, "List the statuses of a Jira project per issue type: status id, name and category (To Do, In Progress, Done). "+
			"Use the names in JQL (status = \"In Review\").", []property{projectKeyProp}, []string{"project_key"}, work, single),
		tool(ToolListFilters, "List the saved Jira filters this account can see: id, name, description, owner, favourite and JQL, optionally "+
			"matching a name. Run one with search_issues and its JQL. Paginated with start_at.",
			withPaging(property{"name", "string", "Filter on filter name (contains).", nil}), nil, work, paged),
	}
}

func (c *Connector) jiraGapWriteTools() []connectors.Tool {
	return []connectors.Tool{{
		App: JiraApp, Name: ToolAddRemoteLink, Kind: connectors.KindWrite,
		Description: "Add a remote (web) link to a Jira issue (by key): an http(s) URL with a title and optional summary, " +
			"for example a Confluence page or a pull request. Returns the link id.",
		InputSchema: objectSchema([]property{keyProp, {"url", "string", "The http or https URL.", nil}, {"title", "string", "Link title.", nil},
			{"summary", "string", "Optional summary.", nil}}, []string{"key", "url", "title"}),
		RequiredScopes:   []string{ScopeJiraWrite},
		ResourceIdentity: jiraIdentity,
		Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileMarker, Check: c.checkRemoteLink},
		ResultIDs:        func(res connectors.Result) map[string]string { return contentMap(res) },
		Bounds:           connectors.Bounds{MaxResultBytes: c.bounds.MaxResultBytes},
	}}
}

func (c *Connector) confluenceGapReadTools() []connectors.Tool {
	return []connectors.Tool{{
		App: ConfluenceApp, Name: ToolListSpacePages, Kind: connectors.KindRead,
		Description: "List the pages of a Confluence space (by key): id, title, status, parent position. depth root lists only the " +
			"top-level pages. Paginated: pass next_cursor as cursor.",
		InputSchema: objectSchema(withCursor(property{"space_key", "string", "Key of the space.", nil},
			property{"depth", "string", "all (default) or root.", strings.Split(spacePageDepthValues, ",")}), []string{"space_key"}),
		RequiredScopes:   []string{ScopePageRead, ScopeSpaceRead},
		ResourceIdentity: confluenceIdentity,
		Bounds:           connectors.Bounds{MaxPageSize: c.bounds.MaxPageSize, MaxResultBytes: c.bounds.MaxResultBytes},
	}}
}

func (c *Connector) jiraGapHandlers(write bool) map[string]handler {
	if write {
		return map[string]handler{ToolAddRemoteLink: c.addRemoteLink}
	}
	return map[string]handler{
		ToolListRemoteLinks: c.listRemoteLinks, ToolGetUser: c.getUser, ToolListProjectStatuses: c.listProjectStatuses, ToolListFilters: c.listFilters,
	}
}

// RemoteLinkView is one remote link of list_remote_links.
type RemoteLinkView struct {
	ID           int    `json:"id"`
	GlobalID     string `json:"global_id,omitempty"`
	Title        string `json:"title"`
	URL          string `json:"url"`
	Summary      string `json:"summary,omitempty"`
	Relationship string `json:"relationship,omitempty"`
	Application  string `json:"application,omitempty"`
}

// StatusView is one status of list_project_statuses.
type StatusView struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category,omitempty"`
}

// IssueTypeStatuses is the statuses of one issue type.
type IssueTypeStatuses struct {
	IssueType string       `json:"issue_type"`
	Subtask   bool         `json:"subtask"`
	Statuses  []StatusView `json:"statuses"`
}

// FilterView is one saved filter of list_filters.
type FilterView struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Owner       string `json:"owner,omitempty"`
	Favourite   bool   `json:"favourite"`
	JQL         string `json:"jql,omitempty"`
}

type wireRemoteLink struct {
	ID           int    `json:"id"`
	GlobalID     string `json:"globalId"`
	Relationship string `json:"relationship"`
	Application  struct {
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"application"`
	Object struct {
		URL     string `json:"url"`
		Title   string `json:"title"`
		Summary string `json:"summary"`
	} `json:"object"`
}

func (c *Connector) listRemoteLinks(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	key, err := keyArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	var links []wireRemoteLink
	if err := c.classify("list remote links", s.getJSON(ctx, s.jiraURL("issue/"+key+"/remotelink", nil), &links)); err != nil {
		return connectors.Result{}, err
	}
	out := struct {
		Issue     string           `json:"issue"`
		Links     []RemoteLinkView `json:"links"`
		Truncated bool             `json:"truncated,omitempty"`
	}{Issue: key, Links: make([]RemoteLinkView, 0, len(links))}
	for _, l := range links {
		app := l.Application.Name
		if app == "" {
			app = l.Application.Type
		}
		out.Links = append(out.Links, RemoteLinkView{ID: l.ID, GlobalID: l.GlobalID, Title: l.Object.Title, URL: l.Object.URL,
			Summary: l.Object.Summary, Relationship: l.Relationship, Application: app})
	}
	out.Truncated = fitList(&out.Links, c.bounds.MaxResultBytes, func() any { return out })
	return listResult(out, len(out.Links), out.Truncated), nil
}

func (c *Connector) getUser(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	id, ok := accountIDArg(call.Args["account_id"])
	if !ok {
		return connectors.Result{}, invalid("account_id is required: an Atlassian account id")
	}
	var u wireUser
	if err := c.classify("get user", s.getJSON(ctx, s.jiraURL("user", url.Values{"accountId": {id}}), &u)); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: u.view()}, nil
}

func (c *Connector) listProjectStatuses(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	project, err := projectKeyArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	var types []struct {
		Name     string `json:"name"`
		Subtask  bool   `json:"subtask"`
		Statuses []struct {
			ID             string `json:"id"`
			Name           string `json:"name"`
			StatusCategory struct {
				Name string `json:"name"`
			} `json:"statusCategory"`
		} `json:"statuses"`
	}
	if err := c.classify("list project statuses", s.getJSON(ctx, s.jiraURL("project/"+project+"/statuses", nil), &types)); err != nil {
		return connectors.Result{}, err
	}
	out := struct {
		Project    string              `json:"project"`
		IssueTypes []IssueTypeStatuses `json:"issue_types"`
		Truncated  bool                `json:"truncated,omitempty"`
	}{Project: project, IssueTypes: make([]IssueTypeStatuses, 0, len(types))}
	for _, t := range types {
		v := IssueTypeStatuses{IssueType: t.Name, Subtask: t.Subtask, Statuses: make([]StatusView, 0, len(t.Statuses))}
		for _, st := range t.Statuses {
			v.Statuses = append(v.Statuses, StatusView{ID: st.ID, Name: st.Name, Category: st.StatusCategory.Name})
		}
		out.IssueTypes = append(out.IssueTypes, v)
	}
	out.Truncated = fitList(&out.IssueTypes, c.bounds.MaxResultBytes, func() any { return out })
	return listResult(out, len(out.IssueTypes), out.Truncated), nil
}

func (c *Connector) listFilters(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	size, clamped, start, err := c.offsetArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	name, err := optionalString(call.Args, "name")
	if err != nil {
		return connectors.Result{}, err
	}
	q := offsetQuery(size, start)
	q.Set("expand", "description,favourite,jql,owner")
	q.Set("orderBy", "name")
	if name = strings.TrimSpace(name); name != "" {
		q.Set("filterName", name)
	}
	var res struct {
		wirePaged
		Values []struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			Description string `json:"description"`
			Owner       *named `json:"owner"`
			Favourite   bool   `json:"favourite"`
			JQL         string `json:"jql"`
		} `json:"values"`
	}
	if err := c.classify("list filters", s.getJSON(ctx, s.jiraURL("filter/search", q), &res)); err != nil {
		return connectors.Result{}, err
	}
	out := struct {
		Filters []FilterView `json:"filters"`
		Paging
	}{Filters: make([]FilterView, 0, len(res.Values)), Paging: res.paging(start, size, len(res.Values))}
	for _, f := range res.Values {
		out.Filters = append(out.Filters, FilterView{ID: f.ID, Name: f.Name, Description: f.Description, Owner: f.Owner.label(), Favourite: f.Favourite, JQL: f.JQL})
	}
	out.Truncated = fitList(&out.Filters, c.bounds.MaxResultBytes, func() any { return out })
	return listResult(out, len(out.Filters), clamped || out.Truncated), nil
}

// remoteLinkGlobalID is the global id add_remote_link gives the link: a
// repeat of the same operation updates the link instead of adding a
// second one, and reconciliation finds it by this id.
func remoteLinkGlobalID(operationID string) string { return remoteLinkGlobalIDPrefix + operationID }

func (c *Connector) addRemoteLink(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	key, err := keyArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	raw, err := requiredString(call.Args, "url")
	if err != nil {
		return connectors.Result{}, err
	}
	if u, perr := url.Parse(raw); perr != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || len(raw) > maxRemoteLinkURL {
		return connectors.Result{}, invalid("url must be an http or https URL of at most %d characters", maxRemoteLinkURL)
	}
	title, err := requiredString(call.Args, "title")
	if err != nil {
		return connectors.Result{}, err
	}
	if len(title) > maxRemoteLinkTitle {
		return connectors.Result{}, invalid("title must be at most %d characters", maxRemoteLinkTitle)
	}
	summary, err := optionalString(call.Args, "summary")
	if err != nil {
		return connectors.Result{}, err
	}
	object := map[string]any{"url": raw, "title": title}
	if summary = strings.TrimSpace(summary); summary != "" {
		object["summary"] = summary
	}
	req := map[string]any{"globalId": remoteLinkGlobalID(call.OperationID), "object": object}
	var created struct {
		ID int `json:"id"`
	}
	if err := c.classifyWrite("add remote link", s.postJSON(ctx, s.jiraURL("issue/"+key+"/remotelink", nil), req, &created)); err != nil {
		return connectors.Result{}, err
	}
	out := map[string]string{"issue": key, "url": browseURL(s.site, key)}
	if created.ID > 0 {
		out["id"] = strconv.Itoa(created.ID)
	}
	return connectors.Result{Content: out}, nil
}

// checkRemoteLink: the issue has a remote link with the operation's
// global id (found: the link id).
func (c *Connector) checkRemoteLink(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	key, err := identityIssue(in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	tg, err := c.target(ctx, in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	var links []wireRemoteLink
	if err := c.classify("reconcile: list remote links", tg.getJSON(ctx, tg.jiraURL("issue/"+key+"/remotelink", nil), &links)); err != nil {
		return connectors.ReconcileResult{}, err
	}
	want := remoteLinkGlobalID(tg.operationID)
	for _, l := range links {
		if l.GlobalID == want {
			return found(strconv.Itoa(l.ID)), nil
		}
	}
	return notFound, nil
}

func (c *Connector) listSpacePages(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	space, _ := call.Args["space_key"].(string)
	if space = strings.TrimSpace(space); !spaceKeyRE.MatchString(space) {
		return connectors.Result{}, invalid("space_key is required: a Confluence space key like DOCS")
	}
	depth, err := enumArg(call.Args, "depth", spacePageDepthValues)
	if err != nil {
		return connectors.Result{}, err
	}
	q, limit, clamped, err := c.cursorArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	if depth != "" {
		q.Set("depth", depth)
	}
	spaceID, err := c.spaceID(ctx, s, space)
	if err != nil {
		return connectors.Result{}, err
	}
	var page struct {
		Results []struct {
			ID       string `json:"id"`
			Title    string `json:"title"`
			Status   string `json:"status"`
			SpaceID  string `json:"spaceId"`
			ParentID string `json:"parentId"`
			Position *int   `json:"position"`
		} `json:"results"`
		Links map[string]string `json:"_links"`
	}
	if err := c.classify("list space pages", s.getJSON(ctx, s.wikiURL("api/v2/spaces/"+spaceID+"/pages", q), &page)); err != nil {
		return connectors.Result{}, err
	}
	type spacePage struct {
		ChildPageView
		ParentID string `json:"parent_id,omitempty"`
	}
	out := struct {
		Space string      `json:"space"`
		Pages []spacePage `json:"pages"`
		CursorPaging
	}{Space: space, Pages: make([]spacePage, 0, len(page.Results)), CursorPaging: cursorPaging(limit, page.Links)}
	for _, p := range page.Results {
		out.Pages = append(out.Pages, spacePage{ChildPageView: ChildPageView{ID: p.ID, Title: p.Title, Status: p.Status, SpaceID: p.SpaceID, Position: p.Position}, ParentID: p.ParentID})
	}
	out.Truncated = fitList(&out.Pages, c.bounds.MaxResultBytes, func() any { return out })
	return listResult(out, len(out.Pages), clamped || out.Truncated), nil
}
