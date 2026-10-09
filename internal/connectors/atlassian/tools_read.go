package atlassian

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Read tool names.
const (
	ToolSearchIssues    = "search_issues"
	ToolGetIssue        = "get_issue"
	ToolListTransitions = "list_transitions"
	ToolSearch          = "search"
	ToolGetPage         = "get_page"
)

// Atlassian OAuth 2.0 (3LO) scopes the tools need (docs/vendor-apps.md
// section 3), declared as RequiredScopes.
const (
	ScopeJiraRead         = "read:jira-work"
	ScopeJiraWrite        = "write:jira-work"
	ScopeConfluenceSearch = "search:confluence"
	ScopePageRead         = "read:page:confluence"
	ScopePageWrite        = "write:page:confluence"
)

// maxPageSize is the ceiling of maxResults / limit on the endpoints used.
const maxPageSize = 100

// defaultPageSize is the page size when the harness gives none.
const defaultPageSize = 10

// Argument shapes.
var (
	issueKeyRE   = regexp.MustCompile(`^[A-Z][A-Z0-9_]*-[1-9][0-9]*$`)
	projectKeyRE = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	spaceKeyRE   = regexp.MustCompile(`^[~A-Za-z0-9_.-]+$`)
	pageIDRE     = regexp.MustCompile(`^[1-9][0-9]*$`)
)

// issueFieldNames are the Jira fields search_issues and get_issue request
// and return; "fields" may name a subset of them.
var issueFieldNames = []string{"summary", "status", "issuetype", "priority", "assignee", "reporter", "labels", "created", "updated", "project"}

// issueDetailFieldNames adds what get_issue returns on top.
var issueDetailFieldNames = append([]string{"description", "components", "resolution"}, issueFieldNames...)

// readTools declares the app's read tools.
func (c *Connector) readTools() []connectors.Tool {
	paged := connectors.Bounds{MaxPageSize: c.bounds.MaxPageSize, MaxResultBytes: c.bounds.MaxResultBytes}
	single := connectors.Bounds{MaxResultBytes: c.bounds.MaxResultBytes}
	if c.app == ConfluenceApp {
		return []connectors.Tool{
			{
				App: ConfluenceApp, Name: ToolSearch, Kind: connectors.KindRead,
				Description: "Search Confluence content with CQL (Confluence Query Language), for example " +
					`space = DOCS AND type = page AND text ~ "release notes". Results list id, type, title, space and url per item; ` +
					"use get_page for a page's body. Paginated with start and limit; has_more says whether another page exists.",
				InputSchema: objectSchema([]property{
					{"cql", "string", "CQL query.", nil},
					{"limit", "integer", "Results per page (1-100); clamped to the tool's maximum.", nil},
					{"start", "integer", "Offset of the first result, starting at 0.", nil},
				}, []string{"cql"}),
				RequiredScopes:   []string{ScopeConfluenceSearch},
				ResourceIdentity: confluenceIdentity,
				Bounds:           paged,
			},
			{
				App: ConfluenceApp, Name: ToolGetPage, Kind: connectors.KindRead,
				Description: "Get one Confluence page by id: title, status, space id, parent id, version and the body in Confluence " +
					"storage format (XHTML). Long bodies are cut to the result bounds (truncated: true).",
				InputSchema:      objectSchema([]property{{"id", "string", "The page id (digits).", nil}}, []string{"id"}),
				RequiredScopes:   []string{ScopePageRead},
				ResourceIdentity: confluenceIdentity,
				Bounds:           single,
			},
		}
	}
	return []connectors.Tool{
		{
			App: JiraApp, Name: ToolSearchIssues, Kind: connectors.KindRead,
			Description: "Search Jira issues with JQL, for example project = ABC AND status = \"In Progress\" ORDER BY updated DESC. " +
				"Each hit lists key, summary, status, issue type, priority, assignee, reporter, labels, dates and url; " +
				"fields narrows that to a subset. Paginated: pass next_page_token from the previous page; has_more says whether one exists.",
			InputSchema: objectSchema([]property{
				{"jql", "string", "JQL query.", nil},
				{"max_results", "integer", "Results per page (1-100); clamped to the tool's maximum.", nil},
				{"fields", "array", "Subset of the fields to return: " + strings.Join(issueFieldNames, ", ") + ". All of them when omitted.", nil},
				{"next_page_token", "string", "Token of the next page, from the previous result.", nil},
			}, []string{"jql"}),
			RequiredScopes:   []string{ScopeJiraRead},
			ResourceIdentity: jiraIdentity,
			Bounds:           paged,
		},
		{
			App: JiraApp, Name: ToolGetIssue, Kind: connectors.KindRead,
			Description: "Get one Jira issue by key (ABC-123): summary, description as plain text, status, issue type, priority, " +
				"assignee, reporter, labels, components, resolution, dates and url. Long descriptions are cut to the result bounds (truncated: true).",
			InputSchema: objectSchema([]property{
				{"key", "string", "The issue key, like ABC-123.", nil},
				{"fields", "array", "Subset of the fields to return: " + strings.Join(issueDetailFieldNames, ", ") + ". All of them when omitted.", nil},
			}, []string{"key"}),
			RequiredScopes:   []string{ScopeJiraRead},
			ResourceIdentity: jiraIdentity,
			Bounds:           single,
		},
		{
			App: JiraApp, Name: ToolListTransitions, Kind: connectors.KindRead,
			Description: "List the workflow transitions a Jira issue can take from its current status: id, name and the status it leads to. " +
				"Pass a transition's id to transition_issue.",
			InputSchema:      objectSchema([]property{{"key", "string", "The issue key, like ABC-123.", nil}}, []string{"key"}),
			RequiredScopes:   []string{ScopeJiraRead},
			ResourceIdentity: jiraIdentity,
			Bounds:           single,
		},
	}
}

// readHandlers maps short tool names to their implementation.
func (c *Connector) readHandlers() map[string]handler {
	if c.app == ConfluenceApp {
		return map[string]handler{ToolSearch: c.search, ToolGetPage: c.getPage}
	}
	return map[string]handler{ToolSearchIssues: c.searchIssues, ToolGetIssue: c.getIssue, ToolListTransitions: c.listTransitions}
}

// --- schema helpers ----------------------------------------------------------

// property is one input-schema property: name, type, description and
// optional enum values.
type property struct {
	Name, Type, Description string
	Enum                    []string
}

// objectSchema builds a closed object schema with the given properties
// and required names.
func objectSchema(props []property, required []string) json.RawMessage {
	type schemaProp struct {
		Type        string   `json:"type"`
		Description string   `json:"description"`
		Enum        []string `json:"enum,omitempty"`
		Items       *struct {
			Type string `json:"type"`
		} `json:"items,omitempty"`
		Minimum *int `json:"minimum,omitempty"`
		Maximum *int `json:"maximum,omitempty"`
	}
	properties := map[string]schemaProp{}
	for _, p := range props {
		sp := schemaProp{Type: p.Type, Description: p.Description, Enum: p.Enum}
		switch p.Name {
		case "max_results", "limit":
			one, max := 1, maxPageSize
			sp.Minimum, sp.Maximum = &one, &max
		case "start":
			zero := 0
			sp.Minimum = &zero
		}
		if p.Type == "array" {
			sp.Items = &struct {
				Type string `json:"type"`
			}{Type: "string"}
		}
		properties[p.Name] = sp
	}
	schema := map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
	if len(required) > 0 {
		schema["required"] = required
	}
	b, err := json.Marshal(schema)
	if err != nil {
		panic(err)
	}
	return b
}

// --- resource identity ----------------------------------------------------------

// jiraIdentity extracts project and issue from the arguments: the issue
// key (upper-cased) and its project prefix, the project_key argument, or
// the project of a JQL "project = KEY" clause when the query has exactly
// one; never argument content.
func jiraIdentity(args map[string]any) map[string]string {
	out := map[string]string{}
	if key, ok := issueKeyArg(args["key"]); ok {
		out["issue"] = key
		out["project"] = key[:strings.IndexByte(key, '-')]
	}
	if p, _ := args["project_key"].(string); p != "" {
		if p = strings.ToUpper(strings.TrimSpace(p)); projectKeyRE.MatchString(p) {
			out["project"] = p
		}
	}
	if jql, _ := args["jql"].(string); jql != "" && out["project"] == "" {
		if p := projectFromJQL(jql); p != "" {
			out["project"] = p
		}
	}
	return out
}

// confluenceIdentity extracts space (the space_key argument, or the space
// of a CQL "space = KEY" clause when the query has exactly one) and page
// (the id argument); never argument content.
func confluenceIdentity(args map[string]any) map[string]string {
	out := map[string]string{}
	if id, _ := args["id"].(string); id != "" {
		if id = strings.TrimSpace(id); pageIDRE.MatchString(id) {
			out["page"] = id
		}
	}
	if s, _ := args["space_key"].(string); s != "" {
		if s = strings.TrimSpace(s); spaceKeyRE.MatchString(s) {
			out["space"] = s
		}
	}
	if cql, _ := args["cql"].(string); cql != "" && out["space"] == "" {
		if s := spaceFromCQL(cql); s != "" {
			out["space"] = s
		}
	}
	return out
}

// issueKeyArg normalises an issue key argument (upper-cased, trimmed).
func issueKeyArg(v any) (string, bool) {
	s, _ := v.(string)
	s = strings.ToUpper(strings.TrimSpace(s))
	if !issueKeyRE.MatchString(s) {
		return "", false
	}
	return s, true
}

// projectFromJQL returns the project key of the query's single
// "project = KEY" clause (bare or quoted), "" when there is none, more
// than one mention of the project field, another operator, or a value
// that is not a project key.
func projectFromJQL(jql string) string {
	return singleEquals(jql, "project", func(s string) bool { return projectKeyRE.MatchString(strings.ToUpper(s)) }, strings.ToUpper)
}

// spaceFromCQL returns the space key of the query's single "space = KEY"
// clause, with the same rules as projectFromJQL.
func spaceFromCQL(cql string) string {
	return singleEquals(cql, "space", spaceKeyRE.MatchString, func(s string) string { return s })
}

// singleEquals tokenises a JQL/CQL query and returns the normalised value
// of "field = value" when the field is mentioned exactly once, with "=",
// and the value passes valid.
func singleEquals(q, field string, valid func(string) bool, norm func(string) string) string {
	toks := tokenize(q)
	idx := -1
	for i, t := range toks {
		if !t.quoted && strings.EqualFold(t.text, field) {
			if idx >= 0 {
				return ""
			}
			idx = i
		}
	}
	if idx < 0 || idx+2 >= len(toks) || toks[idx+1].quoted || toks[idx+1].text != "=" {
		return ""
	}
	v := toks[idx+2]
	// A personal Confluence space key starts with "~", which the tokenizer
	// reads as the contains operator: glue it back to the word after it.
	if !v.quoted && v.text == "~" && idx+3 < len(toks) && !toks[idx+3].quoted && !isOperator(toks[idx+3].text) {
		v = token{text: "~" + toks[idx+3].text}
	}
	if v.text == "" || !valid(v.text) || (!v.quoted && isOperator(v.text)) {
		return ""
	}
	return norm(v.text)
}

// token is one JQL/CQL token: a word, an operator or a quoted string.
type token struct {
	text   string
	quoted bool
}

// tokenize splits a query into words, operators and quoted strings.
func tokenize(q string) []token {
	var toks []token
	runes := []rune(q)
	for i := 0; i < len(runes); {
		r := runes[i]
		switch {
		case r == ' ' || r == '\t' || r == '\n' || r == '\r':
			i++
		case r == '"' || r == '\'':
			quote := r
			var b strings.Builder
			i++
			for i < len(runes) && runes[i] != quote {
				if runes[i] == '\\' && i+1 < len(runes) {
					i++
				}
				b.WriteRune(runes[i])
				i++
			}
			i++ // the closing quote (or the end)
			toks = append(toks, token{text: b.String(), quoted: true})
		case strings.ContainsRune("=!<>~(),", r):
			op := string(r)
			if (r == '!' || r == '<' || r == '>') && i+1 < len(runes) && (runes[i+1] == '=' || runes[i+1] == '~') {
				op += string(runes[i+1])
				i++
			}
			i++
			toks = append(toks, token{text: op})
		default:
			start := i
			for i < len(runes) && !strings.ContainsRune(" \t\n\r\"'=!<>~(),", runes[i]) {
				i++
			}
			toks = append(toks, token{text: string(runes[start:i])})
		}
	}
	return toks
}

func isOperator(s string) bool {
	switch s {
	case "=", "!=", "<", ">", "<=", ">=", "~", "!~", "(", ")", ",":
		return true
	}
	return false
}

// --- argument helpers ---------------------------------------------------------

// keyArg reads and validates the "key" argument (an issue key).
func keyArg(args map[string]any) (string, error) {
	key, ok := issueKeyArg(args["key"])
	if !ok {
		return "", invalid("key is required: a Jira issue key like ABC-123")
	}
	return key, nil
}

// requiredString reads a non-blank string argument.
func requiredString(args map[string]any, name string) (string, error) {
	v, _ := args[name].(string)
	v = strings.TrimSpace(v)
	if v == "" {
		return "", invalid("%s is required", name)
	}
	return v, nil
}

// optionalString reads a string argument, "" when absent.
func optionalString(args map[string]any, name string) (string, error) {
	v, ok := args[name]
	if !ok || v == nil {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", invalid("%s must be a string", name)
	}
	return s, nil
}

// stringList reads an optional array-of-strings argument; blank entries
// are dropped and nil is returned when nothing remains.
func stringList(args map[string]any, name string) ([]string, error) {
	v, ok := args[name]
	if !ok || v == nil {
		return nil, nil
	}
	var out []string
	switch list := v.(type) {
	case []string:
		out = append(out, list...)
	case []any:
		for _, item := range list {
			s, ok := item.(string)
			if !ok {
				return nil, invalid("%s must be an array of strings", name)
			}
			out = append(out, s)
		}
	default:
		return nil, invalid("%s must be an array of strings", name)
	}
	kept := out[:0]
	for _, s := range out {
		if s = strings.TrimSpace(s); s != "" {
			kept = append(kept, s)
		}
	}
	if len(kept) == 0 {
		return nil, nil
	}
	return kept, nil
}

// fieldsArg reads the optional "fields" subset, validated against allowed;
// nil means all of them.
func fieldsArg(args map[string]any, allowed []string) ([]string, error) {
	list, err := stringList(args, "fields")
	if err != nil || list == nil {
		return nil, err
	}
	for _, f := range list {
		found := false
		for _, a := range allowed {
			if strings.EqualFold(f, a) {
				found = true
				break
			}
		}
		if !found {
			return nil, invalid("fields: %q is not one of %s", f, strings.Join(allowed, ", "))
		}
	}
	return list, nil
}

// pageSizeArg reads the page-size argument (max_results or limit),
// defaulting to defaultPageSize and clamped to the bounds (clamped
// reports when it was).
func (c *Connector) pageSizeArg(args map[string]any, name string) (size int, clamped bool, err error) {
	size = min(defaultPageSize, c.bounds.MaxPageSize)
	v, ok := args[name]
	if !ok || v == nil {
		return size, false, nil
	}
	if size, err = toInt(v); err != nil || size < 1 {
		return 0, false, invalid("%s must be a positive integer", name)
	}
	if size > c.bounds.MaxPageSize {
		size, clamped = c.bounds.MaxPageSize, true
	}
	return size, clamped, nil
}

func toInt(v any) (int, error) {
	switch n := v.(type) {
	case int:
		return n, nil
	case int64:
		return int(n), nil
	case float64:
		if n != math.Trunc(n) || math.IsInf(n, 0) || math.IsNaN(n) {
			return 0, errors.New("not an integer")
		}
		return int(n), nil
	case json.Number:
		i, err := n.Int64()
		return int(i), err
	case string:
		return strconv.Atoi(strings.TrimSpace(n))
	}
	return 0, fmt.Errorf("not an integer: %T", v)
}

// --- handlers: jira ------------------------------------------------------------------

func (c *Connector) searchIssues(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	jql, err := requiredString(call.Args, "jql")
	if err != nil {
		return connectors.Result{}, invalid("jql is required: a Jira JQL query")
	}
	size, clamped, err := c.pageSizeArg(call.Args, "max_results")
	if err != nil {
		return connectors.Result{}, err
	}
	fields, err := fieldsArg(call.Args, issueFieldNames)
	if err != nil {
		return connectors.Result{}, err
	}
	if fields == nil {
		fields = issueFieldNames
	}
	token, err := optionalString(call.Args, "next_page_token")
	if err != nil {
		return connectors.Result{}, err
	}
	q := url.Values{"jql": {jql}, "maxResults": {strconv.Itoa(size)}, "fields": {strings.Join(fields, ",")}}
	if token = strings.TrimSpace(token); token != "" {
		q.Set("nextPageToken", token)
	}
	var page wireSearch
	if err := c.classify("search issues", s.getJSON(ctx, s.jiraURL("search/jql", q), &page)); err != nil {
		return connectors.Result{}, err
	}
	out := IssuePage{Issues: make([]IssueSummary, 0, len(page.Issues)), MaxResults: size, NextPageToken: page.NextPageToken}
	out.HasMore = page.NextPageToken != "" || (page.IsLast != nil && !*page.IsLast)
	for _, is := range page.Issues {
		out.Issues = append(out.Issues, toIssueSummary(is, s.site))
	}
	res := connectors.Result{Partial: clamped, Empty: len(out.Issues) == 0}
	for encodedSize(out) > c.bounds.MaxResultBytes && len(out.Issues) > 1 {
		out.Issues = out.Issues[:len(out.Issues)-1]
		out.Truncated, res.Partial = true, true
	}
	res.Content = out
	return res, nil
}

func (c *Connector) getIssue(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	key, err := keyArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	fields, err := fieldsArg(call.Args, issueDetailFieldNames)
	if err != nil {
		return connectors.Result{}, err
	}
	if fields == nil {
		fields = issueDetailFieldNames
	}
	var is wireIssue
	if err := c.classify("get issue", s.getJSON(ctx, s.jiraURL("issue/"+key, url.Values{"fields": {strings.Join(fields, ",")}}), &is)); err != nil {
		return connectors.Result{}, err
	}
	if is.Key == "" {
		is.Key = key
	}
	out := toIssue(is, s.site)
	fitBody(&out.Description, &out.Truncated, c.bounds.MaxResultBytes, func() any { return out })
	return connectors.Result{Content: out, Partial: out.Truncated}, nil
}

func (c *Connector) listTransitions(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	key, err := keyArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	var page wireTransitions
	if err := c.classify("list transitions", s.getJSON(ctx, s.jiraURL("issue/"+key+"/transitions", nil), &page)); err != nil {
		return connectors.Result{}, err
	}
	out := Transitions{Issue: key, Transitions: make([]Transition, 0, len(page.Transitions))}
	for _, tr := range page.Transitions {
		out.Transitions = append(out.Transitions, Transition{ID: tr.ID, Name: tr.Name, To: tr.To.label()})
	}
	res := connectors.Result{Empty: len(out.Transitions) == 0}
	for encodedSize(out) > c.bounds.MaxResultBytes && len(out.Transitions) > 1 {
		out.Transitions = out.Transitions[:len(out.Transitions)-1]
		res.Partial = true
	}
	res.Content = out
	return res, nil
}

// --- handlers: confluence ------------------------------------------------------------

func (c *Connector) search(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	cql, err := requiredString(call.Args, "cql")
	if err != nil {
		return connectors.Result{}, invalid("cql is required: a Confluence CQL query")
	}
	limit, clamped, err := c.pageSizeArg(call.Args, "limit")
	if err != nil {
		return connectors.Result{}, err
	}
	start := 0
	if v, ok := call.Args["start"]; ok && v != nil {
		if start, err = toInt(v); err != nil || start < 0 {
			return connectors.Result{}, invalid("start must be a non-negative integer")
		}
	}
	q := url.Values{"cql": {cql}, "limit": {strconv.Itoa(limit)}, "start": {strconv.Itoa(start)}, "expand": {"space,version"}}
	var page wireContentSearch
	if err := c.classify("search content", s.getJSON(ctx, s.wikiURL("rest/api/content/search", q), &page)); err != nil {
		return connectors.Result{}, err
	}
	out := ContentPage{Results: make([]ContentSummary, 0, len(page.Results)), Start: start, Limit: limit, Size: len(page.Results), HasMore: page.Links["next"] != ""}
	for _, ct := range page.Results {
		out.Results = append(out.Results, toContentSummary(ct, s.site))
	}
	res := connectors.Result{Partial: clamped, Empty: len(out.Results) == 0}
	for encodedSize(out) > c.bounds.MaxResultBytes && len(out.Results) > 1 {
		out.Results = out.Results[:len(out.Results)-1]
		out.Truncated, res.Partial = true, true
	}
	res.Content = out
	return res, nil
}

func (c *Connector) getPage(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	id, _ := call.Args["id"].(string)
	if id = strings.TrimSpace(id); !pageIDRE.MatchString(id) {
		return connectors.Result{}, invalid("id is required: the page id (digits)")
	}
	var p wirePage
	if err := c.classify("get page", s.getJSON(ctx, s.wikiURL("api/v2/pages/"+id, url.Values{"body-format": {"storage"}}), &p)); err != nil {
		return connectors.Result{}, err
	}
	if p.ID == "" {
		p.ID = id
	}
	out := toPage(p, s.site)
	fitBody(&out.Body, &out.Truncated, c.bounds.MaxResultBytes, func() any { return out })
	return connectors.Result{Content: out, Partial: out.Truncated}, nil
}
