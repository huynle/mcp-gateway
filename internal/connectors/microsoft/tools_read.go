package microsoft

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/microsoft/graph"
)

// Read tool names.
const (
	ToolMailSearch               = "mail_search"
	ToolMailGetMessage           = "mail_get_message"
	ToolCalendarListEvents       = "calendar_list_events"
	ToolDriveSearch              = "drive_search"
	ToolTeamsListChannels        = "teams_list_channels"
	ToolTeamsReadChannelMessages = "teams_read_channel_messages"
)

// maxTop is the largest page any tool asks Graph for; channel messages
// are capped lower by Graph itself (maxChannelMessagesTop).
const (
	maxTop                 = 100
	maxChannelMessagesTop  = 50
	defaultTop             = 25
	maxCalendarWindow      = 366 * 24 * time.Hour
	maxIDLength            = 1024
	maxQueryLength         = 1024
	maxFilterLength        = 2048
	calendarDefaultName    = "default"
	driveDefaultName       = "me"
	preferTextBody         = `outlook.body-content-type="text"`
	preferUTC              = `outlook.timezone="UTC"`
	messageSelect          = "id,subject,from,receivedDateTime,bodyPreview,isRead,hasAttachments,webLink"
	messageDetailSelect    = "id,subject,from,toRecipients,ccRecipients,receivedDateTime,sentDateTime,isRead,hasAttachments,conversationId,webLink,body"
	eventSelect            = "id,subject,start,end,isAllDay,isCancelled,location,organizer,webLink"
	driveItemSelect        = "id,name,size,webUrl,lastModifiedDateTime,folder,file,parentReference"
	channelSelect          = "id,displayName,description,membershipType,webUrl"
	teamSelect             = "id,displayName,description"
	messagesPath           = "me/messages"
	calendarViewPath       = "me/calendarView"
	joinedTeamsPath        = "me/joinedTeams"
	searchQuoteReplacement = `\"`
)

// idRE is the shape of a Graph identifier (message, event, drive, item,
// team and channel ids; well-known folder names): no path separators,
// query or fragment characters.
var idRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@!=+-]*$`)

// wellKnownFolders are the mail folder names Graph accepts in place of
// an id.
var wellKnownFolders = map[string]bool{
	"inbox": true, "drafts": true, "sentitems": true, "deleteditems": true, "junkemail": true, "archive": true, "outbox": true,
}

// readTools declares the six read tools.
func (c *Connector) readTools() []connectors.Tool {
	paged := connectors.Bounds{MaxPageSize: c.bounds.MaxPageSize, MaxResultBytes: c.bounds.MaxResultBytes}
	single := connectors.Bounds{MaxResultBytes: c.bounds.MaxResultBytes}
	return []connectors.Tool{
		{
			App: App, Name: ToolMailSearch, Kind: connectors.KindRead,
			Description: "Search or list the user's Outlook mail. q is full-text search (KQL: words, \"quoted phrases\", from:name, subject:word, " +
				"hasAttachments:true); filter is an OData $filter (isRead eq false, receivedDateTime ge 2026-01-01T00:00:00Z) and cannot be " +
				"combined with q; neither lists the newest messages. folder limits the search to one mail folder (inbox, sentitems, drafts, " +
				"deleteditems, junkemail, archive, or a folder id). Returns id, subject, sender, received time and a short preview per message; " +
				"use mail_get_message for the body.",
			InputSchema: objectSchema([]property{
				{"q", "string", "Full-text search query (KQL).", nil},
				{"filter", "string", "OData $filter expression; not with q.", nil},
				{"folder", "string", "Mail folder: inbox, sentitems, drafts, deleteditems, junkemail, archive or a folder id. All folders when omitted.", nil},
				topProperty,
			}, nil),
			RequiredScopes:   []string{ScopeMailRead},
			ResourceIdentity: folderIdentity,
			Bounds:           paged,
		},
		{
			App: App, Name: ToolMailGetMessage, Kind: connectors.KindRead,
			Description:      "Get one Outlook message by id: subject, sender, recipients, timestamps and the body as plain text (cut to the result bounds).",
			InputSchema:      objectSchema([]property{{"id", "string", "The message id from mail_search.", nil}}, []string{"id"}),
			RequiredScopes:   []string{ScopeMailRead},
			ResourceIdentity: idIdentity("id", "message"),
			Bounds:           single,
		},
		{
			App: App, Name: ToolCalendarListEvents, Kind: connectors.KindRead,
			Description: "List the user's calendar events between start and end (ISO 8601 timestamps, at most a year apart), expanded from " +
				"recurring series, ordered by start, in UTC. calendar_id picks a calendar other than the default one.",
			InputSchema: objectSchema([]property{
				{"start", "string", "Window start, ISO 8601 (2026-10-08T00:00:00Z).", nil},
				{"end", "string", "Window end, ISO 8601, after start.", nil},
				{"calendar_id", "string", "Calendar id; the default calendar when omitted.", nil},
				topProperty,
			}, []string{"start", "end"}),
			RequiredScopes:   []string{ScopeCalendarsRead},
			ResourceIdentity: calendarIdentity,
			Bounds:           paged,
		},
		{
			App: App, Name: ToolDriveSearch, Kind: connectors.KindRead,
			Description: "Search files and folders by name and content in the user's OneDrive (drive_id picks another drive the user can " +
				"access, such as a SharePoint library). Returns id, name, size, web url and parent per item.",
			InputSchema: objectSchema([]property{
				{"q", "string", "Search text.", nil},
				{"drive_id", "string", "Drive id; the user's OneDrive when omitted.", nil},
				topProperty,
			}, []string{"q"}),
			RequiredScopes:   []string{ScopeFilesReadAll},
			ResourceIdentity: driveIdentity,
			Bounds:           paged,
		},
		{
			App: App, Name: ToolTeamsListChannels, Kind: connectors.KindRead,
			Description: "List the Teams the user has joined with the channels of each (id, name, membership type). team_id limits it to one team. " +
				"Not available on personal Microsoft accounts.",
			InputSchema: objectSchema([]property{
				{"team_id", "string", "Team id; every joined team when omitted.", nil},
				{"top", "integer", "Maximum number of teams (1-100); clamped to the tool's maximum.", nil},
			}, nil),
			RequiredScopes:   []string{ScopeTeamReadBasicAll, ScopeChannelReadBasicAll},
			ResourceIdentity: teamIdentity(false),
			Bounds:           paged,
		},
		{
			App: App, Name: ToolTeamsReadChannelMessages, Kind: connectors.KindRead,
			Description: "Read the newest messages of a Teams channel (id, author, time, content as text or html). Replies are not included. " +
				"Not available on personal Microsoft accounts; needs admin consent (ChannelMessage.Read.All).",
			InputSchema: objectSchema([]property{
				{"team_id", "string", "Team id.", nil},
				{"channel_id", "string", "Channel id.", nil},
				{"top", "integer", "Number of messages (1-50); clamped to the tool's maximum.", nil},
			}, []string{"team_id", "channel_id"}),
			RequiredScopes:   []string{ScopeChannelMessageReadAll},
			ResourceIdentity: teamIdentity(true),
			Bounds:           paged,
		},
	}
}

// handlers maps short tool names to their implementation.
func (c *Connector) handlers() map[string]handler {
	return map[string]handler{
		ToolMailSearch:               c.mailSearch,
		ToolMailGetMessage:           c.mailGetMessage,
		ToolCalendarListEvents:       c.calendarListEvents,
		ToolDriveSearch:              c.driveSearch,
		ToolTeamsListChannels:        c.teamsListChannels,
		ToolTeamsReadChannelMessages: c.teamsReadChannelMessages,
	}
}

// --- schema helpers ----------------------------------------------------------

// property is one input-schema property: name, type, description and
// optional enum values.
type property struct {
	Name, Type, Description string
	Enum                    []string
}

var topProperty = property{"top", "integer", "Number of results (1-100); clamped to the tool's maximum.", nil}

// objectSchema builds a closed object schema with the given properties
// and required names.
func objectSchema(props []property, required []string) json.RawMessage {
	type schemaProp struct {
		Type        string   `json:"type"`
		Description string   `json:"description"`
		Enum        []string `json:"enum,omitempty"`
		Items       any      `json:"items,omitempty"`
		Minimum     *int     `json:"minimum,omitempty"`
		Maximum     *int     `json:"maximum,omitempty"`
	}
	properties := map[string]schemaProp{}
	for _, p := range props {
		sp := schemaProp{Type: p.Type, Description: p.Description, Enum: p.Enum}
		if p.Name == "top" {
			one, max := 1, maxTop
			sp.Minimum, sp.Maximum = &one, &max
		}
		if p.Type == "array" {
			sp.Items = map[string]string{"type": "string"}
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

// --- resource identity ---------------------------------------------------------

// folderIdentity records the mail folder when given (well-known names
// lower-cased; ids as given).
func folderIdentity(args map[string]any) map[string]string {
	out := map[string]string{}
	if f := strings.TrimSpace(stringArg(args, "folder")); f != "" {
		out["folder"] = folderName(f)
	}
	return out
}

// folderName lower-cases a well-known folder name; ids keep their case.
func folderName(f string) string {
	if wellKnownFolders[strings.ToLower(f)] {
		return strings.ToLower(f)
	}
	return f
}

// idIdentity records the argument named key under name when given.
func idIdentity(key, name string) func(map[string]any) map[string]string {
	return func(args map[string]any) map[string]string {
		out := map[string]string{}
		if v := strings.TrimSpace(stringArg(args, key)); v != "" {
			out[name] = v
		}
		return out
	}
}

// calendarIdentity records the calendar: calendar_id, else "default".
func calendarIdentity(args map[string]any) map[string]string {
	cal := strings.TrimSpace(stringArg(args, "calendar_id"))
	if cal == "" {
		cal = calendarDefaultName
	}
	return map[string]string{"calendar": cal}
}

// driveIdentity records the drive: drive_id, else "me".
func driveIdentity(args map[string]any) map[string]string {
	d := strings.TrimSpace(stringArg(args, "drive_id"))
	if d == "" {
		d = driveDefaultName
	}
	return map[string]string{"drive": d}
}

// teamIdentity records team_id under "team" and, when withChannel,
// channel_id under "channel".
func teamIdentity(withChannel bool) func(map[string]any) map[string]string {
	return func(args map[string]any) map[string]string {
		out := map[string]string{}
		if v := strings.TrimSpace(stringArg(args, "team_id")); v != "" {
			out["team"] = v
		}
		if withChannel {
			if v := strings.TrimSpace(stringArg(args, "channel_id")); v != "" {
				out["channel"] = v
			}
		}
		return out
	}
}

// --- argument helpers ---------------------------------------------------------

func stringArg(args map[string]any, name string) string {
	v, _ := args[name].(string)
	return v
}

// idArg reads an optional Graph identifier argument ("" when absent).
func idArg(args map[string]any, name string) (string, error) {
	v, ok := args[name]
	if !ok || v == nil {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", invalid("%s must be a string", name)
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	if len(s) > maxIDLength || !idRE.MatchString(s) {
		return "", invalid("%s is not a valid identifier", name)
	}
	return s, nil
}

// requiredID reads a required Graph identifier argument.
func requiredID(args map[string]any, name string) (string, error) {
	s, err := idArg(args, name)
	if err != nil {
		return "", err
	}
	if s == "" {
		return "", invalid("%s is required", name)
	}
	return s, nil
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

// topArg reads top; it defaults to defaultTop and is clamped to the
// smaller of the bounds and the vendor's own maximum (clamped reports
// when it was).
func (c *Connector) topArg(args map[string]any, vendorMax int) (top int, clamped bool, err error) {
	limit := min(c.bounds.MaxPageSize, vendorMax)
	top = min(defaultTop, limit)
	if v, ok := args["top"]; ok && v != nil {
		if top, err = toInt(v); err != nil || top < 1 {
			return 0, false, invalid("top must be a positive integer")
		}
		if top > limit {
			top, clamped = limit, true
		}
	}
	return top, clamped, nil
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

// timeArg reads an ISO 8601 timestamp argument.
func timeArg(args map[string]any, name string) (time.Time, error) {
	s, err := requiredString(args, name)
	if err != nil {
		return time.Time{}, err
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, invalid("%s must be an ISO 8601 timestamp (2026-10-08T00:00:00Z)", name)
}

// truncateItems drops trailing items (never below one) until the page
// fits max bytes; it reports whether anything was dropped.
func truncateItems[T any](items *[]T, max int, obj func() any) bool {
	truncated := false
	for encodedSize(obj()) > max && len(*items) > 1 {
		*items = (*items)[:len(*items)-1]
		truncated = true
	}
	return truncated
}

// --- handlers -------------------------------------------------------------------

func (c *Connector) mailSearch(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	q, err := optionalString(call.Args, "q")
	if err != nil {
		return connectors.Result{}, err
	}
	filter, err := optionalString(call.Args, "filter")
	if err != nil {
		return connectors.Result{}, err
	}
	q, filter = strings.TrimSpace(q), strings.TrimSpace(filter)
	if q != "" && filter != "" {
		return connectors.Result{}, invalid("q and filter cannot be combined: Graph does not support $search with $filter")
	}
	if len(q) > maxQueryLength || len(filter) > maxFilterLength {
		return connectors.Result{}, invalid("q or filter is too long")
	}
	folder, err := idArg(call.Args, "folder")
	if err != nil {
		return connectors.Result{}, err
	}
	top, clamped, err := c.topArg(call.Args, maxTop)
	if err != nil {
		return connectors.Result{}, err
	}
	path := messagesPath
	if folder != "" {
		path = "me/mailFolders/" + folderName(folder) + "/messages"
	}
	query := url.Values{"$top": {strconv.Itoa(top)}, "$select": {messageSelect}}
	switch {
	case q != "":
		query.Set("$search", `"`+strings.ReplaceAll(strings.ReplaceAll(q, `\`, `\\`), `"`, searchQuoteReplacement)+`"`)
	case filter != "":
		query.Set("$filter", filter)
		query.Set("$orderby", "receivedDateTime desc")
	default:
		query.Set("$orderby", "receivedDateTime desc")
	}
	items, more, err := graph.Collect[graphMessage](ctx, client, path, query, graph.ListOptions{MaxItems: top, MaxPages: 1})
	if err := classify("search mail", err); err != nil {
		return connectors.Result{}, err
	}
	out := MailPage{Top: top, HasMore: more, Items: make([]MailItem, 0, len(items))}
	for _, m := range items {
		out.Items = append(out.Items, toMailItem(m))
	}
	res := connectors.Result{Partial: clamped, Empty: len(out.Items) == 0}
	if truncateItems(&out.Items, c.bounds.MaxResultBytes, func() any { return out }) {
		out.Truncated, res.Partial = true, true
	}
	res.Content = out
	return res, nil
}

func (c *Connector) mailGetMessage(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	id, err := requiredID(call.Args, "id")
	if err != nil {
		return connectors.Result{}, err
	}
	var m graphMessage
	_, err = client.Do(ctx, graph.Request{
		Method: http.MethodGet, Path: messagesPath + "/" + id,
		Query:  url.Values{"$select": {messageDetailSelect}},
		Header: http.Header{"Prefer": {preferTextBody}},
	}, &m)
	if err := classify("get message", err); err != nil {
		return connectors.Result{}, err
	}
	out := toMessage(m)
	fitBody(&out.Body, &out.Truncated, c.bounds.MaxResultBytes, func() any { return out })
	return connectors.Result{Content: out, Partial: out.Truncated}, nil
}

func (c *Connector) calendarListEvents(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	start, err := timeArg(call.Args, "start")
	if err != nil {
		return connectors.Result{}, err
	}
	end, err := timeArg(call.Args, "end")
	if err != nil {
		return connectors.Result{}, err
	}
	if !end.After(start) {
		return connectors.Result{}, invalid("end must be after start")
	}
	if end.Sub(start) > maxCalendarWindow {
		return connectors.Result{}, invalid("the window between start and end must be at most a year")
	}
	cal, err := idArg(call.Args, "calendar_id")
	if err != nil {
		return connectors.Result{}, err
	}
	top, clamped, err := c.topArg(call.Args, maxTop)
	if err != nil {
		return connectors.Result{}, err
	}
	path := calendarViewPath
	if cal != "" {
		path = "me/calendars/" + cal + "/calendarView"
	}
	query := url.Values{
		"startDateTime": {start.UTC().Format(time.RFC3339)}, "endDateTime": {end.UTC().Format(time.RFC3339)},
		"$top": {strconv.Itoa(top)}, "$select": {eventSelect}, "$orderby": {"start/dateTime"},
	}
	var pg struct {
		Value    []graphEvent `json:"value"`
		NextLink string       `json:"@odata.nextLink"`
	}
	_, err = client.Do(ctx, graph.Request{Method: http.MethodGet, Path: path, Query: query, Header: http.Header{"Prefer": {preferUTC}}}, &pg)
	if err := classify("list events", err); err != nil {
		return connectors.Result{}, err
	}
	out := EventsPage{Top: top, HasMore: pg.NextLink != "", Items: make([]Event, 0, len(pg.Value))}
	for _, e := range pg.Value {
		out.Items = append(out.Items, toEvent(e))
	}
	res := connectors.Result{Partial: clamped, Empty: len(out.Items) == 0}
	if truncateItems(&out.Items, c.bounds.MaxResultBytes, func() any { return out }) {
		out.Truncated, res.Partial = true, true
	}
	res.Content = out
	return res, nil
}

func (c *Connector) driveSearch(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	q, err := requiredString(call.Args, "q")
	if err != nil {
		return connectors.Result{}, err
	}
	if len(q) > maxQueryLength {
		return connectors.Result{}, invalid("q is too long")
	}
	drive, err := idArg(call.Args, "drive_id")
	if err != nil {
		return connectors.Result{}, err
	}
	top, clamped, err := c.topArg(call.Args, maxTop)
	if err != nil {
		return connectors.Result{}, err
	}
	root := "me/drive/root"
	if drive != "" {
		root = "drives/" + drive + "/root"
	}
	path := root + "/search(q=" + graph.Quote(q) + ")"
	query := url.Values{"$top": {strconv.Itoa(top)}, "$select": {driveItemSelect}}
	items, more, err := graph.Collect[graphDriveItem](ctx, client, path, query, graph.ListOptions{MaxItems: top, MaxPages: 1})
	if err := classify("search drive", err); err != nil {
		return connectors.Result{}, err
	}
	out := DrivePage{Top: top, HasMore: more, Items: make([]DriveItem, 0, len(items))}
	for _, d := range items {
		out.Items = append(out.Items, toDriveItem(d))
	}
	res := connectors.Result{Partial: clamped, Empty: len(out.Items) == 0}
	if truncateItems(&out.Items, c.bounds.MaxResultBytes, func() any { return out }) {
		out.Truncated, res.Partial = true, true
	}
	res.Content = out
	return res, nil
}

// teamsListChannels lists the joined teams (or the one given) and the
// channels of each. A team whose channels cannot be listed (forbidden,
// not found) is kept with its error and the result is Partial; any
// other failure (throttle, 5xx, token) is the call's error.
func (c *Connector) teamsListChannels(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	team, err := idArg(call.Args, "team_id")
	if err != nil {
		return connectors.Result{}, err
	}
	top, clamped, err := c.topArg(call.Args, maxTop)
	if err != nil {
		return connectors.Result{}, err
	}
	var teams []graphTeam
	more := false
	if team != "" {
		teams = []graphTeam{{ID: team}}
	} else {
		// joinedTeams takes no $top: read one past the cap to learn has_more.
		teams, more, err = graph.Collect[graphTeam](ctx, client, joinedTeamsPath, url.Values{"$select": {teamSelect}}, graph.ListOptions{MaxItems: top + 1, MaxPages: 2})
		if err := classify("list joined teams", err); err != nil {
			return connectors.Result{}, err
		}
		if len(teams) > top {
			teams, more = teams[:top], true
		}
	}
	out := TeamsPage{HasMore: more, Items: make([]TeamChannels, 0, len(teams))}
	res := connectors.Result{Partial: clamped}
	for _, tm := range teams {
		entry := TeamChannels{TeamID: tm.ID, TeamName: tm.DisplayName, Channels: []Channel{}}
		path := "teams/" + tm.ID + "/channels"
		channels, _, err := graph.Collect[graphChannel](ctx, client, path, url.Values{"$select": {channelSelect}}, graph.ListOptions{MaxItems: maxTop, MaxPages: 2})
		if err := classify("list channels", err); err != nil {
			switch classOf(err) {
			case ClassForbidden, ClassNotFound:
				entry.Error, res.Partial = classOf(err), true
			default:
				return connectors.Result{}, err
			}
		}
		for _, ch := range channels {
			entry.Channels = append(entry.Channels, toChannel(ch))
		}
		out.Items = append(out.Items, entry)
	}
	res.Empty = len(out.Items) == 0
	if truncateItems(&out.Items, c.bounds.MaxResultBytes, func() any { return out }) {
		out.Truncated, res.Partial = true, true
	}
	res.Content = out
	return res, nil
}

func (c *Connector) teamsReadChannelMessages(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	team, err := requiredID(call.Args, "team_id")
	if err != nil {
		return connectors.Result{}, err
	}
	channel, err := requiredID(call.Args, "channel_id")
	if err != nil {
		return connectors.Result{}, err
	}
	top, clamped, err := c.topArg(call.Args, maxChannelMessagesTop)
	if err != nil {
		return connectors.Result{}, err
	}
	path := "teams/" + team + "/channels/" + channel + "/messages"
	items, more, err := graph.Collect[graphChatMessage](ctx, client, path, url.Values{"$top": {strconv.Itoa(top)}}, graph.ListOptions{MaxItems: top, MaxPages: 1})
	if err := classify("read channel messages", err); err != nil {
		return connectors.Result{}, err
	}
	out := ChannelMessagesPage{Top: top, HasMore: more, Items: make([]ChannelMessage, 0, len(items))}
	for _, m := range items {
		out.Items = append(out.Items, toChannelMessage(m))
	}
	res := connectors.Result{Partial: clamped, Empty: len(out.Items) == 0}
	if truncateItems(&out.Items, c.bounds.MaxResultBytes, func() any { return out }) {
		out.Truncated, res.Partial = true, true
	}
	res.Content = out
	return res, nil
}
