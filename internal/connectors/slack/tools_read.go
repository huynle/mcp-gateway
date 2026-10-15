// Tool descriptions, argument shapes, channel-name resolution and the
// history / replies / search handling are adapted from
// korotovsky/slack-mcp-server, pkg/handler/conversations.go,
// pkg/handler/channels.go and pkg/server/server.go (commit
// b88c0de3f706f4f07337c9eda7133c736d1c9524), MIT License, Copyright (c)
// 2025 Dmitrii Korotovskii. Modified for mcp-gateway: one tool per
// read, JSON results instead of CSV, no channel/user cache (names are
// resolved per call through users.conversations, bounded), snake_case
// limit/cursor clamped to the gateway's bounds, resource identity for
// policy and audit, the connectors.Result markers and the connector's
// error vocabulary. See THIRD_PARTY_NOTICES.md.

package slack

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	goslack "github.com/slack-go/slack"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Read tool names.
const (
	ToolListChannels       = "list_channels"
	ToolReadChannelHistory = "read_channel_history"
	ToolGetThread          = "get_thread"
	ToolSearchMessages     = "search_messages"
	ToolGetUser            = "get_user"
)

// Slack user-token scopes the read tools need (RequiredScopes).
const (
	ScopeChannelsRead    = "channels:read"
	ScopeGroupsRead      = "groups:read"
	ScopeChannelsHistory = "channels:history"
	ScopeGroupsHistory   = "groups:history"
	ScopeSearchRead      = "search:read"
	ScopeUsersRead       = "users:read"
)

// maxLimit caps every page size: the smallest of the Slack maximums the
// tools use (search.messages count is at most 100).
const maxLimit = 100

// defaultSearchCount is search_messages's page size when the harness
// gives none (Slack's default), capped by the bounds.
const defaultSearchCount = 20

// Channel-name resolution walks the user's conversations with pages of
// resolveLimit, at most MaxResolvePages of them.
const (
	resolveLimit = 200
	// MaxResolvePages bounds how many pages of the user's conversations
	// a channel name lookup walks before reporting not found.
	MaxResolvePages = 5
)

var (
	// channelIDRE is the shape of a conversation id (C public channel, G
	// private channel, D direct message), upper-cased.
	channelIDRE = regexp.MustCompile(`^[CDG][A-Z0-9]{8,}$`)
	// channelMentionRE is the <#C123|name> form a harness may copy from
	// a message.
	channelMentionRE = regexp.MustCompile(`^<#([A-Za-z0-9]+)(?:\|[^>]*)?>$`)
	// userIDRE is the shape of a user id, with or without <@...>.
	userIDRE        = regexp.MustCompile(`^[UW][A-Z0-9]{8,}$`)
	userMentionRE   = regexp.MustCompile(`^<@([A-Za-z0-9]+)(?:\|[^>]*)?>$`)
	channelNameRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	tsRE            = regexp.MustCompile(`^[0-9]{1,13}\.[0-9]{1,6}$`)
	timeBoundRE     = regexp.MustCompile(`^[0-9]{1,13}(\.[0-9]{1,6})?$`)
	channelTypes    = map[string]bool{"public_channel": true, "private_channel": true}
	defaultChanType = []string{"public_channel", "private_channel"}
)

// readTools declares the five read tools.
func (c *Connector) readTools() []connectors.Tool {
	paged := connectors.Bounds{MaxPageSize: c.bounds.MaxPageSize, MaxResultBytes: c.bounds.MaxResultBytes}
	single := connectors.Bounds{MaxResultBytes: c.bounds.MaxResultBytes}
	return []connectors.Tool{
		{
			App: App, Name: ToolListChannels, Kind: connectors.KindRead,
			Description: "List the Slack channels the connected user is a member of (public and private): id, name, privacy, " +
				"archived flag, member count, topic and purpose. Cursor paginated: pass next_cursor as cursor for the next page. " +
				"Use the id or the name of a channel in the other tools.",
			InputSchema: objectSchema([]property{
				{"types", "string", "Comma separated conversation types to list: public_channel, private_channel. Default: both.", nil},
				limitProperty, cursorProperty,
				{"exclude_archived", "boolean", "Leave out archived channels. Default: true.", nil},
			}, nil),
			RequiredScopes:   []string{ScopeChannelsRead, ScopeGroupsRead},
			ResourceIdentity: identity(),
			Bounds:           paged,
		},
		{
			App: App, Name: ToolReadChannelHistory, Kind: connectors.KindRead,
			Description: "Read the recent messages of a Slack channel, newest first: ts (the message id), user id, text, subtype, " +
				"thread_ts and reply_count for thread parents, reactions. Cursor paginated (next_cursor); oldest and latest " +
				"bound the time range as Slack timestamps. Use get_user to name a user id and get_thread to read a thread.",
			InputSchema: objectSchema([]property{
				channelProperty, limitProperty, cursorProperty,
				{"oldest", "string", "Only messages after this Slack timestamp (e.g. 1700000000.000000 or 1700000000).", nil},
				{"latest", "string", "Only messages before this Slack timestamp.", nil},
			}, []string{"channel"}),
			RequiredScopes:   []string{ScopeChannelsHistory, ScopeGroupsHistory},
			ResourceIdentity: identity(),
			Bounds:           paged,
		},
		{
			App: App, Name: ToolGetThread, Kind: connectors.KindRead,
			Description: "Read a Slack thread: the parent message (thread_ts) and its replies in order, with ts, user id, text " +
				"and reactions. Cursor paginated (next_cursor).",
			InputSchema: objectSchema([]property{
				channelProperty,
				{"thread_ts", "string", "The thread's parent message timestamp (e.g. 1700002000.000100).", nil},
				limitProperty, cursorProperty,
			}, []string{"channel", "thread_ts"}),
			RequiredScopes:   []string{ScopeChannelsHistory, ScopeGroupsHistory},
			ResourceIdentity: identity("thread_ts"),
			Bounds:           paged,
		},
		{
			App: App, Name: ToolSearchMessages, Kind: connectors.KindRead,
			Description: "Search messages across the channels the connected user can see, with Slack's search syntax " +
				"(modifiers such as in:#channel, from:@user, before:2024-01-31, after:2024-01-01, has:link). Page based: " +
				"count per page and page number; has_more says whether another page exists. Each hit carries its channel id and " +
				"name, user id, text, permalink and thread_ts when it is a reply.",
			InputSchema: objectSchema([]property{
				{"query", "string", "Search query in Slack search syntax.", nil},
				{"count", "integer", "Hits per page (1-100); clamped to the tool's maximum. Default: 20.", nil},
				{"page", "integer", "Page number, starting at 1.", nil},
				{"sort", "string", "Sort by score (relevance, default) or timestamp.", []string{"score", "timestamp"}},
				{"sort_dir", "string", "Sort direction: asc or desc (default).", []string{"asc", "desc"}},
			}, []string{"query"}),
			RequiredScopes:   []string{ScopeSearchRead},
			ResourceIdentity: identity(),
			Bounds:           paged,
		},
		{
			App: App, Name: ToolGetUser, Kind: connectors.KindRead,
			Description: "Get a Slack user by id: handle, real name, display name, title, time zone, status and whether it is " +
				"a bot, an admin or deactivated. Use it to name the user ids messages carry.",
			InputSchema:      objectSchema([]property{{"user", "string", "The user id (U... or W..., with or without <@...>).", nil}}, []string{"user"}),
			RequiredScopes:   []string{ScopeUsersRead},
			ResourceIdentity: userIdentity,
			Bounds:           single,
		},
	}
}

// handlers maps short tool names to their implementation.
func (c *Connector) handlers() map[string]handler {
	m := map[string]handler{
		ToolListChannels:       c.listChannels,
		ToolReadChannelHistory: c.readChannelHistory,
		ToolGetThread:          c.getThread,
		ToolSearchMessages:     c.searchMessages,
		ToolGetUser:            c.getUser,
	}
	for name, h := range c.messageReadHandlers() {
		m[name] = h
	}
	return m
}

// --- schema helpers ----------------------------------------------------------

// property is one input-schema property: name, type, description and
// optional enum values.
type property struct {
	Name, Type, Description string
	Enum                    []string
}

var (
	channelProperty = property{"channel", "string", "Channel id (C..., G...) or name (with or without #). Names are resolved among the channels you are a member of; pass the id when a name is not found.", nil}
	// postTargetProperty is channelProperty plus direct messages.
	postTargetProperty = property{"channel", "string", "Channel id (C..., G...) or name (with or without #), or a user id (U...) or <@U...> mention to send a direct message to that user (your own id: a note to yourself). Names are resolved among the channels you are a member of; pass the id when a name is not found.", nil}
	limitProperty      = property{"limit", "integer", "Items per page (1-100); clamped to the tool's maximum.", nil}
	cursorProperty     = property{"cursor", "string", "Pagination cursor from a previous next_cursor.", nil}
)

// objectSchema builds a closed object schema with the given properties
// and required names.
func objectSchema(props []property, required []string) json.RawMessage {
	type schemaProp struct {
		Type        string   `json:"type"`
		Description string   `json:"description"`
		Enum        []string `json:"enum,omitempty"`
		Minimum     *int     `json:"minimum,omitempty"`
		Maximum     *int     `json:"maximum,omitempty"`
		Items       any      `json:"items,omitempty"`
		MaxItems    *int     `json:"maxItems,omitempty"`
		MinItems    *int     `json:"minItems,omitempty"`
	}
	properties := map[string]schemaProp{}
	for _, p := range props {
		sp := schemaProp{Type: p.Type, Description: p.Description, Enum: p.Enum}
		if p.Type == "array" {
			one, max := 1, MaxInviteUsers
			sp.Items, sp.MinItems, sp.MaxItems = map[string]string{"type": "string"}, &one, &max
		}
		switch p.Name {
		case "page":
			one := 1
			sp.Minimum = &one
		case "limit", "count":
			one, max := 1, maxLimit
			sp.Minimum, sp.Maximum = &one, &max
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

// --- resource identity --------------------------------------------------------

// identity extracts the channel from the arguments ("channel": a name
// lower-cased without its "#", or an id as is, plus "channel_name" or
// "channel_id" saying which) and the named timestamp-like arguments
// (thread_ts, timestamp) and the reaction name; never message content.
// A role rule "post only to #eng-*" is a prefix condition eng- on
// channel: a harness that passes an id does not match it and is
// denied, which is the safe default.
func identity(extra ...string) func(map[string]any) map[string]string {
	return func(args map[string]any) map[string]string {
		out := map[string]string{}
		if raw, _ := args["channel"].(string); raw != "" {
			id, name := parseChannelRef(raw)
			if user := parseUserRef(raw); user != "" {
				// A direct message: no channel name for name rules to
				// match, no channel id to resolve.
				id, name = "", ""
				out["channel"], out["dm_user"] = "dm:"+user, user
			}
			switch {
			case id != "":
				out["channel"], out["channel_id"] = id, id
			case name != "":
				out["channel"], out["channel_name"] = name, name
			}
		}
		for _, key := range extra {
			v, _ := args[key].(string)
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			if key == "name" {
				out["reaction"] = strings.ToLower(strings.Trim(v, ":"))
				continue
			}
			out[key] = v
		}
		return out
	}
}

// userIdentity is get_user's identity: the user id.
func userIdentity(args map[string]any) map[string]string {
	out := map[string]string{}
	if raw, _ := args["user"].(string); raw != "" {
		if id := parseUserRef(raw); id != "" {
			out["user"] = id
		}
	}
	return out
}

// parseChannelRef splits a channel argument into an id (C..., G...,
// D..., upper-cased; also from <#C123|name>) or a name (lower-cased,
// without "#"). Both empty when the argument is blank.
func parseChannelRef(raw string) (id, name string) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", ""
	}
	if m := channelMentionRE.FindStringSubmatch(s); m != nil {
		return strings.ToUpper(m[1]), ""
	}
	if strings.HasPrefix(s, "#") {
		return "", strings.ToLower(strings.TrimSpace(s[1:]))
	}
	if up := strings.ToUpper(s); channelIDRE.MatchString(up) {
		return up, ""
	}
	return "", strings.ToLower(s)
}

// parseUserRef returns the user id of a user argument (U..., W..., or
// <@U...>), "" when it is not an id.
func parseUserRef(raw string) string {
	s := strings.TrimSpace(raw)
	if m := userMentionRE.FindStringSubmatch(s); m != nil {
		s = m[1]
	}
	if up := strings.ToUpper(s); userIDRE.MatchString(up) {
		return up
	}
	return ""
}

// --- argument helpers ---------------------------------------------------------

func invalid(format string, a ...any) error {
	return &Error{Class: ClassInvalidArgument, Message: fmt.Sprintf(format, a...)}
}

// channelArg reads and validates the channel argument.
func channelArg(args map[string]any) (id, name string, err error) {
	raw, _ := args["channel"].(string)
	id, name = parseChannelRef(raw)
	switch {
	case id == "" && name == "":
		return "", "", invalid("channel is required: a channel id (C...) or name (#eng-general)")
	case name != "" && !channelNameRE.MatchString(name):
		return "", "", invalid("channel %q is not a channel id or name", strings.TrimSpace(raw))
	}
	return id, name, nil
}

// tsArg reads a required Slack timestamp argument.
func tsArg(args map[string]any, key string) (string, error) {
	v, _ := args[key].(string)
	v = strings.TrimSpace(v)
	if !tsRE.MatchString(v) {
		return "", invalid("%s is required: a Slack message timestamp such as 1700002000.000100", key)
	}
	return v, nil
}

// timeBoundArg reads an optional oldest/latest bound (a Slack timestamp
// or unix seconds).
func timeBoundArg(args map[string]any, key string) (string, error) {
	v, ok := args[key]
	if !ok || v == nil {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		if n, err := toInt(v); err == nil && n > 0 {
			return strconv.Itoa(n), nil
		}
		return "", invalid("%s must be a Slack timestamp string", key)
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	if !timeBoundRE.MatchString(s) {
		return "", invalid("%s must be a Slack timestamp such as 1700000000.000000", key)
	}
	return s, nil
}

// limitArg reads the page size under key (defaultLimit when absent) and
// clamps it to the bounds (clamped reports when it was).
func (c *Connector) limitArg(args map[string]any, key string, defaultLimit int) (limit int, clamped bool, err error) {
	limit = min(defaultLimit, c.bounds.MaxPageSize)
	v, ok := args[key]
	if !ok || v == nil {
		return limit, false, nil
	}
	if limit, err = toInt(v); err != nil || limit < 1 {
		return 0, false, invalid("%s must be a positive integer", key)
	}
	if limit > c.bounds.MaxPageSize {
		limit, clamped = c.bounds.MaxPageSize, true
	}
	return limit, clamped, nil
}

// cursorArg reads the optional pagination cursor.
func cursorArg(args map[string]any) (string, error) {
	v, ok := args["cursor"]
	if !ok || v == nil {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", invalid("cursor must be a string")
	}
	return strings.TrimSpace(s), nil
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

// requiredString reads a non-blank string argument.
func requiredString(args map[string]any, name string) (string, error) {
	v, _ := args[name].(string)
	v = strings.TrimSpace(v)
	if v == "" {
		return "", invalid("%s is required", name)
	}
	return v, nil
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

// parseTS parses a Slack ts into a time.
func parseTS(ts string) (time.Time, bool) {
	sec, frac, _ := strings.Cut(ts, ".")
	s, err := strconv.ParseInt(sec, 10, 64)
	if err != nil || s <= 0 {
		return time.Time{}, false
	}
	var micro int64
	if frac != "" {
		for len(frac) < 6 {
			frac += "0"
		}
		micro, err = strconv.ParseInt(frac[:6], 10, 64)
		if err != nil {
			return time.Time{}, false
		}
	}
	return time.Unix(s, micro*1000), true
}

// --- channel resolution --------------------------------------------------------

// resolveChannel turns a channel argument into an id: an id is returned
// as is (name unknown); a name is looked up among the user's
// conversations (public and private, archived included, pages of
// resolveLimit, at most MaxResolvePages). A name that is not found is
// ClassNotFound with the advice to pass the id. The lookups are reads:
// their failures are known outcomes (classify).
func (c *Connector) resolveChannel(ctx context.Context, api *goslack.Client, id, name string) (string, string, error) {
	if id != "" {
		return id, "", nil
	}
	ch, err := c.findConversation(ctx, api, defaultChanType, func(ch goslack.Channel) bool {
		return strings.EqualFold(ch.Name, name) || strings.EqualFold(ch.NameNormalized, name)
	})
	if err != nil {
		return "", "", err
	}
	if ch == nil {
		return "", "", &Error{Class: ClassNotFound, Message: fmt.Sprintf("channel #%s not found among the channels this account is a member of (first %d pages); pass the channel id instead", name, MaxResolvePages)}
	}
	return ch.ID, ch.Name, nil
}

// fit drops trailing items (never below one) until the page built by
// page(items) serialises within max bytes; reports whether any were
// dropped. The harness still sees the newest items, marked Partial.
func fit[T any](items []T, max int, page func([]T) any) ([]T, bool) {
	truncated := false
	for encodedSize(page(items)) > max && len(items) > 1 {
		items = items[:len(items)-1]
		truncated = true
	}
	return items, truncated
}

// --- handlers -------------------------------------------------------------------

func (c *Connector) listChannels(ctx context.Context, api *goslack.Client, call connectors.Call) (connectors.Result, error) {
	types := defaultChanType
	if raw, err := optionalString(call.Args, "types"); err != nil {
		return connectors.Result{}, err
	} else if strings.TrimSpace(raw) != "" {
		types = nil
		for _, t := range strings.Split(raw, ",") {
			t = strings.ToLower(strings.TrimSpace(t))
			if !channelTypes[t] {
				return connectors.Result{}, invalid("types must list public_channel and/or private_channel")
			}
			types = append(types, t)
		}
	}
	limit, clamped, err := c.limitArg(call.Args, "limit", connectors.DefaultMaxPageSize)
	if err != nil {
		return connectors.Result{}, err
	}
	cursor, err := cursorArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	excludeArchived := true
	if v, ok := call.Args["exclude_archived"]; ok && v != nil {
		b, ok := v.(bool)
		if !ok {
			return connectors.Result{}, invalid("exclude_archived must be a boolean")
		}
		excludeArchived = b
	}
	channels, next, err := api.GetConversationsForUserContext(ctx, &goslack.GetConversationsForUserParameters{Types: types, Limit: limit, Cursor: cursor, ExcludeArchived: excludeArchived})
	if err := classify("list channels", err); err != nil {
		return connectors.Result{}, err
	}
	out := ChannelsPage{Channels: make([]Channel, 0, len(channels)), NextCursor: next, HasMore: next != "", Limit: limit}
	for _, ch := range channels {
		// users.conversations lists only conversations the user is a member
		// of, but does not set is_member on them.
		ch.IsMember = true
		out.Channels = append(out.Channels, toChannel(ch))
	}
	out.Channels, out.Truncated = fit(out.Channels, c.bounds.MaxResultBytes, func(items []Channel) any { out.Channels = items; return out })
	return connectors.Result{Content: out, Partial: clamped || out.Truncated, Empty: len(out.Channels) == 0}, nil
}

func (c *Connector) readChannelHistory(ctx context.Context, api *goslack.Client, call connectors.Call) (connectors.Result, error) {
	id, name, err := channelArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	limit, clamped, err := c.limitArg(call.Args, "limit", connectors.DefaultMaxPageSize)
	if err != nil {
		return connectors.Result{}, err
	}
	cursor, err := cursorArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	oldest, err := timeBoundArg(call.Args, "oldest")
	if err != nil {
		return connectors.Result{}, err
	}
	latest, err := timeBoundArg(call.Args, "latest")
	if err != nil {
		return connectors.Result{}, err
	}
	id, name, err = c.resolveChannel(ctx, api, id, name)
	if err != nil {
		return connectors.Result{}, err
	}
	history, err := api.GetConversationHistoryContext(ctx, &goslack.GetConversationHistoryParameters{ChannelID: id, Limit: limit, Cursor: cursor, Oldest: oldest, Latest: latest})
	if err := classify("read channel history", err); err != nil {
		return connectors.Result{}, err
	}
	out := HistoryPage{Channel: id, ChannelName: name, Messages: make([]Message, 0, len(history.Messages)), HasMore: history.HasMore, NextCursor: history.ResponseMetaData.NextCursor, Limit: limit}
	for _, m := range history.Messages {
		out.Messages = append(out.Messages, toMessage(m))
	}
	out.Messages, out.Truncated = fit(out.Messages, c.bounds.MaxResultBytes, func(items []Message) any { out.Messages = items; return out })
	return connectors.Result{Content: out, Partial: clamped || out.Truncated, Empty: len(out.Messages) == 0}, nil
}

func (c *Connector) getThread(ctx context.Context, api *goslack.Client, call connectors.Call) (connectors.Result, error) {
	id, name, err := channelArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	threadTS, err := tsArg(call.Args, "thread_ts")
	if err != nil {
		return connectors.Result{}, err
	}
	limit, clamped, err := c.limitArg(call.Args, "limit", connectors.DefaultMaxPageSize)
	if err != nil {
		return connectors.Result{}, err
	}
	cursor, err := cursorArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	id, name, err = c.resolveChannel(ctx, api, id, name)
	if err != nil {
		return connectors.Result{}, err
	}
	msgs, hasMore, next, err := api.GetConversationRepliesContext(ctx, &goslack.GetConversationRepliesParameters{ChannelID: id, Timestamp: threadTS, Limit: limit, Cursor: cursor})
	if err := classify("get thread", err); err != nil {
		return connectors.Result{}, err
	}
	out := ThreadPage{Channel: id, ChannelName: name, ThreadTS: threadTS, Messages: make([]Message, 0, len(msgs)), HasMore: hasMore, NextCursor: next, Limit: limit}
	for _, m := range msgs {
		out.Messages = append(out.Messages, toMessage(m))
	}
	out.Messages, out.Truncated = fit(out.Messages, c.bounds.MaxResultBytes, func(items []Message) any { out.Messages = items; return out })
	return connectors.Result{Content: out, Partial: clamped || out.Truncated, Empty: len(out.Messages) == 0}, nil
}

func (c *Connector) searchMessages(ctx context.Context, api *goslack.Client, call connectors.Call) (connectors.Result, error) {
	query, err := requiredString(call.Args, "query")
	if err != nil {
		return connectors.Result{}, err
	}
	count, clamped, err := c.limitArg(call.Args, "count", defaultSearchCount)
	if err != nil {
		return connectors.Result{}, err
	}
	page := 1
	if v, ok := call.Args["page"]; ok && v != nil {
		if page, err = toInt(v); err != nil || page < 1 {
			return connectors.Result{}, invalid("page must be a positive integer")
		}
	}
	sortBy, err := optionalString(call.Args, "sort")
	if err != nil {
		return connectors.Result{}, err
	}
	switch sortBy = strings.ToLower(strings.TrimSpace(sortBy)); sortBy {
	case "", "score", "timestamp":
	default:
		return connectors.Result{}, invalid("sort must be score or timestamp")
	}
	sortDir, err := optionalString(call.Args, "sort_dir")
	if err != nil {
		return connectors.Result{}, err
	}
	switch sortDir = strings.ToLower(strings.TrimSpace(sortDir)); sortDir {
	case "", "asc", "desc":
	default:
		return connectors.Result{}, invalid("sort_dir must be asc or desc")
	}
	if sortBy == "" {
		sortBy = goslack.DEFAULT_SEARCH_SORT
	}
	if sortDir == "" {
		sortDir = goslack.DEFAULT_SEARCH_SORT_DIR
	}
	result, err := api.SearchMessagesContext(ctx, query, goslack.SearchParameters{Sort: sortBy, SortDirection: sortDir, Highlight: false, Count: count, Page: page})
	if err := classify("search messages", err); err != nil {
		return connectors.Result{}, err
	}
	out := SearchPage{Total: result.Total, Page: page, PerPage: count, PageCount: result.PageCount, HasMore: page < result.PageCount, Messages: make([]Message, 0, len(result.Matches))}
	if result.Pagination.Page > 0 {
		out.Page = result.Pagination.Page
	}
	for _, m := range result.Matches {
		out.Messages = append(out.Messages, toSearchMessage(m))
	}
	out.Messages, out.Truncated = fit(out.Messages, c.bounds.MaxResultBytes, func(items []Message) any { out.Messages = items; return out })
	return connectors.Result{Content: out, Partial: clamped || out.Truncated, Empty: len(out.Messages) == 0}, nil
}

func (c *Connector) getUser(ctx context.Context, api *goslack.Client, call connectors.Call) (connectors.Result, error) {
	raw, _ := call.Args["user"].(string)
	id := parseUserRef(raw)
	if id == "" {
		return connectors.Result{}, invalid("user is required: a Slack user id such as U0123ABCDEF (names are not accepted; find the id in messages or search)")
	}
	u, err := api.GetUserInfoContext(ctx, id)
	if err := classify("get user", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: toUser(u)}, nil
}
