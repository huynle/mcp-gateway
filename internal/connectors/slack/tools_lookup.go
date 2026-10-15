package slack

import (
	"context"
	"encoding/base64"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	goslack "github.com/slack-go/slack"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Lookup read tools: the reads of Slack's own MCP server the connector
// lacked (reactions on a message, a channel's members, file search and
// reading, user / channel / emoji search).
const (
	ToolGetReactions       = "get_reactions"
	ToolListChannelMembers = "list_channel_members"
	ToolSearchFiles        = "search_files"
	ToolSearchUsers        = "search_users"
	ToolSearchChannels     = "search_channels"
	ToolSearchEmojis       = "search_emojis"
	ToolReadFile           = "read_file"
)

// Slack user-token scopes of the lookup tools.
const (
	ScopeReactionsRead = "reactions:read"
	ScopeFilesRead     = "files:read"
	ScopeEmojiRead     = "emoji:read"
)

// MaxReadFileBytes caps what read_file downloads (5 MiB): text is cut
// there, a larger binary file is not downloaded at all.
const MaxReadFileBytes = 5 << 20

// readFileResultBytes bounds read_file's result: MaxReadFileBytes in
// base64 plus the metadata.
const readFileResultBytes = 8 << 20

// MaxSearchPages bounds the listing walks of search_users and
// search_channels (pages of searchPageSize).
const MaxSearchPages = 5

// searchPageSize is the page size of those walks.
const searchPageSize = 200

// defaultLookupLimit is the default result count of the name searches.
const defaultLookupLimit = 20

// fileIDRE is the shape of a file id (F...); canvases and lists are files.
var fileIDRE = regexp.MustCompile(`^F[A-Z0-9]{6,}$`)

// ItemReactions is get_reactions's result.
type ItemReactions struct {
	Channel   string             `json:"channel"`
	Timestamp string             `json:"timestamp"`
	Reactions []ReactionWithUser `json:"reactions"`
}

// ReactionWithUser is one emoji on a message with who reacted.
type ReactionWithUser struct {
	Name  string   `json:"name"`
	Count int      `json:"count"`
	Users []string `json:"users,omitempty"`
}

// MembersPage is list_channel_members's result: user ids.
type MembersPage struct {
	Channel    string   `json:"channel"`
	Members    []string `json:"members"`
	NextCursor string   `json:"next_cursor,omitempty"`
	HasMore    bool     `json:"has_more"`
	Limit      int      `json:"limit"`
}

// FileInfo is a file's metadata (search_files, read_file). Never the
// private download URL: read_file fetches the content itself.
type FileInfo struct {
	ID        string   `json:"id"`
	Name      string   `json:"name,omitempty"`
	Title     string   `json:"title,omitempty"`
	Filetype  string   `json:"filetype,omitempty"`
	Mimetype  string   `json:"mimetype,omitempty"`
	Size      int      `json:"size"`
	User      string   `json:"user,omitempty"`
	Created   string   `json:"created,omitempty"`
	Permalink string   `json:"permalink,omitempty"`
	Channels  []string `json:"channels,omitempty"`
}

// FilesPage is search_files's result.
type FilesPage struct {
	Total     int        `json:"total"`
	Page      int        `json:"page"`
	PerPage   int        `json:"per_page"`
	PageCount int        `json:"page_count"`
	HasMore   bool       `json:"has_more"`
	Truncated bool       `json:"truncated,omitempty"`
	Files     []FileInfo `json:"files"`
}

// UsersFound is search_users's result. Scanned is how many workspace
// members were looked at; Complete says the whole directory was.
type UsersFound struct {
	Users    []User `json:"users"`
	Scanned  int    `json:"scanned"`
	Complete bool   `json:"complete"`
}

// ChannelsFound is search_channels's result.
type ChannelsFound struct {
	Channels []Channel `json:"channels"`
	Scanned  int       `json:"scanned"`
	Complete bool      `json:"complete"`
}

// Emoji is one custom emoji: its image URL, or the emoji it aliases.
type Emoji struct {
	Name     string `json:"name"`
	URL      string `json:"url,omitempty"`
	AliasFor string `json:"alias_for,omitempty"`
}

// EmojisFound is search_emojis's result; Total counts every match.
type EmojisFound struct {
	Emojis []Emoji `json:"emojis"`
	Total  int     `json:"total"`
}

// FileContent is read_file's result. Encoding is text or base64;
// Omitted says why there is no content (binary over max_bytes, no
// download URL on a Slack host).
type FileContent struct {
	File      FileInfo `json:"file"`
	Content   string   `json:"content,omitempty"`
	Encoding  string   `json:"encoding,omitempty"`
	Truncated bool     `json:"truncated,omitempty"`
	Omitted   string   `json:"omitted,omitempty"`
}

func (c *Connector) lookupTools() []connectors.Tool {
	single := connectors.Bounds{MaxResultBytes: c.bounds.MaxResultBytes}
	paged := connectors.Bounds{MaxPageSize: c.bounds.MaxPageSize, MaxResultBytes: c.bounds.MaxResultBytes}
	none := func(map[string]any) map[string]string { return map[string]string{} }
	queryProp := func(desc string) property { return property{"query", "string", desc, nil} }
	return []connectors.Tool{
		{
			App: App, Name: ToolGetReactions, Kind: connectors.KindRead,
			Description: "Get the emoji reactions on a Slack message (channel and timestamp): each emoji's name, count and the user ids who reacted.",
			InputSchema: objectSchema([]property{channelProperty, {"timestamp", "string", "The message's ts (e.g. 1700003000.000200).", nil}},
				[]string{"channel", "timestamp"}),
			RequiredScopes: []string{ScopeReactionsRead}, ResourceIdentity: identity("timestamp"), Bounds: single,
		},
		{
			App: App, Name: ToolListChannelMembers, Kind: connectors.KindRead,
			Description:    "List the user ids of a Slack channel's (or DM's) members. Cursor paginated (next_cursor). Use get_user to name one.",
			InputSchema:    objectSchema([]property{channelProperty, limitProperty, cursorProperty}, []string{"channel"}),
			RequiredScopes: []string{ScopeChannelsRead, ScopeGroupsRead}, ResourceIdentity: identity(), Bounds: paged,
		},
		{
			App: App, Name: ToolSearchFiles, Kind: connectors.KindRead,
			Description: "Search files (and canvases) the connected user can see, with Slack's search syntax (in:#channel, from:@user, " +
				"before:, after:, type:). Page based (count, page, has_more). Each hit carries id, name, title, type, size, owner, " +
				"channels and permalink; read_file reads one.",
			InputSchema: objectSchema([]property{
				queryProp("Search query in Slack search syntax."),
				{"count", "integer", "Hits per page (1-100); clamped to the tool's maximum. Default: 20.", nil},
				{"page", "integer", "Page number, starting at 1.", nil},
				{"sort", "string", "Sort by score (relevance, default) or timestamp.", []string{"score", "timestamp"}},
				{"sort_dir", "string", "Sort direction: asc or desc (default).", []string{"asc", "desc"}},
			}, []string{"query"}),
			RequiredScopes: []string{ScopeSearchRead}, ResourceIdentity: none, Bounds: paged,
		},
		{
			App: App, Name: ToolSearchUsers, Kind: connectors.KindRead,
			Description: fmt.Sprintf("Find workspace members whose handle, real name or display name contains query (case-insensitive). "+
				"Bots and deactivated users are left out unless asked for. Walks at most %d pages of %d members; complete says "+
				"the whole directory was searched.", MaxSearchPages, searchPageSize),
			InputSchema: objectSchema([]property{
				queryProp("Part of a handle, real name or display name, e.g. alice."),
				{"limit", "integer", "Most users to return (1-100); default 20.", nil},
				{"include_bots", "boolean", "Include bot users. Default: false.", nil},
				{"include_deactivated", "boolean", "Include deactivated users. Default: false.", nil},
			}, []string{"query"}),
			RequiredScopes: []string{ScopeUsersRead}, ResourceIdentity: none, Bounds: paged,
		},
		{
			App: App, Name: ToolSearchChannels, Kind: connectors.KindRead,
			Description: fmt.Sprintf("Find channels of the workspace whose name contains query (and, with match_description, whose topic "+
				"or purpose does): public channels and the private ones the user is in, archived included by default. Walks at most "+
				"%d pages of %d channels; complete says every channel was searched.", MaxSearchPages, searchPageSize),
			InputSchema: objectSchema([]property{
				queryProp("Part of a channel name (a leading # is ignored)."),
				{"limit", "integer", "Most channels to return (1-100); default 20.", nil},
				{"types", "string", "Comma separated: public_channel, private_channel. Default: both.", nil},
				{"include_archived", "boolean", "Include archived channels. Default: true.", nil},
				{"match_description", "boolean", "Also match the topic and purpose. Default: false.", nil},
			}, []string{"query"}),
			RequiredScopes: []string{ScopeChannelsRead, ScopeGroupsRead}, ResourceIdentity: none, Bounds: paged,
		},
		{
			App: App, Name: ToolSearchEmojis, Kind: connectors.KindRead,
			Description: "List the workspace's custom emoji whose name contains query (all without one), sorted by name: the image URL, " +
				"or the emoji an alias points to. Use a name in add_reaction or set_status.",
			InputSchema: objectSchema([]property{
				queryProp("Optional: part of an emoji name, with or without colons."),
				{"limit", "integer", "Most emoji to return (1-100); clamped to the tool's maximum.", nil},
			}, nil),
			RequiredScopes: []string{ScopeEmojiRead}, ResourceIdentity: none, Bounds: paged,
		},
		{
			App: App, Name: ToolReadFile, Kind: connectors.KindRead,
			Description: fmt.Sprintf("Read a Slack file by id (F...): its metadata and content, text as is (cut at max_bytes) or "+
				"anything else in base64 (left out when larger than max_bytes). At most %d MiB. metadata_only skips the content.", MaxReadFileBytes>>20),
			InputSchema: objectSchema([]property{
				{"file", "string", "The file id (F...), from search_files, list_pins or a message.", nil},
				{"max_bytes", "integer", fmt.Sprintf("Most content bytes to return (1-%d). Default: %d.", MaxReadFileBytes, MaxReadFileBytes), nil},
				{"metadata_only", "boolean", "Return only the metadata. Default: false.", nil},
			}, []string{"file"}),
			RequiredScopes: []string{ScopeFilesRead}, ResourceIdentity: fileIdentity,
			Bounds: connectors.Bounds{MaxResultBytes: max(c.bounds.MaxResultBytes, readFileResultBytes)},
		},
	}
}

func (c *Connector) lookupHandlers() map[string]handler {
	return map[string]handler{
		ToolGetReactions:       c.getReactions,
		ToolListChannelMembers: c.listChannelMembers,
		ToolSearchFiles:        c.searchFiles,
		ToolSearchUsers:        c.searchUsers,
		ToolSearchChannels:     c.searchChannels,
		ToolSearchEmojis:       c.searchEmojis,
	}
}

// webReadHandlers are the reads that need the token itself.
func (c *Connector) webReadHandlers() map[string]webHandler {
	return map[string]webHandler{ToolReadFile: c.readFile}
}

// webWriteHandlers are the writes that need the token itself.
func (c *Connector) webWriteHandlers() map[string]webHandler {
	return map[string]webHandler{}
}

func fileIdentity(args map[string]any) map[string]string {
	out := map[string]string{}
	if args == nil {
		return out
	}
	if id, err := fileArg(args, "file"); err == nil {
		out["file"] = id
	}
	return out
}

func fileArg(args map[string]any, key string) (string, error) {
	v, _ := args[key].(string)
	v = strings.ToUpper(strings.TrimSpace(v))
	if !fileIDRE.MatchString(v) {
		return "", invalid("%s is required: a Slack file id such as F0123ABCDEF", key)
	}
	return v, nil
}

func boolArg(args map[string]any, key string, def bool) (bool, error) {
	v, ok := args[key]
	if !ok || v == nil {
		return def, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, invalid("%s must be a boolean", key)
	}
	return b, nil
}

func toFileInfo(f goslack.File) FileInfo {
	return FileInfo{ID: f.ID, Name: f.Name, Title: f.Title, Filetype: f.Filetype, Mimetype: f.Mimetype, Size: f.Size, User: f.User,
		Created: unixTime(int64(f.Created)), Permalink: f.Permalink, Channels: append(append([]string(nil), f.Channels...), f.Groups...)}
}

// --- handlers --------------------------------------------------------------------

func (c *Connector) getReactions(ctx context.Context, api *goslack.Client, call connectors.Call) (connectors.Result, error) {
	ts, err := tsArg(call.Args, "timestamp")
	if err != nil {
		return connectors.Result{}, err
	}
	id, err := c.channelTarget(ctx, api, call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	item, err := api.GetReactionsContext(ctx, goslack.ItemRef{Channel: id, Timestamp: ts}, goslack.GetReactionsParameters{Full: true})
	if err := classify("get reactions", err); err != nil {
		return connectors.Result{}, err
	}
	out := ItemReactions{Channel: id, Timestamp: ts, Reactions: make([]ReactionWithUser, 0, len(item.Reactions))}
	for _, r := range item.Reactions {
		out.Reactions = append(out.Reactions, ReactionWithUser{Name: r.Name, Count: r.Count, Users: r.Users})
	}
	var truncated bool
	out.Reactions, truncated = fit(out.Reactions, c.bounds.MaxResultBytes, func(items []ReactionWithUser) any { out.Reactions = items; return out })
	return connectors.Result{Content: out, Partial: truncated, Empty: len(out.Reactions) == 0}, nil
}

func (c *Connector) listChannelMembers(ctx context.Context, api *goslack.Client, call connectors.Call) (connectors.Result, error) {
	limit, clamped, err := c.limitArg(call.Args, "limit", connectors.DefaultMaxPageSize)
	if err != nil {
		return connectors.Result{}, err
	}
	cursor, err := cursorArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	id, err := c.channelTarget(ctx, api, call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	members, next, err := api.GetUsersInConversationContext(ctx, &goslack.GetUsersInConversationParameters{ChannelID: id, Limit: limit, Cursor: cursor})
	if err := classify("list channel members", err); err != nil {
		return connectors.Result{}, err
	}
	out := MembersPage{Channel: id, Members: append([]string{}, members...), NextCursor: next, HasMore: next != "", Limit: limit}
	return connectors.Result{Content: out, Partial: clamped, Empty: len(out.Members) == 0}, nil
}

func (c *Connector) searchFiles(ctx context.Context, api *goslack.Client, call connectors.Call) (connectors.Result, error) {
	query, err := requiredString(call.Args, "query")
	if err != nil {
		return connectors.Result{}, err
	}
	params, clamped, err := c.searchParams(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	result, err := api.SearchFilesContext(ctx, query, params)
	if err := classify("search files", err); err != nil {
		return connectors.Result{}, err
	}
	out := FilesPage{Total: result.Total, Page: params.Page, PerPage: params.Count, PageCount: result.PageCount, Files: make([]FileInfo, 0, len(result.Matches))}
	if result.Pagination.Page > 0 {
		out.Page = result.Pagination.Page
	}
	out.HasMore = out.Page < result.PageCount
	for _, f := range result.Matches {
		out.Files = append(out.Files, toFileInfo(f))
	}
	out.Files, out.Truncated = fit(out.Files, c.bounds.MaxResultBytes, func(items []FileInfo) any { out.Files = items; return out })
	return connectors.Result{Content: out, Partial: clamped || out.Truncated, Empty: len(out.Files) == 0}, nil
}

// searchParams reads count, page, sort and sort_dir as search_messages does.
func (c *Connector) searchParams(args map[string]any) (goslack.SearchParameters, bool, error) {
	count, clamped, err := c.limitArg(args, "count", defaultSearchCount)
	if err != nil {
		return goslack.SearchParameters{}, false, err
	}
	page := 1
	if v, ok := args["page"]; ok && v != nil {
		if page, err = toInt(v); err != nil || page < 1 {
			return goslack.SearchParameters{}, false, invalid("page must be a positive integer")
		}
	}
	sortBy, err := enumArg(args, "sort", goslack.DEFAULT_SEARCH_SORT, "score", "timestamp")
	if err != nil {
		return goslack.SearchParameters{}, false, err
	}
	sortDir, err := enumArg(args, "sort_dir", goslack.DEFAULT_SEARCH_SORT_DIR, "asc", "desc")
	if err != nil {
		return goslack.SearchParameters{}, false, err
	}
	return goslack.SearchParameters{Sort: sortBy, SortDirection: sortDir, Count: count, Page: page}, clamped, nil
}

// enumArg reads an optional lower-cased string argument among values.
func enumArg(args map[string]any, key, def string, values ...string) (string, error) {
	s, err := optionalString(args, key)
	if err != nil {
		return "", err
	}
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return def, nil
	}
	for _, v := range values {
		if s == v {
			return s, nil
		}
	}
	return "", invalid("%s must be one of %s", key, strings.Join(values, ", "))
}

// needle is the query lower-cased without a leading # or colons.
func needle(args map[string]any, required bool) (string, error) {
	raw, err := optionalString(args, "query")
	if err != nil {
		return "", err
	}
	q := strings.ToLower(strings.Trim(strings.TrimPrefix(strings.TrimSpace(raw), "#"), ":"))
	if required && q == "" {
		return "", invalid("query is required")
	}
	return q, nil
}

func containsFold(q string, fields ...string) bool {
	for _, f := range fields {
		if f != "" && strings.Contains(strings.ToLower(f), q) {
			return true
		}
	}
	return false
}

func (c *Connector) searchUsers(ctx context.Context, api *goslack.Client, call connectors.Call) (connectors.Result, error) {
	q, err := needle(call.Args, true)
	if err != nil {
		return connectors.Result{}, err
	}
	limit, _, err := c.limitArg(call.Args, "limit", defaultLookupLimit)
	if err != nil {
		return connectors.Result{}, err
	}
	bots, err := boolArg(call.Args, "include_bots", false)
	if err != nil {
		return connectors.Result{}, err
	}
	gone, err := boolArg(call.Args, "include_deactivated", false)
	if err != nil {
		return connectors.Result{}, err
	}
	out := UsersFound{Users: []User{}}
	p := api.GetUsersPaginated(goslack.GetUsersOptionLimit(searchPageSize))
	for page := 0; page < MaxSearchPages && len(out.Users) < limit; page++ {
		if p, err = p.Next(ctx); err != nil {
			if p.Done(err) {
				out.Complete = true
				break
			}
			return connectors.Result{}, classify("search users", err)
		}
		out.Scanned += len(p.Users)
		for i := range p.Users {
			u := &p.Users[i]
			if len(out.Users) >= limit || (u.IsBot && !bots) || (u.Deleted && !gone) {
				continue
			}
			if containsFold(q, u.Name, u.RealName, u.Profile.RealName, u.Profile.DisplayName) {
				out.Users = append(out.Users, toUser(u))
			}
		}
		if p.Cursor == "" {
			out.Complete = true
			break
		}
	}
	out.Users, _ = fit(out.Users, c.bounds.MaxResultBytes, func(items []User) any { out.Users = items; return out })
	return connectors.Result{Content: out, Partial: !out.Complete, Empty: len(out.Users) == 0}, nil
}

func (c *Connector) searchChannels(ctx context.Context, api *goslack.Client, call connectors.Call) (connectors.Result, error) {
	q, err := needle(call.Args, true)
	if err != nil {
		return connectors.Result{}, err
	}
	limit, _, err := c.limitArg(call.Args, "limit", defaultLookupLimit)
	if err != nil {
		return connectors.Result{}, err
	}
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
	archived, err := boolArg(call.Args, "include_archived", true)
	if err != nil {
		return connectors.Result{}, err
	}
	desc, err := boolArg(call.Args, "match_description", false)
	if err != nil {
		return connectors.Result{}, err
	}
	out := ChannelsFound{Channels: []Channel{}}
	params := &goslack.GetConversationsParameters{Types: types, Limit: searchPageSize, ExcludeArchived: !archived}
	for page := 0; page < MaxSearchPages && len(out.Channels) < limit; page++ {
		channels, next, err := api.GetConversationsContext(ctx, params)
		if err := classify("search channels", err); err != nil {
			return connectors.Result{}, err
		}
		out.Scanned += len(channels)
		for _, ch := range channels {
			if len(out.Channels) < limit && (containsFold(q, ch.Name, ch.NameNormalized) || (desc && containsFold(q, ch.Topic.Value, ch.Purpose.Value))) {
				out.Channels = append(out.Channels, toChannel(ch))
			}
		}
		if next == "" {
			out.Complete = true
			break
		}
		params.Cursor = next
	}
	out.Channels, _ = fit(out.Channels, c.bounds.MaxResultBytes, func(items []Channel) any { out.Channels = items; return out })
	return connectors.Result{Content: out, Partial: !out.Complete, Empty: len(out.Channels) == 0}, nil
}

func (c *Connector) searchEmojis(ctx context.Context, api *goslack.Client, call connectors.Call) (connectors.Result, error) {
	q, err := needle(call.Args, false)
	if err != nil {
		return connectors.Result{}, err
	}
	limit, _, err := c.limitArg(call.Args, "limit", connectors.DefaultMaxPageSize)
	if err != nil {
		return connectors.Result{}, err
	}
	all, err := api.GetEmojiContext(ctx)
	if err := classify("search emojis", err); err != nil {
		return connectors.Result{}, err
	}
	names := make([]string, 0, len(all))
	for name := range all {
		if q == "" || strings.Contains(strings.ToLower(name), q) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	out := EmojisFound{Emojis: []Emoji{}, Total: len(names)}
	for _, name := range names[:min(limit, len(names))] {
		e := Emoji{Name: name}
		if alias, ok := strings.CutPrefix(all[name], "alias:"); ok {
			e.AliasFor = alias
		} else {
			e.URL = all[name]
		}
		out.Emojis = append(out.Emojis, e)
	}
	out.Emojis, _ = fit(out.Emojis, c.bounds.MaxResultBytes, func(items []Emoji) any { out.Emojis = items; return out })
	return connectors.Result{Content: out, Partial: len(out.Emojis) < out.Total, Empty: out.Total == 0}, nil
}

// textMIME reports whether a file's content is returned as text.
func textMIME(mimetype, filetype string) bool {
	m := strings.ToLower(strings.TrimSpace(strings.Split(mimetype, ";")[0]))
	switch {
	case strings.HasPrefix(m, "text/"), strings.HasSuffix(m, "+json"), strings.HasSuffix(m, "+xml"):
		return true
	}
	switch m {
	case "application/json", "application/xml", "application/javascript", "application/x-yaml", "application/yaml", "application/csv":
		return true
	}
	switch strings.ToLower(filetype) {
	case "text", "markdown", "csv", "json", "yaml", "xml", "html", "javascript", "python", "go", "shell", "sql", "post":
		return true
	}
	return false
}

func (c *Connector) readFile(ctx context.Context, web *webAPI, call connectors.Call) (connectors.Result, error) {
	id, err := fileArg(call.Args, "file")
	if err != nil {
		return connectors.Result{}, err
	}
	maxBytes := MaxReadFileBytes
	if v, ok := call.Args["max_bytes"]; ok && v != nil {
		if maxBytes, err = toInt(v); err != nil || maxBytes < 1 || maxBytes > MaxReadFileBytes {
			return connectors.Result{}, invalid("max_bytes must be an integer from 1 to %d", MaxReadFileBytes)
		}
	}
	metaOnly, err := boolArg(call.Args, "metadata_only", false)
	if err != nil {
		return connectors.Result{}, err
	}
	f, _, _, err := web.api.GetFileInfoContext(ctx, id, 0, 0)
	if err := classify("read file", err); err != nil {
		return connectors.Result{}, err
	}
	out := FileContent{File: toFileInfo(*f)}
	if metaOnly {
		return connectors.Result{Content: out}, nil
	}
	text := textMIME(f.Mimetype, f.Filetype)
	link := or(f.URLPrivateDownload, f.URLPrivate)
	switch {
	case link == "":
		out.Omitted = "Slack gives no download URL for this file"
	case !c.uploadURLAllowed(link):
		out.Omitted = "the download URL is not on a Slack host; the file was not fetched"
	case !text && f.Size > maxBytes:
		out.Omitted = fmt.Sprintf("binary file of %d bytes is larger than max_bytes %d; not downloaded", f.Size, maxBytes)
	}
	if out.Omitted != "" {
		return connectors.Result{Content: out, Partial: true}, nil
	}
	data, err := web.download(ctx, link, maxBytes)
	if err := classify("download file", err); err != nil {
		return connectors.Result{}, err
	}
	switch {
	case text:
		out.Truncated = len(data) > maxBytes || f.Size > maxBytes
		data = data[:min(len(data), maxBytes)]
		// A cut may split the last rune: drop its partial bytes.
		for i := 0; i < utf8.UTFMax-1 && len(data) > 0 && !utf8.Valid(data); i++ {
			data = data[:len(data)-1]
		}
		out.Content, out.Encoding = strings.ToValidUTF8(string(data), "\uFFFD"), "text"
	case len(data) > maxBytes:
		out.Omitted = fmt.Sprintf("binary file is larger than max_bytes %d; content left out", maxBytes)
	default:
		out.Content, out.Encoding = base64.StdEncoding.EncodeToString(data), "base64"
	}
	return connectors.Result{Content: out, Partial: out.Truncated || out.Omitted != ""}, nil
}
