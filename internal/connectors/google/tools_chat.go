package google

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"google.golang.org/api/chat/v1"
	"google.golang.org/api/googleapi"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// The Google Chat app (increment 4): spaces, messages and members of the
// connected user's Chat, through the Chat API with user authentication.
// Every Chat scope is Workspace-only (WorkspaceOnlyScope): personal
// Google accounts have no Chat API access, so connect never asks them for
// these scopes and the scope gate explains why.

// Chat tool names.
const (
	ToolChatListSpaces   = "list_spaces"
	ToolChatGetSpace     = "get_space"
	ToolChatListMessages = "list_messages"
	ToolChatGetMessage   = "get_message"
	ToolChatListMembers  = "list_members"
)

// defaultChatMessagesPerPage is list_messages' page size when the harness
// gives none (the Chat API's own default).
const defaultChatMessagesPerPage = 25

// chatWorkspaceNote ends every Chat tool's description.
const chatWorkspaceNote = " Google Workspace accounts only (personal Google accounts have no Chat API)."

// chatAppNotConfigured is the advice for the Chat API's 404 "Google Chat
// app not found": the gateway's Cloud project has the API off or no Chat
// app configured, which every user call needs.
const chatAppNotConfigured = "the gateway's Google Cloud project has no Google Chat app: an admin must enable the Google Chat API " +
	"and configure the Chat app on the Chat API's Configuration page in the Google Cloud console"

// Chat resource names: spaces/{space}, spaces/{space}/messages/{message},
// spaces/{space}/threads/{thread}. Ids are letters, digits, dots,
// underscores and hyphens (system message ids carry a dot; client ids
// start with "client-").
var (
	chatIDRE      = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	chatMessageRE = regexp.MustCompile(`^(spaces/[A-Za-z0-9._-]+)/messages/[A-Za-z0-9._-]+$`)
	chatThreadRE  = regexp.MustCompile(`^(spaces/[A-Za-z0-9._-]+)/threads/[A-Za-z0-9._-]+$`)
)

// ChatSpace is one list_spaces item.
type ChatSpace struct {
	Name            string `json:"name"`
	DisplayName     string `json:"display_name,omitempty"`
	SpaceType       string `json:"space_type,omitempty"`
	SingleUserBotDM bool   `json:"single_user_bot_dm,omitempty"`
	Threaded        bool   `json:"threaded,omitempty"`
	URL             string `json:"url,omitempty"`
}

// ChatSpacesPage is list_spaces' result.
type ChatSpacesPage struct {
	MaxResults    int         `json:"max_results"`
	NextPageToken string      `json:"next_page_token,omitempty"`
	HasMore       bool        `json:"has_more"`
	Truncated     bool        `json:"truncated,omitempty"`
	Items         []ChatSpace `json:"items"`
}

// ChatSpaceDetail is get_space's result: the list item plus the space's
// description (cut to the bounds), times and member counts.
type ChatSpaceDetail struct {
	ChatSpace
	Description         string `json:"description,omitempty"`
	Created             string `json:"created,omitempty"`
	LastActive          string `json:"last_active,omitempty"`
	ExternalUserAllowed bool   `json:"external_user_allowed,omitempty"`
	MemberCount         int64  `json:"member_count,omitempty"`
	GroupCount          int64  `json:"group_count,omitempty"`
	Truncated           bool   `json:"truncated,omitempty"`
}

// ChatUser is a message sender or a member. With user authentication
// Google fills display_name only for users the caller shares a space or a
// direct message with, and for apps.
type ChatUser struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	Type        string `json:"type,omitempty"`
}

// ChatMessage is one list_messages item; Attachments counts them.
type ChatMessage struct {
	Name        string   `json:"name"`
	Sender      ChatUser `json:"sender"`
	Created     string   `json:"created,omitempty"`
	Text        string   `json:"text"`
	Truncated   bool     `json:"truncated,omitempty"`
	Thread      string   `json:"thread,omitempty"`
	ThreadReply bool     `json:"thread_reply,omitempty"`
	Attachments int      `json:"attachments,omitempty"`
}

// ChatMessagesPage is list_messages' result.
type ChatMessagesPage struct {
	Space         string        `json:"space"`
	Order         string        `json:"order"`
	MaxResults    int           `json:"max_results"`
	NextPageToken string        `json:"next_page_token,omitempty"`
	HasMore       bool          `json:"has_more"`
	Truncated     bool          `json:"truncated,omitempty"`
	Items         []ChatMessage `json:"items"`
}

// ChatAttachment is one attachment of get_message (metadata only).
type ChatAttachment struct {
	Name        string `json:"name"`
	ContentName string `json:"content_name,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Source      string `json:"source,omitempty"`
}

// ChatMessageDetail is get_message's result.
type ChatMessageDetail struct {
	Name        string           `json:"name"`
	Space       string           `json:"space"`
	Sender      ChatUser         `json:"sender"`
	Created     string           `json:"created,omitempty"`
	Updated     string           `json:"updated,omitempty"`
	Text        string           `json:"text"`
	Truncated   bool             `json:"truncated,omitempty"`
	Thread      string           `json:"thread,omitempty"`
	ThreadReply bool             `json:"thread_reply,omitempty"`
	Attachments []ChatAttachment `json:"attachments"`
}

// ChatMember is one list_members item: a user or app (Member) or a
// Google Group (Group).
type ChatMember struct {
	Name    string    `json:"name"`
	Member  *ChatUser `json:"member,omitempty"`
	Group   string    `json:"group,omitempty"`
	Role    string    `json:"role,omitempty"`
	State   string    `json:"state,omitempty"`
	Created string    `json:"created,omitempty"`
}

// ChatMembersPage is list_members' result.
type ChatMembersPage struct {
	Space         string       `json:"space"`
	MaxResults    int          `json:"max_results"`
	NextPageToken string       `json:"next_page_token,omitempty"`
	HasMore       bool         `json:"has_more"`
	Truncated     bool         `json:"truncated,omitempty"`
	Items         []ChatMember `json:"items"`
}

var (
	chatSpaceProperty      = property{"space", "string", "The space: its resource name spaces/<id> (from chat.list_spaces) or the bare id.", nil}
	chatMaxResultsProperty = func(what string, def int) property {
		return property{"max_results", "integer", fmt.Sprintf("%s per page (1-100; default %d); clamped to the tool's maximum.", what, def), nil}
	}
	chatPageTokenProperty = property{"page_token", "string", "Token of the page to fetch (next_page_token of the previous result).", nil}
)

func (c *Connector) chatReadTools() []connectors.Tool {
	tool := func(name, description string, props []property, required []string, scope string, identity func(map[string]any) map[string]string, bounds connectors.Bounds) connectors.Tool {
		return connectors.Tool{
			App: AppChat, Name: name, Kind: connectors.KindRead,
			Description:      description + chatWorkspaceNote,
			InputSchema:      objectSchema(props, required),
			RequiredScopes:   []string{scope},
			ResourceIdentity: identity,
			Bounds:           bounds,
		}
	}
	return []connectors.Tool{
		tool(ToolChatListSpaces,
			"List the Google Chat spaces the account is a member of (named spaces, group chats and direct messages): name "+
				"(spaces/<id>, the space argument of the other chat tools), display_name, space_type (SPACE, GROUP_CHAT, "+
				"DIRECT_MESSAGE), threaded and url. has_more and next_page_token say whether another page exists.",
			[]property{
				chatMaxResultsProperty("Spaces", connectors.DefaultMaxPageSize), chatPageTokenProperty,
				{"filter", "string", `Chat API filter on the space type, e.g. spaceType = "SPACE" or spaceType = "GROUP_CHAT" OR spaceType = "DIRECT_MESSAGE".`, nil},
			}, nil, ScopeChatSpacesReadonly, noIdentity, c.pagedBounds()),
		tool(ToolChatGetSpace,
			"Get one Google Chat space: display name, type, description, created and last-active times, whether external "+
				"users are allowed, and its member counts.",
			[]property{chatSpaceProperty}, []string{"space"}, ScopeChatSpacesReadonly, chatSpaceIdentity, c.singleBounds()),
		tool(ToolChatListMessages,
			"List the messages of a Google Chat space, newest first unless order is asc: name, sender (name users/<id>, "+
				"display_name, type HUMAN or BOT), created, text (cut to the bounds: truncated), thread and the number of "+
				"attachments. Narrow by thread or by a since / until time window. has_more and next_page_token say whether "+
				"another page exists.",
			[]property{
				chatSpaceProperty,
				chatMaxResultsProperty("Messages", defaultChatMessagesPerPage), chatPageTokenProperty,
				{"thread", "string", "Only this thread: its resource name spaces/<id>/threads/<thread> (a message's thread).", nil},
				{"since", "string", "Only messages created after this RFC 3339 timestamp.", nil},
				{"until", "string", "Only messages created before this RFC 3339 timestamp.", nil},
				{"order", "string", "desc (default: newest first) or asc.", []string{"desc", "asc"}},
			}, []string{"space"}, ScopeChatMessagesReadonly, chatThreadIdentity, c.pagedBounds()),
		tool(ToolChatGetMessage,
			"Get one Google Chat message by its resource name (spaces/<id>/messages/<id>): sender, created, updated, text "+
				"(cut to the bounds: truncated), thread and its attachments' names and types (never their content).",
			[]property{{"message", "string", "The message's resource name spaces/<id>/messages/<id> (from chat.list_messages).", nil}},
			[]string{"message"}, ScopeChatMessagesReadonly, chatMessageIdentity, c.singleBounds()),
		tool(ToolChatListMembers,
			"List the members of a Google Chat space: users and apps (member with name users/<id>, display_name, type) "+
				"and Google Groups (group), with their role (ROLE_MEMBER, ROLE_MANAGER) and state. Google gives display "+
				"names of users only when the account shares a space or direct message with them. has_more and "+
				"next_page_token say whether another page exists.",
			[]property{chatSpaceProperty, chatMaxResultsProperty("Members", connectors.DefaultMaxPageSize), chatPageTokenProperty},
			[]string{"space"}, ScopeChatMembershipsReadonly, chatSpaceIdentity, c.pagedBounds()),
	}
}

func (c *Connector) chatReadHandlers() map[string]handler {
	return map[string]handler{
		ToolChatListSpaces:   c.chatListSpaces,
		ToolChatGetSpace:     c.chatGetSpace,
		ToolChatListMessages: c.chatListMessages,
		ToolChatGetMessage:   c.chatGetMessage,
		ToolChatListMembers:  c.chatListMembers,
	}
}

// --- names and identity ------------------------------------------------------------

// noIdentity is the resource identity of a tool that names no resource
// (never its query or filter).
func noIdentity(map[string]any) map[string]string { return map[string]string{} }

// chatSpaceName normalizes a space argument to spaces/<id>; false when
// it is not one.
func chatSpaceName(v string) (string, bool) {
	id := strings.TrimPrefix(strings.TrimSpace(v), "spaces/")
	if !chatIDRE.MatchString(id) {
		return "", false
	}
	return "spaces/" + id, true
}

// chatSpaceArg reads the required space argument.
func chatSpaceArg(args map[string]any) (string, error) {
	v, err := requiredString(args, "space")
	if err != nil {
		return "", err
	}
	name, ok := chatSpaceName(v)
	if !ok {
		return "", invalid("space must be a Chat space: spaces/<id> or the bare id")
	}
	return name, nil
}

// chatThreadArg reads an optional thread resource name, which must be a
// thread of space.
func chatThreadArg(args map[string]any, space string) (string, error) {
	v, err := optionalString(args, "thread")
	if err != nil {
		return "", err
	}
	if v = strings.TrimSpace(v); v == "" {
		return "", nil
	}
	m := chatThreadRE.FindStringSubmatch(v)
	if m == nil {
		return "", invalid("thread must be a thread's resource name spaces/<id>/threads/<thread>")
	}
	if m[1] != space {
		return "", invalid("thread %s is not a thread of %s", v, space)
	}
	return v, nil
}

// chatSpaceIdentity is the space only (normalized), never anything else.
func chatSpaceIdentity(args map[string]any) map[string]string {
	out := map[string]string{}
	if v, _ := args["space"].(string); v != "" {
		if name, ok := chatSpaceName(v); ok {
			out["space"] = name
		}
	}
	return out
}

// chatThreadIdentity is chatSpaceIdentity plus the thread resource name.
func chatThreadIdentity(args map[string]any) map[string]string {
	out := chatSpaceIdentity(args)
	if v, _ := args["thread"].(string); chatThreadRE.MatchString(strings.TrimSpace(v)) {
		out["thread"] = strings.TrimSpace(v)
	}
	return out
}

// chatMessageIdentity is the message's space and resource name.
func chatMessageIdentity(args map[string]any) map[string]string {
	out := map[string]string{}
	v, _ := args["message"].(string)
	if m := chatMessageRE.FindStringSubmatch(strings.TrimSpace(v)); m != nil {
		out["space"], out["message"] = m[1], strings.TrimSpace(v)
	}
	return out
}

// --- errors ----------------------------------------------------------------------------

// chatAppMissing reports the Chat API's 404 "Google Chat app not found".
func chatAppMissing(err error) bool {
	var ge *googleapi.Error
	return errors.As(err, &ge) && ge.Code == 404 && strings.Contains(ge.Message, "Chat app not found")
}

// classifyChat is classify, except that the Chat API's "Google Chat app
// not found" (a 404 about the gateway's Cloud project, not the resource)
// is forbidden with the admin's fix.
func classifyChat(action string, err error) error {
	if chatAppMissing(err) {
		return &Error{Status: 404, Class: ClassForbidden, Message: action + ": " + chatAppNotConfigured, Err: err}
	}
	return classify(action, err)
}

// --- conversions -----------------------------------------------------------------------

func toChatSpace(s *chat.Space) ChatSpace {
	return ChatSpace{
		Name: s.Name, DisplayName: s.DisplayName, SpaceType: s.SpaceType, SingleUserBotDM: s.SingleUserBotDm,
		Threaded: s.SpaceThreadingState == "THREADED_MESSAGES", URL: s.SpaceUri,
	}
}

func toChatUser(u *chat.User) ChatUser {
	if u == nil {
		return ChatUser{}
	}
	return ChatUser{Name: u.Name, DisplayName: u.DisplayName, Type: u.Type}
}

func chatThreadName(t *chat.Thread) string {
	if t == nil {
		return ""
	}
	return t.Name
}

func toChatMessage(m *chat.Message) ChatMessage {
	return ChatMessage{
		Name: m.Name, Sender: toChatUser(m.Sender), Created: normalizeTimestamp(m.CreateTime), Text: m.Text,
		Thread: chatThreadName(m.Thread), ThreadReply: m.ThreadReply, Attachments: len(m.Attachment),
	}
}

// --- handlers ----------------------------------------------------------------------------

func (c *Connector) chatListSpaces(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	maxResults, pageToken, clamped, err := c.pageArgs(call.Args, connectors.DefaultMaxPageSize)
	if err != nil {
		return connectors.Result{}, err
	}
	filter, err := optionalString(call.Args, "filter")
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.chat(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	req := svc.Spaces.List().Context(ctx).PageSize(int64(maxResults))
	if filter = strings.TrimSpace(filter); filter != "" {
		req = req.Filter(filter)
	}
	if pageToken != "" {
		req = req.PageToken(pageToken)
	}
	resp, err := req.Do()
	if err := classifyChat("list Chat spaces", err); err != nil {
		return connectors.Result{}, err
	}
	page := ChatSpacesPage{MaxResults: maxResults, NextPageToken: resp.NextPageToken, HasMore: resp.NextPageToken != "", Items: make([]ChatSpace, 0, len(resp.Spaces))}
	for _, s := range resp.Spaces {
		if s != nil {
			page.Items = append(page.Items, toChatSpace(s))
		}
	}
	res := connectors.Result{Partial: clamped, Empty: len(page.Items) == 0}
	for encodedSize(page) > c.bounds.MaxResultBytes && len(page.Items) > 1 {
		page.Items = page.Items[:len(page.Items)-1]
		page.Truncated, res.Partial = true, true
	}
	res.Content = page
	return res, nil
}

func (c *Connector) chatGetSpace(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	space, err := chatSpaceArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.chat(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	s, err := svc.Spaces.Get(space).Context(ctx).Do()
	if err := classifyChat("get Chat space", err); err != nil {
		return connectors.Result{}, err
	}
	out := ChatSpaceDetail{
		ChatSpace: toChatSpace(s), Created: normalizeTimestamp(s.CreateTime), LastActive: normalizeTimestamp(s.LastActiveTime),
		ExternalUserAllowed: s.ExternalUserAllowed,
	}
	if s.SpaceDetails != nil {
		out.Description = s.SpaceDetails.Description
	}
	if s.MembershipCount != nil {
		out.MemberCount, out.GroupCount = s.MembershipCount.JoinedDirectHumanUserCount, s.MembershipCount.JoinedGroupCount
	}
	fitBody(&out.Description, &out.Truncated, c.bounds.MaxResultBytes, func() any { return out })
	return connectors.Result{Content: out, Partial: out.Truncated}, nil
}

func (c *Connector) chatListMessages(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	space, err := chatSpaceArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	maxResults, pageToken, clamped, err := c.pageArgs(call.Args, defaultChatMessagesPerPage)
	if err != nil {
		return connectors.Result{}, err
	}
	thread, err := chatThreadArg(call.Args, space)
	if err != nil {
		return connectors.Result{}, err
	}
	since, err := optionalTime(call.Args, "since")
	if err != nil {
		return connectors.Result{}, err
	}
	until, err := optionalTime(call.Args, "until")
	if err != nil {
		return connectors.Result{}, err
	}
	if !since.IsZero() && !until.IsZero() && !until.After(since) {
		return connectors.Result{}, invalid("until must be after since")
	}
	order, err := optionalString(call.Args, "order")
	if err != nil {
		return connectors.Result{}, err
	}
	switch order = strings.ToLower(strings.TrimSpace(order)); order {
	case "":
		order = "desc"
	case "asc", "desc":
	default:
		return connectors.Result{}, invalid("order must be asc or desc")
	}
	var filter []string
	if !since.IsZero() {
		filter = append(filter, fmt.Sprintf("createTime > %q", since.Format(time.RFC3339)))
	}
	if !until.IsZero() {
		filter = append(filter, fmt.Sprintf("createTime < %q", until.Format(time.RFC3339)))
	}
	if thread != "" {
		filter = append(filter, "thread.name = "+thread)
	}
	svc, err := cl.chat(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	req := svc.Spaces.Messages.List(space).Context(ctx).PageSize(int64(maxResults)).OrderBy("createTime " + order)
	if len(filter) > 0 {
		req = req.Filter(strings.Join(filter, " AND "))
	}
	if pageToken != "" {
		req = req.PageToken(pageToken)
	}
	resp, err := req.Do()
	if err := classifyChat("list Chat messages", err); err != nil {
		return connectors.Result{}, err
	}
	page := ChatMessagesPage{Space: space, Order: order, MaxResults: maxResults, NextPageToken: resp.NextPageToken, HasMore: resp.NextPageToken != "", Items: make([]ChatMessage, 0, len(resp.Messages))}
	for _, m := range resp.Messages {
		if m != nil {
			page.Items = append(page.Items, toChatMessage(m))
		}
	}
	res := connectors.Result{Partial: clamped, Empty: len(page.Items) == 0}
	for encodedSize(page) > c.bounds.MaxResultBytes && len(page.Items) > 1 {
		page.Items = page.Items[:len(page.Items)-1]
		page.Truncated, res.Partial = true, true
	}
	if len(page.Items) == 1 && encodedSize(page) > c.bounds.MaxResultBytes {
		first := &page.Items[0]
		fitBody(&first.Text, &first.Truncated, c.bounds.MaxResultBytes, func() any { return page })
		page.Truncated, res.Partial = true, true
	}
	res.Content = page
	return res, nil
}

func (c *Connector) chatGetMessage(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	name, err := requiredString(call.Args, "message")
	if err != nil {
		return connectors.Result{}, err
	}
	m := chatMessageRE.FindStringSubmatch(name)
	if m == nil {
		return connectors.Result{}, invalid("message must be a message's resource name spaces/<id>/messages/<id>")
	}
	svc, err := cl.chat(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	msg, err := svc.Spaces.Messages.Get(name).Context(ctx).Do()
	if err := classifyChat("get Chat message", err); err != nil {
		return connectors.Result{}, err
	}
	out := ChatMessageDetail{
		Name: msg.Name, Space: m[1], Sender: toChatUser(msg.Sender), Created: normalizeTimestamp(msg.CreateTime),
		Updated: normalizeTimestamp(msg.LastUpdateTime), Text: msg.Text, Thread: chatThreadName(msg.Thread), ThreadReply: msg.ThreadReply,
		Attachments: make([]ChatAttachment, 0, len(msg.Attachment)),
	}
	for _, a := range msg.Attachment {
		if a != nil {
			out.Attachments = append(out.Attachments, ChatAttachment{Name: a.Name, ContentName: a.ContentName, ContentType: a.ContentType, Source: a.Source})
		}
	}
	fitBody(&out.Text, &out.Truncated, c.bounds.MaxResultBytes, func() any { return out })
	return connectors.Result{Content: out, Partial: out.Truncated}, nil
}

func (c *Connector) chatListMembers(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	space, err := chatSpaceArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	maxResults, pageToken, clamped, err := c.pageArgs(call.Args, connectors.DefaultMaxPageSize)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.chat(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	req := svc.Spaces.Members.List(space).Context(ctx).PageSize(int64(maxResults)).ShowGroups(true)
	if pageToken != "" {
		req = req.PageToken(pageToken)
	}
	resp, err := req.Do()
	if err := classifyChat("list Chat members", err); err != nil {
		return connectors.Result{}, err
	}
	page := ChatMembersPage{Space: space, MaxResults: maxResults, NextPageToken: resp.NextPageToken, HasMore: resp.NextPageToken != "", Items: make([]ChatMember, 0, len(resp.Memberships))}
	for _, m := range resp.Memberships {
		if m == nil {
			continue
		}
		item := ChatMember{Name: m.Name, Role: m.Role, State: m.State, Created: normalizeTimestamp(m.CreateTime)}
		if m.Member != nil {
			u := toChatUser(m.Member)
			item.Member = &u
		}
		if m.GroupMember != nil {
			item.Group = m.GroupMember.Name
		}
		page.Items = append(page.Items, item)
	}
	res := connectors.Result{Partial: clamped, Empty: len(page.Items) == 0}
	for encodedSize(page) > c.bounds.MaxResultBytes && len(page.Items) > 1 {
		page.Items = page.Items[:len(page.Items)-1]
		page.Truncated, res.Partial = true, true
	}
	res.Content = page
	return res, nil
}
