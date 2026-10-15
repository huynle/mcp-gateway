package microsoft

import (
	"context"
	"net/url"
	"strconv"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/microsoft/graph"
)

// Teams tools beyond channels: the user's chats (1:1, group, meeting),
// their messages, channel thread replies, and posting to chats and
// threads. Work accounts only (WorkOnlyScope).
const (
	ToolTeamsListChats          = "teams_list_chats"
	ToolTeamsReadChatMessages   = "teams_read_chat_messages"
	ToolTeamsReadChannelReplies = "teams_read_channel_replies"
	ToolTeamsSendChatMessage    = "teams_send_chat_message"
	ToolTeamsReplyChannelMsg    = "teams_reply_channel_message"
)

// Chat is one teams_list_chats item.
type Chat struct {
	ID            string `json:"id"`
	Topic         string `json:"topic,omitempty"`
	ChatType      string `json:"chat_type"`
	LastUpdatedAt string `json:"last_updated_at,omitempty"`
	WebURL        string `json:"web_url,omitempty"`
}

type graphChat struct {
	ID                  string `json:"id"`
	Topic               string `json:"topic"`
	ChatType            string `json:"chatType"`
	LastUpdatedDateTime string `json:"lastUpdatedDateTime"`
	WebURL              string `json:"webUrl"`
}

// SentChatMessage is the result of teams_send_chat_message and
// teams_reply_channel_message.
type SentChatMessage struct {
	ID        string `json:"id"`
	WebURL    string `json:"web_url,omitempty"`
	ChatID    string `json:"chat_id,omitempty"`
	TeamID    string `json:"team_id,omitempty"`
	ChannelID string `json:"channel_id,omitempty"`
	ReplyToID string `json:"reply_to_id,omitempty"`
}

func (c *Connector) teamsDefs() []toolDef {
	paged := connectors.Bounds{MaxPageSize: c.bounds.MaxPageSize, MaxResultBytes: c.bounds.MaxResultBytes}
	single := connectors.Bounds{MaxResultBytes: c.bounds.MaxResultBytes}
	chat := property{"chat_id", "string", "The chat id (from teams_list_chats).", nil}
	top50 := property{"top", "integer", "Number of results (1-50); clamped to the tool's maximum.", nil}
	thread := []property{
		{"team_id", "string", "Team id.", nil},
		{"channel_id", "string", "Channel id.", nil},
		{"message_id", "string", "The channel message (thread root) id.", nil},
	}
	threadIdentity := identity("team_id", "team", "channel_id", "channel", "message_id", "message")
	content := []property{
		{"content", "string", "Message content.", nil},
		{"content_type", "string", "Content type: text (default) or html.", []string{"text", "html"}},
	}
	none := connectors.Reconciliation{Kind: connectors.ReconcileNone}
	return []toolDef{
		{Tool: connectors.Tool{
			App: App, Name: ToolTeamsListChats, Kind: connectors.KindRead,
			Description:      "List the user's Teams chats (one-on-one, group and meeting chats): id, topic, type, last update. Work accounts only.",
			InputSchema:      objectSchema([]property{top50}, nil),
			RequiredScopes:   []string{ScopeChatReadBasic},
			ResourceIdentity: identity(),
			Bounds:           paged,
		}, run: c.teamsListChats},
		{Tool: connectors.Tool{
			App: App, Name: ToolTeamsReadChatMessages, Kind: connectors.KindRead,
			Description:      "Read the newest messages of a Teams chat (id, author, time, content as text or html). Work accounts only.",
			InputSchema:      objectSchema([]property{chat, top50}, []string{"chat_id"}),
			RequiredScopes:   []string{ScopeChatRead},
			ResourceIdentity: identity("chat_id", "chat"),
			Bounds:           paged,
		}, run: c.teamsReadChatMessages},
		{Tool: connectors.Tool{
			App: App, Name: ToolTeamsReadChannelReplies, Kind: connectors.KindRead,
			Description: "Read the replies of a Teams channel message (its thread). Work accounts only; needs admin consent " +
				"(ChannelMessage.Read.All).",
			InputSchema:      objectSchema(append(append([]property{}, thread...), top50), []string{"team_id", "channel_id", "message_id"}),
			RequiredScopes:   []string{ScopeChannelMessageReadAll},
			ResourceIdentity: threadIdentity,
			Bounds:           paged,
		}, run: c.teamsReadChannelReplies},
		{Tool: connectors.Tool{
			App: App, Name: ToolTeamsSendChatMessage, Kind: connectors.KindWrite,
			Description: "Send a message to a Teams chat as the user (plain text, or HTML with content_type html). Work accounts only. " +
				"The outcome of a lost reply cannot be verified afterwards.",
			InputSchema:      objectSchema(append([]property{chat}, content...), []string{"chat_id", "content"}),
			RequiredScopes:   []string{ScopeChatMessageSend},
			ResourceIdentity: identity("chat_id", "chat"),
			Reconcile:        none,
			ResultIDs:        resultIDs("id", "web_url"),
			Bounds:           single,
		}, run: c.teamsSendChatMessage},
		{Tool: connectors.Tool{
			App: App, Name: ToolTeamsReplyChannelMsg, Kind: connectors.KindWrite,
			Description: "Reply in the thread of a Teams channel message as the user (plain text, or HTML with content_type html). Work " +
				"accounts only. The outcome of a lost reply cannot be verified afterwards.",
			InputSchema:      objectSchema(append(append([]property{}, thread...), content...), []string{"team_id", "channel_id", "message_id", "content"}),
			RequiredScopes:   []string{ScopeChannelMessageSend},
			ResourceIdentity: threadIdentity,
			Reconcile:        none,
			ResultIDs:        resultIDs("id", "web_url"),
			Bounds:           single,
		}, run: c.teamsReplyChannelMessage},
	}
}

func (c *Connector) teamsListChats(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	top, clamped, err := c.topArg(call.Args, maxChannelMessagesTop)
	if err != nil {
		return connectors.Result{}, err
	}
	return listRead(ctx, c, client, "list chats", "me/chats", url.Values{"$top": {strconv.Itoa(top)}}, nil, top, clamped, func(g graphChat) Chat {
		return Chat{ID: g.ID, Topic: g.Topic, ChatType: g.ChatType, LastUpdatedAt: g.LastUpdatedDateTime, WebURL: g.WebURL}
	})
}

func (c *Connector) teamsReadChatMessages(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	id, err := requiredID(call.Args, "chat_id")
	if err != nil {
		return connectors.Result{}, err
	}
	top, clamped, err := c.topArg(call.Args, maxChannelMessagesTop)
	if err != nil {
		return connectors.Result{}, err
	}
	return listRead(ctx, c, client, "read chat messages", "chats/"+id+"/messages", url.Values{"$top": {strconv.Itoa(top)}}, nil, top, clamped, toChannelMessage)
}

// threadArgs reads team_id, channel_id and message_id.
func threadArgs(args map[string]any) (team, channel, message string, err error) {
	if team, err = requiredID(args, "team_id"); err != nil {
		return
	}
	if channel, err = requiredID(args, "channel_id"); err != nil {
		return
	}
	message, err = requiredID(args, "message_id")
	return
}

func (c *Connector) teamsReadChannelReplies(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	team, channel, message, err := threadArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	top, clamped, err := c.topArg(call.Args, maxChannelMessagesTop)
	if err != nil {
		return connectors.Result{}, err
	}
	path := "teams/" + team + "/channels/" + channel + "/messages/" + message + "/replies"
	return listRead(ctx, c, client, "read channel replies", path, url.Values{"$top": {strconv.Itoa(top)}}, nil, top, clamped, toChannelMessage)
}

// postChatMessage posts content to path and returns the new message.
func postChatMessage(ctx context.Context, client *graph.Client, call connectors.Call, action, path string) (graphChatMessage, error) {
	content, err := requiredString(call.Args, "content")
	if err != nil {
		return graphChatMessage{}, err
	}
	if len(content) > maxBodyBytes {
		return graphChatMessage{}, invalid("content is too long")
	}
	contentType, err := contentTypeArg(call.Args, false)
	if err != nil {
		return graphChatMessage{}, err
	}
	var posted graphChatMessage
	if _, err := client.Post(ctx, path, map[string]any{"body": map[string]string{"contentType": contentType, "content": content}}, &posted); err != nil {
		return graphChatMessage{}, classifyWrite(action, err)
	}
	if posted.ID == "" {
		return graphChatMessage{}, errNoID(action, "message")
	}
	return posted, nil
}

func (c *Connector) teamsSendChatMessage(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	id, err := requiredID(call.Args, "chat_id")
	if err != nil {
		return connectors.Result{}, err
	}
	posted, err := postChatMessage(ctx, client, call, "send chat message", "chats/"+id+"/messages")
	if err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: SentChatMessage{ID: posted.ID, WebURL: posted.WebURL, ChatID: id}}, nil
}

func (c *Connector) teamsReplyChannelMessage(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	team, channel, message, err := threadArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	path := "teams/" + team + "/channels/" + channel + "/messages/" + message + "/replies"
	posted, err := postChatMessage(ctx, client, call, "reply to channel message", path)
	if err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: SentChatMessage{ID: posted.ID, WebURL: posted.WebURL, TeamID: team, ChannelID: channel, ReplyToID: message}}, nil
}
