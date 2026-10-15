package slack

import (
	"context"
	"strings"

	goslack "github.com/slack-go/slack"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// ToolListConversations lists channels and direct messages.
const ToolListConversations = "list_conversations"

// Slack user-token scopes of direct messages: list them (im:read,
// mpim:read) and read their history and threads (im:history,
// mpim:history, used by read_channel_history and get_thread with a D...
// or G... id).
const (
	ScopeIMRead      = "im:read"
	ScopeMpIMRead    = "mpim:read"
	ScopeIMHistory   = "im:history"
	ScopeMpIMHistory = "mpim:history"
)

// conversationTypeScopes maps every conversation type to the read scope
// that lists it, in listing order.
var conversationTypeScopes = []struct{ typ, scope string }{
	{"public_channel", ScopeChannelsRead},
	{"private_channel", ScopeGroupsRead},
	{"im", ScopeIMRead},
	{"mpim", ScopeMpIMRead},
}

// Conversation is one item of list_conversations: a channel, a direct
// message (is_im, the other user's id in user) or a group DM (is_mpim).
type Conversation struct {
	Channel
	IsIM   bool   `json:"is_im,omitempty"`
	IsMpIM bool   `json:"is_mpim,omitempty"`
	User   string `json:"user,omitempty"`
}

// ConversationsPage is list_conversations's result.
type ConversationsPage struct {
	Conversations []Conversation `json:"conversations"`
	NextCursor    string         `json:"next_cursor,omitempty"`
	HasMore       bool           `json:"has_more"`
	Limit         int            `json:"limit"`
	Truncated     bool           `json:"truncated,omitempty"`
}

func (c *Connector) conversationTools() []connectors.Tool {
	return []connectors.Tool{{
		App: App, Name: ToolListConversations, Kind: connectors.KindRead,
		Description: "List the connected user's conversations: channels, direct messages (is_im, with the other user's id) and " +
			"group DMs (is_mpim). Use a DM's id (D...) or group DM's id with read_channel_history and get_thread. " +
			"By default every type the account granted (im:read, mpim:read for DMs). Cursor paginated.",
		InputSchema: objectSchema([]property{
			{"types", "string", "Comma separated: public_channel, private_channel, im, mpim. Default: every type the account may list.", nil},
			limitProperty, cursorProperty,
			{"exclude_archived", "boolean", "Leave out archived channels. Default: true.", nil},
		}, nil),
		RequiredScopes:   []string{ScopeChannelsRead, ScopeGroupsRead},
		ResourceIdentity: func(map[string]any) map[string]string { return map[string]string{} },
		Bounds:           connectors.Bounds{MaxPageSize: c.bounds.MaxPageSize, MaxResultBytes: c.bounds.MaxResultBytes},
	}}
}

func (c *Connector) conversationHandlers() map[string]handler {
	return map[string]handler{ToolListConversations: c.listConversations}
}

// grantedTypes returns the conversation types the call's account granted
// the read scope of; public and private channels when the scopes are
// unknown (no account source, the account not found, none recorded).
func (c *Connector) grantedTypes(ctx context.Context, call connectors.Call) []string {
	if c.accounts == nil {
		return defaultChanType
	}
	accts, err := c.accounts.ListAccounts(ctx, call.Principal.UserID, App)
	if err != nil {
		return defaultChanType
	}
	for _, a := range accts {
		if a.ID != call.Account || len(a.Scopes) == 0 {
			continue
		}
		var types []string
		for _, ts := range conversationTypeScopes {
			if connectors.ScopeEquals(a.Scopes, ts.scope) {
				types = append(types, ts.typ)
			}
		}
		if len(types) > 0 {
			return types
		}
	}
	return defaultChanType
}

func (c *Connector) listConversations(ctx context.Context, api *goslack.Client, call connectors.Call) (connectors.Result, error) {
	raw, err := optionalString(call.Args, "types")
	if err != nil {
		return connectors.Result{}, err
	}
	var types []string
	if strings.TrimSpace(raw) == "" {
		types = c.grantedTypes(ctx, call)
	} else {
		for _, t := range strings.Split(raw, ",") {
			t = strings.ToLower(strings.TrimSpace(t))
			known := false
			for _, ts := range conversationTypeScopes {
				known = known || ts.typ == t
			}
			if !known {
				return connectors.Result{}, invalid("types must list public_channel, private_channel, im and/or mpim")
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
	if err := classify("list conversations", err); err != nil {
		return connectors.Result{}, err
	}
	out := ConversationsPage{Conversations: make([]Conversation, 0, len(channels)), NextCursor: next, HasMore: next != "", Limit: limit}
	for _, ch := range channels {
		ch.IsMember = true // users.conversations lists only the user's own conversations
		out.Conversations = append(out.Conversations, Conversation{Channel: toChannel(ch), IsIM: ch.IsIM, IsMpIM: ch.IsMpIM, User: ch.User})
	}
	out.Conversations, out.Truncated = fit(out.Conversations, c.bounds.MaxResultBytes, func(items []Conversation) any { out.Conversations = items; return out })
	return connectors.Result{Content: out, Partial: clamped || out.Truncated, Empty: len(out.Conversations) == 0}, nil
}
