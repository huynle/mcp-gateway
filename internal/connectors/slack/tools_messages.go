package slack

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	goslack "github.com/slack-go/slack"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Message, scheduled-message and pin tool names.
const (
	ToolUpdateMessage          = "update_message"
	ToolDeleteMessage          = "delete_message"
	ToolScheduleMessage        = "schedule_message"
	ToolListScheduledMessages  = "list_scheduled_messages"
	ToolDeleteScheduledMessage = "delete_scheduled_message"
	ToolPinMessage             = "pin_message"
	ToolUnpinMessage           = "unpin_message"
	ToolListPins               = "list_pins"
)

// Slack user-token scopes of the pin tools.
const (
	ScopePinsRead  = "pins:read"
	ScopePinsWrite = "pins:write"
)

// scheduledIDRE is the shape of a scheduled message id (Q...).
var scheduledIDRE = regexp.MustCompile(`^Q[A-Z0-9]{6,}$`)

// MessageChange is the result of update_message and delete_message.
type MessageChange struct {
	Channel string `json:"channel"`
	TS      string `json:"ts"`
	Action  string `json:"action"`
}

// ScheduledMessage is a message scheduled with schedule_message (the
// result of schedule_message and delete_scheduled_message, and one item
// of list_scheduled_messages). PostAt and Created are RFC 3339 UTC.
type ScheduledMessage struct {
	ID       string `json:"scheduled_message_id"`
	Channel  string `json:"channel"`
	PostAt   string `json:"post_at,omitempty"`
	ThreadTS string `json:"thread_ts,omitempty"`
	Text     string `json:"text,omitempty"`
	Created  string `json:"created,omitempty"`
	Action   string `json:"action,omitempty"`
}

// ScheduledPage is list_scheduled_messages's result.
type ScheduledPage struct {
	Messages   []ScheduledMessage `json:"scheduled_messages"`
	NextCursor string             `json:"next_cursor,omitempty"`
	HasMore    bool               `json:"has_more"`
	Limit      int                `json:"limit"`
	Truncated  bool               `json:"truncated,omitempty"`
}

// PinChange is the result of pin_message and unpin_message. Already says
// the message was already pinned (pin) or not pinned (unpin).
type PinChange struct {
	Channel   string `json:"channel"`
	Timestamp string `json:"timestamp"`
	Action    string `json:"action"`
	Already   bool   `json:"already,omitempty"`
}

// Pin is one pinned item of list_pins: a message (ts, user, text) or a
// file (file_id, file_name, title).
type Pin struct {
	Type     string `json:"type"`
	TS       string `json:"ts,omitempty"`
	User     string `json:"user,omitempty"`
	Text     string `json:"text,omitempty"`
	FileID   string `json:"file_id,omitempty"`
	FileName string `json:"file_name,omitempty"`
	Title    string `json:"title,omitempty"`
	Time     string `json:"time,omitempty"`
}

// PinsPage is list_pins's result.
type PinsPage struct {
	Channel   string `json:"channel"`
	Pins      []Pin  `json:"pins"`
	Truncated bool   `json:"truncated,omitempty"`
}

// messageTools declares the message-management tools.
func (c *Connector) messageTools() []connectors.Tool {
	single := connectors.Bounds{MaxResultBytes: c.bounds.MaxResultBytes}
	paged := connectors.Bounds{MaxPageSize: c.bounds.MaxPageSize, MaxResultBytes: c.bounds.MaxResultBytes}
	none := connectors.Reconciliation{Kind: connectors.ReconcileNone}
	chat := []string{ScopeChatWrite}
	tsProp := property{"ts", "string", "The message's ts (e.g. 1700003000.000200).", nil}
	timestampProp := property{"timestamp", "string", "The message's ts (e.g. 1700003000.000200).", nil}
	textProp := property{"text", "string", "Message text (Slack mrkdwn).", nil}
	scheduledIDProp := property{"scheduled_message_id", "string", "The scheduled message id (Q...) from schedule_message or list_scheduled_messages.", nil}
	return []connectors.Tool{
		{
			App: App, Name: ToolUpdateMessage, Kind: connectors.KindWrite,
			Description:    "Edit the text of a message the connected user posted, identified by channel and ts. Returns the channel and ts.",
			InputSchema:    objectSchema([]property{channelProperty, tsProp, textProp}, []string{"channel", "ts", "text"}),
			RequiredScopes: chat, ResourceIdentity: identity("ts"), Reconcile: none, ResultIDs: messageChangeIDs, Bounds: single,
		},
		{
			App: App, Name: ToolDeleteMessage, Kind: connectors.KindWrite,
			Description:    "Delete a message the connected user posted (or any message, for a workspace admin), identified by channel and ts.",
			InputSchema:    objectSchema([]property{channelProperty, tsProp}, []string{"channel", "ts"}),
			RequiredScopes: chat, ResourceIdentity: identity("ts"), Reconcile: stableID(c.checkDeleted),
			ResultIDs: messageChangeIDs, Bounds: single,
		},
		{
			App: App, Name: ToolScheduleMessage, Kind: connectors.KindWrite,
			Description: "Schedule a message to be posted as the connected user at post_at (at most 120 days ahead); with thread_ts, " +
				"as a reply in that thread. Returns the scheduled_message_id (delete_scheduled_message cancels it).",
			InputSchema: objectSchema([]property{
				channelProperty, textProp,
				{"post_at", "string", "When to post: an RFC 3339 time (2030-01-02T15:04:05Z, 2030-01-02T09:00:00-08:00) or unix seconds.", nil},
				{"thread_ts", "string", "Optional: the parent message timestamp to reply under.", nil},
			}, []string{"channel", "text", "post_at"}),
			RequiredScopes: chat, ResourceIdentity: scheduleIdentity, Reconcile: none, ResultIDs: scheduledIDs, Bounds: single,
		},
		{
			App: App, Name: ToolListScheduledMessages, Kind: connectors.KindRead,
			Description: "List the connected user's pending scheduled messages (id, channel, post_at, text), in one channel or all. Cursor paginated.",
			InputSchema: objectSchema([]property{
				{"channel", "string", "Optional: only this channel (id or name).", nil}, limitProperty, cursorProperty,
			}, nil),
			RequiredScopes: chat, ResourceIdentity: identity(), Bounds: paged,
		},
		{
			App: App, Name: ToolDeleteScheduledMessage, Kind: connectors.KindWrite,
			Description:    "Cancel a pending scheduled message by its channel and scheduled_message_id.",
			InputSchema:    objectSchema([]property{channelProperty, scheduledIDProp}, []string{"channel", "scheduled_message_id"}),
			RequiredScopes: chat, ResourceIdentity: identity("scheduled_message_id"), Reconcile: none, ResultIDs: scheduledIDs, Bounds: single,
		},
		{
			App: App, Name: ToolPinMessage, Kind: connectors.KindWrite,
			Description:    "Pin a message to its channel. Idempotent: an already pinned message is reported with already: true.",
			InputSchema:    objectSchema([]property{channelProperty, timestampProp}, []string{"channel", "timestamp"}),
			RequiredScopes: []string{ScopePinsWrite}, ResourceIdentity: identity("timestamp"),
			Reconcile: stableID(c.checkPinned(true)), ResultIDs: pinChangeIDs, Bounds: single,
		},
		{
			App: App, Name: ToolUnpinMessage, Kind: connectors.KindWrite,
			Description:    "Unpin a message from its channel. Idempotent: a message that is not pinned is reported with already: true.",
			InputSchema:    objectSchema([]property{channelProperty, timestampProp}, []string{"channel", "timestamp"}),
			RequiredScopes: []string{ScopePinsWrite}, ResourceIdentity: identity("timestamp"),
			Reconcile: stableID(c.checkPinned(false)), ResultIDs: pinChangeIDs, Bounds: single,
		},
		{
			App: App, Name: ToolListPins, Kind: connectors.KindRead,
			Description:    "List the items pinned in a Slack channel: messages (ts, user, text) and files (file_id, file_name, title).",
			InputSchema:    objectSchema([]property{channelProperty}, []string{"channel"}),
			RequiredScopes: []string{ScopePinsRead}, ResourceIdentity: identity(), Bounds: single,
		},
	}
}

// messageReadHandlers and messageWriteHandlers map the tools to their implementation.
func (c *Connector) messageReadHandlers() map[string]handler {
	return map[string]handler{ToolListScheduledMessages: c.listScheduled, ToolListPins: c.listPins}
}

func (c *Connector) messageWriteHandlers() map[string]handler {
	return map[string]handler{
		ToolUpdateMessage:          c.updateMessage,
		ToolDeleteMessage:          c.deleteMessage,
		ToolScheduleMessage:        c.scheduleMessage,
		ToolDeleteScheduledMessage: c.deleteScheduled,
		ToolPinMessage:             c.pinMessage,
		ToolUnpinMessage:           c.unpinMessage,
	}
}

// --- identity and result ids ------------------------------------------------------------

// scheduleIdentity: the channel, thread_ts and post_at as unix seconds
// (never the text).
func scheduleIdentity(args map[string]any) map[string]string {
	out := identity("thread_ts")(args)
	if args != nil {
		if at, err := postAtArg(args); err == nil {
			out["post_at"] = strconv.FormatInt(at, 10)
		}
	}
	return out
}

func messageChangeIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(MessageChange)
	if !ok || v.TS == "" {
		return nil
	}
	return map[string]string{"channel": v.Channel, "ts": v.TS}
}

func scheduledIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(ScheduledMessage)
	if !ok || v.ID == "" {
		return nil
	}
	return map[string]string{"channel": v.Channel, "scheduled_message_id": v.ID}
}

func pinChangeIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(PinChange)
	if !ok || v.Timestamp == "" {
		return nil
	}
	return map[string]string{"channel": v.Channel, "timestamp": v.Timestamp}
}

// --- arguments --------------------------------------------------------------------------

// postAtArg reads post_at: an RFC 3339 time or positive unix seconds (a
// number or a numeric string).
func postAtArg(args map[string]any) (int64, error) {
	bad := invalid("post_at is required: an RFC 3339 time such as 2030-01-02T15:04:05Z, or unix seconds")
	switch v := args["post_at"].(type) {
	case string:
		s := strings.TrimSpace(v)
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			if n <= 0 {
				return 0, bad
			}
			return n, nil
		}
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return 0, bad
		}
		return t.Unix(), nil
	case float64, int, int64, json.Number:
		n, err := toInt(v)
		if err != nil || n <= 0 {
			return 0, bad
		}
		return int64(n), nil
	}
	return 0, bad
}

func scheduledIDArg(args map[string]any) (string, error) {
	v, _ := args["scheduled_message_id"].(string)
	v = strings.TrimSpace(v)
	if !scheduledIDRE.MatchString(v) {
		return "", invalid("scheduled_message_id is required: a scheduled message id such as Q1298393284")
	}
	return v, nil
}

// --- handlers ---------------------------------------------------------------------------

func (c *Connector) updateMessage(ctx context.Context, api *goslack.Client, call connectors.Call) (connectors.Result, error) {
	ts, err := tsArg(call.Args, "ts")
	if err != nil {
		return connectors.Result{}, err
	}
	text, err := textArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	id, err := c.channelTarget(ctx, api, call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	channel, newTS, _, err := api.UpdateMessageContext(ctx, id, ts, goslack.MsgOptionText(text, false))
	if err := ClassifyWrite("update message", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: MessageChange{Channel: or(channel, id), TS: or(newTS, ts), Action: "updated"}}, nil
}

func (c *Connector) deleteMessage(ctx context.Context, api *goslack.Client, call connectors.Call) (connectors.Result, error) {
	ts, err := tsArg(call.Args, "ts")
	if err != nil {
		return connectors.Result{}, err
	}
	id, err := c.channelTarget(ctx, api, call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	channel, _, err := api.DeleteMessageContext(ctx, id, ts)
	if err := ClassifyWrite("delete message", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: MessageChange{Channel: or(channel, id), TS: ts, Action: "deleted"}}, nil
}

func (c *Connector) scheduleMessage(ctx context.Context, api *goslack.Client, call connectors.Call) (connectors.Result, error) {
	text, err := textArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	at, err := postAtArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	threadTS, err := optionalTS(call.Args, "thread_ts")
	if err != nil {
		return connectors.Result{}, err
	}
	id, err := c.channelTarget(ctx, api, call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	opts := []goslack.MsgOption{goslack.MsgOptionText(text, false)}
	if threadTS != "" {
		opts = append(opts, goslack.MsgOptionTS(threadTS))
	}
	channel, scheduledID, err := api.ScheduleMessageContext(ctx, id, strconv.FormatInt(at, 10), opts...)
	if err := ClassifyWrite("schedule message", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: ScheduledMessage{ID: scheduledID, Channel: or(channel, id), PostAt: unixTime(at), ThreadTS: threadTS, Action: "scheduled"}}, nil
}

func (c *Connector) deleteScheduled(ctx context.Context, api *goslack.Client, call connectors.Call) (connectors.Result, error) {
	sid, err := scheduledIDArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	id, err := c.channelTarget(ctx, api, call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	_, err = api.DeleteScheduledMessageContext(ctx, &goslack.DeleteScheduledMessageParameters{Channel: id, ScheduledMessageID: sid})
	if err := ClassifyWrite("delete scheduled message", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: ScheduledMessage{ID: sid, Channel: id, Action: "deleted"}}, nil
}

func (c *Connector) listScheduled(ctx context.Context, api *goslack.Client, call connectors.Call) (connectors.Result, error) {
	limit, clamped, err := c.limitArg(call.Args, "limit", connectors.DefaultMaxPageSize)
	if err != nil {
		return connectors.Result{}, err
	}
	cursor, err := cursorArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	channel := ""
	if raw, _ := call.Args["channel"].(string); strings.TrimSpace(raw) != "" {
		if channel, err = c.channelTarget(ctx, api, call.Args); err != nil {
			return connectors.Result{}, err
		}
	}
	msgs, next, err := api.GetScheduledMessagesContext(ctx, &goslack.GetScheduledMessagesParameters{Channel: channel, Limit: limit, Cursor: cursor})
	if err := classify("list scheduled messages", err); err != nil {
		return connectors.Result{}, err
	}
	out := ScheduledPage{Messages: make([]ScheduledMessage, 0, len(msgs)), NextCursor: next, HasMore: next != "", Limit: limit}
	for _, m := range msgs {
		out.Messages = append(out.Messages, ScheduledMessage{ID: m.ID, Channel: m.Channel, PostAt: unixTime(int64(m.PostAt)), Created: unixTime(int64(m.DateCreated)), Text: m.Text})
	}
	out.Messages, out.Truncated = fit(out.Messages, c.bounds.MaxResultBytes, func(items []ScheduledMessage) any { out.Messages = items; return out })
	return connectors.Result{Content: out, Partial: clamped || out.Truncated, Empty: len(out.Messages) == 0}, nil
}

// pinLike runs pins.add / pins.remove; alreadyCodes say the desired
// state already holds.
func (c *Connector) pinLike(ctx context.Context, api *goslack.Client, call connectors.Call, action string, run func(context.Context, string, goslack.ItemRef) error, alreadyCodes ...string) (connectors.Result, error) {
	ts, err := tsArg(call.Args, "timestamp")
	if err != nil {
		return connectors.Result{}, err
	}
	id, err := c.channelTarget(ctx, api, call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	err = run(ctx, id, goslack.ItemRef{Channel: id, Timestamp: ts})
	already := false
	if code := slackCode(err); code != "" {
		for _, a := range alreadyCodes {
			if code == a {
				err, already = nil, true
			}
		}
	}
	if err := ClassifyWrite(action+" message", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: PinChange{Channel: id, Timestamp: ts, Action: action + "ned", Already: already}}, nil
}

func (c *Connector) pinMessage(ctx context.Context, api *goslack.Client, call connectors.Call) (connectors.Result, error) {
	return c.pinLike(ctx, api, call, "pin", api.AddPinContext, "already_pinned")
}

func (c *Connector) unpinMessage(ctx context.Context, api *goslack.Client, call connectors.Call) (connectors.Result, error) {
	return c.pinLike(ctx, api, call, "unpin", api.RemovePinContext, "not_pinned", "no_pin")
}

// listPinItems calls pins.list. slack-go reports its ok:false answers as
// a bare error carrying the code; it is turned back into a
// SlackErrorResponse so the code is classified like any other.
func listPinItems(ctx context.Context, api *goslack.Client, channel string) ([]goslack.Item, error) {
	items, _, err := api.ListPinsContext(ctx, channel)
	if err != nil && codeRE.MatchString(err.Error()) {
		var sce goslack.StatusCodeError
		var rl *goslack.RateLimitedError
		if !errors.As(err, &sce) && !errors.As(err, &rl) {
			err = goslack.SlackErrorResponse{Err: err.Error()}
		}
	}
	return items, err
}

func (c *Connector) listPins(ctx context.Context, api *goslack.Client, call connectors.Call) (connectors.Result, error) {
	id, err := c.channelTarget(ctx, api, call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	items, err := listPinItems(ctx, api, id)
	if err := classify("list pins", err); err != nil {
		return connectors.Result{}, err
	}
	out := PinsPage{Channel: id, Pins: make([]Pin, 0, len(items))}
	for _, it := range items {
		p := Pin{Type: it.Type}
		if it.Message != nil {
			p.TS, p.User, p.Text, p.Time = it.Message.Timestamp, it.Message.User, it.Message.Text, tsTime(it.Message.Timestamp)
		}
		if it.File != nil {
			p.FileID, p.FileName, p.Title = it.File.ID, it.File.Name, it.File.Title
		}
		out.Pins = append(out.Pins, p)
	}
	out.Pins, out.Truncated = fit(out.Pins, c.bounds.MaxResultBytes, func(items []Pin) any { out.Pins = items; return out })
	return connectors.Result{Content: out, Partial: out.Truncated, Empty: len(out.Pins) == 0}, nil
}

// or returns a when set, else b.
func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// --- reconciliation -----------------------------------------------------------------------

// checkDeleted: conversations.replies on the message's ts (which also
// finds thread replies, unlike history). The message present (and not a
// tombstone) is not_found; message_not_found / thread_not_found, a
// tombstone or a listing without it is found (deleted).
func (c *Connector) checkDeleted(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	ts := in.ResourceIdentity["ts"]
	if !tsRE.MatchString(ts) {
		return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no message ts", ErrNotReconcilable)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	api, id, err := c.checkTarget(ctx, in, false)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	msgs, _, _, err := api.GetConversationRepliesContext(ctx, &goslack.GetConversationRepliesParameters{ChannelID: id, Timestamp: ts, Limit: 1, Inclusive: true})
	if err != nil {
		switch slackCode(err) {
		case "message_not_found", "thread_not_found":
			return found(ts), nil
		}
		return connectors.ReconcileResult{}, classify("reconcile: read message", err)
	}
	for _, m := range msgs {
		if m.Timestamp == ts && m.SubType != "tombstone" {
			return notFound, nil
		}
	}
	return found(ts), nil
}

// checkPinned: pins.list on the channel lists the message (want true for
// pin_message) or does not (false for unpin_message).
func (c *Connector) checkPinned(want bool) func(context.Context, connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	return func(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
		ts := in.ResourceIdentity["timestamp"]
		if !tsRE.MatchString(ts) {
			return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no message timestamp", ErrNotReconcilable)
		}
		ctx, cancel := context.WithTimeout(ctx, c.timeout)
		defer cancel()
		api, id, err := c.checkTarget(ctx, in, false)
		if err != nil {
			return connectors.ReconcileResult{}, err
		}
		items, err := listPinItems(ctx, api, id)
		if err := classify("reconcile: list pins", err); err != nil {
			return connectors.ReconcileResult{}, err
		}
		pinned := false
		for _, it := range items {
			if it.Message != nil && it.Message.Timestamp == ts {
				pinned = true
			}
		}
		return verdict(pinned == want, ts), nil
	}
}
