// Tool descriptions and argument shapes are adapted from
// korotovsky/slack-mcp-server, pkg/server/server.go
// (conversations_add_message, reactions_add) and
// pkg/handler/conversations.go (ConversationsAddMessageHandler,
// ReactionsAddHandler) at commit b88c0de3f706f4f07337c9eda7133c736d1c9524,
// MIT License, Copyright (c) 2025 Dmitrii Korotovskii. Modified for
// mcp-gateway: one tool per write (post_message, reply_in_thread,
// add_reaction), plain text only (no markdown-to-blocks, no raw blocks,
// no unfurl or mark options), resource identity for policy and audit,
// the ledger's operation id attached as message metadata when marker
// reconciliation is enabled, result ids instead of a sentence, and the
// connector's error vocabulary (unknown outcomes are reported, never
// guessed). See THIRD_PARTY_NOTICES.md.

package slack

import (
	"context"
	"errors"
	"regexp"
	"strings"

	goslack "github.com/slack-go/slack"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Write tool names.
const (
	ToolPostMessage   = "post_message"
	ToolReplyInThread = "reply_in_thread"
	ToolAddReaction   = "add_reaction"
)

// Slack user-token scopes the write tools need.
const (
	ScopeChatWrite      = "chat:write"
	ScopeReactionsWrite = "reactions:write"
)

// MarkerEventType is the metadata event_type the marker-reconciled
// writes attach to a message; event_payload.operation_id carries the
// ledger operation id. Message metadata is invisible in Slack clients
// and comes back from conversations.history / conversations.replies
// with include_all_metadata.
const MarkerEventType = "mcp_gateway_operation"

// ErrMissingOperation is returned by every write called without
// Call.OperationID: the ledger stage sets it before dispatch, and the
// marker and stable-id reconciliation derive from it, so a write without
// one could never be verified after an unknown outcome. It means a
// pipeline wiring bug (a write dispatched without the ledger), never a
// harness mistake.
var ErrMissingOperation = errors.New("slack: write called without a ledger operation id")

// reactionRE is the shape of an emoji name (without colons; Slack
// accepts skin-tone suffixes such as thumbsup::skin-tone-2).
var reactionRE = regexp.MustCompile(`^[a-z0-9_+-]+(::skin-tone-[2-6])?$`)

// writeTools declares the three write tools. post_message and
// reply_in_thread reconcile by marker only when Options.MarkerReconcile
// is set; otherwise they declare none (decision dovthftx item 3: an
// unknown outcome goes straight to unresolved and the user checks
// Slack).
func (c *Connector) writeTools() []connectors.Tool {
	single := connectors.Bounds{MaxResultBytes: c.bounds.MaxResultBytes}
	messageReconcile := connectors.Reconciliation{Kind: connectors.ReconcileNone}
	if c.marker {
		messageReconcile = connectors.Reconciliation{Kind: connectors.ReconcileMarker, Check: c.checkMessage}
	}
	textProperty := property{"text", "string", "Message text (Slack mrkdwn: *bold*, _italic_, `code`, <@U123> mentions, <#C123> channel links).", nil}
	return []connectors.Tool{
		{
			App: App, Name: ToolPostMessage, Kind: connectors.KindWrite,
			Description: "Post a message to a Slack channel as the connected user; with thread_ts, post it as a reply in that thread. " +
				"Returns the new message's channel id and ts.",
			InputSchema: objectSchema([]property{
				channelProperty, textProperty,
				{"thread_ts", "string", "Optional: the parent message timestamp to reply under instead of posting to the channel.", nil},
			}, []string{"channel", "text"}),
			RequiredScopes:   []string{ScopeChatWrite},
			ResourceIdentity: identity("thread_ts"),
			Reconcile:        messageReconcile,
			ResultIDs:        postedResultIDs,
			Bounds:           single,
		},
		{
			App: App, Name: ToolReplyInThread, Kind: connectors.KindWrite,
			Description: "Reply in a Slack thread as the connected user: the channel and the parent message's thread_ts. " +
				"Returns the new reply's channel id, ts and thread_ts.",
			InputSchema: objectSchema([]property{
				channelProperty,
				{"thread_ts", "string", "The thread's parent message timestamp (e.g. 1700002000.000100).", nil},
				textProperty,
			}, []string{"channel", "thread_ts", "text"}),
			RequiredScopes:   []string{ScopeChatWrite},
			ResourceIdentity: identity("thread_ts"),
			Reconcile:        messageReconcile,
			ResultIDs:        postedResultIDs,
			Bounds:           single,
		},
		{
			App: App, Name: ToolAddReaction, Kind: connectors.KindWrite,
			Description: "Add an emoji reaction as the connected user to a message identified by its channel and timestamp. " +
				"Idempotent: a reaction that is already there is reported as already_reacted.",
			InputSchema: objectSchema([]property{
				channelProperty,
				{"timestamp", "string", "The message's ts (e.g. 1700003000.000200).", nil},
				{"name", "string", "Emoji name without colons, e.g. thumbsup, eyes, white_check_mark.", nil},
			}, []string{"channel", "timestamp", "name"}),
			RequiredScopes:   []string{ScopeReactionsWrite},
			ResourceIdentity: identity("timestamp", "name"),
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkReaction},
			ResultIDs:        reactionResultIDs,
			Bounds:           single,
		},
	}
}

// writeHandlers maps the write tools' short names to their implementation.
func (c *Connector) writeHandlers() map[string]handler {
	return map[string]handler{
		ToolPostMessage:   c.postMessage,
		ToolReplyInThread: c.replyInThread,
		ToolAddReaction:   c.addReaction,
	}
}

// --- result ids -------------------------------------------------------------------

func postedResultIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(PostedMessage)
	if !ok || v.TS == "" {
		return nil
	}
	out := map[string]string{"channel": v.Channel, "ts": v.TS}
	if v.ThreadTS != "" {
		out["thread_ts"] = v.ThreadTS
	}
	return out
}

func reactionResultIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(AddedReaction)
	if !ok || v.Timestamp == "" {
		return nil
	}
	return map[string]string{"channel": v.Channel, "timestamp": v.Timestamp, "name": v.Name}
}

// --- markers --------------------------------------------------------------------------

// Marker returns the message metadata carrying a ledger operation id.
func Marker(operationID string) goslack.SlackMetadata {
	return goslack.SlackMetadata{EventType: MarkerEventType, EventPayload: map[string]any{"operation_id": operationID}}
}

// hasMarker reports whether a message's metadata carries the operation.
func hasMarker(meta goslack.SlackMetadata, operationID string) bool {
	if operationID == "" || meta.EventType != MarkerEventType {
		return false
	}
	id, _ := meta.EventPayload["operation_id"].(string)
	return id == operationID
}

// --- handlers -------------------------------------------------------------------------

// post resolves the channel (a read; its failure is a known outcome),
// posts text (in the thread when threadTS is set, with the operation
// marker when marker reconciliation is on) and returns the new
// message's identifiers. Only the post itself can be an unknown outcome.
func (c *Connector) post(ctx context.Context, api *goslack.Client, call connectors.Call, action, threadTS string) (connectors.Result, error) {
	id, name, err := channelArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	text, err := textArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	id, _, err = c.resolveChannel(ctx, api, id, name)
	if err != nil {
		return connectors.Result{}, err
	}
	opts := []goslack.MsgOption{goslack.MsgOptionText(text, false)}
	if threadTS != "" {
		opts = append(opts, goslack.MsgOptionTS(threadTS))
	}
	if c.marker {
		opts = append(opts, goslack.MsgOptionMetadata(Marker(call.OperationID)))
	}
	channel, ts, err := api.PostMessageContext(ctx, id, opts...)
	if err := ClassifyWrite(action, err); err != nil {
		return connectors.Result{}, err
	}
	if channel == "" {
		channel = id
	}
	return connectors.Result{Content: PostedMessage{Channel: channel, TS: ts, ThreadTS: threadTS}}, nil
}

func (c *Connector) postMessage(ctx context.Context, api *goslack.Client, call connectors.Call) (connectors.Result, error) {
	threadTS, err := optionalTS(call.Args, "thread_ts")
	if err != nil {
		return connectors.Result{}, err
	}
	return c.post(ctx, api, call, "post message", threadTS)
}

func (c *Connector) replyInThread(ctx context.Context, api *goslack.Client, call connectors.Call) (connectors.Result, error) {
	threadTS, err := tsArg(call.Args, "thread_ts")
	if err != nil {
		return connectors.Result{}, err
	}
	return c.post(ctx, api, call, "reply in thread", threadTS)
}

func (c *Connector) addReaction(ctx context.Context, api *goslack.Client, call connectors.Call) (connectors.Result, error) {
	id, name, err := channelArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	ts, err := tsArg(call.Args, "timestamp")
	if err != nil {
		return connectors.Result{}, err
	}
	reaction, err := reactionArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	id, _, err = c.resolveChannel(ctx, api, id, name)
	if err != nil {
		return connectors.Result{}, err
	}
	err = api.AddReactionContext(ctx, reaction, goslack.ItemRef{Channel: id, Timestamp: ts})
	already := false
	var ser goslack.SlackErrorResponse
	if errors.As(err, &ser) && ser.Err == "already_reacted" {
		err, already = nil, true
	}
	if err := ClassifyWrite("add reaction", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: AddedReaction{Channel: id, Timestamp: ts, Name: reaction, AlreadyReacted: already}}, nil
}

// --- argument helpers -------------------------------------------------------------------

// textArg reads the non-blank message text.
func textArg(args map[string]any) (string, error) {
	v, ok := args["text"]
	if !ok || v == nil {
		return "", invalid("text is required")
	}
	s, ok := v.(string)
	if !ok {
		return "", invalid("text must be a string")
	}
	if strings.TrimSpace(s) == "" {
		return "", invalid("text is required")
	}
	return s, nil
}

// optionalTS reads an optional Slack timestamp argument.
func optionalTS(args map[string]any, key string) (string, error) {
	v, ok := args[key]
	if !ok || v == nil {
		return "", nil
	}
	s, ok := v.(string)
	if !ok || (strings.TrimSpace(s) != "" && !tsRE.MatchString(strings.TrimSpace(s))) {
		return "", invalid("%s must be a Slack message timestamp such as 1700002000.000100", key)
	}
	return strings.TrimSpace(s), nil
}

// reactionArg reads the emoji name, lower-cased, without colons.
func reactionArg(args map[string]any) (string, error) {
	v, _ := args["name"].(string)
	v = strings.ToLower(strings.Trim(strings.TrimSpace(v), ":"))
	if !reactionRE.MatchString(v) {
		return "", invalid("name is required: an emoji name without colons, such as thumbsup")
	}
	return v, nil
}
