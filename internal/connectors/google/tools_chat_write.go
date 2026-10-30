package google

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"google.golang.org/api/chat/v1"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// The Chat writes (increment 4): a text message posted as the connected
// user, to a space or into a thread. Each names its message with a
// client-assigned id derived from the operation (ChatMessageID), so the
// reconciliation is a stable-id lookup: spaces.messages.get on
// spaces/<space>/messages/<ChatMessageID(op)>.

// Chat write tool names.
const (
	ToolChatSendMessage   = "send_message"
	ToolChatReplyInThread = "reply_in_thread"
)

// Chat's limits: a message is at most 32,000 bytes; a thread key at most
// 4,000 characters.
const (
	MaxChatMessageBytes = 32000
	maxChatThreadKey    = 4000
)

// chatReplyOption makes a reply start a new thread when the thread is
// gone or the space is not threaded, rather than fail.
const chatReplyOption = "REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD"

// ChatMessageID is the client-assigned message id of the operation:
// "client-mcpgw-" + EventID(op) (lowercase letters and digits of
// base32hex: Chat's custom ids must start with "client-" and hold at most
// 63 lowercase letters, digits and hyphens; this one has 45). It is unique
// within a space, so a retry of the same operation answers 409 conflict
// rather than posting twice.
func ChatMessageID(op string) string { return "client-mcpgw-" + EventID(op) }

// SentChatMessage is the result of send_message and reply_in_thread: the
// message's resource name, its space and thread, and the client id it
// was created under.
type SentChatMessage struct {
	Name            string `json:"name"`
	Space           string `json:"space"`
	Thread          string `json:"thread,omitempty"`
	Created         string `json:"created,omitempty"`
	ClientMessageID string `json:"client_message_id"`
}

func sentChatResultIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(SentChatMessage)
	if !ok || v.Name == "" {
		return nil
	}
	out := map[string]string{"name": v.Name}
	if v.Thread != "" {
		out["thread"] = v.Thread
	}
	return out
}

var chatTextProperty = property{"text", "string", "The message, plain text with Chat's formatting (*bold*, _italic_, <users/123> mentions); at most 32,000 bytes.", nil}

func (c *Connector) chatWriteTools() []connectors.Tool {
	tool := func(name, description string, props []property, required []string, identity func(map[string]any) map[string]string) connectors.Tool {
		return connectors.Tool{
			App: AppChat, Name: name, Kind: connectors.KindWrite,
			Description:      description + chatWorkspaceNote,
			InputSchema:      objectSchema(props, required),
			RequiredScopes:   []string{ScopeChatMessagesCreate},
			ResourceIdentity: identity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkChatMessage},
			ResultIDs:        sentChatResultIDs,
			Bounds:           c.singleBounds(),
		}
	}
	return []connectors.Tool{
		tool(ToolChatSendMessage,
			"Post a text message as the account to a Google Chat space (in a threaded space it starts a new thread). "+
				"Returns the message's name and thread.",
			[]property{chatSpaceProperty, chatTextProperty}, []string{"space", "text"}, chatSpaceIdentity),
		tool(ToolChatReplyInThread,
			"Reply as the account in a thread of a Google Chat space: thread (a message's thread name) or thread_key "+
				"(a key of your choice: messages with the same key share a thread). A thread that does not exist starts "+
				"a new one. Returns the message's name and thread.",
			[]property{
				chatSpaceProperty,
				{"thread", "string", "The thread's resource name spaces/<id>/threads/<thread> (from chat.list_messages).", nil},
				{"thread_key", "string", "Instead of thread: a thread key (at most 4,000 characters).", nil},
				chatTextProperty,
			}, []string{"space", "text"}, chatThreadIdentity),
	}
}

func (c *Connector) chatWriteHandlers() map[string]handler {
	return map[string]handler{ToolChatSendMessage: c.chatSendMessage, ToolChatReplyInThread: c.chatReplyInThread}
}

// chatTextArg reads the required text as given (not trimmed: leading
// indentation is formatting), within Chat's size limit.
func chatTextArg(args map[string]any) (string, error) {
	if _, err := requiredString(args, "text"); err != nil {
		return "", err
	}
	text, _ := args["text"].(string)
	if len(text) > MaxChatMessageBytes {
		return "", invalid("text is %d bytes; a Chat message holds at most %d", len(text), MaxChatMessageBytes)
	}
	return text, nil
}

func (c *Connector) chatSendMessage(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	space, err := chatSpaceArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	text, err := chatTextArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	return c.createChatMessage(ctx, cl, call, space, &chat.Message{Text: text}, "")
}

func (c *Connector) chatReplyInThread(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	space, err := chatSpaceArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	thread, err := chatThreadArg(call.Args, space)
	if err != nil {
		return connectors.Result{}, err
	}
	key, err := optionalString(call.Args, "thread_key")
	if err != nil {
		return connectors.Result{}, err
	}
	key = strings.TrimSpace(key)
	switch {
	case thread == "" && key == "":
		return connectors.Result{}, invalid("thread or thread_key is required")
	case thread != "" && key != "":
		return connectors.Result{}, invalid("give thread or thread_key, not both")
	case utf8.RuneCountInString(key) > maxChatThreadKey:
		return connectors.Result{}, invalid("thread_key holds at most %d characters", maxChatThreadKey)
	}
	text, err := chatTextArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	return c.createChatMessage(ctx, cl, call, space, &chat.Message{Text: text, Thread: &chat.Thread{Name: thread, ThreadKey: key}}, chatReplyOption)
}

// createChatMessage posts msg in space under the operation's client
// message id (and the reply option, when given).
func (c *Connector) createChatMessage(ctx context.Context, cl *client, call connectors.Call, space string, msg *chat.Message, replyOption string) (connectors.Result, error) {
	id := ChatMessageID(call.OperationID)
	svc, err := cl.chat(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	req := svc.Spaces.Messages.Create(space, msg).Context(ctx).MessageId(id)
	if replyOption != "" {
		req = req.MessageReplyOption(replyOption)
	}
	created, err := req.Do()
	if err := classifyChatWrite("send Chat message", err); err != nil {
		return connectors.Result{}, err
	}
	name := created.Name
	if name == "" {
		name = space + "/messages/" + id
	}
	return connectors.Result{Content: SentChatMessage{
		Name: name, Space: space, Thread: chatThreadName(created.Thread), Created: normalizeTimestamp(created.CreateTime), ClientMessageID: id,
	}}, nil
}

// classifyChatWrite is classifyWrite, with the Chat API's "Google Chat
// app not found" reported as forbidden (a known outcome: nothing was
// posted).
func classifyChatWrite(action string, err error) error {
	if chatAppMissing(err) {
		return classifyChat(action, err)
	}
	return classifyWrite(action, err)
}

// --- reconciliation -------------------------------------------------------------------

// checkChatMessage is the Chat writes' stable-id reconciliation: the
// message is looked up by its client-assigned id in the space the
// resource identity names. Present is found (with the system resource
// name); not_found (404) is not_found; anything else (including the
// Chat app not configured, 403 and 5xx) is "cannot tell yet". The lookup
// needs chat.messages.readonly or chat.messages: an account that granted
// only chat.messages.create gets 403, and the operation ends unresolved.
func (c *Connector) checkChatMessage(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	tg, err := c.target(in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	space, ok := chatSpaceName(in.ResourceIdentity["space"])
	if !ok {
		return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no Chat space", ErrNotReconcilable)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	svc, err := tg.client.chat(ctx)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	name := space + "/messages/" + ChatMessageID(tg.operationID)
	msg, err := svc.Spaces.Messages.Get(name).Context(ctx).Do()
	if err := classifyChat("reconcile: get Chat message", err); err != nil {
		var e *Error
		if errors.As(err, &e) && e.Class == ClassNotFound {
			return notFound, nil
		}
		return connectors.ReconcileResult{}, err
	}
	if msg.Name != "" {
		name = msg.Name
	}
	return found(name), nil
}
