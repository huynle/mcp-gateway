package google_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

// Increment 4: the Chat writes, reconciled by the client-assigned message
// id derived from the operation.

const (
	chatCreatePath = "POST /v1/spaces/AAAAexample1/messages"
	wantChatMsgID  = "client-mcpgw-" + wantEventID
	chatCheckPath  = "GET /v1/spaces/AAAAexample1/messages/" + wantChatMsgID
	chatSentName   = "spaces/AAAAexample1/messages/sys3.sys3"
)

var chatWriteTools = []string{"chat.send_message", "chat.reply_in_thread"}

func TestChatMessageID(t *testing.T) {
	id := google.ChatMessageID(opID)
	if id != wantChatMsgID || len(id) > 63 || !strings.HasPrefix(id, "client-") {
		t.Fatalf("ChatMessageID = %q, want %q (client-, at most 63 characters)", id, wantChatMsgID)
	}
	if strings.Trim(id, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" {
		t.Fatalf("ChatMessageID %q: Chat allows only lowercase letters, digits and hyphens", id)
	}
	if google.ChatMessageID("another-operation") == id {
		t.Error("two operations share a message id")
	}
}

func TestChatWriteDeclarations(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	for _, full := range chatWriteTools {
		tool := declared(t, c, full, connectors.KindWrite, []string{google.ScopeChatMessagesCreate}, connectors.ReconcileStableID)
		if !strings.Contains(tool.Description, "Google Workspace") {
			t.Errorf("%s description does not say it is Google Workspace only: %q", full, tool.Description)
		}
	}
	id := toolOf(t, c, "chat.send_message").ResourceIdentity(map[string]any{"space": "AAAAexample1", "text": "secret"})
	if len(id) != 1 || id["space"] != chatSpace {
		t.Errorf("send_message identity = %v, want only the space", id)
	}
	reply := toolOf(t, c, "chat.reply_in_thread")
	id = reply.ResourceIdentity(map[string]any{"space": chatSpace, "thread": chatThread, "text": "secret"})
	if len(id) != 2 || id["space"] != chatSpace || id["thread"] != chatThread {
		t.Errorf("reply identity = %v, want space and thread", id)
	}
	id = reply.ResourceIdentity(map[string]any{"space": chatSpace, "thread_key": "secret key", "text": "secret"})
	if len(id) != 1 || id["space"] != chatSpace {
		t.Errorf("reply identity with thread_key = %v, want only the space (never the key)", id)
	}
}

func TestChatSendMessage(t *testing.T) {
	srv := newAPIServer(t, map[string]route{chatCreatePath: {status: 200, body: "chat_sent_message.json"}})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("chat.send_message", map[string]any{"space": "AAAAexample1", "text": "hello"}))
	if err != nil {
		t.Fatalf("chat.send_message: %v", err)
	}
	if len(tk.calls) != 1 {
		t.Errorf("token calls = %v", tk.calls)
	}
	req := srv.Last(t, chatCreatePath)
	if got := req.URL.Query().Get("messageId"); got != wantChatMsgID {
		t.Errorf("messageId = %q, want %q", got, wantChatMsgID)
	}
	if req.URL.Query().Has("messageReplyOption") {
		t.Errorf("send_message sent messageReplyOption: %v", req.URL.Query())
	}
	body := bodyOf(t, req)
	if body["text"] != "hello" || body["thread"] != nil {
		t.Errorf("body = %s", req.Body)
	}
	sent, ok := res.Content.(google.SentChatMessage)
	if !ok || sent.Name != chatSentName || sent.Space != chatSpace || sent.Thread != "spaces/AAAAexample1/threads/thr9" ||
		sent.ClientMessageID != wantChatMsgID || sent.Created != "2026-10-30T10:00:00Z" {
		t.Errorf("content = %#v", res.Content)
	}
	ids := toolOf(t, c, "chat.send_message").ResultIDs(res)
	if ids["name"] != chatSentName || ids["thread"] != "spaces/AAAAexample1/threads/thr9" {
		t.Errorf("ResultIDs = %v", ids)
	}
}

func TestChatReplyInThread(t *testing.T) {
	srv := newAPIServer(t, map[string]route{chatCreatePath: {status: 200, body: "chat_sent_message.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	if _, err := run(t, c, write("chat.reply_in_thread", map[string]any{"space": chatSpace, "thread": chatThread, "text": "on it"})); err != nil {
		t.Fatalf("reply_in_thread: %v", err)
	}
	req := srv.Last(t, chatCreatePath)
	q := req.URL.Query()
	if q.Get("messageId") != wantChatMsgID || q.Get("messageReplyOption") != "REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD" {
		t.Errorf("query = %v", q)
	}
	body := bodyOf(t, req)
	thread, _ := body["thread"].(map[string]any)
	if body["text"] != "on it" || thread["name"] != chatThread || thread["threadKey"] != nil {
		t.Errorf("body = %s", req.Body)
	}

	if _, err := run(t, c, write("chat.reply_in_thread", map[string]any{"space": chatSpace, "thread_key": "deploy-42", "text": "on it"})); err != nil {
		t.Fatalf("reply_in_thread by key: %v", err)
	}
	req = srv.Last(t, chatCreatePath)
	body = bodyOf(t, req)
	thread, _ = body["thread"].(map[string]any)
	if thread["threadKey"] != "deploy-42" || thread["name"] != nil || req.URL.Query().Get("messageReplyOption") != "REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD" {
		t.Errorf("by key: body = %s query = %v", req.Body, req.URL.Query())
	}
}

func TestChatWriteArguments(t *testing.T) {
	c, tk := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	for name, tc := range map[string]struct {
		tool string
		args map[string]any
	}{
		"send missing space":       {"chat.send_message", map[string]any{"text": "x"}},
		"send bad space":           {"chat.send_message", map[string]any{"space": "spaces/a/b", "text": "x"}},
		"send missing text":        {"chat.send_message", map[string]any{"space": chatSpace}},
		"send blank text":          {"chat.send_message", map[string]any{"space": chatSpace, "text": "  "}},
		"send text too long":       {"chat.send_message", map[string]any{"space": chatSpace, "text": strings.Repeat("x", 32001)}},
		"reply no thread":          {"chat.reply_in_thread", map[string]any{"space": chatSpace, "text": "x"}},
		"reply thread and key":     {"chat.reply_in_thread", map[string]any{"space": chatSpace, "thread": chatThread, "thread_key": "k", "text": "x"}},
		"reply other space thread": {"chat.reply_in_thread", map[string]any{"space": chatSpace, "thread": "spaces/OTHER/threads/t", "text": "x"}},
		"reply bad thread":         {"chat.reply_in_thread", map[string]any{"space": chatSpace, "thread": "thr1", "text": "x"}},
		"reply key too long":       {"chat.reply_in_thread", map[string]any{"space": chatSpace, "thread_key": strings.Repeat("k", 4001), "text": "x"}},
		"reply missing text":       {"chat.reply_in_thread", map[string]any{"space": chatSpace, "thread": chatThread}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := run(t, c, write(tc.tool, tc.args))
			wantClass(t, err, google.ClassInvalidArgument, 0)
		})
	}
	if len(tk.calls) != 0 {
		t.Errorf("token calls for invalid arguments = %d", len(tk.calls))
	}
	for _, full := range chatWriteTools {
		if _, err := run(t, c, call(full, map[string]any{"space": chatSpace, "thread": chatThread, "text": "x"})); !errors.Is(err, google.ErrMissingOperation) {
			t.Errorf("%s without an operation id: err = %v, want ErrMissingOperation", full, err)
		}
	}
}

func TestChatWriteErrors(t *testing.T) {
	args := map[string]any{"space": chatSpace, "thread": chatThread, "text": "x"}
	for _, full := range chatWriteTools {
		for _, tc := range writeErrorCases("chat_sent_message.json") {
			t.Run(full+" "+tc.name, func(t *testing.T) {
				srv := newAPIServer(t, map[string]route{chatCreatePath: tc.rt})
				res, err := run(t, shortTimeout(t, srv), write(full, args))
				checkWriteError(t, tc, res, err)
			})
		}
		t.Run(full+" chat app not configured", func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{chatCreatePath: {status: 404, body: "error_chat_app_not_found.json"}})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			_, err := run(t, c, write(full, args))
			wantClass(t, err, google.ClassForbidden, 404)
			if errors.Is(err, connectors.ErrOutcomeUnknown) {
				t.Error("a configuration refusal is a known outcome")
			}
		})
	}
}

func TestCheckChatMessage(t *testing.T) {
	for _, full := range chatWriteTools {
		for name, tc := range map[string]struct {
			rt   route
			want string
		}{
			"found":                  {route{status: 200, body: "chat_sent_message.json"}, "found"},
			"not found":              {route{status: 404, body: "error_not_found.json"}, "not_found"},
			"chat app not found":     {route{status: 404, body: "error_chat_app_not_found.json"}, "cannot"},
			"403 forbidden":          {route{status: 403, body: "error_forbidden.json"}, "cannot"},
			"403 insufficient scope": {route{status: 403, body: "error_insufficient_scope.json"}, "cannot"},
			"500":                    {route{status: 500, body: "error_server.json"}, "cannot"},
		} {
			t.Run(full+" "+name, func(t *testing.T) {
				srv := newAPIServer(t, map[string]route{chatCheckPath: tc.rt})
				c, tk := newConnector(t, srv, connectors.Bounds{})
				tool, in := reconcileInput(t, c, full, map[string]any{"space": chatSpace, "thread": chatThread, "text": "secret"})
				out, err := tool.Reconcile.Check(context.Background(), in)
				wantOutcome(t, out, err, tc.want, chatSentName)
				if len(tk.calls) != 1 || tk.calls[0] != alice+"/"+acct {
					t.Errorf("token calls = %v", tk.calls)
				}
			})
		}
	}
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	tool, in := reconcileInput(t, c, "chat.send_message", map[string]any{"text": "no space"})
	if _, err := tool.Reconcile.Check(context.Background(), in); !errors.Is(err, google.ErrNotReconcilable) {
		t.Errorf("no space in the identity: err = %v, want ErrNotReconcilable", err)
	}
	in.OperationID, in.Call.OperationID = "", ""
	if _, err := tool.Reconcile.Check(context.Background(), in); !errors.Is(err, google.ErrNotReconcilable) {
		t.Errorf("no operation id: err = %v, want ErrNotReconcilable", err)
	}
}
