package microsoft_test

import (
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/microsoft"
)

const chatID = "19:chat-1@thread.v2"

func TestTeamsChatToolsMetadata(t *testing.T) {
	r, w := connectors.KindRead, connectors.KindWrite
	chan1 := "19:chan-general@thread.tacv2"
	checkMeta(t, []toolMeta{
		{tool: "teams_list_chats", kind: r, scopes: []string{"Chat.ReadBasic"}, identity: map[string]string{}},
		{tool: "teams_read_chat_messages", kind: r, scopes: []string{"Chat.Read"}, required: []string{"chat_id"},
			args: map[string]any{"chat_id": chatID}, identity: map[string]string{"chat": chatID}},
		{tool: "teams_read_channel_replies", kind: r, scopes: []string{"ChannelMessage.Read.All"}, required: []string{"team_id", "channel_id", "message_id"},
			args: map[string]any{"team_id": "t-1", "channel_id": chan1, "message_id": "m-1"}, identity: map[string]string{"team": "t-1", "channel": chan1, "message": "m-1"}},
		{tool: "teams_send_chat_message", kind: w, reconcile: connectors.ReconcileNone, scopes: []string{"ChatMessage.Send"}, required: []string{"chat_id", "content"},
			args: map[string]any{"chat_id": chatID, "content": "secret"}, identity: map[string]string{"chat": chatID}},
		{tool: "teams_reply_channel_message", kind: w, reconcile: connectors.ReconcileNone, scopes: []string{"ChannelMessage.Send"}, required: []string{"team_id", "channel_id", "message_id", "content"},
			args: map[string]any{"team_id": "t-1", "channel_id": chan1, "message_id": "m-1", "content": "secret"}, identity: map[string]string{"team": "t-1", "channel": chan1, "message": "m-1"}},
	})
}

func TestTeamsListChatsAndMessages(t *testing.T) {
	srv, res := mustRun(t, map[string]route{"GET /v1.0/me/chats": {status: 200, body: `{"value":[{"id":"` + chatID + `","topic":"Launch","chatType":"group","lastUpdatedDateTime":"2026-10-10T10:00:00Z","webUrl":"https://teams.example.test/c"}]}`}},
		"teams_list_chats", map[string]any{"top": 80}, false)
	var chats struct {
		Items []struct {
			ID       string `json:"id"`
			Topic    string `json:"topic"`
			ChatType string `json:"chat_type"`
		} `json:"items"`
	}
	decode(t, res, &chats)
	if len(chats.Items) != 1 || chats.Items[0].ChatType != "group" || !res.Partial {
		t.Errorf("chats = %+v partial %v (top 80 is clamped to Graph's 50)", chats, res.Partial)
	}
	if q := query(t, srv, "/v1.0/me/chats"); q.Get("$top") != "50" {
		t.Errorf("$top = %q", q.Get("$top"))
	}
	_, res = mustRun(t, map[string]route{"GET /v1.0/chats/" + chatID + "/messages": {status: 200, body: "channel_messages.json"}},
		"teams_read_chat_messages", map[string]any{"chat_id": chatID}, false)
	var msgs struct {
		Items []struct{ ID, Content string } `json:"items"`
	}
	decode(t, res, &msgs)
	if len(msgs.Items) == 0 || msgs.Items[0].ID == "" {
		t.Errorf("messages = %+v", msgs)
	}
	_, res = mustRun(t, map[string]route{"GET /v1.0/teams/t-1/channels/c-1/messages/m-1/replies": {status: 200, body: "channel_messages_empty.json"}},
		"teams_read_channel_replies", map[string]any{"team_id": "t-1", "channel_id": "c-1", "message_id": "m-1"}, false)
	if !res.Empty {
		t.Error("no replies not marked Empty")
	}
}

func TestTeamsChatToolsRefusePersonalAccounts(t *testing.T) {
	srv := newAPIServer(t, nil)
	c, _ := newConnectorWithScopes(t, srv, connectors.Bounds{}, []string{"User.Read", "Mail.Read"})
	_, err := c.Call(t.Context(), call("teams_list_chats", nil))
	wantClass(t, err, microsoft.ClassScopeRequired, 0)
	if !strings.Contains(err.Error(), "personal") {
		t.Errorf("message %q should explain personal accounts", err)
	}
}

func TestTeamsSendChatAndReply(t *testing.T) {
	chatPath := "POST /v1.0/chats/" + chatID + "/messages"
	srv, res := mustRun(t, map[string]route{chatPath: {status: 201, body: "posted_message.json"}},
		"teams_send_chat_message", map[string]any{"chat_id": chatID, "content": "<b>hi</b>", "content_type": "html"}, true)
	b := jsonBody(t, srv.Last(t, chatPath))
	if body, _ := b["body"].(map[string]any); body["contentType"] != "html" || body["content"] != "<b>hi</b>" {
		t.Errorf("body = %v", b)
	}
	if ids := toolNamed(t, mustConnector(t), "teams_send_chat_message").ResultIDs(res); ids["id"] == "" {
		t.Errorf("ResultIDs = %v", ids)
	}
	replyPath := "POST /v1.0/teams/t-1/channels/c-1/messages/m-1/replies"
	srv, _ = mustRun(t, map[string]route{replyPath: {status: 201, body: "posted_message.json"}},
		"teams_reply_channel_message", map[string]any{"team_id": "t-1", "channel_id": "c-1", "message_id": "m-1", "content": "ack"}, true)
	if body, _ := jsonBody(t, srv.Last(t, replyPath))["body"].(map[string]any); body["contentType"] != "text" {
		t.Errorf("reply body = %v", body)
	}
	wantInvalid(t, "teams_send_chat_message", map[string]any{"chat_id": chatID, "content": " "}, true)
	wantInvalid(t, "teams_send_chat_message", map[string]any{"chat_id": "../x", "content": "x"}, true)
	runWriteErrorCases(t, chatPath, route{status: 201, body: "posted_message.json"}, "teams_send_chat_message", map[string]any{"chat_id": chatID, "content": "x"})
}
