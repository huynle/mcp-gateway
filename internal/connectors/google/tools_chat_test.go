package google_test

import (
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

// Increment 4: the Google Chat app (Workspace accounts only).

const (
	chatSpacesPath   = "GET /v1/spaces"
	chatSpacePath    = "GET /v1/spaces/AAAAexample1"
	chatMessagesPath = "GET /v1/spaces/AAAAexample1/messages"
	chatMessagePath  = "GET /v1/spaces/AAAAexample1/messages/msg1.msg1"
	chatMembersPath  = "GET /v1/spaces/AAAAexample1/members"
	chatSpace        = "spaces/AAAAexample1"
	chatThread       = "spaces/AAAAexample1/threads/thr1"
)

func TestChatReadDeclarations(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	r := connectors.KindRead
	for full, scope := range map[string]string{
		"chat.list_spaces":   google.ScopeChatSpacesReadonly,
		"chat.get_space":     google.ScopeChatSpacesReadonly,
		"chat.list_messages": google.ScopeChatMessagesReadonly,
		"chat.get_message":   google.ScopeChatMessagesReadonly,
		"chat.list_members":  google.ScopeChatMembershipsReadonly,
	} {
		tool := declared(t, c, full, r, []string{scope}, "")
		if !google.WorkspaceOnlyScope(scope) {
			t.Errorf("%s: scope %s is not Workspace-only", full, scope)
		}
		if !strings.Contains(tool.Description, "Google Workspace") {
			t.Errorf("%s description does not say it is Google Workspace only: %q", full, tool.Description)
		}
	}
	secret := map[string]any{"filter": "secret", "text": "secret", "since": "2026-10-01T00:00:00Z"}
	with := func(extra map[string]any) map[string]any {
		out := map[string]any{}
		for k, v := range secret {
			out[k] = v
		}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}
	for _, tc := range []struct {
		tool string
		args map[string]any
		want map[string]string
	}{
		{"chat.list_spaces", with(nil), map[string]string{}},
		{"chat.get_space", with(map[string]any{"space": "AAAAexample1"}), map[string]string{"space": chatSpace}},
		{"chat.list_members", with(map[string]any{"space": chatSpace}), map[string]string{"space": chatSpace}},
		{"chat.list_messages", with(map[string]any{"space": chatSpace}), map[string]string{"space": chatSpace}},
		{"chat.list_messages", with(map[string]any{"space": chatSpace, "thread": chatThread}), map[string]string{"space": chatSpace, "thread": chatThread}},
		{"chat.get_message", with(map[string]any{"message": "spaces/AAAAexample1/messages/msg1.msg1"}), map[string]string{"space": chatSpace, "message": "spaces/AAAAexample1/messages/msg1.msg1"}},
	} {
		got := toolOf(t, c, tc.tool).ResourceIdentity(tc.args)
		if len(got) != len(tc.want) {
			t.Errorf("%s identity = %v, want %v", tc.tool, got, tc.want)
			continue
		}
		for k, v := range tc.want {
			if got[k] != v {
				t.Errorf("%s identity = %v, want %v", tc.tool, got, tc.want)
			}
		}
	}
}

func TestChatListSpaces(t *testing.T) {
	srv := newAPIServer(t, map[string]route{chatSpacesPath: {status: 200, body: "chat_spaces_list.json"}})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("chat.list_spaces", map[string]any{"max_results": 5, "page_token": "spaces-page-1", "filter": `spaceType = "SPACE"`}))
	if err != nil {
		t.Fatalf("chat.list_spaces: %v", err)
	}
	if res.Empty || res.Partial || res.Unavailable || len(tk.calls) != 1 {
		t.Errorf("markers = %+v, token calls = %v", res, tk.calls)
	}
	q := query(t, srv, "/v1/spaces")
	if q.Get("pageSize") != "5" || q.Get("pageToken") != "spaces-page-1" || q.Get("filter") != `spaceType = "SPACE"` {
		t.Errorf("query = %v", q)
	}
	var page google.ChatSpacesPage
	decode(t, res, &page)
	if page.MaxResults != 5 || page.NextPageToken != "spaces-page-2" || !page.HasMore || len(page.Items) != 2 {
		t.Fatalf("page = %+v", page)
	}
	room, dm := page.Items[0], page.Items[1]
	if room.Name != chatSpace || room.DisplayName != "Eng Team" || room.SpaceType != "SPACE" || !room.Threaded || room.SingleUserBotDM ||
		room.URL != "https://chat.google.com/room/AAAAexample1?cls=11" {
		t.Errorf("room = %+v", room)
	}
	if dm.Name != "spaces/BBBBexample2" || dm.SpaceType != "DIRECT_MESSAGE" || dm.Threaded || !dm.SingleUserBotDM {
		t.Errorf("dm = %+v", dm)
	}

	// Defaults: page 50, no filter, no token.
	if _, err := run(t, c, call("chat.list_spaces", nil)); err != nil {
		t.Fatal(err)
	}
	q = query(t, srv, "/v1/spaces")
	if q.Get("pageSize") != "50" || q.Has("filter") || q.Has("pageToken") {
		t.Errorf("default query = %v", q)
	}
}

func TestChatGetSpace(t *testing.T) {
	srv := newAPIServer(t, map[string]route{chatSpacePath: {status: 200, body: "chat_space.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	// A bare id is accepted as spaces/<id>.
	res, err := run(t, c, call("chat.get_space", map[string]any{"space": "AAAAexample1"}))
	if err != nil {
		t.Fatalf("chat.get_space: %v", err)
	}
	var sp google.ChatSpaceDetail
	decode(t, res, &sp)
	if sp.Name != chatSpace || sp.DisplayName != "Eng Team" || sp.SpaceType != "SPACE" || !sp.Threaded || sp.Description != "Where the engineers talk." ||
		sp.Created != "2026-01-05T17:00:00Z" || sp.LastActive != "2026-10-28T09:15:00Z" || !sp.ExternalUserAllowed || sp.MemberCount != 12 || sp.GroupCount != 1 || sp.Truncated {
		t.Errorf("space = %+v", sp)
	}
	if res.Empty || res.Partial {
		t.Errorf("markers = %+v", res)
	}
}

func TestChatListMessages(t *testing.T) {
	srv := newAPIServer(t, map[string]route{chatMessagesPath: {status: 200, body: "chat_messages_list.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("chat.list_messages", map[string]any{
		"space": chatSpace, "max_results": 10, "page_token": "messages-page-1", "thread": chatThread,
		"since": "2026-10-28T00:00:00Z", "until": "2026-10-29T00:00:00-07:00",
	}))
	if err != nil {
		t.Fatalf("chat.list_messages: %v", err)
	}
	q := query(t, srv, "/v1/spaces/AAAAexample1/messages")
	wantFilter := `createTime > "2026-10-28T00:00:00Z" AND createTime < "2026-10-29T00:00:00-07:00" AND thread.name = ` + chatThread
	if q.Get("filter") != wantFilter || q.Get("orderBy") != "createTime desc" || q.Get("pageSize") != "10" || q.Get("pageToken") != "messages-page-1" {
		t.Errorf("query = %v, want filter %q", q, wantFilter)
	}
	var page google.ChatMessagesPage
	decode(t, res, &page)
	if page.Space != chatSpace || page.Order != "desc" || page.MaxResults != 10 || page.NextPageToken != "messages-page-2" || !page.HasMore || len(page.Items) != 2 {
		t.Fatalf("page = %+v", page)
	}
	newest, oldest := page.Items[0], page.Items[1]
	if newest.Name != "spaces/AAAAexample1/messages/msg2.msg2" || newest.Sender.Name != "users/111111111111111111111" || newest.Sender.Type != "HUMAN" ||
		newest.Created != "2026-10-28T09:15:00Z" || newest.Text != "Deploy is done." || newest.Thread != chatThread || !newest.ThreadReply || newest.Attachments != 0 {
		t.Errorf("newest = %+v", newest)
	}
	if oldest.Sender.DisplayName != "Dave Example" || oldest.Attachments != 2 || oldest.ThreadReply {
		t.Errorf("oldest = %+v", oldest)
	}

	// Defaults: newest first, page 25, no filter; order asc.
	if _, err := run(t, c, call("chat.list_messages", map[string]any{"space": chatSpace, "order": "asc"})); err != nil {
		t.Fatal(err)
	}
	q = query(t, srv, "/v1/spaces/AAAAexample1/messages")
	if q.Get("orderBy") != "createTime asc" || q.Get("pageSize") != "25" || q.Has("filter") {
		t.Errorf("asc query = %v", q)
	}
	if _, err := run(t, c, call("chat.list_messages", map[string]any{"space": chatSpace, "since": "2026-10-28T00:00:00Z"})); err != nil {
		t.Fatal(err)
	}
	if q = query(t, srv, "/v1/spaces/AAAAexample1/messages"); q.Get("filter") != `createTime > "2026-10-28T00:00:00Z"` || q.Get("orderBy") != "createTime desc" {
		t.Errorf("since-only query = %v", q)
	}
}

func TestChatGetMessage(t *testing.T) {
	srv := newAPIServer(t, map[string]route{chatMessagePath: {status: 200, body: "chat_message.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("chat.get_message", map[string]any{"message": "spaces/AAAAexample1/messages/msg1.msg1"}))
	if err != nil {
		t.Fatalf("chat.get_message: %v", err)
	}
	var m google.ChatMessageDetail
	decode(t, res, &m)
	if m.Name != "spaces/AAAAexample1/messages/msg1.msg1" || m.Space != chatSpace || m.Sender.DisplayName != "Dave Example" || m.Created != "2026-10-28T09:00:00Z" ||
		m.Updated != "2026-10-28T09:01:00Z" || m.Text != "Starting the deploy, see the attached plan." || m.Thread != chatThread || m.Truncated {
		t.Errorf("message = %+v", m)
	}
	if len(m.Attachments) != 1 || m.Attachments[0].ContentName != "plan.pdf" || m.Attachments[0].ContentType != "application/pdf" || m.Attachments[0].Source != "UPLOADED_CONTENT" {
		t.Errorf("attachments = %+v", m.Attachments)
	}

	// The text is cut to the bounds.
	c, _ = newConnector(t, srv, connectors.Bounds{MaxResultBytes: 500})
	if res, err = run(t, c, call("chat.get_message", map[string]any{"message": "spaces/AAAAexample1/messages/msg1.msg1"})); err != nil {
		t.Fatal(err)
	}
	decode(t, res, &m)
	if !res.Partial || !m.Truncated || len(m.Text) >= len("Starting the deploy, see the attached plan.") {
		t.Errorf("res = %+v message = %+v, want the text cut and Partial", res, m)
	}
}

func TestChatListMembers(t *testing.T) {
	srv := newAPIServer(t, map[string]route{chatMembersPath: {status: 200, body: "chat_members_list.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("chat.list_members", map[string]any{"space": chatSpace, "max_results": 3, "page_token": "members-page-1"}))
	if err != nil {
		t.Fatalf("chat.list_members: %v", err)
	}
	q := query(t, srv, "/v1/spaces/AAAAexample1/members")
	if q.Get("pageSize") != "3" || q.Get("pageToken") != "members-page-1" || q.Get("showGroups") != "true" {
		t.Errorf("query = %v", q)
	}
	var page google.ChatMembersPage
	decode(t, res, &page)
	if page.Space != chatSpace || page.NextPageToken != "members-page-2" || !page.HasMore || len(page.Items) != 3 {
		t.Fatalf("page = %+v", page)
	}
	human, bot, group := page.Items[0], page.Items[1], page.Items[2]
	if human.Name != "spaces/AAAAexample1/members/111111111111111111111" || human.Member == nil || human.Member.Name != "users/111111111111111111111" ||
		human.Member.Type != "HUMAN" || human.Role != "ROLE_MANAGER" || human.State != "JOINED" || human.Group != "" {
		t.Errorf("human = %+v", human)
	}
	if bot.Member == nil || bot.Member.DisplayName != "Build Bot" || bot.Member.Type != "BOT" {
		t.Errorf("bot = %+v", bot)
	}
	if group.Member != nil || group.Group != "groups/03abcexample" {
		t.Errorf("group = %+v", group)
	}
}

func TestChatReadsEmptyClampedAndTruncated(t *testing.T) {
	for _, tc := range []struct {
		tool, path, empty, full string
		args                    map[string]any
	}{
		{"chat.list_spaces", chatSpacesPath, "chat_spaces_empty.json", "chat_spaces_list.json", map[string]any{}},
		{"chat.list_messages", chatMessagesPath, "chat_messages_empty.json", "chat_messages_list.json", map[string]any{"space": chatSpace}},
		{"chat.list_members", chatMembersPath, "chat_members_empty.json", "chat_members_list.json", map[string]any{"space": chatSpace}},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			urlPath := strings.TrimPrefix(tc.path, "GET ")
			srv := newAPIServer(t, map[string]route{tc.path: {status: 200, body: tc.empty}})
			c, _ := newConnector(t, srv, connectors.Bounds{MaxPageSize: 20})
			res, err := run(t, c, call(tc.tool, tc.args))
			if err != nil {
				t.Fatal(err)
			}
			var page struct {
				Items     []any `json:"items"`
				Truncated bool  `json:"truncated"`
			}
			decode(t, res, &page)
			if !res.Empty || res.Partial || page.Items == nil || len(page.Items) != 0 {
				t.Errorf("res = %+v page = %+v, want Empty with an empty items list", res, page)
			}
			args := map[string]any{"max_results": 99}
			for k, v := range tc.args {
				args[k] = v
			}
			if res, err = run(t, c, call(tc.tool, args)); err != nil {
				t.Fatal(err)
			}
			if got := query(t, srv, urlPath).Get("pageSize"); got != "20" || !res.Partial {
				t.Errorf("pageSize = %q partial = %v, want 20 and Partial", got, res.Partial)
			}

			srv = newAPIServer(t, map[string]route{tc.path: {status: 200, body: tc.full}})
			c, _ = newConnector(t, srv, connectors.Bounds{MaxResultBytes: 250})
			if res, err = run(t, c, call(tc.tool, tc.args)); err != nil {
				t.Fatal(err)
			}
			decode(t, res, &page)
			if !res.Partial || !page.Truncated || len(page.Items) != 1 {
				t.Errorf("res = %+v page = %+v, want one item, truncated", res, page)
			}
		})
	}
}

// One message larger than the bounds keeps its metadata and loses text.
func TestChatListMessagesCutsALongText(t *testing.T) {
	long := strings.Repeat("x", 2000)
	srv := newAPIServer(t, map[string]route{chatMessagesPath: {status: 200, body: `{"messages":[{"name":"spaces/AAAAexample1/messages/m.m","text":"` + long + `","sender":{"name":"users/1","type":"HUMAN"}}]}`}})
	c, _ := newConnector(t, srv, connectors.Bounds{MaxResultBytes: 500})
	res, err := run(t, c, call("chat.list_messages", map[string]any{"space": chatSpace}))
	if err != nil {
		t.Fatal(err)
	}
	var page google.ChatMessagesPage
	decode(t, res, &page)
	if !res.Partial || !page.Truncated || len(page.Items) != 1 || !page.Items[0].Truncated || len(page.Items[0].Text) >= 2000 || page.Items[0].Name != "spaces/AAAAexample1/messages/m.m" {
		t.Errorf("res = %+v page = %+v", res, page)
	}
}

func TestChatReadArgumentsAndErrors(t *testing.T) {
	c, tk := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	for name, tc := range map[string]struct {
		tool string
		args map[string]any
	}{
		"get_space missing":           {"chat.get_space", map[string]any{}},
		"get_space bad":               {"chat.get_space", map[string]any{"space": "spaces/a/b"}},
		"get_space spaces only":       {"chat.get_space", map[string]any{"space": "spaces/"}},
		"get_space space":             {"chat.get_space", map[string]any{"space": "has space"}},
		"list_spaces max 0":           {"chat.list_spaces", map[string]any{"max_results": 0}},
		"list_spaces filter number":   {"chat.list_spaces", map[string]any{"filter": 5}},
		"list_messages missing space": {"chat.list_messages", map[string]any{}},
		"list_messages bad since":     {"chat.list_messages", map[string]any{"space": chatSpace, "since": "yesterday"}},
		"list_messages until<since":   {"chat.list_messages", map[string]any{"space": chatSpace, "since": "2026-10-29T00:00:00Z", "until": "2026-10-28T00:00:00Z"}},
		"list_messages bad order":     {"chat.list_messages", map[string]any{"space": chatSpace, "order": "newest"}},
		"list_messages bad thread":    {"chat.list_messages", map[string]any{"space": chatSpace, "thread": "thr1"}},
		"list_messages other thread":  {"chat.list_messages", map[string]any{"space": chatSpace, "thread": "spaces/OTHER/threads/thr1"}},
		"get_message missing":         {"chat.get_message", map[string]any{}},
		"get_message bad":             {"chat.get_message", map[string]any{"message": "msg1.msg1"}},
		"get_message thread":          {"chat.get_message", map[string]any{"message": chatThread}},
		"list_members missing":        {"chat.list_members", map[string]any{}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := run(t, c, call(tc.tool, tc.args))
			wantClass(t, err, google.ClassInvalidArgument, 0)
		})
	}
	if len(tk.calls) != 0 {
		t.Errorf("token calls for invalid arguments = %d", len(tk.calls))
	}
	reads := []struct {
		tool, path string
		args       map[string]any
	}{
		{"chat.list_spaces", chatSpacesPath, nil},
		{"chat.get_space", chatSpacePath, map[string]any{"space": chatSpace}},
		{"chat.list_messages", chatMessagesPath, map[string]any{"space": chatSpace}},
		{"chat.get_message", chatMessagePath, map[string]any{"message": "spaces/AAAAexample1/messages/msg1.msg1"}},
		{"chat.list_members", chatMembersPath, map[string]any{"space": chatSpace}},
	}
	for _, tc := range readErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			routes := map[string]route{}
			for _, r := range reads {
				routes[r.path] = tc.rt
			}
			c, _ := newConnector(t, newAPIServer(t, routes), connectors.Bounds{})
			for _, r := range reads {
				res, err := run(t, c, call(r.tool, r.args))
				checkReadError(t, tc, res, err)
			}
		})
	}
	// The Chat API answers 404 "Google Chat app not found" when the
	// gateway's Cloud project has no Chat app configured: an admin's
	// job, not a missing resource.
	routes := map[string]route{}
	for _, r := range reads {
		routes[r.path] = route{status: 404, body: "error_chat_app_not_found.json"}
	}
	c, _ = newConnector(t, newAPIServer(t, routes), connectors.Bounds{})
	for _, r := range reads {
		_, err := run(t, c, call(r.tool, r.args))
		wantClass(t, err, google.ClassForbidden, 404)
		if !strings.Contains(err.Error(), "Chat API") || !strings.Contains(err.Error(), "Configuration") {
			t.Errorf("%s: message %q does not tell the admin to configure the Chat app", r.tool, err.Error())
		}
	}
}

// A personal account cannot grant the Chat scopes: the scope gate says
// so before any request.
func TestChatScopeGateWorkspaceOnly(t *testing.T) {
	srv := newAPIServer(t, nil)
	accounts := connectors.NewStaticAccountSource()
	accounts.Add(alice, connectors.Account{ID: acct, App: google.AppChat, Label: connectors.LabelPersonal, Scopes: []string{"openid", google.ScopeGmailReadonly}})
	c, err := google.New(google.Options{Tokens: (&tokens{}).source, BaseURL: srv.URL + "/", Accounts: accounts})
	if err != nil {
		t.Fatal(err)
	}
	for _, cl := range []connectors.Call{
		call("chat.list_spaces", nil),
		call("chat.list_messages", map[string]any{"space": chatSpace}),
		call("chat.list_members", map[string]any{"space": chatSpace}),
	} {
		_, err = run(t, c, cl)
		wantClass(t, err, google.ClassScopeRequired, 0)
		if !strings.Contains(err.Error(), "personal Google (gmail.com) accounts cannot grant") {
			t.Errorf("%s: message %q", cl.Tool, err.Error())
		}
	}
	if n := len(srv.Requests()); n != 0 {
		t.Errorf("requests = %d, want none", n)
	}
	// chat.memberships covers chat.memberships.readonly.
	if !google.Grants([]string{google.ScopeChatMemberships}, google.ScopeChatMembershipsReadonly) ||
		google.Grants([]string{google.ScopeChatMembershipsReadonly}, google.ScopeChatMemberships) {
		t.Error("chat.memberships must cover chat.memberships.readonly and not the reverse")
	}
	if !google.WorkspaceOnlyScope(google.ScopeChatMemberships) || !google.WorkspaceOnlyScope(google.ScopeChatMembershipsReadonly) {
		t.Error("the Chat membership scopes are Workspace-only")
	}
}
