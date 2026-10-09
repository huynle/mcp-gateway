package microsoft_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/microsoft"
)

// --- tool metadata ----------------------------------------------------------

func TestToolsStartWithTheSixReads(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	if c.App() != "microsoft" {
		t.Errorf("App() = %q", c.App())
	}
	var names []string
	for _, tool := range c.Tools() {
		if tool.Kind != connectors.KindRead {
			continue
		}
		names = append(names, tool.Name)
		if tool.Reconcile.Kind != "" || tool.ResultIDs != nil {
			t.Errorf("%s: a read must not declare reconciliation or ResultIDs", tool.Name)
		}
		if tool.Bounds.MaxResultBytes <= 0 {
			t.Errorf("%s: MaxResultBytes = %d", tool.Name, tool.Bounds.MaxResultBytes)
		}
	}
	want := []string{"mail_search", "mail_get_message", "calendar_list_events", "drive_search", "teams_list_channels", "teams_read_channel_messages"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("read tools = %v, want %v", names, want)
	}
	if got := len(c.Tools()); got != len(want)+4 {
		t.Errorf("Tools() = %d tools, want the %d reads and 4 writes", got, len(want))
	}
}

func TestReadToolSchemasAndIdentity(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	tools := map[string]connectors.Tool{}
	for _, tool := range c.Tools() {
		tools[tool.Name] = tool
	}
	type schema struct {
		Type       string                    `json:"type"`
		Properties map[string]map[string]any `json:"properties"`
		Required   []string                  `json:"required"`
		Additional *bool                     `json:"additionalProperties"`
	}
	cases := []struct {
		tool     string
		required []string
		props    []string
		args     map[string]any
		identity map[string]string
		scopes   []string
		paged    bool
	}{
		{
			tool: "mail_search", props: []string{"q", "filter", "folder", "top"},
			args:     map[string]any{"q": "secret words", "folder": "Inbox"},
			identity: map[string]string{"folder": "inbox"},
			scopes:   []string{"Mail.Read"}, paged: true,
		},
		{
			tool: "mail_get_message", required: []string{"id"}, props: []string{"id"},
			args:     map[string]any{"id": "AAMkAGE1-msg-1"},
			identity: map[string]string{"message": "AAMkAGE1-msg-1"},
			scopes:   []string{"Mail.Read"},
		},
		{
			tool: "calendar_list_events", required: []string{"start", "end"}, props: []string{"start", "end", "calendar_id", "top"},
			args:     map[string]any{"start": "2026-10-08T00:00:00Z", "end": "2026-10-09T00:00:00Z"},
			identity: map[string]string{"calendar": "default"},
			scopes:   []string{"Calendars.Read"}, paged: true,
		},
		{
			tool: "drive_search", required: []string{"q"}, props: []string{"q", "drive_id", "top"},
			args:     map[string]any{"q": "secret", "drive_id": "b!drive-1"},
			identity: map[string]string{"drive": "b!drive-1"},
			scopes:   []string{"Files.Read.All"}, paged: true,
		},
		{
			tool: "teams_list_channels", props: []string{"team_id", "top"},
			args:     map[string]any{"team_id": "team-1"},
			identity: map[string]string{"team": "team-1"},
			scopes:   []string{"Team.ReadBasic.All", "Channel.ReadBasic.All"}, paged: true,
		},
		{
			tool: "teams_read_channel_messages", required: []string{"team_id", "channel_id"}, props: []string{"team_id", "channel_id", "top"},
			args:     map[string]any{"team_id": "team-1", "channel_id": "19:chan-general@thread.tacv2"},
			identity: map[string]string{"team": "team-1", "channel": "19:chan-general@thread.tacv2"},
			scopes:   []string{"ChannelMessage.Read.All"}, paged: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			tool, ok := tools[tc.tool]
			if !ok {
				t.Fatalf("tool %s not declared", tc.tool)
			}
			var s schema
			if err := json.Unmarshal(tool.InputSchema, &s); err != nil {
				t.Fatalf("schema: %v", err)
			}
			if s.Type != "object" || s.Additional == nil || *s.Additional {
				t.Errorf("schema must be a closed object: %s", tool.InputSchema)
			}
			if strings.Join(s.Required, ",") != strings.Join(tc.required, ",") {
				t.Errorf("required = %v, want %v", s.Required, tc.required)
			}
			for _, p := range tc.props {
				if s.Properties[p] == nil {
					t.Errorf("property %q missing", p)
				} else if d, _ := s.Properties[p]["description"].(string); strings.TrimSpace(d) == "" {
					t.Errorf("property %q has no description", p)
				}
			}
			if len(s.Properties) != len(tc.props) {
				t.Errorf("properties = %d, want %d: %s", len(s.Properties), len(tc.props), tool.InputSchema)
			}
			if tc.paged {
				if s.Properties["top"]["type"] != "integer" {
					t.Errorf("top must be an integer: %s", tool.InputSchema)
				}
				if tool.Bounds.MaxPageSize <= 0 || tool.Bounds.MaxPageSize > 100 {
					t.Errorf("MaxPageSize = %d, want 1..100", tool.Bounds.MaxPageSize)
				}
			} else if tool.Bounds.MaxPageSize != 0 {
				t.Errorf("MaxPageSize = %d for a tool that does not paginate", tool.Bounds.MaxPageSize)
			}
			got := tool.ResourceIdentity(tc.args)
			if len(got) != len(tc.identity) {
				t.Errorf("ResourceIdentity = %v, want %v", got, tc.identity)
			}
			for k, v := range tc.identity {
				if got[k] != v {
					t.Errorf("ResourceIdentity[%s] = %q, want %q (all: %v)", k, got[k], v, got)
				}
			}
			for _, v := range got {
				if strings.Contains(v, "secret") {
					t.Errorf("ResourceIdentity leaks argument content: %v", got)
				}
			}
			if id := tool.ResourceIdentity(nil); id == nil {
				t.Errorf("ResourceIdentity(nil) = nil, want a map")
			}
			if strings.Join(tool.RequiredScopes, ",") != strings.Join(tc.scopes, ",") {
				t.Errorf("RequiredScopes = %v, want %v", tool.RequiredScopes, tc.scopes)
			}
		})
	}
}

func TestNewRequiresTokens(t *testing.T) {
	if _, err := microsoft.New(microsoft.Options{}); err == nil {
		t.Error("New without Tokens succeeded")
	}
	if _, err := microsoft.New(microsoft.Options{Tokens: (&tokens{}).source, BaseURL: "not a url"}); err == nil {
		t.Error("New with a bad BaseURL succeeded")
	}
	c, err := microsoft.New(microsoft.Options{Tokens: (&tokens{}).source})
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range c.Tools() {
		if tool.Bounds.MaxResultBytes != connectors.DefaultMaxResultBytes {
			t.Errorf("%s: MaxResultBytes = %d, want the package default", tool.Name, tool.Bounds.MaxResultBytes)
		}
		if tool.Bounds.MaxPageSize != 0 && tool.Bounds.MaxPageSize != connectors.DefaultMaxPageSize {
			t.Errorf("%s: MaxPageSize = %d, want 0 or the default %d", tool.Name, tool.Bounds.MaxPageSize, connectors.DefaultMaxPageSize)
		}
	}
}

// --- Call plumbing -----------------------------------------------------------------

func TestCallWithoutAccount(t *testing.T) {
	c, tk := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	in := call("mail_search", nil)
	in.Account = ""
	_, err := c.Call(context.Background(), in)
	wantClass(t, err, microsoft.ClassNoAccount, 0)
	if len(tk.calls) != 0 {
		t.Errorf("token source consulted without an account: %v", tk.calls)
	}
}

func TestCallNeedsReconnectFromTokenSource(t *testing.T) {
	c, tk := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	tk.fail = connections.ErrNeedsReconnect
	_, err := c.Call(context.Background(), call("mail_search", nil))
	wantClass(t, err, microsoft.ClassReconnectRequired, 0)
	if !errors.Is(err, connections.ErrNeedsReconnect) {
		t.Errorf("err %v does not wrap ErrNeedsReconnect", err)
	}
}

func TestUnknownTool(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	if _, err := c.Call(context.Background(), call("nope", nil)); !errors.Is(err, connectors.ErrUnknownTool) {
		t.Errorf("err = %v, want ErrUnknownTool", err)
	}
}

// Scope enforcement: the pipeline does not compare Tool.RequiredScopes
// with Account.Scopes yet, so the connector does it in Call (decision
// recorded in the task report). A personal Microsoft account never
// carries the Teams scopes (the binder strips them), so its Teams calls
// are refused before any request; a work account with them proceeds; a
// work account that has not granted a scope is told to grant it.
func TestCallRefusesToolsWhoseScopesTheAccountLacks(t *testing.T) {
	personal := []string{"User.Read", "offline_access", "Mail.Read", "Mail.Send", "Calendars.ReadWrite", "Files.ReadWrite"}
	srv := newAPIServer(t, map[string]route{"GET /v1.0/me/messages": {status: 200, body: "messages.json"}})
	c, tk := newConnectorWithScopes(t, srv, connectors.Bounds{}, personal)
	for _, tool := range []string{"teams_list_channels", "teams_read_channel_messages", "teams_post_channel_message"} {
		in := call(tool, map[string]any{"team_id": "team-1", "channel_id": "c", "content": "x"})
		in.OperationID = "op-1"
		_, err := c.Call(context.Background(), in)
		wantClass(t, err, microsoft.ClassScopeRequired, 0)
		if !strings.Contains(err.Error(), "personal Microsoft accounts") {
			t.Errorf("%s: message %q should explain that personal accounts have no Teams", tool, err.Error())
		}
	}
	if len(tk.calls) != 0 || len(srv.Requests()) != 0 {
		t.Errorf("a refused tool fetched a token (%v) or sent requests (%d)", tk.calls, len(srv.Requests()))
	}
	// Mail still works: Mail.Read is granted.
	if _, err := c.Call(context.Background(), call("mail_search", nil)); err != nil {
		t.Errorf("mail_search with Mail.Read: %v", err)
	}
	// Files.ReadWrite covers Files.Read (same resource, wider access) but
	// not Files.Read.All.
	_, err := c.Call(context.Background(), call("drive_search", map[string]any{"q": "x"}))
	wantClass(t, err, microsoft.ClassScopeRequired, 0)
	if !strings.Contains(err.Error(), "Files.Read.All") || !strings.Contains(err.Error(), "/connections") {
		t.Errorf("message %q should name the missing scope and the portal page", err.Error())
	}
}

func TestCallWithoutAccountSourceDoesNotCheckScopes(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /v1.0/me/joinedTeams": {status: 200, body: "joined_teams_empty.json"}})
	c, err := microsoft.New(microsoft.Options{Tokens: (&tokens{}).source, BaseURL: srv.URL + "/v1.0/"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Call(context.Background(), call("teams_list_channels", nil)); err != nil {
		t.Errorf("without an account source Graph decides: %v", err)
	}
}

func TestScopeCovered(t *testing.T) {
	cases := []struct {
		granted  string
		required string
		want     bool
	}{
		{"Mail.Read", "Mail.Read", true},
		{"mail.read", "Mail.Read", true},
		{"https://graph.microsoft.com/Mail.Read", "Mail.Read", true},
		{"Mail.ReadWrite", "Mail.Read", true},
		{"Mail.Send", "Mail.Read", false},
		{"Calendars.ReadWrite", "Calendars.Read", true},
		{"Calendars.Read", "Calendars.ReadWrite", false},
		{"Files.ReadWrite.All", "Files.Read.All", true},
		{"Files.ReadWrite.All", "Files.ReadWrite", true},
		{"Files.ReadWrite", "Files.Read.All", false},
		{"Files.Read.All", "Files.Read", true},
		{"ChannelMessage.ReadWrite", "ChannelMessage.Read.All", false},
		{"", "Mail.Read", false},
	}
	for _, tc := range cases {
		if got := microsoft.ScopeCovered([]string{tc.granted}, tc.required); got != tc.want {
			t.Errorf("ScopeCovered(%q, %q) = %v, want %v", tc.granted, tc.required, got, tc.want)
		}
	}
}

// --- error classes shared by every tool ------------------------------------------

func TestErrorClasses(t *testing.T) {
	cases := []struct {
		name        string
		rt          route
		class       string
		status      int
		unavailable bool
		retryAfter  time.Duration
	}{
		{name: "401 reconnect", rt: route{status: 401, body: "error_invalid_token.json"}, class: microsoft.ClassReconnectRequired, status: 401},
		{name: "403 forbidden", rt: route{status: 403, body: "error_access_denied.json"}, class: microsoft.ClassForbidden, status: 403},
		{name: "404 not found", rt: route{status: 404, body: "error_item_not_found.json"}, class: microsoft.ClassNotFound, status: 404},
		{name: "400 invalid", rt: route{status: 400, body: "error_invalid_request.json"}, class: microsoft.ClassInvalidArgument, status: 400},
		{name: "500 unavailable", rt: route{status: 500, body: "error_server.json"}, unavailable: true},
		{name: "503 without Retry-After unavailable", rt: route{status: 503, body: "error_server.json"}, unavailable: true},
		{name: "429 throttled", rt: route{status: 429, body: "error_throttled.json", headers: map[string]string{"Retry-After": "37"}}, retryAfter: 37 * time.Second},
		{name: "429 without Retry-After", rt: route{status: 429, body: "error_throttled.json"}, retryAfter: microsoft.DefaultRetryAfter},
		{name: "503 with Retry-After throttled", rt: route{status: 503, body: "error_server.json", headers: map[string]string{"Retry-After": "12"}}, retryAfter: 12 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"GET /v1.0/me/messages/AAMkAGE1-msg-1": tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := c.Call(context.Background(), call("mail_get_message", map[string]any{"id": "AAMkAGE1-msg-1"}))
			switch {
			case tc.unavailable:
				if err != nil || !res.Unavailable || res.Content != nil {
					t.Fatalf("res = %+v err = %v, want Unavailable without content", res, err)
				}
			case tc.retryAfter > 0:
				var rl *connectors.RateLimited
				if !errors.As(err, &rl) {
					t.Fatalf("err = %v (%T), want *connectors.RateLimited", err, err)
				}
				if rl.App != "microsoft" || rl.RetryAfter != tc.retryAfter {
					t.Errorf("RateLimited = %+v, want app microsoft retry after %s", rl, tc.retryAfter)
				}
			default:
				wantClass(t, err, tc.class, tc.status)
				if strings.Contains(err.Error(), testToken) {
					t.Errorf("error message leaks the token: %q", err.Error())
				}
			}
		})
	}
}

func TestNetworkFailureIsUnavailable(t *testing.T) {
	srv := newAPIServer(t, nil)
	c, _ := newConnector(t, srv, connectors.Bounds{})
	srv.Close()
	res, err := c.Call(context.Background(), call("mail_search", nil))
	if err != nil || !res.Unavailable {
		t.Fatalf("res = %+v err = %v, want Unavailable", res, err)
	}
}

func TestCancelledContextIsAnError(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /v1.0/me/messages": {status: 200, body: "messages.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := c.Call(ctx, call("mail_search", nil))
	if !errors.Is(err, context.Canceled) || res.Unavailable {
		t.Fatalf("res = %+v err = %v, want context.Canceled", res, err)
	}
}

// --- mail_search --------------------------------------------------------------------

type mailPage struct {
	Top       int  `json:"top"`
	HasMore   bool `json:"has_more"`
	Truncated bool `json:"truncated"`
	Items     []struct {
		ID             string `json:"id"`
		Subject        string `json:"subject"`
		FromName       string `json:"from_name"`
		FromAddress    string `json:"from_address"`
		ReceivedAt     string `json:"received_at"`
		Preview        string `json:"preview"`
		IsRead         bool   `json:"is_read"`
		HasAttachments bool   `json:"has_attachments"`
		WebLink        string `json:"web_link"`
	} `json:"items"`
}

func TestMailSearch(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /v1.0/me/messages": {status: 200, body: "messages.json"}})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call("mail_search", map[string]any{"q": "budget"}))
	if err != nil {
		t.Fatalf("mail_search: %v", err)
	}
	var page mailPage
	decode(t, res, &page)
	if len(page.Items) != 2 || page.HasMore || page.Top != 25 {
		t.Errorf("page = %+v", page)
	}
	first := page.Items[0]
	if first.ID != "AAMkAGE1-msg-1" || first.Subject != "Q3 budget review" || first.FromName != "Bob Example" || first.FromAddress != "bob@example.test" ||
		first.ReceivedAt != "2026-10-07T09:15:00Z" || !strings.HasPrefix(first.Preview, "Hi Alice") || first.IsRead || !first.HasAttachments || first.WebLink == "" {
		t.Errorf("item = %+v", first)
	}
	if res.Empty || res.Partial || res.Unavailable {
		t.Errorf("markers = %+v", res)
	}
	q := query(t, srv, "/v1.0/me/messages")
	if got := q.Get("$search"); got != `"budget"` {
		t.Errorf("$search = %q", got)
	}
	if q.Get("$top") != "25" || q.Get("$select") == "" || q.Has("$filter") || q.Has("$orderby") {
		t.Errorf("query = %v (search cannot combine with $filter/$orderby)", q)
	}
	if len(tk.calls) != 1 || tk.calls[0] != alice+"/"+acct {
		t.Errorf("token source calls = %v", tk.calls)
	}
	if ua := srv.Requests()[0].Header.Get("User-Agent"); !strings.Contains(ua, "mcp-gateway") {
		t.Errorf("User-Agent = %q", ua)
	}
}

func TestMailSearchFilterAndFolder(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /v1.0/me/mailFolders/inbox/messages": {status: 200, body: "messages.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	if _, err := c.Call(context.Background(), call("mail_search", map[string]any{"filter": "isRead eq false", "folder": "Inbox", "top": 5})); err != nil {
		t.Fatal(err)
	}
	q := query(t, srv, "/v1.0/me/mailFolders/inbox/messages")
	if q.Get("$filter") != "isRead eq false" || q.Get("$orderby") != "receivedDateTime desc" || q.Get("$top") != "5" || q.Has("$search") {
		t.Errorf("query = %v", q)
	}
	// Search quotes are escaped, never injected.
	srv2 := newAPIServer(t, map[string]route{"GET /v1.0/me/messages": {status: 200, body: "messages.json"}})
	c2, _ := newConnector(t, srv2, connectors.Bounds{})
	if _, err := c2.Call(context.Background(), call("mail_search", map[string]any{"q": `say "hi"`})); err != nil {
		t.Fatal(err)
	}
	if got := query(t, srv2, "/v1.0/me/messages").Get("$search"); got != `"say \"hi\""` {
		t.Errorf("$search = %q", got)
	}
}

func TestMailSearchNewestWhenNoQuery(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /v1.0/me/messages": {status: 200, body: "messages.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	if _, err := c.Call(context.Background(), call("mail_search", nil)); err != nil {
		t.Fatal(err)
	}
	q := query(t, srv, "/v1.0/me/messages")
	if q.Get("$orderby") != "receivedDateTime desc" || q.Has("$search") || q.Has("$filter") {
		t.Errorf("query = %v", q)
	}
}

func TestMailSearchArguments(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	for name, args := range map[string]map[string]any{
		"bad folder":   {"folder": "inbox/../x"},
		"zero top":     {"top": 0},
		"string top":   {"top": "lots"},
		"query+filter": {"q": "x", "filter": "isRead eq false"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := c.Call(context.Background(), call("mail_search", args))
			wantClass(t, err, microsoft.ClassInvalidArgument, 0)
		})
	}
}

func TestMailSearchEmptyAndMore(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /v1.0/me/messages": {status: 200, body: "messages_empty.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call("mail_search", map[string]any{"q": "nothing"}))
	if err != nil {
		t.Fatal(err)
	}
	var page mailPage
	decode(t, res, &page)
	if !res.Empty || res.Partial || page.Items == nil || len(page.Items) != 0 {
		t.Errorf("res = %+v items = %v, want Empty with an empty items array", res, page.Items)
	}
	srv2 := newAPIServer(t, map[string]route{"GET /v1.0/me/messages": {status: 200, body: "messages_more.json"}})
	c2, _ := newConnector(t, srv2, connectors.Bounds{})
	res, err = c2.Call(context.Background(), call("mail_search", map[string]any{"q": "x", "top": 1}))
	if err != nil {
		t.Fatal(err)
	}
	decode(t, res, &page)
	if !page.HasMore || len(page.Items) != 1 || res.Partial {
		t.Errorf("res = %+v page = %+v, want has_more without Partial", res, page)
	}
	if n := len(srv2.Requests()); n != 1 {
		t.Errorf("requests = %d, want 1 (the next link is reported, not followed)", n)
	}
}

func TestMailSearchClampedTopIsPartial(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /v1.0/me/messages": {status: 200, body: "messages.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{MaxPageSize: 10})
	res, err := c.Call(context.Background(), call("mail_search", map[string]any{"q": "x", "top": 500}))
	if err != nil {
		t.Fatal(err)
	}
	var page mailPage
	decode(t, res, &page)
	if !res.Partial || page.Top != 10 || query(t, srv, "/v1.0/me/messages").Get("$top") != "10" {
		t.Errorf("res = %+v page = %+v, want Partial with top clamped to 10", res, page)
	}
}

func TestMailSearchTruncatedToResultBytes(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /v1.0/me/messages": {status: 200, body: "messages.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{MaxResultBytes: 400})
	res, err := c.Call(context.Background(), call("mail_search", map[string]any{"q": "x"}))
	if err != nil {
		t.Fatal(err)
	}
	var page mailPage
	decode(t, res, &page)
	raw, _ := json.Marshal(res.Content)
	if !res.Partial || !page.Truncated || len(page.Items) != 1 || len(raw) > 400 {
		t.Errorf("partial=%v truncated=%v items=%d bytes=%d, want Partial, truncated, 1 item, <= 400 bytes", res.Partial, page.Truncated, len(page.Items), len(raw))
	}
}

// --- mail_get_message ----------------------------------------------------------------

type message struct {
	ID              string   `json:"id"`
	Subject         string   `json:"subject"`
	FromName        string   `json:"from_name"`
	FromAddress     string   `json:"from_address"`
	To              []string `json:"to"`
	CC              []string `json:"cc"`
	ReceivedAt      string   `json:"received_at"`
	SentAt          string   `json:"sent_at"`
	IsRead          bool     `json:"is_read"`
	HasAttachments  bool     `json:"has_attachments"`
	ConversationID  string   `json:"conversation_id"`
	WebLink         string   `json:"web_link"`
	BodyContentType string   `json:"body_content_type"`
	Body            string   `json:"body"`
	Truncated       bool     `json:"truncated"`
}

func TestMailGetMessage(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /v1.0/me/messages/AAMkAGE1-msg-1": {status: 200, body: "message.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call("mail_get_message", map[string]any{"id": "AAMkAGE1-msg-1"}))
	if err != nil {
		t.Fatalf("mail_get_message: %v", err)
	}
	var m message
	decode(t, res, &m)
	if m.ID != "AAMkAGE1-msg-1" || m.Subject != "Q3 budget review" || m.FromAddress != "bob@example.test" || m.ReceivedAt != "2026-10-07T09:15:00Z" ||
		m.SentAt != "2026-10-07T09:14:30Z" || !m.HasAttachments || m.IsRead || m.ConversationID != "AAQkAGE1-conv-1" || m.WebLink == "" ||
		m.BodyContentType != "text" || !strings.Contains(m.Body, "Q3 budget") || m.Truncated {
		t.Errorf("message = %+v", m)
	}
	if len(m.To) != 1 || m.To[0] != "Alice Example <alice@example.test>" || len(m.CC) != 1 || m.CC[0] != "Carol Example <carol@example.test>" {
		t.Errorf("to/cc = %v / %v", m.To, m.CC)
	}
	req := srv.Last(t, "GET /v1.0/me/messages/AAMkAGE1-msg-1")
	if got := req.Header.Get("Prefer"); !strings.Contains(got, `outlook.body-content-type="text"`) {
		t.Errorf("Prefer = %q, want the text body", got)
	}
	if res.Empty || res.Partial || res.Unavailable {
		t.Errorf("markers = %+v", res)
	}
}

func TestMailGetMessageArguments(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	for name, args := range map[string]map[string]any{
		"missing id":    {},
		"blank id":      {"id": "  "},
		"id with slash": {"id": "a/b"},
		"id with query": {"id": "a?b"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := c.Call(context.Background(), call("mail_get_message", args))
			wantClass(t, err, microsoft.ClassInvalidArgument, 0)
		})
	}
}

func TestMailGetMessageBodyTruncated(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /v1.0/me/messages/AAMkAGE1-msg-1": {status: 200, body: "message.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{MaxResultBytes: 520})
	res, err := c.Call(context.Background(), call("mail_get_message", map[string]any{"id": "AAMkAGE1-msg-1"}))
	if err != nil {
		t.Fatal(err)
	}
	var m message
	decode(t, res, &m)
	raw, _ := json.Marshal(res.Content)
	if !res.Partial || !m.Truncated || len(raw) > 520 || m.Subject != "Q3 budget review" {
		t.Errorf("partial=%v truncated=%v bytes=%d subject=%q", res.Partial, m.Truncated, len(raw), m.Subject)
	}
}

// --- calendar_list_events --------------------------------------------------------------

type eventsPage struct {
	Top     int  `json:"top"`
	HasMore bool `json:"has_more"`
	Items   []struct {
		ID               string `json:"id"`
		Subject          string `json:"subject"`
		Start            string `json:"start"`
		End              string `json:"end"`
		TimeZone         string `json:"time_zone"`
		IsAllDay         bool   `json:"is_all_day"`
		IsCancelled      bool   `json:"is_cancelled"`
		Location         string `json:"location"`
		OrganizerName    string `json:"organizer_name"`
		OrganizerAddress string `json:"organizer_address"`
		WebLink          string `json:"web_link"`
	} `json:"items"`
}

func TestCalendarListEvents(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /v1.0/me/calendarView": {status: 200, body: "calendar_view.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call("calendar_list_events", map[string]any{"start": "2026-10-08T00:00:00Z", "end": "2026-10-10T00:00:00Z", "top": 10}))
	if err != nil {
		t.Fatalf("calendar_list_events: %v", err)
	}
	var page eventsPage
	decode(t, res, &page)
	if len(page.Items) != 2 || page.HasMore || page.Top != 10 {
		t.Errorf("page = %+v", page)
	}
	first := page.Items[0]
	if first.ID != "AAMkAGE1-evt-1" || first.Subject != "Sprint planning" || first.Start != "2026-10-08T09:00:00.0000000" || first.TimeZone != "UTC" ||
		first.Location != "Room 4" || first.OrganizerAddress != "bob@example.test" || first.IsAllDay || first.WebLink == "" {
		t.Errorf("item = %+v", first)
	}
	if !page.Items[1].IsAllDay {
		t.Error("second event should be all-day")
	}
	q := query(t, srv, "/v1.0/me/calendarView")
	if q.Get("startDateTime") != "2026-10-08T00:00:00Z" || q.Get("endDateTime") != "2026-10-10T00:00:00Z" || q.Get("$top") != "10" || q.Get("$orderby") != "start/dateTime" {
		t.Errorf("query = %v", q)
	}
	if got := srv.Last(t, "GET /v1.0/me/calendarView").Header.Get("Prefer"); !strings.Contains(got, `outlook.timezone="UTC"`) {
		t.Errorf("Prefer = %q", got)
	}
	if res.Empty || res.Partial {
		t.Errorf("markers = %+v", res)
	}
}

func TestCalendarListEventsCalendarAndEmpty(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /v1.0/me/calendars/cal-2/calendarView": {status: 200, body: "calendar_view_empty.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call("calendar_list_events", map[string]any{"start": "2026-10-08T00:00:00Z", "end": "2026-10-10T00:00:00Z", "calendar_id": "cal-2"}))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Empty {
		t.Errorf("res = %+v, want Empty", res)
	}
}

func TestCalendarListEventsArguments(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	for name, args := range map[string]map[string]any{
		"missing end":    {"start": "2026-10-08T00:00:00Z"},
		"bad start":      {"start": "tomorrow", "end": "2026-10-10T00:00:00Z"},
		"end before":     {"start": "2026-10-10T00:00:00Z", "end": "2026-10-08T00:00:00Z"},
		"bad calendar":   {"start": "2026-10-08T00:00:00Z", "end": "2026-10-10T00:00:00Z", "calendar_id": "a/b"},
		"window too big": {"start": "2020-01-01T00:00:00Z", "end": "2026-10-10T00:00:00Z"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := c.Call(context.Background(), call("calendar_list_events", args))
			wantClass(t, err, microsoft.ClassInvalidArgument, 0)
		})
	}
}

// --- drive_search -------------------------------------------------------------------------

type drivePage struct {
	Top     int  `json:"top"`
	HasMore bool `json:"has_more"`
	Items   []struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		IsFolder   bool   `json:"is_folder"`
		Size       int64  `json:"size"`
		WebURL     string `json:"web_url"`
		ModifiedAt string `json:"modified_at"`
		DriveID    string `json:"drive_id"`
		ParentID   string `json:"parent_id"`
		ParentPath string `json:"parent_path"`
		MimeType   string `json:"mime_type"`
	} `json:"items"`
}

func TestDriveSearch(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /v1.0/me/drive/root/search(q='Q3 budget')": {status: 200, body: "drive_search.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call("drive_search", map[string]any{"q": "Q3 budget"}))
	if err != nil {
		t.Fatalf("drive_search: %v", err)
	}
	var page drivePage
	decode(t, res, &page)
	if len(page.Items) != 2 || page.HasMore {
		t.Errorf("page = %+v", page)
	}
	first := page.Items[0]
	if first.ID != "01DRIVE-item-1" || first.Name != "Q3 budget.xlsx" || first.IsFolder || first.Size != 48213 || first.WebURL == "" ||
		first.ModifiedAt != "2026-10-05T16:20:00Z" || first.DriveID != "b!drive-1" || first.ParentID != "01DRIVE-folder-finance" || first.ParentPath != "/drive/root:/Finance" ||
		!strings.Contains(first.MimeType, "spreadsheet") {
		t.Errorf("item = %+v", first)
	}
	if !page.Items[1].IsFolder {
		t.Error("second item should be a folder")
	}
	if q := query(t, srv, "/v1.0/me/drive/root/search(q='Q3 budget')"); q.Get("$top") != "25" || q.Get("$select") == "" {
		t.Errorf("query = %v", q)
	}
}

func TestDriveSearchQuotesAndDrive(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /v1.0/drives/b!drive-1/root/search(q='it''s')": {status: 200, body: "drive_search_empty.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call("drive_search", map[string]any{"q": "it's", "drive_id": "b!drive-1"}))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Empty {
		t.Errorf("res = %+v, want Empty", res)
	}
	for name, args := range map[string]map[string]any{
		"missing q": {},
		"bad drive": {"q": "x", "drive_id": "a/b"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := c.Call(context.Background(), call("drive_search", args))
			wantClass(t, err, microsoft.ClassInvalidArgument, 0)
		})
	}
}

// --- teams_list_channels ----------------------------------------------------------------

type teamsPage struct {
	HasMore bool `json:"has_more"`
	Items   []struct {
		TeamID   string `json:"team_id"`
		TeamName string `json:"team_name"`
		Channels []struct {
			ID             string `json:"id"`
			DisplayName    string `json:"display_name"`
			MembershipType string `json:"membership_type"`
			WebURL         string `json:"web_url"`
		} `json:"channels"`
		Error string `json:"error"`
	} `json:"items"`
}

func TestTeamsListChannels(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		"GET /v1.0/me/joinedTeams":        {status: 200, body: "joined_teams.json"},
		"GET /v1.0/teams/team-1/channels": {status: 200, body: "channels_team1.json"},
		"GET /v1.0/teams/team-2/channels": {status: 200, body: "channels_team2.json"},
	})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call("teams_list_channels", nil))
	if err != nil {
		t.Fatalf("teams_list_channels: %v", err)
	}
	var page teamsPage
	decode(t, res, &page)
	if len(page.Items) != 2 || page.HasMore || page.Items[0].TeamID != "team-1" || page.Items[0].TeamName != "Engineering" || len(page.Items[0].Channels) != 2 || len(page.Items[1].Channels) != 1 {
		t.Errorf("page = %+v", page)
	}
	ch := page.Items[0].Channels[0]
	if ch.ID != "19:chan-general@thread.tacv2" || ch.DisplayName != "General" || ch.MembershipType != "standard" || ch.WebURL == "" {
		t.Errorf("channel = %+v", ch)
	}
	if res.Empty || res.Partial {
		t.Errorf("markers = %+v", res)
	}
}

func TestTeamsListChannelsOneTeamAndFailures(t *testing.T) {
	// A single team skips joinedTeams; a team whose channels are
	// forbidden is reported with an error and the result is Partial.
	srv := newAPIServer(t, map[string]route{
		"GET /v1.0/teams/team-1/channels": {status: 403, body: "error_access_denied.json"},
	})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call("teams_list_channels", map[string]any{"team_id": "team-1"}))
	if err != nil {
		t.Fatalf("teams_list_channels: %v", err)
	}
	var page teamsPage
	decode(t, res, &page)
	if !res.Partial || len(page.Items) != 1 || page.Items[0].Error == "" || len(page.Items[0].Channels) != 0 {
		t.Errorf("res = %+v page = %+v, want Partial with the team's error", res, page)
	}
	if srv.Count("GET /v1.0/me/joinedTeams") != 0 {
		t.Error("joinedTeams listed although team_id was given")
	}
	// No teams at all is Empty; a clamped top is Partial with has_more.
	srv2 := newAPIServer(t, map[string]route{"GET /v1.0/me/joinedTeams": {status: 200, body: "joined_teams_empty.json"}})
	c2, _ := newConnector(t, srv2, connectors.Bounds{})
	res, err = c2.Call(context.Background(), call("teams_list_channels", nil))
	if err != nil || !res.Empty {
		t.Errorf("res = %+v err = %v, want Empty", res, err)
	}
	srv3 := newAPIServer(t, map[string]route{
		"GET /v1.0/me/joinedTeams":        {status: 200, body: "joined_teams.json"},
		"GET /v1.0/teams/team-1/channels": {status: 200, body: "channels_team1.json"},
	})
	c3, _ := newConnector(t, srv3, connectors.Bounds{})
	res, err = c3.Call(context.Background(), call("teams_list_channels", map[string]any{"top": 1}))
	if err != nil {
		t.Fatal(err)
	}
	decode(t, res, &page)
	if len(page.Items) != 1 || !page.HasMore || srv3.Count("GET /v1.0/teams/team-2/channels") != 0 {
		t.Errorf("page = %+v (team-2 channels requested: %d)", page, srv3.Count("GET /v1.0/teams/team-2/channels"))
	}
}

// --- teams_read_channel_messages ------------------------------------------------------------

type channelMessagesPage struct {
	Top       int  `json:"top"`
	HasMore   bool `json:"has_more"`
	Truncated bool `json:"truncated"`
	Items     []struct {
		ID          string `json:"id"`
		FromName    string `json:"from_name"`
		CreatedAt   string `json:"created_at"`
		ContentType string `json:"content_type"`
		Content     string `json:"content"`
		WebURL      string `json:"web_url"`
	} `json:"items"`
}

func TestTeamsReadChannelMessages(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /v1.0/teams/team-1/channels/19:chan-general@thread.tacv2/messages": {status: 200, body: "channel_messages.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call("teams_read_channel_messages", map[string]any{"team_id": "team-1", "channel_id": "19:chan-general@thread.tacv2", "top": 20}))
	if err != nil {
		t.Fatalf("teams_read_channel_messages: %v", err)
	}
	var page channelMessagesPage
	decode(t, res, &page)
	if len(page.Items) != 2 || page.HasMore || page.Top != 20 {
		t.Errorf("page = %+v", page)
	}
	first := page.Items[0]
	if first.ID != "1728380000001" || first.FromName != "Bob Example" || first.CreatedAt != "2026-10-08T08:00:00.001Z" || first.ContentType != "html" || !strings.Contains(first.Content, "14:00") || first.WebURL == "" {
		t.Errorf("item = %+v", first)
	}
	if q := query(t, srv, "/v1.0/teams/team-1/channels/19:chan-general@thread.tacv2/messages"); q.Get("$top") != "20" {
		t.Errorf("query = %v", q)
	}
	if res.Empty || res.Partial {
		t.Errorf("markers = %+v", res)
	}
}

func TestTeamsReadChannelMessagesTopCappedAtGraphMaximum(t *testing.T) {
	// Graph caps channel messages at 50 per page whatever the bounds say.
	srv := newAPIServer(t, map[string]route{"GET /v1.0/teams/team-1/channels/c1/messages": {status: 200, body: "channel_messages_empty.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{MaxPageSize: 100})
	res, err := c.Call(context.Background(), call("teams_read_channel_messages", map[string]any{"team_id": "team-1", "channel_id": "c1", "top": 80}))
	if err != nil {
		t.Fatal(err)
	}
	if got := query(t, srv, "/v1.0/teams/team-1/channels/c1/messages").Get("$top"); got != "50" {
		t.Errorf("$top = %q, want 50", got)
	}
	if !res.Empty || !res.Partial {
		t.Errorf("res = %+v, want Empty and Partial (clamped)", res)
	}
}

func TestTeamsReadChannelMessagesTruncated(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /v1.0/teams/team-1/channels/c1/messages": {status: 200, body: "channel_messages.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{MaxResultBytes: 450})
	res, err := c.Call(context.Background(), call("teams_read_channel_messages", map[string]any{"team_id": "team-1", "channel_id": "c1"}))
	if err != nil {
		t.Fatal(err)
	}
	var page channelMessagesPage
	decode(t, res, &page)
	raw, _ := json.Marshal(res.Content)
	if !res.Partial || !page.Truncated || len(page.Items) != 1 || len(raw) > 450 {
		t.Errorf("partial=%v truncated=%v items=%d bytes=%d", res.Partial, page.Truncated, len(page.Items), len(raw))
	}
}

func TestTeamsReadChannelMessagesArguments(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	for name, args := range map[string]map[string]any{
		"missing channel": {"team_id": "team-1"},
		"bad team":        {"team_id": "a/b", "channel_id": "c"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := c.Call(context.Background(), call("teams_read_channel_messages", args))
			wantClass(t, err, microsoft.ClassInvalidArgument, 0)
		})
	}
}
