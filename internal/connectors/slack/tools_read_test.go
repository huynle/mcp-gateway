package slack_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/slack"
)

const (
	alice = "user-alice"
	acct  = "0b7f7a2e-1c7e-4c2a-9a39-2d2a6c0f9b11"
)

// tokens is the TokenSourceFunc of the tests: every call records who asked
// for which connection and gets the fixture user token, unless fail is set.
type tokens struct {
	calls []string
	fail  error
}

func (tk *tokens) source(_ context.Context, userID, connectionID string) oauth2.TokenSource {
	tk.calls = append(tk.calls, userID+"/"+connectionID)
	if tk.fail != nil {
		return failingSource{err: tk.fail}
	}
	return oauth2.StaticTokenSource(&oauth2.Token{AccessToken: testToken})
}

type failingSource struct{ err error }

func (f failingSource) Token() (*oauth2.Token, error) { return nil, f.err }

// newConnector builds a connector against the fixture server.
func newConnector(t *testing.T, srv *apiServer, opts slack.Options) (*slack.Connector, *tokens) {
	t.Helper()
	tk := &tokens{}
	opts.Tokens = tk.source
	opts.BaseURL = srv.API()
	c, err := slack.New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, tk
}

func call(tool string, args map[string]any) connectors.Call {
	if args == nil {
		args = map[string]any{}
	}
	return connectors.Call{Principal: connectors.Principal{UserID: alice, TokenID: "tok"}, Tool: "slack." + tool, Account: acct, Args: args}
}

// decode marshals a result's content and decodes it into v.
func decode(t *testing.T, res connectors.Result, v any) {
	t.Helper()
	raw, err := json.Marshal(res.Content)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
}

func wantClass(t *testing.T, err error, class string) {
	t.Helper()
	var sErr *slack.Error
	if !errors.As(err, &sErr) {
		t.Fatalf("err = %v (%T), want *slack.Error class %s", err, err, class)
	}
	if sErr.Class != class {
		t.Fatalf("err = class %s (%v), want class %s", sErr.Class, err, class)
	}
}

func noMarkers(t *testing.T, res connectors.Result) {
	t.Helper()
	if res.Empty || res.Partial || res.Unavailable {
		t.Errorf("markers = empty %v partial %v unavailable %v", res.Empty, res.Partial, res.Unavailable)
	}
}

// toolNamed returns the connector's tool by short name.
func toolNamed(t *testing.T, c *slack.Connector, name string) connectors.Tool {
	t.Helper()
	for _, tool := range c.Tools() {
		if tool.Name == name {
			return tool
		}
	}
	t.Fatalf("tool %s not declared", name)
	return connectors.Tool{}
}

// --- tool metadata ----------------------------------------------------------

func TestToolsAreTheFiveReadsAndThreeWrites(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), slack.Options{})
	if c.App() != "slack" {
		t.Errorf("App() = %q", c.App())
	}
	var reads, writes []string
	for _, tool := range c.Tools() {
		if tool.Kind == connectors.KindRead {
			reads = append(reads, tool.Name)
			if tool.Reconcile.Kind != "" || tool.ResultIDs != nil {
				t.Errorf("%s: a read must not declare reconciliation or ResultIDs", tool.Name)
			}
		} else {
			writes = append(writes, tool.Name)
		}
		if tool.Bounds.MaxResultBytes <= 0 {
			t.Errorf("%s: MaxResultBytes = %d", tool.Name, tool.Bounds.MaxResultBytes)
		}
	}
	if want := "list_channels,read_channel_history,get_thread,search_messages,get_user"; strings.Join(reads, ",") != want {
		t.Errorf("reads = %v, want %s", reads, want)
	}
	if want := "post_message,reply_in_thread,add_reaction"; strings.Join(writes, ",") != want {
		t.Errorf("writes = %v, want %s", writes, want)
	}
}

type schemaShape struct {
	Type       string                    `json:"type"`
	Properties map[string]map[string]any `json:"properties"`
	Required   []string                  `json:"required"`
	Additional *bool                     `json:"additionalProperties"`
}

func checkSchema(t *testing.T, tool connectors.Tool, required, props []string) {
	t.Helper()
	var s schemaShape
	if err := json.Unmarshal(tool.InputSchema, &s); err != nil {
		t.Fatalf("schema: %v", err)
	}
	if s.Type != "object" || s.Additional == nil || *s.Additional {
		t.Errorf("schema must be a closed object: %s", tool.InputSchema)
	}
	if strings.Join(s.Required, ",") != strings.Join(required, ",") {
		t.Errorf("required = %v, want %v", s.Required, required)
	}
	for _, p := range props {
		if s.Properties[p] == nil {
			t.Errorf("property %q missing", p)
		} else if d, _ := s.Properties[p]["description"].(string); strings.TrimSpace(d) == "" {
			t.Errorf("property %q has no description", p)
		}
	}
	if len(s.Properties) != len(props) {
		t.Errorf("properties = %d, want %d: %s", len(s.Properties), len(props), tool.InputSchema)
	}
	if strings.TrimSpace(tool.Description) == "" {
		t.Error("empty description")
	}
}

func checkIdentity(t *testing.T, tool connectors.Tool, args map[string]any, want map[string]string) {
	t.Helper()
	got := tool.ResourceIdentity(args)
	if len(got) != len(want) {
		t.Errorf("ResourceIdentity = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("ResourceIdentity[%s] = %q, want %q (all: %v)", k, got[k], v, got)
		}
	}
	for _, v := range got {
		if strings.Contains(v, "secret") {
			t.Errorf("ResourceIdentity leaks argument content: %v", got)
		}
	}
	if id := tool.ResourceIdentity(nil); id == nil || len(id) != 0 {
		t.Errorf("ResourceIdentity(nil) = %v, want empty map", id)
	}
}

func TestReadToolSchemasScopesAndIdentity(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), slack.Options{})
	cases := []struct {
		tool     string
		required []string
		props    []string
		scopes   []string
		args     map[string]any
		identity map[string]string
		paged    bool
	}{
		{
			tool: "list_channels", props: []string{"types", "limit", "cursor", "exclude_archived"},
			scopes: []string{"channels:read", "groups:read"}, args: map[string]any{"limit": 10}, identity: map[string]string{}, paged: true,
		},
		{
			tool: "read_channel_history", required: []string{"channel"}, props: []string{"channel", "limit", "cursor", "oldest", "latest"},
			scopes: []string{"channels:history", "groups:history"},
			args:   map[string]any{"channel": "#Eng-General", "limit": 5}, identity: map[string]string{"channel": "eng-general", "channel_name": "eng-general"}, paged: true,
		},
		{
			tool: "get_thread", required: []string{"channel", "thread_ts"}, props: []string{"channel", "thread_ts", "limit", "cursor"},
			scopes:   []string{"channels:history", "groups:history"},
			args:     map[string]any{"channel": "C0ENGGEN01", "thread_ts": "1700002000.000100"},
			identity: map[string]string{"channel": "C0ENGGEN01", "channel_id": "C0ENGGEN01", "thread_ts": "1700002000.000100"}, paged: true,
		},
		{
			tool: "search_messages", required: []string{"query"}, props: []string{"query", "count", "page", "sort", "sort_dir"},
			scopes: []string{"search:read"}, args: map[string]any{"query": "secret words"}, identity: map[string]string{}, paged: true,
		},
		{
			tool: "get_user", required: []string{"user"}, props: []string{"user"},
			scopes: []string{"users:read"}, args: map[string]any{"user": "u0bob00002"}, identity: map[string]string{"user": "U0BOB00002"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			tool := toolNamed(t, c, tc.tool)
			checkSchema(t, tool, tc.required, tc.props)
			checkIdentity(t, tool, tc.args, tc.identity)
			if strings.Join(tool.RequiredScopes, ",") != strings.Join(tc.scopes, ",") {
				t.Errorf("RequiredScopes = %v, want %v", tool.RequiredScopes, tc.scopes)
			}
			if tc.paged && (tool.Bounds.MaxPageSize <= 0 || tool.Bounds.MaxPageSize > 100) {
				t.Errorf("MaxPageSize = %d, want 1..100", tool.Bounds.MaxPageSize)
			}
			if !tc.paged && tool.Bounds.MaxPageSize != 0 {
				t.Errorf("MaxPageSize = %d for a tool that does not paginate", tool.Bounds.MaxPageSize)
			}
		})
	}
}

// The channel in the resource identity is what a role rule such as
// "post only to #eng-*" (prefix eng- on key channel) matches: a name is
// stored lower-cased without its "#", an id as is; channel_name or
// channel_id says which one it was.
func TestChannelIdentity(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), slack.Options{})
	tool := toolNamed(t, c, "read_channel_history")
	cases := map[string]map[string]string{
		"#eng-general":              {"channel": "eng-general", "channel_name": "eng-general"},
		"eng-general":               {"channel": "eng-general", "channel_name": "eng-general"},
		"#ENG-Leads":                {"channel": "eng-leads", "channel_name": "eng-leads"},
		"C0ENGGEN01":                {"channel": "C0ENGGEN01", "channel_id": "C0ENGGEN01"},
		"c0enggen01":                {"channel": "C0ENGGEN01", "channel_id": "C0ENGGEN01"},
		"G0SECRET01":                {"channel": "G0SECRET01", "channel_id": "G0SECRET01"},
		"D0DM0000001":               {"channel": "D0DM0000001", "channel_id": "D0DM0000001"},
		"<#C0ENGGEN01>":             {"channel": "C0ENGGEN01", "channel_id": "C0ENGGEN01"},
		"<#C0ENGGEN01|eng-general>": {"channel": "C0ENGGEN01", "channel_id": "C0ENGGEN01"},
		"":                          {},
	}
	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			checkIdentity(t, tool, map[string]any{"channel": in}, want)
		})
	}
	// Surrounding whitespace is trimmed.
	checkIdentity(t, tool, map[string]any{"channel": " \t#ENG-Leads "}, map[string]string{"channel": "eng-leads", "channel_name": "eng-leads"})
}

func TestNewOptions(t *testing.T) {
	if _, err := slack.New(slack.Options{}); err == nil {
		t.Error("New without Tokens succeeded")
	}
	if _, err := slack.New(slack.Options{Tokens: (&tokens{}).source, BaseURL: "not a url"}); err == nil {
		t.Error("New with a bad BaseURL succeeded")
	}
	c, err := slack.New(slack.Options{Tokens: (&tokens{}).source})
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range c.Tools() {
		if tool.Bounds.MaxResultBytes != connectors.DefaultMaxResultBytes {
			t.Errorf("%s: MaxResultBytes = %d, want the package default", tool.Name, tool.Bounds.MaxResultBytes)
		}
		if tool.Bounds.MaxPageSize != 0 && tool.Bounds.MaxPageSize != connectors.DefaultMaxPageSize {
			t.Errorf("%s: MaxPageSize = %d, want 0 or the default", tool.Name, tool.Bounds.MaxPageSize)
		}
	}
	c, err = slack.New(slack.Options{Tokens: (&tokens{}).source, Bounds: connectors.Bounds{MaxPageSize: 5000}})
	if err != nil {
		t.Fatal(err)
	}
	if got := toolNamed(t, c, "list_channels").Bounds.MaxPageSize; got != 100 {
		t.Errorf("MaxPageSize = %d, want capped at Slack's 100", got)
	}
}

// --- call plumbing ------------------------------------------------------------

func TestCallWithoutAccount(t *testing.T) {
	c, tk := newConnector(t, newAPIServer(t, nil), slack.Options{})
	in := call("get_user", map[string]any{"user": "U0BOB00002"})
	in.Account = ""
	_, err := c.Call(context.Background(), in)
	wantClass(t, err, slack.ClassNoAccount)
	if len(tk.calls) != 0 {
		t.Errorf("token source consulted without an account: %v", tk.calls)
	}
}

func TestCallNeedsReconnectFromTokenSource(t *testing.T) {
	c, tk := newConnector(t, newAPIServer(t, nil), slack.Options{})
	tk.fail = connections.ErrNeedsReconnect
	_, err := c.Call(context.Background(), call("get_user", map[string]any{"user": "U0BOB00002"}))
	wantClass(t, err, slack.ClassReconnectRequired)
	if !errors.Is(err, connections.ErrNeedsReconnect) {
		t.Errorf("err %v does not wrap ErrNeedsReconnect", err)
	}
}

func TestUnknownTool(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), slack.Options{})
	if _, err := c.Call(context.Background(), call("nope", nil)); !errors.Is(err, connectors.ErrUnknownTool) {
		t.Errorf("err = %v, want ErrUnknownTool", err)
	}
}

func TestCancelledContextIsAnError(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"users.info": {body: "users_info.json"}})
	c, _ := newConnector(t, srv, slack.Options{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := c.Call(ctx, call("get_user", map[string]any{"user": "U0BOB00002"}))
	if !errors.Is(err, context.Canceled) || res.Unavailable {
		t.Fatalf("res = %+v err = %v, want context.Canceled", res, err)
	}
}

// --- error classes shared by every read -----------------------------------------

func TestReadErrorClasses(t *testing.T) {
	cases := []struct {
		name        string
		rt          route
		class       string
		unavailable bool
		retryAfter  time.Duration
	}{
		{name: "invalid_auth reconnect", rt: route{body: "error_invalid_auth.json"}, class: slack.ClassReconnectRequired},
		{name: "missing_scope forbidden", rt: route{body: "error_missing_scope.json"}, class: slack.ClassForbidden},
		{name: "user_not_found", rt: route{body: "error_user_not_found.json"}, class: slack.ClassNotFound},
		{name: "fatal_error unavailable", rt: route{body: "error_fatal.json"}, unavailable: true},
		{name: "500 unavailable", rt: route{status: 500, body: "<html>oops</html>"}, unavailable: true},
		{name: "503 unavailable", rt: route{status: 503, body: ""}, unavailable: true},
		{name: "429 with Retry-After", rt: route{status: 429, body: "{}", headers: map[string]string{"Retry-After": "37"}}, retryAfter: 37 * time.Second},
		{name: "ok:false ratelimited", rt: route{body: "error_ratelimited.json"}, retryAfter: slack.DefaultRetryAfter},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"users.info": tc.rt})
			c, _ := newConnector(t, srv, slack.Options{})
			res, err := c.Call(context.Background(), call("get_user", map[string]any{"user": "U0BOB00002"}))
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
				if rl.App != "slack" || rl.RetryAfter != tc.retryAfter {
					t.Errorf("RateLimited = %+v, want slack / %s", rl, tc.retryAfter)
				}
			default:
				wantClass(t, err, tc.class)
			}
			if err != nil && strings.Contains(err.Error(), testToken) {
				t.Errorf("error message leaks the token: %q", err.Error())
			}
		})
	}
}

func TestNetworkFailureIsUnavailable(t *testing.T) {
	srv := newAPIServer(t, nil)
	c, _ := newConnector(t, srv, slack.Options{})
	srv.Close()
	res, err := c.Call(context.Background(), call("get_user", map[string]any{"user": "U0BOB00002"}))
	if err != nil || !res.Unavailable {
		t.Fatalf("res = %+v err = %v, want Unavailable", res, err)
	}
}

// --- list_channels ------------------------------------------------------------

type channelsPage struct {
	Channels []struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		IsPrivate  bool   `json:"is_private"`
		IsArchived bool   `json:"is_archived"`
		IsMember   bool   `json:"is_member"`
		NumMembers int    `json:"num_members"`
		Topic      string `json:"topic"`
		Purpose    string `json:"purpose"`
	} `json:"channels"`
	NextCursor string `json:"next_cursor"`
	HasMore    bool   `json:"has_more"`
	Limit      int    `json:"limit"`
	Truncated  bool   `json:"truncated"`
}

func TestListChannels(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"users.conversations": {byCursor: map[string]route{
		"":                     {body: "users_conversations_page1.json"},
		"dXNlcjpVMEc5V0ZYTlo=": {body: "users_conversations_page2.json"},
	}}})
	c, tk := newConnector(t, srv, slack.Options{})
	res, err := c.Call(context.Background(), call("list_channels", nil))
	if err != nil {
		t.Fatalf("list_channels: %v", err)
	}
	var page channelsPage
	decode(t, res, &page)
	if len(page.Channels) != 2 || !page.HasMore || page.NextCursor != "dXNlcjpVMEc5V0ZYTlo=" || page.Limit != 50 {
		t.Errorf("page = %+v", page)
	}
	first := page.Channels[0]
	if first.ID != "C0ENGGEN01" || first.Name != "eng-general" || first.IsPrivate || first.NumMembers != 42 || first.Topic != "Engineering chatter" || first.Purpose != "Everything engineering" {
		t.Errorf("channel = %+v", first)
	}
	if !page.Channels[1].IsPrivate || page.Channels[1].Name != "eng-leads" {
		t.Errorf("second channel = %+v", page.Channels[1])
	}
	// users.conversations lists only the user's own conversations but
	// leaves is_member unset (as in the fixture): every row is a member.
	for _, ch := range page.Channels {
		if !ch.IsMember {
			t.Errorf("%s: is_member = false, want true (users.conversations returns only the user's conversations)", ch.Name)
		}
	}
	noMarkers(t, res)
	form := srv.Last(t, "users.conversations").Form
	if form.Get("types") != "public_channel,private_channel" || form.Get("limit") != "50" || form.Get("exclude_archived") != "true" {
		t.Errorf("form = %v", redactForm(form))
	}
	if len(tk.calls) != 1 || tk.calls[0] != alice+"/"+acct {
		t.Errorf("token source calls = %v", tk.calls)
	}
	if ua := srv.Requests()[0].Header.Get("User-Agent"); !strings.Contains(ua, "mcp-gateway") {
		t.Errorf("User-Agent = %q", ua)
	}

	// The next page through the cursor; includes archived when asked.
	res, err = c.Call(context.Background(), call("list_channels", map[string]any{"cursor": "dXNlcjpVMEc5V0ZYTlo=", "exclude_archived": false, "types": "public_channel"}))
	if err != nil {
		t.Fatal(err)
	}
	var page2 channelsPage
	decode(t, res, &page2)
	if len(page2.Channels) != 1 || page2.HasMore || page2.NextCursor != "" || !page2.Channels[0].IsArchived {
		t.Errorf("page 2 = %+v", page2)
	}
	form = srv.Last(t, "users.conversations").Form
	if form.Get("cursor") != "dXNlcjpVMEc5V0ZYTlo=" || form.Get("exclude_archived") != "" || form.Get("types") != "public_channel" {
		t.Errorf("form = %v", redactForm(form))
	}
}

func TestListChannelsEmptyAndClamped(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"users.conversations": {body: "users_conversations_empty.json"}})
	c, _ := newConnector(t, srv, slack.Options{Bounds: connectors.Bounds{MaxPageSize: 10}})
	res, err := c.Call(context.Background(), call("list_channels", map[string]any{"limit": 500}))
	if err != nil {
		t.Fatal(err)
	}
	var page channelsPage
	decode(t, res, &page)
	if !res.Empty || !res.Partial || page.Channels == nil || len(page.Channels) != 0 || page.Limit != 10 {
		t.Errorf("res = %+v page = %+v, want Empty and Partial (clamped) with an empty array", res, page)
	}
	if got := srv.Last(t, "users.conversations").Form.Get("limit"); got != "10" {
		t.Errorf("limit sent = %q, want 10", got)
	}
}

func TestListChannelsValidation(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), slack.Options{})
	for name, args := range map[string]map[string]any{
		"bad limit":  {"limit": 0},
		"bad types":  {"types": "im"},
		"bad cursor": {"cursor": 12},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := c.Call(context.Background(), call("list_channels", args))
			wantClass(t, err, slack.ClassInvalidArgument)
		})
	}
}

func TestListChannelsTruncatedToBounds(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"users.conversations": {body: "users_conversations_page1.json"}})
	c, _ := newConnector(t, srv, slack.Options{Bounds: connectors.Bounds{MaxResultBytes: 300}})
	res, err := c.Call(context.Background(), call("list_channels", nil))
	if err != nil {
		t.Fatal(err)
	}
	var page channelsPage
	decode(t, res, &page)
	if !res.Partial || !page.Truncated || len(page.Channels) != 1 {
		t.Errorf("res = %+v page = %+v, want one channel left and Partial", res, page)
	}
}

// --- read_channel_history -------------------------------------------------------

type historyPage struct {
	Channel     string `json:"channel"`
	ChannelName string `json:"channel_name"`
	Messages    []struct {
		TS         string `json:"ts"`
		ThreadTS   string `json:"thread_ts"`
		User       string `json:"user"`
		Text       string `json:"text"`
		Subtype    string `json:"subtype"`
		ReplyCount int    `json:"reply_count"`
		Edited     bool   `json:"edited"`
		Reactions  []struct {
			Name  string `json:"name"`
			Count int    `json:"count"`
		} `json:"reactions"`
	} `json:"messages"`
	HasMore    bool   `json:"has_more"`
	NextCursor string `json:"next_cursor"`
	Limit      int    `json:"limit"`
	Truncated  bool   `json:"truncated"`
}

func TestReadChannelHistoryByID(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"conversations.history": {body: "conversations_history.json"}})
	c, _ := newConnector(t, srv, slack.Options{})
	res, err := c.Call(context.Background(), call("read_channel_history", map[string]any{"channel": "C0ENGGEN01", "limit": 20, "oldest": "1700000000.000000", "latest": "1700009999.000000"}))
	if err != nil {
		t.Fatalf("read_channel_history: %v", err)
	}
	var page historyPage
	decode(t, res, &page)
	if page.Channel != "C0ENGGEN01" || page.ChannelName != "" || len(page.Messages) != 3 || !page.HasMore || page.NextCursor == "" || page.Limit != 20 {
		t.Errorf("page = %+v", page)
	}
	m := page.Messages[0]
	if m.TS != "1700003000.000200" || m.User != "U0BOB00002" || !strings.HasPrefix(m.Text, "Deploy of widgets") || len(m.Reactions) != 1 || m.Reactions[0].Name != "tada" || m.Reactions[0].Count != 2 {
		t.Errorf("message = %+v", m)
	}
	if page.Messages[1].Subtype != "channel_join" {
		t.Errorf("subtype = %q", page.Messages[1].Subtype)
	}
	if last := page.Messages[2]; last.ThreadTS != "1700002000.000100" || last.ReplyCount != 2 || !last.Edited {
		t.Errorf("thread parent = %+v", last)
	}
	noMarkers(t, res)
	form := srv.Last(t, "conversations.history").Form
	if form.Get("channel") != "C0ENGGEN01" || form.Get("limit") != "20" || form.Get("oldest") != "1700000000.000000" || form.Get("latest") != "1700009999.000000" {
		t.Errorf("form = %v", redactForm(form))
	}
	if srv.Count("users.conversations") != 0 {
		t.Error("an id needs no name resolution")
	}
}

// A channel name is resolved through the user's conversations (bounded
// cursor walk) before the history call, which needs the id.
func TestReadChannelHistoryByName(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		"users.conversations": {byCursor: map[string]route{
			"":                     {body: "users_conversations_page1.json"},
			"dXNlcjpVMEc5V0ZYTlo=": {body: "users_conversations_page2.json"},
		}},
		"conversations.history": {body: "conversations_history.json"},
	})
	c, _ := newConnector(t, srv, slack.Options{})
	res, err := c.Call(context.Background(), call("read_channel_history", map[string]any{"channel": "#Random"}))
	if err != nil {
		t.Fatalf("read_channel_history: %v", err)
	}
	var page historyPage
	decode(t, res, &page)
	if page.Channel != "C0RANDOM01" || page.ChannelName != "random" {
		t.Errorf("page = %+v", page)
	}
	if got := srv.Last(t, "conversations.history").Form.Get("channel"); got != "C0RANDOM01" {
		t.Errorf("history channel = %q, want the resolved id", got)
	}
	if got := srv.Last(t, "users.conversations").Form.Get("limit"); got != "200" {
		t.Errorf("resolution page size = %q, want 200", got)
	}
	if n := srv.Count("users.conversations"); n != 2 {
		t.Errorf("resolution walked %d pages, want 2 (found on the second)", n)
	}
	if got := srv.Last(t, "users.conversations").Form.Get("exclude_archived"); got != "" {
		t.Errorf("resolution excluded archived channels; names must resolve for archived ones too")
	}
}

func TestReadChannelHistoryUnknownNameIsNotFound(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"users.conversations": {byCursor: map[string]route{
		"":                     {body: "users_conversations_page1.json"},
		"dXNlcjpVMEc5V0ZYTlo=": {body: "users_conversations_page2.json"},
	}}})
	c, _ := newConnector(t, srv, slack.Options{})
	_, err := c.Call(context.Background(), call("read_channel_history", map[string]any{"channel": "#nope"}))
	wantClass(t, err, slack.ClassNotFound)
	if srv.Count("conversations.history") != 0 {
		t.Error("history requested for an unresolved name")
	}
}

func TestReadChannelHistoryNameResolutionIsBounded(t *testing.T) {
	// Every page has a next cursor pointing at itself: the walk must stop
	// at MaxResolvePages and report that it could not tell.
	srv := newAPIServer(t, map[string]route{"users.conversations": {body: "users_conversations_page1.json"}})
	c, _ := newConnector(t, srv, slack.Options{})
	_, err := c.Call(context.Background(), call("read_channel_history", map[string]any{"channel": "#nope"}))
	wantClass(t, err, slack.ClassNotFound)
	if n := srv.Count("users.conversations"); n != slack.MaxResolvePages {
		t.Errorf("resolution walked %d pages, want MaxResolvePages (%d)", n, slack.MaxResolvePages)
	}
	if !strings.Contains(err.Error(), "channel id") {
		t.Errorf("error should tell the harness to pass the channel id: %v", err)
	}
}

func TestReadChannelHistoryEmptyAndErrors(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{"conversations.history": {body: "conversations_history_empty.json"}})
		c, _ := newConnector(t, srv, slack.Options{})
		res, err := c.Call(context.Background(), call("read_channel_history", map[string]any{"channel": "C0ENGGEN01"}))
		if err != nil {
			t.Fatal(err)
		}
		var page historyPage
		decode(t, res, &page)
		if !res.Empty || res.Partial || page.Messages == nil || len(page.Messages) != 0 || page.HasMore {
			t.Errorf("res = %+v page = %+v", res, page)
		}
	})
	for name, tc := range map[string]struct {
		body  string
		class string
	}{
		"channel_not_found": {"error_channel_not_found.json", slack.ClassNotFound},
		"not_in_channel":    {"error_not_in_channel.json", slack.ClassForbidden},
		"missing_scope":     {"error_missing_scope.json", slack.ClassForbidden},
		"invalid_auth":      {"error_invalid_auth.json", slack.ClassReconnectRequired},
	} {
		t.Run(name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"conversations.history": {body: tc.body}})
			c, _ := newConnector(t, srv, slack.Options{})
			_, err := c.Call(context.Background(), call("read_channel_history", map[string]any{"channel": "C0ENGGEN01"}))
			wantClass(t, err, tc.class)
		})
	}
	t.Run("5xx unavailable", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{"conversations.history": {status: 502, body: ""}})
		c, _ := newConnector(t, srv, slack.Options{})
		res, err := c.Call(context.Background(), call("read_channel_history", map[string]any{"channel": "C0ENGGEN01"}))
		if err != nil || !res.Unavailable {
			t.Fatalf("res = %+v err = %v", res, err)
		}
	})
}

func TestReadChannelHistoryValidationAndBounds(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), slack.Options{})
	for name, args := range map[string]map[string]any{
		"missing channel": {},
		"bad limit":       {"channel": "C0ENGGEN01", "limit": -1},
		"bad oldest":      {"channel": "C0ENGGEN01", "oldest": "yesterday"},
		"bad latest":      {"channel": "C0ENGGEN01", "latest": "12:00"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := c.Call(context.Background(), call("read_channel_history", args))
			wantClass(t, err, slack.ClassInvalidArgument)
		})
	}
	t.Run("clamped and truncated", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{"conversations.history": {body: "conversations_history.json"}})
		c, _ := newConnector(t, srv, slack.Options{Bounds: connectors.Bounds{MaxPageSize: 2, MaxResultBytes: 260}})
		res, err := c.Call(context.Background(), call("read_channel_history", map[string]any{"channel": "C0ENGGEN01", "limit": 50}))
		if err != nil {
			t.Fatal(err)
		}
		var page historyPage
		decode(t, res, &page)
		if !res.Partial || !page.Truncated || len(page.Messages) < 1 || len(page.Messages) >= 3 || page.Limit != 2 {
			t.Errorf("res = %+v page = %+v, want clamped to 2 and truncated", res, page)
		}
		if got := srv.Last(t, "conversations.history").Form.Get("limit"); got != "2" {
			t.Errorf("limit sent = %q", got)
		}
	})
}

// --- get_thread -----------------------------------------------------------------

func TestGetThread(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"conversations.replies": {body: "conversations_replies.json"}})
	c, _ := newConnector(t, srv, slack.Options{})
	res, err := c.Call(context.Background(), call("get_thread", map[string]any{"channel": "C0ENGGEN01", "thread_ts": "1700002000.000100"}))
	if err != nil {
		t.Fatalf("get_thread: %v", err)
	}
	var page struct {
		historyPage
		ThreadTS string `json:"thread_ts"`
	}
	decode(t, res, &page)
	if page.Channel != "C0ENGGEN01" || page.ThreadTS != "1700002000.000100" || len(page.Messages) != 3 || page.HasMore {
		t.Errorf("page = %+v", page)
	}
	if page.Messages[0].ReplyCount != 2 || page.Messages[2].Text != "All green" {
		t.Errorf("messages = %+v", page.Messages)
	}
	noMarkers(t, res)
	form := srv.Last(t, "conversations.replies").Form
	if form.Get("channel") != "C0ENGGEN01" || form.Get("ts") != "1700002000.000100" || form.Get("limit") != "50" {
		t.Errorf("form = %v", redactForm(form))
	}
}

func TestGetThreadErrors(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), slack.Options{})
	for name, args := range map[string]map[string]any{
		"missing thread_ts": {"channel": "C0ENGGEN01"},
		"bad thread_ts":     {"channel": "C0ENGGEN01", "thread_ts": "p1700002000000100"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := c.Call(context.Background(), call("get_thread", args))
			wantClass(t, err, slack.ClassInvalidArgument)
		})
	}
	t.Run("thread_not_found", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{"conversations.replies": {body: "error_thread_not_found.json"}})
		c, _ := newConnector(t, srv, slack.Options{})
		_, err := c.Call(context.Background(), call("get_thread", map[string]any{"channel": "C0ENGGEN01", "thread_ts": "1700002000.000100"}))
		wantClass(t, err, slack.ClassNotFound)
	})
}

// --- search_messages ---------------------------------------------------------------

type searchPage struct {
	Total     int  `json:"total"`
	Page      int  `json:"page"`
	PerPage   int  `json:"per_page"`
	PageCount int  `json:"page_count"`
	HasMore   bool `json:"has_more"`
	Truncated bool `json:"truncated"`
	Messages  []struct {
		TS          string `json:"ts"`
		Channel     string `json:"channel"`
		ChannelName string `json:"channel_name"`
		User        string `json:"user"`
		Username    string `json:"username"`
		Text        string `json:"text"`
		Permalink   string `json:"permalink"`
		ThreadTS    string `json:"thread_ts"`
	} `json:"messages"`
}

func TestSearchMessages(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"search.messages": {body: "search_messages.json"}})
	c, _ := newConnector(t, srv, slack.Options{})
	res, err := c.Call(context.Background(), call("search_messages", map[string]any{"query": "deploy widgets", "sort": "timestamp", "sort_dir": "desc"}))
	if err != nil {
		t.Fatalf("search_messages: %v", err)
	}
	var page searchPage
	decode(t, res, &page)
	if page.Total != 2 || page.Page != 1 || page.PageCount != 1 || page.HasMore || len(page.Messages) != 2 {
		t.Errorf("page = %+v", page)
	}
	m := page.Messages[0]
	if m.Channel != "C0ENGGEN01" || m.ChannelName != "eng-general" || m.User != "U0BOB00002" || m.Username != "bob" || m.Permalink == "" || m.ThreadTS != "" {
		t.Errorf("message = %+v", m)
	}
	if page.Messages[1].ThreadTS != "1700002000.000100" {
		t.Errorf("thread_ts from the permalink = %q", page.Messages[1].ThreadTS)
	}
	noMarkers(t, res)
	// slack-go omits parameters at Slack's defaults (count 20, page 1,
	// sort_dir desc, no highlight); only the non-default sort travels.
	form := srv.Last(t, "search.messages").Form
	if form.Get("query") != "deploy widgets" || form.Get("count") != "" || form.Get("page") != "" || form.Get("sort") != "timestamp" || form.Get("sort_dir") != "" || form.Get("highlight") != "" {
		t.Errorf("form = %v", redactForm(form))
	}
}

func TestSearchMessagesPagesEmptyAndValidation(t *testing.T) {
	t.Run("page 2 of 3 has more", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{"search.messages": {byPage: map[string]route{"2": {body: "search_messages_page2of3.json"}}}})
		c, _ := newConnector(t, srv, slack.Options{Bounds: connectors.Bounds{MaxPageSize: 10}})
		res, err := c.Call(context.Background(), call("search_messages", map[string]any{"query": "deploy", "count": 10, "page": 2}))
		if err != nil {
			t.Fatal(err)
		}
		var page searchPage
		decode(t, res, &page)
		if page.Page != 2 || page.PageCount != 3 || !page.HasMore || page.PerPage != 10 || res.Partial {
			t.Errorf("res = %+v page = %+v", res, page)
		}
	})
	t.Run("empty", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{"search.messages": {body: "search_messages_empty.json"}})
		c, _ := newConnector(t, srv, slack.Options{})
		res, err := c.Call(context.Background(), call("search_messages", map[string]any{"query": "nothing here"}))
		if err != nil {
			t.Fatal(err)
		}
		var page searchPage
		decode(t, res, &page)
		if !res.Empty || page.Messages == nil || len(page.Messages) != 0 || page.HasMore {
			t.Errorf("res = %+v page = %+v", res, page)
		}
	})
	t.Run("clamped count is partial", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{"search.messages": {body: "search_messages.json"}})
		c, _ := newConnector(t, srv, slack.Options{Bounds: connectors.Bounds{MaxPageSize: 10}})
		res, err := c.Call(context.Background(), call("search_messages", map[string]any{"query": "deploy", "count": 99}))
		if err != nil {
			t.Fatal(err)
		}
		if !res.Partial {
			t.Error("clamped count should be Partial")
		}
		if got := srv.Last(t, "search.messages").Form.Get("count"); got != "10" {
			t.Errorf("count sent = %q", got)
		}
	})
	c, _ := newConnector(t, newAPIServer(t, nil), slack.Options{})
	for name, args := range map[string]map[string]any{
		"blank query": {"query": "  "},
		"bad page":    {"query": "x", "page": 0},
		"bad sort":    {"query": "x", "sort": "relevance"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := c.Call(context.Background(), call("search_messages", args))
			wantClass(t, err, slack.ClassInvalidArgument)
		})
	}
}

// --- get_user --------------------------------------------------------------------

func TestGetUser(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"users.info": {body: "users_info.json"}})
	c, _ := newConnector(t, srv, slack.Options{})
	res, err := c.Call(context.Background(), call("get_user", map[string]any{"user": "<@U0BOB00002>"}))
	if err != nil {
		t.Fatalf("get_user: %v", err)
	}
	var u struct {
		ID          string `json:"id"`
		TeamID      string `json:"team_id"`
		Name        string `json:"name"`
		RealName    string `json:"real_name"`
		DisplayName string `json:"display_name"`
		Title       string `json:"title"`
		TZ          string `json:"tz"`
		IsBot       bool   `json:"is_bot"`
		IsAdmin     bool   `json:"is_admin"`
		Deleted     bool   `json:"deleted"`
		Email       string `json:"email"`
	}
	decode(t, res, &u)
	if u.ID != "U0BOB00002" || u.TeamID != "T0EXAMPLE1" || u.Name != "bob" || u.RealName != "Bob Example" || u.DisplayName != "bobby" || u.Title != "Site Reliability" || u.TZ != "America/New_York" || u.IsBot || u.IsAdmin || u.Deleted {
		t.Errorf("user = %+v", u)
	}
	if u.Email != "" {
		t.Errorf("email %q returned: users:read does not grant it and the tool does not expose it", u.Email)
	}
	noMarkers(t, res)
	if got := srv.Last(t, "users.info").Form.Get("user"); got != "U0BOB00002" {
		t.Errorf("user sent = %q", got)
	}
	for name, args := range map[string]map[string]any{
		"missing": {},
		"a name":  {"user": "bob"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := c.Call(context.Background(), call("get_user", args))
			wantClass(t, err, slack.ClassInvalidArgument)
		})
	}
}

// --- recorded wire shapes stay token-free ------------------------------------------

func TestFixturesCarryNoRealTokens(t *testing.T) {
	for _, f := range []string{"auth_test_user.json", "users_info.json", "conversations_history.json", "search_messages.json"} {
		if strings.Contains(fixture(t, f), "xox") {
			t.Errorf("%s carries a token-like string", f)
		}
	}
	_ = http.StatusOK
}
