package slack_test

import (
	"context"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/slack"
)

func TestLookupToolsMetadata(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), slack.Options{})
	r := connectors.KindRead
	byID := map[string]string{"channel": "C0ENGGEN01", "channel_id": "C0ENGGEN01"}
	checkToolCases(t, c, []toolCase{
		{tool: "get_reactions", kind: r, scopes: []string{"reactions:read"}, required: []string{"channel", "timestamp"},
			props: []string{"channel", "timestamp"}, args: map[string]any{"channel": "C0ENGGEN01", "timestamp": msgTS},
			identity: map[string]string{"channel": "C0ENGGEN01", "channel_id": "C0ENGGEN01", "timestamp": msgTS}},
		{tool: "list_channel_members", kind: r, scopes: []string{"channels:read", "groups:read"}, required: []string{"channel"},
			props: []string{"channel", "limit", "cursor"}, args: map[string]any{"channel": "C0ENGGEN01"}, identity: byID},
		{tool: "search_files", kind: r, scopes: []string{"search:read"}, required: []string{"query"},
			props: []string{"query", "count", "page", "sort", "sort_dir"}, args: map[string]any{"query": "secret"}, identity: map[string]string{}},
		{tool: "search_users", kind: r, scopes: []string{"users:read"}, required: []string{"query"},
			props: []string{"query", "limit", "include_bots", "include_deactivated"}, args: map[string]any{"query": "secret"}, identity: map[string]string{}},
		{tool: "search_channels", kind: r, scopes: []string{"channels:read", "groups:read"}, required: []string{"query"},
			props: []string{"query", "limit", "types", "include_archived", "match_description"}, args: map[string]any{"query": "secret"}, identity: map[string]string{}},
		{tool: "search_emojis", kind: r, scopes: []string{"emoji:read"}, required: nil,
			props: []string{"query", "limit"}, args: map[string]any{"query": "secret"}, identity: map[string]string{}},
		{tool: "read_file", kind: r, scopes: []string{"files:read"}, required: []string{"file"},
			props: []string{"file", "max_bytes", "metadata_only"}, args: map[string]any{"file": "F0FILE0001"}, identity: map[string]string{"file": "F0FILE0001"}},
	})
	if got := toolNamed(t, c, "list_channel_members").OptionalScopes; strings.Join(got, ",") != "im:read,mpim:read" {
		t.Errorf("list_channel_members optional scopes = %v", got)
	}
	if b := toolNamed(t, c, "read_file").Bounds.MaxResultBytes; b < base64.StdEncoding.EncodedLen(slack.MaxReadFileBytes) {
		t.Errorf("read_file MaxResultBytes = %d, too small for %d base64 bytes", b, slack.MaxReadFileBytes)
	}
}

func TestGetReactions(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"reactions.get": {body: "reactions_get_with_user.json"}})
	c, _ := newConnector(t, srv, slack.Options{})
	res, err := c.Call(context.Background(), call("get_reactions", map[string]any{"channel": "C0ENGGEN01", "timestamp": msgTS}))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Channel   string `json:"channel"`
		Timestamp string `json:"timestamp"`
		Reactions []struct {
			Name  string   `json:"name"`
			Count int      `json:"count"`
			Users []string `json:"users"`
		} `json:"reactions"`
	}
	decode(t, res, &got)
	if got.Channel != "C0ENGGEN01" || got.Timestamp != msgTS || len(got.Reactions) != 2 || got.Reactions[0].Name != "tada" ||
		got.Reactions[0].Count != 2 || strings.Join(got.Reactions[0].Users, ",") != "U0CAROL003,U0ALICE001" {
		t.Errorf("content = %+v", got)
	}
	if f := srv.Last(t, "reactions.get").Form; f.Get("channel") != "C0ENGGEN01" || f.Get("timestamp") != msgTS || f.Get("full") != "true" {
		t.Errorf("form = %v", redactForm(f))
	}
	noMarkers(t, res)

	srv2 := newAPIServer(t, map[string]route{"reactions.get": {body: "reactions_get_none.json"}})
	c2, _ := newConnector(t, srv2, slack.Options{})
	res, err = c2.Call(context.Background(), call("get_reactions", map[string]any{"channel": "C0ENGGEN01", "timestamp": msgTS}))
	if err != nil || !res.Empty {
		t.Errorf("no reactions: err %v, empty %v", err, res.Empty)
	}

	srv3 := newAPIServer(t, map[string]route{"reactions.get": {body: "error_message_not_found.json"}})
	c3, _ := newConnector(t, srv3, slack.Options{})
	_, err = c3.Call(context.Background(), call("get_reactions", map[string]any{"channel": "C0ENGGEN01", "timestamp": msgTS}))
	wantClass(t, err, slack.ClassNotFound)

	c4, _ := newConnector(t, newAPIServer(t, nil), slack.Options{})
	_, err = c4.Call(context.Background(), call("get_reactions", map[string]any{"channel": "C0ENGGEN01", "timestamp": "soon"}))
	wantClass(t, err, slack.ClassInvalidArgument)
}

func TestListChannelMembers(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"conversations.members": {body: `{"ok":true,"members":["U0ALICE001","U0BOB00002"],"response_metadata":{"next_cursor":"bmV4dA=="}}`}})
	c, _ := newConnector(t, srv, slack.Options{})
	res, err := c.Call(context.Background(), call("list_channel_members", map[string]any{"channel": "C0ENGGEN01", "limit": 500, "cursor": "abc"}))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Channel    string   `json:"channel"`
		Members    []string `json:"members"`
		NextCursor string   `json:"next_cursor"`
		HasMore    bool     `json:"has_more"`
		Limit      int      `json:"limit"`
	}
	decode(t, res, &got)
	if got.Channel != "C0ENGGEN01" || strings.Join(got.Members, ",") != "U0ALICE001,U0BOB00002" || got.NextCursor != "bmV4dA==" || !got.HasMore || got.Limit != 50 {
		t.Errorf("content = %+v", got)
	}
	if !res.Partial {
		t.Error("a clamped limit is partial")
	}
	if f := srv.Last(t, "conversations.members").Form; f.Get("channel") != "C0ENGGEN01" || f.Get("limit") != "50" || f.Get("cursor") != "abc" {
		t.Errorf("form = %v", redactForm(f))
	}

	srv2 := newAPIServer(t, map[string]route{"conversations.members": {body: "error_channel_not_found.json"}})
	c2, _ := newConnector(t, srv2, slack.Options{})
	_, err = c2.Call(context.Background(), call("list_channel_members", map[string]any{"channel": "C0ENGGEN01"}))
	wantClass(t, err, slack.ClassNotFound)
}

func TestSearchFiles(t *testing.T) {
	body := `{"ok":true,"files":{"total":3,"pagination":{"total_count":3,"page":1,"per_page":2,"page_count":2},"paging":{"count":2,"total":3,"page":1,"pages":2},
		"matches":[{"id":"F0FILE0001","name":"plan.md","title":"Plan","filetype":"markdown","mimetype":"text/markdown","size":120,"user":"U0ALICE001","created":1700000000,"permalink":"https://acme.slack.com/files/U0ALICE001/F0FILE0001/plan.md","channels":["C0ENGGEN01"],"url_private":"https://files.slack.com/files-pri/T0EXAMPLE1-F0FILE0001/plan.md"},
		{"id":"F0FILE0002","name":"chart.png","title":"Chart","filetype":"png","mimetype":"image/png","size":2048,"user":"U0BOB00002","created":1700000100}]}}`
	srv := newAPIServer(t, map[string]route{"search.files": {body: body}})
	c, _ := newConnector(t, srv, slack.Options{})
	res, err := c.Call(context.Background(), call("search_files", map[string]any{"query": "plan in:#eng", "count": 2, "sort": "timestamp"}))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Total   int  `json:"total"`
		Page    int  `json:"page"`
		HasMore bool `json:"has_more"`
		Files   []struct {
			ID, Name, Title, Filetype, Mimetype, User, Created, Permalink string
			Size                                                          int
			Channels                                                      []string
			URLPrivate                                                    string `json:"url_private"`
		} `json:"files"`
	}
	decode(t, res, &got)
	if got.Total != 3 || got.Page != 1 || !got.HasMore || len(got.Files) != 2 || got.Files[0].ID != "F0FILE0001" || got.Files[0].Name != "plan.md" ||
		got.Files[0].Size != 120 || got.Files[0].Created != "2023-11-14T22:13:20Z" || strings.Join(got.Files[0].Channels, ",") != "C0ENGGEN01" {
		t.Errorf("content = %+v", got)
	}
	if got.Files[0].URLPrivate != "" {
		t.Error("private download URLs are not returned: read_file fetches the content")
	}
	if f := srv.Last(t, "search.files").Form; f.Get("query") != "plan in:#eng" || f.Get("count") != "2" || f.Get("sort") != "timestamp" {
		t.Errorf("form = %v", redactForm(f))
	}

	c2, _ := newConnector(t, newAPIServer(t, nil), slack.Options{})
	_, err = c2.Call(context.Background(), call("search_files", map[string]any{"query": "  "}))
	wantClass(t, err, slack.ClassInvalidArgument)
}

const usersPage1 = `{"ok":true,"members":[
	{"id":"U0ALICE001","name":"alice","real_name":"Alice Archer","profile":{"display_name":"ali","real_name":"Alice Archer"}},
	{"id":"U0BOT00001","name":"deploybot","is_bot":true,"profile":{"real_name":"Deploy Bot"}},
	{"id":"U0GONE0001","name":"alicia","deleted":true,"profile":{"real_name":"Alicia Gone"}}],
	"response_metadata":{"next_cursor":"cGFnZTI="}}`

const usersPage2 = `{"ok":true,"members":[
	{"id":"U0BOB00002","name":"bob","real_name":"Bob Baker","profile":{"display_name":"bobby"}},
	{"id":"U0ALI00003","name":"ali.k","real_name":"Ali Khan","profile":{"display_name":""}}],
	"response_metadata":{"next_cursor":""}}`

type userSearch struct {
	Users []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"users"`
	Scanned  int  `json:"scanned"`
	Complete bool `json:"complete"`
}

func TestSearchUsers(t *testing.T) {
	routes := map[string]route{"users.list": {byCursor: map[string]route{"": {body: usersPage1}, "cGFnZTI=": {body: usersPage2}}}}
	srv := newAPIServer(t, routes)
	c, _ := newConnector(t, srv, slack.Options{})
	res, err := c.Call(context.Background(), call("search_users", map[string]any{"query": "ALI"}))
	if err != nil {
		t.Fatal(err)
	}
	var got userSearch
	decode(t, res, &got)
	var ids []string
	for _, u := range got.Users {
		ids = append(ids, u.ID)
	}
	if strings.Join(ids, ",") != "U0ALICE001,U0ALI00003" || got.Scanned != 5 || !got.Complete {
		t.Errorf("content = %+v", got)
	}
	if res.Partial {
		t.Error("a complete scan is not partial")
	}

	srv2 := newAPIServer(t, routes)
	c2, _ := newConnector(t, srv2, slack.Options{})
	res, err = c2.Call(context.Background(), call("search_users", map[string]any{"query": "bot", "include_bots": true, "limit": 1}))
	if err != nil {
		t.Fatal(err)
	}
	decode(t, res, &got)
	if len(got.Users) != 1 || got.Users[0].ID != "U0BOT00001" {
		t.Errorf("bots: %+v", got)
	}
	if srv2.Count("users.list") != 1 {
		t.Errorf("stopped at the limit: users.list called %d times", srv2.Count("users.list"))
	}

	srv3 := newAPIServer(t, routes)
	c3, _ := newConnector(t, srv3, slack.Options{})
	res, _ = c3.Call(context.Background(), call("search_users", map[string]any{"query": "alicia", "include_deactivated": true}))
	decode(t, res, &got)
	if len(got.Users) != 1 || got.Users[0].ID != "U0GONE0001" {
		t.Errorf("deactivated: %+v", got)
	}

	srv4 := newAPIServer(t, routes)
	c4, _ := newConnector(t, srv4, slack.Options{})
	res, _ = c4.Call(context.Background(), call("search_users", map[string]any{"query": "nobody"}))
	if !res.Empty {
		t.Error("no match is empty")
	}
}

func TestSearchUsersIsBounded(t *testing.T) {
	loop := `{"ok":true,"members":[{"id":"U0BOB00002","name":"bob"}],"response_metadata":{"next_cursor":"more"}}`
	srv := newAPIServer(t, map[string]route{"users.list": {byCursor: map[string]route{"": {body: loop}, "more": {body: loop}}}})
	c, _ := newConnector(t, srv, slack.Options{})
	res, err := c.Call(context.Background(), call("search_users", map[string]any{"query": "alice"}))
	if err != nil {
		t.Fatal(err)
	}
	var got userSearch
	decode(t, res, &got)
	if got.Complete || !res.Partial || srv.Count("users.list") != slack.MaxSearchPages {
		t.Errorf("complete %v partial %v pages %d, want %d pages and partial", got.Complete, res.Partial, srv.Count("users.list"), slack.MaxSearchPages)
	}
}

func TestSearchChannels(t *testing.T) {
	page := `{"ok":true,"channels":[
		{"id":"C0ENGGEN01","name":"eng-general","is_channel":true,"is_member":true,"num_members":12,"topic":{"value":"Engineering"},"purpose":{"value":"All eng talk"}},
		{"id":"C0RANDOM01","name":"random","is_channel":true,"purpose":{"value":"engineering memes"}},
		{"id":"C0ENGDEP01","name":"eng-deploys","is_channel":true,"is_archived":true}],
		"response_metadata":{"next_cursor":""}}`
	srv := newAPIServer(t, map[string]route{"conversations.list": {body: page}})
	c, _ := newConnector(t, srv, slack.Options{})
	res, err := c.Call(context.Background(), call("search_channels", map[string]any{"query": "#ENG"}))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Channels []struct {
			ID       string `json:"id"`
			IsMember bool   `json:"is_member"`
		} `json:"channels"`
		Complete bool `json:"complete"`
	}
	decode(t, res, &got)
	if len(got.Channels) != 2 || got.Channels[0].ID != "C0ENGGEN01" || !got.Channels[0].IsMember || got.Channels[1].ID != "C0ENGDEP01" || !got.Complete {
		t.Errorf("content = %+v", got)
	}
	f := srv.Last(t, "conversations.list").Form
	if f.Get("types") != "public_channel,private_channel" || f.Get("exclude_archived") == "true" || f.Get("limit") != "200" {
		t.Errorf("form = %v", redactForm(f))
	}

	srv2 := newAPIServer(t, map[string]route{"conversations.list": {body: page}})
	c2, _ := newConnector(t, srv2, slack.Options{})
	res, _ = c2.Call(context.Background(), call("search_channels", map[string]any{"query": "engineering", "match_description": true, "include_archived": false, "types": "public_channel"}))
	decode(t, res, &got)
	if len(got.Channels) != 2 || got.Channels[0].ID != "C0ENGGEN01" || got.Channels[1].ID != "C0RANDOM01" {
		t.Errorf("description match = %+v", got)
	}
	if f := srv2.Last(t, "conversations.list").Form; f.Get("types") != "public_channel" || f.Get("exclude_archived") != "true" {
		t.Errorf("form = %v", redactForm(f))
	}

	c3, _ := newConnector(t, newAPIServer(t, nil), slack.Options{})
	_, err = c3.Call(context.Background(), call("search_channels", map[string]any{"query": "eng", "types": "im"}))
	wantClass(t, err, slack.ClassInvalidArgument)
}

func TestSearchEmojis(t *testing.T) {
	body := `{"ok":true,"emoji":{"partyparrot":"https://emoji.slack-edge.com/T0EXAMPLE1/partyparrot/abc.gif","parrot":"alias:partyparrot","shipit":"https://emoji.slack-edge.com/T0EXAMPLE1/shipit/def.png"}}`
	srv := newAPIServer(t, map[string]route{"emoji.list": {body: body}})
	c, _ := newConnector(t, srv, slack.Options{})
	res, err := c.Call(context.Background(), call("search_emojis", map[string]any{"query": ":Parrot:"}))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Emojis []struct {
			Name     string `json:"name"`
			URL      string `json:"url"`
			AliasFor string `json:"alias_for"`
		} `json:"emojis"`
		Total int `json:"total"`
	}
	decode(t, res, &got)
	if len(got.Emojis) != 2 || got.Emojis[0].Name != "parrot" || got.Emojis[0].AliasFor != "partyparrot" || got.Emojis[0].URL != "" ||
		got.Emojis[1].Name != "partyparrot" || !strings.HasSuffix(got.Emojis[1].URL, "abc.gif") || got.Total != 2 {
		t.Errorf("content = %+v", got)
	}

	srv2 := newAPIServer(t, map[string]route{"emoji.list": {body: body}})
	c2, _ := newConnector(t, srv2, slack.Options{})
	res, _ = c2.Call(context.Background(), call("search_emojis", map[string]any{"limit": 1}))
	decode(t, res, &got)
	if len(got.Emojis) != 1 || got.Total != 3 || !res.Partial {
		t.Errorf("all, limit 1 = %+v (partial %v)", got, res.Partial)
	}
}

// fileServer answers files.info with a file whose private download URL
// points back at the fixture server.
func fileServer(t *testing.T, mimetype, filetype string, size int, content string) *apiServer {
	t.Helper()
	routes := map[string]route{"files/F0FILE0001/download": {body: content, raw: true}}
	srv := newAPIServer(t, routes)
	routes["files.info"] = route{body: `{"ok":true,"file":{"id":"F0FILE0001","name":"notes.txt","title":"Notes","mimetype":"` + mimetype + `","filetype":"` + filetype +
		`","size":` + strconv.Itoa(size) + `,"user":"U0ALICE001","created":1700000000,"permalink":"https://acme.slack.com/files/U0ALICE001/F0FILE0001/notes.txt",` +
		`"url_private_download":"` + srv.URL + `/api/files/F0FILE0001/download"}}`}
	return srv
}

type readFile struct {
	File struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Mimetype string `json:"mimetype"`
		Size     int    `json:"size"`
	} `json:"file"`
	Content   string `json:"content"`
	Encoding  string `json:"encoding"`
	Truncated bool   `json:"truncated"`
	Omitted   string `json:"omitted"`
}

func TestReadFileText(t *testing.T) {
	srv := fileServer(t, "text/plain", "text", 11, "hello world")
	c, _ := newConnector(t, srv, slack.Options{})
	res, err := c.Call(context.Background(), call("read_file", map[string]any{"file": "F0FILE0001"}))
	if err != nil {
		t.Fatal(err)
	}
	var got readFile
	decode(t, res, &got)
	if got.File.ID != "F0FILE0001" || got.File.Name != "notes.txt" || got.Content != "hello world" || got.Encoding != "text" || got.Truncated {
		t.Errorf("content = %+v", got)
	}
	if f := srv.Last(t, "files.info").Form; f.Get("file") != "F0FILE0001" {
		t.Errorf("form = %v", redactForm(f))
	}
	if h := srv.Last(t, "files/F0FILE0001/download").Header.Get("Authorization"); h != "Bearer "+testToken {
		t.Errorf("download Authorization = %q", h)
	}
	noMarkers(t, res)
}

func TestReadFileBinaryIsBase64(t *testing.T) {
	raw := "\x89PNG\x00\x01\x02"
	srv := fileServer(t, "image/png", "png", len(raw), raw)
	c, _ := newConnector(t, srv, slack.Options{})
	res, err := c.Call(context.Background(), call("read_file", map[string]any{"file": "F0FILE0001"}))
	if err != nil {
		t.Fatal(err)
	}
	var got readFile
	decode(t, res, &got)
	if got.Encoding != "base64" || got.Content != base64.StdEncoding.EncodeToString([]byte(raw)) {
		t.Errorf("content = %+v", got)
	}
}

func TestReadFileBounds(t *testing.T) {
	// Text over max_bytes is cut and marked truncated.
	srv := fileServer(t, "text/plain", "text", 20, "0123456789abcdefghij")
	c, _ := newConnector(t, srv, slack.Options{})
	res, err := c.Call(context.Background(), call("read_file", map[string]any{"file": "F0FILE0001", "max_bytes": 10}))
	if err != nil {
		t.Fatal(err)
	}
	var got readFile
	got = readFile{}
	decode(t, res, &got)
	if got.Content != "0123456789" || !got.Truncated || !res.Partial {
		t.Errorf("text cut: %+v partial %v", got, res.Partial)
	}

	// A binary file over max_bytes is not downloaded at all.
	srv2 := fileServer(t, "image/png", "png", 4096, "unused")
	c2, _ := newConnector(t, srv2, slack.Options{})
	res, err = c2.Call(context.Background(), call("read_file", map[string]any{"file": "F0FILE0001", "max_bytes": 1024}))
	if err != nil {
		t.Fatal(err)
	}
	got = readFile{}
	decode(t, res, &got)
	if got.Content != "" || got.Omitted == "" || srv2.Count("files/F0FILE0001/download") != 0 || !res.Partial {
		t.Errorf("binary too big: %+v, downloads %d", got, srv2.Count("files/F0FILE0001/download"))
	}

	// A file Slack reports as larger than the cap is never fetched.
	srv3 := fileServer(t, "text/plain", "text", slack.MaxReadFileBytes+1, "unused")
	c3, _ := newConnector(t, srv3, slack.Options{})
	res, _ = c3.Call(context.Background(), call("read_file", map[string]any{"file": "F0FILE0001", "max_bytes": slack.MaxReadFileBytes}))
	got = readFile{}
	decode(t, res, &got)
	if srv3.Count("files/F0FILE0001/download") != 1 || !got.Truncated {
		// text is read up to the cap and cut
		t.Errorf("text over the cap: %+v downloads %d", got, srv3.Count("files/F0FILE0001/download"))
	}

	// metadata_only never downloads.
	srv4 := fileServer(t, "text/plain", "text", 11, "hello world")
	c4, _ := newConnector(t, srv4, slack.Options{})
	res, _ = c4.Call(context.Background(), call("read_file", map[string]any{"file": "F0FILE0001", "metadata_only": true}))
	got = readFile{}
	decode(t, res, &got)
	if got.Content != "" || srv4.Count("files/F0FILE0001/download") != 0 || got.File.ID != "F0FILE0001" {
		t.Errorf("metadata only: %+v", got)
	}

	c5, _ := newConnector(t, newAPIServer(t, nil), slack.Options{})
	for name, args := range map[string]map[string]any{
		"no file":       {},
		"bad file":      {"file": "../x"},
		"max too large": {"file": "F0FILE0001", "max_bytes": slack.MaxReadFileBytes + 1},
		"max zero":      {"file": "F0FILE0001", "max_bytes": 0},
	} {
		_, err := c5.Call(context.Background(), call("read_file", args))
		if err == nil {
			t.Errorf("%s: no error", name)
			continue
		}
		wantClass(t, err, slack.ClassInvalidArgument)
	}
}

func TestReadFileRefusesForeignDownloadHost(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"files.info": {body: `{"ok":true,"file":{"id":"F0FILE0001","name":"a.txt","mimetype":"text/plain","size":3,"url_private_download":"https://evil.example.com/a.txt"}}`}})
	c, _ := newConnector(t, srv, slack.Options{})
	res, err := c.Call(context.Background(), call("read_file", map[string]any{"file": "F0FILE0001"}))
	if err != nil {
		t.Fatal(err)
	}
	var got readFile
	decode(t, res, &got)
	if got.Content != "" || got.Omitted == "" {
		t.Errorf("foreign host: %+v; want the content omitted and the token never sent", got)
	}
}

func TestReadFileErrors(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"files.info": {body: `{"ok":false,"error":"file_not_found"}`}})
	c, _ := newConnector(t, srv, slack.Options{})
	_, err := c.Call(context.Background(), call("read_file", map[string]any{"file": "F0FILE0001"}))
	wantClass(t, err, slack.ClassNotFound)

	routes := map[string]route{"files/F0FILE0001/download": {status: 502}}
	srv2 := newAPIServer(t, routes)
	routes["files.info"] = route{body: `{"ok":true,"file":{"id":"F0FILE0001","name":"a.txt","mimetype":"text/plain","size":3,"url_private_download":"` + srv2.URL + `/api/files/F0FILE0001/download"}}`}
	c2, _ := newConnector(t, srv2, slack.Options{})
	res, err := c2.Call(context.Background(), call("read_file", map[string]any{"file": "F0FILE0001"}))
	if err != nil || !res.Unavailable {
		t.Errorf("download 502: err %v unavailable %v", err, res.Unavailable)
	}
}
