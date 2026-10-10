package google_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

const (
	listMessagesPath = "GET /gmail/v1/users/me/messages"
	getMessage1Path  = "GET /gmail/v1/users/me/messages/18f1a2b3c4d5e6f7"
	getMessage2Path  = "GET /gmail/v1/users/me/messages/18f1a2b3c4d5e6f8"
	listLabelsPath   = "GET /gmail/v1/users/me/labels"
)

// --- list_labels ---------------------------------------------------------------------

func TestGmailListLabels(t *testing.T) {
	srv := newAPIServer(t, map[string]route{listLabelsPath: {status: 200, body: "labels_list.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("gmail.list_labels", nil))
	if err != nil {
		t.Fatalf("list_labels: %v", err)
	}
	if res.Empty || res.Partial {
		t.Errorf("markers = %+v", res)
	}
	var out google.Labels
	decode(t, res, &out)
	if len(out.Items) != 4 || out.Items[3].ID != "Label_12" || out.Items[3].Name != "Projects/Gateway" || out.Items[3].Type != "user" || out.Items[0].Type != "system" {
		t.Errorf("labels = %+v", out)
	}
	tool := toolOf(t, c, "gmail.list_labels")
	if tool.RequiredScopes[0] != google.ScopeGmailLabels {
		t.Errorf("scopes = %v, want gmail.labels (the non-restricted alternative)", tool.RequiredScopes)
	}
	if got := tool.ResourceIdentity(map[string]any{}); got == nil || len(got) != 0 {
		t.Errorf("identity = %v, want an empty map", got)
	}
}

func TestGmailListLabelsEmptyAndErrors(t *testing.T) {
	srv := newAPIServer(t, map[string]route{listLabelsPath: {status: 200, body: "labels_list_empty.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("gmail.list_labels", nil))
	if err != nil || !res.Empty {
		t.Errorf("res = %+v err = %v, want Empty", res, err)
	}
	for _, tc := range readErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{listLabelsPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := run(t, c, call("gmail.list_labels", nil))
			checkReadError(t, tc, res, err)
		})
	}
}

// --- search ----------------------------------------------------------------------------

func TestGmailSearch(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		listMessagesPath: {status: 200, body: "messages_list.json"},
		getMessage1Path:  {status: 200, body: "message_metadata_1.json"},
		getMessage2Path:  {status: 200, body: "message_metadata_2.json"},
	})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("gmail.search", map[string]any{"q": "from:bob newer_than:7d", "label_ids": []any{"INBOX", "Label_12"}}))
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if res.Empty || res.Partial || res.Unavailable {
		t.Errorf("markers = %+v", res)
	}
	if len(tk.calls) != 1 {
		t.Errorf("token calls = %v, want one for the whole search", tk.calls)
	}
	q := query(t, srv, "/gmail/v1/users/me/messages")
	if q.Get("q") != "from:bob newer_than:7d" || q.Get("maxResults") != "10" || strings.Join(q["labelIds"], ",") != "INBOX,Label_12" || q.Get("includeSpamTrash") == "true" {
		t.Errorf("list query = %v", q)
	}
	mq := query(t, srv, "/gmail/v1/users/me/messages/18f1a2b3c4d5e6f7")
	if mq.Get("format") != "metadata" || len(mq["metadataHeaders"]) < 4 {
		t.Errorf("metadata query = %v", mq)
	}
	var page google.MessagesPage
	decode(t, res, &page)
	if page.Query != "from:bob newer_than:7d" || !page.HasMore || page.NextPageToken != "mail-page-two" || page.ResultSizeEstimate != 27 || len(page.Items) != 2 {
		t.Fatalf("page = %+v", page)
	}
	first := page.Items[0]
	if first.ID != "18f1a2b3c4d5e6f7" || first.ThreadID != "18f1a2b3c4d5e6f0" || first.From != "Bob Example <bob@example.test>" || first.To != "alice@example.test" ||
		first.Subject != "Gateway review" || first.Date != "2026-10-07T17:15:00Z" || first.Snippet != "Hi Alice, the gateway review is on Friday." ||
		!first.Unread || strings.Join(first.Labels, ",") != "INBOX,UNREAD,Label_12" {
		t.Errorf("first = %+v", first)
	}
	if page.Items[1].Unread || page.Items[1].Subject != "Lunch" || page.Items[1].Date != "2026-10-06T18:00:00Z" {
		t.Errorf("second = %+v", page.Items[1])
	}
}

func TestGmailSearchEmptyClampAndTruncate(t *testing.T) {
	srv := newAPIServer(t, map[string]route{listMessagesPath: {status: 200, body: "messages_list_empty.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{MaxPageSize: 5})
	res, err := run(t, c, call("gmail.search", map[string]any{"q": "nothing", "max_results": 50, "page_token": "mail-page-two", "include_spam_trash": true}))
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if !res.Empty || !res.Partial {
		t.Errorf("markers = %+v, want Empty and Partial (clamped)", res)
	}
	q := query(t, srv, "/gmail/v1/users/me/messages")
	if q.Get("maxResults") != "5" || q.Get("pageToken") != "mail-page-two" || q.Get("includeSpamTrash") != "true" {
		t.Errorf("query = %v", q)
	}

	srv2 := newAPIServer(t, map[string]route{
		listMessagesPath: {status: 200, body: "messages_list.json"},
		getMessage1Path:  {status: 200, body: "message_metadata_1.json"},
		getMessage2Path:  {status: 200, body: "message_metadata_2.json"},
	})
	c2, _ := newConnector(t, srv2, connectors.Bounds{MaxResultBytes: 500})
	res, err = run(t, c2, call("gmail.search", map[string]any{"q": "x"}))
	if err != nil {
		t.Fatal(err)
	}
	var page google.MessagesPage
	decode(t, res, &page)
	if !res.Partial || !page.Truncated || len(page.Items) != 1 {
		t.Errorf("res = %+v page = %+v, want truncated to one item", res, page)
	}
}

// A metadata fetch that fails for one message (deleted between the list
// and the get, or a 5xx) keeps the item with its ids and marks the
// result partial; auth and rate-limit failures stop the search.
func TestGmailSearchPartialWhenOneMetadataFetchFails(t *testing.T) {
	for name, rt := range map[string]route{"404": {status: 404, body: "error_not_found.json"}, "500": {status: 500, body: "error_server.json"}} {
		t.Run(name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{
				listMessagesPath: {status: 200, body: "messages_list.json"},
				getMessage1Path:  {status: 200, body: "message_metadata_1.json"},
				getMessage2Path:  rt,
			})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := run(t, c, call("gmail.search", map[string]any{"q": "x"}))
			if err != nil {
				t.Fatalf("search: %v", err)
			}
			var page google.MessagesPage
			decode(t, res, &page)
			if !res.Partial || len(page.Items) != 2 || page.Items[1].ID != "18f1a2b3c4d5e6f8" || page.Items[1].Subject != "" || page.Items[1].Error == "" {
				t.Errorf("res = %+v page = %+v, want partial with the second item id-only and an error note", res, page)
			}
		})
	}
	for name, rt := range map[string]route{"401": {status: 401, body: "error_unauthorized.json"}, "429": {status: 429, body: "error_rate_limit_429.json"}} {
		t.Run(name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{
				listMessagesPath: {status: 200, body: "messages_list.json"},
				getMessage1Path:  rt,
				getMessage2Path:  {status: 200, body: "message_metadata_2.json"},
			})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			if _, err := run(t, c, call("gmail.search", map[string]any{"q": "x"})); err == nil {
				t.Fatal("want the auth / rate-limit error to stop the search")
			}
			if srv.Count(getMessage2Path) != 0 {
				t.Errorf("the search went on after a %s", name)
			}
		})
	}
}

func TestGmailSearchArgumentsAndErrors(t *testing.T) {
	c, tk := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	for name, args := range map[string]map[string]any{
		"missing q":     {},
		"blank q":       {"q": "  "},
		"bad label_ids": {"q": "x", "label_ids": []any{1}},
		"max_results 0": {"q": "x", "max_results": 0},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := run(t, c, call("gmail.search", args))
			wantClass(t, err, google.ClassInvalidArgument, 0)
		})
	}
	if len(tk.calls) != 0 {
		t.Errorf("token calls for invalid arguments = %d", len(tk.calls))
	}
	for _, tc := range readErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{listMessagesPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := run(t, c, call("gmail.search", map[string]any{"q": "x"}))
			checkReadError(t, tc, res, err)
		})
	}
}

// --- get_message ---------------------------------------------------------------------

func TestGmailGetMessage(t *testing.T) {
	srv := newAPIServer(t, map[string]route{getMessage1Path: {status: 200, body: "message_full.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("gmail.get_message", map[string]any{"id": "18f1a2b3c4d5e6f7"}))
	if err != nil {
		t.Fatalf("get_message: %v", err)
	}
	if res.Partial || res.Empty {
		t.Errorf("markers = %+v", res)
	}
	if got := query(t, srv, "/gmail/v1/users/me/messages/18f1a2b3c4d5e6f7").Get("format"); got != "full" {
		t.Errorf("format = %q, want full", got)
	}
	var msg google.Message
	decode(t, res, &msg)
	if msg.ID != "18f1a2b3c4d5e6f7" || msg.ThreadID != "18f1a2b3c4d5e6f0" || msg.From != "Bob Example <bob@example.test>" || msg.To != "alice@example.test" ||
		msg.Cc != "carol@example.test" || msg.Subject != "Gateway review" || msg.Date != "2026-10-07T17:15:00Z" || msg.MessageID != "<abc123@example.test>" ||
		msg.InReplyTo != "<prev@example.test>" || !msg.Unread || strings.Join(msg.Labels, ",") != "INBOX,UNREAD,Label_12" {
		t.Errorf("message = %+v", msg)
	}
	if msg.BodyType != "text/plain" || msg.Body != "Hi Alice,\n\nThe gateway review is on Friday at 10.\n\nBob" || msg.BodyTruncated {
		t.Errorf("body = %q (%s, truncated %v)", msg.Body, msg.BodyType, msg.BodyTruncated)
	}
	if len(msg.Attachments) != 1 || msg.Attachments[0].Filename != "agenda.pdf" || msg.Attachments[0].MimeType != "application/pdf" || msg.Attachments[0].Size != 18234 || msg.Attachments[0].ID != "ANGjdJ8example" {
		t.Errorf("attachments = %+v (listed, never fetched)", msg.Attachments)
	}
	if srv.Count("GET /gmail/v1/users/me/messages/18f1a2b3c4d5e6f7/attachments/ANGjdJ8example") != 0 {
		t.Error("an attachment was fetched")
	}
}

func TestGmailGetMessageHTMLOnlyAndTruncation(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /gmail/v1/users/me/messages/18f1a2b3c4d5e6f9": {status: 200, body: "message_full_html_only.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("gmail.get_message", map[string]any{"id": "18f1a2b3c4d5e6f9"}))
	if err != nil {
		t.Fatal(err)
	}
	var msg google.Message
	decode(t, res, &msg)
	if msg.BodyType != "text/html" || !strings.Contains(msg.Body, "<b>Friday</b>") {
		t.Errorf("html-only message = %+v", msg)
	}

	srv2 := newAPIServer(t, map[string]route{getMessage1Path: {status: 200, body: "message_full.json"}})
	c2, _ := newConnector(t, srv2, connectors.Bounds{MaxResultBytes: 620})
	res, err = run(t, c2, call("gmail.get_message", map[string]any{"id": "18f1a2b3c4d5e6f7"}))
	if err != nil {
		t.Fatal(err)
	}
	var cut google.Message
	decode(t, res, &cut)
	if !res.Partial || !cut.BodyTruncated || strings.Contains(cut.Body, "Bob") || cut.Subject != "Gateway review" || len(cut.Attachments) != 1 {
		t.Errorf("res = %+v msg = %+v, want a cut body and everything else kept", res, cut)
	}
	if b, _ := json.Marshal(res.Content); len(b) > 620 {
		t.Errorf("result is %d bytes, over the bound", len(b))
	}
}

func TestGmailGetMessageArgumentsAndErrors(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	for name, args := range map[string]map[string]any{"missing id": {}, "id slash": {"id": "a/b"}} {
		t.Run(name, func(t *testing.T) {
			_, err := run(t, c, call("gmail.get_message", args))
			wantClass(t, err, google.ClassInvalidArgument, 0)
		})
	}
	for _, tc := range readErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{getMessage1Path: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := run(t, c, call("gmail.get_message", map[string]any{"id": "18f1a2b3c4d5e6f7"}))
			checkReadError(t, tc, res, err)
		})
	}
}

func TestGmailReadIdentityAndScopes(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	search := toolOf(t, c, "gmail.search")
	if got := search.ResourceIdentity(map[string]any{"q": "secret", "label_ids": []any{"INBOX", "Label_12"}}); got["label"] != "INBOX,Label_12" || len(got) != 1 {
		t.Errorf("search identity = %v, want label only (never q)", got)
	}
	if got := search.ResourceIdentity(map[string]any{"q": "secret"}); len(got) != 0 {
		t.Errorf("search identity without labels = %v, want empty", got)
	}
	get := toolOf(t, c, "gmail.get_message")
	if got := get.ResourceIdentity(map[string]any{"id": "m1"}); got["message_id"] != "m1" {
		t.Errorf("get identity = %v", got)
	}
	if search.RequiredScopes[0] != google.ScopeGmailReadonly || get.RequiredScopes[0] != google.ScopeGmailReadonly {
		t.Errorf("scopes = %v / %v", search.RequiredScopes, get.RequiredScopes)
	}
}

// Acceptance: an account that declined the Gmail scope (granular consent)
// keeps its Calendar tools and is blocked on every Gmail tool before any
// request is sent.
func TestDeclinedGmailScopeBlocksGmailToolsWhileCalendarWorks(t *testing.T) {
	srv := newAPIServer(t, map[string]route{listEventsPath: {status: 200, body: "events_list.json"}})
	accounts := connectors.NewStaticAccountSource()
	for _, app := range google.Apps {
		accounts.Add(alice, connectors.Account{
			ID: acct, App: app, Label: connectors.LabelCompany, DisplayName: "alice@example.test",
			Scopes: []string{"openid", "https://www.googleapis.com/auth/userinfo.email", google.ScopeCalendarEvents, google.ScopeTasks},
		})
	}
	c, err := google.New(google.Options{Tokens: (&tokens{}).source, BaseURL: srv.URL + "/", Accounts: accounts})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, c, call("calendar.list_events", nil)); err != nil {
		t.Fatalf("calendar.list_events: %v", err)
	}
	for _, name := range []string{"gmail.search", "gmail.get_message", "gmail.list_labels"} {
		_, err := run(t, c, call(name, map[string]any{"q": "x", "id": "m1"}))
		wantClass(t, err, google.ClassScopeRequired, 0)
	}
	if n := len(srv.Requests()); n != 1 {
		t.Errorf("requests = %d, want only the calendar listing", n)
	}
}
