package slack_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/slack"
)

const opID = "0f1e2d3c-4b5a-4968-8777-66554433aa11"

// write builds a write call under the ledger operation opID.
func write(tool string, args map[string]any) connectors.Call {
	c := call(tool, args)
	c.OperationID = opID
	return c
}

// --- tool metadata ----------------------------------------------------------

// By default post_message and reply_in_thread declare reconciliation
// none (the ledger makes an unknown outcome unresolved at once) and
// add_reaction reconciles by stable id.
func TestWriteToolsMetadataDefault(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), slack.Options{})
	cases := []struct {
		tool      string
		kind      connectors.ReconcileKind
		scopes    []string
		required  []string
		props     []string
		args      map[string]any
		identity  map[string]string
		resultIDs []string
	}{
		{
			tool: "post_message", kind: connectors.ReconcileNone, scopes: []string{"chat:write"},
			required: []string{"channel", "text"}, props: []string{"channel", "text", "thread_ts"},
			args:     map[string]any{"channel": "#Eng-General", "text": "secret text", "thread_ts": "1700002000.000100"},
			identity: map[string]string{"channel": "eng-general", "channel_name": "eng-general", "thread_ts": "1700002000.000100"},
		},
		{
			tool: "reply_in_thread", kind: connectors.ReconcileNone, scopes: []string{"chat:write"},
			required: []string{"channel", "thread_ts", "text"}, props: []string{"channel", "thread_ts", "text"},
			args:     map[string]any{"channel": "C0ENGGEN01", "thread_ts": "1700002000.000100", "text": "secret text"},
			identity: map[string]string{"channel": "C0ENGGEN01", "channel_id": "C0ENGGEN01", "thread_ts": "1700002000.000100"},
		},
		{
			tool: "add_reaction", kind: connectors.ReconcileStableID, scopes: []string{"reactions:write"},
			required: []string{"channel", "timestamp", "name"}, props: []string{"channel", "timestamp", "name"},
			args:     map[string]any{"channel": "C0ENGGEN01", "timestamp": "1700003000.000200", "name": ":Tada:"},
			identity: map[string]string{"channel": "C0ENGGEN01", "channel_id": "C0ENGGEN01", "timestamp": "1700003000.000200", "reaction": "tada"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			tool := toolNamed(t, c, tc.tool)
			if tool.Kind != connectors.KindWrite {
				t.Errorf("Kind = %q, want write", tool.Kind)
			}
			if tool.Reconcile.Kind != tc.kind {
				t.Errorf("Reconcile.Kind = %q, want %q", tool.Reconcile.Kind, tc.kind)
			}
			if (tool.Reconcile.Check != nil) != (tc.kind != connectors.ReconcileNone) {
				t.Errorf("Reconcile.Check present = %v for kind %q", tool.Reconcile.Check != nil, tc.kind)
			}
			if tool.ResultIDs == nil {
				t.Error("ResultIDs is nil")
			}
			if strings.Join(tool.RequiredScopes, ",") != strings.Join(tc.scopes, ",") {
				t.Errorf("RequiredScopes = %v, want %v", tool.RequiredScopes, tc.scopes)
			}
			if tool.Bounds.MaxPageSize != 0 || tool.Bounds.MaxResultBytes <= 0 {
				t.Errorf("Bounds = %+v", tool.Bounds)
			}
			checkSchema(t, tool, tc.required, tc.props)
			checkIdentity(t, tool, tc.args, tc.identity)
		})
	}
}

// With Options.MarkerReconcile the two message writes reconcile by
// marker and carry a Check; add_reaction is unchanged.
func TestWriteToolsMetadataWithMarker(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), slack.Options{MarkerReconcile: true})
	for _, name := range []string{"post_message", "reply_in_thread"} {
		tool := toolNamed(t, c, name)
		if tool.Reconcile.Kind != connectors.ReconcileMarker || tool.Reconcile.Check == nil {
			t.Errorf("%s: Reconcile = %q check %v, want marker with a Check", name, tool.Reconcile.Kind, tool.Reconcile.Check != nil)
		}
	}
	if tool := toolNamed(t, c, "add_reaction"); tool.Reconcile.Kind != connectors.ReconcileStableID {
		t.Errorf("add_reaction: Reconcile = %q", tool.Reconcile.Kind)
	}
}

// --- shared write behaviour -----------------------------------------------------

func TestWritesRequireAnOperationID(t *testing.T) {
	srv := newAPIServer(t, nil)
	c, tk := newConnector(t, srv, slack.Options{})
	for _, tool := range []string{"post_message", "reply_in_thread", "add_reaction"} {
		_, err := c.Call(context.Background(), call(tool, map[string]any{"channel": "C0ENGGEN01", "text": "t", "thread_ts": "1700002000.000100", "timestamp": "1700002000.000100", "name": "tada"}))
		if !errors.Is(err, slack.ErrMissingOperation) {
			t.Errorf("%s without an operation id: err = %v, want ErrMissingOperation", tool, err)
		}
	}
	if len(srv.Requests()) != 0 || len(tk.calls) != 0 {
		t.Errorf("requests = %d, token calls = %v; want none", len(srv.Requests()), tk.calls)
	}
}

type writeErrorCase struct {
	name    string
	rt      route
	class   string
	unknown bool
	rateLim bool
}

func writeErrorCases() []writeErrorCase {
	return []writeErrorCase{
		{name: "channel_not_found is known", rt: route{body: "error_channel_not_found.json"}, class: slack.ClassNotFound},
		{name: "not_in_channel is known", rt: route{body: "error_not_in_channel.json"}, class: slack.ClassForbidden},
		{name: "missing_scope is known", rt: route{body: "error_missing_scope.json"}, class: slack.ClassForbidden},
		{name: "invalid_auth is known", rt: route{body: "error_invalid_auth.json"}, class: slack.ClassReconnectRequired},
		{name: "429 is known", rt: route{status: 429, body: "{}", headers: map[string]string{"Retry-After": "7"}}, rateLim: true},
		{name: "fatal_error is unknown", rt: route{body: "error_fatal.json"}, unknown: true},
		{name: "500 is unknown", rt: route{status: 500, body: "<html>oops</html>"}, unknown: true},
		{name: "502 is unknown", rt: route{status: 502, body: ""}, unknown: true},
		{name: "timeout is unknown", rt: route{body: "ok.json", delay: 2 * time.Second}, unknown: true},
	}
}

func checkWriteError(t *testing.T, tc writeErrorCase, res connectors.Result, err error) {
	t.Helper()
	switch {
	case tc.unknown:
		if !errors.Is(err, connectors.ErrOutcomeUnknown) {
			t.Fatalf("err = %v (%T), want ErrOutcomeUnknown", err, err)
		}
		if res.Unavailable || res.Content != nil {
			t.Errorf("res = %+v, want an empty result with the error", res)
		}
	case tc.rateLim:
		var rl *connectors.RateLimited
		if !errors.As(err, &rl) || rl.App != "slack" || rl.RetryAfter != 7*time.Second {
			t.Fatalf("err = %v (%T), want *connectors.RateLimited of 7s", err, err)
		}
	default:
		wantClass(t, err, tc.class)
		if errors.Is(err, connectors.ErrOutcomeUnknown) {
			t.Errorf("a Slack answer is a known outcome, got ErrOutcomeUnknown")
		}
	}
	if err != nil && strings.Contains(err.Error(), testToken) {
		t.Errorf("error message leaks the token: %q", err.Error())
	}
}

// --- post_message ---------------------------------------------------------------------

func TestPostMessage(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"chat.postMessage": {body: "chat_post_message.json"}})
	c, tk := newConnector(t, srv, slack.Options{})
	res, err := c.Call(context.Background(), write("post_message", map[string]any{"channel": "C0ENGGEN01", "text": "Deploy starts in 5 minutes"}))
	if err != nil {
		t.Fatalf("post_message: %v", err)
	}
	posted, ok := res.Content.(slack.PostedMessage)
	if !ok || posted.Channel != "C0ENGGEN01" || posted.TS != "1700004000.000100" || posted.ThreadTS != "" {
		t.Errorf("content = %#v", res.Content)
	}
	noMarkers(t, res)
	tool := toolNamed(t, c, "post_message")
	ids := tool.ResultIDs(res)
	if ids["channel"] != "C0ENGGEN01" || ids["ts"] != "1700004000.000100" || len(ids) != 2 {
		t.Errorf("ResultIDs = %v", ids)
	}
	if tool.ResultIDs(connectors.Result{}) != nil {
		t.Error("ResultIDs of an empty result should be nil")
	}
	form := srv.Last(t, "chat.postMessage").Form
	if form.Get("channel") != "C0ENGGEN01" || form.Get("text") != "Deploy starts in 5 minutes" || form.Get("thread_ts") != "" {
		t.Errorf("form = %v", redactForm(form))
	}
	if form.Get("metadata") != "" {
		t.Errorf("metadata %q sent without marker reconciliation", form.Get("metadata"))
	}
	if len(tk.calls) != 1 || tk.calls[0] != alice+"/"+acct {
		t.Errorf("token source calls = %v", tk.calls)
	}
}

func TestPostMessageInThreadByName(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		"users.conversations": {body: "users_conversations_page1.json"},
		"chat.postMessage":    {body: "chat_post_reply.json"},
	})
	c, _ := newConnector(t, srv, slack.Options{})
	res, err := c.Call(context.Background(), write("post_message", map[string]any{"channel": "#eng-general", "text": "On it", "thread_ts": "1700002000.000100"}))
	if err != nil {
		t.Fatalf("post_message: %v", err)
	}
	posted := res.Content.(slack.PostedMessage)
	if posted.Channel != "C0ENGGEN01" || posted.TS != "1700004100.000200" || posted.ThreadTS != "1700002000.000100" {
		t.Errorf("content = %+v", posted)
	}
	ids := toolNamed(t, c, "post_message").ResultIDs(res)
	if ids["thread_ts"] != "1700002000.000100" || len(ids) != 3 {
		t.Errorf("ResultIDs = %v", ids)
	}
	form := srv.Last(t, "chat.postMessage").Form
	if form.Get("channel") != "C0ENGGEN01" || form.Get("thread_ts") != "1700002000.000100" {
		t.Errorf("form = %v, want the resolved id and the thread", redactForm(form))
	}
}

// A name that does not resolve is a known failure before the write:
// nothing is posted.
func TestPostMessageUnknownNameIsNotFound(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"users.conversations": {body: "users_conversations_empty.json"}})
	c, _ := newConnector(t, srv, slack.Options{})
	_, err := c.Call(context.Background(), write("post_message", map[string]any{"channel": "#nope", "text": "hi"}))
	wantClass(t, err, slack.ClassNotFound)
	if errors.Is(err, connectors.ErrOutcomeUnknown) || srv.Count("chat.postMessage") != 0 {
		t.Errorf("err = %v, posts = %d; want a known failure and no post", err, srv.Count("chat.postMessage"))
	}
}

func TestPostMessageWithMarkerAttachesMetadata(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"chat.postMessage": {body: "chat_post_message.json"}})
	c, _ := newConnector(t, srv, slack.Options{MarkerReconcile: true})
	res, err := c.Call(context.Background(), write("post_message", map[string]any{"channel": "C0ENGGEN01", "text": "Deploy starts in 5 minutes"}))
	if err != nil {
		t.Fatal(err)
	}
	form := srv.Last(t, "chat.postMessage").Form
	var meta struct {
		EventType    string            `json:"event_type"`
		EventPayload map[string]string `json:"event_payload"`
	}
	if err := json.Unmarshal([]byte(form.Get("metadata")), &meta); err != nil {
		t.Fatalf("metadata %q: %v", form.Get("metadata"), err)
	}
	if meta.EventType != slack.MarkerEventType || meta.EventPayload["operation_id"] != opID {
		t.Errorf("metadata = %+v, want %s with the operation id", meta, slack.MarkerEventType)
	}
	if form.Get("text") != "Deploy starts in 5 minutes" {
		t.Errorf("text = %q, want it untouched (the marker is metadata, not text)", form.Get("text"))
	}
	if strings.Contains(string(mustJSON(t, res.Content)), opID) {
		t.Error("the operation id leaked into the result")
	}
}

func TestPostMessageValidation(t *testing.T) {
	srv := newAPIServer(t, nil)
	c, _ := newConnector(t, srv, slack.Options{})
	for name, args := range map[string]map[string]any{
		"missing channel": {"text": "hi"},
		"missing text":    {"channel": "C0ENGGEN01"},
		"blank text":      {"channel": "C0ENGGEN01", "text": "  "},
		"bad thread_ts":   {"channel": "C0ENGGEN01", "text": "hi", "thread_ts": "yesterday"},
		"text not string": {"channel": "C0ENGGEN01", "text": 42},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := c.Call(context.Background(), write("post_message", args))
			wantClass(t, err, slack.ClassInvalidArgument)
		})
	}
	if n := len(srv.Requests()); n != 0 {
		t.Errorf("%d requests sent for invalid arguments", n)
	}
}

func TestPostMessageErrors(t *testing.T) {
	for _, tc := range writeErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"chat.postMessage": tc.rt})
			c, _ := newConnector(t, srv, slack.Options{Timeout: 300 * time.Millisecond})
			res, err := c.Call(context.Background(), write("post_message", map[string]any{"channel": "C0ENGGEN01", "text": "hi"}))
			checkWriteError(t, tc, res, err)
		})
	}
}

func TestPostMessageConnectionLostIsUnknown(t *testing.T) {
	srv := newAPIServer(t, nil)
	c, _ := newConnector(t, srv, slack.Options{})
	srv.Close()
	res, err := c.Call(context.Background(), write("post_message", map[string]any{"channel": "C0ENGGEN01", "text": "hi"}))
	if !errors.Is(err, connectors.ErrOutcomeUnknown) || res.Unavailable {
		t.Fatalf("res = %+v err = %v, want ErrOutcomeUnknown (never Unavailable for a write)", res, err)
	}
}

// --- reply_in_thread ---------------------------------------------------------------

func TestReplyInThread(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"chat.postMessage": {body: "chat_post_reply.json"}})
	c, _ := newConnector(t, srv, slack.Options{})
	res, err := c.Call(context.Background(), write("reply_in_thread", map[string]any{"channel": "C0ENGGEN01", "thread_ts": "1700002000.000100", "text": "On it"}))
	if err != nil {
		t.Fatalf("reply_in_thread: %v", err)
	}
	posted := res.Content.(slack.PostedMessage)
	if posted.Channel != "C0ENGGEN01" || posted.TS != "1700004100.000200" || posted.ThreadTS != "1700002000.000100" {
		t.Errorf("content = %+v", posted)
	}
	ids := toolNamed(t, c, "reply_in_thread").ResultIDs(res)
	if ids["ts"] != "1700004100.000200" || ids["thread_ts"] != "1700002000.000100" || ids["channel"] != "C0ENGGEN01" {
		t.Errorf("ResultIDs = %v", ids)
	}
	form := srv.Last(t, "chat.postMessage").Form
	if form.Get("thread_ts") != "1700002000.000100" || form.Get("text") != "On it" {
		t.Errorf("form = %v", redactForm(form))
	}
	for name, args := range map[string]map[string]any{
		"missing thread_ts": {"channel": "C0ENGGEN01", "text": "hi"},
		"missing text":      {"channel": "C0ENGGEN01", "thread_ts": "1700002000.000100"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := c.Call(context.Background(), write("reply_in_thread", args))
			wantClass(t, err, slack.ClassInvalidArgument)
		})
	}
}

func TestReplyInThreadErrors(t *testing.T) {
	for _, tc := range writeErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"chat.postMessage": tc.rt})
			c, _ := newConnector(t, srv, slack.Options{Timeout: 300 * time.Millisecond})
			res, err := c.Call(context.Background(), write("reply_in_thread", map[string]any{"channel": "C0ENGGEN01", "thread_ts": "1700002000.000100", "text": "hi"}))
			checkWriteError(t, tc, res, err)
		})
	}
}

// --- add_reaction -----------------------------------------------------------------

func TestAddReaction(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"reactions.add": {body: "ok.json"}})
	c, _ := newConnector(t, srv, slack.Options{})
	res, err := c.Call(context.Background(), write("add_reaction", map[string]any{"channel": "C0ENGGEN01", "timestamp": "1700003000.000200", "name": ":tada:"}))
	if err != nil {
		t.Fatalf("add_reaction: %v", err)
	}
	added, ok := res.Content.(slack.AddedReaction)
	if !ok || added.Channel != "C0ENGGEN01" || added.Timestamp != "1700003000.000200" || added.Name != "tada" || added.AlreadyReacted {
		t.Errorf("content = %#v", res.Content)
	}
	ids := toolNamed(t, c, "add_reaction").ResultIDs(res)
	if ids["channel"] != "C0ENGGEN01" || ids["timestamp"] != "1700003000.000200" || ids["name"] != "tada" || len(ids) != 3 {
		t.Errorf("ResultIDs = %v", ids)
	}
	form := srv.Last(t, "reactions.add").Form
	if form.Get("channel") != "C0ENGGEN01" || form.Get("timestamp") != "1700003000.000200" || form.Get("name") != "tada" {
		t.Errorf("form = %v", redactForm(form))
	}
}

// already_reacted means the desired state holds (a retry after an
// unknown outcome, or the user reacted by hand): success, flagged.
func TestAddReactionAlreadyReactedIsSuccess(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"reactions.add": {body: "error_already_reacted.json"}})
	c, _ := newConnector(t, srv, slack.Options{})
	res, err := c.Call(context.Background(), write("add_reaction", map[string]any{"channel": "C0ENGGEN01", "timestamp": "1700003000.000200", "name": "tada"}))
	if err != nil {
		t.Fatalf("add_reaction: %v", err)
	}
	if added := res.Content.(slack.AddedReaction); !added.AlreadyReacted || added.Name != "tada" {
		t.Errorf("content = %+v", added)
	}
}

func TestAddReactionValidationAndErrors(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), slack.Options{})
	for name, args := range map[string]map[string]any{
		"missing timestamp": {"channel": "C0ENGGEN01", "name": "tada"},
		"bad timestamp":     {"channel": "C0ENGGEN01", "timestamp": "now", "name": "tada"},
		"missing name":      {"channel": "C0ENGGEN01", "timestamp": "1700003000.000200"},
		"bad name":          {"channel": "C0ENGGEN01", "timestamp": "1700003000.000200", "name": "party parrot!"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := c.Call(context.Background(), write("add_reaction", args))
			wantClass(t, err, slack.ClassInvalidArgument)
		})
	}
	cases := append(writeErrorCases(), writeErrorCase{name: "message_not_found is known", rt: route{body: "error_message_not_found.json"}, class: slack.ClassNotFound})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"reactions.add": tc.rt})
			c, _ := newConnector(t, srv, slack.Options{Timeout: 300 * time.Millisecond})
			res, err := c.Call(context.Background(), write("add_reaction", map[string]any{"channel": "C0ENGGEN01", "timestamp": "1700003000.000200", "name": "tada"}))
			checkWriteError(t, tc, res, err)
		})
	}
}

// --- reconciliation ---------------------------------------------------------------

// reconcile builds the input the ledger's reconciler hands to Check:
// the principal and account, the operation id and the stored resource
// identity; never arguments.
func reconcile(tool string, identity map[string]string) connectors.ReconcileInput {
	return connectors.ReconcileInput{
		Call:             connectors.Call{Principal: connectors.Principal{UserID: alice, TokenID: "tok"}, Tool: "slack." + tool, Account: acct, OperationID: opID},
		OperationID:      opID,
		ResourceIdentity: identity,
	}
}

func wantFound(t *testing.T, res connectors.ReconcileResult, err error, id string) {
	t.Helper()
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if res.Outcome != connectors.ReconcileFound || res.ResourceID != id {
		t.Fatalf("Check = %+v, want found %s", res, id)
	}
}

func wantNotFound(t *testing.T, res connectors.ReconcileResult, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if res.Outcome != connectors.ReconcileNotFound || res.ResourceID != "" {
		t.Fatalf("Check = %+v, want not_found", res)
	}
}

var reactionIdentity = map[string]string{"channel": "C0ENGGEN01", "channel_id": "C0ENGGEN01", "timestamp": "1700003000.000200", "reaction": "tada"}

// add_reaction's check: reactions.get on the message, full user lists;
// the account's own user id (auth.test) must be among the reactors of
// that emoji.
func TestCheckReaction(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{"auth.test": {body: "auth_test_user.json"}, "reactions.get": {body: "reactions_get_with_user.json"}})
		c, _ := newConnector(t, srv, slack.Options{})
		res, err := toolNamed(t, c, "add_reaction").Reconcile.Check(context.Background(), reconcile("add_reaction", reactionIdentity))
		wantFound(t, res, err, "1700003000.000200")
		form := srv.Last(t, "reactions.get").Form
		if form.Get("channel") != "C0ENGGEN01" || form.Get("timestamp") != "1700003000.000200" || form.Get("full") != "true" {
			t.Errorf("form = %v", redactForm(form))
		}
	})
	t.Run("other users reacted, not this one", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{"auth.test": {body: "auth_test_user.json"}, "reactions.get": {body: "reactions_get_without_user.json"}})
		c, _ := newConnector(t, srv, slack.Options{})
		res, err := toolNamed(t, c, "add_reaction").Reconcile.Check(context.Background(), reconcile("add_reaction", reactionIdentity))
		wantNotFound(t, res, err)
	})
	t.Run("no reactions", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{"auth.test": {body: "auth_test_user.json"}, "reactions.get": {body: "reactions_get_none.json"}})
		c, _ := newConnector(t, srv, slack.Options{})
		res, err := toolNamed(t, c, "add_reaction").Reconcile.Check(context.Background(), reconcile("add_reaction", reactionIdentity))
		wantNotFound(t, res, err)
	})
	t.Run("message gone is not_found", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{"auth.test": {body: "auth_test_user.json"}, "reactions.get": {body: "error_message_not_found.json"}})
		c, _ := newConnector(t, srv, slack.Options{})
		res, err := toolNamed(t, c, "add_reaction").Reconcile.Check(context.Background(), reconcile("add_reaction", reactionIdentity))
		wantNotFound(t, res, err)
	})
	t.Run("channel name is resolved", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{
			"auth.test": {body: "auth_test_user.json"}, "users.conversations": {body: "users_conversations_page1.json"},
			"reactions.get": {body: "reactions_get_with_user.json"},
		})
		c, _ := newConnector(t, srv, slack.Options{})
		id := map[string]string{"channel": "eng-general", "channel_name": "eng-general", "timestamp": "1700003000.000200", "reaction": "tada"}
		res, err := toolNamed(t, c, "add_reaction").Reconcile.Check(context.Background(), reconcile("add_reaction", id))
		wantFound(t, res, err, "1700003000.000200")
		if got := srv.Last(t, "reactions.get").Form.Get("channel"); got != "C0ENGGEN01" {
			t.Errorf("reactions.get channel = %q", got)
		}
	})
	t.Run("cannot tell", func(t *testing.T) {
		for name, routes := range map[string]map[string]route{
			"channel_not_found": {"auth.test": {body: "auth_test_user.json"}, "reactions.get": {body: "error_channel_not_found.json"}},
			"5xx":               {"auth.test": {body: "auth_test_user.json"}, "reactions.get": {status: 503, body: ""}},
			"auth fails":        {"auth.test": {body: "error_invalid_auth.json"}},
		} {
			t.Run(name, func(t *testing.T) {
				srv := newAPIServer(t, routes)
				c, _ := newConnector(t, srv, slack.Options{})
				if _, err := toolNamed(t, c, "add_reaction").Reconcile.Check(context.Background(), reconcile("add_reaction", reactionIdentity)); err == nil {
					t.Fatal("Check succeeded, want cannot tell")
				}
			})
		}
	})
	t.Run("needs identity and operation", func(t *testing.T) {
		srv := newAPIServer(t, nil)
		c, _ := newConnector(t, srv, slack.Options{})
		check := toolNamed(t, c, "add_reaction").Reconcile.Check
		for name, in := range map[string]connectors.ReconcileInput{
			"no channel":   reconcile("add_reaction", map[string]string{"timestamp": "1700003000.000200", "reaction": "tada"}),
			"no timestamp": reconcile("add_reaction", map[string]string{"channel": "C0ENGGEN01", "channel_id": "C0ENGGEN01", "reaction": "tada"}),
			"no reaction":  reconcile("add_reaction", map[string]string{"channel": "C0ENGGEN01", "channel_id": "C0ENGGEN01", "timestamp": "1700003000.000200"}),
		} {
			if _, err := check(context.Background(), in); !errors.Is(err, slack.ErrNotReconcilable) {
				t.Errorf("%s: err = %v, want ErrNotReconcilable", name, err)
			}
		}
		in := reconcile("add_reaction", reactionIdentity)
		in.Call.Account = ""
		if _, err := check(context.Background(), in); !errors.Is(err, slack.ErrNotReconcilable) {
			t.Errorf("no account: err = %v", err)
		}
		in = reconcile("add_reaction", reactionIdentity)
		in.OperationID, in.Call.OperationID = "", ""
		if _, err := check(context.Background(), in); !errors.Is(err, slack.ErrNotReconcilable) {
			t.Errorf("no operation: err = %v", err)
		}
		if n := len(srv.Requests()); n != 0 {
			t.Errorf("%d requests for unreconcilable input", n)
		}
	})
}

var postIdentity = map[string]string{"channel": "C0ENGGEN01", "channel_id": "C0ENGGEN01"}

// post_message's marker check (opt-in): the channel history, newest
// first with metadata, bounded by MaxReconcilePages; the message whose
// metadata carries the operation id is found; the end of the history
// without it is not_found; running out of pages is cannot tell.
func TestCheckPostMessageByMarker(t *testing.T) {
	t.Run("found on the second page", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{"conversations.history": {byCursor: map[string]route{
			"":                                     {body: "conversations_history_marker_page1.json"},
			"bmV4dF90czoxNzAwMDA0OTAwLjAwMDEwMA==": {body: "conversations_history_marker_page2.json"},
		}}})
		c, _ := newConnector(t, srv, slack.Options{MarkerReconcile: true})
		res, err := toolNamed(t, c, "post_message").Reconcile.Check(context.Background(), reconcile("post_message", postIdentity))
		wantFound(t, res, err, "1700004000.000100")
		form := srv.Last(t, "conversations.history").Form
		if form.Get("channel") != "C0ENGGEN01" || form.Get("include_all_metadata") != "1" || form.Get("limit") != "200" {
			t.Errorf("form = %v", redactForm(form))
		}
	})
	t.Run("not found at the end of the history", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{"conversations.history": {body: "conversations_history_marker_absent.json"}})
		c, _ := newConnector(t, srv, slack.Options{MarkerReconcile: true})
		res, err := toolNamed(t, c, "post_message").Reconcile.Check(context.Background(), reconcile("post_message", postIdentity))
		wantNotFound(t, res, err)
	})
	t.Run("too many pages is cannot tell", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{"conversations.history": {body: "conversations_history_marker_page1.json"}})
		c, _ := newConnector(t, srv, slack.Options{MarkerReconcile: true})
		_, err := toolNamed(t, c, "post_message").Reconcile.Check(context.Background(), reconcile("post_message", postIdentity))
		if err == nil {
			t.Fatal("Check succeeded after exhausting the pages")
		}
		if n := srv.Count("conversations.history"); n != slack.MaxReconcilePages {
			t.Errorf("walked %d pages, want %d", n, slack.MaxReconcilePages)
		}
	})
	t.Run("listing error is cannot tell", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{"conversations.history": {body: "error_channel_not_found.json"}})
		c, _ := newConnector(t, srv, slack.Options{MarkerReconcile: true})
		if _, err := toolNamed(t, c, "post_message").Reconcile.Check(context.Background(), reconcile("post_message", postIdentity)); err == nil {
			t.Fatal("Check succeeded on a listing error")
		}
	})
	t.Run("thread post is checked in the thread", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{"conversations.replies": {body: "conversations_replies_marker.json"}})
		c, _ := newConnector(t, srv, slack.Options{MarkerReconcile: true})
		id := map[string]string{"channel": "C0ENGGEN01", "channel_id": "C0ENGGEN01", "thread_ts": "1700002000.000100"}
		res, err := toolNamed(t, c, "post_message").Reconcile.Check(context.Background(), reconcile("post_message", id))
		wantFound(t, res, err, "1700004100.000200")
		form := srv.Last(t, "conversations.replies").Form
		if form.Get("ts") != "1700002000.000100" || form.Get("include_all_metadata") != "1" {
			t.Errorf("form = %v", redactForm(form))
		}
		if srv.Count("conversations.history") != 0 {
			t.Error("a thread reply must not scan the channel history")
		}
	})
	t.Run("channel name is resolved", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{"users.conversations": {body: "users_conversations_page1.json"}, "conversations.history": {body: "conversations_history_marker_page2.json"}})
		c, _ := newConnector(t, srv, slack.Options{MarkerReconcile: true})
		res, err := toolNamed(t, c, "post_message").Reconcile.Check(context.Background(), reconcile("post_message", map[string]string{"channel": "eng-general", "channel_name": "eng-general"}))
		wantFound(t, res, err, "1700004000.000100")
	})
	t.Run("needs a channel", func(t *testing.T) {
		c, _ := newConnector(t, newAPIServer(t, nil), slack.Options{MarkerReconcile: true})
		if _, err := toolNamed(t, c, "post_message").Reconcile.Check(context.Background(), reconcile("post_message", map[string]string{})); !errors.Is(err, slack.ErrNotReconcilable) {
			t.Errorf("err = %v, want ErrNotReconcilable", err)
		}
	})
}

func TestCheckReplyInThreadByMarker(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"conversations.replies": {body: "conversations_replies_marker.json"}})
	c, _ := newConnector(t, srv, slack.Options{MarkerReconcile: true})
	id := map[string]string{"channel": "C0ENGGEN01", "channel_id": "C0ENGGEN01", "thread_ts": "1700002000.000100"}
	res, err := toolNamed(t, c, "reply_in_thread").Reconcile.Check(context.Background(), reconcile("reply_in_thread", id))
	wantFound(t, res, err, "1700004100.000200")
	if _, err := toolNamed(t, c, "reply_in_thread").Reconcile.Check(context.Background(), reconcile("reply_in_thread", postIdentity)); !errors.Is(err, slack.ErrNotReconcilable) {
		t.Errorf("without thread_ts: err = %v, want ErrNotReconcilable", err)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
