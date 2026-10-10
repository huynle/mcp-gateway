//go:build integration || e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/slack"
	"github.com/huynle/mcp-gateway/internal/jobs"
	"github.com/huynle/mcp-gateway/internal/ledger"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/store"
)

// The Slack world: the real Slack connector (writes behind the whole
// safety core) against stubSlackAPI, an httptest stand-in for the two
// Web API methods post_message uses (users.conversations to resolve a
// channel name, chat.postMessage). alice's company Slack connection is
// the one newWorld seeds for the approval DMs (TACME:UALICE); its token
// comes from a static token source (the stub checks the form token),
// so the world needs no OAuth flow. The approval notifier keeps using
// the world's own fake Slack with the bot token.

const (
	slackUserToken = "xoxp-e2e-stub-user-token-7b2d"
	slackTimeout   = 1500 * time.Millisecond
)

// stubSlackAPI serves users.conversations and chat.postMessage; hang
// makes the next post never answer (and apply nothing).
type stubSlackAPI struct {
	srv   *httptest.Server
	mu    sync.Mutex
	posts []map[string]string
	hang  bool
	hangs int
}

func newStubSlackAPI(t *testing.T) *stubSlackAPI {
	t.Helper()
	s := &stubSlackAPI{}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *stubSlackAPI) URL() string { return s.srv.URL + "/api/" }

func (s *stubSlackAPI) setHang(hang bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hang = hang
}

func (s *stubSlackAPI) list() []map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]map[string]string(nil), s.posts...)
}

func (s *stubSlackAPI) serve(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.PostForm.Get("token") != slackUserToken {
		_, _ = w.Write([]byte(`{"ok":false,"error":"invalid_auth"}`))
		return
	}
	switch strings.TrimPrefix(r.URL.Path, "/api/") {
	case "users.conversations":
		_, _ = w.Write([]byte(`{"ok":true,"channels":[
			{"id":"C0ENGDEP01","name":"eng-deploys","name_normalized":"eng-deploys","is_channel":true,"is_member":true},
			{"id":"C0RANDOM01","name":"random","name_normalized":"random","is_channel":true,"is_member":true}
		],"response_metadata":{"next_cursor":""}}`))
	case "chat.postMessage":
		form := map[string]string{}
		for k := range r.PostForm {
			if k != "token" {
				form[k] = r.PostForm.Get(k)
			}
		}
		s.mu.Lock()
		hang := s.hang
		s.hang = false
		if hang {
			s.hangs++
		} else {
			s.posts = append(s.posts, form)
		}
		n := len(s.posts)
		s.mu.Unlock()
		if hang {
			<-r.Context().Done()
			return
		}
		_, _ = fmt.Fprintf(w, `{"ok":true,"channel":%q,"ts":"17000040%02d.000100"}`, form["channel"], n)
	default:
		_, _ = w.Write([]byte(`{"ok":false,"error":"unknown_method"}`))
	}
}

// slackWorld is a world with the Slack connector registered against the
// stub and the member role granting slack.post_message only to #eng-*
// channels (confirm), nothing elsewhere (so #random is denied).
type slackWorld struct {
	*world
	stub *stubSlackAPI
}

func newSlackWorld(t *testing.T) *slackWorld {
	t.Helper()
	stub := newStubSlackAPI(t)
	sw := &slackWorld{stub: stub}
	w := newWorld(t, options{register: func(reg *connectors.Registry) error {
		c, err := slack.New(slack.Options{
			Tokens: func(context.Context, string, string) oauth2.TokenSource {
				return oauth2.StaticTokenSource(&oauth2.Token{AccessToken: slackUserToken})
			},
			BaseURL: stub.URL(), Timeout: slackTimeout,
		})
		if err != nil {
			return err
		}
		return connectors.RegisterConnector(reg, c, sw.accounts())
	}})
	sw.world = w
	w.forbid(slackUserToken, "slack user token")
	sw.saveSlackRules()
	return sw
}

func (sw *slackWorld) accounts() connectors.AccountSource {
	return accountSourceFunc(func(ctx context.Context, userID, app string) ([]connectors.Account, error) {
		return sw.conn.ListAccounts(ctx, userID, app)
	})
}

// saveSlackRules adds the Slack rules to the member role: post only to
// #eng-* (confirm), list channels and accounts freely.
func (sw *slackWorld) saveSlackRules() {
	sw.t.Helper()
	ctx := sw.t.Context()
	member, err := sw.policy.Role(ctx, roleMember)
	if err != nil {
		sw.t.Fatal(err)
	}
	member.Rules = append(member.Rules,
		policy.ToolRule{App: slack.App, Tool: slack.ToolPostMessage, Outcome: policy.OutcomeConfirm, Conditions: []policy.Condition{{Key: "channel", Op: policy.OpPrefix, Value: "eng-"}}},
		policy.ToolRule{App: slack.App, Tool: slack.ToolListChannels, Outcome: policy.OutcomeAllow},
		policy.ToolRule{App: slack.App, Tool: connectors.ListAccountsName, Outcome: policy.OutcomeAllow},
	)
	if err := sw.policy.SaveRole(ctx, sw.admin.id, member); err != nil {
		sw.t.Fatalf("SaveRole member: %v", err)
	}
	sw.policy.Invalidate()
}

// postArgs builds post_message arguments; the text is content that must
// never reach the logs or audit rows.
func (sw *slackWorld) postArgs(channel, text string) map[string]any {
	sw.forbid(text, "message text")
	return map[string]any{"channel": channel, "text": text}
}

// TestE2ESlackPostOnlyToEngChannels: the role rule "post only to
// #eng-*" works on the channel name of the resource identity. A post to
// #eng-deploys needs an approval; the approved retry resolves the name
// to its id and posts, the ledger stores the result ids and the identity
// carries the channel name; a post to #random is denied before the
// connector runs, by name and by id alike (the id is resolved to its
// name before policy decides); the id of #eng-deploys needs the same
// approval as the name, and an id the account cannot see is denied
// (identity_unresolved).
func TestE2ESlackPostOnlyToEngChannels(t *testing.T) {
	sw := newSlackWorld(t)
	alice := sw.client(sw.alice)

	tools := toolNames(t, alice)
	if !contains(tools, "slack.post_message") || !contains(tools, "slack.list_channels") || !contains(tools, "slack.list_accounts") {
		t.Fatalf("tools/list = %v", tools)
	}
	if contains(tools, "slack.add_reaction") {
		t.Errorf("tools/list shows an ungranted tool: %v", tools)
	}

	args := sw.postArgs("#eng-deploys", "Deploy of widgets 2.3.1 starts in 5 minutes")
	_, err := sw.call(alice, "slack.post_message", args)
	id := approvalRequired(t, err)
	if n := len(sw.stub.list()); n != 0 {
		t.Fatalf("stub has %d posts before the approval", n)
	}
	if code, _ := sw.post(sw.alice, "/approvals/"+id+"/approve", true); code != 303 {
		t.Fatalf("approve = %d, want 303", code)
	}
	res, err := sw.call(alice, "slack.post_message", map[string]any{"channel": "#eng-deploys", "text": "drifted", "approval_id": id})
	if err != nil || res.IsError {
		t.Fatalf("approved retry: err=%v res=%+v", err, res)
	}
	var posted struct {
		Channel string `json:"channel"`
		TS      string `json:"ts"`
	}
	if err := json.Unmarshal([]byte(text(t, res)), &posted); err != nil {
		t.Fatalf("result %q: %v", text(t, res), err)
	}
	if posted.Channel != "C0ENGDEP01" || posted.TS == "" {
		t.Errorf("result = %+v", posted)
	}
	op := sw.opFor(sw.alice, "slack.post_message", store.LedgerSucceeded)
	if op == nil || op.ApprovalID == nil || *op.ApprovalID != id {
		t.Fatalf("ledger op = %s", describe(op))
	}
	if ids := resultIDs(t, op); ids["channel"] != "C0ENGDEP01" || ids["ts"] != posted.TS {
		t.Errorf("stored result ids = %v", ids)
	}
	if rid := resource(t, op); rid["channel"] != "eng-deploys" || rid["channel_name"] != "eng-deploys" {
		t.Errorf("resource identity = %v", rid)
	}
	posts := sw.stub.list()
	if len(posts) != 1 || posts[0]["channel"] != "C0ENGDEP01" || posts[0]["text"] != args["text"] {
		t.Errorf("stub posts = %+v, want one to C0ENGDEP01 with the approved text", posts)
	}
	if _, ok := posts[0]["metadata"]; ok {
		t.Errorf("metadata sent without marker reconciliation: %v", posts[0])
	}

	// #random by name, by id and by mention, and an id that is not among
	// the account's conversations: denied by policy, the connector never
	// called.
	for _, channel := range []string{"#random", "C0RANDOM01", "<#C0RANDOM01|eng-deploys>", "C0NOWHERE1"} {
		_, err = sw.call(alice, "slack.post_message", sw.postArgs(channel, "This text must never be posted to "+channel))
		if je := rpcError(t, err, mcp.CodeDenied); !strings.Contains(je.Message, "denied") {
			t.Errorf("deny %s = %q", channel, je.Message)
		}
	}
	if n := len(sw.stub.list()); n != 1 {
		t.Errorf("stub posts = %d after denied writes, want still 1", n)
	}
	var denied, unresolved int
	for _, ev := range sw.events(sw.alice) {
		if ev.Tool != "slack.post_message" || ev.Decision != "deny" {
			continue
		}
		denied++
		switch ev.ErrorClass {
		case "identity_unresolved":
			unresolved++
			if ev.ResourceIdentity["channel_id"] != "C0NOWHERE1" || ev.Outcome != "denied" {
				t.Errorf("identity_unresolved audit row = %+v", ev)
			}
		case "denied":
			if ev.ResourceIdentity["channel"] != "random" {
				t.Errorf("denied audit row does not name #random: %+v", ev)
			}
		default:
			t.Errorf("unexpected deny class %q: %+v", ev.ErrorClass, ev)
		}
	}
	if denied != 4 || unresolved != 1 {
		t.Errorf("audit deny events = %d (identity_unresolved %d), want 4 (1)", denied, unresolved)
	}

	// The id of #eng-deploys gets the name's outcome: an approval is
	// required and nothing is posted until it is granted.
	_, err = sw.call(alice, "slack.post_message", sw.postArgs("C0ENGDEP01", "By id"))
	if id := approvalRequired(t, err); id == "" {
		t.Fatal("post by id: no approval required")
	}
	if n := len(sw.stub.list()); n != 1 {
		t.Errorf("stub posts = %d after the post by id, want still 1 (awaiting approval)", n)
	}
}

// TestE2ESlackUnknownOutcomeUnresolved: post_message declares
// reconciliation none, so when Slack never answers the ledger marks the
// operation unknown, a duplicate is blocked, and the reconciler turns it
// unresolved at once (not_reconcilable), notifies the user and lifts the
// block: a deliberate retry is a new operation that posts.
func TestE2ESlackUnknownOutcomeUnresolved(t *testing.T) {
	sw := newSlackWorld(t)
	alice := sw.client(sw.alice)
	args := sw.postArgs("#eng-deploys", "Lost answer: did this post?")

	// Approve once; the approved retry is the one that hangs.
	_, err := sw.call(alice, "slack.post_message", args)
	id := approvalRequired(t, err)
	if code, _ := sw.post(sw.alice, "/approvals/"+id+"/approve", true); code != 303 {
		t.Fatalf("approve = %d, want 303", code)
	}
	sw.stub.setHang(true)
	retry := map[string]any{"channel": "#eng-deploys", "text": "drifted", "approval_id": id}
	res, err := sw.call(alice, "slack.post_message", retry)
	if err != nil || !res.IsError || !strings.Contains(text(t, res), "outcome unknown") {
		t.Fatalf("unknown write: err=%v res=%+v", err, res)
	}
	op := sw.opFor(sw.alice, "slack.post_message", store.LedgerUnknown)
	if op == nil {
		t.Fatalf("no unknown op: %+v", sw.ops(sw.alice))
	}
	// Meanwhile the consumed approval cannot run the write again (an
	// approval executes at most once; decision dovthftx).
	_, err = sw.call(alice, "slack.post_message", retry)
	if je := rpcError(t, err, mcp.CodeDenied); !strings.Contains(je.Message, "approval already used") {
		t.Errorf("duplicate with the consumed approval = %q", je.Message)
	}

	sw.runJobs(jobs.NewReconcilerJob(sw.ledger, 100*time.Millisecond))
	sw.eventually("post_message unresolved", 10*time.Second, func() bool { return sw.op(op.ID).State == store.LedgerUnresolved })
	row := sw.op(op.ID)
	if errorCode(row) != ledger.ClassNotReconcilable || len(resultIDs(t, row)) != 0 || row.FinishedAt == nil {
		t.Errorf("unresolved row = %s", describe(row))
	}
	sw.eventually("user notified", 5*time.Second, func() bool { return len(sw.notifier.list()) == 1 })
	if n := sw.notifier.list(); len(n) != 1 || n[0].ID != op.ID {
		t.Errorf("notifications = %+v, want one for %s", n, op.ID)
	}
	var unresolved int
	for _, ev := range sw.events(sw.alice) {
		if ev.OperationID == op.ID && ev.Outcome == "unresolved" {
			unresolved++
		}
	}
	if unresolved != 1 {
		t.Errorf("audit unresolved events = %d, want 1", unresolved)
	}
	if code, body := sw.get(sw.alice, "/operations"); code != 200 || !strings.Contains(body, "slack.post_message") || !strings.Contains(body, "unresolved") {
		t.Errorf("GET /operations = %d", code)
	}

	// The block is lifted: a new approval and retry post for real.
	_, err = sw.call(alice, "slack.post_message", args)
	id2 := approvalRequired(t, err)
	if id2 == id {
		t.Fatalf("the consumed approval was reused")
	}
	if code, _ := sw.post(sw.alice, "/approvals/"+id2+"/approve", true); code != 303 {
		t.Fatalf("approve = %d, want 303", code)
	}
	res, err = sw.call(alice, "slack.post_message", map[string]any{"channel": "#eng-deploys", "text": "drifted", "approval_id": id2})
	if err != nil || res.IsError {
		t.Fatalf("retry after unresolved: err=%v res=%+v", err, res)
	}
	second := sw.opFor(sw.alice, "slack.post_message", store.LedgerSucceeded)
	if second == nil || second.ID == op.ID {
		t.Fatalf("retry op = %s", describe(second))
	}
	if posts := sw.stub.list(); len(posts) != 1 || posts[0]["text"] != args["text"] {
		t.Errorf("stub posts = %+v, want exactly the retry's post", posts)
	}
}
