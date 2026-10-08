package approvals_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/approvals"
	"github.com/huynle/mcp-gateway/internal/approvals/approvalstest"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/observability"
)

var updateGolden = flag.Bool("update", false, "rewrite the golden files under testdata")

// fakeSlack is an httptest stand-in for the Slack Web API methods the
// notifier and the interactions endpoint call: conversations.open,
// chat.postMessage and chat.update. It records every call.
type fakeSlack struct {
	srv *httptest.Server
	mu  sync.Mutex
	// calls are the method names in order.
	calls []string
	// posts are the chat.postMessage form values; updates the chat.update ones.
	posts, updates []map[string]string
	tokens         []string
	// fail makes the named method answer {"ok":false,"error":fail[method]}.
	fail map[string]string
	// hang delays every call (tests the timeout).
	hang time.Duration
}

func newFakeSlack(t *testing.T) *fakeSlack {
	t.Helper()
	f := &fakeSlack{fail: map[string]string{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

// URL is the API base the slack client is pointed at (trailing slash,
// like slack.APIURL).
func (f *fakeSlack) URL() string { return f.srv.URL + "/api/" }

func (f *fakeSlack) serve(w http.ResponseWriter, r *http.Request) {
	method := strings.TrimPrefix(r.URL.Path, "/api/")
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	form := map[string]string{}
	for k := range r.PostForm {
		form[k] = r.PostForm.Get(k)
	}
	f.mu.Lock()
	f.calls = append(f.calls, method)
	f.tokens = append(f.tokens, form["token"])
	hang, failMsg := f.hang, f.fail[method]
	switch method {
	case "chat.postMessage":
		f.posts = append(f.posts, form)
	case "chat.update":
		f.updates = append(f.updates, form)
	}
	f.mu.Unlock()
	if hang > 0 {
		select {
		case <-time.After(hang):
		case <-r.Context().Done():
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if failMsg != "" {
		_, _ = w.Write([]byte(`{"ok":false,"error":"` + failMsg + `"}`))
		return
	}
	switch method {
	case "conversations.open":
		_, _ = w.Write([]byte(`{"ok":true,"channel":{"id":"D-` + form["users"] + `"}}`))
	case "chat.postMessage":
		_, _ = w.Write([]byte(`{"ok":true,"channel":"` + form["channel"] + `","ts":"1700000000.000100"}`))
	case "chat.update":
		_, _ = w.Write([]byte(`{"ok":true,"channel":"` + form["channel"] + `","ts":"` + form["ts"] + `"}`))
	default:
		_, _ = w.Write([]byte(`{"ok":false,"error":"unknown_method"}`))
	}
}

func (f *fakeSlack) methods() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeSlack) lastPost() map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.posts) == 0 {
		return nil
	}
	return f.posts[len(f.posts)-1]
}

// fakeDirectory is a SlackIdentitySource and SlackSecretSource over maps.
type fakeDirectory struct {
	mu      sync.Mutex
	users   map[string][2]string // gateway user -> {slack user, team}
	secrets map[string]string
	err     error
}

func (d *fakeDirectory) SlackIdentity(_ context.Context, userID string) (string, string, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.err != nil {
		return "", "", false, d.err
	}
	id, ok := d.users[userID]
	return id[0], id[1], ok, nil
}

func (d *fakeDirectory) VendorSecrets(_ context.Context, vendor, _ string, keys ...string) (map[string]string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if vendor != "slack" {
		return nil, errors.New("wrong vendor " + vendor)
	}
	out := map[string]string{}
	for _, k := range keys {
		if v := d.secrets[k]; v != "" {
			out[k] = v
		}
	}
	return out, nil
}

type slackFixture struct {
	*fixture
	slack *fakeSlack
	dir   *fakeDirectory
	n     *approvals.SlackNotifier
	logs  *bytes.Buffer
}

// newSlackFixture wires the notifier into a fresh service so Create
// drives it, the way cmd/gateway does.
func newSlackFixture(t *testing.T) *slackFixture {
	t.Helper()
	keys, err := crypto.NewStaticProvider("k1", map[string][]byte{"k1": bytes.Repeat([]byte{7}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	fs := newFakeSlack(t)
	dir := &fakeDirectory{
		users:   map[string][2]string{alice: {"UALICE", "TACME"}},
		secrets: map[string]string{"bot_token": "xoxb-test-token", "signing_secret": "sign-test"},
	}
	logs := &bytes.Buffer{}
	n, err := approvals.NewSlackNotifier(approvals.SlackNotifierOptions{
		Identity: dir, Secrets: dir, APIURL: fs.URL(), PortalURL: "https://gw.example.com/approvals", Timeout: 2 * time.Second,
		Log: slog.New(slog.NewTextHandler(logs, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{st: approvalstest.NewMemStore(), audit: &recordingAudit{}, notifier: &recordingNotifier{}, metrics: observability.NewMetrics(), now: time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)}
	f.st.Accounts[acctA] = [2]string{"company", "Alice at work"}
	svc, err := approvals.New(approvals.Config{TTL: 15 * time.Minute, Wait: 30 * time.Second, BaseURL: "https://gw.example.com"}, f.st, keys, approvals.Options{
		Audit: f.audit, Metrics: f.metrics, Notifier: approvals.MultiNotifier{approvals.PortalNotifier{}, n, f.notifier}, Log: slog.New(slog.NewTextHandler(logs, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetClock(f.clock)
	f.svc = svc
	n.SetArguments(svc)
	return &slackFixture{fixture: f, slack: fs, dir: dir, n: n, logs: logs}
}

func (f *slackFixture) createFor(t *testing.T, user, acct string) *approvals.Approval {
	t.Helper()
	a, err := f.svc.Create(t.Context(), approvals.Request{
		UserID: user, TokenID: "tok-1", AccountID: acct, AccountLabel: "company", Tool: "fake.create_item",
		Args:             map[string]any{"id": "it-1", "name": "first", "body": strings.Repeat("long body ", 40), "tags": []any{"a", "b"}, "count": float64(3)},
		ResourceIdentity: map[string]string{"id": "it-1", "repo": "acme/widgets"}, PolicyVersionID: policyV1,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return a
}

func TestSlackNotifierDMsTheConnectedCompanySlackUser(t *testing.T) {
	f := newSlackFixture(t)
	a := f.createFor(t, alice, acctA)
	if got := strings.Join(f.slack.methods(), ","); got != "conversations.open,chat.postMessage" {
		t.Fatalf("slack calls = %s", got)
	}
	post := f.slack.lastPost()
	if post["channel"] != "D-UALICE" || post["token"] != "xoxb-test-token" {
		t.Errorf("post = %v", post)
	}
	if !strings.Contains(post["text"], "fake.create_item") {
		t.Errorf("fallback text = %q", post["text"])
	}
	// The blocks carry tool, account, resource, argument summary, expiry
	// and the two buttons whose value is the approval id.
	blocks := post["blocks"]
	for _, want := range []string{"fake.create_item", "company", "Alice at work", "acme/widgets", "it-1", "long body", "tags", `[\"a\",\"b\"]`, `"action_id":"approve"`, `"action_id":"deny"`, `"value":"` + a.ID + `"`, "https://gw.example.com/approvals"} {
		if !strings.Contains(blocks, want) {
			t.Errorf("blocks lack %q:\n%s", want, blocks)
		}
	}
	if strings.Contains(f.logs.String(), "xoxb-test-token") {
		t.Errorf("bot token in logs:\n%s", f.logs.String())
	}
	// The other notifiers still ran and the approval is pending.
	if len(f.notifier.seen) != 1 || f.notifier.seen[0].ID != a.ID {
		t.Errorf("fan-out = %+v", f.notifier.seen)
	}
	if got, _ := f.svc.Get(t.Context(), alice, a.ID); got == nil || got.Status != approvals.StatusPending {
		t.Errorf("approval = %+v", got)
	}
}

func TestSlackNotifierIsANoOpWithoutASlackConnection(t *testing.T) {
	f := newSlackFixture(t)
	f.st.Accounts[acctB] = [2]string{"personal", "Bob at home"}
	a := f.createFor(t, bob, acctB)
	if len(f.slack.methods()) != 0 {
		t.Fatalf("slack called for a user without a connection: %v", f.slack.methods())
	}
	if strings.Contains(f.logs.String(), "notify_failed") {
		t.Errorf("no-op logged as a failure:\n%s", f.logs.String())
	}
	if got, _ := f.svc.Get(t.Context(), bob, a.ID); got == nil || got.Status != approvals.StatusPending {
		t.Errorf("portal entry missing: %+v", got)
	}
}

func TestSlackNotifierFailuresNeverFailCreate(t *testing.T) {
	cases := map[string]func(f *slackFixture){
		"api error":         func(f *slackFixture) { f.slack.fail["chat.postMessage"] = "channel_not_found" },
		"open error":        func(f *slackFixture) { f.slack.fail["conversations.open"] = "user_not_found" },
		"no bot token":      func(f *slackFixture) { delete(f.dir.secrets, "bot_token") },
		"directory error":   func(f *slackFixture) { f.dir.err = errors.New("db down") },
		"slack unreachable": func(f *slackFixture) { f.slack.srv.Close() },
		"timeout":           func(f *slackFixture) { f.slack.hang = 5 * time.Second },
	}
	for name, arrange := range cases {
		t.Run(name, func(t *testing.T) {
			f := newSlackFixture(t)
			arrange(f)
			start := time.Now()
			a := f.createFor(t, alice, acctA)
			if took := time.Since(start); took > 4*time.Second {
				t.Errorf("Create took %v; the notifier must be bounded", took)
			}
			if got, _ := f.svc.Get(t.Context(), alice, a.ID); got == nil || got.Status != approvals.StatusPending {
				t.Fatalf("approval = %+v", got)
			}
			if !strings.Contains(f.logs.String(), "approvals.notify_failed") {
				t.Errorf("failure not logged:\n%s", f.logs.String())
			}
			if strings.Contains(f.logs.String(), "xoxb-test-token") {
				t.Errorf("bot token in logs:\n%s", f.logs.String())
			}
		})
	}
}

func TestSlackNotifierNeedsIdentityAndSecrets(t *testing.T) {
	if _, err := approvals.NewSlackNotifier(approvals.SlackNotifierOptions{}); err == nil {
		t.Error("no sources: want error")
	}
}

// The DM layout is pinned by a golden file so a change to what users see
// is reviewed. Run with -update after reviewing.
func TestSlackApprovalBlocksGolden(t *testing.T) {
	expires := time.Date(2026, 10, 8, 12, 15, 0, 0, time.UTC)
	a := approvals.Approval{
		ID: "0f0f0f0f-0000-4000-8000-000000000001", UserID: alice, AccountID: acctA, AccountLabel: "company", AccountName: "Alice at work",
		Tool: "fake.create_item", ResourceIdentity: map[string]string{"repo": "acme/widgets", "id": "it-1"},
		CreatedAt: expires.Add(-15 * time.Minute), ExpiresAt: expires,
	}
	summary := approvals.Summarize(map[string]any{"id": "it-1", "name": "first", "body": "the body <b>&amp;</b>", "tags": []any{"a", "b"}})
	blocks := approvals.SlackApprovalBlocks(a, summary, "https://gw.example.com/approvals")
	got, err := json.MarshalIndent(blocks, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	golden := filepath.Join("testdata", "slack_dm.golden.json")
	if *updateGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if !bytes.Equal(want, got) {
		t.Errorf("DM blocks differ from %s (run with -update after reviewing):\n--- want\n%s\n--- got\n%s", golden, want, got)
	}
}

func TestSlackApprovalBlocksTruncateLongSummaries(t *testing.T) {
	args := map[string]any{}
	for i := range 40 {
		args[strings.Repeat("k", 10)+string(rune('a'+i%26))+string(rune('a'+i/26))] = strings.Repeat("v", 200)
	}
	blocks := approvals.SlackApprovalBlocks(approvals.Approval{ID: "x", Tool: "fake.create_item", ExpiresAt: time.Now()}, approvals.Summarize(args), "")
	js, _ := json.Marshal(blocks)
	var raw []map[string]any
	if err := json.Unmarshal(js, &raw); err != nil {
		t.Fatal(err)
	}
	for _, b := range raw {
		if txt, ok := b["text"].(map[string]any); ok {
			if s, _ := txt["text"].(string); len(s) > 3000 {
				t.Errorf("block text of %d chars exceeds Slack's 3000 limit", len(s))
			}
		}
	}
	if !strings.Contains(string(js), "…") {
		t.Errorf("long summary not truncated:\n%s", js)
	}
}
