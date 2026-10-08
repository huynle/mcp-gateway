package slack_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/approvals"
	"github.com/huynle/mcp-gateway/internal/approvals/approvalstest"
	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/slack"
)

const (
	alice    = "11111111-1111-4111-8111-111111111111"
	bob      = "22222222-2222-4222-8222-222222222222"
	acctA    = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	policyV1 = "99999999-9999-4999-8999-999999999991"
	secret   = "sign-test-secret"
)

// The vector from Slack's "Verifying requests from Slack" guide.
const (
	vectorSecret    = "8f742231b10e8888abcd99yyyzzz85a5"
	vectorTimestamp = "1531420618"
	vectorBody      = "token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c"
	vectorSignature = "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503"
)

func sign(secret, ts string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("v0:" + ts + ":"))
	mac.Write(body)
	return "v0=" + hex.EncodeToString(mac.Sum(nil))
}

func TestVerifySignatureAgainstSlacksPublishedVector(t *testing.T) {
	at := time.Unix(1531420618, 0).Add(2 * time.Minute)
	if err := slack.VerifySignature(vectorSecret, vectorTimestamp, vectorSignature, []byte(vectorBody), at, 5*time.Minute); err != nil {
		t.Fatalf("valid vector rejected: %v", err)
	}
	cases := map[string]struct {
		ts, sig string
		body    string
		at      time.Time
		want    error
	}{
		"stale (future)":   {vectorTimestamp, vectorSignature, vectorBody, time.Unix(1531420618, 0).Add(5*time.Minute + time.Second), slack.ErrStaleTimestamp},
		"stale (past)":     {vectorTimestamp, vectorSignature, vectorBody, time.Unix(1531420618, 0).Add(-6 * time.Minute), slack.ErrStaleTimestamp},
		"bad timestamp":    {"yesterday", vectorSignature, vectorBody, at, slack.ErrStaleTimestamp},
		"wrong secret sig": {vectorTimestamp, sign("other", vectorTimestamp, []byte(vectorBody)), vectorBody, at, slack.ErrBadSignature},
		"tampered body":    {vectorTimestamp, vectorSignature, vectorBody + "&x=1", at, slack.ErrBadSignature},
		"no version":       {vectorTimestamp, strings.TrimPrefix(vectorSignature, "v0="), vectorBody, at, slack.ErrBadSignature},
		"garbage sig":      {vectorTimestamp, "v0=zz", vectorBody, at, slack.ErrBadSignature},
		"missing sig":      {vectorTimestamp, "", vectorBody, at, slack.ErrBadSignature},
		"missing ts":       {"", vectorSignature, vectorBody, at, slack.ErrStaleTimestamp},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			err := slack.VerifySignature(vectorSecret, c.ts, c.sig, []byte(c.body), c.at, 5*time.Minute)
			if !errors.Is(err, c.want) {
				t.Errorf("err = %v, want %v", err, c.want)
			}
		})
	}
	if err := slack.VerifySignature("", vectorTimestamp, vectorSignature, []byte(vectorBody), at, 5*time.Minute); err == nil {
		t.Error("empty secret accepted")
	}
}

// --- handler fixture ---------------------------------------------------------

type fakeSlackAPI struct {
	srv     *httptest.Server
	mu      sync.Mutex
	updates []map[string]string
	fail    bool
}

func newFakeSlackAPI(t *testing.T) *fakeSlackAPI {
	t.Helper()
	f := &fakeSlackAPI{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		form := map[string]string{}
		for k := range r.PostForm {
			form[k] = r.PostForm.Get(k)
		}
		f.mu.Lock()
		fail := f.fail
		if strings.HasSuffix(r.URL.Path, "chat.update") {
			f.updates = append(f.updates, form)
		}
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if fail {
			_, _ = w.Write([]byte(`{"ok":false,"error":"message_not_found"}`))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true,"channel":"` + form["channel"] + `","ts":"` + form["ts"] + `"}`))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeSlackAPI) lastUpdate() map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.updates) == 0 {
		return nil
	}
	return f.updates[len(f.updates)-1]
}

func (f *fakeSlackAPI) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.updates)
}

type fakeDirectory struct {
	users   map[string][2]string
	secrets map[string]string
}

func (d *fakeDirectory) SlackIdentity(_ context.Context, userID string) (string, string, bool, error) {
	id, ok := d.users[userID]
	return id[0], id[1], ok, nil
}

func (d *fakeDirectory) VendorSecrets(_ context.Context, _, _ string, keys ...string) (map[string]string, error) {
	out := map[string]string{}
	for _, k := range keys {
		if v := d.secrets[k]; v != "" {
			out[k] = v
		}
	}
	return out, nil
}

type recordingAudit struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *recordingAudit) Record(_ context.Context, ev audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
	return nil
}

func (r *recordingAudit) all() []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]audit.Event(nil), r.events...)
}

type fixture struct {
	h     http.Handler
	svc   *approvals.Service
	st    *approvalstest.MemStore
	api   *fakeSlackAPI
	dir   *fakeDirectory
	audit *recordingAudit
	logs  *bytes.Buffer
	now   time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	keys, err := crypto.NewStaticProvider("k1", map[string][]byte{"k1": bytes.Repeat([]byte{7}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{st: approvalstest.NewMemStore(), api: newFakeSlackAPI(t), audit: &recordingAudit{}, logs: &bytes.Buffer{}, now: time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)}
	f.st.Accounts[acctA] = [2]string{"company", "Alice at work"}
	f.dir = &fakeDirectory{users: map[string][2]string{alice: {"UALICE", "TACME"}, bob: {"UBOB", "TACME"}}, secrets: map[string]string{"signing_secret": secret, "bot_token": "xoxb-test-token"}}
	log := slog.New(slog.NewTextHandler(f.logs, nil))
	f.svc, err = approvals.New(approvals.Config{TTL: 15 * time.Minute, Wait: 30 * time.Second, BaseURL: "https://gw.example.com"}, f.st, keys, approvals.Options{Audit: f.audit, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	f.svc.SetClock(func() time.Time { return f.now })
	h, err := slack.NewInteractionsHandler(slack.Options{
		Approvals: f.svc, Identity: f.dir, Secrets: f.dir, Audit: f.audit, APIURL: f.api.srv.URL + "/api/",
		Now: func() time.Time { return f.now }, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.h = h
	return f
}

func (f *fixture) create(t *testing.T) *approvals.Approval {
	t.Helper()
	a, err := f.svc.Create(context.Background(), approvals.Request{
		UserID: alice, AccountID: acctA, AccountLabel: "company", Tool: "fake.create_item",
		Args: map[string]any{"id": "it-1"}, PolicyVersionID: policyV1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// blockActions builds a block_actions payload the way Slack sends it.
func blockActions(action, value, user, team string) []byte {
	payload := map[string]any{
		"type":         "block_actions",
		"team":         map[string]any{"id": team, "domain": "acme"},
		"user":         map[string]any{"id": user, "username": "someone", "team_id": team},
		"api_app_id":   "A0001",
		"container":    map[string]any{"type": "message", "message_ts": "1700000000.000100", "channel_id": "D-" + user, "is_ephemeral": false},
		"channel":      map[string]any{"id": "D-" + user, "name": "directmessage"},
		"message":      map[string]any{"type": "message", "ts": "1700000000.000100", "text": "Approval required"},
		"response_url": "https://hooks.slack.com/actions/T1/1/x",
		"actions": []map[string]any{{
			"action_id": action, "block_id": "approval:" + value, "type": "button", "value": value, "action_ts": "1700000001.000000",
			"text": map[string]any{"type": "plain_text", "text": "Approve"},
		}},
	}
	js, _ := json.Marshal(payload)
	return []byte(url.Values{"payload": {string(js)}}.Encode())
}

type post struct {
	body      []byte
	ts, sig   string
	noHeaders bool
}

func (f *fixture) post(t *testing.T, p post) *httptest.ResponseRecorder {
	t.Helper()
	if p.ts == "" {
		p.ts = strconv.FormatInt(f.now.Unix(), 10)
	}
	if p.sig == "" {
		p.sig = sign(secret, p.ts, p.body)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/slack/interactions", bytes.NewReader(p.body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if !p.noHeaders {
		req.Header.Set("X-Slack-Request-Timestamp", p.ts)
		req.Header.Set("X-Slack-Signature", p.sig)
	}
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	return rec
}

func TestInteractionsRejectsBadSignaturesBeforeParsing(t *testing.T) {
	f := newFixture(t)
	a := f.create(t)
	body := blockActions("approve", a.ID, "UALICE", "TACME")
	cases := map[string]post{
		"no headers":      {body: body, noHeaders: true},
		"stale timestamp": {body: body, ts: strconv.FormatInt(f.now.Add(-6*time.Minute).Unix(), 10)},
		"wrong secret":    {body: body, sig: sign("not-the-secret", strconv.FormatInt(f.now.Unix(), 10), body)},
		"tampered body":   {body: append(body, '&', 'x'), sig: sign(secret, strconv.FormatInt(f.now.Unix(), 10), body)},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			rec := f.post(t, p)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", rec.Code)
			}
		})
	}
	got, _ := f.svc.Get(context.Background(), alice, a.ID)
	if got.Status != approvals.StatusPending {
		t.Errorf("approval touched: %s", got.Status)
	}
	if f.api.count() != 0 {
		t.Errorf("slack called on rejected requests")
	}
	if !strings.Contains(f.logs.String(), "slack.signature_rejected") {
		t.Errorf("rejections not logged:\n%s", f.logs.String())
	}
	// Garbage body with a valid signature is a 400, not a crash.
	if rec := f.post(t, post{body: []byte("payload=%7Bnot-json")}); rec.Code != http.StatusBadRequest {
		t.Errorf("garbage payload = %d", rec.Code)
	}
	// GET is not served.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/slack/interactions", nil)
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET = %d", rec.Code)
	}
}

func TestInteractionsWithoutASigningSecretAre401(t *testing.T) {
	f := newFixture(t)
	a := f.create(t)
	delete(f.dir.secrets, "signing_secret")
	if rec := f.post(t, post{body: blockActions("approve", a.ID, "UALICE", "TACME")}); rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestInteractionsApproveResolvesTheApprovalAndUpdatesTheMessage(t *testing.T) {
	f := newFixture(t)
	a := f.create(t)
	rec := f.post(t, post{body: blockActions("approve", a.ID, "UALICE", "TACME")})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	got, err := f.svc.Get(context.Background(), alice, a.ID)
	if err != nil || got.Status != approvals.StatusApproved {
		t.Fatalf("approval = %+v, %v", got, err)
	}
	up := f.api.lastUpdate()
	if up == nil || up["channel"] != "D-UALICE" || up["ts"] != "1700000000.000100" || up["token"] != "xoxb-test-token" {
		t.Fatalf("chat.update = %v", up)
	}
	if !strings.Contains(up["blocks"], "Approved by you") || strings.Contains(up["blocks"], `"type":"button"`) || !strings.Contains(up["blocks"], "fake.create_item") {
		t.Errorf("updated blocks = %s", up["blocks"])
	}
	// The decision is the user's own audit event, like the portal's.
	var decided bool
	for _, ev := range f.audit.all() {
		if ev.UserID == alice && ev.ResourceIdentity["action"] == "approval_approved" && ev.ApprovalID == a.ID {
			decided = true
		}
	}
	if !decided {
		t.Errorf("no approval_approved audit event: %+v", f.audit.all())
	}
	// Pressing again: already decided, message says so, still 200.
	rec = f.post(t, post{body: blockActions("deny", a.ID, "UALICE", "TACME")})
	if rec.Code != http.StatusOK {
		t.Errorf("second press = %d", rec.Code)
	}
	got, _ = f.svc.Get(context.Background(), alice, a.ID)
	if got.Status != approvals.StatusApproved {
		t.Errorf("second press changed the status: %s", got.Status)
	}
	if up := f.api.lastUpdate(); !strings.Contains(up["blocks"], "already") {
		t.Errorf("second press blocks = %s", up["blocks"])
	}
	if strings.Contains(f.logs.String(), "xoxb-test-token") {
		t.Errorf("bot token in logs")
	}
}

func TestInteractionsDenyResolvesTheApproval(t *testing.T) {
	f := newFixture(t)
	a := f.create(t)
	if rec := f.post(t, post{body: blockActions("deny", a.ID, "UALICE", "TACME")}); rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	got, _ := f.svc.Get(context.Background(), alice, a.ID)
	if got.Status != approvals.StatusDenied {
		t.Fatalf("status = %s", got.Status)
	}
	if up := f.api.lastUpdate(); up == nil || !strings.Contains(up["blocks"], "Denied") || strings.Contains(up["blocks"], `"type":"button"`) {
		t.Errorf("blocks = %v", up)
	}
}

func TestInteractionsFromAnotherSlackUserAreRefusedAndAudited(t *testing.T) {
	f := newFixture(t)
	a := f.create(t)
	cases := map[string][2]string{
		"other user":  {"UBOB", "TACME"},
		"other team":  {"UALICE", "TOTHER"},
		"empty user":  {"", "TACME"},
		"unconnected": {"UNOBODY", "TACME"},
	}
	for name, who := range cases {
		t.Run(name, func(t *testing.T) {
			rec := f.post(t, post{body: blockActions("approve", a.ID, who[0], who[1])})
			if rec.Code != http.StatusForbidden {
				t.Errorf("status = %d, want 403", rec.Code)
			}
		})
	}
	got, _ := f.svc.Get(context.Background(), alice, a.ID)
	if got.Status != approvals.StatusPending {
		t.Fatalf("approval decided by a stranger: %s", got.Status)
	}
	if f.api.count() != 0 {
		t.Errorf("message updated for a stranger")
	}
	var rejected int
	for _, ev := range f.audit.all() {
		if ev.ResourceIdentity["action"] == "approval_slack_rejected" && ev.ApprovalID == a.ID && ev.UserID == alice && ev.Decision == "deny" && ev.Outcome == "denied" && ev.ErrorClass == "slack_user_mismatch" {
			rejected++
		}
	}
	if rejected != len(cases) {
		t.Errorf("rejections audited = %d, want %d: %+v", rejected, len(cases), f.audit.all())
	}
	// The owner's own Slack user no longer connected: refused too.
	delete(f.dir.users, alice)
	if rec := f.post(t, post{body: blockActions("approve", a.ID, "UALICE", "TACME")}); rec.Code != http.StatusForbidden {
		t.Errorf("disconnected owner = %d", rec.Code)
	}
}

func TestInteractionsOnUnknownOrExpiredApprovalsSayExpired(t *testing.T) {
	f := newFixture(t)
	// Unknown id: 200, message replaced.
	rec := f.post(t, post{body: blockActions("approve", "0f0f0f0f-0000-4000-8000-00000000dead", "UALICE", "TACME")})
	if rec.Code != http.StatusOK {
		t.Fatalf("unknown = %d", rec.Code)
	}
	if up := f.api.lastUpdate(); up == nil || !strings.Contains(strings.ToLower(up["blocks"]), "expired") {
		t.Errorf("unknown blocks = %v", up)
	}
	// Expired: past its expiry but not yet swept.
	a := f.create(t)
	f.now = f.now.Add(16 * time.Minute)
	rec = f.post(t, post{body: blockActions("approve", a.ID, "UALICE", "TACME")})
	if rec.Code != http.StatusOK {
		t.Fatalf("expired = %d", rec.Code)
	}
	got, _ := f.svc.Get(context.Background(), alice, a.ID)
	if got.Status != approvals.StatusPending {
		t.Errorf("expired approval approved: %s", got.Status)
	}
	if up := f.api.lastUpdate(); !strings.Contains(strings.ToLower(up["blocks"]), "expired") || strings.Contains(up["blocks"], `"type":"button"`) {
		t.Errorf("expired blocks = %s", up["blocks"])
	}
}

func TestInteractionsIgnoreOtherPayloadsAndSurviveUpdateFailures(t *testing.T) {
	f := newFixture(t)
	a := f.create(t)
	// A payload type we do not handle, and a block action we do not know.
	other := []byte(url.Values{"payload": {`{"type":"view_submission","user":{"id":"UALICE"}}`}}.Encode())
	if rec := f.post(t, post{body: other}); rec.Code != http.StatusOK {
		t.Errorf("view_submission = %d", rec.Code)
	}
	if rec := f.post(t, post{body: blockActions("snooze", a.ID, "UALICE", "TACME")}); rec.Code != http.StatusOK {
		t.Errorf("unknown action = %d", rec.Code)
	}
	if got, _ := f.svc.Get(context.Background(), alice, a.ID); got.Status != approvals.StatusPending {
		t.Fatalf("status = %s", got.Status)
	}
	// chat.update failing does not undo the decision or fail the request.
	f.api.fail = true
	if rec := f.post(t, post{body: blockActions("approve", a.ID, "UALICE", "TACME")}); rec.Code != http.StatusOK {
		t.Errorf("approve with failing update = %d", rec.Code)
	}
	if got, _ := f.svc.Get(context.Background(), alice, a.ID); got.Status != approvals.StatusApproved {
		t.Errorf("status = %s", got.Status)
	}
	if !strings.Contains(f.logs.String(), "slack.update_failed") {
		t.Errorf("update failure not logged:\n%s", f.logs.String())
	}
}

func TestInteractionsHandlerNeedsItsCollaborators(t *testing.T) {
	if _, err := slack.NewInteractionsHandler(slack.Options{}); err == nil {
		t.Error("want error without approvals/identity/secrets")
	}
}
