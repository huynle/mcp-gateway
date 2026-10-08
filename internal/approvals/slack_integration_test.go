//go:build integration

package approvals_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/approvals"
	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/slack"
	"github.com/huynle/mcp-gateway/internal/store"
)

// slackWorld extends world with the connections service over the same
// database (the Slack vendor app with its bot token and signing secret,
// alice's company Slack connection), a second approvals service that
// carries the Slack notifier (another replica), the fake Slack API and
// the interactions endpoint.
type slackWorld struct {
	*world
	conn     *connections.Service
	notified *approvals.Service
	slack    *fakeSlack
	inter    http.Handler
	signing  string
}

func newSlackWorld(t *testing.T) *slackWorld {
	t.Helper()
	w := newWorld(t, 0)
	ctx := t.Context()
	log := slog.New(slog.DiscardHandler)
	keys, err := crypto.NewStaticProvider("k1", map[string][]byte{"k1": bytes.Repeat([]byte{9}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := connections.New(connections.Config{BaseURL: "http://localhost:18080"}, connections.NewPostgresStore(w.st), keys, connections.Options{Audit: w.rec, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	sw := &slackWorld{world: w, conn: conn, slack: newFakeSlack(t), signing: "integration-signing-secret"}
	app := connections.Defaults(connections.VendorSlack, "")
	app.ClientID, app.ClientSecret = "slack-cid", "slack-secret"
	app.Secrets = map[string]string{connections.SecretSlackBotToken: "xoxb-integration", connections.SecretSlackSigningSecret: sw.signing}
	saved, err := conn.SaveVendorApp(ctx, w.admin, app)
	if err != nil {
		t.Fatalf("SaveVendorApp: %v", err)
	}
	// Alice connected her company Slack; bob did not.
	err = w.st.WithUser(ctx, w.alice, func(tx store.Tx) error {
		return tx.Connections().Create(ctx, &store.Connection{
			UserID: w.alice, VendorAppID: saved.ID, ExternalAccountID: connections.SlackAccountID("TACME", "UALICE"),
			Label: store.AccountCompany, DisplayName: "alice@acme", Status: store.ConnectionActive,
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	n, err := approvals.NewSlackNotifier(approvals.SlackNotifierOptions{Identity: conn, Secrets: conn, APIURL: sw.slack.URL(), PortalURL: "http://localhost:18080/approvals", Log: log})
	if err != nil {
		t.Fatal(err)
	}
	sw.notified, err = approvals.New(approvals.Config{TTL: 15 * time.Minute, Wait: 0, BaseURL: "http://localhost:18080"}, approvals.NewPostgresStore(w.st), keys, approvals.Options{
		Audit: w.rec, Notifier: approvals.MultiNotifier{approvals.PortalNotifier{}, n}, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	n.SetArguments(sw.notified)
	sw.inter, err = slack.NewInteractionsHandler(slack.Options{Approvals: sw.notified, Identity: conn, Secrets: conn, Audit: w.rec, APIURL: sw.slack.URL(), Log: log})
	if err != nil {
		t.Fatal(err)
	}
	return sw
}

func (sw *slackWorld) press(t *testing.T, action, approvalID, slackUser, team string) *httptest.ResponseRecorder {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{
		"type":      "block_actions",
		"team":      map[string]any{"id": team},
		"user":      map[string]any{"id": slackUser, "team_id": team},
		"container": map[string]any{"type": "message", "message_ts": "1700000000.000100", "channel_id": "D-" + slackUser},
		"actions":   []map[string]any{{"action_id": action, "block_id": "approval:" + approvalID, "type": "button", "value": approvalID}},
	})
	body := []byte(url.Values{"payload": {string(payload)}}.Encode())
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, []byte(sw.signing))
	mac.Write([]byte("v0:" + ts + ":"))
	mac.Write(body)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/slack/interactions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Slack-Request-Timestamp", ts)
	req.Header.Set("X-Slack-Signature", "v0="+hex.EncodeToString(mac.Sum(nil)))
	rec := httptest.NewRecorder()
	sw.inter.ServeHTTP(rec, req)
	return rec
}

func TestIntegrationApproveFromSlackThenRetryConsumesTheStoredArguments(t *testing.T) {
	sw := newSlackWorld(t)
	ctx := t.Context()
	cs := sw.client(t, sw.alice)

	// The confirmed call creates the approval on this replica (no
	// notifier), exactly as before; the DM goes out from the replica that
	// carries the notifier (same rows).
	_, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "fake.create_item", Arguments: map[string]any{"id": "it-1", "name": "first", "body": "the original body"}})
	id, _ := approvalRequired(t, err)
	if a, err := sw.notified.Lookup(ctx, id); err != nil || a.UserID != sw.alice {
		t.Fatalf("Lookup = %+v, %v", a, err)
	}
	cur, _ := sw.policy.Current(ctx)
	dm, err := sw.notified.Create(ctx, approvals.Request{UserID: sw.alice, AccountID: sw.aliceAcc, AccountLabel: "company", Tool: "fake.create_item", Args: map[string]any{"id": "it-9", "name": "ninth", "body": "SECRET NINE"}, PolicyVersionID: cur.ID})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(sw.slack.methods(), ","); got != "conversations.open,chat.postMessage" {
		t.Fatalf("DM calls = %s", got)
	}
	post := sw.slack.lastPost()
	if post["channel"] != "D-UALICE" || post["token"] != "xoxb-integration" || !strings.Contains(post["blocks"], "SECRET NINE") || !strings.Contains(post["blocks"], `"value":"`+dm.ID+`"`) {
		t.Fatalf("DM = %v", post)
	}

	// A stranger's Slack user (bob is not connected; a foreign id) is
	// refused and audited against the owner.
	if rec := sw.press(t, "approve", id, "UBOB", "TACME"); rec.Code != http.StatusForbidden {
		t.Fatalf("stranger press = %d", rec.Code)
	}
	if rec := sw.press(t, "approve", id, "UALICE", "TOTHER"); rec.Code != http.StatusForbidden {
		t.Fatalf("other-team press = %d", rec.Code)
	}
	if got, _ := sw.svc.Get(ctx, sw.alice, id); got.Status != approvals.StatusPending {
		t.Fatalf("stranger decided: %s", got.Status)
	}
	rows, err := sw.rec.AdminSearch(ctx, audit.Filter{UserID: sw.alice, Outcome: "denied"}, audit.Page{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	var refused int
	for _, r := range rows {
		if r.ResourceIdentity["action"] == "approval_slack_rejected" && r.ApprovalID == id && r.ErrorClass == "slack_user_mismatch" {
			refused++
		}
	}
	if refused != 2 {
		t.Fatalf("refusals audited = %d: %+v", refused, rows)
	}

	// Alice presses Approve from the Slack the connection names.
	if rec := sw.press(t, "approve", id, "UALICE", "TACME"); rec.Code != http.StatusOK {
		t.Fatalf("approve press = %d: %s", rec.Code, rec.Body)
	}
	if got, _ := sw.svc.Get(ctx, sw.alice, id); got.Status != approvals.StatusApproved {
		t.Fatalf("after press: %s", got.Status)
	}
	if up := sw.slack.lastUpdate(); up == nil || !strings.Contains(up["blocks"], "Approved by you") || up["channel"] != "D-UALICE" {
		t.Fatalf("message update = %v", up)
	}
	// The retry path is the portal's: stored arguments run, single use.
	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "fake.create_item", Arguments: map[string]any{"id": "it-1", "name": "drifted", "body": "drifted", "approval_id": id}})
	if err != nil || res.IsError {
		t.Fatalf("retry: err=%v res=%+v", err, res)
	}
	items := sw.fake.State().Items(sw.aliceAcc)
	if len(items) != 1 || items[0].Body != "the original body" {
		t.Fatalf("connector received %+v", items)
	}
	sw.assertPayloadNull(t, id, "consumed")
	_, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "fake.create_item", Arguments: map[string]any{"id": "it-2", "approval_id": id}})
	if err == nil || !strings.Contains(err.Error(), "already used") {
		t.Errorf("second use: %v", err)
	}
	// A press on the consumed approval changes nothing and tells the user.
	if rec := sw.press(t, "deny", id, "UALICE", "TACME"); rec.Code != http.StatusOK {
		t.Errorf("press after consume = %d", rec.Code)
	}
	if up := sw.slack.lastUpdate(); !strings.Contains(up["blocks"], "already used") {
		t.Errorf("post-consume update = %v", up)
	}

	// Deny from Slack drops the payload like the portal's deny.
	if rec := sw.press(t, "deny", dm.ID, "UALICE", "TACME"); rec.Code != http.StatusOK {
		t.Fatalf("deny press = %d", rec.Code)
	}
	sw.assertPayloadNull(t, dm.ID, "denied")
}

func TestIntegrationUserWithoutSlackIsPortalOnly(t *testing.T) {
	sw := newSlackWorld(t)
	ctx := t.Context()
	cur, _ := sw.policy.Current(ctx)
	a, err := sw.notified.Create(ctx, approvals.Request{UserID: sw.bob, AccountID: sw.bobAcc, AccountLabel: "personal", Tool: "fake.create_item", Args: map[string]any{"id": "b-1"}, PolicyVersionID: cur.ID})
	if err != nil {
		t.Fatalf("Create for bob: %v", err)
	}
	if len(sw.slack.methods()) != 0 {
		t.Errorf("Slack called for bob: %v", sw.slack.methods())
	}
	pend, err := sw.notified.Pending(ctx, sw.bob)
	if err != nil || len(pend) != 1 || pend[0].ID != a.ID {
		t.Errorf("portal entry = %+v, %v", pend, err)
	}
	// And the harness still gets the "approval required" answer.
	cs := sw.client(t, sw.bob)
	_, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "fake.create_item", Arguments: map[string]any{"id": "b-2", "name": "x"}})
	approvalRequired(t, err)
}
