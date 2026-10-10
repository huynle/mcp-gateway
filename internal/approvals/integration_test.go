//go:build integration

package approvals_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/approvals"
	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/fake"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// The approvals integration tests run against their own database
// (gateway_approvals_test, created from GATEWAY_TEST_DATABASE_URL) so they
// never race the store package's TRUNCATE (quirk 01mepmn6). They need a
// superuser URL and give the two application roles a temporary LOGIN
// password, retrying the ALTER ROLE race (quirk aihn7hjb).

const (
	testDB      = "gateway_approvals_test"
	appPassword = "gateway-app-test"
	jobsPass    = "gateway-jobs-test"
	dexIssuer   = "http://localhost:15556/dex"
)

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	raw := os.Getenv("GATEWAY_TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("GATEWAY_TEST_DATABASE_URL not set; skipping integration test")
	}
	ctx := t.Context()
	admin, err := pgx.Connect(ctx, raw)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = admin.Close(ctx) }()
	var exists bool
	if err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, testDB).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		if _, err := admin.Exec(ctx, `CREATE DATABASE `+testDB); err != nil {
			t.Fatalf("create database: %v", err)
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + testDB
	superURL := u.String()
	if err := migrations.Up(ctx, superURL); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	super, err := pgx.Connect(ctx, superURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = super.Close(ctx) }()
	for _, stmt := range []string{
		"ALTER ROLE gateway_app LOGIN PASSWORD '" + appPassword + "'",
		"ALTER ROLE gateway_jobs LOGIN PASSWORD '" + jobsPass + "'",
		"TRUNCATE users, identities, sessions, roles, role_assignments, user_restrictions, policy_versions, tokens, vendor_apps, connections, approvals, audit_events, job_locks CASCADE",
	} {
		if err := execRetryingConcurrentUpdate(ctx, super, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	appURL, jobsURL := *u, *u
	appURL.User = url.UserPassword("gateway_app", appPassword)
	jobsURL.User = url.UserPassword("gateway_jobs", jobsPass)
	st, err := store.New(ctx, appURL.String(), store.WithJobsURL(jobsURL.String()))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(st.Close)
	return st
}

func execRetryingConcurrentUpdate(ctx context.Context, conn *pgx.Conn, stmt string) error {
	var err error
	for attempt := 0; attempt < 20; attempt++ {
		if _, err = conn.Exec(ctx, stmt); err == nil || !strings.Contains(err.Error(), "concurrently updated") {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
	return err
}

// world is everything a real deployment wires: two signed-in users with
// one fake connection each, the policy service with the member role
// confirming create_item, the approvals service over PostgreSQL, the
// fake connector whose accounts are the connection rows, and /mcp.
type world struct {
	st       *store.Store
	rec      *audit.StoreRecorder
	idSvc    *identity.Service
	policy   *policy.Service
	tokens   *tokens.Service
	svc      *approvals.Service
	fake     *fake.Connector
	alice    string
	bob      string
	admin    string
	aliceAcc string
	bobAcc   string
	srv      *httptest.Server
}

func newWorld(t *testing.T, wait time.Duration) *world {
	t.Helper()
	st := openTestStore(t)
	ctx := t.Context()
	log := slog.New(slog.DiscardHandler)
	w := &world{st: st}

	idSvc, err := identity.New(identity.Config{
		BaseURL:         "http://localhost:18080",
		Providers:       []config.OIDCProvider{{Name: "dex", DisplayName: "dex", Issuer: dexIssuer, ClientID: "gateway", ClientSecret: "s", AllowedDomains: []string{"example.com"}}},
		DefaultRole:     "member",
		BootstrapAdmins: []string{dexIssuer + "|admin-subject"},
		IdleTimeout:     12 * time.Hour,
		AbsoluteTimeout: 7 * 24 * time.Hour,
	}, identity.NewPostgresStore(st), log)
	if err != nil {
		t.Fatal(err)
	}
	w.idSvc = idSvc
	signIn := func(sub, name string) string {
		s, err := idSvc.SignIn(ctx, "dex", identity.Claims{Issuer: dexIssuer, Subject: sub, Name: name, Email: sub + "@example.com", EmailVerified: true})
		if err != nil {
			t.Fatalf("SignIn %s: %v", sub, err)
		}
		return s.Principal.UserID
	}
	w.admin = signIn("admin-subject", "Admin")
	w.alice = signIn("alice-subject", "Alice")
	w.bob = signIn("bob-subject", "Bob")

	// One fake vendor app and one connection per user: approvals reference
	// connections, and the account stage's IDs are those rows.
	var appID string
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		app := &store.VendorApp{Vendor: "fake", Name: "fake-test", ClientID: "cid", ClientSecret: store.Encrypted{KeyID: "k", WrappedDataKey: []byte("w"), Nonce: []byte("n"), Ciphertext: []byte("c")}, Enabled: true}
		if err := tx.VendorApps().Create(ctx, app); err != nil {
			return err
		}
		appID = app.ID
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	connect := func(user, label, name string) string {
		var id string
		err := st.WithUser(ctx, user, func(tx store.Tx) error {
			c := &store.Connection{UserID: user, VendorAppID: appID, ExternalAccountID: user + "-ext", Label: label, DisplayName: name}
			if err := tx.Connections().Create(ctx, c); err != nil {
				return err
			}
			id = c.ID
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	w.aliceAcc = connect(w.alice, "company", "Alice at work")
	w.bobAcc = connect(w.bob, "personal", "Bob at home")

	w.rec = audit.NewStoreRecorder(st)
	metrics := observability.NewMetrics()
	w.tokens, err = tokens.New(tokens.Config{SignInMaxAge: 30 * 24 * time.Hour}, tokens.NewPostgresStore(st), metrics, w.rec, log)
	if err != nil {
		t.Fatal(err)
	}
	w.policy, err = policy.New(policy.NewPostgresStore(st), policy.Options{Audit: w.rec, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	member, err := w.policy.Role(ctx, "member")
	if err != nil {
		t.Fatal(err)
	}
	member.Rules = []policy.ToolRule{
		{App: "fake", Tool: "*", Outcome: policy.OutcomeAllow},
		{App: "fake", Tool: "create_item", Outcome: policy.OutcomeConfirm},
	}
	if err := w.policy.SaveRole(ctx, w.admin, member); err != nil {
		t.Fatalf("SaveRole: %v", err)
	}

	keys, err := crypto.NewStaticProvider("k1", map[string][]byte{"k1": bytes.Repeat([]byte{9}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	w.svc, err = approvals.New(approvals.Config{TTL: 15 * time.Minute, Wait: wait, BaseURL: "http://localhost:18080"}, approvals.NewPostgresStore(st), keys, approvals.Options{
		Audit: w.rec, Metrics: metrics, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}

	w.fake = fake.New(fake.Options{})
	w.fake.SeedAccount(w.alice, connectors.Account{ID: w.aliceAcc, Label: connectors.LabelCompany, DisplayName: "Alice at work"})
	w.fake.SeedAccount(w.bob, connectors.Account{ID: w.bobAcc, Label: connectors.LabelPersonal, DisplayName: "Bob at home"})
	reg := connectors.NewRegistry()
	if err := connectors.RegisterConnector(reg, w.fake, w.fake.Accounts()); err != nil {
		t.Fatal(err)
	}
	h, err := mcp.Handler(mcp.Options{
		Registry:      reg,
		Authenticator: w.tokens,
		Auth:          tokens.MiddlewareOptions{Limiter: tokens.NewFailureLimiter(tokens.DefaultFailureBurst, tokens.DefaultFailureWindow)},
		BaseURL:       "http://localhost:18080",
		Accounts:      w.fake.Accounts(),
		Policy:        w.policy,
		Confirm:       approvals.NewConfirmHandler(w.svc, metrics, log),
		Audit:         w.rec,
		Metrics:       metrics,
		Log:           log,
	})
	if err != nil {
		t.Fatal(err)
	}
	w.srv = httptest.NewServer(observability.RequestID(h))
	t.Cleanup(w.srv.Close)
	return w
}

func (w *world) client(t *testing.T, user string) *sdk.ClientSession {
	t.Helper()
	created, err := w.tokens.Create(t.Context(), user, tokens.CreateRequest{Name: "laptop"})
	if err != nil {
		t.Fatal(err)
	}
	transport := &sdk.StreamableClientTransport{Endpoint: w.srv.URL, HTTPClient: bearerClient(created.Raw)}
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "test", Version: "0"}, nil).Connect(t.Context(), transport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

// payloadColumns reads the raw ciphertext columns through the bypass
// scope: the assertion that a payload is gone must not depend on the
// repository's own reading.
func (w *world) payloadColumns(t *testing.T, id string) (status string, keyID, wrapped, nonce, ciphertext []byte) {
	t.Helper()
	err := w.st.WithJobs(t.Context(), func(tx store.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT status::text, payload_key_id, payload_wrapped_key, payload_nonce, payload_ciphertext FROM approvals WHERE id = $1`, id).
			Scan(&status, &keyID, &wrapped, &nonce, &ciphertext)
	})
	if err != nil {
		t.Fatalf("read approval %s: %v", id, err)
	}
	return status, keyID, wrapped, nonce, ciphertext
}

func (w *world) assertPayloadNull(t *testing.T, id, wantStatus string) {
	t.Helper()
	status, keyID, wrapped, nonce, ciphertext := w.payloadColumns(t, id)
	if status != wantStatus {
		t.Errorf("%s status = %s, want %s", id, status, wantStatus)
	}
	if keyID != nil || wrapped != nil || nonce != nil || ciphertext != nil {
		t.Errorf("%s (%s) still has payload columns: key=%v wrapped=%d nonce=%d ct=%d", id, status, keyID, len(wrapped), len(nonce), len(ciphertext))
	}
}

func (w *world) create(t *testing.T, user, acct string, args map[string]any) *approvals.Approval {
	t.Helper()
	cur, err := w.policy.Current(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	a, err := w.svc.Create(t.Context(), approvals.Request{UserID: user, AccountID: acct, AccountLabel: "company", Tool: "fake.create_item", Args: args, PolicyVersionID: cur.ID})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return a
}

func TestIntegrationPayloadIsNullAfterDenyConsumeAndExpiry(t *testing.T) {
	w := newWorld(t, 0)
	ctx := t.Context()
	args := map[string]any{"id": "it-1", "name": "first", "body": "SECRET BODY"}

	// Pending: encrypted payload present, plaintext absent, invisible to bob.
	a := w.create(t, w.alice, w.aliceAcc, args)
	status, keyID, _, _, ciphertext := w.payloadColumns(t, a.ID)
	if status != "pending" || keyID == nil || len(ciphertext) == 0 || bytes.Contains(ciphertext, []byte("SECRET")) {
		t.Fatalf("pending row: status %s key %v ct %d", status, keyID, len(ciphertext))
	}
	if _, err := w.svc.Get(ctx, w.bob, a.ID); !errors.Is(err, approvals.ErrNotFound) {
		t.Errorf("bob reads alice's approval: %v", err)
	}
	if _, err := w.svc.Approve(ctx, w.bob, a.ID); !errors.Is(err, approvals.ErrNotFound) {
		t.Errorf("bob approves alice's approval: %v", err)
	}
	got, err := w.svc.Get(ctx, w.alice, a.ID)
	if err != nil || got.AccountLabel != "company" || got.AccountName != "Alice at work" || !got.HasPayload {
		t.Errorf("Get = %+v, %v", got, err)
	}

	// Deny drops the payload.
	if _, err := w.svc.Deny(ctx, w.alice, a.ID); err != nil {
		t.Fatal(err)
	}
	w.assertPayloadNull(t, a.ID, "denied")

	// Approve keeps it (the schema must allow that); consume drops it and
	// returns the stored arguments.
	b := w.create(t, w.alice, w.aliceAcc, args)
	if _, err := w.svc.Approve(ctx, w.alice, b.ID); err != nil {
		t.Fatal(err)
	}
	if status, _, _, _, ct := w.payloadColumns(t, b.ID); status != "approved" || len(ct) == 0 {
		t.Fatalf("approved row lost its payload: %s %d", status, len(ct))
	}
	cur, _ := w.policy.Current(ctx)
	consumed, err := w.svc.ConsumeNow(ctx, approvals.Binding{UserID: w.alice, AccountID: w.aliceAcc, Tool: "fake.create_item", PolicyVersionID: cur.ID, ApprovalID: b.ID})
	if err != nil || consumed.Args["body"] != "SECRET BODY" {
		t.Fatalf("consume = %+v, %v", consumed, err)
	}
	w.assertPayloadNull(t, b.ID, "consumed")

	// Expiry: a pending and an approved row past their expiry are swept.
	c := w.create(t, w.alice, w.aliceAcc, args)
	d := w.create(t, w.alice, w.aliceAcc, args)
	if _, err := w.svc.Approve(ctx, w.alice, d.ID); err != nil {
		t.Fatal(err)
	}
	e := w.create(t, w.alice, w.aliceAcc, args) // stays
	err = w.st.WithJobs(ctx, func(tx store.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE approvals SET expires_at = now() - interval '1 second' WHERE id = ANY($1)`, []string{c.ID, d.ID})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	job := w.svc.ExpiryJob(0)
	if err := job.Run(ctx); err != nil {
		t.Fatalf("expiry job: %v", err)
	}
	w.assertPayloadNull(t, c.ID, "expired")
	w.assertPayloadNull(t, d.ID, "expired")
	if status, _, _, _, ct := w.payloadColumns(t, e.ID); status != "pending" || len(ct) == 0 {
		t.Errorf("unexpired row touched: %s %d", status, len(ct))
	}
	// History shows them all without payloads; pending shows only e.
	hist, err := w.svc.History(ctx, w.alice, 50)
	if err != nil || len(hist) != 5 {
		t.Errorf("History = %d, %v", len(hist), err)
	}
	pend, err := w.svc.Pending(ctx, w.alice)
	if err != nil || len(pend) != 1 || pend[0].ID != e.ID || pend[0].Args["body"] != "SECRET BODY" {
		t.Errorf("Pending = %+v, %v", pend, err)
	}
}

func TestIntegrationConcurrentDoubleConsumeHasOneWinner(t *testing.T) {
	w := newWorld(t, 0)
	ctx := t.Context()
	a := w.create(t, w.alice, w.aliceAcc, map[string]any{"id": "it-1", "name": "first"})
	if _, err := w.svc.Approve(ctx, w.alice, a.ID); err != nil {
		t.Fatal(err)
	}
	cur, _ := w.policy.Current(ctx)
	b := approvals.Binding{UserID: w.alice, AccountID: w.aliceAcc, Tool: "fake.create_item", PolicyVersionID: cur.ID, ApprovalID: a.ID}
	const n = 16
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, results[i] = w.svc.ConsumeNow(ctx, b)
		}()
	}
	close(start)
	wg.Wait()
	var winners, used int
	for _, err := range results {
		switch {
		case err == nil:
			winners++
		case errors.Is(err, approvals.ErrConsumed):
			used++
		default:
			t.Errorf("unexpected consume error: %v", err)
		}
	}
	if winners != 1 || used != n-1 {
		t.Errorf("winners = %d, already-used = %d (of %d)", winners, used, n)
	}
	w.assertPayloadNull(t, a.ID, "consumed")
}

func TestIntegrationEndToEndRetryWithStoredArgumentsAndPolicyVersion(t *testing.T) {
	w := newWorld(t, 0)
	ctx := t.Context()
	cs := w.client(t, w.alice)

	// Confirmed call: approval required, with the id in error.data.
	_, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "fake.create_item", Arguments: map[string]any{"id": "it-1", "name": "first", "body": "the original body"}})
	id, data := approvalRequired(t, err)
	if data["portal_url"] != "http://localhost:18080/approvals" || data["expires_at"] == nil || !strings.Contains(data["instructions"].(string), id) {
		t.Errorf("error data = %v", data)
	}
	// The user approves in the portal (the service is what the page calls).
	if _, err := w.svc.Approve(ctx, w.alice, id); err != nil {
		t.Fatal(err)
	}
	// The harness retries with drifted arguments and the id: the stored
	// arguments run.
	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "fake.create_item", Arguments: map[string]any{"id": "it-1", "name": "first, reworded", "body": "drifted", "approval_id": id}})
	if err != nil || res.IsError {
		t.Fatalf("retry: err=%v res=%+v", err, res)
	}
	items := w.fake.State().Items(w.aliceAcc)
	if len(items) != 1 || items[0].Name != "first" || items[0].Body != "the original body" {
		t.Errorf("connector received %+v, want the stored arguments", items)
	}
	// Second use is refused.
	_, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "fake.create_item", Arguments: map[string]any{"id": "it-2", "name": "again", "approval_id": id}})
	if err == nil || !strings.Contains(err.Error(), "already used") {
		t.Errorf("second use: %v", err)
	}
	// Bob cannot use alice's approval (not found == mismatch answer).
	bobCS := w.client(t, w.bob)
	_, err = bobCS.CallTool(ctx, &sdk.CallToolParams{Name: "fake.create_item", Arguments: map[string]any{"id": "it-3", "name": "bob", "approval_id": id}})
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Errorf("bob with alice's approval: %v", err)
	}

	// A role change after the approval was granted: new policy version,
	// the approval no longer matches.
	_, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "fake.create_item", Arguments: map[string]any{"id": "it-4", "name": "fourth"}})
	id2, _ := approvalRequired(t, err)
	if _, err := w.svc.Approve(ctx, w.alice, id2); err != nil {
		t.Fatal(err)
	}
	member, _ := w.policy.Role(ctx, "member")
	member.Rules = append(member.Rules, policy.ToolRule{App: "fake", Tool: "flaky_write", Outcome: policy.OutcomeHidden})
	if err := w.policy.SaveRole(ctx, w.admin, member); err != nil {
		t.Fatal(err)
	}
	_, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "fake.create_item", Arguments: map[string]any{"id": "it-4", "name": "fourth", "approval_id": id2}})
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Errorf("approval under the old policy version: %v", err)
	}
	if len(w.fake.State().Items(w.aliceAcc)) != 1 {
		t.Errorf("items = %+v", w.fake.State().Items(w.aliceAcc))
	}

	// Audit: tool_call rows carry the approval id; approve is a user event.
	events, err := w.rec.ListForUser(ctx, w.alice, audit.Filter{}, audit.Page{})
	if err != nil {
		t.Fatal(err)
	}
	var withApproval, approvedEvents int
	for _, ev := range events {
		if ev.EventType == audit.EventTypeToolCall && ev.ApprovalID == id {
			withApproval++
		}
		if ev.EventType == audit.EventTypeUser && ev.ResourceIdentity["action"] == "approval_approved" {
			approvedEvents++
		}
		raw, _ := json.Marshal(ev)
		if strings.Contains(string(raw), "original body") {
			t.Errorf("argument content in audit: %s", raw)
		}
	}
	if withApproval < 2 || approvedEvents != 2 {
		t.Errorf("audit: tool calls with approval %s = %d, approve events = %d", id, withApproval, approvedEvents)
	}
}

func TestIntegrationApproveDuringWaitCompletesInOneRoundTrip(t *testing.T) {
	w := newWorld(t, 5*time.Second)
	ctx := t.Context()
	cs := w.client(t, w.alice)
	go func() {
		deadline := time.Now().Add(4 * time.Second)
		for time.Now().Before(deadline) {
			pend, _ := w.svc.Pending(context.Background(), w.alice)
			if len(pend) == 1 {
				_, _ = w.svc.Approve(context.Background(), w.alice, pend[0].ID)
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "fake.create_item", Arguments: map[string]any{"id": "it-1", "name": "first"}})
	if err != nil || res.IsError {
		t.Fatalf("call: err=%v res=%+v", err, res)
	}
	if items := w.fake.State().Items(w.aliceAcc); len(items) != 1 {
		t.Errorf("items = %+v", items)
	}
	hist, _ := w.svc.History(ctx, w.alice, 10)
	if len(hist) != 1 || hist[0].Status != approvals.StatusConsumed {
		t.Errorf("history = %+v", hist)
	}
}

// approvalRequired asserts err is the -32032 answer and returns the id
// and the data object.
func approvalRequired(t *testing.T, err error) (string, map[string]any) {
	t.Helper()
	var je *jsonrpc.Error
	if !errors.As(err, &je) {
		t.Fatalf("err = %v (%T), want *jsonrpc.Error", err, err)
	}
	if je.Code != mcp.CodeApprovalRequired || !strings.Contains(je.Message, "approval required") {
		t.Fatalf("error = %d %q", je.Code, je.Message)
	}
	var data map[string]any
	if err := json.Unmarshal(je.Data, &data); err != nil {
		t.Fatalf("error data %s: %v", je.Data, err)
	}
	id, _ := data["approval_id"].(string)
	if id == "" || !strings.Contains(je.Message, id) {
		t.Fatalf("no approval id: %q %v", je.Message, data)
	}
	return id, data
}

// bearerClient adds Authorization to every request.
func bearerClient(token string) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		r = r.Clone(r.Context())
		r.Header.Set("Authorization", "Bearer "+token)
		return http.DefaultTransport.RoundTrip(r)
	})}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
