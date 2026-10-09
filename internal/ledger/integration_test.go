//go:build integration

package ledger_test

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
	"github.com/huynle/mcp-gateway/internal/ledger"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// The ledger integration tests run against their own database
// (gateway_ledger_test, created from GATEWAY_TEST_DATABASE_URL) so they
// never race the store package's TRUNCATE (quirk 01mepmn6). They need a
// superuser URL and give the two application roles a temporary LOGIN
// password, retrying the ALTER ROLE race (quirk aihn7hjb).

const (
	testDB      = "gateway_ledger_test"
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
		"TRUNCATE users, identities, sessions, roles, role_assignments, user_restrictions, policy_versions, tokens, vendor_apps, connections, approvals, ledger_operations, ledger_attempts, audit_events, job_locks CASCADE",
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
// confirming create_item (unconfirmed post_note and flaky_write), the
// approvals and ledger services over PostgreSQL, the fake connector whose
// accounts are the connection rows, /mcp with the ledger stage, and the
// deferred confirm handler.
type world struct {
	st       *store.Store
	rec      *audit.StoreRecorder
	policy   *policy.Service
	tokens   *tokens.Service
	approval *approvals.Service
	ledger   *ledger.Service
	notifier *memNotifier
	fake     *fake.Connector
	alice    string
	bob      string
	admin    string
	aliceAcc string
	bobAcc   string
	srv      *httptest.Server
	now      func() time.Time
	nowMu    sync.Mutex
	offset   time.Duration
}

func newWorld(t *testing.T) *world {
	t.Helper()
	st := openTestStore(t)
	ctx := t.Context()
	log := slog.New(slog.DiscardHandler)
	w := &world{st: st, notifier: &memNotifier{}}
	w.now = func() time.Time {
		w.nowMu.Lock()
		defer w.nowMu.Unlock()
		return time.Now().UTC().Add(w.offset)
	}

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
	w.approval, err = approvals.New(approvals.Config{TTL: 15 * time.Minute, Wait: 0, BaseURL: "http://localhost:18080"}, approvals.NewPostgresStore(st), keys, approvals.Options{
		Audit: w.rec, Metrics: metrics, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	w.approval.SetClock(w.now)

	w.fake = fake.New(fake.Options{})
	w.fake.SeedAccount(w.alice, connectors.Account{ID: w.aliceAcc, Label: connectors.LabelCompany, DisplayName: "Alice at work"})
	w.fake.SeedAccount(w.bob, connectors.Account{ID: w.bobAcc, Label: connectors.LabelPersonal, DisplayName: "Bob at home"})
	reg := connectors.NewRegistry()
	if err := connectors.RegisterConnector(reg, w.fake, w.fake.Accounts()); err != nil {
		t.Fatal(err)
	}
	lcfg := ledger.DefaultConfig()
	lcfg.BaseURL = "http://localhost:18080"
	w.ledger, err = ledger.New(lcfg, ledger.NewPostgresStore(st), ledger.Options{
		Approvals: w.approval.LedgerConsumer(), Registry: reg, Notifier: w.notifier, Audit: w.rec, Metrics: metrics, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	w.ledger.SetClock(w.now)

	confirm := approvals.NewConfirmHandler(w.approval, metrics, log)
	confirm.DeferConsumption(true)
	visibility := mcp.PolicyVisibility{Decider: w.policy, Log: log}
	pipeline, err := mcp.DefaultPipeline(mcp.PipelineDeps{
		Registry: reg, Visibility: visibility, Accounts: w.fake.Accounts(), Policy: w.policy, Confirm: confirm,
		Audit: w.rec, Metrics: metrics, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := pipeline.Insert(mcp.Before, mcp.StageRateLimit, mcp.LedgerStage(w.ledger, log)); err != nil {
		t.Fatal(err)
	}
	h, err := mcp.Handler(mcp.Options{
		Registry:      reg,
		Pipeline:      pipeline,
		Visibility:    visibility,
		Authenticator: w.tokens,
		Auth:          tokens.MiddlewareOptions{Limiter: tokens.NewFailureLimiter(tokens.DefaultFailureBurst, tokens.DefaultFailureWindow)},
		BaseURL:       "http://localhost:18080",
		Log:           log,
	})
	if err != nil {
		t.Fatal(err)
	}
	w.srv = httptest.NewServer(observability.RequestID(h))
	t.Cleanup(w.srv.Close)
	return w
}

func (w *world) advance(d time.Duration) {
	w.nowMu.Lock()
	defer w.nowMu.Unlock()
	w.offset += d
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

func (w *world) intent(user, acct string, args map[string]any) ledger.Intent {
	cur, _ := w.policy.Current(context.Background())
	return ledger.Intent{UserID: user, AccountID: acct, Tool: "fake.create_item", Digest: ledger.Digest(args), PolicyVersionID: cur.ID}
}

// row reads the raw operation through the bypass scope.
func (w *world) row(t *testing.T, id string) *store.LedgerOperation {
	t.Helper()
	var op *store.LedgerOperation
	err := w.st.WithJobs(t.Context(), func(tx store.Tx) error {
		var err error
		op, err = store.GetLedgerOperation(t.Context(), tx, id)
		return err
	})
	if err != nil {
		t.Fatalf("read operation %s: %v", id, err)
	}
	return op
}

func (w *world) ops(t *testing.T, user string) []store.LedgerOperation {
	t.Helper()
	var out []store.LedgerOperation
	err := w.st.WithJobs(t.Context(), func(tx store.Tx) error {
		var err error
		out, err = store.ListLedgerOperations(t.Context(), tx, store.LedgerFilter{UserID: user})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (w *world) approvalStatus(t *testing.T, id string) string {
	t.Helper()
	var status string
	err := w.st.WithJobs(t.Context(), func(tx store.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT status::text FROM approvals WHERE id = $1`, id).Scan(&status)
	})
	if err != nil {
		t.Fatalf("read approval %s: %v", id, err)
	}
	return status
}

func TestIntegrationConcurrentBeginYieldsOneInProgress(t *testing.T) {
	w := newWorld(t)
	ctx := t.Context()
	in := w.intent(w.alice, w.aliceAcc, map[string]any{"id": "it-race", "name": "n"})
	const n = 16
	var wg sync.WaitGroup
	start := make(chan struct{})
	ops := make([]*ledger.Operation, n)
	priors := make([]ledger.Prior, n)
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ops[i], priors[i], errs[i] = w.ledger.Begin(ctx, in)
		}()
	}
	close(start)
	wg.Wait()
	var inserted, pending int
	for i := range n {
		switch {
		case errs[i] != nil:
			t.Errorf("begin %d: %v", i, errs[i])
		case ops[i] != nil:
			inserted++
		case priors[i].Kind == ledger.PriorPending:
			pending++
		default:
			t.Errorf("begin %d: op=%v prior=%+v", i, ops[i], priors[i])
		}
	}
	if inserted != 1 || pending != n-1 {
		t.Errorf("inserted = %d, pending = %d (of %d)", inserted, pending, n)
	}
	if rows := w.ops(t, w.alice); len(rows) != 1 || rows[0].State != store.LedgerInProgress {
		t.Errorf("rows = %+v", rows)
	}
}

func TestIntegrationApprovalConsumeAndInsertCommitOrRollBackTogether(t *testing.T) {
	w := newWorld(t)
	ctx := t.Context()
	cur, _ := w.policy.Current(ctx)
	create := func(args map[string]any) string {
		a, err := w.approval.Create(ctx, approvals.Request{UserID: w.alice, AccountID: w.aliceAcc, AccountLabel: "company", Tool: "fake.create_item", Args: args, PolicyVersionID: cur.ID})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.approval.Approve(ctx, w.alice, a.ID); err != nil {
			t.Fatal(err)
		}
		return a.ID
	}
	// A failure after the consume (before the insert) rolls the consume
	// back: the approval is still approved and usable.
	id := create(map[string]any{"id": "it-tx", "name": "n"})
	ledger.SetAfterConsume(w.ledger, func() error { return errors.New("injected after consume") })
	in := w.intent(w.alice, w.aliceAcc, map[string]any{"id": "it-tx", "name": "n"})
	in.ApprovalID = id
	if _, _, err := w.ledger.Begin(ctx, in); err == nil || !strings.Contains(err.Error(), "injected") {
		t.Fatalf("begin with injected failure: %v", err)
	}
	if got := w.approvalStatus(t, id); got != "approved" {
		t.Errorf("approval after rolled-back begin = %s, want approved (payload intact)", got)
	}
	if rows := w.ops(t, w.alice); len(rows) != 0 {
		t.Errorf("rows after rolled-back begin = %+v", rows)
	}
	// Without the failure both land together.
	ledger.SetAfterConsume(w.ledger, nil)
	op, prior, err := w.ledger.Begin(ctx, in)
	if err != nil || prior.Kind != ledger.PriorNone || op == nil || op.ApprovalID != id || op.ApprovalArgs["name"] != "n" {
		t.Fatalf("begin: op=%+v prior=%+v err=%v", op, prior, err)
	}
	if got := w.approvalStatus(t, id); got != "consumed" {
		t.Errorf("approval after begin = %s", got)
	}
	if row := w.row(t, op.ID); row.State != store.LedgerInProgress || row.ApprovalID == nil || *row.ApprovalID != id || row.IdempotencyKey != ledger.ApprovalKey(id) {
		t.Errorf("row = %+v", row)
	}
	// An approval executes at most once, whatever the digest.
	if _, _, err := w.ledger.Begin(ctx, in); !errors.Is(err, approvals.ErrConsumed) {
		t.Errorf("second begin with the same approval: %v", err)
	}
	// Someone else's approval does not match (RLS hides it: not found).
	other := w.intent(w.bob, w.bobAcc, map[string]any{"id": "it-tx", "name": "n"})
	other.ApprovalID = create(map[string]any{"id": "it-bob", "name": "n"})
	if _, _, err := w.ledger.Begin(ctx, other); !errors.Is(err, approvals.ErrNotFound) {
		t.Errorf("bob with alice's approval: %v", err)
	}
}

func TestIntegrationEndToEndIdempotencyReplayAndPendingVerification(t *testing.T) {
	w := newWorld(t)
	ctx := t.Context()
	cs := w.client(t, w.alice)

	// An unconfirmed write (post_note) runs once; the same arguments inside
	// the window replay the stored result ids and never reach the app.
	args := map[string]any{"text": "LGTM"}
	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "fake.post_note", Arguments: args})
	if err != nil || res.IsError {
		t.Fatalf("first: err=%v res=%+v", err, res)
	}
	var note fake.Note
	if err := json.Unmarshal([]byte(text(t, res)), &note); err != nil {
		t.Fatal(err)
	}
	w.advance(time.Hour)
	res, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "fake.post_note", Arguments: args})
	if err != nil || res.IsError {
		t.Fatalf("duplicate: err=%v res=%+v", err, res)
	}
	var replay struct {
		Ledger      string            `json:"_ledger"`
		OperationID string            `json:"operation_id"`
		Result      map[string]string `json:"result"`
	}
	if err := json.Unmarshal([]byte(text(t, res)), &replay); err != nil {
		t.Fatal(err)
	}
	if replay.Ledger != "replayed" || replay.Result["id"] != note.ID || replay.OperationID == "" {
		t.Errorf("replay = %+v (note %s)", replay, note.ID)
	}
	if notes := w.fake.State().Notes(w.aliceAcc); len(notes) != 1 {
		t.Errorf("notes = %+v", notes)
	}
	// Outside the window: a new note.
	w.advance(24 * time.Hour)
	if res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "fake.post_note", Arguments: args}); err != nil || res.IsError {
		t.Fatalf("after window: err=%v res=%+v", err, res)
	}
	if notes := w.fake.State().Notes(w.aliceAcc); len(notes) != 2 {
		t.Errorf("notes after window = %d", len(notes))
	}
	// Bob with the same arguments: his own operation.
	bobCS := w.client(t, w.bob)
	if res, err := bobCS.CallTool(ctx, &sdk.CallToolParams{Name: "fake.post_note", Arguments: args}); err != nil || res.IsError {
		t.Fatalf("bob: err=%v res=%+v", err, res)
	}

	// A hung write leaves in_progress while it runs; a retry meanwhile is
	// "pending verification". Cutting the connection (what the drain
	// does at the end of the grace period) cancels the handler's context:
	// the connector reports the outcome unknown and the stage records it
	// even though the request context is gone.
	w.fake.InjectFault("flaky_write", fake.Fault{Mode: fake.FaultHang, Applied: true, Remaining: 1})
	hungArgs := map[string]any{"marker": "m-hung", "payload": "p"}
	hungCS := w.client(t, w.alice)
	done := make(chan error, 1)
	go func() {
		_, err := hungCS.CallTool(ctx, &sdk.CallToolParams{Name: "fake.flaky_write", Arguments: hungArgs})
		done <- err
	}()
	// The in_progress row exists before the connector runs: once it is
	// there the hung call owns the fault and any retry is a duplicate.
	var hungOp string
	deadline := time.Now().Add(5 * time.Second)
	for hungOp == "" && time.Now().Before(deadline) {
		for _, row := range w.ops(t, w.alice) {
			if row.Tool == "fake.flaky_write" && row.State == store.LedgerInProgress {
				hungOp = row.ID
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if hungOp == "" {
		t.Fatal("the hung write never recorded in_progress")
	}
	time.Sleep(50 * time.Millisecond) // let the hung call reach the connector
	_, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "fake.flaky_write", Arguments: hungArgs})
	var je *jsonrpc.Error
	if !errors.As(err, &je) || je.Code != mcp.CodePendingVerification {
		t.Fatalf("retry while hung: %v", err)
	}
	var data map[string]any
	_ = json.Unmarshal(je.Data, &data)
	if data["operation_id"] != hungOp || data["state"] != store.LedgerInProgress {
		t.Fatalf("pending verification data = %v, want operation %s", data, hungOp)
	}
	w.srv.CloseClientConnections()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the hung call did not return after its connection was cut")
	}
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && w.row(t, hungOp).State == store.LedgerInProgress {
		time.Sleep(50 * time.Millisecond)
	}
	if row := w.row(t, hungOp); row.State != store.LedgerUnknown || row.ErrorCode == nil || *row.ErrorCode != "outcome_unknown" {
		t.Fatalf("hung op after the cut = %+v", row)
	}
	// The reconciler finds the applied marker: succeeded, and a retry
	// replays it.
	w.advance(time.Minute)
	stats, err := w.ledger.Reconcile(ctx)
	if err != nil || stats.Succeeded != 1 {
		t.Fatalf("reconcile hung: stats=%+v err=%v", stats, err)
	}
	if row := w.row(t, hungOp); row.State != store.LedgerSucceeded || !strings.Contains(string(row.ResultIDs), "m-hung") {
		t.Errorf("hung after reconcile = %+v", row)
	}
	cs = w.client(t, w.alice) // the cut closed every client connection
	res, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "fake.flaky_write", Arguments: hungArgs})
	if err != nil || res.IsError || !strings.Contains(text(t, res), "replayed") {
		t.Errorf("retry after reconcile: err=%v res=%+v", err, res)
	}
}

func TestIntegrationEndToEndUnknownOutcomesReconcileOrSurface(t *testing.T) {
	w := newWorld(t)
	ctx := t.Context()
	cs := w.client(t, w.alice)

	// Reconcilable: create_item with the write applied but the reply lost.
	// Confirmed by policy, so approve first and retry with the id.
	_, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "fake.create_item", Arguments: map[string]any{"id": "it-lost", "name": "n"}})
	id := approvalRequired(t, err)
	if _, err := w.approval.Approve(ctx, w.alice, id); err != nil {
		t.Fatal(err)
	}
	w.fake.InjectFault("create_item", fake.Fault{Mode: fake.FaultUnknown, Applied: true, Remaining: 1})
	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "fake.create_item", Arguments: map[string]any{"id": "it-lost", "name": "n", "approval_id": id}})
	if err != nil || !res.IsError || !strings.Contains(text(t, res), "outcome unknown") {
		t.Fatalf("unknown write: err=%v res=%+v", err, res)
	}
	rows := w.ops(t, w.alice)
	if len(rows) != 1 || rows[0].State != store.LedgerUnknown || rows[0].ApprovalID == nil || *rows[0].ApprovalID != id || !strings.Contains(string(rows[0].Resource), "it-lost") {
		t.Fatalf("rows = %+v", rows)
	}
	createOp := rows[0].ID
	// The approval is used up: the harness cannot run it again, and the
	// user sees the operation on the page.
	_, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "fake.create_item", Arguments: map[string]any{"id": "it-lost", "name": "n", "approval_id": id}})
	if err == nil || !strings.Contains(err.Error(), "already used") {
		t.Errorf("retry with the used approval: %v", err)
	}

	// Non-reconcilable: post_note with the reply lost.
	w.fake.InjectFault("post_note", fake.Fault{Mode: fake.FaultUnknown, Applied: true, Remaining: 1})
	noteArgs := map[string]any{"text": "lost"}
	res, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "fake.post_note", Arguments: noteArgs})
	if err != nil || !res.IsError {
		t.Fatalf("unknown note: err=%v res=%+v", err, res)
	}
	// Meanwhile the same note is blocked.
	_, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "fake.post_note", Arguments: noteArgs})
	var je *jsonrpc.Error
	if !errors.As(err, &je) || je.Code != mcp.CodePendingVerification {
		t.Fatalf("note while unknown: %v", err)
	}

	// One reconciler run: the non-reconcilable one is unresolved at once
	// (user notified, audited); the reconcilable one is not due yet.
	stats, err := w.ledger.Reconcile(ctx)
	if err != nil || stats.Unresolved != 1 || stats.Checked != 0 {
		t.Fatalf("first run: stats=%+v err=%v", stats, err)
	}
	if n := w.notifier.count(); n != 1 || w.notifier.ops[0].Tool != "fake.post_note" || w.notifier.ops[0].UserID != w.alice {
		t.Errorf("notified = %+v", w.notifier.ops)
	}
	// The block is lifted: the note can be posted deliberately again.
	res, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "fake.post_note", Arguments: noteArgs})
	if err != nil || res.IsError {
		t.Errorf("note after unresolved: err=%v res=%+v", err, res)
	}
	if notes := w.fake.State().Notes(w.aliceAcc); len(notes) != 2 {
		t.Errorf("notes = %d, want the lost one and the deliberate retry", len(notes))
	}
	// A minute later the reconcilable one is checked and found.
	w.advance(time.Minute)
	stats, err = w.ledger.Reconcile(ctx)
	if err != nil || stats.Checked != 1 || stats.Succeeded != 1 {
		t.Fatalf("second run: stats=%+v err=%v", stats, err)
	}
	if row := w.row(t, createOp); row.State != store.LedgerSucceeded || !strings.Contains(string(row.ResultIDs), "it-lost") || row.FinishedAt == nil {
		t.Errorf("create op = %+v", row)
	}
	// Audit: the reconciler's verdicts and the replay are on the record,
	// never argument content.
	events, err := w.rec.ListForUser(ctx, w.alice, audit.Filter{}, audit.Page{})
	if err != nil {
		t.Fatal(err)
	}
	var unresolved, reconciled int
	for _, ev := range events {
		switch {
		case ev.Outcome == "unresolved":
			unresolved++
		case ev.OperationID == createOp && ev.Outcome == "succeeded" && ev.ErrorClass == "reconciled":
			reconciled++
		}
		if raw, _ := json.Marshal(ev); strings.Contains(string(raw), `"lost"`) {
			t.Errorf("argument content in audit: %s", raw)
		}
	}
	if unresolved != 1 || reconciled != 1 {
		t.Errorf("audit: unresolved=%d reconciled=%d", unresolved, reconciled)
	}
	// The operations page shows both with the hint.
	ops, err := w.ledger.Operations(ctx, w.alice, 10)
	if err != nil || len(ops) < 3 {
		t.Fatalf("operations = %d, %v", len(ops), err)
	}
	// Bob sees none of alice's.
	if ops, _ := w.ledger.Operations(ctx, w.bob, 10); len(ops) != 0 {
		t.Errorf("bob sees %d of alice's operations", len(ops))
	}
}

func TestIntegrationStaleSweepOnBackdatedInProgress(t *testing.T) {
	w := newWorld(t)
	ctx := t.Context()
	// A replica that died mid-call: an in_progress row created 10 minutes ago.
	op, prior, err := w.ledger.Begin(ctx, w.intent(w.alice, w.aliceAcc, map[string]any{"id": "it-dead", "name": "n"}))
	if err != nil || prior.Kind != ledger.PriorNone {
		t.Fatal(err)
	}
	err = w.st.WithJobs(ctx, func(tx store.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE ledger_operations SET created_at = now() - interval '10 minutes', updated_at = now() - interval '10 minutes' WHERE id = $1`, op.ID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	live, _, err := w.ledger.Begin(ctx, w.intent(w.alice, w.aliceAcc, map[string]any{"id": "it-live", "name": "n"}))
	if err != nil {
		t.Fatal(err)
	}
	n, err := w.ledger.SweepStale(ctx)
	if err != nil || n != 1 {
		t.Fatalf("sweep = %d, %v", n, err)
	}
	if row := w.row(t, op.ID); row.State != store.LedgerUnknown || row.ErrorCode == nil || *row.ErrorCode != ledger.ClassStale {
		t.Errorf("dead = %+v", row)
	}
	if row := w.row(t, live.ID); row.State != store.LedgerInProgress {
		t.Errorf("live = %+v", row)
	}
	// The dead one reconciles: create_item "it-dead" never happened in the
	// fake, so it is failed and the key is free again.
	w.advance(time.Minute)
	if stats, err := w.ledger.Reconcile(ctx); err != nil || stats.Failed != 1 {
		t.Fatalf("reconcile = %+v, %v", stats, err)
	}
	again, prior, err := w.ledger.Begin(ctx, w.intent(w.alice, w.aliceAcc, map[string]any{"id": "it-dead", "name": "n"}))
	if err != nil || prior.Kind != ledger.PriorNone || again == nil {
		t.Fatalf("after failed: op=%v prior=%+v err=%v", again, prior, err)
	}
	// Shutdown marks this replica's in-flight operations (live and the
	// retry) unknown; the dead one, already resolved, is untouched.
	if n, err := w.ledger.Shutdown(ctx); err != nil || n != 2 {
		t.Errorf("shutdown = %d, %v", n, err)
	}
	for _, id := range []string{live.ID, again.ID} {
		if row := w.row(t, id); row.State != store.LedgerUnknown || row.ErrorCode == nil || *row.ErrorCode != ledger.ClassShutdown {
			t.Errorf("%s after shutdown = %+v", id, row)
		}
	}
	if row := w.row(t, op.ID); row.State != store.LedgerFailed {
		t.Errorf("dead after shutdown = %+v", row)
	}
}

// approvalRequired asserts err is the -32005 answer and returns the id.
func approvalRequired(t *testing.T, err error) string {
	t.Helper()
	var je *jsonrpc.Error
	if !errors.As(err, &je) {
		t.Fatalf("err = %v (%T), want *jsonrpc.Error", err, err)
	}
	if je.Code != mcp.CodeApprovalRequired {
		t.Fatalf("error = %d %q", je.Code, je.Message)
	}
	var data map[string]any
	if err := json.Unmarshal(je.Data, &data); err != nil {
		t.Fatalf("error data %s: %v", je.Data, err)
	}
	id, _ := data["approval_id"].(string)
	if id == "" {
		t.Fatalf("no approval id: %q %v", je.Message, data)
	}
	return id
}

// text returns the first text block of a result.
func text(t *testing.T, res *sdk.CallToolResult) string {
	t.Helper()
	for _, c := range res.Content {
		if tc, ok := c.(*sdk.TextContent); ok {
			return tc.Text
		}
	}
	t.Fatalf("no text content in %+v", res)
	return ""
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
