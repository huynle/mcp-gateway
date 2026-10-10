package approvals_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/approvals"
	"github.com/huynle/mcp-gateway/internal/approvals/approvalstest"
	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/observability"
)

const (
	alice    = "11111111-1111-4111-8111-111111111111"
	bob      = "22222222-2222-4222-8222-222222222222"
	acctA    = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	acctB    = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	policyV1 = "99999999-9999-4999-8999-999999999991"
	policyV2 = "99999999-9999-4999-8999-999999999992"
)

// recordingAudit keeps every event it gets.
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

// recordingNotifier remembers what it was told.
type recordingNotifier struct {
	mu   sync.Mutex
	seen []approvals.Approval
	err  error
}

func (n *recordingNotifier) Notify(_ context.Context, a approvals.Approval) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.seen = append(n.seen, a)
	return n.err
}

type fixture struct {
	st       *approvalstest.MemStore
	svc      *approvals.Service
	audit    *recordingAudit
	notifier *recordingNotifier
	metrics  *observability.Metrics
	now      time.Time
	mu       sync.Mutex
}

func (f *fixture) clock() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *fixture) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	keys, err := crypto.NewStaticProvider("k1", map[string][]byte{"k1": bytes.Repeat([]byte{7}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{st: approvalstest.NewMemStore(), audit: &recordingAudit{}, notifier: &recordingNotifier{}, metrics: observability.NewMetrics(), now: time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)}
	svc, err := approvals.New(approvals.Config{TTL: 15 * time.Minute, Wait: 30 * time.Second, BaseURL: "https://gw.example.com"}, f.st, keys, approvals.Options{
		Audit: f.audit, Metrics: f.metrics, Notifier: f.notifier, Log: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetClock(f.clock)
	f.svc = svc
	return f
}

func (f *fixture) create(t *testing.T, args map[string]any) *approvals.Approval {
	t.Helper()
	a, err := f.svc.Create(t.Context(), approvals.Request{
		UserID: alice, TokenID: "tok-1", AccountID: acctA, AccountLabel: "company", Tool: "fake.create_item",
		Args: args, ResourceIdentity: map[string]string{"id": "it-1"}, PolicyVersionID: policyV1,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return a
}

func binding(id string) approvals.Binding {
	return approvals.Binding{UserID: alice, AccountID: acctA, Tool: "fake.create_item", PolicyVersionID: policyV1, ApprovalID: id}
}

var sampleArgs = map[string]any{"id": "it-1", "name": "first", "body": "SECRET BODY", "tags": []any{"a", "b"}}

func TestCreateStoresPendingEncryptedPayloadWithExpiry(t *testing.T) {
	f := newFixture(t)
	a := f.create(t, sampleArgs)
	if a.ID == "" || a.Status != approvals.StatusPending || a.UserID != alice || a.AccountID != acctA || a.Tool != "fake.create_item" || a.PolicyVersionID != policyV1 {
		t.Errorf("approval = %+v", a)
	}
	if !a.ExpiresAt.Equal(f.now.Add(15 * time.Minute)) {
		t.Errorf("ExpiresAt = %v, want %v", a.ExpiresAt, f.now.Add(15*time.Minute))
	}
	if !bytes.Equal(a.Digest, approvals.Digest(sampleArgs)) {
		t.Errorf("digest not canonical: %x", a.Digest)
	}
	if a.AccountLabel != "company" || a.ResourceIdentity["id"] != "it-1" || a.TokenID != "tok-1" {
		t.Errorf("metadata = %+v", a)
	}
	rec := f.st.Record(a.ID)
	if rec.Payload == nil || len(rec.Payload.Ciphertext) == 0 || rec.Payload.KeyID != "k1" {
		t.Fatalf("payload not stored encrypted: %+v", rec.Payload)
	}
	if bytes.Contains(rec.Payload.Ciphertext, []byte("SECRET")) {
		t.Error("plaintext argument in the payload column")
	}
	if len(f.notifier.seen) != 1 || f.notifier.seen[0].ID != a.ID {
		t.Errorf("notifier saw %+v", f.notifier.seen)
	}
	got, err := f.svc.Get(t.Context(), alice, a.ID)
	if err != nil || got.ID != a.ID || !got.HasPayload {
		t.Errorf("Get = %+v, %v", got, err)
	}
	if _, err := f.svc.Get(t.Context(), bob, a.ID); !errors.Is(err, approvals.ErrNotFound) {
		t.Errorf("Get as bob: err = %v, want ErrNotFound", err)
	}
}

func TestCreateRequiresTheBindingFields(t *testing.T) {
	f := newFixture(t)
	for name, req := range map[string]approvals.Request{
		"user":    {AccountID: acctA, Tool: "fake.create_item", PolicyVersionID: policyV1},
		"account": {UserID: alice, Tool: "fake.create_item", PolicyVersionID: policyV1},
		"tool":    {UserID: alice, AccountID: acctA, PolicyVersionID: policyV1},
		"policy":  {UserID: alice, AccountID: acctA, Tool: "fake.create_item"},
	} {
		if _, err := f.svc.Create(t.Context(), req); !errors.Is(err, approvals.ErrInvalid) {
			t.Errorf("%s missing: err = %v, want ErrInvalid", name, err)
		}
	}
}

func TestNotifierFailureDoesNotFailCreate(t *testing.T) {
	f := newFixture(t)
	f.notifier.err = errors.New("slack down")
	a := f.create(t, sampleArgs)
	if a.Status != approvals.StatusPending {
		t.Errorf("status = %s", a.Status)
	}
}

func TestMultiNotifierFansOutAndJoinsErrors(t *testing.T) {
	n1, n2 := &recordingNotifier{}, &recordingNotifier{err: errors.New("n2 failed")}
	m := approvals.MultiNotifier{approvals.PortalNotifier{}, n1, n2}
	err := m.Notify(context.Background(), approvals.Approval{ID: "x"})
	if err == nil || !errors.Is(err, n2.err) {
		t.Errorf("err = %v", err)
	}
	if len(n1.seen) != 1 || len(n2.seen) != 1 {
		t.Errorf("fan-out: n1=%d n2=%d", len(n1.seen), len(n2.seen))
	}
}

func TestApproveKeepsPayloadAndDenyNullsIt(t *testing.T) {
	f := newFixture(t)
	a := f.create(t, sampleArgs)
	f.advance(time.Minute)
	got, err := f.svc.Approve(t.Context(), alice, a.ID)
	if err != nil || got.Status != approvals.StatusApproved || got.DecidedAt == nil || !got.DecidedAt.Equal(f.now) {
		t.Fatalf("Approve = %+v, %v", got, err)
	}
	if f.st.Record(a.ID).Payload == nil {
		t.Error("approve dropped the payload; the stored arguments must survive until consumption")
	}
	// Already decided: not pending any more.
	if _, err := f.svc.Approve(t.Context(), alice, a.ID); !errors.Is(err, approvals.ErrNotPending) {
		t.Errorf("second approve: err = %v", err)
	}
	if _, err := f.svc.Deny(t.Context(), alice, a.ID); !errors.Is(err, approvals.ErrNotPending) {
		t.Errorf("deny after approve: err = %v", err)
	}

	b := f.create(t, sampleArgs)
	got, err = f.svc.Deny(t.Context(), alice, b.ID)
	if err != nil || got.Status != approvals.StatusDenied {
		t.Fatalf("Deny = %+v, %v", got, err)
	}
	if f.st.Record(b.ID).Payload != nil {
		t.Error("deny left the payload in place")
	}
	// Someone else's approval does not exist for bob.
	c := f.create(t, sampleArgs)
	if _, err := f.svc.Approve(t.Context(), bob, c.ID); !errors.Is(err, approvals.ErrNotFound) {
		t.Errorf("approve as bob: err = %v", err)
	}
	if f.st.Record(c.ID).Status != approvals.StatusPending {
		t.Error("bob changed alice's approval")
	}
	// An expired approval cannot be decided.
	d := f.create(t, sampleArgs)
	f.advance(16 * time.Minute)
	if _, err := f.svc.Approve(t.Context(), alice, d.ID); !errors.Is(err, approvals.ErrNotPending) {
		t.Errorf("approve after expiry: err = %v", err)
	}

	// Approve and deny are user audit events.
	var actions []string
	for _, ev := range f.audit.all() {
		if ev.UserID == alice && ev.ApprovalID != "" {
			actions = append(actions, ev.ResourceIdentity["action"]+":"+ev.ApprovalID+":"+ev.ResourceIdentity["tool"])
		}
	}
	want := []string{"approval_approved:" + a.ID + ":fake.create_item", "approval_denied:" + b.ID + ":fake.create_item"}
	if len(actions) != 2 || actions[0] != want[0] || actions[1] != want[1] {
		t.Errorf("audit actions = %v, want %v", actions, want)
	}
}

func TestConsumeReturnsStoredArgsExactlyOnce(t *testing.T) {
	f := newFixture(t)
	a := f.create(t, sampleArgs)
	if _, err := f.svc.ConsumeNow(t.Context(), binding(a.ID)); !errors.Is(err, approvals.ErrPending) {
		t.Fatalf("consume while pending: err = %v", err)
	}
	if _, err := f.svc.Approve(t.Context(), alice, a.ID); err != nil {
		t.Fatal(err)
	}
	got, err := f.svc.ConsumeNow(t.Context(), binding(a.ID))
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if got.ID != a.ID || got.Args["body"] != "SECRET BODY" || got.Args["name"] != "first" {
		t.Errorf("consumed = %+v", got)
	}
	if tags, ok := got.Args["tags"].([]any); !ok || len(tags) != 2 {
		t.Errorf("nested args lost: %+v", got.Args["tags"])
	}
	rec := f.st.Record(a.ID)
	if rec.Status != approvals.StatusConsumed || rec.ConsumedAt == nil || rec.Payload != nil {
		t.Errorf("after consume: %+v", rec)
	}
	if _, err := f.svc.ConsumeNow(t.Context(), binding(a.ID)); !errors.Is(err, approvals.ErrConsumed) {
		t.Errorf("second consume: err = %v, want ErrConsumed", err)
	}
}

func TestConsumeRejectsBindingMismatch(t *testing.T) {
	f := newFixture(t)
	a := f.create(t, sampleArgs)
	if _, err := f.svc.Approve(t.Context(), alice, a.ID); err != nil {
		t.Fatal(err)
	}
	cases := map[string]approvals.Binding{
		"account": {UserID: alice, AccountID: acctB, Tool: "fake.create_item", PolicyVersionID: policyV1, ApprovalID: a.ID},
		"tool":    {UserID: alice, AccountID: acctA, Tool: "fake.post_note", PolicyVersionID: policyV1, ApprovalID: a.ID},
		"policy":  {UserID: alice, AccountID: acctA, Tool: "fake.create_item", PolicyVersionID: policyV2, ApprovalID: a.ID},
	}
	for name, b := range cases {
		if _, err := f.svc.ConsumeNow(t.Context(), b); !errors.Is(err, approvals.ErrMismatch) {
			t.Errorf("%s mismatch: err = %v, want ErrMismatch", name, err)
		}
	}
	// Another user: the row is not visible, so it is simply not found.
	other := binding(a.ID)
	other.UserID = bob
	if _, err := f.svc.ConsumeNow(t.Context(), other); !errors.Is(err, approvals.ErrNotFound) {
		t.Errorf("bob: err = %v, want ErrNotFound", err)
	}
	if _, err := f.svc.ConsumeNow(t.Context(), binding("00000000-0000-4000-8000-000000000000")); !errors.Is(err, approvals.ErrNotFound) {
		t.Errorf("unknown id: err = %v, want ErrNotFound", err)
	}
	// None of the above consumed it.
	if got, err := f.svc.ConsumeNow(t.Context(), binding(a.ID)); err != nil || got.Args["name"] != "first" {
		t.Errorf("valid consume after mismatches: %+v, %v", got, err)
	}
}

func TestConsumeDeniedAndExpired(t *testing.T) {
	f := newFixture(t)
	d := f.create(t, sampleArgs)
	if _, err := f.svc.Deny(t.Context(), alice, d.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ConsumeNow(t.Context(), binding(d.ID)); !errors.Is(err, approvals.ErrDenied) {
		t.Errorf("denied: err = %v", err)
	}
	e := f.create(t, sampleArgs)
	if _, err := f.svc.Approve(t.Context(), alice, e.ID); err != nil {
		t.Fatal(err)
	}
	f.advance(16 * time.Minute)
	if _, err := f.svc.ConsumeNow(t.Context(), binding(e.ID)); !errors.Is(err, approvals.ErrExpired) {
		t.Errorf("expired: err = %v", err)
	}
	// The sweep, not the failed consume, drops the payload: a consume runs
	// inside the caller's transaction, which rolls back on error.
	if f.st.Record(e.ID).Payload == nil {
		t.Error("a failed consume mutated the row")
	}
	if n, err := f.svc.Expire(t.Context()); err != nil || n != 1 {
		t.Fatalf("Expire = %d, %v", n, err)
	}
	if rec := f.st.Record(e.ID); rec.Payload != nil || rec.Status != approvals.StatusExpired {
		t.Errorf("after the sweep: %+v", rec)
	}
}

func TestConsumeByDigestFindsAnApprovedMatch(t *testing.T) {
	f := newFixture(t)
	a := f.create(t, sampleArgs)
	byDigest := approvals.Binding{UserID: alice, AccountID: acctA, Tool: "fake.create_item", PolicyVersionID: policyV1, Digest: approvals.Digest(sampleArgs)}
	if _, err := f.svc.ConsumeNow(t.Context(), byDigest); !errors.Is(err, approvals.ErrNotFound) {
		t.Errorf("pending by digest: err = %v, want ErrNotFound", err)
	}
	if _, err := f.svc.Approve(t.Context(), alice, a.ID); err != nil {
		t.Fatal(err)
	}
	drift := approvals.Binding{UserID: alice, AccountID: acctA, Tool: "fake.create_item", PolicyVersionID: policyV1, Digest: approvals.Digest(map[string]any{"id": "other"})}
	if _, err := f.svc.ConsumeNow(t.Context(), drift); !errors.Is(err, approvals.ErrNotFound) {
		t.Errorf("different digest: err = %v", err)
	}
	got, err := f.svc.ConsumeNow(t.Context(), byDigest)
	if err != nil || got.ID != a.ID {
		t.Fatalf("by digest: %+v, %v", got, err)
	}
	if _, err := f.svc.ConsumeNow(t.Context(), byDigest); !errors.Is(err, approvals.ErrNotFound) {
		t.Errorf("by digest again: err = %v", err)
	}
}

func TestWaitReturnsWhenDecidedOrTimesOut(t *testing.T) {
	f := newFixture(t)
	a := f.create(t, sampleArgs)
	// Decided during the wait: returns at once (in-process wake-up).
	go func() {
		time.Sleep(50 * time.Millisecond)
		_, _ = f.svc.Approve(context.Background(), alice, a.ID)
	}()
	start := time.Now()
	status, err := f.svc.Wait(t.Context(), alice, a.ID, 5*time.Second)
	if err != nil || status != approvals.StatusApproved {
		t.Fatalf("Wait = %s, %v", status, err)
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("wait took %v; the approve should have woken it", time.Since(start))
	}
	// Timeout: still pending.
	b := f.create(t, sampleArgs)
	status, err = f.svc.Wait(t.Context(), alice, b.ID, 100*time.Millisecond)
	if err != nil || status != approvals.StatusPending {
		t.Errorf("Wait timeout = %s, %v", status, err)
	}
	// Already decided before the wait: returns immediately.
	c := f.create(t, sampleArgs)
	if _, err := f.svc.Deny(t.Context(), alice, c.ID); err != nil {
		t.Fatal(err)
	}
	status, err = f.svc.Wait(t.Context(), alice, c.ID, 5*time.Second)
	if err != nil || status != approvals.StatusDenied {
		t.Errorf("Wait decided = %s, %v", status, err)
	}
	// Caller's context cancelled: the error is the context's.
	d := f.create(t, sampleArgs)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := f.svc.Wait(ctx, alice, d.ID, 5*time.Second); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled wait: err = %v", err)
	}
}

func TestPendingListsDecryptedSummariesAndHistoryOmitsPayload(t *testing.T) {
	f := newFixture(t)
	long := map[string]any{"id": "it-1", "name": string(bytes.Repeat([]byte("x"), 300)), "nested": map[string]any{"k": []any{1.0, 2.0}}, "flag": true}
	a := f.create(t, long)
	f.advance(time.Second)
	b := f.create(t, sampleArgs)
	if _, err := f.svc.Approve(t.Context(), alice, b.ID); err != nil {
		t.Fatal(err)
	}
	pending, err := f.svc.Pending(t.Context(), alice)
	if err != nil || len(pending) != 1 || pending[0].ID != a.ID {
		t.Fatalf("Pending = %+v, %v", pending, err)
	}
	fields := map[string]string{}
	for _, fld := range pending[0].Summary {
		fields[fld.Key] = fld.Value
	}
	if len(fields["name"]) >= 300 || fields["id"] != "it-1" || fields["flag"] != "true" || fields["nested"] != `{"k":[1,2]}` {
		t.Errorf("summary = %+v", fields)
	}
	if pending[0].Summary[0].Key != "flag" { // sorted keys
		t.Errorf("summary order = %+v", pending[0].Summary)
	}
	if _, err := f.svc.Pending(t.Context(), bob); err != nil || len(mustPending(t, f, bob)) != 0 {
		t.Errorf("bob sees alice's pending approvals")
	}
	hist, err := f.svc.History(t.Context(), alice, 50)
	if err != nil || len(hist) != 2 {
		t.Fatalf("History = %+v, %v", hist, err)
	}
	if hist[0].ID != b.ID || hist[0].Status != approvals.StatusApproved {
		t.Errorf("history order/newest first = %+v", hist)
	}
}

func mustPending(t *testing.T, f *fixture, user string) []approvals.Pending {
	t.Helper()
	p, err := f.svc.Pending(t.Context(), user)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestExpireMarksRowsAndNullsPayloads(t *testing.T) {
	f := newFixture(t)
	a := f.create(t, sampleArgs)
	b := f.create(t, sampleArgs)
	if _, err := f.svc.Approve(t.Context(), alice, b.ID); err != nil {
		t.Fatal(err)
	}
	f.advance(10 * time.Minute)
	c := f.create(t, sampleArgs)
	f.advance(6 * time.Minute)
	n, err := f.svc.Expire(t.Context())
	if err != nil || n != 2 {
		t.Fatalf("Expire = %d, %v", n, err)
	}
	for _, id := range []string{a.ID, b.ID} {
		if rec := f.st.Record(id); rec.Status != approvals.StatusExpired || rec.Payload != nil {
			t.Errorf("%s after expiry: %+v", id, rec)
		}
	}
	if rec := f.st.Record(c.ID); rec.Status != approvals.StatusPending || rec.Payload == nil {
		t.Errorf("unexpired approval touched: %+v", rec)
	}
	job := f.svc.ExpiryJob(time.Second)
	if job.Name() != "approvals.expire" || job.Interval() != time.Second {
		t.Errorf("job = %s/%v", job.Name(), job.Interval())
	}
	f.advance(10 * time.Minute)
	if err := job.Run(t.Context()); err != nil || f.st.Record(c.ID).Status != approvals.StatusExpired {
		t.Errorf("job run: %v, status %s", err, f.st.Record(c.ID).Status)
	}
}

func TestConfigFromEnv(t *testing.T) {
	env := map[string]string{}
	get := func(k string) string { return env[k] }
	cfg, err := approvals.ConfigFromEnv(get)
	if err != nil || cfg.TTL != approvals.DefaultTTL || cfg.Wait != approvals.DefaultWait {
		t.Errorf("defaults = %+v, %v", cfg, err)
	}
	env["GATEWAY_APPROVAL_TTL"] = "1h"
	env["GATEWAY_APPROVAL_WAIT"] = "5s"
	cfg, err = approvals.ConfigFromEnv(get)
	if err != nil || cfg.TTL != time.Hour || cfg.Wait != 5*time.Second {
		t.Errorf("set = %+v, %v", cfg, err)
	}
	env["GATEWAY_APPROVAL_WAIT"] = "2h"
	if _, err := approvals.ConfigFromEnv(get); err == nil {
		t.Error("wait longer than ttl accepted")
	}
	env["GATEWAY_APPROVAL_WAIT"] = "nope"
	if _, err := approvals.ConfigFromEnv(get); err == nil {
		t.Error("bad duration accepted")
	}
}
