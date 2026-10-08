package approvals_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/approvals"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/fake"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// stubDecider confirms create_item and post_note, allows everything else
// in the fake app, and reports the policy version it is set to.
type stubDecider struct {
	versionID string
}

func (s *stubDecider) Decide(_ context.Context, in policy.Input) (policy.Decision, error) {
	d := policy.Decision{Outcome: policy.OutcomeAllow, Version: "hash-" + s.versionID, VersionID: s.versionID, Reason: "stub"}
	switch in.Tool.Name {
	case "create_item", "post_note":
		d.Outcome = policy.OutcomeConfirm
	}
	return d, nil
}

func (s *stubDecider) Visible(context.Context, policy.Input) (bool, error) { return true, nil }

// pipelineFixture is the policy stage with the real confirm handler over
// the fake connector and the in-memory approvals store.
type pipelineFixture struct {
	*fixture
	fake     *fake.Connector
	acct     connectors.Account
	decider  *stubDecider
	pipeline *mcp.Pipeline
}

func newPipeline(t *testing.T, wait time.Duration) *pipelineFixture {
	t.Helper()
	f := newFixture(t)
	keys, _ := crypto.NewStaticProvider("k1", map[string][]byte{"k1": bytes.Repeat([]byte{7}, 32)})
	svc, err := approvals.New(approvals.Config{TTL: 15 * time.Minute, Wait: wait, BaseURL: "https://gw.example.com/"}, f.st, keys, approvals.Options{
		Audit: f.audit, Metrics: f.metrics, Notifier: f.notifier, Log: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	// A real clock: the wait and the in-process wake-up are what is under test.
	f.svc = svc
	fc := fake.New(fake.Options{})
	acct := fc.SeedAccount(alice, connectors.Account{ID: acctA, Label: connectors.LabelCompany, DisplayName: "Work"})
	reg := connectors.NewRegistry()
	if err := connectors.RegisterConnector(reg, fc, fc.Accounts()); err != nil {
		t.Fatal(err)
	}
	d := &stubDecider{versionID: policyV1}
	p, err := mcp.DefaultPipeline(mcp.PipelineDeps{
		Registry: reg, Accounts: fc.Accounts(), Policy: d, Confirm: approvals.NewConfirmHandler(svc, nil, slog.New(slog.DiscardHandler)),
		Metrics: f.metrics, Log: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	return &pipelineFixture{fixture: f, fake: fc, acct: acct, decider: d, pipeline: p}
}

func (p *pipelineFixture) call(t *testing.T, tool string, args map[string]any) (*mcp.CallContext, connectors.Result, error) {
	t.Helper()
	cc := &mcp.CallContext{Principal: &tokens.Principal{UserID: alice, TokenID: "tok-1", PublicID: "pub1"}, Name: tool, RawArgs: args}
	res, err := p.pipeline.Run(t.Context(), cc)
	return cc, res, err
}

func toolErr(t *testing.T, err error) *mcp.ToolError {
	t.Helper()
	var te *mcp.ToolError
	if !errors.As(err, &te) {
		t.Fatalf("err = %v, want *mcp.ToolError", err)
	}
	return te
}

func TestConfirmWithoutApprovalCreatesOneAndAnswersApprovalRequired(t *testing.T) {
	p := newPipeline(t, 50*time.Millisecond)
	cc, _, err := p.call(t, "fake.create_item", map[string]any{"id": "it-1", "name": "first", "body": "SECRET"})
	te := toolErr(t, err)
	if te.Code != mcp.CodeApprovalRequired || te.Class() != "approval_required" || !strings.Contains(te.Message, "approval required") {
		t.Errorf("error = %d %q class %s", te.Code, te.Message, te.Class())
	}
	id, _ := te.Data["approval_id"].(string)
	if id == "" || cc.ApprovalID != id {
		t.Fatalf("approval_id missing: data=%v cc=%q", te.Data, cc.ApprovalID)
	}
	if te.Data["portal_url"] != "https://gw.example.com/approvals" {
		t.Errorf("portal_url = %v", te.Data["portal_url"])
	}
	if _, ok := te.Data["expires_at"].(string); !ok {
		t.Errorf("expires_at = %v", te.Data["expires_at"])
	}
	if instr, _ := te.Data["instructions"].(string); !strings.Contains(instr, "approval_id="+id) {
		t.Errorf("instructions = %q", instr)
	}
	if !strings.Contains(te.Message, id) {
		t.Errorf("message should name the id for harnesses that drop data: %q", te.Message)
	}
	a, err := p.svc.Get(t.Context(), alice, id)
	if err != nil || a.Status != approvals.StatusPending || a.Tool != "fake.create_item" || a.AccountID != acctA || a.AccountLabel != "company" || a.PolicyVersionID != policyV1 || a.TokenID != "tok-1" {
		t.Errorf("stored approval = %+v, %v", a, err)
	}
	if a.ResourceIdentity["id"] != "it-1" {
		t.Errorf("resource identity = %v", a.ResourceIdentity)
	}
	if len(p.fake.State().Items(acctA)) != 0 {
		t.Error("the tool ran without an approval")
	}
	if cc.Decision != "confirm" {
		t.Errorf("decision = %q", cc.Decision)
	}
}

func TestApprovedDuringTheWaitRunsInOneRoundTrip(t *testing.T) {
	p := newPipeline(t, 5*time.Second)
	go func() {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			pend, _ := p.svc.Pending(context.Background(), alice)
			if len(pend) == 1 {
				_, _ = p.svc.Approve(context.Background(), alice, pend[0].ID)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	start := time.Now()
	cc, res, err := p.call(t, "fake.create_item", map[string]any{"id": "it-1", "name": "first", "body": "SECRET"})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("took %v", time.Since(start))
	}
	items := p.fake.State().Items(acctA)
	if len(items) != 1 || items[0].Name != "first" || items[0].Body != "SECRET" {
		t.Errorf("items = %+v (result %+v)", items, res)
	}
	if cc.ApprovalID == "" {
		t.Error("ApprovalID not set on the call context")
	}
	if rec := p.st.Record(cc.ApprovalID); rec.Status != approvals.StatusConsumed || rec.Payload != nil {
		t.Errorf("approval after the call: %+v", rec)
	}
}

func TestRetryWithApprovalIDRunsTheStoredArgumentsOnce(t *testing.T) {
	p := newPipeline(t, 0)
	_, _, err := p.call(t, "fake.create_item", map[string]any{"id": "it-1", "name": "first", "body": "the original body"})
	te := toolErr(t, err)
	id := te.Data["approval_id"].(string)
	if _, err := p.svc.Approve(t.Context(), alice, id); err != nil {
		t.Fatal(err)
	}
	// The harness regenerates the arguments with drift and adds approval_id.
	cc, _, err := p.call(t, "fake.create_item", map[string]any{"id": "it-1", "name": "first (reworded)", "body": "a different body", "approval_id": id})
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	items := p.fake.State().Items(acctA)
	if len(items) != 1 || items[0].Name != "first" || items[0].Body != "the original body" {
		t.Errorf("the connector did not receive the stored arguments: %+v", items)
	}
	if cc.ApprovalID != id || cc.Call.Args["name"] != "first" {
		t.Errorf("cc = approval %q args %v", cc.ApprovalID, cc.Call.Args)
	}
	// Second use: refused, nothing runs.
	_, _, err = p.call(t, "fake.create_item", map[string]any{"id": "it-2", "name": "again", "approval_id": id})
	te = toolErr(t, err)
	if te.Code != mcp.CodeDenied || !strings.Contains(te.Message, "already used") || !te.Denial() {
		t.Errorf("second use = %d %q denial=%v", te.Code, te.Message, te.Denial())
	}
	if len(p.fake.State().Items(acctA)) != 1 {
		t.Error("the second use ran the tool")
	}
}

func TestRetryWithMismatchedApprovalIsDenied(t *testing.T) {
	p := newPipeline(t, 0)
	_, _, err := p.call(t, "fake.create_item", map[string]any{"id": "it-1", "name": "first"})
	id := toolErr(t, err).Data["approval_id"].(string)
	if _, err := p.svc.Approve(t.Context(), alice, id); err != nil {
		t.Fatal(err)
	}
	// Another confirmed tool with this approval.
	_, _, err = p.call(t, "fake.post_note", map[string]any{"text": "hi", "approval_id": id})
	te := toolErr(t, err)
	if te.Code != mcp.CodeDenied || te.Message != "approval does not match this call" {
		t.Errorf("tool mismatch = %d %q", te.Code, te.Message)
	}
	// Unknown id: same answer.
	_, _, err = p.call(t, "fake.create_item", map[string]any{"id": "it-1", "name": "first", "approval_id": "00000000-0000-4000-8000-000000000000"})
	te = toolErr(t, err)
	if te.Code != mcp.CodeDenied || te.Message != "approval does not match this call" {
		t.Errorf("unknown id = %d %q", te.Code, te.Message)
	}
	// A role change moved the policy version on: the approval no longer matches.
	p.decider.versionID = policyV2
	_, _, err = p.call(t, "fake.create_item", map[string]any{"id": "it-1", "name": "first", "approval_id": id})
	te = toolErr(t, err)
	if te.Code != mcp.CodeDenied || te.Message != "approval does not match this call" {
		t.Errorf("policy version mismatch = %d %q", te.Code, te.Message)
	}
	if len(p.fake.State().Items(acctA)) != 0 || len(p.fake.State().Notes(acctA)) != 0 {
		t.Error("a mismatched approval ran a tool")
	}
	// Back on the right version it is still usable: nothing consumed it.
	p.decider.versionID = policyV1
	if _, _, err := p.call(t, "fake.create_item", map[string]any{"id": "it-1", "name": "first", "approval_id": id}); err != nil {
		t.Errorf("valid retry after mismatches: %v", err)
	}
}

func TestDeniedAndExpiredApprovalsAreRefused(t *testing.T) {
	p := newPipeline(t, 0)
	_, _, err := p.call(t, "fake.create_item", map[string]any{"id": "it-1", "name": "first"})
	id := toolErr(t, err).Data["approval_id"].(string)
	if _, err := p.svc.Deny(t.Context(), alice, id); err != nil {
		t.Fatal(err)
	}
	_, _, err = p.call(t, "fake.create_item", map[string]any{"id": "it-1", "name": "first", "approval_id": id})
	te := toolErr(t, err)
	if te.Code != mcp.CodeDenied || !strings.Contains(te.Message, "denied") || !te.Denial() {
		t.Errorf("denied = %d %q", te.Code, te.Message)
	}
	// Expired: the clock is real here, so expire through the store.
	_, _, err = p.call(t, "fake.create_item", map[string]any{"id": "it-2", "name": "second"})
	id2 := toolErr(t, err).Data["approval_id"].(string)
	if _, err := p.svc.Approve(t.Context(), alice, id2); err != nil {
		t.Fatal(err)
	}
	p.svc.SetClock(func() time.Time { return time.Now().Add(time.Hour) })
	_, _, err = p.call(t, "fake.create_item", map[string]any{"id": "it-2", "name": "second", "approval_id": id2})
	te = toolErr(t, err)
	if te.Code != mcp.CodeDenied || !strings.Contains(te.Message, "expired") {
		t.Errorf("expired = %d %q", te.Code, te.Message)
	}
	if len(p.fake.State().Items(acctA)) != 0 {
		t.Error("a refused approval ran the tool")
	}
}

func TestRetryWhilePendingWaitsThenAnswersWithTheSameID(t *testing.T) {
	p := newPipeline(t, 50*time.Millisecond)
	_, _, err := p.call(t, "fake.create_item", map[string]any{"id": "it-1", "name": "first"})
	id := toolErr(t, err).Data["approval_id"].(string)
	// Retried too early: still the same approval, not a new one.
	_, _, err = p.call(t, "fake.create_item", map[string]any{"id": "it-1", "name": "first", "approval_id": id})
	te := toolErr(t, err)
	if te.Code != mcp.CodeApprovalRequired || te.Data["approval_id"] != id {
		t.Errorf("early retry = %d %v", te.Code, te.Data)
	}
	if p.st.Count() != 1 {
		t.Errorf("approvals = %d, want 1", p.st.Count())
	}
	// Approved while the retry waits.
	go func() {
		time.Sleep(10 * time.Millisecond)
		_, _ = p.svc.Approve(context.Background(), alice, id)
	}()
	cc, _, err := p.call(t, "fake.create_item", map[string]any{"id": "it-1", "name": "first", "approval_id": id})
	if err != nil {
		t.Fatalf("retry while approving: %v", err)
	}
	if cc.ApprovalID != id || len(p.fake.State().Items(acctA)) != 1 {
		t.Errorf("after retry: approval %q items %d", cc.ApprovalID, len(p.fake.State().Items(acctA)))
	}
}

func TestRetryWithoutIDMatchesAnApprovedDigest(t *testing.T) {
	p := newPipeline(t, 0)
	args := map[string]any{"id": "it-1", "name": "first", "tags": []any{"x"}}
	_, _, err := p.call(t, "fake.create_item", args)
	id := toolErr(t, err).Data["approval_id"].(string)
	if _, err := p.svc.Approve(t.Context(), alice, id); err != nil {
		t.Fatal(err)
	}
	// Same arguments (different key order is the same digest), no id.
	cc, _, err := p.call(t, "fake.create_item", map[string]any{"tags": []any{"x"}, "name": "first", "id": "it-1"})
	if err != nil {
		t.Fatalf("digest retry: %v", err)
	}
	if cc.ApprovalID != id || len(p.fake.State().Items(acctA)) != 1 {
		t.Errorf("digest retry: approval %q items %d", cc.ApprovalID, len(p.fake.State().Items(acctA)))
	}
	// Different arguments: a new approval.
	_, _, err = p.call(t, "fake.create_item", map[string]any{"id": "it-9", "name": "other"})
	te := toolErr(t, err)
	if te.Code != mcp.CodeApprovalRequired || te.Data["approval_id"] == id {
		t.Errorf("drifted retry = %d %v", te.Code, te.Data)
	}
}

func TestConfirmHandlerRequiresAnAccount(t *testing.T) {
	// Without an account stage the binding is incomplete; the handler must
	// fail closed rather than store an unbound approval.
	f := newFixture(t)
	h := approvals.NewConfirmHandler(f.svc, nil, slog.New(slog.DiscardHandler))
	tool := connectors.Tool{App: "fake", Name: "create_item", Kind: connectors.KindWrite}
	cc := &mcp.CallContext{Principal: &tokens.Principal{UserID: alice}, Name: "fake.create_item", Tool: &tool, PolicyVersion: policyV1, Call: connectors.Call{Tool: "fake.create_item", Args: map[string]any{}}}
	_, err := h.Confirm(t.Context(), cc, func(context.Context) (connectors.Result, error) {
		t.Fatal("next ran")
		return connectors.Result{}, nil
	})
	te := toolErr(t, err)
	if te.Code != mcp.CodeInternal {
		t.Errorf("no account = %d %q", te.Code, te.Message)
	}
	if f.st.Count() != 0 {
		t.Error("an unbound approval was stored")
	}
}

func TestMetricsCountTransitions(t *testing.T) {
	p := newPipeline(t, 0)
	_, _, err := p.call(t, "fake.create_item", map[string]any{"id": "it-1", "name": "first"})
	id := toolErr(t, err).Data["approval_id"].(string)
	_, _ = p.svc.Approve(t.Context(), alice, id)
	_, _, _ = p.call(t, "fake.create_item", map[string]any{"id": "it-1", "name": "first", "approval_id": id})
	rec := httptest.NewRecorder()
	p.metrics.Handler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))
	out := rec.Body.String()
	for _, want := range []string{`approvals_total{state="created"} 1`, `approvals_total{state="approved"} 1`, `approvals_total{state="consumed"} 1`} {
		if !strings.Contains(out, want) {
			t.Errorf("scrape missing %q", want)
		}
	}
}
