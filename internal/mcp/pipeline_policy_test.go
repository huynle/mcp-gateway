package mcp_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/fake"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/policy/policytest"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// stubDecider answers from a table keyed by tool name and records the
// inputs it saw.
type stubDecider struct {
	outcomes map[string]policy.Outcome
	err      error
	inputs   []policy.Input
}

func (s *stubDecider) Decide(_ context.Context, in policy.Input) (policy.Decision, error) {
	s.inputs = append(s.inputs, in)
	if s.err != nil {
		return policy.Decision{Outcome: policy.OutcomeDeny}, s.err
	}
	o, ok := s.outcomes[in.Tool.FullName()]
	if !ok {
		o = policy.OutcomeHidden
	}
	return policy.Decision{Outcome: o, Version: "v1", VersionID: "11111111-1111-1111-1111-111111111111", Reason: "stub"}, nil
}

func (s *stubDecider) Visible(_ context.Context, in policy.Input) (bool, error) {
	if s.err != nil {
		return false, s.err
	}
	o := s.outcomes[in.Tool.FullName()]
	return o == policy.OutcomeAllow || o == policy.OutcomeConfirm || o == policy.OutcomeDeny, nil
}

func policyPipeline(t *testing.T, d mcp.Decider, confirm mcp.ConfirmHandler) *mcp.Pipeline {
	t.Helper()
	reg := connectors.NewRegistry()
	echo := func(_ context.Context, call connectors.Call) (connectors.Result, error) {
		return connectors.Result{Content: "ran " + call.Tool}, nil
	}
	for _, name := range []string{"list_issues", "create_issue", "merge_pr", "delete_repo"} {
		kind := connectors.KindWrite
		if name == "list_issues" {
			kind = connectors.KindRead
		}
		tool := stubTool("github", name, kind)
		tool.Handler = echo
		tool.ResourceIdentity = func(args map[string]any) map[string]string {
			if r, _ := args["repo"].(string); r != "" {
				return map[string]string{"repo": r}
			}
			return nil
		}
		if err := reg.Register(tool); err != nil {
			t.Fatal(err)
		}
	}
	p, err := mcp.DefaultPipeline(mcp.PipelineDeps{Registry: reg, Policy: d, Confirm: confirm, Visibility: mcp.PolicyVisibility{Decider: d}, Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func run(t *testing.T, p *mcp.Pipeline, name string, args map[string]any) (*mcp.CallContext, connectors.Result, error) {
	t.Helper()
	cc := &mcp.CallContext{Principal: &tokens.Principal{UserID: "user-1", TokenID: "token-1", Scope: tokens.Scope{ReadOnly: false}}, Name: name, RawArgs: args}
	res, err := p.Run(t.Context(), cc)
	return cc, res, err
}

func TestPolicyStageOrderAndOutcomes(t *testing.T) {
	d := &stubDecider{outcomes: map[string]policy.Outcome{
		"github.list_issues":  policy.OutcomeAllow,
		"github.create_issue": policy.OutcomeConfirm,
		"github.merge_pr":     policy.OutcomeDeny,
		"github.delete_repo":  policy.OutcomeHidden,
	}}
	p := policyPipeline(t, d, nil)
	if names := strings.Join(p.Names(), ","); names != "authenticate,audit,resolve,strip,policy,ratelimit,dispatch" {
		t.Errorf("stages = %s", names)
	}

	cc, res, err := run(t, p, "github.list_issues", map[string]any{"repo": "acme/web"})
	if err != nil || res.Content != "ran github.list_issues" {
		t.Fatalf("allow: res=%+v err=%v", res, err)
	}
	if cc.Decision != "allow" || cc.PolicyVersion != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("allow context: decision=%q version=%q", cc.Decision, cc.PolicyVersion)
	}
	in := d.inputs[len(d.inputs)-1]
	if in.UserID != "user-1" || in.TokenID != "token-1" || in.Tool.FullName() != "github.list_issues" || in.ResourceIdentity["repo"] != "acme/web" {
		t.Errorf("decider input = %+v", in)
	}

	cc, _, err = run(t, p, "github.create_issue", nil)
	var te *mcp.ToolError
	if !errors.As(err, &te) || te.Code != mcp.CodeApprovalRequired || te.Message != "approval required" {
		t.Fatalf("confirm: err = %v", err)
	}
	if cc.Decision != "confirm" {
		t.Errorf("confirm decision = %q", cc.Decision)
	}

	cc, _, err = run(t, p, "github.merge_pr", nil)
	if !errors.As(err, &te) || te.Code != mcp.CodeDenied || !te.Denial() {
		t.Fatalf("deny: err = %v", err)
	}
	if cc.Decision != "deny" {
		t.Errorf("deny decision = %q", cc.Decision)
	}

	// Hidden: resolve already answers not-found (visibility), and even a
	// decider that says hidden at call time yields the very same error.
	_, _, err = run(t, p, "github.delete_repo", nil)
	if !errors.As(err, &te) || te.Code != mcp.CodeToolNotFound || te.Message != mcp.ErrToolNotFound("github.delete_repo").Message || te.Class() != "tool_not_found" {
		t.Fatalf("hidden: err = %v", err)
	}
	_, _, err = run(t, p, "github.nope", nil)
	if !errors.As(err, &te) || te.Message != mcp.ErrToolNotFound("github.nope").Message {
		t.Fatalf("unknown: err = %v", err)
	}
	// A decider that hides at call time what visibility showed (the
	// second line of defence): the same not-found, decision hidden.
	d2 := visibleButHidden{&stubDecider{outcomes: map[string]policy.Outcome{"github.list_issues": policy.OutcomeHidden}}}
	p2 := policyPipeline(t, d2, nil)
	cc, _, err = run(t, p2, "github.list_issues", nil)
	if !errors.As(err, &te) || te.Message != mcp.ErrToolNotFound("github.list_issues").Message || cc.Decision != "hidden" {
		t.Fatalf("hidden at call: err = %v decision=%q", err, cc.Decision)
	}
}

type visibleButHidden struct{ *stubDecider }

func (v visibleButHidden) Visible(context.Context, policy.Input) (bool, error) { return true, nil }

func TestPolicyStageFailsClosedWhenPolicyUnavailable(t *testing.T) {
	d := &stubDecider{outcomes: map[string]policy.Outcome{"github.list_issues": policy.OutcomeAllow}, err: errors.New("db down")}
	p := policyPipeline(t, d, nil)
	_, _, err := run(t, p, "github.list_issues", nil)
	var te *mcp.ToolError
	// Visibility fails closed first: the tool does not exist for the caller.
	if !errors.As(err, &te) || te.Code != mcp.CodeToolNotFound {
		t.Fatalf("err = %v", err)
	}
	// With visibility bypassed, the stage itself refuses with an internal error
	// that never carries the cause.
	reg := connectors.NewRegistry()
	tool := stubTool("github", "list_issues", connectors.KindRead)
	tool.Handler = func(context.Context, connectors.Call) (connectors.Result, error) {
		return connectors.Result{Content: "ran"}, nil
	}
	if err := reg.Register(tool); err != nil {
		t.Fatal(err)
	}
	p, err = mcp.DefaultPipeline(mcp.PipelineDeps{Registry: reg, Policy: d, Visibility: allVisible{}, Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	cc, _, err := run(t, p, "github.list_issues", nil)
	if !errors.As(err, &te) || te.Code != mcp.CodeInternal || strings.Contains(te.Message, "db down") || cc.Decision != "deny" {
		t.Fatalf("policy unavailable: err = %v decision=%q", err, cc.Decision)
	}
}

type allVisible struct{}

func (allVisible) Visible(context.Context, *tokens.Principal, connectors.Tool) bool { return true }

func TestConfirmHandlerHook(t *testing.T) {
	d := &stubDecider{outcomes: map[string]policy.Outcome{"github.create_issue": policy.OutcomeConfirm}}
	var seen *mcp.CallContext
	custom := mcp.ConfirmHandlerFunc(func(ctx context.Context, cc *mcp.CallContext, next mcp.Next) (connectors.Result, error) {
		seen = cc
		cc.ApprovalID = "appr-1"
		return next(ctx)
	})
	p := policyPipeline(t, d, custom)
	cc, res, err := run(t, p, "github.create_issue", nil)
	if err != nil || res.Content != "ran github.create_issue" || seen != cc || cc.ApprovalID != "appr-1" || cc.Decision != "confirm" {
		t.Errorf("custom confirm handler: res=%+v err=%v seen=%v cc=%+v", res, err, seen == cc, cc)
	}
	// The default is the hook's zero value.
	if _, err := mcp.DefaultConfirmHandler().Confirm(context.Background(), &mcp.CallContext{}, nil); !errors.Is(err, mcp.ErrApprovalRequired) {
		t.Errorf("default handler err = %v", err)
	}
}

func TestPolicyVisibilityFailsClosed(t *testing.T) {
	d := &stubDecider{outcomes: map[string]policy.Outcome{"github.list_issues": policy.OutcomeAllow, "github.merge_pr": policy.OutcomeDeny, "github.delete_repo": policy.OutcomeHidden}}
	v := mcp.PolicyVisibility{Decider: d}
	pr := &tokens.Principal{UserID: "u", TokenID: "t"}
	if !v.Visible(context.Background(), pr, stubTool("github", "list_issues", connectors.KindRead)) {
		t.Error("allowed tool hidden")
	}
	if !v.Visible(context.Background(), pr, stubTool("github", "merge_pr", connectors.KindWrite)) {
		t.Error("conditionally denied tool hidden")
	}
	if v.Visible(context.Background(), pr, stubTool("github", "delete_repo", connectors.KindWrite)) {
		t.Error("hidden tool visible")
	}
	if v.Visible(context.Background(), nil, stubTool("github", "list_issues", connectors.KindRead)) {
		t.Error("nil principal sees tools")
	}
	d.err = errors.New("db down")
	if v.Visible(context.Background(), pr, stubTool("github", "list_issues", connectors.KindRead)) {
		t.Error("visible while the policy is unavailable")
	}
}

// TestPolicyEndToEndWithFakeConnector drives the real policy service over
// the fake connector through the SDK client: a hidden tool is absent from
// tools/list and a call to it is byte-identical to an unknown tool; a
// confirm tool answers approval required; a role change (new version)
// takes effect at once and a stub approval bound to the old version no
// longer matches.
func TestPolicyEndToEndWithFakeConnector(t *testing.T) {
	f := fake.New(fake.Options{})
	f.SeedAccount("user-1", connectors.Account{ID: connectors.NewAccountID(), Label: connectors.LabelCompany, DisplayName: "Work"})
	f.SeedAccount("user-2", connectors.Account{ID: connectors.NewAccountID(), Label: connectors.LabelPersonal, DisplayName: "Home"})
	reg := connectors.NewRegistry()
	if err := connectors.RegisterConnector(reg, f, f.Accounts()); err != nil {
		t.Fatal(err)
	}
	st := policytest.NewMemStore()
	st.PutRole(policy.Role{Name: "member", Rules: []policy.ToolRule{
		{App: "fake", Tool: "*", Outcome: policy.OutcomeAllow},
		{App: "fake", Tool: "create_item", Outcome: policy.OutcomeHidden},
		{App: "fake", Tool: "post_note", Outcome: policy.OutcomeConfirm},
		{App: "fake", Tool: "get_item", Outcome: policy.OutcomeDeny, Conditions: []policy.Condition{{Key: "id", Op: policy.OpPrefix, Value: "secret-"}}},
	}, PersonalAccounts: map[string]policy.Allowance{"fake": policy.AllowanceConfirmWrites}})
	st.PutRole(policy.Role{Name: "admin"})
	st.Assign("user-1", "member")
	st.Assign("user-2", "member")
	st.Assign("user-2", "admin")
	svc, err := policy.New(st, policy.Options{Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	// user-2's token is read-only (readOnlyToken) and is also an admin:
	// neither widens anything.
	srv := httptest.NewServer(newHandler(t, reg, func(o *mcp.Options) {
		o.Accounts = f.Accounts()
		o.Policy = svc
		o.Visibility = mcp.PolicyVisibility{Decider: svc}
	}))
	defer srv.Close()
	ctx := t.Context()

	cs := connect(t, srv.URL, fullToken, "2025-11-25")
	list, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range list.Tools {
		names = append(names, tool.Name)
	}
	joined := strings.Join(names, ",")
	if strings.Contains(joined, "fake.create_item") {
		t.Errorf("hidden tool listed: %s", joined)
	}
	for _, want := range []string{"fake.list_accounts", "fake.list_items", "fake.get_item", "fake.post_note", "fake.flaky_write"} {
		if !strings.Contains(joined, want) {
			t.Errorf("tools/list lacks %s: %s", want, joined)
		}
	}

	// Byte-identical not-found for hidden and unknown (raw JSON-RPC).
	hidden := post(t, srv.URL, fullToken, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fake.create_item","arguments":{"name":"x"}}}`)
	unknown := post(t, srv.URL, fullToken, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fake.create_xxxx","arguments":{"name":"x"}}}`)
	if hidden.StatusCode != unknown.StatusCode || strings.ReplaceAll(string(hidden.Body), "create_item", "create_xxxx") != string(unknown.Body) {
		t.Errorf("hidden and unknown differ:\n%s\n%s", hidden.Body, unknown.Body)
	}
	if !strings.Contains(string(hidden.Body), `unknown tool \"fake.create_item\"`) {
		t.Errorf("hidden body = %s", hidden.Body)
	}

	// Allowed read runs; conditional deny by resource identity.
	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "fake.list_items"})
	if err != nil || res.IsError {
		t.Fatalf("list_items: err=%v res=%+v", err, res)
	}
	_, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "fake.get_item", Arguments: map[string]any{"id": "secret-1"}})
	if err == nil || !strings.Contains(err.Error(), "denied") {
		t.Errorf("conditional deny: err = %v", err)
	}
	res, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "fake.get_item", Arguments: map[string]any{"id": "public-1"}})
	if err != nil || !res.IsError { // the item does not exist: a tool error, not a policy one
		t.Errorf("conditional deny no match: err=%v res=%+v", err, res)
	}

	// Confirm: approval required (the approvals task replaces this body).
	_, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "fake.post_note", Arguments: map[string]any{"text": "hi"}})
	if err == nil || !strings.Contains(err.Error(), "approval required") {
		t.Errorf("confirm: err = %v", err)
	}
	// Personal account: confirm_writes turns an allowed write into confirm;
	// but user-2's token is read-only, so writes are hidden altogether.
	cs2 := connect(t, srv.URL, readOnlyToken, "2025-11-25")
	list2, _ := cs2.ListTools(ctx, nil)
	for _, tool := range list2.Tools {
		if tool.Name == "fake.flaky_write" || tool.Name == "fake.post_note" {
			t.Errorf("read-only admin token lists a write: %s", tool.Name)
		}
	}
	if _, err := cs2.CallTool(ctx, &sdk.CallToolParams{Name: "fake.flaky_write", Arguments: map[string]any{}}); err == nil || !strings.Contains(err.Error(), "unknown tool") {
		t.Errorf("read-only write call: err = %v", err)
	}

	// A role change produces a new version; an approval bound to the old
	// version no longer matches the version the next decision reports.
	before, _ := svc.Current(ctx)
	approval := struct{ PolicyVersion string }{PolicyVersion: before.ID}
	member, _ := svc.Role(ctx, "member")
	member.Rules = append(member.Rules, policy.ToolRule{App: "fake", Tool: "flaky_write", Outcome: policy.OutcomeHidden})
	if err := svc.SaveRole(ctx, "user-2", member); err != nil {
		t.Fatal(err)
	}
	after, _ := svc.Current(ctx)
	if after.ID == approval.PolicyVersion || after.Version == before.Version {
		t.Errorf("version unchanged after role edit")
	}
	if _, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "fake.flaky_write", Arguments: map[string]any{}}); err == nil || !strings.Contains(err.Error(), "unknown tool") {
		t.Errorf("newly hidden tool: err = %v", err)
	}
	d, _ := svc.Decide(ctx, policy.Input{UserID: "user-1", TokenID: "token-1", Tool: connectors.Tool{App: "fake", Name: "list_items", Kind: connectors.KindRead}, AccountLabel: "company"})
	if d.VersionID == approval.PolicyVersion {
		t.Error("decision still reports the approval's old version")
	}
}
