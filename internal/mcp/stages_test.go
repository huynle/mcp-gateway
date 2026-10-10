package mcp_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// captureRecorder keeps every audit event it is given.
type captureRecorder struct{ events []audit.Event }

func (c *captureRecorder) Record(_ context.Context, ev audit.Event) error {
	c.events = append(c.events, ev)
	return nil
}

// echoTool returns its Call so tests can see exactly what reached the
// handler.
func echoTool(app, name string, kind connectors.Kind) connectors.Tool {
	t := stubTool(app, name, kind)
	t.ResourceIdentity = func(args map[string]any) map[string]string {
		repo, _ := args["repo"].(string)
		return map[string]string{"repo": repo}
	}
	t.Handler = func(_ context.Context, call connectors.Call) (connectors.Result, error) {
		return connectors.Result{Content: call}, nil
	}
	return t
}

func stubTool(app, name string, kind connectors.Kind) connectors.Tool {
	return connectors.Tool{
		App:         app,
		Name:        name,
		Description: app + " " + name,
		InputSchema: json.RawMessage(`{"type":"object","properties":{"repo":{"type":"string"}}}`),
		Kind:        kind,
		Handler: func(context.Context, connectors.Call) (connectors.Result, error) {
			return connectors.Result{Content: "ok"}, nil
		},
	}
}

func newRegistry(t *testing.T, tools ...connectors.Tool) *connectors.Registry {
	t.Helper()
	reg := connectors.NewRegistry()
	for _, tool := range tools {
		if err := reg.Register(tool); err != nil {
			t.Fatal(err)
		}
	}
	return reg
}

var principal = &tokens.Principal{UserID: "user-1", TokenID: "token-1", PublicID: "abcdefgh"}

func defaultPipeline(t *testing.T, reg *connectors.Registry, rec audit.Recorder, lim mcp.RateLimiter) *mcp.Pipeline {
	t.Helper()
	p, err := mcp.DefaultPipeline(mcp.PipelineDeps{
		Registry:    reg,
		Visibility:  mcp.ScopeVisibility{},
		RateLimiter: lim,
		Audit:       rec,
		Log:         slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDefaultPipelineOrder(t *testing.T) {
	p := defaultPipeline(t, newRegistry(t), nil, nil)
	want := []string{mcp.StageAuthenticate, mcp.StageAudit, mcp.StageResolve, mcp.StageStrip, mcp.StageRateLimit, mcp.StageDispatch}
	if got := p.Names(); !reflect.DeepEqual(got, want) {
		t.Errorf("Names = %v, want %v", got, want)
	}
}

func TestAuthenticateStageRequiresPrincipal(t *testing.T) {
	p := defaultPipeline(t, newRegistry(t, echoTool("github", "list_issues", connectors.KindRead)), nil, nil)
	_, err := p.Run(context.Background(), &mcp.CallContext{Name: "github.list_issues"})
	var te *mcp.ToolError
	if !errors.As(err, &te) || te.Code != mcp.CodeUnauthenticated {
		t.Fatalf("err = %v, want ToolError{CodeUnauthenticated}", err)
	}
}

func TestResolveHiddenAndUnknownAreIdentical(t *testing.T) {
	reg := newRegistry(t, echoTool("github", "create_issue", connectors.KindWrite))
	readOnly := &tokens.Principal{UserID: "u", TokenID: "t", Scope: tokens.Scope{ReadOnly: true}}
	p := defaultPipeline(t, reg, nil, nil)

	_, hiddenErr := p.Run(context.Background(), &mcp.CallContext{Principal: readOnly, Name: "github.create_issue"})
	_, unknownErr := p.Run(context.Background(), &mcp.CallContext{Principal: readOnly, Name: "github.nonexistent"})
	for _, err := range []error{hiddenErr, unknownErr} {
		var te *mcp.ToolError
		if !errors.As(err, &te) || te.Code != mcp.CodeToolNotFound {
			t.Fatalf("err = %v, want ToolError{CodeToolNotFound}", err)
		}
	}
	// Same name, two registries: one hides it, the other never had it.
	_, hidden := p.Run(context.Background(), &mcp.CallContext{Principal: readOnly, Name: "github.create_issue"})
	_, absent := defaultPipeline(t, newRegistry(t), nil, nil).Run(context.Background(), &mcp.CallContext{Principal: readOnly, Name: "github.create_issue"})
	if !reflect.DeepEqual(hidden, absent) {
		t.Errorf("hidden = %#v, absent = %#v; must be identical", hidden, absent)
	}
	if strings.Contains(hidden.Error(), "hidden") || strings.Contains(hidden.Error(), "read-only") {
		t.Errorf("error leaks why: %q", hidden.Error())
	}
}

func TestResolveSeesScopeAllowList(t *testing.T) {
	reg := newRegistry(t, echoTool("github", "list_issues", connectors.KindRead), echoTool("slack", "list_channels", connectors.KindRead))
	scoped := &tokens.Principal{UserID: "u", TokenID: "t", Scope: tokens.Scope{Apps: []string{"github"}}}
	p := defaultPipeline(t, reg, nil, nil)
	if _, err := p.Run(context.Background(), &mcp.CallContext{Principal: scoped, Name: "github.list_issues"}); err != nil {
		t.Errorf("allowed app: %v", err)
	}
	var te *mcp.ToolError
	if _, err := p.Run(context.Background(), &mcp.CallContext{Principal: scoped, Name: "slack.list_channels"}); !errors.As(err, &te) || te.Code != mcp.CodeToolNotFound {
		t.Errorf("app outside scope: err = %v, want not found", err)
	}
}

func TestStripStageRemovesInjectedArguments(t *testing.T) {
	reg := newRegistry(t, echoTool("github", "create_issue", connectors.KindWrite))
	p := defaultPipeline(t, reg, nil, nil)
	res, err := p.Run(context.Background(), &mcp.CallContext{
		Principal: principal,
		Name:      "github.create_issue",
		RawArgs:   map[string]any{"repo": "acme/web", "title": "x", "account": "acct-7", "approval_id": "appr-9"},
	})
	if err != nil {
		t.Fatal(err)
	}
	call := res.Content.(connectors.Call)
	if call.Account != "acct-7" || call.ApprovalID != "appr-9" {
		t.Errorf("Account/ApprovalID = %q/%q", call.Account, call.ApprovalID)
	}
	if _, ok := call.Args["account"]; ok {
		t.Error("account reached the handler")
	}
	if _, ok := call.Args["approval_id"]; ok {
		t.Error("approval_id reached the handler")
	}
	if call.Args["repo"] != "acme/web" || call.Args["title"] != "x" {
		t.Errorf("Args = %v", call.Args)
	}
	if call.Tool != "github.create_issue" || call.Principal != (connectors.Principal{UserID: "user-1", TokenID: "token-1"}) {
		t.Errorf("Call = %+v", call)
	}
}

func TestStripStageRejectsNonStringInjectedArguments(t *testing.T) {
	reg := newRegistry(t, echoTool("github", "create_issue", connectors.KindWrite))
	p := defaultPipeline(t, reg, nil, nil)
	_, err := p.Run(context.Background(), &mcp.CallContext{
		Principal: principal, Name: "github.create_issue",
		RawArgs: map[string]any{"account": 12},
	})
	var te *mcp.ToolError
	if !errors.As(err, &te) || te.Code != mcp.CodeInvalidParams {
		t.Fatalf("err = %v, want ToolError{CodeInvalidParams}", err)
	}
}

func TestStripStageWithNilArgs(t *testing.T) {
	reg := newRegistry(t, echoTool("github", "list_issues", connectors.KindRead))
	p := defaultPipeline(t, reg, nil, nil)
	res, err := p.Run(context.Background(), &mcp.CallContext{Principal: principal, Name: "github.list_issues"})
	if err != nil {
		t.Fatal(err)
	}
	if args := res.Content.(connectors.Call).Args; args == nil || len(args) != 0 {
		t.Errorf("Args = %v, want empty non-nil map", args)
	}
}

type denyLimiter struct {
	calls []string
	wait  time.Duration
}

func (d *denyLimiter) Allow(_ context.Context, userID, tool string) (bool, time.Duration) {
	d.calls = append(d.calls, userID+":"+tool)
	return d.wait == 0, d.wait
}

func TestRateLimitStage(t *testing.T) {
	reg := newRegistry(t, echoTool("github", "list_issues", connectors.KindRead))
	lim := &denyLimiter{}
	p := defaultPipeline(t, reg, nil, lim)
	if _, err := p.Run(context.Background(), &mcp.CallContext{Principal: principal, Name: "github.list_issues"}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(lim.calls, []string{"user-1:github.list_issues"}) {
		t.Errorf("limiter calls = %v", lim.calls)
	}
	lim.wait = 7 * time.Second
	_, err := p.Run(context.Background(), &mcp.CallContext{Principal: principal, Name: "github.list_issues"})
	var te *mcp.ToolError
	if !errors.As(err, &te) || te.Code != mcp.CodeRateLimited || !strings.Contains(te.Message, "7s") {
		t.Fatalf("err = %v, want ToolError{CodeRateLimited} mentioning 7s", err)
	}
}

func TestAuditStageRecordsMetadataNeverArguments(t *testing.T) {
	reg := newRegistry(t, echoTool("github", "create_issue", connectors.KindWrite))
	rec := &captureRecorder{}
	p := defaultPipeline(t, reg, rec, nil)
	ctx := observability.WithRequestID(context.Background(), "req-0000000001")
	_, err := p.Run(ctx, &mcp.CallContext{
		Principal: principal, Name: "github.create_issue",
		RawArgs: map[string]any{"repo": "acme/web", "body": "SECRET BODY", "account": "acct-7"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.events) != 1 {
		t.Fatalf("events = %d, want 1", len(rec.events))
	}
	ev := rec.events[0]
	if ev.Tool != "github.create_issue" || ev.UserID != "user-1" || ev.TokenID != "token-1" {
		t.Errorf("Tool/UserID/TokenID = %q/%q/%q", ev.Tool, ev.UserID, ev.TokenID)
	}
	if ev.Decision != "allow" || ev.Outcome != "succeeded" || ev.ErrorClass != "" {
		t.Errorf("Decision/Outcome/ErrorClass = %q/%q/%q", ev.Decision, ev.Outcome, ev.ErrorClass)
	}
	if ev.RequestID != "req-0000000001" {
		t.Errorf("RequestID = %q", ev.RequestID)
	}
	if ev.Latency <= 0 {
		t.Errorf("Latency = %v", ev.Latency)
	}
	if ev.Time.IsZero() {
		t.Error("Time unset")
	}
	if !reflect.DeepEqual(ev.ResourceIdentity, map[string]string{"repo": "acme/web"}) {
		t.Errorf("ResourceIdentity = %v", ev.ResourceIdentity)
	}
	for k, v := range ev.ResourceIdentity {
		if strings.Contains(v, "SECRET") || k == "body" {
			t.Errorf("argument leaked into audit: %s=%s", k, v)
		}
	}
}

func TestAuditStageRecordsFailures(t *testing.T) {
	failing := echoTool("github", "list_issues", connectors.KindRead)
	failing.Handler = func(context.Context, connectors.Call) (connectors.Result, error) {
		return connectors.Result{}, errors.New("vendor said no: token=abc")
	}
	unavailable := echoTool("github", "list_prs", connectors.KindRead)
	unavailable.Handler = func(context.Context, connectors.Call) (connectors.Result, error) {
		return connectors.Result{Unavailable: true}, nil
	}
	reg := newRegistry(t, failing, unavailable)
	rec := &captureRecorder{}
	lim := &denyLimiter{}
	p := defaultPipeline(t, reg, rec, lim)

	run := func(name string, pr *tokens.Principal) {
		t.Helper()
		_, _ = p.Run(context.Background(), &mcp.CallContext{Principal: pr, Name: name, RawArgs: map[string]any{"repo": "r"}})
	}
	run("github.list_issues", principal) // handler error
	run("github.list_prs", principal)    // unavailable read
	run("github.nope", principal)        // not found
	lim.wait = time.Second
	run("github.list_issues", principal) // rate limited
	run("github.list_issues", nil)       // unauthenticated: no principal, must not be recorded as a user event

	want := []struct{ tool, decision, outcome, class string }{
		{"github.list_issues", "allow", "failed", "tool_error"},
		{"github.list_prs", "allow", "succeeded", "unavailable"},
		{"github.nope", "deny", "denied", "tool_not_found"},
		{"github.list_issues", "deny", "denied", "rate_limited"},
	}
	if len(rec.events) != len(want) {
		t.Fatalf("events = %d, want %d: %+v", len(rec.events), len(want), rec.events)
	}
	for i, w := range want {
		ev := rec.events[i]
		if ev.Tool != w.tool || ev.Decision != w.decision || ev.Outcome != w.outcome || ev.ErrorClass != w.class {
			t.Errorf("event %d = %s/%s/%s/%s, want %s/%s/%s/%s", i, ev.Tool, ev.Decision, ev.Outcome, ev.ErrorClass, w.tool, w.decision, w.outcome, w.class)
		}
		if ev.UserID != "user-1" {
			t.Errorf("event %d UserID = %q", i, ev.UserID)
		}
	}
	// The not-found event has no resource identity (no tool to extract it);
	// the others do, from the tool's hook, never from raw arguments.
	if rec.events[2].ResourceIdentity != nil {
		t.Errorf("not-found event has resource identity %v", rec.events[2].ResourceIdentity)
	}
}

func TestAuditStageSurvivesRecorderFailure(t *testing.T) {
	reg := newRegistry(t, echoTool("github", "list_issues", connectors.KindRead))
	p := defaultPipeline(t, reg, failingRecorder{}, nil)
	if _, err := p.Run(context.Background(), &mcp.CallContext{Principal: principal, Name: "github.list_issues"}); err != nil {
		t.Fatalf("a recorder failure must not fail the call: %v", err)
	}
}

type failingRecorder struct{}

func (failingRecorder) Record(context.Context, audit.Event) error { return errors.New("db down") }

func TestScopeVisibility(t *testing.T) {
	read := stubTool("github", "list_issues", connectors.KindRead)
	write := stubTool("github", "create_issue", connectors.KindWrite)
	other := stubTool("slack", "post_message", connectors.KindWrite)
	cases := []struct {
		name  string
		scope tokens.Scope
		tool  connectors.Tool
		want  bool
	}{
		{"unrestricted read", tokens.Scope{}, read, true},
		{"unrestricted write", tokens.Scope{}, write, true},
		{"read-only hides write", tokens.Scope{ReadOnly: true}, write, false},
		{"read-only shows read", tokens.Scope{ReadOnly: true}, read, true},
		{"app allow-list", tokens.Scope{Apps: []string{"github"}}, other, false},
		{"tool allow-list", tokens.Scope{Tools: []string{"github.create_issue"}}, write, true},
		{"tool allow-list excludes sibling", tokens.Scope{Tools: []string{"github.create_issue"}}, read, false},
		{"read-only and allow-list", tokens.Scope{ReadOnly: true, Tools: []string{"github.create_issue"}}, write, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := mcp.ScopeVisibility{}.Visible(context.Background(), &tokens.Principal{Scope: c.scope}, c.tool)
			if got != c.want {
				t.Errorf("Visible = %v, want %v", got, c.want)
			}
		})
	}
	if (mcp.ScopeVisibility{}).Visible(context.Background(), nil, read) {
		t.Error("nil principal must see nothing")
	}
}

func TestToolErrorMessage(t *testing.T) {
	err := mcp.ErrToolNotFound("github.x")
	if err.Error() != `unknown tool "github.x"` {
		t.Errorf("Error = %q", err.Error())
	}
	if err.Class() != "tool_not_found" {
		t.Errorf("Class = %q", err.Class())
	}
}
