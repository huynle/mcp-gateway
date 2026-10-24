package secrets_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/secrets"
	"github.com/huynle/mcp-gateway/internal/secrets/ref"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// recordHook collects the uses the stage reports.
type recordHook struct {
	mu   sync.Mutex
	uses []secrets.Use
}

func (h *recordHook) SecretUsed(_ context.Context, u secrets.Use) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.uses = append(h.uses, u)
}

func (h *recordHook) all() []secrets.Use {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]secrets.Use(nil), h.uses...)
}

// classed is a handler error with an audit class, like the federation
// connector's upstreamError.
type classed struct {
	class, msg string
	unknown    bool
}

func (e *classed) Error() string      { return e.msg }
func (e *classed) ErrorClass() string { return e.class }
func (e *classed) Is(target error) bool {
	return e.unknown && target == connectors.ErrOutcomeUnknown
}

type stageFixture struct {
	*fixture
	stage mcp.Stage
	hook  *recordHook
}

func newStageFixture(t *testing.T) *stageFixture {
	t.Helper()
	f := newFixture(t)
	hook := &recordHook{}
	st, err := secrets.NewStage(secrets.StageOptions{Service: f.svc, Targets: targets, BaseURL: baseURL, Hook: hook})
	if err != nil {
		t.Fatal(err)
	}
	if st.Name() != secrets.StageName {
		t.Errorf("stage name = %q", st.Name())
	}
	return &stageFixture{fixture: f, stage: st, hook: hook}
}

func callContext(tokenID, app, tool string, args map[string]any) *mcp.CallContext {
	owner := alice
	t := connectors.Tool{App: app, Name: tool, Kind: connectors.KindWrite}
	return &mcp.CallContext{
		Principal: &tokens.Principal{UserID: owner, TokenID: tokenID},
		Name:      t.FullName(),
		Tool:      &t,
		Call: connectors.Call{Principal: connectors.Principal{UserID: owner, TokenID: tokenID}, Tool: t.FullName(),
			Args: args},
	}
}

func refArgs(handle string) map[string]any {
	return map[string]any{"user": "admin", "password": map[string]any{ref.Key: handle}}
}

// run runs the stage with next; it reports whether next ran and the
// arguments next saw.
func (f *stageFixture) run(cc *mcp.CallContext, next func(ctx context.Context, args map[string]any) (connectors.Result, error)) (connectors.Result, bool, map[string]any, error) {
	ran := false
	var seen map[string]any
	res, err := f.stage.Run(context.Background(), cc, func(ctx context.Context) (connectors.Result, error) {
		ran = true
		seen = cc.Call.Args
		if next == nil {
			return connectors.Result{Content: "ok"}, nil
		}
		return next(ctx, cc.Call.Args)
	})
	return res, ran, seen, err
}

func (f *stageFixture) usesLeft(t *testing.T, id string) int {
	t.Helper()
	rec := f.mem.Record(id)
	if rec == nil {
		t.Fatalf("no record %s", id)
	}
	return rec.UsesLeft
}

func wire(te *mcp.ToolError) string {
	data, _ := json.Marshal(te.Data)
	return fmt.Sprintf("%d|%s|%s|%s|%d", te.Code, te.Class(), te.Message, data, te.RetryAfterSeconds())
}

func TestStageWithoutRefsPassesThrough(t *testing.T) {
	f := newStageFixture(t)
	args := map[string]any{"user": "admin", "password": map[string]any{"$secret": "not-a-handle"}}
	cc := callContext(harness, "github", "list_issues", args)
	res, ran, seen, err := f.run(cc, nil)
	if err != nil || !ran || res.Content != "ok" {
		t.Fatalf("passthrough = %v, %v, ran %v", res, err, ran)
	}
	if reflect.ValueOf(seen).Pointer() != reflect.ValueOf(args).Pointer() {
		t.Error("the stage copied arguments without refs")
	}
}

func TestStageSubstitutesScrubsAndRestores(t *testing.T) {
	f := newStageFixture(t)
	r := f.provided(t, alice, 0, 2)
	args := refArgs(r.Handle)
	cc := callContext(harness, "vault", "login", args)
	b64 := base64.StdEncoding.EncodeToString([]byte(value))
	res, ran, seen, err := f.run(cc, func(_ context.Context, a map[string]any) (connectors.Result, error) {
		return connectors.Result{Content: &sdk.CallToolResult{
			Content:           []sdk.Content{&sdk.TextContent{Text: "logged in with " + value + " / " + b64}},
			StructuredContent: map[string]any{"echo": a["password"]},
		}}, nil
	})
	if err != nil || !ran {
		t.Fatalf("call = %v, ran %v", err, ran)
	}
	if seen["password"] != value || seen["user"] != "admin" {
		t.Errorf("next saw %v, want the plaintext in password", seen)
	}
	out, _ := json.Marshal(res.Content)
	if strings.Contains(string(out), value) || strings.Contains(string(out), b64) || !strings.Contains(string(out), "[secret]") {
		t.Errorf("result not scrubbed: %s", out)
	}
	if !reflect.DeepEqual(cc.Call.Args, refArgs(r.Handle)) {
		t.Errorf("Call.Args after the call = %v, want the handle form back", cc.Call.Args)
	}
	if !reflect.DeepEqual(args, refArgs(r.Handle)) {
		t.Errorf("the caller's argument map was mutated: %v", args)
	}
	if n := f.usesLeft(t, r.Secret.ID); n != 1 {
		t.Errorf("uses left = %d, want 1", n)
	}
	if uses := f.hook.all(); len(uses) != 1 || uses[0].SecretID != r.Secret.ID || uses[0].Label != "vault password" ||
		uses[0].UserID != alice || uses[0].Tool != "vault.login" {
		t.Errorf("hook uses = %+v", uses)
	}
}

func TestStageScrubsErrors(t *testing.T) {
	f := newStageFixture(t)
	r := f.provided(t, alice, 0, 3)

	_, _, _, err := f.run(callContext(harness, "vault", "login", refArgs(r.Handle)), func(context.Context, map[string]any) (connectors.Result, error) {
		return connectors.Result{}, fmt.Errorf("login failed for password %s (%s)", value, base64.StdEncoding.EncodeToString([]byte(value)))
	})
	if err == nil || strings.Contains(err.Error(), value) || !strings.Contains(err.Error(), "[secret]") {
		t.Errorf("handler error = %v", err)
	}

	cause := mcp.NewToolError(mcp.CodeInvalidParams, "args_invalid", "bad value "+value)
	cause.Data = map[string]any{"echo": value, "list": []string{"x", value}}
	cause.RetryAfter = 3 * time.Second
	_, _, _, err = f.run(callContext(harness, "vault", "login", refArgs(r.Handle)), func(context.Context, map[string]any) (connectors.Result, error) {
		return connectors.Result{}, fmt.Errorf("wrapped: %w", cause)
	})
	var te *mcp.ToolError
	if !errors.As(err, &te) {
		t.Fatalf("tool error lost: %v", err)
	}
	if strings.Contains(err.Error(), value) || strings.Contains(wire(te), value) || te.Code != mcp.CodeInvalidParams ||
		te.Class() != "args_invalid" || te.RetryAfter != 3*time.Second || !strings.Contains(te.Message, "[secret]") {
		t.Errorf("tool error = %s", wire(te))
	}
}

func TestStageUnavailableIsIdenticalForEveryCause(t *testing.T) {
	f := newStageFixture(t)
	ctx := context.Background()
	other, err := f.svc.Request(ctx, alice, harness, "other", secrets.Binding{ServerID: server, Tool: "vault.other", Arg: "password"}, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Provide(ctx, alice, other.RequestID, []byte(value)); err != nil {
		t.Fatal(err)
	}
	wrongArg, _ := f.svc.Request(ctx, alice, harness, "arg", secrets.Binding{ServerID: server, Tool: "vault.login", Arg: "user"}, 0, 1)
	if _, err := f.svc.Provide(ctx, alice, wrongArg.RequestID, []byte(value)); err != nil {
		t.Fatal(err)
	}
	pendingOther, _ := f.svc.Request(ctx, alice, harness, "p", secrets.Binding{ServerID: server, Tool: "vault.other", Arg: "password"}, 0, 1)
	mine := f.provided(t, alice, 0, 1)
	bobs := f.provided(t, bob, 0, 1)
	usedUp := f.provided(t, alice, 0, 1)
	if _, err := f.svc.Consume(ctx, alice, harness, usedUp.Handle, binding); err != nil {
		t.Fatal(err)
	}
	revoked := f.provided(t, alice, 0, 1)
	if _, err := f.svc.Revoke(ctx, alice, revoked.Secret.ID); err != nil {
		t.Fatal(err)
	}
	unknown, _ := ref.Generate()

	cases := map[string]*mcp.CallContext{
		"wrong tool":           callContext(harness, "vault", "login", refArgs(other.Handle)),
		"wrong argument":       callContext(harness, "vault", "login", refArgs(wrongArg.Handle)),
		"pending, wrong tool":  callContext(harness, "vault", "login", refArgs(pendingOther.Handle)),
		"wrong harness":        callContext("tok-other", "vault", "login", refArgs(mine.Handle)),
		"another user":         callContext(harness, "vault", "login", refArgs(bobs.Handle)),
		"used up":              callContext(harness, "vault", "login", refArgs(usedUp.Handle)),
		"revoked":              callContext(harness, "vault", "login", refArgs(revoked.Handle)),
		"unknown handle":       callContext(harness, "vault", "login", refArgs(unknown)),
		"built-in tool":        callContext(harness, "github", "create_issue", map[string]any{"password": map[string]any{ref.Key: mine.Handle}}),
		"nested ref":           callContext(harness, "vault", "login", map[string]any{"opts": map[string]any{"password": map[string]any{ref.Key: mine.Handle}}}),
		"ref in a list":        callContext(harness, "vault", "login", map[string]any{"password": []any{map[string]any{ref.Key: mine.Handle}}}),
		"one handle, two args": callContext(harness, "vault", "login", map[string]any{"password": map[string]any{ref.Key: mine.Handle}, "user": map[string]any{ref.Key: mine.Handle}}),
	}
	var want string
	for name, cc := range cases {
		_, ran, _, err := f.run(cc, nil)
		if ran {
			t.Errorf("%s: next ran", name)
		}
		te := toolError(t, err)
		got := wire(te)
		if te.Code != mcp.CodeSecretUnavailable || te.Class() != "secret_unavailable" {
			t.Errorf("%s: %s", name, got)
		}
		if want == "" {
			want = got
		} else if got != want {
			t.Errorf("%s: %s differs from %s", name, got, want)
		}
	}
	// Expired, checked last (it moves the clock).
	f.clk.Advance(secrets.DefaultTTL + time.Minute)
	_, _, _, err = f.run(callContext(harness, "vault", "login", refArgs(mine.Handle)), nil)
	if got := wire(toolError(t, err)); got != want {
		t.Errorf("expired: %s differs from %s", got, want)
	}
	// Nothing was consumed by the refused calls.
	if n := f.usesLeft(t, other.Secret.ID); n != 1 {
		t.Errorf("wrong-tool secret lost a use: %d", n)
	}
	if n := f.usesLeft(t, mine.Secret.ID); n != 1 {
		t.Errorf("refused calls consumed a use: %d", n)
	}
	if len(f.hook.all()) != 0 {
		t.Errorf("hook reported uses: %+v", f.hook.all())
	}
}

func TestStagePendingAnswersTheSameLink(t *testing.T) {
	f := newStageFixture(t)
	r := f.request(t, alice, 0, 1)
	_, ran, _, err := f.run(callContext(harness, "vault", "login", refArgs(r.Handle)), nil)
	if ran {
		t.Error("next ran")
	}
	te := toolError(t, err)
	link := baseURL + "/s/" + r.RequestID
	fp := ref.Fingerprint(r.RequestID)
	if te.Code != mcp.CodeSecretRequired || te.Class() != "secret_required" || te.Data["url"] != link ||
		te.Data["handle"] != r.Handle || te.Data["fingerprint"] != fp || !strings.Contains(te.Message, link) ||
		!strings.Contains(te.Message, `{"password": {"$secret": "`+r.Handle+`"}}`) {
		t.Errorf("pending = %s", wire(te))
	}
}

func TestStageDenied(t *testing.T) {
	f := newStageFixture(t)
	r := f.request(t, alice, 0, 1)
	if _, err := f.svc.Deny(context.Background(), alice, r.RequestID); err != nil {
		t.Fatal(err)
	}
	_, ran, _, err := f.run(callContext(harness, "vault", "login", refArgs(r.Handle)), nil)
	te := toolError(t, err)
	if ran || te.Code != mcp.CodeDenied || te.Message != "secret request denied" || te.Class() != "secret_denied" {
		t.Errorf("denied = %s (ran %v)", wire(te), ran)
	}
}

func TestStageRefundsCallsThatNeverReachedTheTarget(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		refund bool
	}{
		{"tunnel offline", &classed{class: "tunnel_offline", msg: "offline"}, true},
		{"tunnel unavailable", &classed{class: "tunnel_unavailable", msg: "unavailable"}, true},
		{"gateway refusal", mcp.NewToolError(mcp.CodeDenied, "tool_disabled", "disabled"), true},
		{"credentials", mcp.NewToolError(mcp.CodeInternal, "credentials_unavailable", "x"), true},
		{"per-user header missing (credential links)", mcp.NewURLElicitationRequired("user_header_missing", "set them", nil, nil), true},
		{"tunnel offline mid-write", &classed{class: "tunnel_offline", msg: "offline", unknown: true}, false},
		{"upstream tool error", &classed{class: "upstream_tool_error", msg: "refused"}, false},
		{"upstream timeout", &classed{class: "upstream_timeout", msg: "slow"}, false},
		{"plain error", errors.New("boom"), false},
		{"success", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newStageFixture(t)
			r := f.provided(t, alice, 0, 2)
			_, ran, _, _ := f.run(callContext(harness, "vault", "login", refArgs(r.Handle)), func(context.Context, map[string]any) (connectors.Result, error) {
				return connectors.Result{Content: "x"}, tc.err
			})
			if !ran {
				t.Fatal("next did not run")
			}
			want := 1
			if tc.refund {
				want = 2
			}
			if n := f.usesLeft(t, r.Secret.ID); n != want {
				t.Errorf("uses left = %d, want %d", n, want)
			}
			if got := len(f.hook.all()); (got == 1) == tc.refund {
				t.Errorf("hook uses = %d with refund %v", got, tc.refund)
			}
		})
	}
}

func TestStageTwoHandles(t *testing.T) {
	f := newStageFixture(t)
	ctx := context.Background()
	user, err := f.svc.Request(ctx, alice, harness, "user", secrets.Binding{ServerID: server, Tool: "vault.login", Arg: "user"}, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Provide(ctx, alice, user.RequestID, []byte("another-secret-value")); err != nil {
		t.Fatal(err)
	}
	pass := f.provided(t, alice, 0, 1)
	args := map[string]any{"user": map[string]any{ref.Key: user.Handle}, "password": map[string]any{ref.Key: pass.Handle}}
	res, _, seen, err := f.run(callContext(harness, "vault", "login", args), func(_ context.Context, a map[string]any) (connectors.Result, error) {
		return connectors.Result{Content: fmt.Sprint(a["user"], a["password"])}, nil
	})
	if err != nil || seen["user"] != "another-secret-value" || seen["password"] != value {
		t.Fatalf("call = %v, next saw %v", err, seen)
	}
	if s, _ := res.Content.(string); strings.Contains(s, value) || strings.Contains(s, "another-secret-value") {
		t.Errorf("result = %q", s)
	}
	// One pending handle among provided ones: nothing is consumed.
	pending := f.request(t, alice, 0, 1)
	again := f.provided(t, alice, 0, 1)
	args = map[string]any{"user": map[string]any{ref.Key: pending.Handle}, "password": map[string]any{ref.Key: again.Handle}}
	_, ran, _, err := f.run(callContext(harness, "vault", "login", args), nil)
	if ran || toolError(t, err).Code != mcp.CodeSecretUnavailable && toolError(t, err).Code != mcp.CodeSecretRequired {
		t.Errorf("mixed = %v (ran %v)", err, ran)
	}
	if n := f.usesLeft(t, again.Secret.ID); n != 1 {
		t.Errorf("a refused call consumed a use: %d", n)
	}
}

// auditCapture records audit events.
type auditCapture struct {
	mu  sync.Mutex
	evs []audit.Event
}

func (a *auditCapture) Record(_ context.Context, ev audit.Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.evs = append(a.evs, ev)
	return nil
}

// In a real pipeline (inserted before dispatch, as cmd/gateway will) the
// handler gets the plaintext, the harness a scrubbed result, and audit
// computes the resource identity from the handle-form arguments.
func TestStageInThePipeline(t *testing.T) {
	f := newStageFixture(t)
	r := f.provided(t, alice, 0, 1)
	reg := connectors.NewRegistry()
	var gotPassword any
	var identityArg any
	tool := handlerTool("vault", "login", `{"type":"object"}`)
	tool.ResourceIdentity = func(args map[string]any) map[string]string {
		identityArg = args["password"]
		return map[string]string{"server": "vault"}
	}
	tool.Handler = func(_ context.Context, call connectors.Call) (connectors.Result, error) {
		gotPassword = call.Args["password"]
		return connectors.Result{Content: "echo " + value}, nil
	}
	if err := reg.Register(tool); err != nil {
		t.Fatal(err)
	}
	rec := &auditCapture{}
	p, err := mcp.DefaultPipeline(mcp.PipelineDeps{Registry: reg, Audit: rec})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Insert(mcp.Before, mcp.StageDispatch, f.stage); err != nil {
		t.Fatal(err)
	}
	cc := &mcp.CallContext{Principal: &tokens.Principal{UserID: alice, TokenID: harness}, Name: "vault.login",
		RawArgs: refArgs(r.Handle)}
	res, err := p.Run(context.Background(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if gotPassword != value {
		t.Errorf("handler got %v", gotPassword)
	}
	if s, _ := res.Content.(string); s != "echo [secret]" {
		t.Errorf("result = %v", res.Content)
	}
	if _, ok := ref.IsRef(identityArg); !ok {
		t.Errorf("audit saw password = %v, want the ref", identityArg)
	}
	if len(rec.evs) != 1 || rec.evs[0].Outcome != "succeeded" {
		t.Errorf("audit events = %+v", rec.evs)
	}
}
