package mcp_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// countingConfirm records how often the confirm hook ran (an approval
// row and its notification would be created there).
type countingConfirm struct{ calls int }

func (c *countingConfirm) Confirm(context.Context, *mcp.CallContext, mcp.Next) (connectors.Result, error) {
	c.calls++
	return connectors.Result{}, mcp.ErrApprovalRequired
}

// prePipeline is a policy pipeline with a precheck (Brain task 8ky7l4e6)
// that refuses calls whose "title" is not a string.
func prePipeline(t *testing.T, confirm mcp.ConfirmHandler, rec *captureRecorder) (*mcp.Pipeline, *[]connectors.Call) {
	t.Helper()
	reg := connectors.NewRegistry()
	tool := stubTool("notes", "create_note", connectors.KindWrite)
	tool.Handler = func(_ context.Context, call connectors.Call) (connectors.Result, error) {
		return connectors.Result{Content: "ran"}, nil
	}
	if err := reg.Register(tool); err != nil {
		t.Fatal(err)
	}
	var seen []connectors.Call
	pre := mcp.PrecheckerFunc(func(_ context.Context, tool connectors.Tool, call connectors.Call) error {
		seen = append(seen, call)
		if _, ok := call.Args["title"].(string); !ok {
			return mcp.NewToolError(mcp.CodeInvalidParams, "args_invalid", "arguments do not match the reviewed input schema of "+tool.FullName())
		}
		return nil
	})
	d := &stubDecider{outcomes: map[string]policy.Outcome{"notes.create_note": policy.OutcomeConfirm}}
	p, err := mcp.DefaultPipeline(mcp.PipelineDeps{Registry: reg, Policy: d, Confirm: confirm, Precheck: pre,
		Visibility: mcp.PolicyVisibility{Decider: d}, Audit: rec, Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	return p, &seen
}

func TestPrecheckRunsBeforePolicyAndConfirm(t *testing.T) {
	confirm := &countingConfirm{}
	rec := &captureRecorder{}
	p, seen := prePipeline(t, confirm, rec)
	if names := strings.Join(p.Names(), ","); names != "authenticate,audit,resolve,strip,precheck,policy,ratelimit,dispatch" {
		t.Errorf("stages = %s", names)
	}

	// Invalid arguments: refused before the confirm hook runs.
	cc := &mcp.CallContext{Principal: &tokens.Principal{UserID: "user-1"}, Name: "notes.create_note",
		RawArgs: map[string]any{"title": 7, "approval_id": "a-1"}}
	_, err := p.Run(t.Context(), cc)
	var te *mcp.ToolError
	if !errors.As(err, &te) || te.Code != mcp.CodeInvalidParams || te.Class() != "args_invalid" {
		t.Fatalf("invalid args: %v", err)
	}
	if confirm.calls != 0 {
		t.Errorf("confirm ran %d times for a call that can never run", confirm.calls)
	}
	if len(*seen) != 1 || (*seen)[0].Args["approval_id"] != nil || (*seen)[0].Principal.UserID != "user-1" {
		t.Errorf("precheck saw %+v, want the stripped call", *seen)
	}
	ev := rec.events[len(rec.events)-1]
	if ev.Decision != "deny" || ev.Outcome != "denied" || ev.ErrorClass != "args_invalid" {
		t.Errorf("audit = decision %q outcome %q class %q, want deny/denied/args_invalid", ev.Decision, ev.Outcome, ev.ErrorClass)
	}

	// Valid arguments: on to policy and the confirm hook as before.
	_, err = p.Run(t.Context(), &mcp.CallContext{Principal: &tokens.Principal{UserID: "user-1"}, Name: "notes.create_note",
		RawArgs: map[string]any{"title": "x"}})
	if !errors.Is(err, mcp.ErrApprovalRequired) || confirm.calls != 1 {
		t.Errorf("valid args: err %v, confirm calls %d", err, confirm.calls)
	}
}

// A handler error from the precheck (not a ToolError) fails closed.
func TestPrecheckFailureFailsClosed(t *testing.T) {
	reg := connectors.NewRegistry()
	if err := reg.Register(stubTool("notes", "create_note", connectors.KindWrite)); err != nil {
		t.Fatal(err)
	}
	ran := false
	stage := mcp.PrecheckStage(mcp.PrecheckerFunc(func(context.Context, connectors.Tool, connectors.Call) error {
		return errors.New("db down")
	}), nil)
	p, err := mcp.NewPipeline(mcp.AuthenticateStage(), mcp.ResolveStage(reg, mcp.ScopeVisibility{}), mcp.StripStage(), stage,
		mcp.DispatchStage())
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Run(t.Context(), &mcp.CallContext{Principal: &tokens.Principal{UserID: "u"}, Name: "notes.create_note", RawArgs: map[string]any{}})
	var te *mcp.ToolError
	if !errors.As(err, &te) || te.Code != mcp.CodeInternal || strings.Contains(te.Message, "db down") || ran {
		t.Errorf("precheck failure: %v", err)
	}
	if mcp.StagePrecheck != "precheck" {
		t.Errorf("StagePrecheck = %q", mcp.StagePrecheck)
	}
}

func TestArgsInvalidIsADenial(t *testing.T) {
	if !mcp.NewToolError(mcp.CodeInvalidParams, "args_invalid", "x").Denial() {
		t.Error("args_invalid (refused against the reviewed schema) must be audited as a denial")
	}
}
