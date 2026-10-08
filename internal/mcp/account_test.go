package mcp_test

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// accountPipeline builds the default pipeline with an account source.
func accountPipeline(t *testing.T, reg *connectors.Registry, src connectors.AccountSource, rec audit.Recorder) *mcp.Pipeline {
	t.Helper()
	p, err := mcp.DefaultPipeline(mcp.PipelineDeps{
		Registry: reg, Accounts: src, Audit: rec, Log: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAccountStageSitsAfterStrip(t *testing.T) {
	p := accountPipeline(t, newRegistry(t), connectors.NewStaticAccountSource(), nil)
	want := []string{mcp.StageAuthenticate, mcp.StageAudit, mcp.StageResolve, mcp.StageStrip, mcp.StageAccount, mcp.StageRateLimit, mcp.StageDispatch}
	if got := p.Names(); !reflect.DeepEqual(got, want) {
		t.Errorf("Names = %v, want %v", got, want)
	}
	// Without a source the pipeline is unchanged (the account argument
	// passes through unchecked, as before this stage existed).
	if got := defaultPipeline(t, newRegistry(t), nil, nil).Names(); len(got) != 6 {
		t.Errorf("no source: Names = %v", got)
	}
}

func TestAccountStageAutoResolvesSingleAccount(t *testing.T) {
	src := connectors.NewStaticAccountSource()
	src.Add("user-1", connectors.Account{ID: "gh-1", App: "github", Label: connectors.LabelPersonal, DisplayName: "alice"})
	rec := &captureRecorder{}
	p := accountPipeline(t, newRegistry(t, echoTool("github", "list_issues", connectors.KindRead)), src, rec)
	res, err := p.Run(context.Background(), &mcp.CallContext{Principal: principal, Name: "github.list_issues"})
	if err != nil {
		t.Fatal(err)
	}
	if call := res.Content.(connectors.Call); call.Account != "gh-1" {
		t.Errorf("Call.Account = %q, want gh-1", call.Account)
	}
	ev := rec.events[0]
	if ev.AccountID != "gh-1" || ev.AccountLabel != "personal" || ev.Outcome != "succeeded" {
		t.Errorf("audit = %+v", ev)
	}
}

func TestAccountStageAcceptsOwnAccountWhenSeveral(t *testing.T) {
	src := connectors.NewStaticAccountSource()
	src.Add("user-1", connectors.Account{ID: "gh-1", App: "github", Label: connectors.LabelCompany, DisplayName: "acme"})
	src.Add("user-1", connectors.Account{ID: "gh-2", App: "github", Label: connectors.LabelPersonal, DisplayName: "alice"})
	rec := &captureRecorder{}
	p := accountPipeline(t, newRegistry(t, echoTool("github", "list_issues", connectors.KindRead)), src, rec)
	res, err := p.Run(context.Background(), &mcp.CallContext{Principal: principal, Name: "github.list_issues", RawArgs: map[string]any{"account": "gh-2"}})
	if err != nil {
		t.Fatal(err)
	}
	if call := res.Content.(connectors.Call); call.Account != "gh-2" {
		t.Errorf("Call.Account = %q", call.Account)
	}
	if ev := rec.events[0]; ev.AccountID != "gh-2" || ev.AccountLabel != "personal" {
		t.Errorf("audit = %+v", ev)
	}
}

func TestAccountStageRequiresChoiceWhenSeveral(t *testing.T) {
	src := connectors.NewStaticAccountSource()
	src.Add("user-1", connectors.Account{ID: "gh-1", App: "github", Label: connectors.LabelCompany, DisplayName: "acme"})
	src.Add("user-1", connectors.Account{ID: "gh-2", App: "github", Label: connectors.LabelPersonal, DisplayName: "alice"})
	src.Add("user-2", connectors.Account{ID: "gh-bob", App: "github", Label: connectors.LabelCompany, DisplayName: "bob"})
	rec := &captureRecorder{}
	p := accountPipeline(t, newRegistry(t, echoTool("github", "list_issues", connectors.KindRead)), src, rec)
	_, err := p.Run(context.Background(), &mcp.CallContext{Principal: principal, Name: "github.list_issues"})
	var te *mcp.ToolError
	if !errors.As(err, &te) || te.Code != mcp.CodeInvalidParams || te.Class() != "account_required" {
		t.Fatalf("err = %v, want ToolError{CodeInvalidParams, account_required}", err)
	}
	msg := te.Message
	for _, want := range []string{"account required", "github", "gh-1", "acme", "gh-2", "alice"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q lacks %q", msg, want)
		}
	}
	if strings.Contains(msg, "gh-bob") || strings.Contains(msg, "bob") {
		t.Errorf("message enumerates another user's account: %q", msg)
	}
	if ev := rec.events[0]; ev.Outcome != "failed" || ev.ErrorClass != "account_required" || ev.AccountID != "" {
		t.Errorf("audit = %+v", ev)
	}
}

func TestAccountStageRejectsForeignOrUnknownAccountIdentically(t *testing.T) {
	src := connectors.NewStaticAccountSource()
	src.Add("user-1", connectors.Account{ID: "gh-1", App: "github", Label: connectors.LabelCompany, DisplayName: "acme"})
	src.Add("user-2", connectors.Account{ID: "gh-2", App: "github", Label: connectors.LabelCompany, DisplayName: "bob"})
	src.Add("user-1", connectors.Account{ID: "sl-1", App: "slack", Label: connectors.LabelCompany, DisplayName: "acme slack"})
	rec := &captureRecorder{}
	reg := newRegistry(t, echoTool("github", "list_issues", connectors.KindRead))
	p := accountPipeline(t, reg, src, rec)

	run := func(account string) error {
		_, err := p.Run(context.Background(), &mcp.CallContext{Principal: principal, Name: "github.list_issues", RawArgs: map[string]any{"account": account}})
		return err
	}
	foreign := run("gh-2")    // another user's account
	unknown := run("gh-nope") // nobody's
	otherApp := run("sl-1")   // the caller's, but for another app
	for _, err := range []error{foreign, unknown, otherApp} {
		var te *mcp.ToolError
		if !errors.As(err, &te) || te.Code != mcp.CodeInvalidParams || te.Class() != "account_not_found" {
			t.Fatalf("err = %v, want ToolError{CodeInvalidParams, account_not_found}", err)
		}
		if strings.Contains(te.Message, "gh-1") || strings.Contains(te.Message, "bob") {
			t.Errorf("message enumerates accounts: %q", te.Message)
		}
	}
	// Foreign and unknown are byte-identical apart from the id echoed back.
	f, u := foreign.Error(), unknown.Error()
	if strings.ReplaceAll(f, "gh-2", "X") != strings.ReplaceAll(u, "gh-nope", "X") {
		t.Errorf("foreign %q vs unknown %q differ", f, u)
	}
	for _, ev := range rec.events {
		if ev.AccountID != "" || ev.Outcome != "failed" || ev.ErrorClass != "account_not_found" {
			t.Errorf("audit = %+v", ev)
		}
	}
}

func TestAccountStageNoAccountIsClear(t *testing.T) {
	src := connectors.NewStaticAccountSource()
	src.Add("user-1", connectors.Account{ID: "sl-1", App: "slack", Label: connectors.LabelCompany})
	rec := &captureRecorder{}
	p := accountPipeline(t, newRegistry(t, echoTool("github", "list_issues", connectors.KindRead)), src, rec)
	for _, raw := range []map[string]any{nil, {"account": "gh-1"}} {
		_, err := p.Run(context.Background(), &mcp.CallContext{Principal: principal, Name: "github.list_issues", RawArgs: raw})
		var te *mcp.ToolError
		if !errors.As(err, &te) || te.Code != mcp.CodeNoAccount || te.Class() != "no_account" || te.Message != "no connected account for github" {
			t.Errorf("raw %v: err = %v, want ToolError{CodeNoAccount, no_account, \"no connected account for github\"}", raw, err)
		}
	}
	if rec.events[0].ErrorClass != "no_account" || rec.events[0].Outcome != "failed" {
		t.Errorf("audit = %+v", rec.events[0])
	}
}

func TestAccountStageSkipsListAccounts(t *testing.T) {
	src := connectors.NewStaticAccountSource() // nobody has anything
	reg := connectors.NewRegistry()
	if err := reg.Register(connectors.ListAccountsTool("github", src)); err != nil {
		t.Fatal(err)
	}
	rec := &captureRecorder{}
	p := accountPipeline(t, reg, src, rec)
	res, err := p.Run(context.Background(), &mcp.CallContext{Principal: principal, Name: "github.list_accounts"})
	if err != nil || !res.Empty {
		t.Fatalf("list_accounts with no accounts: res=%+v err=%v", res, err)
	}
	if ev := rec.events[0]; ev.AccountID != "" || ev.Outcome != "succeeded" {
		t.Errorf("audit = %+v", ev)
	}
}

type failingSource struct{}

func (failingSource) ListAccounts(context.Context, string, string) ([]connectors.Account, error) {
	return nil, errors.New("connections db down: password=hunter2")
}

func TestAccountStageSourceFailureIsInternalError(t *testing.T) {
	rec := &captureRecorder{}
	p := accountPipeline(t, newRegistry(t, echoTool("github", "list_issues", connectors.KindRead)), failingSource{}, rec)
	_, err := p.Run(context.Background(), &mcp.CallContext{Principal: principal, Name: "github.list_issues"})
	var te *mcp.ToolError
	if !errors.As(err, &te) || te.Code != mcp.CodeInternal || te.Class() != "account_lookup_failed" {
		t.Fatalf("err = %v, want ToolError{CodeInternal, account_lookup_failed}", err)
	}
	if strings.Contains(te.Message, "hunter2") || strings.Contains(te.Message, "db down") {
		t.Errorf("message leaks the cause: %q", te.Message)
	}
}

func TestAccountStageUsesPrincipalNotArgs(t *testing.T) {
	// A caller cannot pick another user by smuggling a user id argument:
	// the stage only ever asks for the principal's accounts.
	src := connectors.NewStaticAccountSource()
	src.Add("user-2", connectors.Account{ID: "gh-bob", App: "github", Label: connectors.LabelCompany})
	p := accountPipeline(t, newRegistry(t, echoTool("github", "list_issues", connectors.KindRead)), src, nil)
	_, err := p.Run(context.Background(), &mcp.CallContext{
		Principal: &tokens.Principal{UserID: "user-1", TokenID: "t"}, Name: "github.list_issues",
		RawArgs: map[string]any{"user_id": "user-2", "account": "gh-bob"},
	})
	var te *mcp.ToolError
	if !errors.As(err, &te) || te.Class() != "no_account" {
		t.Errorf("err = %v", err)
	}
}
