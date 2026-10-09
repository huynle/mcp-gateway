package mcp_test

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/fake"
	"github.com/huynle/mcp-gateway/internal/mcp"
)

// scopeFixture registers the fake connector with list_items requiring
// two vendor scopes and get_item one, on top of an account source whose
// accounts carry recorded scopes, and builds the pipeline with the scope
// stage (no policy: the stage sits before it).
type scopeFixture struct {
	fake  *fake.Connector
	reg   *connectors.Registry
	src   *connectors.StaticAccountSource
	rec   *captureRecorder
	p     *mcp.Pipeline
	calls int
}

func newScopeFixture(t *testing.T) *scopeFixture {
	t.Helper()
	f := &scopeFixture{fake: fake.New(fake.Options{}), reg: connectors.NewRegistry(), src: connectors.NewStaticAccountSource(), rec: &captureRecorder{}}
	for _, tool := range f.fake.Tools() {
		switch tool.Name {
		case fake.ToolListItems:
			tool.RequiredScopes = []string{"items:read", "items:list"}
		case fake.ToolGetItem:
			tool.RequiredScopes = []string{"items:read"}
		}
		tool.Handler = func(ctx context.Context, call connectors.Call) (connectors.Result, error) {
			f.calls++
			return f.fake.Call(ctx, call)
		}
		if err := f.reg.Register(tool); err != nil {
			t.Fatal(err)
		}
	}
	p, err := mcp.DefaultPipeline(mcp.PipelineDeps{
		Registry: f.reg, Accounts: f.src, Audit: f.rec, Log: slog.New(slog.DiscardHandler), BaseURL: "https://gw.example.test/",
	})
	if err != nil {
		t.Fatal(err)
	}
	f.p = p
	return f
}

func (f *scopeFixture) account(id string, scopes ...string) {
	f.src.Add("user-1", connectors.Account{ID: id, App: fake.App, Label: connectors.LabelCompany, DisplayName: id, Scopes: scopes})
}

func (f *scopeFixture) run(t *testing.T, tool string, args map[string]any) (connectors.Result, error) {
	t.Helper()
	return f.p.Run(context.Background(), &mcp.CallContext{Principal: principal, Name: tool, RawArgs: args})
}

func scopeRequired(t *testing.T, err error) *mcp.ToolError {
	t.Helper()
	var te *mcp.ToolError
	if !errors.As(err, &te) || te.Code != mcp.CodeScopeRequired || te.Class() != "scope_required" {
		t.Fatalf("err = %v, want ToolError{CodeScopeRequired, scope_required}", err)
	}
	return te
}

func TestScopeStageSitsBetweenAccountAndRateLimit(t *testing.T) {
	f := newScopeFixture(t)
	want := []string{mcp.StageAuthenticate, mcp.StageAudit, mcp.StageResolve, mcp.StageStrip, mcp.StageAccount, mcp.StageScope, mcp.StageRateLimit, mcp.StageDispatch}
	if got := f.p.Names(); !reflect.DeepEqual(got, want) {
		t.Errorf("Names = %v, want %v", got, want)
	}
}

func TestScopeStageRefusesUnderScopedAccountBeforeTheConnector(t *testing.T) {
	f := newScopeFixture(t)
	f.account("acc-1", "items:read")
	_, err := f.run(t, "fake.list_items", nil)
	te := scopeRequired(t, err)
	if f.calls != 0 {
		t.Errorf("the connector ran %d times", f.calls)
	}
	for _, want := range []string{"fake.list_items", "items:list", "acc-1", "https://gw.example.test/connections"} {
		if !strings.Contains(te.Message, want) {
			t.Errorf("message %q lacks %q", te.Message, want)
		}
	}
	if strings.Contains(te.Message, "items:read,") || strings.Contains(te.Message, "items:read ") {
		t.Errorf("message %q names a granted scope as missing", te.Message)
	}
	if te.Data["app"] != fake.App || te.Data["account"] != "acc-1" || te.Data["portal_url"] != "https://gw.example.test/connections" {
		t.Errorf("data = %v", te.Data)
	}
	if missing, _ := te.Data["missing_scopes"].([]string); !reflect.DeepEqual(missing, []string{"items:list"}) {
		t.Errorf("missing_scopes = %v", te.Data["missing_scopes"])
	}
	ev := f.rec.events[0]
	if ev.Outcome != "failed" || ev.ErrorClass != "scope_required" || ev.AccountID != "acc-1" {
		t.Errorf("audit = %+v", ev)
	}
}

func TestScopeStagePassesCoveredAccounts(t *testing.T) {
	f := newScopeFixture(t)
	f.account("acc-1", "ITEMS:READ", " items:list ")
	f.fake.SeedItems("acc-1", fake.Item{ID: "x", Name: "x"})
	if _, err := f.run(t, "fake.list_items", nil); err != nil {
		t.Fatalf("covered (case and space insensitive): %v", err)
	}
	if _, err := f.run(t, "fake.get_item", map[string]any{"id": "x"}); err != nil {
		t.Fatalf("single scope: %v", err)
	}
	if f.calls != 2 {
		t.Errorf("connector calls = %d, want 2", f.calls)
	}
}

func TestScopeStageSkipsAccountsWithoutRecordedScopes(t *testing.T) {
	f := newScopeFixture(t)
	f.account("acc-1")
	if _, err := f.run(t, "fake.list_items", nil); err != nil {
		t.Fatalf("no recorded scopes must not block: %v", err)
	}
	// Tools that require nothing are never refused.
	f2 := newScopeFixture(t)
	f2.account("acc-2", "something:else")
	if _, err := f2.run(t, "fake.post_note", map[string]any{"text": "hi"}); err != nil {
		t.Fatalf("tool without RequiredScopes: %v", err)
	}
	// A NoAccount tool (list_accounts) never reaches the check: its
	// registration through RegisterConnector sets NoAccount, so the
	// stage sees no account and no scopes.
	reg := connectors.NewRegistry()
	src := connectors.NewStaticAccountSource()
	src.Add("user-1", connectors.Account{ID: "acc-3", App: fake.App, Label: connectors.LabelCompany, DisplayName: "acc-3", Scopes: []string{"nothing"}})
	if err := connectors.RegisterConnector(reg, fake.New(fake.Options{}), src); err != nil {
		t.Fatal(err)
	}
	p, err := mcp.DefaultPipeline(mcp.PipelineDeps{Registry: reg, Accounts: src, Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Run(context.Background(), &mcp.CallContext{Principal: principal, Name: "fake.list_accounts"}); err != nil {
		t.Fatalf("list_accounts: %v", err)
	}
}

func TestScopeStageUsesTheAppCoverageFunction(t *testing.T) {
	f := newScopeFixture(t)
	f.account("acc-1", "items:all")
	if _, err := f.run(t, "fake.list_items", nil); err == nil {
		t.Fatal("items:all must not cover anything under the default coverage")
	}
	f.reg.SetScopeCoverage(fake.App, func(granted []string, required string) bool {
		return connectors.ScopeEquals(granted, "items:all") || connectors.ScopeEquals(granted, required)
	})
	if _, err := f.run(t, "fake.list_items", nil); err != nil {
		t.Fatalf("with the app's coverage: %v", err)
	}
	f.reg.SetScopeCoverage(fake.App, nil)
	if _, err := f.run(t, "fake.list_items", nil); err == nil {
		t.Fatal("nil restores the default coverage")
	}
}

func TestScopeStageDoesNotFilterToolsList(t *testing.T) {
	// Visibility is per principal, not per account: the stage changes
	// nothing about resolve, so an under-scoped account still resolves
	// the tool (and is told at call time which scope is missing).
	f := newScopeFixture(t)
	f.account("acc-1", "nothing")
	_, err := f.run(t, "fake.list_items", nil)
	te := scopeRequired(t, err)
	if te.Code == mcp.CodeToolNotFound {
		t.Errorf("the tool was hidden instead of refused: %v", err)
	}
}
