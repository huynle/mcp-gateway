package mcp_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/store"
)

// An upstream MCP result (a federated tool's) passes through as is:
// content blocks, structuredContent and isError.
func TestCallToolResultPassesThrough(t *testing.T) {
	upstream := &sdk.CallToolResult{
		Content:           []sdk.Content{&sdk.TextContent{Text: "found 2"}},
		StructuredContent: map[string]any{"count": 2},
	}
	failed := &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "no such note"}}, IsError: true}
	empty := &sdk.CallToolResult{}
	tool := func(name string, res *sdk.CallToolResult) connectors.Tool {
		t := stubTool("github", name, connectors.KindRead)
		t.Handler = func(context.Context, connectors.Call) (connectors.Result, error) {
			return connectors.Result{Content: res}, nil
		}
		return t
	}
	reg := newRegistry(t, tool("list_issues", upstream), tool("list_prs", failed), tool("list_runs", empty))
	srv := httptest.NewServer(newHandler(t, reg, nil))
	defer srv.Close()
	cs := connect(t, srv.URL, fullToken, "")

	res, err := cs.CallTool(t.Context(), &sdk.CallToolParams{Name: "github.list_issues", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError || len(res.Content) != 1 || res.Content[0].(*sdk.TextContent).Text != "found 2" {
		t.Errorf("content = %+v isError=%v", res.Content, res.IsError)
	}
	sc, _ := json.Marshal(res.StructuredContent)
	if string(sc) != `{"count":2}` {
		t.Errorf("structuredContent = %s", sc)
	}

	res, err = cs.CallTool(t.Context(), &sdk.CallToolParams{Name: "github.list_prs", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || res.Content[0].(*sdk.TextContent).Text != "no such note" {
		t.Errorf("upstream isError not passed through: %+v", res)
	}

	res, err = cs.CallTool(t.Context(), &sdk.CallToolParams{Name: "github.list_runs", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Content == nil || len(res.Content) != 0 {
		t.Errorf("empty upstream result content = %#v, want an empty list", res.Content)
	}
}

// classed is a handler error that names its own audit / ledger class.
type classed struct{ class string }

func (c classed) Error() string      { return "upstream unreachable" }
func (c classed) ErrorClass() string { return c.class }

// A handler error with a class (federation: tunnel_offline,
// upstream_unreachable, ...) is audited and ledgered under that class.
func TestClassedHandlerErrorsKeepTheirClass(t *testing.T) {
	failing := echoTool("github", "list_issues", connectors.KindRead)
	failing.Handler = func(context.Context, connectors.Call) (connectors.Result, error) {
		return connectors.Result{}, classed{"tunnel_offline"}
	}
	rec := &captureRecorder{}
	p := defaultPipeline(t, newRegistry(t, failing), rec, nil)
	_, err := p.Run(context.Background(), &mcp.CallContext{Principal: principal, Name: "github.list_issues", RawArgs: map[string]any{}})
	if err == nil {
		t.Fatal("expected the handler error")
	}
	if len(rec.events) != 1 || rec.events[0].ErrorClass != "tunnel_offline" || rec.events[0].Outcome != "failed" {
		t.Errorf("events = %+v", rec.events)
	}

	f := newLedgerFixture(t, nil)
	f.handler = func(context.Context, connectors.Call) (connectors.Result, error) {
		return connectors.Result{}, classed{"upstream_forbidden"}
	}
	cc, _, err := f.run(t, t.Context(), "github.create_issue", map[string]any{"repo": "acme/web"})
	if err == nil {
		t.Fatal("expected the handler error")
	}
	if row := f.st.Operation(cc.OperationID); row == nil || row.State != store.LedgerFailed || row.ErrorCode == nil || *row.ErrorCode != "upstream_forbidden" {
		t.Errorf("row = %+v", row)
	}
	// ErrOutcomeUnknown still wins over the class.
	f2 := newLedgerFixture(t, nil)
	f2.handler = func(context.Context, connectors.Call) (connectors.Result, error) {
		return connectors.Result{}, errors.Join(classed{"upstream_timeout"}, connectors.ErrOutcomeUnknown)
	}
	cc, _, _ = f2.run(t, t.Context(), "github.create_issue", map[string]any{"repo": "acme/web"})
	if row := f2.st.Operation(cc.OperationID); row == nil || row.State != store.LedgerUnknown {
		t.Errorf("unknown outcome row = %+v", row)
	}
}
