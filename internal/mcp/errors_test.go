package mcp_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/mcp"
)

// sdkInternalCodes are the JSON-RPC error codes the official Go SDK's
// jsonrpc2 layer reserves for its own signalling (internal/jsonrpc2/wire.go
// in go-sdk v1.8.0: ErrUnknown, CodeResourceNotFound (pre-1.7), ErrClient-
// Closing, ErrServerClosing, ErrRejected) plus the mcp package's own
// (CodeHeaderMismatch, CodeMissingRequiredClientCapabilities,
// CodeUnsupportedProtocolVersion, CodeURLElicitationRequired). WireError.Is
// compares by code only, so a server error with one of these codes is
// mistaken for the SDK's condition: the client rewrites -32003 and -32004
// into ErrConnectionClosed ("connection closed: calling tools/call: ...")
// and drops the *jsonrpc.Error from the chain.
var sdkInternalCodes = map[int64]string{
	-32001: "ErrUnknown", -32002: "CodeResourceNotFound (pre-1.7)", -32003: "ErrClientClosing", -32004: "ErrServerClosing", -32005: "ErrRejected",
	-32020: "CodeHeaderMismatch", -32021: "CodeMissingRequiredClientCapabilities", -32022: "CodeUnsupportedProtocolVersion", -32042: "CodeURLElicitationRequired",
}

// gatewayCodes are every code the gateway returns from its own pipeline.
var gatewayCodes = map[string]int64{
	"unauthenticated":      mcp.CodeUnauthenticated,
	"denied":               mcp.CodeDenied,
	"no_account":           mcp.CodeNoAccount,
	"approval_required":    mcp.CodeApprovalRequired,
	"pending_verification": mcp.CodePendingVerification,
	"rate_limited":         mcp.CodeRateLimited,
}

func TestGatewayErrorCodesDoNotCollideWithTheSDKsInternalCodes(t *testing.T) {
	seen := map[int64]string{}
	for name, code := range gatewayCodes {
		if sdkName, clash := sdkInternalCodes[code]; clash {
			t.Errorf("%s = %d collides with go-sdk's %s", name, code, sdkName)
		}
		if code > -32000 || code < -32099 {
			t.Errorf("%s = %d is outside the JSON-RPC server-error range (-32000..-32099)", name, code)
		}
		if other, dup := seen[code]; dup {
			t.Errorf("%s and %s share code %d", name, other, code)
		}
		seen[code] = name
	}
}

// Every gateway refusal reaches the official SDK client as a *jsonrpc.Error
// carrying the gateway's code, so a harness can branch on it; none is
// rewritten into a transport failure.
func TestGatewayErrorsReachTheSDKClientAsJSONRPCErrors(t *testing.T) {
	cases := map[string]struct {
		code  int64
		class string
	}{
		"denied":               {mcp.CodeDenied, "policy_denied"},
		"no account":           {mcp.CodeNoAccount, "no_account"},
		"approval required":    {mcp.CodeApprovalRequired, "approval_required"},
		"pending verification": {mcp.CodePendingVerification, "pending_verification"},
		"rate limited":         {mcp.CodeRateLimited, "rate_limited"},
		"unauthenticated":      {mcp.CodeUnauthenticated, "unauthenticated"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			tool := stubTool("github", "list_issues", connectors.KindRead)
			tool.Handler = func(context.Context, connectors.Call) (connectors.Result, error) {
				return connectors.Result{}, mcp.NewToolError(tc.code, tc.class, "refused: "+name)
			}
			srv := httptest.NewServer(newHandler(t, newRegistry(t, tool), nil))
			t.Cleanup(srv.Close)
			cs := connect(t, srv.URL, fullToken, "2025-11-25")
			_, err := cs.CallTool(t.Context(), &sdk.CallToolParams{Name: "github.list_issues", Arguments: map[string]any{}})
			var je *jsonrpc.Error
			if !errors.As(err, &je) {
				t.Fatalf("SDK client got %v (%T), want *jsonrpc.Error with code %d", err, err, tc.code)
			}
			if je.Code != tc.code || je.Message != "refused: "+name {
				t.Errorf("error = %d %q, want %d", je.Code, je.Message, tc.code)
			}
			if errors.Is(err, sdk.ErrConnectionClosed) {
				t.Errorf("the SDK took %d for a closed connection", tc.code)
			}
		})
	}
}
