package mcp_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

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
	"scope_required":       mcp.CodeScopeRequired,
	"upstream":             mcp.CodeUpstream,
	"secret_unavailable":   mcp.CodeSecretUnavailable,
}

// sdkCodesUsedOnPurpose are SDK codes the gateway returns with exactly the
// SDK's meaning, so a harness's SDK handles them as the spec says:
// "secret required" is a URL elicitation (design correction 1).
var sdkCodesUsedOnPurpose = map[string]int64{
	"secret_required": mcp.CodeSecretRequired,
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
	for name, code := range sdkCodesUsedOnPurpose {
		if _, ok := sdkInternalCodes[code]; !ok {
			t.Errorf("%s = %d is not an SDK code; move it to gatewayCodes", name, code)
		}
		if other, dup := seen[code]; dup {
			t.Errorf("%s and %s share code %d", name, other, code)
		}
	}
	if mcp.CodeSecretRequired != sdk.CodeURLElicitationRequired {
		t.Errorf("CodeSecretRequired = %d, want the SDK's CodeURLElicitationRequired %d", mcp.CodeSecretRequired, sdk.CodeURLElicitationRequired)
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
		"secret unavailable":   {mcp.CodeSecretUnavailable, "secret_unavailable"},
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

// Federated-tool refusals (the review refused the tool, or the arguments
// do not match its reviewed schema: Brain task 8ky7l4e6) are gateway
// denials in the audit row, like policy denials; credential problems are
// failures.
func TestFederationRefusalsAreDenials(t *testing.T) {
	for _, class := range []string{"tool_disabled", "tool_not_reviewed", "tool_changed", "args_invalid"} {
		if !mcp.NewToolError(mcp.CodeDenied, class, "x").Denial() {
			t.Errorf("%s is not a denial", class)
		}
	}
	for _, class := range []string{"auth_required", "needs_reconnect"} {
		if mcp.NewToolError(mcp.CodeNoAccount, class, "x").Denial() {
			t.Errorf("%s is a denial", class)
		}
	}
}

// The secret errors: "unavailable" is one fixed answer for every cause
// (expired, used up, revoked, wrong binding, not yours), a failure in the
// audit row; the user's Deny is a denial on -32030; "required" is the
// SDK's URL elicitation code carrying the caller's data.
func TestSecretErrors(t *testing.T) {
	a, b := mcp.ErrSecretUnavailable(), mcp.ErrSecretUnavailable()
	if a == b {
		t.Error("ErrSecretUnavailable returns a shared value; callers may not mutate it")
	}
	if a.Code != mcp.CodeSecretUnavailable || mcp.CodeSecretUnavailable != -32037 || a.Class() != "secret_unavailable" || a.Message != b.Message ||
		a.Data != nil || a.RetryAfter != 0 || a.Denial() {
		t.Errorf("ErrSecretUnavailable = %+v (class %s, denial %v)", a, a.Class(), a.Denial())
	}
	d := mcp.ErrSecretDenied()
	if d.Code != mcp.CodeDenied || d.Class() != "secret_denied" || d.Message != "secret request denied" || !d.Denial() {
		t.Errorf("ErrSecretDenied = %+v (class %s, denial %v)", d, d.Class(), d.Denial())
	}
	data := map[string]any{"url": "https://gw/s/x"}
	r := mcp.NewSecretRequired("open the link", data)
	if r.Code != -32042 || r.Class() != "secret_required" || r.Message != "open the link" || r.Data["url"] != "https://gw/s/x" || r.Denial() {
		t.Errorf("NewSecretRequired = %+v (class %s)", r, r.Class())
	}
	l := mcp.ErrSecretsLimited(90 * time.Second)
	if l.Code != mcp.CodeRateLimited || l.Class() != "secret_requests_limited" || l.RetryAfterSeconds() != 90 || !l.Denial() {
		t.Errorf("ErrSecretsLimited = %+v (class %s)", l, l.Class())
	}
}

// A -32042 answer reaches an SDK client without an elicitation handler as
// the *jsonrpc.Error with the elicitation data intact.
func TestSecretRequiredReachesTheSDKClient(t *testing.T) {
	tool := stubTool("github", "list_issues", connectors.KindRead)
	tool.Handler = func(context.Context, connectors.Call) (connectors.Result, error) {
		return connectors.Result{}, mcp.NewSecretRequired("open https://gw/s/abc", map[string]any{
			"elicitations": []any{map[string]any{"mode": "url", "elicitationId": "e1", "url": "https://gw/s/abc", "message": "m"}},
			"url":          "https://gw/s/abc",
		})
	}
	srv := httptest.NewServer(newHandler(t, newRegistry(t, tool), nil))
	t.Cleanup(srv.Close)
	cs := connect(t, srv.URL, fullToken, "2025-11-25")
	_, err := cs.CallTool(t.Context(), &sdk.CallToolParams{Name: "github.list_issues", Arguments: map[string]any{}})
	var je *jsonrpc.Error
	if !errors.As(err, &je) || je.Code != sdk.CodeURLElicitationRequired {
		t.Fatalf("SDK client got %v, want -32042", err)
	}
	var data struct {
		Elicitations []sdk.ElicitParams `json:"elicitations"`
		URL          string             `json:"url"`
	}
	if err := json.Unmarshal(je.Data, &data); err != nil || len(data.Elicitations) != 1 || data.Elicitations[0].URL != "https://gw/s/abc" ||
		data.Elicitations[0].ElicitationID != "e1" || data.URL != "https://gw/s/abc" {
		t.Errorf("data = %s (%v)", je.Data, err)
	}
}
