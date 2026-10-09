package mcp

import (
	"fmt"
	"time"
)

// JSON-RPC error codes the gateway returns for tools/call. CodeToolNotFound
// and CodeInvalidParams reuse the standard "invalid params" code (the SDK
// does the same for unknown tools); the others are in the server-defined
// range (-32000..-32099), in the gateway's own block -32029..-32035.
//
// The block avoids the codes the official Go SDK reserves for its own
// signalling (-32001..-32005: ErrUnknown, CodeResourceNotFound,
// ErrClientClosing, ErrServerClosing, ErrRejected; -32020..-32022 and
// -32042 in the mcp package): the SDK's WireError.Is compares by code
// only, so an answer with one of those codes is mistaken for the SDK's
// condition (-32003 and -32004 came back to the client as "connection
// closed" with the *jsonrpc.Error dropped from the chain). errors_test.go
// guards the block.
const (
	CodeInvalidParams int64 = -32602
	CodeToolNotFound  int64 = -32602
	CodeRateLimited   int64 = -32029
	CodeDenied        int64 = -32030
	// CodeNoAccount: the user has no connected account for the tool's app;
	// changing the arguments cannot fix it, connecting one can.
	CodeNoAccount int64 = -32031
	// CodeApprovalRequired: policy says confirm and the call has no
	// granted approval yet (decision 490o45d0; the approvals task adds
	// the approval id and the retry contract to this error).
	CodeApprovalRequired int64 = -32032
	// CodePendingVerification: an earlier attempt of the same write is
	// still in progress or awaiting reconciliation, so the gateway will
	// not run it again yet (decision dovthftx; the ledger stage).
	CodePendingVerification int64 = -32033
	CodeUnauthenticated     int64 = -32034
	// CodeScopeRequired: the resolved account has not granted a scope the
	// tool needs; error.data carries app, account, missing_scopes and
	// portal_url. Changing the arguments cannot fix it, granting more
	// access to the account on the portal can (the scope stage).
	CodeScopeRequired int64 = -32035
	// CodeInternal is the JSON-RPC internal error, used when a gateway
	// dependency (the account source) failed; the message never carries
	// the cause.
	CodeInternal int64 = -32603
)

// ToolError is a failure of the gateway's own pipeline (not of the tool):
// unknown tool, bad injected argument, rate limit, policy denial. The
// endpoint reports it as a JSON-RPC error with Code and Message, byte for
// byte the same for every caller that hits the same condition. Errors a
// tool Handler returns are not ToolErrors; they become tool results with
// IsError set so the model can see and react to them.
type ToolError struct {
	Code    int64
	Message string
	// RetryAfter, when set, is how long the harness should wait before
	// retrying (rate limits); the endpoint puts it on the wire as
	// error.data.retry_after in whole seconds, rounded up.
	RetryAfter time.Duration
	// Data, when set, is merged into error.data on the wire (the approval
	// id and instructions of an "approval required" answer). Never
	// argument content.
	Data map[string]any
	// class is the short audit error class (ErrorClass column).
	class string
}

func (e *ToolError) Error() string { return e.Message }

// Class returns the audit error class for this error.
func (e *ToolError) Class() string { return e.class }

// Denial reports whether the error is the gateway refusing the call
// (audit decision deny / outcome denied) rather than a precondition or
// argument failure (outcome failed). Codes alone cannot tell: invalid
// params and unknown tool share -32602.
func (e *ToolError) Denial() bool {
	switch e.class {
	case "tool_not_found", "denied", "rate_limited", "vendor_rate_limited", "unauthenticated",
		"approval_mismatch", "approval_denied", "approval_used", "approval_expired", "pending_verification":
		return true
	}
	return false
}

// NewToolError builds a ToolError with an audit class.
func NewToolError(code int64, class, message string) *ToolError {
	return &ToolError{Code: code, Message: message, class: class}
}

// RetryAfterSeconds is RetryAfter in whole seconds, rounded up, at least 1
// when RetryAfter is set.
func (e *ToolError) RetryAfterSeconds() int64 {
	if e.RetryAfter <= 0 {
		return 0
	}
	return int64((e.RetryAfter + time.Second - 1) / time.Second)
}

// ErrToolNotFound is the one error for a tool that does not exist or that
// the caller may not see (decisions t109ks1d, 490o45d0): the message never
// says which.
func ErrToolNotFound(name string) *ToolError {
	return NewToolError(CodeToolNotFound, "tool_not_found", fmt.Sprintf("unknown tool %q", name))
}

// errUnauthenticated is returned when no principal reached the pipeline.
var errUnauthenticated = NewToolError(CodeUnauthenticated, "unauthenticated", "authentication required")
