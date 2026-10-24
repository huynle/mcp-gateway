package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// JSON-RPC error codes the gateway returns for tools/call. CodeToolNotFound
// and CodeInvalidParams reuse the standard "invalid params" code (the SDK
// does the same for unknown tools); the others are in the server-defined
// range (-32000..-32099), in the gateway's own block -32029..-32037
// (CodeUpstream, -32036, lives in resources.go).
//
// The block avoids the codes the official Go SDK reserves for its own
// signalling (-32001..-32005: ErrUnknown, CodeResourceNotFound,
// ErrClientClosing, ErrServerClosing, ErrRejected; -32020..-32022 and
// -32042 in the mcp package): the SDK's WireError.Is compares by code
// only, so an answer with one of those codes is mistaken for the SDK's
// condition (-32003 and -32004 came back to the client as "connection
// closed" with the *jsonrpc.Error dropped from the chain). errors_test.go
// guards the block. The one deliberate exception is the SDK's own -32042
// (CodeSecretRequired, NewURLElicitationRequired), used with exactly its
// meaning: a URL elicitation the harness must complete before retrying.
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
	// CodeSecretUnavailable: a {"$secret": handle} reference in the
	// arguments cannot be used for this call: expired, used up, revoked,
	// bound to another tool or argument, or not the caller's. One fixed
	// answer for every cause (ErrSecretUnavailable); the harness asks for
	// a new secret with secrets.request.
	CodeSecretUnavailable int64 = -32037
	// CodeSecretRequired is the SDK's URL elicitation code (-32042): the
	// user must enter a secret at the link in error.data before the call
	// can run (secrets.request, and a retry with a handle not entered yet).
	CodeSecretRequired int64 = sdk.CodeURLElicitationRequired
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
	case "tool_not_found", "denied", "identity_unresolved", "rate_limited", "vendor_rate_limited", "unauthenticated",
		"approval_mismatch", "approval_denied", "approval_used", "approval_expired", "pending_verification",
		// Federated tools the server's review does not allow (connector),
		// and arguments outside the reviewed input schema (refused by the
		// gateway before policy or at dispatch, Brain task 8ky7l4e6).
		"tool_disabled", "tool_not_reviewed", "tool_changed", "args_invalid",
		// Resources and prompts that do not exist or are hidden.
		"resource_not_found", "prompt_not_found",
		// Ephemeral secrets: the user denied the request; too many requests.
		"secret_denied", "secret_requests_limited":
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

// ClassedError is a tool handler error that names its own short error
// class (the federation connector's tunnel_offline, upstream_timeout,
// ...). The audit row and a failed ledger operation record that class
// instead of the generic "tool_error"; the class must be a fixed
// identifier, never upstream text.
type ClassedError interface {
	error
	ErrorClass() string
}

// errorClass returns err's ClassedError class, or fallback.
func errorClass(err error, fallback string) string {
	var ce ClassedError
	if errors.As(err, &ce) && ce.ErrorClass() != "" {
		return ce.ErrorClass()
	}
	return fallback
}

// ErrToolNotFound is the one error for a tool that does not exist or that
// the caller may not see (decisions t109ks1d, 490o45d0): the message never
// says which.
func ErrToolNotFound(name string) *ToolError {
	return NewToolError(CodeToolNotFound, "tool_not_found", fmt.Sprintf("unknown tool %q", name))
}

// errUnauthenticated is returned when no principal reached the pipeline.
var errUnauthenticated = NewToolError(CodeUnauthenticated, "unauthenticated", "authentication required")

// secretUnavailableMessage is the one text of every "secret unavailable"
// answer; it must not depend on the cause.
const secretUnavailableMessage = "secret unavailable: it expired, was used up or revoked, or is not for this call; " +
	"request a new one with secrets.request"

// ErrSecretUnavailable is the answer for a secret reference that cannot
// be used for this call, byte for byte the same whatever the cause
// (design section 3). It returns a new value each time so a caller that
// sets fields cannot change the next answer.
func ErrSecretUnavailable() *ToolError {
	return NewToolError(CodeSecretUnavailable, "secret_unavailable", secretUnavailableMessage)
}

// ErrSecretDenied answers a call whose secret request the user denied:
// a gateway denial on CodeDenied.
func ErrSecretDenied() *ToolError {
	return NewToolError(CodeDenied, "secret_denied", "secret request denied")
}

// NewSecretRequired is the -32042 answer asking the user to enter a
// secret: message repeats the link, data carries the spec's
// elicitations[] plus url, handle and fingerprint. Neither may hold a
// secret value.
func NewSecretRequired(message string, data map[string]any) *ToolError {
	te := NewToolError(CodeSecretRequired, "secret_required", message)
	te.Data = data
	return te
}

// URLElicitation is one entry of a -32042 answer's data.elicitations: a
// page the user opens in the browser (MCP 2025-11-25 URL mode). It
// serializes to the spec shape {"mode":"url","elicitationId","url",
// "message"}. URL and Message are shown to the harness and the user; they
// must never carry a secret or upstream text.
type URLElicitation struct {
	ElicitationID string
	URL           string
	Message       string
}

// MarshalJSON writes the spec shape, mode included, in the spec's key
// order.
func (e URLElicitation) MarshalJSON() ([]byte, error) {
	return json.Marshal(urlElicitationWire{Mode: "url", ElicitationID: e.ElicitationID, URL: e.URL, Message: e.Message})
}

type urlElicitationWire struct {
	Mode          string `json:"mode"`
	ElicitationID string `json:"elicitationId"`
	URL           string `json:"url"`
	Message       string `json:"message"`
}

// NewURLElicitationRequired is a -32042 (the SDK's
// CodeURLElicitationRequired) answer with an audit class: the user must
// open a link before a retry can succeed. data.elicitations lists the
// links in the spec shape, data.url repeats the first for harnesses that
// read only url, and extra keys are merged in (they never replace
// elicitations or url). message should repeat the link for harnesses that
// ignore data. Data holds only maps, slices and strings, so the secrets
// stage can scrub it like any other error data.
func NewURLElicitationRequired(class, message string, elicitations []URLElicitation, extra map[string]any) *ToolError {
	data := make(map[string]any, len(extra)+2)
	for k, v := range extra {
		data[k] = v
	}
	list := make([]any, 0, len(elicitations))
	for _, e := range elicitations {
		list = append(list, map[string]any{"mode": "url", "elicitationId": e.ElicitationID, "url": e.URL, "message": e.Message})
	}
	data["elicitations"] = list
	delete(data, "url")
	if len(elicitations) > 0 {
		data["url"] = elicitations[0].URL
	}
	te := NewToolError(sdk.CodeURLElicitationRequired, class, message)
	te.Data = data
	return te
}

// ErrSecretsLimited answers a secrets.request beyond the per-user limits
// (pending requests, requests per hour) with the time to wait.
func ErrSecretsLimited(retryAfter time.Duration) *ToolError {
	te := NewToolError(CodeRateLimited, "secret_requests_limited",
		fmt.Sprintf("too many secret requests; retry in %s", retryAfter.Round(time.Second)))
	te.RetryAfter = retryAfter
	return te
}
