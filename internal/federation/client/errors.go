package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"

	"github.com/huynle/mcp-gateway/internal/netguard"
)

// ErrInvalidEndpoint is returned (wrapped) by Connect for a malformed
// Endpoint. It is a configuration error, not an upstream failure, so it is
// not an *Error.
var ErrInvalidEndpoint = errors.New("federation client: invalid endpoint")

// Class is the coarse kind of an upstream failure. Callers branch on it;
// messages shown to users and models are built from it, never from
// upstream text.
type Class string

// Error classes.
const (
	// ClassUnreachable: the server could not be reached or is failing
	// (dial/TLS errors, connection lost, HTTP 5xx, 408, 429).
	ClassUnreachable Class = "unreachable"
	// ClassBlocked: netguard refused the destination (Reason holds the
	// netguard reason) or a request left the endpoint's origin (Reason
	// ReasonCrossOrigin).
	ClassBlocked Class = "blocked"
	// ClassAuthRequired: HTTP 401 (WWWAuthenticate holds the challenge), or
	// the Authorizer could not supply credentials (Reason "authorizer").
	ClassAuthRequired Class = "auth_required"
	// ClassForbidden: HTTP 403.
	ClassForbidden Class = "forbidden"
	// ClassProtocol: the server does not speak MCP correctly (malformed
	// JSON, unexpected HTTP status or content type, JSON-RPC errors outside
	// tools/call, broken pagination).
	ClassProtocol Class = "protocol_error"
	// ClassTooLarge: a response exceeded MaxResultBytes or a list exceeded
	// MaxListItems.
	ClassTooLarge Class = "too_large"
	// ClassTimeout: the operation's deadline passed or its context was
	// cancelled.
	ClassTimeout Class = "timeout"
	// ClassToolError: the server answered tools/call with a JSON-RPC error
	// (unknown tool, invalid arguments). A tool that runs and fails is not
	// an error: it is a result with IsError set.
	ClassToolError Class = "tool_error"
)

// Reasons set by this package (netguard reasons are used verbatim).
const (
	ReasonCrossOrigin = "cross_origin" // redirect or SSE endpoint to another origin
	ReasonAuthorizer  = "authorizer"   // the Authorizer returned an error
)

// maxChallengeBytes caps the WWW-Authenticate value kept on an Error.
const maxChallengeBytes = 4096

// Error is a classified upstream failure. Its message contains only the
// operation, class, HTTP status, reason and JSON-RPC code: never upstream
// bodies or messages, URLs, or credentials. The underlying cause is
// available through errors.Is / errors.As (it may contain the URL, so do
// not log it unredacted).
type Error struct {
	Class Class
	// Op is the MCP operation: "connect", "tools/list", "tools/call", ...
	Op string
	// Status is the HTTP status that decided the class, if any.
	Status int
	// WWWAuthenticate is the challenge of a 401 (or 403) response, kept for
	// the upstream-auth flow. Upstream-controlled: never show it verbatim.
	WWWAuthenticate string
	// Reason refines Class (netguard reason, ReasonCrossOrigin, ...).
	Reason string
	// RPCCode is the JSON-RPC error code when the server answered with one.
	RPCCode int64

	err error
}

func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString("federation client: ")
	if e.Op != "" {
		b.WriteString(e.Op)
		b.WriteString(": ")
	}
	b.WriteString(string(e.Class))
	if e.Status != 0 {
		b.WriteString(" (HTTP " + strconv.Itoa(e.Status) + ")")
	}
	if e.RPCCode != 0 {
		b.WriteString(" (JSON-RPC " + strconv.FormatInt(e.RPCCode, 10) + ")")
	}
	if e.Reason != "" {
		b.WriteString(": " + e.Reason)
	}
	return b.String()
}

// Unwrap returns the underlying cause.
func (e *Error) Unwrap() error { return e.err }

// classify turns err from op into an *Error using the facts the observers
// recorded at the HTTP layer and ctx's state. Precedence: refusals
// (netguard, cross-origin, authorizer) > HTTP 401/403 > size > deadline >
// network failure > other HTTP status > JSON-RPC error > protocol.
func classify(ctx context.Context, op string, err error, obs ...*observer) *Error {
	var ce *Error
	if errors.As(err, &ce) && ce.Op != "" {
		return ce
	}
	f := merge(obs)
	mk := func(c Class) *Error { return &Error{Class: c, Op: op, err: err} }

	if ce != nil { // one of our own refusals (cross-origin, authorizer)
		e := *ce
		e.Op = op
		return &e
	}
	if f.refusal != nil {
		e := *f.refusal
		e.Op = op
		return &e
	}
	var be *netguard.BlockedError
	if errors.As(err, &be) || errors.As(f.transportErr, &be) {
		e := mk(ClassBlocked)
		e.Reason = string(be.Reason)
		return e
	}
	switch f.status {
	case http.StatusUnauthorized, http.StatusForbidden:
		e := mk(ClassAuthRequired)
		if f.status == http.StatusForbidden {
			e.Class = ClassForbidden
		}
		e.Status = f.status
		e.WWWAuthenticate = f.challenge
		return e
	}
	if f.tooLarge {
		return mk(ClassTooLarge)
	}
	if ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return mk(ClassTimeout)
	}
	if f.transportErr != nil {
		var ne net.Error
		if errors.As(f.transportErr, &ne) && ne.Timeout() {
			return mk(ClassTimeout)
		}
		return mk(ClassUnreachable)
	}
	if f.status != 0 {
		e := mk(ClassProtocol)
		e.Status = f.status
		if f.status >= 500 || f.status == http.StatusRequestTimeout || f.status == http.StatusTooManyRequests {
			e.Class = ClassUnreachable
		}
		return e
	}
	var we *jsonrpc.Error
	if errors.As(err, &we) {
		e := mk(ClassProtocol)
		if op == opCallTool {
			e.Class = ClassToolError
		}
		e.RPCCode = we.Code
		return e
	}
	return mk(ClassProtocol)
}

// facts is the merged content of several observers.
type facts struct {
	status       int
	challenge    string
	transportErr error
	refusal      *Error
	tooLarge     bool
}

func merge(obs []*observer) facts {
	var f facts
	for _, o := range obs {
		if o == nil {
			continue
		}
		o.mu.Lock()
		if f.refusal == nil {
			f.refusal = o.refusal
		}
		f.tooLarge = f.tooLarge || o.tooLarge
		if f.transportErr == nil {
			f.transportErr = o.transportErr
		}
		if f.status == 0 || o.status == http.StatusUnauthorized || o.status == http.StatusForbidden {
			if o.status != 0 {
				f.status, f.challenge = o.status, o.challenge
			}
		}
		o.mu.Unlock()
	}
	return f
}

func truncateChallenge(s string) string {
	if len(s) > maxChallengeBytes {
		return s[:maxChallengeBytes]
	}
	return s
}

// errorf builds an unclassified-op *Error for refusals made inside the
// round tripper; classify fills in Op.
func refusal(c Class, reason string, cause error) *Error {
	if cause == nil {
		cause = fmt.Errorf("%s", reason)
	}
	return &Error{Class: c, Reason: reason, err: cause}
}
