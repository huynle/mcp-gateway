package microsoft

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/microsoft/graph"
)

// Error classes a Microsoft tool error carries (Error.Class). They are
// short identifiers a harness or a log reader can branch on; the Message
// says what to do.
const (
	// ClassReconnectRequired: Graph rejected the account's token (401,
	// InvalidAuthenticationToken) or the connection has no usable token.
	// The user must reconnect the account on the portal.
	ClassReconnectRequired = "reconnect_required"
	// ClassNoAccount: the call carried no connected account.
	ClassNoAccount = "no_account"
	// ClassScopeRequired: the connected account has not granted a
	// permission the tool needs (or cannot: personal accounts and Teams).
	ClassScopeRequired = "scope_required"
	// ClassNotFound: the resource does not exist or the account cannot see
	// it (404, ErrorItemNotFound, itemNotFound, ResourceNotFound).
	ClassNotFound = "not_found"
	// ClassForbidden: the token is valid but lacks the permission or the
	// tenant denies it (403, Authorization_RequestDenied, accessDenied).
	ClassForbidden = "forbidden"
	// ClassInvalidArgument: the arguments were rejected by the connector or
	// by Graph (400, 409 name conflicts, 422).
	ClassInvalidArgument = "invalid_argument"
	// ClassUnavailable: Graph answered 5xx (not a throttle) or could not be
	// reached. Reads turn this into Result{Unavailable: true}.
	ClassUnavailable = "unavailable"
	// ClassVendorError: any other Graph error.
	ClassVendorError = "vendor_error"
)

// DefaultRetryAfter is the wait reported for a throttle Graph did not put
// a Retry-After on.
const DefaultRetryAfter = 60 * time.Second

// Error is a classified Graph failure: the HTTP status (0 when the
// request never got an answer or the connector refused the call), a
// Class and a message safe to show the harness (never the token, never
// response bodies beyond Graph's own message).
type Error struct {
	Status  int
	Class   string
	Message string
	Err     error
}

// Error implements error.
func (e *Error) Error() string {
	if e.Status > 0 {
		return fmt.Sprintf("microsoft: %s (http %d)", e.Message, e.Status)
	}
	return "microsoft: " + e.Message
}

// Unwrap returns the underlying graph or transport error.
func (e *Error) Unwrap() error { return e.Err }

// classify turns an error from the graph client into the connector's
// error vocabulary: nil stays nil, context errors pass through untouched
// (the pipeline treats them as cancellation), throttles become
// *connectors.RateLimited with Graph's Retry-After, Graph answers become
// *Error with a Class by status and error code, and anything else (DNS,
// TLS, connection reset) is ClassUnavailable.
func classify(action string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, connections.ErrNeedsReconnect) {
		return &Error{Class: ClassReconnectRequired, Message: action + ": this Microsoft account needs to be reconnected on the portal (Connections)", Err: err}
	}
	var ge *graph.Error
	if errors.As(err, &ge) {
		if ge.Throttled() {
			wait := ge.RetryAfter
			if wait <= 0 {
				wait = DefaultRetryAfter
			}
			return &connectors.RateLimited{App: App, RetryAfter: wait}
		}
		return fromGraph(action, ge, err)
	}
	return &Error{Class: ClassUnavailable, Message: action + ": Microsoft Graph could not be reached: " + err.Error(), Err: err}
}

// fromGraph maps a Graph answer to a classified Error. The error code
// decides when it is one Graph documents; the status decides otherwise.
func fromGraph(action string, ge *graph.Error, err error) *Error {
	e := &Error{Status: ge.Status, Err: err}
	code := strings.ToLower(ge.Code)
	switch {
	case ge.Status == http.StatusUnauthorized || code == "invalidauthenticationtoken":
		e.Class = ClassReconnectRequired
		e.Message = action + ": Microsoft rejected this account's token; reconnect your Microsoft account on the portal (Connections)"
	case ge.Status == http.StatusForbidden || code == "authorization_requestdenied" || code == "accessdenied" || code == "erroraccessdenied":
		e.Class = ClassForbidden
		e.Message = action + ": not allowed: the account lacks the permission, or the tenant denies it"
	case ge.Status == http.StatusNotFound || ge.Status == http.StatusGone || code == "erroritemnotfound" || code == "itemnotfound" || code == "resourcenotfound" || code == "notfound" || code == "request_resourcenotfound":
		e.Class = ClassNotFound
		e.Message = action + ": not found, or this account cannot see it"
	case ge.Status == http.StatusBadRequest || ge.Status == http.StatusConflict || ge.Status == http.StatusUnprocessableEntity || code == "errorinvalidrequest" || code == "badrequest" || code == "invalidrequest" || code == "namealreadyexists":
		e.Class = ClassInvalidArgument
		e.Message = action + ": Microsoft Graph rejected the request"
	case ge.Status >= 500:
		e.Class = ClassUnavailable
		e.Message = action + ": Microsoft Graph is unavailable"
	default:
		e.Class = ClassVendorError
		e.Message = action + ": Microsoft Graph error"
	}
	if ge.Code != "" || ge.Message != "" {
		e.Message += " (" + strings.TrimSpace(strings.TrimSpace(ge.Code)+" "+ge.Message) + ")"
	}
	return e
}

// classOf returns the class behind a classified error, "" when none.
func classOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Class
	}
	return ""
}

// invalid builds an invalid-argument error.
func invalid(format string, a ...any) error {
	return &Error{Class: ClassInvalidArgument, Message: fmt.Sprintf(format, a...)}
}

// statusOf returns the HTTP status behind a classified error, 0 when none.
func statusOf(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.Status
	}
	return 0
}
