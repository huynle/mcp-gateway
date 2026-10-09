package google

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"google.golang.org/api/googleapi"

	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Error classes a Google tool error carries (Error.Class). They are short
// identifiers a harness or a log reader can branch on; the Message says
// what to do.
const (
	// ClassReconnectRequired: Google rejected the account's token (401)
	// or the connection has no usable token. The user must reconnect the
	// account on the portal.
	ClassReconnectRequired = "reconnect_required"
	// ClassNoAccount: the call carried no connected account.
	ClassNoAccount = "no_account"
	// ClassScopeRequired: the account did not grant the scope the tool
	// needs (granular consent declined it, or Google answered 403
	// insufficientPermissions). The user must grant more access on the
	// portal (reconnect with the scope).
	ClassScopeRequired = "scope_required"
	// ClassNotFound: the resource does not exist or the account cannot
	// see it (404, 410).
	ClassNotFound = "not_found"
	// ClassForbidden: the token is valid but Google refused the action
	// (403 that is neither a quota nor a scope problem).
	ClassForbidden = "forbidden"
	// ClassInvalidArgument: the arguments were rejected by the connector
	// or by Google (400, 412, 422).
	ClassInvalidArgument = "invalid_argument"
	// ClassConflict: Google answered 409 (an event with the same id
	// already exists).
	ClassConflict = "conflict"
	// ClassUnavailable: Google answered 5xx or could not be reached.
	// Reads turn this into Result{Unavailable: true} rather than an error.
	ClassUnavailable = "unavailable"
	// ClassVendorError: any other Google error.
	ClassVendorError = "vendor_error"
)

// DefaultRetryAfter is the wait reported for a rate limit Google did not
// put a Retry-After on.
const DefaultRetryAfter = 60 * time.Second

// ErrMissingOperation is returned by every write called without
// Call.OperationID: the ledger stage sets it before dispatch, and the
// event id, marker and Message-ID reconciliation derive from it, so a
// write without one could never be verified after an unknown outcome.
// It means a pipeline wiring bug (a write dispatched without the
// ledger), never a harness mistake.
var ErrMissingOperation = errors.New("google: write called without a ledger operation id")

// Error is a classified Google API failure: the HTTP status (0 when the
// request never got an answer), a Class and a message safe to show the
// harness (never the token, never response bodies beyond Google's own
// message).
type Error struct {
	Status  int
	Class   string
	Message string
	Err     error
}

// Error implements error.
func (e *Error) Error() string {
	if e.Status > 0 {
		return fmt.Sprintf("google: %s (http %d)", e.Message, e.Status)
	}
	return "google: " + e.Message
}

// Unwrap returns the underlying googleapi or transport error.
func (e *Error) Unwrap() error { return e.Err }

// quotaReasons are the 403 reasons that mean "slow down", not "no".
var quotaReasons = map[string]bool{
	"rateLimitExceeded": true, "userRateLimitExceeded": true, "quotaExceeded": true, "dailyLimitExceeded": true,
	"RESOURCE_EXHAUSTED": true,
}

// scopeReasons are the 403 reasons that mean the token lacks a scope.
var scopeReasons = map[string]bool{
	"insufficientPermissions": true, "ACCESS_TOKEN_SCOPE_INSUFFICIENT": true,
}

// classify turns an error from the Google API client into the
// connector's error vocabulary: nil stays nil, context errors pass
// through untouched (the pipeline treats them as cancellation), 429 and
// the 403 quota reasons become *connectors.RateLimited with Google's
// Retry-After, HTTP statuses become *Error with a Class, and anything
// else (DNS, TLS, connection reset) is ClassUnavailable.
func classify(action string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, connections.ErrNeedsReconnect) {
		return &Error{Class: ClassReconnectRequired, Message: action + ": this Google account needs to be reconnected on the portal (Connections)", Err: err}
	}
	var ge *googleapi.Error
	if errors.As(err, &ge) {
		reason := reasonOf(ge)
		if ge.Code == http.StatusTooManyRequests || (ge.Code == http.StatusForbidden && quotaReasons[reason]) {
			return &connectors.RateLimited{App: Vendor, RetryAfter: retryAfter(ge.Header)}
		}
		return fromStatus(action, ge.Code, reason, ge.Message, err)
	}
	return &Error{Class: ClassUnavailable, Message: action + ": Google could not be reached: " + err.Error(), Err: err}
}

// reasonOf returns the first typed reason of a Google error ("notFound",
// "rateLimitExceeded", ...), "" when none.
func reasonOf(ge *googleapi.Error) string {
	for _, item := range ge.Errors {
		if item.Reason != "" {
			return item.Reason
		}
	}
	return ""
}

// fromStatus maps an HTTP status (and Google's reason) to a classified
// Error.
func fromStatus(action string, status int, reason, vendorMessage string, err error) *Error {
	e := &Error{Status: status, Err: err}
	switch {
	case status == http.StatusUnauthorized:
		e.Class = ClassReconnectRequired
		e.Message = action + ": Google rejected this account's token; reconnect your Google account on the portal (Connections)"
	case status == http.StatusForbidden && scopeReasons[reason]:
		e.Class = ClassScopeRequired
		e.Message = action + ": this Google account did not grant the access this tool needs; grant more access on the portal (Connections)"
	case status == http.StatusForbidden:
		e.Class = ClassForbidden
		e.Message = action + ": not allowed for this Google account"
	case status == http.StatusNotFound || status == http.StatusGone:
		e.Class = ClassNotFound
		e.Message = action + ": not found, or this account cannot see it"
	case status == http.StatusBadRequest || status == http.StatusPreconditionFailed || status == http.StatusUnprocessableEntity:
		e.Class = ClassInvalidArgument
		e.Message = action + ": Google rejected the request"
	case status == http.StatusConflict:
		e.Class = ClassConflict
		e.Message = action + ": Google reports a conflict (the resource already exists)"
	case status >= 500:
		e.Class = ClassUnavailable
		e.Message = action + ": Google is unavailable"
	default:
		e.Class = ClassVendorError
		e.Message = action + ": Google error"
	}
	if vendorMessage = strings.TrimSpace(vendorMessage); vendorMessage != "" {
		e.Message += " (" + vendorMessage + ")"
	}
	return e
}

// retryAfter reads a Retry-After header (seconds or HTTP date), at least
// one second, DefaultRetryAfter when absent or unreadable.
func retryAfter(h http.Header) time.Duration {
	raw := strings.TrimSpace(h.Get("Retry-After"))
	if raw == "" {
		return DefaultRetryAfter
	}
	if secs, err := strconv.Atoi(raw); err == nil {
		if secs < 1 {
			return time.Second
		}
		return time.Duration(secs) * time.Second
	}
	if at, err := http.ParseTime(raw); err == nil {
		d := time.Until(at).Round(time.Second)
		if d < time.Second {
			d = time.Second
		}
		return d
	}
	return DefaultRetryAfter
}

// classifyWrite maps the error of the request that performs a write: an
// answer from Google (4xx, rate limit) is a known outcome and is
// classified like a read's; anything that leaves the outcome open (5xx,
// a timeout, a cancelled context, a dropped connection: the request may
// have been applied) wraps connectors.ErrOutcomeUnknown so the ledger
// marks the operation unknown and the reconciler checks it.
func classifyWrite(action string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return fmt.Errorf("%w: %s: Google did not answer in time (%w)", connectors.ErrOutcomeUnknown, action, err)
	}
	classified := classify(action, err)
	var e *Error
	if errors.As(classified, &e) && e.Class == ClassUnavailable {
		return fmt.Errorf("%w: %w", connectors.ErrOutcomeUnknown, classified)
	}
	return classified
}

// statusOf returns the HTTP status behind a classified error, 0 when none.
func statusOf(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.Status
	}
	return 0
}

// invalid builds an invalid_argument error from the connector's own
// validation.
func invalid(format string, a ...any) error {
	return &Error{Class: ClassInvalidArgument, Message: fmt.Sprintf(format, a...)}
}
