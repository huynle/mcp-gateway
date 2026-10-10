package github

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	gh "github.com/google/go-github/v90/github"

	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/observability"
)

// Error classes a GitHub tool error carries (Error.Class). They are short
// identifiers a harness or a log reader can branch on; the Message says
// what to do.
const (
	// ClassReconnectRequired: GitHub rejected the account's token (401) or
	// the connection has no usable token. The user must reconnect the
	// account on the portal.
	ClassReconnectRequired = "reconnect_required"
	// ClassNoAccount: the call carried no connected account.
	ClassNoAccount = "no_account"
	// ClassNotFound: the resource does not exist or the account cannot see
	// it (GitHub answers 404 for both).
	ClassNotFound = "not_found"
	// ClassForbidden: the token is valid but the GitHub App is not
	// installed on the repository or organization, or lacks the permission.
	ClassForbidden = "forbidden"
	// ClassInvalidArgument: the arguments were rejected by the connector or
	// by GitHub (422).
	ClassInvalidArgument = "invalid_argument"
	// ClassUnavailable: GitHub answered 5xx or could not be reached. Reads
	// turn this into Result{Unavailable: true} rather than an error.
	ClassUnavailable = "unavailable"
	// ClassVendorError: any other GitHub error.
	ClassVendorError = "vendor_error"
)

// DefaultRetryAfter is the wait reported for a rate limit GitHub did not
// put a reset time on.
const DefaultRetryAfter = 60 * time.Second

// Error is a classified GitHub API failure: the HTTP status (0 when the
// request never got an answer), a Class and a message safe to show the
// harness (never the token, never response bodies beyond GitHub's own
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
		return fmt.Sprintf("github: %s (http %d)", e.Message, e.Status)
	}
	return "github: " + e.Message
}

// Unwrap returns the underlying go-github or transport error.
func (e *Error) Unwrap() error { return e.Err }

// classify turns an error from go-github into the connector's error
// vocabulary: nil stays nil, context errors pass through untouched (the
// pipeline treats them as cancellation), vendor rate limits become
// *connectors.RateLimited with GitHub's reset or Retry-After, HTTP
// statuses become *Error with a Class, and anything else (DNS, TLS,
// connection reset) is ClassUnavailable.
func classify(action string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, connections.ErrNeedsReconnect) {
		return &Error{Class: ClassReconnectRequired, Message: action + ": this GitHub account needs to be reconnected on the portal (Connections)", Err: err}
	}
	var rl *gh.RateLimitError
	if errors.As(err, &rl) {
		return &connectors.RateLimited{App: App, RetryAfter: retryAfterReset(rl.Rate.Reset.Time)}
	}
	var abuse *gh.AbuseRateLimitError
	if errors.As(err, &abuse) {
		wait := DefaultRetryAfter
		if abuse.RetryAfter != nil && *abuse.RetryAfter > 0 {
			wait = *abuse.RetryAfter
		}
		return &connectors.RateLimited{App: App, RetryAfter: wait}
	}
	var er *gh.ErrorResponse
	if errors.As(err, &er) && er.Response != nil {
		return fromStatus(action, er.Response.StatusCode, er.Message, err)
	}
	return &Error{Class: ClassUnavailable, Message: action + ": GitHub could not be reached: " + err.Error(), Err: err}
}

// fromStatus maps an HTTP status to a classified Error.
func fromStatus(action string, status int, vendorMessage string, err error) *Error {
	e := &Error{Status: status, Err: err}
	switch {
	case status == http.StatusUnauthorized:
		e.Class = ClassReconnectRequired
		e.Message = action + ": GitHub rejected this account's token; reconnect your GitHub account on the portal (Connections)"
	case status == http.StatusForbidden:
		e.Class = ClassForbidden
		e.Message = action + ": not allowed: the GitHub App is not installed on this repository or organization, or lacks the permission"
	case status == http.StatusNotFound || status == http.StatusGone:
		e.Class = ClassNotFound
		e.Message = action + ": not found, or this account cannot see it"
	case status == http.StatusUnprocessableEntity || status == http.StatusBadRequest:
		e.Class = ClassInvalidArgument
		e.Message = action + ": GitHub rejected the request"
	case status >= 500:
		e.Class = ClassUnavailable
		e.Message = action + ": GitHub is unavailable"
	default:
		e.Class = ClassVendorError
		e.Message = action + ": GitHub error"
	}
	if hint := vendorHint(status, vendorMessage); hint != "" {
		e.Message += " (" + hint + ")"
	}
	return e
}

// maxVendorHint bounds the vendor text relayed to the model.
const maxVendorHint = 120

// vendorHint is the part of GitHub's error message worth showing the
// model: only for client errors (a 4xx message says what was wrong with
// the request; a 5xx body is a proxy page, a stack trace or an internal
// hostname and says nothing the class does not), one line, without
// markup or URLs, cut to maxVendorHint, and redacted (security review
// kwcbub3k: vendor bodies must not reach clients verbatim).
func vendorHint(status int, msg string) string {
	if status >= 500 || msg == "" {
		return ""
	}
	msg = strings.Join(strings.Fields(msg), " ")
	if strings.ContainsAny(msg, "<>") || strings.Contains(msg, "://") {
		return ""
	}
	if len(msg) > maxVendorHint {
		msg = msg[:maxVendorHint] + "…"
	}
	return observability.Redact(msg)
}

// retryAfterReset is the wait until a rate-limit reset, at least one
// second, DefaultRetryAfter when GitHub gave none.
func retryAfterReset(reset time.Time) time.Duration {
	if reset.IsZero() {
		return DefaultRetryAfter
	}
	d := time.Until(reset).Round(time.Second)
	if d < time.Second {
		d = time.Second
	}
	return d
}

// statusOf returns the HTTP status behind a classified error, 0 when none.
func statusOf(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.Status
	}
	return 0
}
