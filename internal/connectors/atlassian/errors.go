package atlassian

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Error classes an Atlassian tool error carries (Error.Class). They are
// short identifiers a harness or a log reader can branch on; the Message
// says what to do.
const (
	// ClassReconnectRequired: Atlassian rejected the account's token (401)
	// or the connection has no usable token. The user must reconnect the
	// account on the portal.
	ClassReconnectRequired = "reconnect_required"
	// ClassNoAccount: the call carried no connected account.
	ClassNoAccount = "no_account"
	// ClassNotFound: the resource does not exist or the account cannot see
	// it (Jira and Confluence answer 404 for both).
	ClassNotFound = "not_found"
	// ClassForbidden: the token is valid but the account lacks the
	// permission on the project or space, or the app lacks the scope.
	ClassForbidden = "forbidden"
	// ClassInvalidArgument: the arguments were rejected by the connector or
	// by Atlassian (400, 422).
	ClassInvalidArgument = "invalid_argument"
	// ClassUnavailable: Atlassian answered 5xx or could not be reached.
	// Reads turn this into Result{Unavailable: true} rather than an error.
	ClassUnavailable = "unavailable"
	// ClassVendorError: any other Atlassian error, an unreadable reply, or
	// a connection whose site could not be resolved.
	ClassVendorError = "vendor_error"
)

// DefaultRetryAfter is the wait reported for a 429 Atlassian did not put
// a Retry-After on.
const DefaultRetryAfter = 60 * time.Second

// Error is a classified Atlassian API failure: the HTTP status (0 when the
// request never got an answer), a Class and a message safe to show the
// harness (never the token, never response bodies beyond Atlassian's own
// error messages).
type Error struct {
	Status  int
	Class   string
	Message string
	Err     error
}

// Error implements error.
func (e *Error) Error() string {
	if e.Status > 0 {
		return fmt.Sprintf("atlassian: %s (http %d)", e.Message, e.Status)
	}
	return "atlassian: " + e.Message
}

// Unwrap returns the underlying transport or decoding error.
func (e *Error) Unwrap() error { return e.Err }

// httpError is the error the client returns for a non-2xx answer, before
// classification: the status, the Retry-After header and the vendor's
// own message.
type httpError struct {
	status     int
	retryAfter string
	message    string
}

func (e *httpError) Error() string { return fmt.Sprintf("http %d: %s", e.status, e.message) }

// classify turns an error from the client into the connector's error
// vocabulary for app: nil stays nil, context errors pass through
// untouched (the pipeline treats them as cancellation), a 429 becomes
// *connectors.RateLimited with Retry-After (DefaultRetryAfter when
// absent), HTTP statuses become *Error with a Class, and anything else
// (DNS, TLS, connection reset) is ClassUnavailable. A reply that could
// not be decoded is ClassVendorError with the status it came with.
func classify(app, action string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, connections.ErrNeedsReconnect) {
		return &Error{Class: ClassReconnectRequired, Message: action + ": this Atlassian account needs to be reconnected on the portal (Connections)", Err: err}
	}
	var he *httpError
	if errors.As(err, &he) {
		if he.status == http.StatusTooManyRequests {
			return &connectors.RateLimited{App: app, RetryAfter: retryAfter(he.retryAfter)}
		}
		return fromStatus(action, he.status, he.message, err)
	}
	var de *decodeError
	if errors.As(err, &de) {
		return &Error{Status: de.status, Class: ClassVendorError, Message: action + ": Atlassian's reply could not be read", Err: err}
	}
	var ae *Error
	if errors.As(err, &ae) {
		return err
	}
	return &Error{Class: ClassUnavailable, Message: action + ": Atlassian could not be reached: " + err.Error(), Err: err}
}

// decodeError says a 2xx reply did not carry the expected JSON.
type decodeError struct {
	status int
	err    error
}

func (e *decodeError) Error() string {
	return fmt.Sprintf("decode reply (http %d): %v", e.status, e.err)
}

func (e *decodeError) Unwrap() error { return e.err }

// fromStatus maps an HTTP status to a classified Error.
func fromStatus(action string, status int, vendorMessage string, err error) *Error {
	e := &Error{Status: status, Err: err}
	switch {
	case status == http.StatusUnauthorized:
		e.Class = ClassReconnectRequired
		e.Message = action + ": Atlassian rejected this account's token; reconnect your Atlassian account on the portal (Connections)"
	case status == http.StatusForbidden:
		e.Class = ClassForbidden
		e.Message = action + ": not allowed: the account lacks the permission on this project or space, or the app lacks the scope"
	case status == http.StatusNotFound || status == http.StatusGone:
		e.Class = ClassNotFound
		e.Message = action + ": not found, or this account cannot see it"
	case status == http.StatusBadRequest || status == http.StatusUnprocessableEntity:
		e.Class = ClassInvalidArgument
		e.Message = action + ": Atlassian rejected the request"
	case status >= 500:
		e.Class = ClassUnavailable
		e.Message = action + ": Atlassian is unavailable"
	default:
		e.Class = ClassVendorError
		e.Message = action + ": Atlassian error"
	}
	if vendorMessage != "" {
		e.Message += " (" + vendorMessage + ")"
	}
	return e
}

// retryAfter parses a Retry-After header in seconds (at least one second),
// DefaultRetryAfter when absent or unreadable.
func retryAfter(header string) time.Duration {
	n, err := strconv.Atoi(strings.TrimSpace(header))
	if err != nil || n <= 0 {
		return DefaultRetryAfter
	}
	return time.Duration(n) * time.Second
}

// vendorMessage extracts Atlassian's own error text from a response body:
// Jira's errorMessages and errors, Confluence's message, or nothing.
func vendorMessage(body []byte) string {
	var doc struct {
		ErrorMessages []string       `json:"errorMessages"`
		Errors        map[string]any `json:"errors"`
		Message       string         `json:"message"`
		Title         string         `json:"title"`
		Detail        string         `json:"detail"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return ""
	}
	parts := append([]string(nil), doc.ErrorMessages...)
	keys := make([]string, 0, len(doc.Errors))
	for k := range doc.Errors {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		parts = append(parts, k+": "+fmt.Sprint(doc.Errors[k]))
	}
	switch {
	case doc.Message != "":
		parts = append(parts, doc.Message)
	case doc.Title != "":
		parts = append(parts, doc.Title)
	case doc.Detail != "":
		parts = append(parts, doc.Detail)
	}
	const maxLen = 300
	s := strings.Join(parts, "; ")
	if len(s) > maxLen {
		s = s[:maxLen] + "..."
	}
	return s
}

// statusOf returns the HTTP status behind a classified error, 0 when none.
func statusOf(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.Status
	}
	return 0
}

// invalid builds a ClassInvalidArgument error.
func invalid(format string, a ...any) error {
	return &Error{Class: ClassInvalidArgument, Message: fmt.Sprintf(format, a...)}
}
