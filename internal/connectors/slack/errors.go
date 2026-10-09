package slack

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	goslack "github.com/slack-go/slack"

	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Error classes a Slack tool error carries (Error.Class). They are short
// identifiers a harness or a log reader can branch on; the Message says
// what to do.
const (
	// ClassReconnectRequired: Slack rejected the account's token
	// (invalid_auth, token_revoked, account_inactive, HTTP 401) or the
	// connection has no usable token. The user must reconnect the account
	// on the portal.
	ClassReconnectRequired = "reconnect_required"
	// ClassNoAccount: the call carried no connected account.
	ClassNoAccount = "no_account"
	// ClassNotFound: the channel, user, message or thread does not exist
	// or the account cannot see it.
	ClassNotFound = "not_found"
	// ClassForbidden: the token is valid but lacks the scope
	// (missing_scope), the user is not in the channel (not_in_channel) or
	// the workspace restricts the action.
	ClassForbidden = "forbidden"
	// ClassInvalidArgument: the arguments were rejected by the connector
	// or by Slack (invalid_arguments, invalid_cursor, msg_too_long, ...).
	ClassInvalidArgument = "invalid_argument"
	// ClassUnavailable: Slack answered 5xx, fatal_error / internal_error /
	// service_unavailable, or could not be reached. Reads turn this into
	// Result{Unavailable: true} rather than an error.
	ClassUnavailable = "unavailable"
	// ClassVendorError: any other Slack error.
	ClassVendorError = "vendor_error"
)

// DefaultRetryAfter is the wait reported for a rate limit Slack did not
// put a Retry-After on.
const DefaultRetryAfter = 30 * time.Second

// Error is a classified Slack API failure: the HTTP status (0 for an
// ok:false answer or when the request never got an answer), a Class and
// a message safe to show the harness (never the token; only Slack's own
// error code).
type Error struct {
	Status  int
	Class   string
	Message string
	Err     error
}

// Error implements error.
func (e *Error) Error() string {
	if e.Status > 0 {
		return fmt.Sprintf("slack: %s (http %d)", e.Message, e.Status)
	}
	return "slack: " + e.Message
}

// Unwrap returns the underlying slack-go or transport error.
func (e *Error) Unwrap() error { return e.Err }

// Slack ok:false error codes by class. Codes not listed are vendor_error.
var (
	reconnectCodes = set("invalid_auth", "not_authed", "token_revoked", "token_expired", "account_inactive", "invalid_refresh_token")
	forbiddenCodes = set("missing_scope", "not_allowed", "not_allowed_token_type", "restricted_action", "user_is_restricted",
		"user_is_ultra_restricted", "not_in_channel", "is_archived", "ekm_access_denied", "org_login_required",
		"team_access_not_granted", "channel_is_archived", "posting_to_general_channel_denied", "restricted_action_read_only_channel",
		"restricted_action_thread_only_channel", "restricted_action_non_threadable_channel", "restricted_action_thread_locked")
	notFoundCodes = set("channel_not_found", "user_not_found", "users_not_found", "thread_not_found", "message_not_found",
		"not_found", "no_item_specified", "team_not_found")
	invalidCodes = set("invalid_arguments", "invalid_arg_name", "invalid_cursor", "invalid_ts_latest", "invalid_ts_oldest",
		"invalid_name", "invalid_limit", "invalid_page", "invalid_count", "msg_too_long", "no_text", "bad_timestamp",
		"invalid_blocks", "invalid_blocks_format", "invalid_metadata_format", "invalid_metadata_schema", "too_many_attachments",
		"invalid_json", "json_not_object", "invalid_form_data", "query_too_long", "invalid_charset", "invalid_post_type",
		"too_many_emoji", "too_many_reactions", "invalid_thread_ts")
	unavailableCodes = set("fatal_error", "internal_error", "service_unavailable", "request_timeout")
)

func set(codes ...string) map[string]bool {
	m := make(map[string]bool, len(codes))
	for _, c := range codes {
		m[c] = true
	}
	return m
}

// Classify turns an error from slack-go into the connector's error
// vocabulary: nil stays nil, context errors pass through untouched (the
// pipeline treats them as cancellation), rate limits become
// *connectors.RateLimited with Slack's Retry-After (DefaultRetryAfter
// when it gave none), ok:false answers and HTTP statuses become *Error
// with a Class, and anything else (DNS, TLS, connection reset) is
// ClassUnavailable. Exported for the binder and the tests; tools call
// it as classify.
func Classify(action string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, connections.ErrNeedsReconnect) {
		return &Error{Class: ClassReconnectRequired, Message: action + ": this Slack account needs to be reconnected on the portal (Connections)", Err: err}
	}
	var rl *goslack.RateLimitedError
	if errors.As(err, &rl) {
		wait := rl.RetryAfter
		if wait <= 0 {
			wait = DefaultRetryAfter
		}
		return &connectors.RateLimited{App: App, RetryAfter: wait}
	}
	var sce goslack.StatusCodeError
	if errors.As(err, &sce) {
		if sce.Code == http.StatusTooManyRequests {
			return &connectors.RateLimited{App: App, RetryAfter: DefaultRetryAfter}
		}
		return fromStatus(action, sce.Code, err)
	}
	var ser goslack.SlackErrorResponse
	if errors.As(err, &ser) {
		return fromCode(action, ser.Err, err)
	}
	return &Error{Class: ClassUnavailable, Message: action + ": Slack could not be reached: " + err.Error(), Err: err}
}

// classify is Classify for the package's own use.
func classify(action string, err error) error { return Classify(action, err) }

// fromCode maps a Slack ok:false error code to a classified Error.
func fromCode(action, code string, err error) error {
	e := &Error{Err: err}
	switch {
	case code == "ratelimited":
		return &connectors.RateLimited{App: App, RetryAfter: DefaultRetryAfter}
	case reconnectCodes[code]:
		e.Class = ClassReconnectRequired
		e.Message = action + ": Slack rejected this account's token; reconnect your Slack account on the portal (Connections)"
	case forbiddenCodes[code]:
		e.Class = ClassForbidden
		e.Message = action + ": not allowed: the account lacks the scope, is not a member of the channel, or the workspace restricts this action"
	case notFoundCodes[code]:
		e.Class = ClassNotFound
		e.Message = action + ": not found, or this account cannot see it"
	case invalidCodes[code]:
		e.Class = ClassInvalidArgument
		e.Message = action + ": Slack rejected the request"
	case unavailableCodes[code]:
		e.Class = ClassUnavailable
		e.Message = action + ": Slack is unavailable"
	default:
		e.Class = ClassVendorError
		e.Message = action + ": Slack error"
	}
	if code != "" {
		e.Message += " (" + code + ")"
	}
	return e
}

// fromStatus maps a non-200 HTTP status to a classified Error (Slack
// normally answers 200 with ok:false; a status means the API itself
// refused or failed).
func fromStatus(action string, status int, err error) *Error {
	e := &Error{Status: status, Err: err}
	switch {
	case status == http.StatusUnauthorized:
		e.Class = ClassReconnectRequired
		e.Message = action + ": Slack rejected this account's token; reconnect your Slack account on the portal (Connections)"
	case status == http.StatusForbidden:
		e.Class = ClassForbidden
		e.Message = action + ": not allowed"
	case status == http.StatusNotFound || status == http.StatusGone:
		e.Class = ClassNotFound
		e.Message = action + ": not found"
	case status == http.StatusBadRequest || status == http.StatusUnprocessableEntity:
		e.Class = ClassInvalidArgument
		e.Message = action + ": Slack rejected the request"
	case status >= 500:
		e.Class = ClassUnavailable
		e.Message = action + ": Slack is unavailable"
	default:
		e.Class = ClassVendorError
		e.Message = action + ": Slack error"
	}
	return e
}

// ClassifyWrite maps the error of the request that performs a write: an
// answer from Slack (ok:false with a code, 4xx, rate limit) is a known
// outcome and is classified like a read's; anything that leaves the
// outcome open (5xx, fatal_error, a timeout, a cancelled context, a
// dropped connection: the request may have been applied) wraps
// connectors.ErrOutcomeUnknown so the ledger marks the operation unknown
// and the reconciler checks it.
func ClassifyWrite(action string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return fmt.Errorf("%w: %s: Slack did not answer in time (%w)", connectors.ErrOutcomeUnknown, action, err)
	}
	classified := Classify(action, err)
	var e *Error
	if errors.As(classified, &e) && e.Class == ClassUnavailable {
		return fmt.Errorf("%w: %w", connectors.ErrOutcomeUnknown, classified)
	}
	return classified
}

// classifyWrite is ClassifyWrite for the package's own use.
func classifyWrite(action string, err error) error { return ClassifyWrite(action, err) }

// statusOf returns the HTTP status behind a classified error, 0 when none.
func statusOf(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.Status
	}
	return 0
}

// classOf returns the Class behind a classified error, "" when none.
func classOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Class
	}
	return ""
}
