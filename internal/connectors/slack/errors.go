package slack

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
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
	conflictCodes  = set("name_taken")
	reconnectCodes = set("invalid_auth", "not_authed", "token_revoked", "token_expired", "account_inactive", "invalid_refresh_token")
	forbiddenCodes = set("missing_scope", "not_allowed", "not_allowed_token_type", "restricted_action", "user_is_restricted",
		"user_is_ultra_restricted", "not_in_channel", "is_archived", "ekm_access_denied", "org_login_required",
		"team_access_not_granted", "channel_is_archived", "posting_to_general_channel_denied", "restricted_action_read_only_channel",
		"restricted_action_thread_only_channel", "restricted_action_non_threadable_channel", "restricted_action_thread_locked",
		"cant_archive_general", "cant_archive_required", "cant_leave_general", "cant_kick_from_general", "cant_invite", "last_member",
		"no_permission", "not_authorized", "access_denied", "channel_is_limited_access", "app_cannot_join_channel",
		"invitee_cant_see_channel", "no_external_invite_permission", "ura_max_channels", "cannot_create_channel",
		"cant_update_message", "cant_delete_message", "edit_window_closed", "compliance_exports_prevent_deletion",
		"posting_to_channel_denied", "not_pinnable", "file_uploads_disabled", "file_uploads_except_images_disabled",
		"file_type_not_allowed", "user_is_external_guest", "cannot_update_admin_user", "two_factor_setup_required",
		"canvas_disabled_user_team", "free_teams_cannot_create_standalone_canvases", "free_teams_cannot_edit_standalone_canvases",
		"free_team_canvas_tab_already_exists", "permission_denied", "over_list_file_maximum", "over_row_maximum")
	notFoundCodes = set("channel_not_found", "user_not_found", "users_not_found", "thread_not_found", "message_not_found",
		"not_found", "no_item_specified", "team_not_found", "no_user", "invalid_scheduled_message_id", "file_not_found",
		"user_not_visible", "canvas_not_found", "list_not_found", "row_not_found", "column_not_found",
		"duplicated_item_not_found")
	invalidCodes = set("invalid_arguments", "invalid_arg_name", "invalid_cursor", "invalid_ts_latest", "invalid_ts_oldest",
		"invalid_name", "invalid_limit", "invalid_page", "invalid_count", "msg_too_long", "no_text", "bad_timestamp",
		"invalid_blocks", "invalid_blocks_format", "invalid_metadata_format", "invalid_metadata_schema", "too_many_attachments",
		"invalid_json", "json_not_object", "invalid_form_data", "query_too_long", "invalid_charset", "invalid_post_type",
		"too_many_emoji", "too_many_reactions", "invalid_thread_ts",
		"invalid_name_required", "invalid_name_punctuation", "invalid_name_maxlength", "invalid_name_specials", "no_channel",
		"cant_kick_self", "cant_invite_self", "method_not_supported_for_channel_type", "too_long", "too_many_users",
		"too_many_members", "missing_argument", "invalid_array_arg", "invalid_channel", "invalid_channel_id",
		"time_in_past", "time_too_far", "invalid_time", "too_many_pins", "missing_duration", "invalid_profile",
		"must_clear_both_status_text_and_status_emoji", "invalid_emoji_not_allowed", "file_upload_size_restricted",
		"snippet_too_large", "alt_txt_too_large", "invalid_starts_with_at",
		"canvas_creation_failed", "canvas_editing_failed", "canvas_too_large", "invalid_schema", "invalid_column_type",
		"invalid_primary_column", "invalid_copy_and_schema_args", "invalid_column_id", "invalid_option_id", "invalid_date",
		"invalid_email", "invalid_phone_number", "invalid_row_id", "invalid_input_type", "invalid_text_block", "invalid_vote_value",
		"invalid_link", "invalid_message", "invalid_attachment", "uneditable_column", "over_cell_fields_limit", "over_column_maximum",
		"over_title_length_maximum", "invalid_args", "column_id_not_provided", "row_id_not_provided")
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
	case conflictCodes[code]:
		e.Class = ClassConflict
		e.Message = action + ": it already exists (pick another name)"
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
	if codeRE.MatchString(code) {
		e.Message += " (" + code + ")"
	}
	return e
}

// codeRE is the shape of a Slack error code (snake_case identifier).
// Anything else in the "error" field is not a code and is never
// relayed to the model (security review kwcbub3k: a hostile or broken
// vendor body must not reach clients verbatim).
var codeRE = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

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

// classOf returns the Class behind a classified error, "" when none.
func classOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Class
	}
	return ""
}
