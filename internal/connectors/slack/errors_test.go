package slack_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	goslack "github.com/slack-go/slack"

	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/slack"
)

// Classify is the one mapping every tool and the binder share: Slack's
// ok:false error codes, HTTP statuses, rate limits and transport
// failures become the connector's error vocabulary.
func TestClassify(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		class  string
		status int
	}{
		{"nil stays nil", nil, "", 0},
		{"invalid_auth reconnect", goslack.SlackErrorResponse{Err: "invalid_auth"}, slack.ClassReconnectRequired, 0},
		{"token_revoked reconnect", goslack.SlackErrorResponse{Err: "token_revoked"}, slack.ClassReconnectRequired, 0},
		{"account_inactive reconnect", goslack.SlackErrorResponse{Err: "account_inactive"}, slack.ClassReconnectRequired, 0},
		{"not_authed reconnect", goslack.SlackErrorResponse{Err: "not_authed"}, slack.ClassReconnectRequired, 0},
		{"missing_scope forbidden", goslack.SlackErrorResponse{Err: "missing_scope"}, slack.ClassForbidden, 0},
		{"not_in_channel forbidden", goslack.SlackErrorResponse{Err: "not_in_channel"}, slack.ClassForbidden, 0},
		{"restricted_action forbidden", goslack.SlackErrorResponse{Err: "restricted_action"}, slack.ClassForbidden, 0},
		{"channel_not_found", goslack.SlackErrorResponse{Err: "channel_not_found"}, slack.ClassNotFound, 0},
		{"user_not_found", goslack.SlackErrorResponse{Err: "user_not_found"}, slack.ClassNotFound, 0},
		{"thread_not_found", goslack.SlackErrorResponse{Err: "thread_not_found"}, slack.ClassNotFound, 0},
		{"message_not_found", goslack.SlackErrorResponse{Err: "message_not_found"}, slack.ClassNotFound, 0},
		{"invalid_arguments", goslack.SlackErrorResponse{Err: "invalid_arguments"}, slack.ClassInvalidArgument, 0},
		{"invalid_cursor", goslack.SlackErrorResponse{Err: "invalid_cursor"}, slack.ClassInvalidArgument, 0},
		{"msg_too_long", goslack.SlackErrorResponse{Err: "msg_too_long"}, slack.ClassInvalidArgument, 0},
		{"invalid_name", goslack.SlackErrorResponse{Err: "invalid_name"}, slack.ClassInvalidArgument, 0},
		{"fatal_error unavailable", goslack.SlackErrorResponse{Err: "fatal_error"}, slack.ClassUnavailable, 0},
		{"internal_error unavailable", goslack.SlackErrorResponse{Err: "internal_error"}, slack.ClassUnavailable, 0},
		{"service_unavailable", goslack.SlackErrorResponse{Err: "service_unavailable"}, slack.ClassUnavailable, 0},
		{"unknown code is vendor_error", goslack.SlackErrorResponse{Err: "something_new"}, slack.ClassVendorError, 0},
		{"http 500", goslack.StatusCodeError{Code: 500, Status: "500 Internal Server Error"}, slack.ClassUnavailable, 500},
		{"http 502", goslack.StatusCodeError{Code: 502, Status: "502 Bad Gateway"}, slack.ClassUnavailable, 502},
		{"http 401", goslack.StatusCodeError{Code: 401, Status: "401 Unauthorized"}, slack.ClassReconnectRequired, 401},
		{"http 403", goslack.StatusCodeError{Code: 403, Status: "403 Forbidden"}, slack.ClassForbidden, 403},
		{"http 404", goslack.StatusCodeError{Code: 404, Status: "404 Not Found"}, slack.ClassNotFound, 404},
		{"http 400", goslack.StatusCodeError{Code: 400, Status: "400 Bad Request"}, slack.ClassInvalidArgument, 400},
		{"http 418", goslack.StatusCodeError{Code: 418, Status: "418"}, slack.ClassVendorError, 418},
		{"network unavailable", errors.New("dial tcp: connection refused"), slack.ClassUnavailable, 0},
		{"needs reconnect from the token source", connections.ErrNeedsReconnect, slack.ClassReconnectRequired, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := slack.Classify("do thing", tc.err)
			if tc.err == nil {
				if got != nil {
					t.Fatalf("Classify(nil) = %v", got)
				}
				return
			}
			var e *slack.Error
			if !errors.As(got, &e) {
				t.Fatalf("Classify(%v) = %v (%T), want *slack.Error", tc.err, got, got)
			}
			if e.Class != tc.class || e.Status != tc.status {
				t.Errorf("class/status = %s/%d, want %s/%d (%v)", e.Class, e.Status, tc.class, tc.status, got)
			}
			if !wrapsCause(got, tc.err) {
				t.Errorf("classified error %v does not wrap the cause %v", got, tc.err)
			}
			if e.Message == "" || e.Message[:len("do thing")] != "do thing" {
				t.Errorf("message %q should start with the action", e.Message)
			}
		})
	}
}

func TestClassifyRateLimits(t *testing.T) {
	t.Run("429 with Retry-After", func(t *testing.T) {
		got := slack.Classify("search", &goslack.RateLimitedError{RetryAfter: 37 * time.Second})
		var rl *connectors.RateLimited
		if !errors.As(got, &rl) || rl.App != "slack" || rl.RetryAfter != 37*time.Second {
			t.Fatalf("got %v (%T), want RateLimited 37s", got, got)
		}
	})
	t.Run("ok:false ratelimited without a wait", func(t *testing.T) {
		got := slack.Classify("search", goslack.SlackErrorResponse{Err: "ratelimited"})
		var rl *connectors.RateLimited
		if !errors.As(got, &rl) || rl.RetryAfter != slack.DefaultRetryAfter {
			t.Fatalf("got %v, want RateLimited with the default wait", got)
		}
	})
	t.Run("http 429 without Retry-After", func(t *testing.T) {
		got := slack.Classify("search", goslack.StatusCodeError{Code: http.StatusTooManyRequests, Status: "429"})
		var rl *connectors.RateLimited
		if !errors.As(got, &rl) || rl.RetryAfter != slack.DefaultRetryAfter {
			t.Fatalf("got %v, want RateLimited with the default wait", got)
		}
	})
}

func TestClassifyPassesContextErrorsThrough(t *testing.T) {
	for _, err := range []error{context.Canceled, context.DeadlineExceeded} {
		if got := slack.Classify("x", err); !errors.Is(got, err) || got.Error() != err.Error() {
			t.Errorf("Classify(%v) = %v, want the same error", err, got)
		}
	}
}

func TestClassifyWrite(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		unknown bool
	}{
		{"deadline is unknown", context.DeadlineExceeded, true},
		{"cancel is unknown", context.Canceled, true},
		{"5xx is unknown", goslack.StatusCodeError{Code: 503, Status: "503"}, true},
		{"fatal_error is unknown", goslack.SlackErrorResponse{Err: "fatal_error"}, true},
		{"network is unknown", errors.New("read: connection reset by peer"), true},
		{"channel_not_found is known", goslack.SlackErrorResponse{Err: "channel_not_found"}, false},
		{"invalid_auth is known", goslack.SlackErrorResponse{Err: "invalid_auth"}, false},
		{"rate limit is known", &goslack.RateLimitedError{RetryAfter: time.Second}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := slack.ClassifyWrite("post", tc.err)
			if errors.Is(got, connectors.ErrOutcomeUnknown) != tc.unknown {
				t.Fatalf("ClassifyWrite(%v) = %v, want unknown=%v", tc.err, got, tc.unknown)
			}
			var rl *connectors.RateLimited
			if !errors.As(got, &rl) && !wrapsCause(got, tc.err) {
				t.Errorf("does not wrap the cause: %v", got)
			}
		})
	}
	if slack.ClassifyWrite("post", nil) != nil {
		t.Error("ClassifyWrite(nil) != nil")
	}
}

func TestErrorString(t *testing.T) {
	e := &slack.Error{Status: 500, Class: slack.ClassUnavailable, Message: "post: Slack is unavailable"}
	if e.Error() != "slack: post: Slack is unavailable (http 500)" {
		t.Errorf("Error() = %q", e.Error())
	}
	e2 := &slack.Error{Class: slack.ClassNotFound, Message: "post: not found (channel_not_found)"}
	if e2.Error() != "slack: post: not found (channel_not_found)" {
		t.Errorf("Error() = %q", e2.Error())
	}
}

// wrapsCause reports whether err wraps cause: by identity for comparable
// errors, by type for slack-go's non-comparable SlackErrorResponse.
func wrapsCause(err, cause error) bool {
	if errors.Is(err, cause) {
		return true
	}
	var ser, causeSER goslack.SlackErrorResponse
	if errors.As(cause, &causeSER) && errors.As(err, &ser) {
		return ser.Err == causeSER.Err
	}
	var sce, causeSCE goslack.StatusCodeError
	if errors.As(cause, &causeSCE) && errors.As(err, &sce) {
		return sce.Code == causeSCE.Code
	}
	return false
}
