package google

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/api/googleapi"

	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors"
)

func gerr(code int, reason string, header http.Header) *googleapi.Error {
	e := &googleapi.Error{Code: code, Message: "vendor says " + reason, Header: header}
	if reason != "" {
		e.Errors = []googleapi.ErrorItem{{Reason: reason, Message: "vendor says " + reason}}
	}
	return e
}

func TestClassifyStatuses(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		class  string
		status int
	}{
		{"401 reconnect", gerr(401, "authError", nil), ClassReconnectRequired, 401},
		{"403 forbidden", gerr(403, "forbidden", nil), ClassForbidden, 403},
		{"403 insufficient scope", gerr(403, "insufficientPermissions", nil), ClassScopeRequired, 403},
		{"403 scope insufficient (new style)", gerr(403, "ACCESS_TOKEN_SCOPE_INSUFFICIENT", nil), ClassScopeRequired, 403},
		{"404 not found", gerr(404, "notFound", nil), ClassNotFound, 404},
		{"410 gone", gerr(410, "deleted", nil), ClassNotFound, 410},
		{"400 invalid", gerr(400, "invalid", nil), ClassInvalidArgument, 400},
		{"412 precondition", gerr(412, "conditionNotMet", nil), ClassInvalidArgument, 412},
		{"409 conflict", gerr(409, "duplicate", nil), ClassConflict, 409},
		{"500 unavailable", gerr(500, "backendError", nil), ClassUnavailable, 500},
		{"503 unavailable", gerr(503, "backendError", nil), ClassUnavailable, 503},
		{"418 other", gerr(418, "", nil), ClassVendorError, 418},
		{"needs reconnect", connections.ErrNeedsReconnect, ClassReconnectRequired, 0},
		{"network", errors.New("dial tcp: connection refused"), ClassUnavailable, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classify("do thing", tc.err)
			var e *Error
			if !errors.As(got, &e) {
				t.Fatalf("classify = %v (%T), want *Error", got, got)
			}
			if e.Class != tc.class || e.Status != tc.status {
				t.Errorf("class %s status %d, want %s %d (%v)", e.Class, e.Status, tc.class, tc.status, got)
			}
			if !errors.Is(got, tc.err) {
				t.Errorf("classified error does not wrap the cause")
			}
			if !strings.HasPrefix(e.Message, "do thing") {
				t.Errorf("message %q should start with the action", e.Message)
			}
		})
	}
}

func TestClassifyRateLimits(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want time.Duration
	}{
		{"429 with retry-after", gerr(429, "rateLimitExceeded", http.Header{"Retry-After": []string{"7"}}), 7 * time.Second},
		{"429 without retry-after", gerr(429, "", nil), DefaultRetryAfter},
		{"403 rateLimitExceeded", gerr(403, "rateLimitExceeded", nil), DefaultRetryAfter},
		{"403 userRateLimitExceeded", gerr(403, "userRateLimitExceeded", http.Header{"Retry-After": []string{"3"}}), 3 * time.Second},
		{"403 quotaExceeded", gerr(403, "quotaExceeded", nil), DefaultRetryAfter},
		{"403 dailyLimitExceeded", gerr(403, "dailyLimitExceeded", nil), DefaultRetryAfter},
		{"429 RESOURCE_EXHAUSTED", gerr(429, "RESOURCE_EXHAUSTED", nil), DefaultRetryAfter},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classify("do thing", tc.err)
			var rl *connectors.RateLimited
			if !errors.As(got, &rl) {
				t.Fatalf("classify = %v (%T), want *connectors.RateLimited", got, got)
			}
			if rl.App != Vendor || rl.RetryAfter != tc.want {
				t.Errorf("RateLimited = %+v, want app %s retry %s", rl, Vendor, tc.want)
			}
		})
	}
}

func TestClassifyPassesContextAndNil(t *testing.T) {
	if classify("x", nil) != nil {
		t.Error("nil should stay nil")
	}
	for _, err := range []error{context.Canceled, context.DeadlineExceeded} {
		if got := classify("x", err); !errors.Is(got, err) {
			t.Errorf("classify(%v) = %v, want it untouched", err, got)
		}
	}
}

func TestClassifyWriteUnknownOutcomes(t *testing.T) {
	for name, err := range map[string]error{
		"deadline": context.DeadlineExceeded,
		"canceled": context.Canceled,
		"500":      gerr(500, "backendError", nil),
		"502":      gerr(502, "", nil),
		"network":  errors.New("read: connection reset by peer"),
	} {
		t.Run(name, func(t *testing.T) {
			got := classifyWrite("send", err)
			if !errors.Is(got, connectors.ErrOutcomeUnknown) {
				t.Errorf("classifyWrite(%v) = %v, want ErrOutcomeUnknown", err, got)
			}
		})
	}
	for name, err := range map[string]error{
		"400": gerr(400, "invalid", nil),
		"403": gerr(403, "forbidden", nil),
		"404": gerr(404, "notFound", nil),
		"401": gerr(401, "authError", nil),
		"429": gerr(429, "rateLimitExceeded", nil),
	} {
		t.Run(name+" known", func(t *testing.T) {
			got := classifyWrite("send", err)
			if got == nil || errors.Is(got, connectors.ErrOutcomeUnknown) {
				t.Errorf("classifyWrite(%v) = %v, want a known failure", err, got)
			}
		})
	}
	if classifyWrite("send", nil) != nil {
		t.Error("nil should stay nil")
	}
}

func TestErrorStringNeverCarriesBody(t *testing.T) {
	e := gerr(403, "forbidden", nil)
	e.Body = `{"error":{"message":"secret-body-token"}}`
	got := classify("read", e)
	if s := got.Error(); s == "" || strings.Contains(s, "secret-body-token") {
		t.Errorf("Error() = %q leaks the response body", s)
	}
}
