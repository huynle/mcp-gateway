package tokens_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/tokens"
)

// --- FailureLimiter ----------------------------------------------------------

func TestFailureLimiterBucketsPerKeyAndRefills(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	l := tokens.NewFailureLimiter(3, time.Minute)
	l.SetClock(func() time.Time { return now })

	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow("a"); !ok {
			t.Fatalf("attempt %d refused before the burst was spent", i+1)
		}
		l.Fail("a")
	}
	ok, retry := l.Allow("a")
	if ok {
		t.Fatal("4th attempt allowed after 3 failures")
	}
	if retry <= 0 || retry > 20*time.Second {
		t.Errorf("retry-after = %v, want (0, 20s] (one token refills every 20s)", retry)
	}
	if ok, _ := l.Allow("b"); !ok {
		t.Error("another key blocked by a's failures")
	}
	// Failures past empty do not go negative: one refill interval is enough.
	l.Fail("a")
	l.Fail("a")
	now = now.Add(20 * time.Second)
	if ok, _ := l.Allow("a"); !ok {
		t.Error("not allowed after one refill interval")
	}
	now = now.Add(time.Hour)
	if ok, _ := l.Allow("a"); !ok {
		t.Error("not allowed after a long wait")
	}
	// Allow never allocates: only failures are tracked.
	if n := l.Len(); n != 1 {
		t.Errorf("tracked keys = %d, want 1", n)
	}
}

func TestFailureLimiterEvictsIdleKeys(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	l := tokens.NewFailureLimiter(2, time.Minute)
	l.SetClock(func() time.Time { return now })
	for i := 0; i < tokens.LimiterMaxKeys+10; i++ {
		l.Fail("ip-" + strconv.Itoa(i))
	}
	if n := l.Len(); n > tokens.LimiterMaxKeys {
		t.Errorf("limiter tracks %d keys, want at most %d", n, tokens.LimiterMaxKeys)
	}
	now = now.Add(time.Hour)
	l.Fail("fresh")
	if n := l.Len(); n != 1 {
		t.Errorf("after everyone refilled, limiter tracks %d keys, want 1", n)
	}
}

// --- BearerMiddleware --------------------------------------------------------

type stubAuth struct {
	principal *tokens.Principal
	err       error
	calls     int
	last      string
}

func (s *stubAuth) Authenticate(_ context.Context, bearer string) (*tokens.Principal, error) {
	s.calls++
	s.last = bearer
	if s.err != nil {
		return nil, s.err
	}
	return s.principal, nil
}

func serve(t *testing.T, h http.Handler, auth string, remote string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestBearerMiddlewareAttachesPrincipalOnSuccess(t *testing.T) {
	auth := &stubAuth{principal: &tokens.Principal{UserID: alice, TokenID: "t1", PublicID: "abcdefgh"}}
	var got *tokens.Principal
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = tokens.PrincipalFrom(r.Context())
		w.WriteHeader(http.StatusNoContent)
	})
	h := tokens.BearerMiddleware(auth, tokens.MiddlewareOptions{})(next)
	rec := serve(t, h, "bearer mgw_x", "10.0.0.1:1234")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d body %s", rec.Code, rec.Body)
	}
	if got == nil || got.UserID != alice || got.TokenID != "t1" {
		t.Errorf("principal in context = %+v", got)
	}
	if auth.last != "mgw_x" {
		t.Errorf("bearer passed = %q", auth.last)
	}
	if tokens.PrincipalFrom(context.Background()) != nil {
		t.Error("PrincipalFrom(empty ctx) != nil")
	}
}

func TestBearerMiddlewareMissingCredentialsIs401WithoutCountingAFailure(t *testing.T) {
	auth := &stubAuth{err: &tokens.Error{Reason: tokens.ReasonMalformed}}
	l := tokens.NewFailureLimiter(1, time.Minute)
	h := tokens.BearerMiddleware(auth, tokens.MiddlewareOptions{Limiter: l})(http.NotFoundHandler())
	for _, a := range []string{"", "Basic abc", "Bearer", "Bearer  "} {
		rec := serve(t, h, a, "10.0.0.1:1")
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Authorization %q: status = %d, want 401", a, rec.Code)
		}
		if got := rec.Header().Get("WWW-Authenticate"); !strings.HasPrefix(got, `Bearer realm="mcp-gateway"`) {
			t.Errorf("Authorization %q: WWW-Authenticate = %q", a, got)
		}
	}
	if auth.calls != 0 {
		t.Errorf("authenticator called %d times for requests without a bearer", auth.calls)
	}
	if ok, _ := l.Allow("10.0.0.1"); !ok {
		t.Error("missing credentials consumed the failure budget")
	}
}

func TestBearerMiddlewareRejectsWith401AndRateLimitsPerIP(t *testing.T) {
	auth := &stubAuth{err: &tokens.Error{Reason: tokens.ReasonSignInStale, PublicID: "abcdefgh"}}
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	l := tokens.NewFailureLimiter(2, time.Minute)
	l.SetClock(func() time.Time { return now })
	h := tokens.BearerMiddleware(auth, tokens.MiddlewareOptions{Limiter: l})(http.NotFoundHandler())

	for i := 0; i < 2; i++ {
		rec := serve(t, h, "Bearer mgw_bad", "10.0.0.1:50000")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d body %s", i+1, rec.Code, rec.Body)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Errorf("content-type = %q", ct)
		}
		var body struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("body %s: %v", rec.Body, err)
		}
		if body.Error != "invalid_token" || body.ErrorDescription != tokens.StaleMessage {
			t.Errorf("body = %+v", body)
		}
		if got := rec.Header().Get("WWW-Authenticate"); !strings.Contains(got, `error="invalid_token"`) || !strings.Contains(got, tokens.StaleMessage) {
			t.Errorf("WWW-Authenticate = %q", got)
		}
		if strings.Contains(rec.Body.String(), "mgw_bad") {
			t.Error("response echoes the bearer")
		}
	}
	// Budget spent: 429 without consulting the authenticator; another IP
	// (same client port) is unaffected.
	calls := auth.calls
	rec := serve(t, h, "Bearer mgw_bad", "10.0.0.1:50001")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("3rd attempt: status = %d, want 429", rec.Code)
	}
	if ra, err := strconv.Atoi(rec.Header().Get("Retry-After")); err != nil || ra < 1 {
		t.Errorf("Retry-After = %q", rec.Header().Get("Retry-After"))
	}
	if auth.calls != calls {
		t.Error("authenticator consulted while rate limited")
	}
	if rec := serve(t, h, "Bearer mgw_bad", "10.0.0.2:50000"); rec.Code != http.StatusUnauthorized {
		t.Errorf("other IP: status = %d, want 401", rec.Code)
	}
	// A success from the limited IP is still refused until the bucket refills.
	auth.err = nil
	auth.principal = &tokens.Principal{UserID: alice}
	if rec := serve(t, h, "Bearer mgw_good", "10.0.0.1:50002"); rec.Code != http.StatusTooManyRequests {
		t.Errorf("limited IP with a good token: status = %d, want 429", rec.Code)
	}
	now = now.Add(time.Minute)
	if rec := serve(t, h, "Bearer mgw_good", "10.0.0.1:50003"); rec.Code != http.StatusNotFound {
		t.Errorf("after refill: status = %d, want 404 from next", rec.Code)
	}
}

func TestBearerMiddlewareClientIPOption(t *testing.T) {
	auth := &stubAuth{err: &tokens.Error{Reason: tokens.ReasonUnknown}}
	l := tokens.NewFailureLimiter(1, time.Minute)
	opts := tokens.MiddlewareOptions{Limiter: l, ClientIP: func(r *http.Request) string { return r.Header.Get("X-Forwarded-For") }}
	h := tokens.BearerMiddleware(auth, opts)(http.NotFoundHandler())
	req := func(xff string) int {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", nil)
		r.Header.Set("Authorization", "Bearer mgw_bad")
		r.Header.Set("X-Forwarded-For", xff)
		r.RemoteAddr = "127.0.0.1:1"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code
	}
	if c := req("203.0.113.5"); c != http.StatusUnauthorized {
		t.Errorf("first = %d", c)
	}
	if c := req("203.0.113.5"); c != http.StatusTooManyRequests {
		t.Errorf("second from same forwarded IP = %d, want 429", c)
	}
	if c := req("203.0.113.6"); c != http.StatusUnauthorized {
		t.Errorf("other forwarded IP = %d, want 401", c)
	}
}

func TestBearerMiddlewareLookupFailureIs503NotAFailure(t *testing.T) {
	auth := &stubAuth{err: errors.New("database unreachable")}
	l := tokens.NewFailureLimiter(1, time.Minute)
	h := tokens.BearerMiddleware(auth, tokens.MiddlewareOptions{Limiter: l, Log: slog.New(slog.DiscardHandler)})(http.NotFoundHandler())
	rec := serve(t, h, "Bearer mgw_x", "10.0.0.1:1")
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "unreachable") {
		t.Error("internal error text leaked to the client")
	}
	if ok, _ := l.Allow("10.0.0.1"); !ok {
		t.Error("an infrastructure error consumed the client's failure budget")
	}
}
