package observability_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/observability"
)

var requestIDRE = regexp.MustCompile(`^[A-Za-z0-9._-]{8,64}$`)

func serveWithRequestID(t *testing.T, incoming string) (seen string, rec *httptest.ResponseRecorder) {
	t.Helper()
	h := observability.RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = observability.RequestIDFromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", nil)
	if incoming != "" {
		req.Header.Set("X-Request-Id", incoming)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return seen, rec
}

func TestRequestIDGeneratesWhenAbsent(t *testing.T) {
	seen, rec := serveWithRequestID(t, "")
	if !requestIDRE.MatchString(seen) {
		t.Fatalf("generated id %q does not match the accepted shape", seen)
	}
	if got := rec.Header().Get("X-Request-Id"); got != seen {
		t.Errorf("response header %q, want %q (echoed)", got, seen)
	}
	seen2, _ := serveWithRequestID(t, "")
	if seen2 == seen {
		t.Error("two requests got the same generated id")
	}
}

func TestRequestIDAcceptsWellFormedIncoming(t *testing.T) {
	in := "abc-123_DEF.456"
	seen, rec := serveWithRequestID(t, in)
	if seen != in {
		t.Errorf("context id %q, want incoming %q", seen, in)
	}
	if rec.Header().Get("X-Request-Id") != in {
		t.Errorf("response header %q, want %q", rec.Header().Get("X-Request-Id"), in)
	}
}

func TestRequestIDRejectsMalformedIncoming(t *testing.T) {
	for _, in := range []string{
		"short",                      // < 8
		strings.Repeat("a", 65),      // > 64
		"has space 1234",             // space
		"semi;colon-123",             // punctuation
		"newline\n12345678",          // control char
		"<script>alert(1)</script>",  // markup
		"Bearer-mgw_xxxxxxxxxxxxxx!", // trailing !
		"ünïcödé-12345",              // non-ASCII
	} {
		seen, rec := serveWithRequestID(t, in)
		if seen == in {
			t.Errorf("malformed id %q was accepted", in)
		}
		if !requestIDRE.MatchString(seen) {
			t.Errorf("replacement id %q is malformed", seen)
		}
		if rec.Header().Get("X-Request-Id") == in {
			t.Errorf("malformed id %q echoed in response", in)
		}
	}
}

func TestRequestIDFromContextWithoutMiddleware(t *testing.T) {
	if got := observability.RequestIDFromContext(context.Background()); got != "" {
		t.Errorf("expected empty id, got %q", got)
	}
}

func TestRequestIDAttr(t *testing.T) {
	ctx := observability.WithRequestID(context.Background(), "req-12345678")
	a := observability.RequestIDAttr(ctx)
	if a.Key != "request_id" || a.Value.String() != "req-12345678" {
		t.Errorf("attr = %v", a)
	}
	empty := observability.RequestIDAttr(context.Background())
	if empty.Key != "request_id" || empty.Value.String() != "" {
		t.Errorf("attr for missing id = %v", empty)
	}
}
