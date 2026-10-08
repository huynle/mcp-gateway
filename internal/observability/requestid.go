package observability

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"regexp"
)

// RequestIDHeader is the header the gateway reads and always writes.
const RequestIDHeader = "X-Request-Id"

// requestIDRE is the only shape accepted from a client or upstream proxy.
// Anything else (too short to be unique, too long to be sane, control
// characters, markup) is replaced so a request ID can never carry an
// injection into logs or the audit table.
var requestIDRE = regexp.MustCompile(`^[A-Za-z0-9._-]{8,64}$`)

type requestIDKey struct{}

// RequestID is HTTP middleware that ensures every request has an ID: an
// incoming X-Request-Id is kept when it matches ^[A-Za-z0-9._-]{8,64}$,
// otherwise a random one is generated. The ID is placed in the request
// context (RequestIDFromContext) and echoed in the response header so a
// user can quote it from an error page and an operator can find the log and
// audit lines.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(RequestIDHeader)
		if !requestIDRE.MatchString(id) {
			id = newRequestID()
		}
		w.Header().Set(RequestIDHeader, id)
		next.ServeHTTP(w, r.WithContext(WithRequestID(r.Context(), id)))
	})
}

// WithRequestID returns a context carrying id. The middleware calls it;
// background work that outlives a request can use it to keep the trail.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestIDFromContext returns the request ID or "" when none was set.
func RequestIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// RequestIDAttr is the log attribute for the request in ctx: key
// "request_id", empty when no middleware ran.
func RequestIDAttr(ctx context.Context) slog.Attr {
	return slog.String("request_id", RequestIDFromContext(ctx))
}

// newRequestID returns 16 random bytes as 32 hex characters.
func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("observability: cannot generate request id: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
