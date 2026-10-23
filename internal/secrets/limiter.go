package secrets

import (
	"net"
	"net/http"
	"time"

	"github.com/huynle/mcp-gateway/internal/tokens"
)

// Per-address limit on failed entry-link lookups (design section 3:
// "guessing /s/<id>"). The 256-bit request id is the security boundary;
// the limit only slows guessing.
const (
	// EntryFailureBurst failed lookups per EntryFailureWindow from one
	// address before the entry routes answer 429.
	EntryFailureBurst = 20
	// EntryFailureWindow is the refill period for EntryFailureBurst.
	EntryFailureWindow = time.Minute
)

// FailureLimiter bounds failed /s/{id} lookups (the 404 answers). Allow
// is asked before a lookup; when it refuses, the page answers 429 with
// Retry-After wait. Fail records one 404.
type FailureLimiter interface {
	Allow(r *http.Request) (ok bool, wait time.Duration)
	Fail(r *http.Request)
}

// AddressLimiter is a FailureLimiter keyed by client address over the
// same in-memory token bucket the bearer middleware uses
// (tokens.FailureLimiter): per process, so each replica allows its own
// burst.
type AddressLimiter struct {
	lim      *tokens.FailureLimiter
	clientIP func(*http.Request) string
}

// NewAddressLimiter allows burst failures per window for each address.
// clientIP derives the address; nil means the host part of RemoteAddr
// (a deployment behind a trusted proxy supplies one reading its header).
func NewAddressLimiter(burst int, window time.Duration, clientIP func(*http.Request) string) *AddressLimiter {
	if clientIP == nil {
		clientIP = remoteIP
	}
	return &AddressLimiter{lim: tokens.NewFailureLimiter(burst, window), clientIP: clientIP}
}

// Allow implements FailureLimiter.
func (l *AddressLimiter) Allow(r *http.Request) (bool, time.Duration) {
	return l.lim.Allow(l.clientIP(r))
}

// Fail implements FailureLimiter.
func (l *AddressLimiter) Fail(r *http.Request) { l.lim.Fail(l.clientIP(r)) }

// remoteIP is the default address: the host part of RemoteAddr.
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
