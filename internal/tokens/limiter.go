package tokens

import (
	"math"
	"sync"
	"time"
)

// Per-IP failed-authentication limiting (plan 36bakiw8 section 3 step 1):
// an attacker guessing secrets gets a bounded number of wrong answers per
// minute from one address. Successful calls are not limited here.
const (
	// DefaultFailureBurst failures per DefaultFailureWindow before 429.
	DefaultFailureBurst = 20
	// DefaultFailureWindow is the refill period for DefaultFailureBurst.
	DefaultFailureWindow = time.Minute
	// LimiterMaxKeys bounds the memory of the limiter: past it, idle (fully
	// refilled) keys are evicted on the next failure and, if none are idle,
	// new keys are not tracked until some are.
	LimiterMaxKeys = 10000
)

// FailureLimiter is an in-memory token bucket per key (normally a client
// IP): burst tokens, refilled continuously at burst per window. A failure
// consumes one token; a key with less than one token is refused. State is
// per process, which is fine for the purpose (slowing guessing); replicas
// each allow their own burst.
type FailureLimiter struct {
	burst  float64
	rate   float64 // tokens per second
	now    func() time.Time
	mu     sync.Mutex
	bucket map[string]*bucket
}

type bucket struct {
	tokens float64
	at     time.Time
}

// NewFailureLimiter allows burst failures per window for each key.
func NewFailureLimiter(burst int, window time.Duration) *FailureLimiter {
	if burst < 1 {
		burst = 1
	}
	if window <= 0 {
		window = DefaultFailureWindow
	}
	return &FailureLimiter{
		burst:  float64(burst),
		rate:   float64(burst) / window.Seconds(),
		now:    time.Now,
		bucket: map[string]*bucket{},
	}
}

// SetClock replaces the time source (tests).
func (l *FailureLimiter) SetClock(now func() time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.now = now
}

// Allow reports whether key may attempt an authentication now and, when it
// may not, how long until it may.
func (l *FailureLimiter) Allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.bucket[key]
	if !ok {
		return true, 0
	}
	l.refill(b)
	if b.tokens >= 1 {
		return true, 0
	}
	wait := time.Duration(math.Ceil((1-b.tokens)/l.rate*1000)) * time.Millisecond
	return false, wait
}

// Fail records one failed authentication for key.
func (l *FailureLimiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.bucket[key]
	if !ok {
		if len(l.bucket) >= LimiterMaxKeys {
			l.evict()
		}
		if len(l.bucket) >= LimiterMaxKeys {
			// Every tracked key is still being limited: fail open for new
			// keys rather than grow without bound. The limiter slows
			// guessing; the 256-bit secret is the security boundary.
			return
		}
		b = &bucket{tokens: l.burst, at: l.now()}
		l.bucket[key] = b
	}
	l.refill(b)
	b.tokens = math.Max(0, b.tokens-1)
}

// Len returns the number of tracked keys (tests, metrics).
func (l *FailureLimiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.bucket)
}

// refill credits the time elapsed since the bucket was last seen.
func (l *FailureLimiter) refill(b *bucket) {
	now := l.now()
	if elapsed := now.Sub(b.at).Seconds(); elapsed > 0 {
		b.tokens = math.Min(l.burst, b.tokens+elapsed*l.rate)
	}
	b.at = now
}

// evict drops every key whose bucket is full again (it carries no
// information). Called with the lock held.
func (l *FailureLimiter) evict() {
	for key, b := range l.bucket {
		l.refill(b)
		if b.tokens >= l.burst {
			delete(l.bucket, key)
		}
	}
}
