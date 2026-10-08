package mcp

import (
	"context"
	"strings"
	"sync"
	"time"
)

// Default budgets (GATEWAY_RATE_USER_PER_MIN, GATEWAY_RATE_APP_PER_MIN).
// Per user: one harness working steadily makes a call every few seconds;
// 60/min leaves room for bursts of tool use without letting a looping
// agent drain the vendor quota. Per app: vendor quotas are per registered
// app, shared by every user of the deployment (decision dovthftx).
const (
	DefaultUserPerMinute = 60
	DefaultAppPerMinute  = 600
)

// RateLimitConfig configures NewRateLimiter. Zero values take the
// defaults; Now is for tests.
type RateLimitConfig struct {
	UserPerMinute int
	AppPerMinute  int
	Now           func() time.Time
}

// AppPauser is the optional side of a RateLimiter the ratelimit stage
// uses when a connector reports a vendor 429: Pause holds every call to
// app for the vendor's Retry-After. TokenBucketLimiter implements it.
type AppPauser interface {
	Pause(app string, retryAfter time.Duration)
}

// TokenBucketLimiter is the production RateLimiter: one token bucket per
// user and one per vendor app, both refilled continuously at the
// configured per-minute rate with a burst equal to that rate, plus a
// per-app pause honouring vendor Retry-After. A call is admitted only when
// both buckets have a token, and tokens are taken only then, so a call
// refused by the app bucket does not eat the user's budget. Memory is
// bounded: user buckets idle for longer than a full refill are dropped.
type TokenBucketLimiter struct {
	userRate float64 // tokens per second
	userCap  float64
	appRate  float64
	appCap   float64
	now      func() time.Time

	mu        sync.Mutex
	users     map[string]*bucket
	apps      map[string]*bucket
	paused    map[string]time.Time
	lastPrune time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewRateLimiter builds a TokenBucketLimiter.
func NewRateLimiter(cfg RateLimitConfig) *TokenBucketLimiter {
	if cfg.UserPerMinute <= 0 {
		cfg.UserPerMinute = DefaultUserPerMinute
	}
	if cfg.AppPerMinute <= 0 {
		cfg.AppPerMinute = DefaultAppPerMinute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &TokenBucketLimiter{
		userRate:  float64(cfg.UserPerMinute) / 60,
		userCap:   float64(cfg.UserPerMinute),
		appRate:   float64(cfg.AppPerMinute) / 60,
		appCap:    float64(cfg.AppPerMinute),
		now:       cfg.Now,
		users:     map[string]*bucket{},
		apps:      map[string]*bucket{},
		paused:    map[string]time.Time{},
		lastPrune: cfg.Now(),
	}
}

// UserPerMinute returns the configured per-user budget.
func (l *TokenBucketLimiter) UserPerMinute() int { return int(l.userCap) }

// AppPerMinute returns the configured per-app budget.
func (l *TokenBucketLimiter) AppPerMinute() int { return int(l.appCap) }

// TrackedUsers returns how many user buckets are held (for tests and
// diagnostics).
func (l *TokenBucketLimiter) TrackedUsers() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.users)
}

// Allow implements RateLimiter. The app is the part of tool before the
// first dot.
func (l *TokenBucketLimiter) Allow(_ context.Context, userID, tool string) (bool, time.Duration) {
	app := appOf(tool)
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	if until, ok := l.paused[app]; ok {
		if now.Before(until) {
			return false, until.Sub(now)
		}
		delete(l.paused, app)
	}
	l.maybePrune(now)

	ub := l.bucket(l.users, userID, l.userCap, l.userRate, now)
	ab := l.bucket(l.apps, app, l.appCap, l.appRate, now)
	if ub.tokens < 1-epsilon {
		return false, waitFor(ub, l.userRate)
	}
	if ab.tokens < 1-epsilon {
		return false, waitFor(ab, l.appRate)
	}
	ub.tokens--
	ab.tokens--
	return true, 0
}

// Pause implements AppPauser: calls to app are refused until retryAfter
// has elapsed. A pause never shortens one already in force.
func (l *TokenBucketLimiter) Pause(app string, retryAfter time.Duration) {
	if retryAfter <= 0 {
		return
	}
	until := l.now().Add(retryAfter)
	l.mu.Lock()
	defer l.mu.Unlock()
	if cur, ok := l.paused[app]; !ok || until.After(cur) {
		l.paused[app] = until
	}
}

// bucket returns the refilled bucket for key, creating a full one.
// Callers hold mu.
func (l *TokenBucketLimiter) bucket(m map[string]*bucket, key string, capacity, rate float64, now time.Time) *bucket {
	b, ok := m[key]
	if !ok {
		b = &bucket{tokens: capacity, last: now}
		m[key] = b
		return b
	}
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = min(capacity, b.tokens+elapsed*rate)
		b.last = now
	}
	return b
}

// epsilon absorbs floating-point drift so a caller that waited exactly the
// advertised time is admitted.
const epsilon = 1e-9

// waitFor is how long until b has a whole token, rounded to the
// millisecond (never below one).
func waitFor(b *bucket, rate float64) time.Duration {
	missing := 1 - b.tokens
	d := time.Duration(missing / rate * float64(time.Second)).Round(time.Millisecond)
	return max(d, time.Millisecond)
}

// maybePrune drops user buckets that have been idle long enough to be full
// again (they would be recreated full anyway). It runs at most once per
// refill period, so the sweep is amortised. Callers hold mu.
func (l *TokenBucketLimiter) maybePrune(now time.Time) {
	idle := time.Duration(l.userCap/l.userRate*float64(time.Second)) + time.Second
	if now.Sub(l.lastPrune) < idle {
		return
	}
	l.lastPrune = now
	for id, b := range l.users {
		if now.Sub(b.last) > idle {
			delete(l.users, id)
		}
	}
}

// appOf returns the app part of an "app.tool" name.
func appOf(tool string) string {
	app, _, _ := strings.Cut(tool, ".")
	return app
}
