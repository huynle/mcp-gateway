package mcp_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/observability"
)

// fakeClock drives the limiter's notion of time.
type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time          { return c.now }
func (c *fakeClock) Advance(d time.Duration) { c.now = c.now.Add(d) }
func newClock() *fakeClock                   { return &fakeClock{now: time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)} }
func allow(l mcp.RateLimiter, user, tool string) (bool, time.Duration) {
	return l.Allow(context.Background(), user, tool)
}

func TestRateLimiterDefaults(t *testing.T) {
	l := mcp.NewRateLimiter(mcp.RateLimitConfig{})
	if l.UserPerMinute() != mcp.DefaultUserPerMinute || l.AppPerMinute() != mcp.DefaultAppPerMinute {
		t.Errorf("defaults = %d/%d, want %d/%d", l.UserPerMinute(), l.AppPerMinute(), mcp.DefaultUserPerMinute, mcp.DefaultAppPerMinute)
	}
	if mcp.DefaultUserPerMinute != 60 || mcp.DefaultAppPerMinute != 600 {
		t.Errorf("documented defaults changed: %d/%d", mcp.DefaultUserPerMinute, mcp.DefaultAppPerMinute)
	}
}

func TestRateLimiterPerUser(t *testing.T) {
	clock := newClock()
	l := mcp.NewRateLimiter(mcp.RateLimitConfig{UserPerMinute: 2, AppPerMinute: 1000, Now: clock.Now})
	for i := range 2 {
		if ok, wait := allow(l, "alice", "github.list_issues"); !ok {
			t.Fatalf("call %d denied (wait %v)", i, wait)
		}
	}
	ok, wait := allow(l, "alice", "github.list_issues")
	if ok || wait <= 0 || wait > 30*time.Second {
		t.Fatalf("third call: ok=%v wait=%v, want denied with a wait of at most 30s", ok, wait)
	}
	// Another user is unaffected, even on the same tool.
	if ok, _ := allow(l, "bob", "github.list_issues"); !ok {
		t.Error("bob denied by alice's bucket")
	}
	// The bucket refills at the configured rate: 2/min is one per 30s.
	clock.Advance(wait)
	if ok, _ := allow(l, "alice", "github.list_issues"); !ok {
		t.Error("alice still denied after the advertised wait")
	}
	if ok, _ := allow(l, "alice", "slack.list_channels"); ok {
		t.Error("the per-user budget is per user, not per app")
	}
}

func TestRateLimiterPerApp(t *testing.T) {
	clock := newClock()
	l := mcp.NewRateLimiter(mcp.RateLimitConfig{UserPerMinute: 2, AppPerMinute: 3, Now: clock.Now})
	for i := range 3 {
		if ok, _ := allow(l, fmt.Sprintf("user-%d", i), "github.list_issues"); !ok {
			t.Fatalf("call %d denied", i)
		}
	}
	ok, wait := allow(l, "user-9", "github.create_issue")
	if ok || wait <= 0 || wait > 20*time.Second {
		t.Fatalf("fourth github call: ok=%v wait=%v", ok, wait)
	}
	// A denied call must not have consumed the user's own budget: user-9
	// still has both of its per-user tokens for slack (app budget 3).
	for i := range 2 {
		if ok, _ := allow(l, "user-9", "slack.list_channels"); !ok {
			t.Fatalf("slack call %d denied: the denied github call consumed user-9's budget", i)
		}
	}
	if ok, _ := allow(l, "user-9", "slack.list_channels"); ok {
		t.Error("third slack call allowed beyond the per-user budget")
	}
	clock.Advance(wait)
	if ok, _ := allow(l, "user-10", "github.list_issues"); !ok {
		t.Error("github still denied after the advertised wait")
	}
}

func TestRateLimiterPauseHonoursVendorRetryAfter(t *testing.T) {
	clock := newClock()
	l := mcp.NewRateLimiter(mcp.RateLimitConfig{Now: clock.Now})
	l.Pause("github", 17*time.Second)
	ok, wait := allow(l, "alice", "github.list_issues")
	if ok || wait != 17*time.Second {
		t.Fatalf("paused app: ok=%v wait=%v, want denied for 17s", ok, wait)
	}
	if ok, _ := allow(l, "alice", "slack.list_channels"); !ok {
		t.Error("slack paused by github's Retry-After")
	}
	clock.Advance(10 * time.Second)
	if _, wait := allow(l, "alice", "github.list_issues"); wait != 7*time.Second {
		t.Errorf("wait after 10s = %v, want 7s", wait)
	}
	// A shorter pause never cuts an existing one short; a longer one extends it.
	l.Pause("github", time.Second)
	if _, wait := allow(l, "alice", "github.list_issues"); wait != 7*time.Second {
		t.Errorf("shorter pause replaced the longer one: wait = %v", wait)
	}
	l.Pause("github", 30*time.Second)
	if _, wait := allow(l, "alice", "github.list_issues"); wait != 30*time.Second {
		t.Errorf("longer pause not applied: wait = %v", wait)
	}
	clock.Advance(30 * time.Second)
	if ok, _ := allow(l, "alice", "github.list_issues"); !ok {
		t.Error("still paused after the pause elapsed")
	}
	// Pausing with no duration is a no-op.
	l.Pause("github", 0)
	if ok, _ := allow(l, "alice", "github.list_issues"); !ok {
		t.Error("zero pause blocked the app")
	}
}

func TestRateLimiterForgetsIdleUsers(t *testing.T) {
	clock := newClock()
	l := mcp.NewRateLimiter(mcp.RateLimitConfig{UserPerMinute: 1, Now: clock.Now})
	for i := range 5000 {
		allow(l, fmt.Sprintf("u-%d", i), "github.x")
	}
	clock.Advance(10 * time.Minute)
	allow(l, "late", "github.x")
	if n := l.TrackedUsers(); n > 1 {
		t.Errorf("tracked users after idle period = %d, want 1", n)
	}
}

func TestRateLimitStageSurfacesVendorRetryAfter(t *testing.T) {
	limited := echoTool("github", "list_issues", connectors.KindRead)
	limited.Handler = func(context.Context, connectors.Call) (connectors.Result, error) {
		return connectors.Result{}, fmt.Errorf("GET /issues: %w", &connectors.RateLimited{App: "github", RetryAfter: 17 * time.Second})
	}
	clock := newClock()
	lim := mcp.NewRateLimiter(mcp.RateLimitConfig{Now: clock.Now})
	metrics := observability.NewMetrics()
	rec := &captureRecorder{}
	p, err := mcp.DefaultPipeline(mcp.PipelineDeps{
		Registry:    newRegistry(t, limited, echoTool("github", "list_prs", connectors.KindRead)),
		RateLimiter: lim, Metrics: metrics, Audit: rec, Log: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Run(context.Background(), &mcp.CallContext{Principal: principal, Name: "github.list_issues"})
	var te *mcp.ToolError
	if !errors.As(err, &te) || te.Code != mcp.CodeRateLimited || te.Class() != "vendor_rate_limited" || te.RetryAfter != 17*time.Second {
		t.Fatalf("err = %#v, want ToolError{CodeRateLimited, vendor_rate_limited, 17s}", err)
	}
	if !strings.Contains(te.Message, "17s") || !strings.Contains(te.Message, "github") {
		t.Errorf("message = %q", te.Message)
	}
	// The app's bucket is paused: a different tool of the same app waits too.
	_, err = p.Run(context.Background(), &mcp.CallContext{Principal: principal, Name: "github.list_prs"})
	if !errors.As(err, &te) || te.Code != mcp.CodeRateLimited || te.RetryAfter != 17*time.Second || te.Class() != "rate_limited" {
		t.Fatalf("second call err = %#v, want the pause", err)
	}
	if got := counterValue(t, metrics, "vendor_rate_limited_total", "app", "github"); got != 1 {
		t.Errorf("vendor_rate_limited_total{app=github} = %v, want 1", got)
	}
	if len(rec.events) != 2 || rec.events[0].ErrorClass != "vendor_rate_limited" || rec.events[0].Outcome != "denied" {
		t.Errorf("audit = %+v", rec.events)
	}
}

func TestRateLimitStageWithoutPauserStillSurfacesRetryAfter(t *testing.T) {
	limited := echoTool("github", "list_issues", connectors.KindRead)
	limited.Handler = func(context.Context, connectors.Call) (connectors.Result, error) {
		return connectors.Result{}, &connectors.RateLimited{App: "github", RetryAfter: 3 * time.Second}
	}
	p := defaultPipeline(t, newRegistry(t, limited), nil, &denyLimiter{})
	_, err := p.Run(context.Background(), &mcp.CallContext{Principal: principal, Name: "github.list_issues"})
	var te *mcp.ToolError
	if !errors.As(err, &te) || te.RetryAfter != 3*time.Second {
		t.Fatalf("err = %#v", err)
	}
}

func TestRateLimitedErrorCarriesRetryAfterOnTheWire(t *testing.T) {
	limited := stubTool("github", "list_issues", connectors.KindRead)
	limited.Handler = func(context.Context, connectors.Call) (connectors.Result, error) {
		return connectors.Result{}, &connectors.RateLimited{App: "github", RetryAfter: 1500 * time.Millisecond}
	}
	srv := httptest.NewServer(newHandler(t, newRegistry(t, limited), func(o *mcp.Options) {
		o.RateLimiter = mcp.NewRateLimiter(mcp.RateLimitConfig{})
	}))
	defer srv.Close()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"github.list_issues","arguments":{}}}`
	r := post(t, srv.URL, fullToken, body)
	var msg struct {
		Error struct {
			Code    int64  `json:"code"`
			Message string `json:"message"`
			Data    struct {
				RetryAfter int `json:"retry_after"`
			} `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(r.Body, &msg); err != nil {
		t.Fatalf("%s: %v", r.Body, err)
	}
	if msg.Error.Code != mcp.CodeRateLimited || msg.Error.Data.RetryAfter != 2 {
		t.Errorf("error = %+v (body %s), want code %d and retry_after 2 (1.5s rounded up)", msg.Error, r.Body, mcp.CodeRateLimited)
	}
	// The second call hits the pause and reports the remaining wait.
	r = post(t, srv.URL, fullToken, body)
	if err := json.Unmarshal(r.Body, &msg); err != nil {
		t.Fatal(err)
	}
	if msg.Error.Code != mcp.CodeRateLimited || msg.Error.Data.RetryAfter < 1 || msg.Error.Data.RetryAfter > 2 {
		t.Errorf("paused call error = %+v", msg.Error)
	}
}

// counterValue reads one labelled counter from the metrics registry.
func counterValue(t *testing.T, m *observability.Metrics, name, label, value string) float64 {
	t.Helper()
	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		for _, metric := range f.GetMetric() {
			for _, l := range metric.GetLabel() {
				if l.GetName() == label && l.GetValue() == value {
					return metric.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}
