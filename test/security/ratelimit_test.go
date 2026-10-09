//go:build integration || e2e || security

package security

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/connectors/fake"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// loadResult is one call's outcome under concurrent load.
type loadResult struct {
	status     int
	code       int64
	retryAfter int64
	body       string
}

// fire posts n concurrent tools/call requests with the given tokens
// (round-robin) and returns every outcome.
func (w *world) fire(n int, tokensList []string, tool string, args map[string]any) []loadResult {
	w.t.Helper()
	out := make([]loadResult, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			status, _, body := w.rawCall(tokensList[i%len(tokensList)], tool, args)
			var env struct {
				Error *struct {
					Code int64           `json:"code"`
					Data json.RawMessage `json:"data"`
				} `json:"error"`
			}
			_ = json.Unmarshal(body, &env)
			r := loadResult{status: status, body: string(body)}
			if env.Error != nil {
				r.code = env.Error.Code
				var data struct {
					RetryAfter int64 `json:"retry_after"`
				}
				_ = json.Unmarshal(env.Error.Data, &data)
				r.retryAfter = data.RetryAfter
			}
			out[i] = r
		}(i)
	}
	wg.Wait()
	return out
}

// tally counts the outcomes: admitted calls (a result), rate-limited
// calls (-32029 with retry_after >= 1) and anything else.
func tally(t *testing.T, results []loadResult) (admitted, limited int) {
	t.Helper()
	for _, r := range results {
		switch {
		case r.status == http.StatusOK && r.code == 0:
			admitted++
		case r.code == mcp.CodeRateLimited:
			if r.retryAfter < 1 {
				t.Errorf("rate limited without retry_after: %s", r.body)
			}
			limited++
		default:
			t.Errorf("unexpected outcome under load: %d %s", r.status, r.body)
		}
	}
	return admitted, limited
}

// TestSecurityRateLimitsUnderConcurrentLoad: 200 concurrent calls by one
// user against a per-user budget of 50 admit exactly the budget (the
// bucket is atomic under contention), the rest answer -32029 with a
// usable retry_after; switching between several tokens of the same user
// does not widen the budget; the per-app bucket caps every user of an
// app together; a vendor 429 pauses the app for everyone for exactly the
// vendor's Retry-After and the harness is told that number.
func TestSecurityRateLimitsUnderConcurrentLoad(t *testing.T) {
	w := newWorld(t, options{rateUser: 50, rateApp: 600})

	// One user, four tokens, 200 concurrent reads.
	var aliceTokens []string
	for i := 0; i < 4; i++ {
		aliceTokens = append(aliceTokens, w.token(w.alice, tokens.CreateRequest{Name: "t" + strconv.Itoa(i)}))
	}
	started := time.Now()
	results := w.fire(200, aliceTokens, "fake.list_items", map[string]any{})
	// The bucket refills continuously (50/min), so a burst that takes
	// several seconds to process may admit a few more than the burst
	// size; never fewer, never more than the refill allows.
	refill := int(time.Since(started).Seconds()*50/60) + 1
	admitted, limited := tally(t, results)
	if admitted < 50 || admitted > 50+refill || admitted+limited != 200 {
		t.Errorf("per-user budget 50 across 4 tokens: admitted %d (allowed 50..%d), limited %d", admitted, 50+refill, limited)
	}
	// bob's budget is untouched (his own user bucket).
	bobToken := w.token(w.bob, tokens.CreateRequest{})
	if status, _, body := w.rawCall(bobToken, "fake.list_items", map[string]any{"account": w.bobAcc}); status != 200 || strings.Contains(string(body), `"error"`) {
		t.Errorf("bob after alice's exhaustion: %d %s", status, body)
	}
	// Refused calls are audited as denied with class rate_limited and
	// the connector never saw them.
	var denied int
	for _, ev := range w.events(w.alice) {
		if ev.Tool == "fake.list_items" && ev.ErrorClass == "rate_limited" && ev.Decision == "deny" {
			denied++
		}
	}
	if denied != limited {
		t.Errorf("audit rate_limited rows = %d, want %d", denied, limited)
	}

	// Per-app budget: a fresh world with a small app bucket shared by
	// alice and bob.
	w2 := newWorld(t, options{rateUser: 600, rateApp: 40})
	both := []string{w2.token(w2.alice, tokens.CreateRequest{}), w2.token(w2.bob, tokens.CreateRequest{})}
	started = time.Now()
	results = w2.fire(120, both, "fake.list_accounts", map[string]any{})
	refill = int(time.Since(started).Seconds()*40/60) + 1
	admitted, limited = tally(t, results)
	if admitted < 40 || admitted > 40+refill || admitted+limited != 120 {
		t.Errorf("per-app budget 40 across 2 users: admitted %d (allowed 40..%d), limited %d", admitted, 40+refill, limited)
	}
	// A different app is unaffected: the buckets are per app.
	if status, _, body := w2.rawCall(both[0], "github.list_accounts", map[string]any{}); status != 200 || strings.Contains(string(body), `"error"`) {
		t.Errorf("github after fake's app bucket ran dry: %d %s", status, body)
	}

	// Vendor 429: the fake reports RateLimited{RetryAfter: 7s} once; the
	// caller gets -32029 with retry_after 7 and the app is paused for
	// everyone, including the other user, with the remaining wait.
	w3 := newWorld(t, options{})
	a, b := w3.token(w3.alice, tokens.CreateRequest{}), w3.token(w3.bob, tokens.CreateRequest{})
	w3.fake.InjectFault(fake.ToolListItems, fake.Fault{Mode: fake.FaultRateLimited, RetryAfter: 7 * time.Second, Remaining: 1})
	_, _, body := w3.rawCall(a, "fake.list_items", map[string]any{})
	var env struct {
		Error struct {
			Code    int64  `json:"code"`
			Message string `json:"message"`
			Data    struct {
				RetryAfter int64 `json:"retry_after"`
			} `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err != nil || env.Error.Code != mcp.CodeRateLimited || env.Error.Data.RetryAfter != 7 || !strings.Contains(env.Error.Message, "fake is rate limiting") {
		t.Fatalf("vendor 429 answer: %s", body)
	}
	var paused atomic.Int32
	results = w3.fire(20, []string{a}, "fake.list_items", map[string]any{})
	for _, r := range results {
		if r.code == mcp.CodeRateLimited && r.retryAfter >= 1 && r.retryAfter <= 7 {
			paused.Add(1)
		}
	}
	if int(paused.Load()) != 20 {
		t.Errorf("calls during the vendor pause: %d of 20 were paused with retry_after <= 7: %+v", paused.Load(), results[:3])
	}
	_, _, body = w3.rawCall(b, "fake.list_items", map[string]any{"account": w3.bobAcc})
	if err := json.Unmarshal(body, &env); err != nil || env.Error.Code != mcp.CodeRateLimited || env.Error.Data.RetryAfter < 1 || env.Error.Data.RetryAfter > 7 {
		t.Errorf("bob during fake's vendor pause: %s", body)
	}
	if n := len(w3.fake.State().Items(w3.bobAcc)); n != 0 {
		t.Errorf("fake state touched during the pause: %d", n)
	}
	// Another app is not paused.
	if status, _, body := w3.rawCall(b, "slack.list_accounts", map[string]any{}); status != 200 || strings.Contains(string(body), `"error"`) {
		t.Errorf("slack during fake's vendor pause: %d %s", status, body)
	}
}
