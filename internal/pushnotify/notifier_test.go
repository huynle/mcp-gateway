package pushnotify_test

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/approvals"
	"github.com/huynle/mcp-gateway/internal/pushnotify"
	"github.com/huynle/mcp-gateway/internal/webpush"
)

// The service is an approvals.Notifier.
var _ approvals.Notifier = (*pushnotify.Service)(nil)

func pendingApproval(f *fixture, expiresIn time.Duration) approvals.Approval {
	return approvals.Approval{
		ID: "44444444-4444-4444-8444-444444444444", UserID: alice, Tool: "github.create_issue",
		AccountID: "conn-1", AccountLabel: "company", AccountName: "octocat-private-name",
		ResourceIdentity: map[string]string{"repo": "acme/secret-roadmap"},
		Status:           approvals.StatusPending, CreatedAt: f.now, ExpiresAt: f.now.Add(expiresIn),
	}
}

func subscribeN(t *testing.T, f *fixture, user string, n int) []string {
	t.Helper()
	var eps []string
	for range n {
		ep, js := subscription(t, "fcm.googleapis.com")
		if _, err := f.svc.Subscribe(t.Context(), user, js, ""); err != nil {
			t.Fatal(err)
		}
		eps = append(eps, ep)
	}
	return eps
}

func TestNotifyPayloadIsMinimal(t *testing.T) {
	f := newFixture(t)
	subscribeN(t, f, alice, 2)
	subscribeN(t, f, bob, 1)
	a := pendingApproval(f, 10*time.Minute)
	if err := f.svc.Notify(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	calls := f.sender.sent()
	if len(calls) != 2 {
		t.Fatalf("sent %d messages, want one per device of alice (2)", len(calls))
	}
	for _, c := range calls {
		var msg map[string]any
		if err := json.Unmarshal(c.payload, &msg); err != nil {
			t.Fatal(err)
		}
		want := map[string]any{
			"title": "Approval needed", "body": "github.create_issue (company)",
			"url": "/approvals", "tag": "approval-" + a.ID,
		}
		if len(msg) != len(want) {
			t.Errorf("payload keys = %v, want exactly title, body, url, tag", msg)
		}
		for k, v := range want {
			if msg[k] != v {
				t.Errorf("payload %s = %v, want %v", k, msg[k], v)
			}
		}
		for _, secret := range []string{"secret-roadmap", "acme", "octocat"} {
			if strings.Contains(string(c.payload), secret) {
				t.Errorf("payload leaks %q: %s", secret, c.payload)
			}
		}
		if c.opts.TTL != 10*time.Minute || c.opts.Urgency != "high" {
			t.Errorf("send options = %+v", c.opts)
		}
		if !regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`).MatchString(c.opts.Topic) || strings.Contains(c.opts.Topic, "4444") {
			t.Errorf("topic = %q, want a short base64url hash of the approval id", c.opts.Topic)
		}
	}
	if calls[0].opts.Topic != calls[1].opts.Topic {
		t.Error("topic differs between devices")
	}
	// The account label is optional.
	a.AccountLabel = ""
	f.sender.calls = nil
	if err := f.svc.Notify(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	var msg map[string]string
	_ = json.Unmarshal(f.sender.sent()[0].payload, &msg)
	if msg["body"] != "github.create_issue" {
		t.Errorf("body without label = %q", msg["body"])
	}
}

func TestNotifyTTLFollowsTheExpiryWithinBounds(t *testing.T) {
	for expiresIn, want := range map[time.Duration]time.Duration{
		10 * time.Minute: 10 * time.Minute,
		20 * time.Second: time.Minute,
		-time.Minute:     time.Minute,
		3 * time.Hour:    time.Hour,
	} {
		f := newFixture(t)
		subscribeN(t, f, alice, 1)
		if err := f.svc.Notify(t.Context(), pendingApproval(f, expiresIn)); err != nil {
			t.Fatal(err)
		}
		if got := f.sender.sent()[0].opts.TTL; got != want {
			t.Errorf("expires in %s: TTL %s, want %s", expiresIn, got, want)
		}
	}
}

// Users without devices cost nothing: no key is created, nothing is sent.
func TestNotifyWithoutDevicesDoesNothing(t *testing.T) {
	f := newFixture(t)
	if err := f.svc.Notify(t.Context(), pendingApproval(f, time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(f.sender.sent()) != 0 || f.st.key != nil {
		t.Errorf("sent %d, key created %v", len(f.sender.sent()), f.st.key != nil)
	}
}

func TestNotifyDeletesGoneAndRecordsDeliveries(t *testing.T) {
	f := newFixture(t)
	eps := subscribeN(t, f, alice, 4)
	errA, errB := errors.New("push service A down"), errors.New("push service B down")
	f.sender.result = func(_ context.Context, ep string) error {
		switch ep {
		case eps[1]:
			return &webpush.StatusError{StatusCode: 410, Host: "fcm.googleapis.com"}
		case eps[2]:
			return errA
		case eps[3]:
			return errB
		}
		return nil
	}
	err := f.svc.Notify(t.Context(), pendingApproval(f, 5*time.Minute))
	if !errors.Is(err, errA) || !errors.Is(err, errB) {
		t.Fatalf("Notify = %v, want both failures joined", err)
	}
	if strings.Contains(err.Error(), "/fcm/send/") {
		t.Errorf("error names an endpoint: %v", err)
	}
	devs, _ := f.svc.Devices(t.Context(), alice)
	if len(devs) != 3 {
		t.Fatalf("devices after a 410 = %d, want the gone one deleted (3)", len(devs))
	}
	ok, failed := 0, 0
	for _, d := range devs {
		if d.LastSuccessAt != nil && d.LastSuccessAt.Equal(f.now) && d.FailureCount == 0 {
			ok++
		}
		if d.LastFailureAt != nil && d.FailureCount == 1 {
			failed++
		}
	}
	if ok != 1 || failed != 2 {
		t.Errorf("deliveries recorded: %d ok, %d failed; want 1, 2 (%+v)", ok, failed, devs)
	}
}

// A slow push service never holds the approval flow longer than the
// timeout, even when the sender ignores its context.
func TestNotifyIsBoundedByTheTimeout(t *testing.T) {
	f := newFixture(t, func(o *pushnotify.Options) { o.Timeout = 100 * time.Millisecond })
	eps := subscribeN(t, f, alice, 3)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	f.sender.result = func(ctx context.Context, ep string) error {
		switch ep {
		case eps[0]:
			return nil
		case eps[1]:
			<-ctx.Done()
			return ctx.Err()
		}
		<-release // ignores the context entirely
		return nil
	}
	start := time.Now()
	err := f.svc.Notify(t.Context(), pendingApproval(f, 5*time.Minute))
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Notify took %s with a 100ms timeout", elapsed)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Notify = %v, want the deadline reported", err)
	}
}

func TestNotifyBoundsConcurrency(t *testing.T) {
	f := newFixture(t)
	subscribeN(t, f, alice, pushnotify.MaxSubscriptionsPerUser)
	var inFlight, peak atomic.Int32
	var mu sync.Mutex
	f.sender.result = func(context.Context, string) error {
		n := inFlight.Add(1)
		mu.Lock()
		if n > peak.Load() {
			peak.Store(n)
		}
		mu.Unlock()
		time.Sleep(20 * time.Millisecond)
		inFlight.Add(-1)
		return nil
	}
	if err := f.svc.Notify(t.Context(), pendingApproval(f, 5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if p := peak.Load(); p > pushnotify.NotifyConcurrency || p < 2 {
		t.Errorf("peak concurrent sends = %d, want 2..%d", p, pushnotify.NotifyConcurrency)
	}
	if n := len(f.sender.sent()); n != pushnotify.MaxSubscriptionsPerUser {
		t.Errorf("sent %d", n)
	}
}

// A sealed subscription moved to another user's row does not open: the
// AAD binds it to its owner and record.
func TestNotifyRefusesMovedEnvelope(t *testing.T) {
	f := newFixture(t)
	subscribeN(t, f, alice, 1)
	subscribeN(t, f, bob, 1)
	rows := f.st.all()
	f.st.mu.Lock()
	f.st.subs[rows[0].ID].Sealed, f.st.subs[rows[1].ID].Sealed = rows[1].Sealed, rows[0].Sealed
	f.st.mu.Unlock()
	if err := f.svc.Notify(t.Context(), pendingApproval(f, time.Minute)); err == nil {
		t.Error("swapped envelope opened")
	}
	if n := len(f.sender.sent()); n != 0 {
		t.Errorf("sent %d messages with a swapped envelope", n)
	}
}

func TestSendTestIsRateLimited(t *testing.T) {
	f := newFixture(t)
	subscribeN(t, f, alice, 2)
	n, err := f.svc.SendTest(t.Context(), alice)
	if err != nil || n != 2 {
		t.Fatalf("SendTest = %d, %v", n, err)
	}
	var msg map[string]string
	_ = json.Unmarshal(f.sender.sent()[0].payload, &msg)
	if msg["title"] != "Test notification" || msg["url"] == "" || msg["tag"] == "" || len(msg) != 4 {
		t.Errorf("test payload = %v", msg)
	}
	f.now = f.now.Add(10 * time.Second)
	_, err = f.svc.SendTest(t.Context(), alice)
	var soon *pushnotify.TestTooSoonError
	if !errors.As(err, &soon) || !errors.Is(err, pushnotify.ErrTestTooSoon) || soon.RetryAfter != 20*time.Second {
		t.Fatalf("second test within 30s = %v, want TestTooSoonError{20s}", err)
	}
	// Bob is not limited by alice.
	if _, err := f.svc.SendTest(t.Context(), bob); err != nil {
		t.Errorf("bob: %v", err)
	}
	f.now = f.now.Add(pushnotify.TestInterval)
	if _, err := f.svc.SendTest(t.Context(), alice); err != nil {
		t.Errorf("after the interval: %v", err)
	}
	if got := f.audit.actions(); got[len(got)-1] != "push.test_sent" {
		t.Errorf("audit = %v", got)
	}
}
