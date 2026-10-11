package netguard

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// fakeSource is a loader whose entries and error the test changes.
type fakeSource struct {
	mu      sync.Mutex
	entries []string
	err     error
	calls   int
}

func (f *fakeSource) load(context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return append([]string(nil), f.entries...), f.err
}

func (f *fakeSource) set(entries []string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries, f.err = entries, err
}

func (f *fakeSource) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func TestCachedAllowListCachesForTTL(t *testing.T) {
	src := &fakeSource{entries: []string{"mcp.internal.example", "10.20.0.0/16"}}
	now := time.Unix(1000, 0)
	al := NewCachedAllowList(src.load, CachedAllowListOptions{TTL: time.Minute, Now: func() time.Time { return now }})
	ctx := context.Background()

	if !al.Allowed(ctx, "mcp.internal.example", netip.Addr{}) {
		t.Error("listed host refused")
	}
	if !al.Allowed(ctx, "x", netip.MustParseAddr("10.20.3.4")) {
		t.Error("address inside a listed CIDR refused")
	}
	if al.Allowed(ctx, "other.example", netip.MustParseAddr("10.30.0.1")) {
		t.Error("unlisted destination allowed")
	}
	if src.count() != 1 {
		t.Errorf("loads within the TTL = %d, want 1", src.count())
	}

	// An entry removed by an admin stops matching once the TTL passed.
	src.set([]string{"10.20.0.0/16"}, nil)
	now = now.Add(59 * time.Second)
	if !al.Allowed(ctx, "mcp.internal.example", netip.Addr{}) {
		t.Error("cached entry gone before the TTL")
	}
	now = now.Add(2 * time.Second)
	if al.Allowed(ctx, "mcp.internal.example", netip.Addr{}) {
		t.Error("removed entry still allowed after the TTL")
	}
	if src.count() != 2 {
		t.Errorf("loads = %d, want 2", src.count())
	}
}

func TestCachedAllowListInvalidate(t *testing.T) {
	src := &fakeSource{}
	al := NewCachedAllowList(src.load, CachedAllowListOptions{TTL: time.Hour})
	ctx := context.Background()
	if al.Allowed(ctx, "new.example", netip.Addr{}) {
		t.Fatal("empty list allowed a host")
	}
	src.set([]string{"new.example"}, nil)
	al.Invalidate()
	if !al.Allowed(ctx, "new.example", netip.Addr{}) {
		t.Error("entry added before Invalidate not seen")
	}
}

func TestCachedAllowListFailsClosed(t *testing.T) {
	src := &fakeSource{entries: []string{"mcp.internal.example"}}
	now := time.Unix(1000, 0)
	al := NewCachedAllowList(src.load, CachedAllowListOptions{TTL: time.Minute, Now: func() time.Time { return now }})
	ctx := context.Background()
	if !al.Allowed(ctx, "mcp.internal.example", netip.Addr{}) {
		t.Fatal("listed host refused")
	}
	// The store fails after the TTL: nothing is allowed, and the next ask
	// retries instead of caching the failure.
	src.set(nil, errors.New("database down"))
	now = now.Add(2 * time.Minute)
	if al.Allowed(ctx, "mcp.internal.example", netip.Addr{}) {
		t.Error("allowed while the list could not be loaded")
	}
	src.set([]string{"mcp.internal.example"}, nil)
	if !al.Allowed(ctx, "mcp.internal.example", netip.Addr{}) {
		t.Error("did not recover after the store came back")
	}
}

func TestCachedAllowListSkipsInvalidEntries(t *testing.T) {
	src := &fakeSource{entries: []string{"not a host!", "ok.example", "300.1.1.1/8"}}
	al := NewCachedAllowList(src.load, CachedAllowListOptions{})
	ctx := context.Background()
	if !al.Allowed(ctx, "ok.example", netip.Addr{}) {
		t.Error("a bad entry disabled the valid ones")
	}
	if al.Allowed(ctx, "not a host!", netip.Addr{}) {
		t.Error("an invalid entry matched")
	}
}

func TestCachedAllowListNilLoader(t *testing.T) {
	al := NewCachedAllowList(nil, CachedAllowListOptions{})
	if al.Allowed(context.Background(), "x.example", netip.Addr{}) {
		t.Error("nil loader allowed a host")
	}
}
