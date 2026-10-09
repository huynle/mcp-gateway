package slack

import (
	"fmt"
	"testing"
	"time"
)

// TestNameCacheExpiresAndStaysBounded: an entry is served until its
// TTL and gone after; past the bound, expired entries make room first,
// then live ones, so the map never exceeds max.
func TestNameCacheExpiresAndStaysBounded(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	c := newNameCache(5*time.Minute, 3)
	c.now = func() time.Time { return now }

	c.put("acct/C1", "one")
	if got, ok := c.get("acct/C1"); !ok || got != "one" {
		t.Fatalf("fresh entry: %q %v", got, ok)
	}
	now = now.Add(5*time.Minute - time.Second)
	if _, ok := c.get("acct/C1"); !ok {
		t.Error("entry expired before its TTL")
	}
	now = now.Add(2 * time.Second)
	if _, ok := c.get("acct/C1"); ok {
		t.Error("entry served after its TTL")
	}
	if c.len() != 0 {
		t.Errorf("expired entry kept: len = %d", c.len())
	}

	// Bound: three live entries fill it; a fourth evicts one (an
	// expired one when there is one) and the size never exceeds max.
	c.put("acct/C1", "one")
	c.put("acct/C2", "two")
	now = now.Add(6 * time.Minute) // C1 and C2 expire
	c.put("acct/C3", "three")
	c.put("acct/C4", "four")
	if c.len() > 3 {
		t.Errorf("len = %d, want at most 3", c.len())
	}
	if _, ok := c.get("acct/C3"); !ok {
		t.Error("live entry C3 evicted while expired ones were available")
	}
	if _, ok := c.get("acct/C4"); !ok {
		t.Error("the entry just put is missing")
	}
	for i := 5; i < 50; i++ {
		c.put(fmt.Sprintf("acct/C%d", i), "n")
		if c.len() > 3 {
			t.Fatalf("after %d puts len = %d, want at most 3", i, c.len())
		}
	}
	// Re-putting an existing key never evicts another.
	keys := c.len()
	for k := range c.entries {
		c.put(k, "again")
		break
	}
	if c.len() != keys {
		t.Errorf("re-put changed the size: %d -> %d", keys, c.len())
	}
}
