package netguard

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"time"
)

// DefaultAllowListTTL is how long CachedAllowList keeps a loaded list.
const DefaultAllowListTTL = 30 * time.Second

// CachedAllowListOptions configure NewCachedAllowList.
type CachedAllowListOptions struct {
	// TTL is how long a loaded list is used before it is loaded again
	// (default DefaultAllowListTTL). Admin edits on this replica call
	// Invalidate; other replicas see them within TTL.
	TTL time.Duration
	// Now is the clock (tests); default time.Now.
	Now func() time.Time
	// Log receives load failures and skipped entries (the entry text is an
	// admin-entered host or CIDR, never a secret). Default: discard.
	Log *slog.Logger
}

// CachedAllowList is an AllowList over entries loaded from elsewhere
// (cmd/gateway loads netguard_allow_hosts through the store) and kept for
// a short TTL, so the dial-time check does not query the database on every
// connection. It fails closed: when the load fails nothing is allowed and
// the next ask loads again. An entry NewStaticAllowList refuses is skipped
// (and logged), so one bad row cannot close or open everything.
type CachedAllowList struct {
	load func(context.Context) ([]string, error)
	ttl  time.Duration
	now  func() time.Time
	log  *slog.Logger

	mu       sync.Mutex
	list     *StaticAllowList
	loadedAt time.Time
	valid    bool
}

// NewCachedAllowList returns a list over load. A nil load allows nothing.
func NewCachedAllowList(load func(context.Context) ([]string, error), o CachedAllowListOptions) *CachedAllowList {
	if o.TTL <= 0 {
		o.TTL = DefaultAllowListTTL
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	return &CachedAllowList{load: load, ttl: o.TTL, now: o.Now, log: o.Log}
}

// Allowed implements AllowList.
func (c *CachedAllowList) Allowed(ctx context.Context, host string, ip netip.Addr) bool {
	list := c.current(ctx)
	return list != nil && list.Allowed(ctx, host, ip)
}

// Invalidate makes the next Allowed load the list again (call it after an
// admin changed the entries).
func (c *CachedAllowList) Invalidate() {
	c.mu.Lock()
	c.valid = false
	c.mu.Unlock()
}

// current returns the cached list, loading it when it is missing or older
// than the TTL; nil when the load failed. Loads are serialised so a burst
// of dials shares one query.
func (c *CachedAllowList) current(ctx context.Context) *StaticAllowList {
	if c.load == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.valid && c.now().Sub(c.loadedAt) < c.ttl {
		return c.list
	}
	entries, err := c.load(ctx)
	if err != nil {
		c.valid, c.list = false, nil
		c.log.Error("netguard: allow list could not be loaded; allowing nothing", "error", err.Error())
		return nil
	}
	valid := make([]string, 0, len(entries))
	for _, e := range entries {
		if _, err := NewStaticAllowList(e); err != nil {
			c.log.Warn("netguard: allow list entry skipped", "entry", e)
			continue
		}
		valid = append(valid, e)
	}
	list, err := NewStaticAllowList(valid...)
	if err != nil { // unreachable: every entry was checked
		c.valid, c.list = false, nil
		return nil
	}
	c.list, c.loadedAt, c.valid = list, c.now(), true
	return list
}
