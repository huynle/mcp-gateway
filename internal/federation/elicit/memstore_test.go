package elicit_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"github.com/huynle/mcp-gateway/internal/federation/elicit"
	"github.com/huynle/mcp-gateway/internal/store"
)

// memStore is an in-memory elicit.Store with the semantics of the
// PostgreSQL queries (owner scope as row security, live = not cancelled
// and not expired). One mutex serialises transactions.
type memStore struct {
	mu   sync.Mutex
	rows []*store.UpstreamElicitation
	// failCreate, when set, is CreateUpstreamElicitation's error.
	failCreate error
}

func newMemStore() *memStore { return &memStore{} }

type memTx struct {
	m     *memStore
	owner string // "" in the bypass scope
}

func (m *memStore) AsUser(_ context.Context, userID string, fn func(elicit.Tx) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return fn(memTx{m: m, owner: userID})
}

func (m *memStore) Bypass(_ context.Context, fn func(elicit.Tx) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return fn(memTx{m: m})
}

func (t memTx) visible(e *store.UpstreamElicitation) bool {
	return t.owner == "" || e.OwnerUserID == t.owner
}

func (t memTx) Lock(context.Context, string) error { return nil }

func (t memTx) CountLive(_ context.Context, owner string, at time.Time) (int, error) {
	n := 0
	for _, e := range t.m.rows {
		if t.visible(e) && e.OwnerUserID == owner && e.CancelledAt == nil && e.ExpiresAt.After(at) {
			n++
		}
	}
	return n, nil
}

func (t memTx) Create(_ context.Context, e *store.UpstreamElicitation) error {
	if t.m.failCreate != nil {
		return t.m.failCreate
	}
	if t.owner != "" && e.OwnerUserID != t.owner {
		return fmt.Errorf("row security: owner mismatch")
	}
	for _, r := range t.m.rows {
		if bytes.Equal(r.LinkHash, e.LinkHash) {
			return fmt.Errorf("duplicate link hash")
		}
	}
	cp := *e
	if cp.ID == "" {
		cp.ID = randomUUID()
	}
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = time.Now()
	}
	t.m.rows = append(t.m.rows, &cp)
	*e = cp
	return nil
}

func (t memTx) live(owner string, h []byte, at time.Time) *store.UpstreamElicitation {
	for _, e := range t.m.rows {
		if t.visible(e) && e.OwnerUserID == owner && bytes.Equal(e.LinkHash, h) && e.CancelledAt == nil && e.ExpiresAt.After(at) {
			return e
		}
	}
	return nil
}

func (t memTx) GetByLink(_ context.Context, owner string, h []byte, at time.Time) (*store.UpstreamElicitation, error) {
	e := t.live(owner, h, at)
	if e == nil {
		return nil, store.ErrNotFound
	}
	cp := *e
	return &cp, nil
}

func (t memTx) MarkOpened(_ context.Context, owner string, h []byte, at time.Time) (*store.UpstreamElicitation, error) {
	e := t.live(owner, h, at)
	if e == nil {
		return nil, store.ErrNotFound
	}
	if e.OpenedAt == nil {
		at := at
		e.OpenedAt = &at
	}
	cp := *e
	return &cp, nil
}

func (t memTx) MarkCancelled(_ context.Context, owner string, h []byte, at time.Time) (*store.UpstreamElicitation, error) {
	e := t.live(owner, h, at)
	if e == nil {
		return nil, store.ErrNotFound
	}
	e.CancelledAt = &at
	cp := *e
	return &cp, nil
}

func (t memTx) PurgeExpired(_ context.Context, before time.Time) (int64, error) {
	if t.owner != "" {
		return 0, fmt.Errorf("permission denied")
	}
	var keep []*store.UpstreamElicitation
	var n int64
	for _, e := range t.m.rows {
		if !e.ExpiresAt.After(before) {
			n++
			continue
		}
		keep = append(keep, e)
	}
	t.m.rows = keep
	return n, nil
}

func (m *memStore) all() []store.UpstreamElicitation {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.UpstreamElicitation, 0, len(m.rows))
	for _, e := range m.rows {
		out = append(out, *e)
	}
	return out
}

func randomUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
