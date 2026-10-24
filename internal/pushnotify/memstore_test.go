package pushnotify_test

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/huynle/mcp-gateway/internal/pushnotify"
	"github.com/huynle/mcp-gateway/internal/store"
)

// memStore is an in-memory pushnotify.Store that imitates the PostgreSQL
// one: under AsUser only the scoped user's subscriptions are visible and
// writable (the VAPID key is a system row, visible to every scope); under
// Bypass every row is. Transactions are serialised; a callback that
// returns an error rolls its changes back.
type memStore struct {
	mu   sync.Mutex
	key  *store.WebPushKey
	subs map[string]*store.PushSubscription
	// keyReads counts GetKey calls (cache tests).
	keyReads int
}

func newMemStore() *memStore { return &memStore{subs: map[string]*store.PushSubscription{}} }

func (m *memStore) AsUser(_ context.Context, userID string, fn func(pushnotify.Tx) error) error {
	if userID == "" {
		return store.ErrInvalidUserID
	}
	return m.run(userID, fn)
}

func (m *memStore) Bypass(_ context.Context, fn func(pushnotify.Tx) error) error {
	return m.run("", fn)
}

func (m *memStore) run(user string, fn func(pushnotify.Tx) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	saved := map[string]*store.PushSubscription{}
	for id, s := range m.subs {
		c := *s
		saved[id] = &c
	}
	savedKey := m.key
	if err := fn(&memTx{m: m, user: user}); err != nil {
		m.subs, m.key = saved, savedKey
		return err
	}
	return nil
}

// all returns copies of every subscription, oldest first.
func (m *memStore) all() []store.PushSubscription {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.PushSubscription
	for _, s := range m.subs {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

type memTx struct {
	m    *memStore
	user string
}

func (t *memTx) visible(s *store.PushSubscription) bool { return t.user == "" || s.UserID == t.user }

func (t *memTx) GetKey(context.Context) (*store.WebPushKey, error) {
	t.m.keyReads++
	if t.m.key == nil {
		return nil, store.ErrNotFound
	}
	k := *t.m.key
	return &k, nil
}

func (t *memTx) CreateKey(_ context.Context, k *store.WebPushKey) (bool, error) {
	if t.m.key != nil {
		return false, nil
	}
	c := *k
	c.CreatedAt = time.Now()
	t.m.key = &c
	return true, nil
}

func (t *memTx) Lock(context.Context, string) error { return nil }

func (t *memTx) Count(_ context.Context, userID string) (int, error) {
	n := 0
	for _, s := range t.m.subs {
		if t.visible(s) && s.UserID == userID {
			n++
		}
	}
	return n, nil
}

func (t *memTx) GetByHash(_ context.Context, h []byte) (*store.PushSubscription, error) {
	for _, s := range t.m.subs {
		if t.visible(s) && bytes.Equal(s.EndpointSHA256, h) {
			c := *s
			return &c, nil
		}
	}
	return nil, store.ErrNotFound
}

func (t *memTx) Create(_ context.Context, s *store.PushSubscription) error {
	if t.user != "" && s.UserID != t.user {
		return errors.New("memstore: row-level security")
	}
	for _, o := range t.m.subs {
		if bytes.Equal(o.EndpointSHA256, s.EndpointSHA256) {
			return store.ErrPushEndpointTaken
		}
	}
	now := time.Now()
	c := *s
	c.CreatedAt, c.UpdatedAt = now, now
	// Distinct creation times keep "oldest first" deterministic.
	time.Sleep(time.Millisecond)
	t.m.subs[c.ID] = &c
	*s = c
	return nil
}

func (t *memTx) Update(_ context.Context, s *store.PushSubscription) error {
	o, ok := t.m.subs[s.ID]
	if !ok || !t.visible(o) {
		return store.ErrNotFound
	}
	o.Sealed, o.EndpointHost, o.DeviceLabel, o.FailureCount, o.UpdatedAt = s.Sealed, s.EndpointHost, s.DeviceLabel, 0, time.Now()
	*s = *o
	return nil
}

func (t *memTx) List(_ context.Context, userID string) ([]store.PushSubscription, error) {
	var out []store.PushSubscription
	for _, s := range t.m.subs {
		if t.visible(s) && s.UserID == userID {
			out = append(out, *s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (t *memTx) Delete(_ context.Context, id string) (bool, error) {
	s, ok := t.m.subs[id]
	if !ok || !t.visible(s) {
		return false, nil
	}
	delete(t.m.subs, id)
	return true, nil
}

func (t *memTx) DeleteByHash(ctx context.Context, h []byte) (bool, error) {
	s, err := t.GetByHash(ctx, h)
	if err != nil {
		return false, nil
	}
	return t.Delete(ctx, s.ID)
}

func (t *memTx) Release(_ context.Context, h []byte, newOwner string) (int64, error) {
	if t.user != "" {
		return 0, errors.New("memstore: release needs the bypass scope")
	}
	var n int64
	for id, s := range t.m.subs {
		if bytes.Equal(s.EndpointSHA256, h) && s.UserID != newOwner {
			delete(t.m.subs, id)
			n++
		}
	}
	return n, nil
}

func (t *memTx) RecordDelivery(_ context.Context, id string, ok bool, at time.Time) error {
	s, found := t.m.subs[id]
	if !found || !t.visible(s) {
		return nil
	}
	if ok {
		s.LastSuccessAt, s.FailureCount = &at, 0
	} else {
		s.LastFailureAt = &at
		s.FailureCount++
	}
	return nil
}

func (t *memTx) DeleteUser(_ context.Context, userID string) (int64, error) {
	var n int64
	for id, s := range t.m.subs {
		if t.visible(s) && s.UserID == userID {
			delete(t.m.subs, id)
			n++
		}
	}
	return n, nil
}
