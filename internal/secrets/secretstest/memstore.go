// Package secretstest provides an in-memory secrets.Store for tests in
// this and other packages (the portal, the pipeline).
package secretstest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/huynle/mcp-gateway/internal/secrets"
	"github.com/huynle/mcp-gateway/internal/store"
)

// MemStore is an in-memory secrets.Store that imitates the PostgreSQL
// one: under AsUser only the scoped user's rows are visible and writable;
// under Bypass every row is. Transactions are serialised, and a callback
// that returns an error rolls back every change it made.
type MemStore struct {
	mu   sync.Mutex
	rows map[string]*store.Secret
	n    int
}

// NewMemStore returns an empty store.
func NewMemStore() *MemStore { return &MemStore{rows: map[string]*store.Secret{}} }

// Record returns a copy of the stored row (value included) for
// assertions; nil when it does not exist.
func (m *MemStore) Record(id string) *store.Secret {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rows[id]
	if !ok {
		return nil
	}
	return clone(r)
}

// SwapValue exchanges the stored envelopes of two rows (tests of the AAD
// binding).
func (m *MemStore) SwapValue(a, b string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rows[a].Value, m.rows[b].Value = m.rows[b].Value, m.rows[a].Value
}

// AsUser implements secrets.Store.
func (m *MemStore) AsUser(_ context.Context, userID string, fn func(secrets.Tx) error) error {
	if userID == "" {
		return store.ErrInvalidUserID
	}
	return m.run(userID, fn)
}

// Bypass implements secrets.Store.
func (m *MemStore) Bypass(_ context.Context, fn func(secrets.Tx) error) error { return m.run("", fn) }

func (m *MemStore) run(user string, fn func(secrets.Tx) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	saved := make(map[string]*store.Secret, len(m.rows))
	for id, r := range m.rows {
		saved[id] = clone(r)
	}
	if err := fn(&memTx{m: m, user: user}); err != nil {
		m.rows = saved
		return err
	}
	return nil
}

func clone(r *store.Secret) *store.Secret {
	c := *r
	if r.Arg != nil {
		a := *r.Arg
		c.Arg = &a
	}
	if r.Value != nil {
		v := *r.Value
		v.WrappedDataKey = bytes.Clone(v.WrappedDataKey)
		v.Nonce = bytes.Clone(v.Nonce)
		v.Ciphertext = bytes.Clone(v.Ciphertext)
		c.Value = &v
	}
	for _, p := range []**time.Time{&c.ExpiresAt, &c.ProvidedAt, &c.EndedAt} {
		if *p != nil {
			t := **p
			*p = &t
		}
	}
	c.RequestHash = bytes.Clone(r.RequestHash)
	c.HandleHash = bytes.Clone(r.HandleHash)
	return &c
}

type memTx struct {
	m    *MemStore
	user string // "" under Bypass
}

func (t *memTx) visible(r *store.Secret) bool { return t.user == "" || r.OwnerUserID == t.user }

func (t *memTx) find(match func(*store.Secret) bool) *store.Secret {
	for _, r := range t.m.rows {
		if t.visible(r) && match(r) {
			return r
		}
	}
	return nil
}

func (t *memTx) get(match func(*store.Secret) bool) (*store.Secret, error) {
	if r := t.find(match); r != nil {
		return clone(r), nil
	}
	return nil, store.ErrNotFound
}

func (t *memTx) LockRequests(context.Context, string) error { return nil }

func (t *memTx) CountRequests(_ context.Context, ownerID string, since, at time.Time) (int, int, error) {
	var pending, recent int
	for _, r := range t.m.rows {
		if !t.visible(r) || r.OwnerUserID != ownerID {
			continue
		}
		if r.State == store.SecretPending && r.LinkExpiresAt.After(at) {
			pending++
		}
		if r.CreatedAt.After(since) {
			recent++
		}
	}
	return pending, recent, nil
}

func (t *memTx) CreateSecret(_ context.Context, s *store.Secret) error {
	if t.user != "" && s.OwnerUserID != t.user {
		return errors.New("secretstest: row violates row-level security policy")
	}
	for _, r := range t.m.rows {
		if bytes.Equal(r.RequestHash, s.RequestHash) || bytes.Equal(r.HandleHash, s.HandleHash) {
			return errors.New("secretstest: duplicate hash")
		}
	}
	c := clone(s)
	if c.ID == "" {
		t.m.n++
		c.ID = fmt.Sprintf("00000000-0000-4000-9000-%012d", t.m.n)
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now()
	}
	c.UpdatedAt = c.CreatedAt
	c.State, c.Value, c.ExpiresAt, c.ProvidedAt, c.EndedAt = store.SecretPending, nil, nil, nil, nil
	t.m.rows[c.ID] = c
	*s = *clone(c)
	return nil
}

func (t *memTx) GetSecret(_ context.Context, id string) (*store.Secret, error) {
	return t.get(func(r *store.Secret) bool { return r.ID == id })
}

func (t *memTx) GetSecretByRequestHash(_ context.Context, h []byte) (*store.Secret, error) {
	return t.get(func(r *store.Secret) bool { return bytes.Equal(r.RequestHash, h) })
}

func (t *memTx) GetSecretByHandleHash(_ context.Context, h []byte) (*store.Secret, error) {
	return t.get(func(r *store.Secret) bool { return bytes.Equal(r.HandleHash, h) })
}

func (t *memTx) ListSecrets(_ context.Context, ownerID string) ([]store.Secret, error) {
	var out []store.Secret
	for _, r := range t.m.rows {
		if t.visible(r) && r.OwnerUserID == ownerID {
			out = append(out, *clone(r))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID > out[j].ID
	})
	return out, nil
}

func (t *memTx) update(match func(*store.Secret) bool, change func(*store.Secret)) (*store.Secret, error) {
	r := t.find(match)
	if r == nil {
		return nil, store.ErrNotFound
	}
	change(r)
	return clone(r), nil
}

func wipe(r *store.Secret) { r.Value = nil }

func end(r *store.Secret, state string, at time.Time) {
	r.State, r.EndedAt, r.UpdatedAt = state, &at, at
	wipe(r)
}

func (t *memTx) ProvideSecret(_ context.Context, id string, requestHash []byte, value store.Encrypted, at time.Time) (*store.Secret, error) {
	return t.update(func(r *store.Secret) bool {
		return r.ID == id && bytes.Equal(r.RequestHash, requestHash) && r.State == store.SecretPending && r.LinkExpiresAt.After(at)
	}, func(r *store.Secret) {
		exp := at.Add(r.TTL)
		v := value
		r.State, r.ProvidedAt, r.ExpiresAt, r.UsesLeft, r.Value, r.UpdatedAt = store.SecretProvided, &at, &exp, r.UsesTotal, &v, at
	})
}

func (t *memTx) DenySecret(_ context.Context, requestHash []byte, at time.Time) (*store.Secret, error) {
	return t.update(func(r *store.Secret) bool {
		return bytes.Equal(r.RequestHash, requestHash) && r.State == store.SecretPending && r.LinkExpiresAt.After(at)
	}, func(r *store.Secret) { end(r, store.SecretDenied, at) })
}

func (t *memTx) RevokeSecret(_ context.Context, id string, at time.Time) (*store.Secret, error) {
	return t.update(func(r *store.Secret) bool {
		return r.ID == id && (r.State == store.SecretPending || r.State == store.SecretProvided)
	}, func(r *store.Secret) { end(r, store.SecretRevoked, at) })
}

func sameArg(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func (t *memTx) ConsumeSecret(_ context.Context, handleHash []byte, ownerID, harnessID string, b store.SecretBinding, at time.Time) (*store.Secret, error) {
	r, err := t.update(func(r *store.Secret) bool {
		return bytes.Equal(r.HandleHash, handleHash) && r.OwnerUserID == ownerID && r.HarnessID == harnessID &&
			r.ServerID == b.ServerID && r.Tool == b.Tool && sameArg(r.Arg, b.Arg) &&
			r.State == store.SecretProvided && r.UsesLeft > 0 && r.ExpiresAt.After(at)
	}, func(r *store.Secret) { r.UsesLeft--; r.UpdatedAt = at })
	if errors.Is(err, store.ErrNotFound) {
		return nil, store.ErrSecretNotConsumable
	}
	return r, err
}

func (t *memTx) RefundSecret(_ context.Context, id string, at time.Time) error {
	_, err := t.update(func(r *store.Secret) bool {
		return r.ID == id && r.State == store.SecretProvided && r.UsesLeft < r.UsesTotal && r.ExpiresAt.After(at)
	}, func(r *store.Secret) { r.UsesLeft++; r.UpdatedAt = at })
	return err
}

func (t *memTx) ExpireSecrets(_ context.Context, at time.Time, retention time.Duration) (store.SecretExpiry, error) {
	var out store.SecretExpiry
	cutoff := at.Add(-retention)
	for id, r := range t.m.rows {
		switch {
		case r.State == store.SecretPending && !r.LinkExpiresAt.After(at),
			r.State == store.SecretProvided && (r.UsesLeft == 0 || !r.ExpiresAt.After(at)):
			end(r, store.SecretExpired, at)
			out.Expired++
		case r.State != store.SecretPending && r.State != store.SecretProvided && r.EndedAt != nil && !r.EndedAt.After(cutoff):
			delete(t.m.rows, id)
			out.Deleted++
		}
	}
	return out, nil
}

func (t *memTx) RevokeUserSecrets(_ context.Context, ownerID string, at time.Time) (int64, error) {
	var n int64
	for _, r := range t.m.rows {
		if t.visible(r) && r.OwnerUserID == ownerID && (r.State == store.SecretPending || r.State == store.SecretProvided) {
			end(r, store.SecretRevoked, at)
			n++
		}
	}
	return n, nil
}
