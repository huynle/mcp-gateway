// Package approvalstest provides an in-memory approvals.Store for tests
// in this and other packages (the portal, the pipeline).
package approvalstest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/huynle/mcp-gateway/internal/approvals"
	"github.com/huynle/mcp-gateway/internal/caps"
	"github.com/huynle/mcp-gateway/internal/store"
)

// MemStore is an in-memory approvals.Store that imitates row-level
// security: under AsUser only the scoped user's approvals are visible;
// under Bypass every row is. Accounts, when set, supplies the label and
// display name the real store joins from the connections table.
type MemStore struct {
	mu       sync.Mutex
	rows     map[string]*store.ApprovalRecord
	Accounts map[string][2]string // account id -> {label, display name}
}

// NewMemStore returns an empty store.
func NewMemStore() *MemStore {
	return &MemStore{rows: map[string]*store.ApprovalRecord{}, Accounts: map[string][2]string{}}
}

// Record returns a copy of the stored row (payload included) for
// assertions; nil when it does not exist.
func (m *MemStore) Record(id string) *store.ApprovalRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rows[id]
	if !ok {
		return nil
	}
	return m.copy(r)
}

// Count returns how many rows exist.
func (m *MemStore) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.rows)
}

func (m *MemStore) AsUser(_ context.Context, userID string, fn func(approvals.Tx) error) error {
	if userID == "" {
		return store.ErrInvalidUserID
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return fn(&memTx{m: m, user: userID})
}

func (m *MemStore) Bypass(_ context.Context, fn func(approvals.Tx) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return fn(&memTx{m: m})
}

func (m *MemStore) copy(r *store.ApprovalRecord) *store.ApprovalRecord {
	c := *r
	if r.Payload != nil {
		p := *r.Payload
		c.Payload = &p
	}
	if r.TokenID != nil {
		t := *r.TokenID
		c.TokenID = &t
	}
	c.Resource = bytes.Clone(r.Resource)
	if acct, ok := m.Accounts[r.ConnectionID]; ok {
		c.AccountLabel, c.AccountDisplayName = acct[0], acct[1]
	}
	return &c
}

// memTx holds the store lock for its lifetime; user is "" under Bypass.
type memTx struct {
	m    *MemStore
	user string
}

func (t *memTx) visible(r *store.ApprovalRecord) bool { return t.user == "" || r.UserID == t.user }

// ReservePendingApproval counts the user's pending, unexpired approvals
// like the PostgreSQL store.
func (t *memTx) ReservePendingApproval(ctx context.Context, l caps.Limiter, userID string, at time.Time) error {
	n := 0
	for _, r := range t.m.rows {
		if r.UserID == userID && r.Status == store.ApprovalPending && r.ExpiresAt.After(at) {
			n++
		}
	}
	return caps.Check(ctx, l, userID, caps.PendingApprovals, n)
}

func (t *memTx) CreateApproval(_ context.Context, a *store.ApprovalRecord) error {
	if a.ID == "" || a.Payload == nil {
		return errors.New("memstore: id and payload are required")
	}
	if !t.visible(a) {
		return fmt.Errorf("memstore: rls: new row violates policy for user %s", t.user)
	}
	if _, dup := t.m.rows[a.ID]; dup {
		return errors.New("memstore: duplicate id")
	}
	a.Status = store.ApprovalPending
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now()
	}
	if len(a.Resource) == 0 {
		a.Resource = []byte(`{}`)
	}
	if acct, ok := t.m.Accounts[a.ConnectionID]; !ok {
		t.m.Accounts[a.ConnectionID] = [2]string{a.AccountLabel, ""}
	} else {
		a.AccountLabel, a.AccountDisplayName = acct[0], acct[1]
	}
	t.m.rows[a.ID] = t.m.copy(a)
	return nil
}

func (t *memTx) GetApproval(_ context.Context, id string) (*store.ApprovalRecord, error) {
	r, ok := t.m.rows[id]
	if !ok || !t.visible(r) {
		return nil, store.ErrNotFound
	}
	return t.m.copy(r), nil
}

func (t *memTx) ListApprovals(_ context.Context, userID string, pendingOnly bool, limit int) ([]store.ApprovalRecord, error) {
	var out []store.ApprovalRecord
	for _, r := range t.m.rows {
		if r.UserID != userID || !t.visible(r) || (pendingOnly && r.Status != store.ApprovalPending) {
			continue
		}
		out = append(out, *t.m.copy(r))
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID > out[j].ID
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (t *memTx) DecideApproval(ctx context.Context, id, userID, status string, at time.Time) (*store.ApprovalRecord, error) {
	r, ok := t.m.rows[id]
	if !ok || !t.visible(r) || r.UserID != userID || r.Status != store.ApprovalPending || !r.ExpiresAt.After(at) {
		return nil, store.ErrNotFound
	}
	switch status {
	case store.ApprovalApproved:
		r.Status = store.ApprovalApproved
	case store.ApprovalDenied:
		r.Status = store.ApprovalDenied
		r.Payload = nil
	default:
		return nil, fmt.Errorf("memstore: status %q is not a decision", status)
	}
	decided := at
	r.DecidedAt = &decided
	return t.GetApproval(ctx, id)
}

func (t *memTx) ConsumeApproval(_ context.Context, id string, b store.ApprovalBinding, at time.Time) error {
	r, ok := t.m.rows[id]
	if !ok || !t.visible(r) || r.UserID != b.UserID || r.ConnectionID != b.ConnectionID || r.Tool != b.Tool || r.PolicyVersionID != b.PolicyVersionID ||
		r.Status != store.ApprovalApproved || r.ConsumedAt != nil || !r.ExpiresAt.After(at) {
		return store.ErrApprovalNotConsumable
	}
	consumed := at
	r.Status = store.ApprovalConsumed
	r.ConsumedAt = &consumed
	r.Payload = nil
	return nil
}

func (t *memTx) FindApprovedApproval(_ context.Context, b store.ApprovalBinding, digest []byte, at time.Time) (string, error) {
	var best *store.ApprovalRecord
	for _, r := range t.m.rows {
		if !t.visible(r) || r.UserID != b.UserID || r.ConnectionID != b.ConnectionID || r.Tool != b.Tool || r.PolicyVersionID != b.PolicyVersionID ||
			!bytes.Equal(r.Digest, digest) || r.Status != store.ApprovalApproved || r.ConsumedAt != nil || !r.ExpiresAt.After(at) {
			continue
		}
		if best == nil || (r.DecidedAt != nil && best.DecidedAt != nil && r.DecidedAt.After(*best.DecidedAt)) {
			best = r
		}
	}
	if best == nil {
		return "", store.ErrNotFound
	}
	return best.ID, nil
}

func (t *memTx) ExpireApprovals(_ context.Context, at time.Time) (int64, error) {
	var n int64
	for _, r := range t.m.rows {
		if !t.visible(r) {
			continue
		}
		if (r.Status == store.ApprovalPending || r.Status == store.ApprovalApproved) && !r.ExpiresAt.After(at) {
			r.Status = store.ApprovalExpired
			r.Payload = nil
			n++
		}
	}
	return n, nil
}
