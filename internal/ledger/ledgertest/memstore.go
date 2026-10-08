// Package ledgertest provides an in-memory ledger.Store for tests in this
// and other packages (the pipeline stage, the jobs).
package ledgertest

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/huynle/mcp-gateway/internal/ledger"
	"github.com/huynle/mcp-gateway/internal/store"
)

// MemStore is an in-memory ledger.Store that imitates row-level security
// (under AsUser only the scoped user's rows are visible; under Bypass
// every row is) and transactions (a callback that errs leaves the store
// as it was). One mutex serialises transactions, which also stands in
// for the per-key lock.
type MemStore struct {
	mu        sync.Mutex
	ops       map[string]*store.LedgerOperation
	attempts  map[string][]store.LedgerAttempt
	rollbacks int
	failNext  error
}

// NewMemStore returns an empty store.
func NewMemStore() *MemStore {
	return &MemStore{ops: map[string]*store.LedgerOperation{}, attempts: map[string][]store.LedgerAttempt{}}
}

// Operation returns a copy of the stored row; nil when it does not exist.
func (m *MemStore) Operation(id string) *store.LedgerOperation {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.ops[id]
	if !ok {
		return nil
	}
	return copyOp(r)
}

// Attempts returns the operation's attempts in insertion order.
func (m *MemStore) Attempts(id string) []store.LedgerAttempt {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.attempts[id])
}

// Count returns how many operations exist.
func (m *MemStore) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.ops)
}

// Rollbacks returns how many transactions were rolled back.
func (m *MemStore) Rollbacks() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rollbacks
}

// SetState rewrites an operation's state directly (what the reconciler
// would do, without running it).
func (m *MemStore) SetState(id, state string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.ops[id]; ok {
		r.State = state
	}
}

// SetCreatedAt backdates an operation (to simulate a replica that died
// mid-call).
func (m *MemStore) SetCreatedAt(id string, at time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.ops[id]; ok {
		r.CreatedAt, r.UpdatedAt = at, at
	}
}

// FailNextCreate makes the next Create return err (and the transaction
// roll back).
func (m *MemStore) FailNextCreate(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failNext = err
}

func (m *MemStore) AsUser(ctx context.Context, userID string, fn func(ledger.Tx) error) error {
	if userID == "" {
		return store.ErrInvalidUserID
	}
	return m.run(ctx, userID, fn)
}

func (m *MemStore) Bypass(ctx context.Context, fn func(ledger.Tx) error) error {
	return m.run(ctx, "", fn)
}

func (m *MemStore) run(_ context.Context, userID string, fn func(ledger.Tx) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	snapshotOps := make(map[string]*store.LedgerOperation, len(m.ops))
	for k, v := range m.ops {
		snapshotOps[k] = copyOp(v)
	}
	snapshotAtts := make(map[string][]store.LedgerAttempt, len(m.attempts))
	for k, v := range m.attempts {
		snapshotAtts[k] = slices.Clone(v)
	}
	if err := fn(&memTx{m: m, user: userID}); err != nil {
		m.ops, m.attempts = snapshotOps, snapshotAtts
		m.rollbacks++
		return err
	}
	return nil
}

func copyOp(r *store.LedgerOperation) *store.LedgerOperation {
	c := *r
	c.Digest = bytes.Clone(r.Digest)
	c.ResultIDs = bytes.Clone(r.ResultIDs)
	c.Resource = bytes.Clone(r.Resource)
	if r.ApprovalID != nil {
		v := *r.ApprovalID
		c.ApprovalID = &v
	}
	if r.TokenID != nil {
		v := *r.TokenID
		c.TokenID = &v
	}
	if r.ErrorCode != nil {
		v := *r.ErrorCode
		c.ErrorCode = &v
	}
	if r.FinishedAt != nil {
		v := *r.FinishedAt
		c.FinishedAt = &v
	}
	return &c
}

// memTx implements ledger.Tx.
type memTx struct {
	m    *MemStore
	user string
}

func (t *memTx) visible(r *store.LedgerOperation) bool { return t.user == "" || r.UserID == t.user }

func (t *memTx) LockKey(context.Context, string) error { return nil }

func (t *memTx) LatestByKey(_ context.Context, key string, since time.Time) (*store.LedgerOperation, error) {
	var best *store.LedgerOperation
	for _, r := range t.m.ops {
		if !t.visible(r) || r.IdempotencyKey != key || r.CreatedAt.Before(since) {
			continue
		}
		if best == nil || r.CreatedAt.After(best.CreatedAt) {
			best = r
		}
	}
	if best == nil {
		return nil, store.ErrNotFound
	}
	return copyOp(best), nil
}

func (t *memTx) Create(_ context.Context, op *store.LedgerOperation) error {
	if t.m.failNext != nil {
		err := t.m.failNext
		t.m.failNext = nil
		return err
	}
	if t.user != "" && op.UserID != t.user {
		return fmt.Errorf("store: create ledger operation: row-level security violation")
	}
	for _, r := range t.m.ops {
		if r.IdempotencyKey == op.IdempotencyKey && (r.State == store.LedgerInProgress || r.State == store.LedgerUnknown) {
			return store.ErrLedgerKeyOpen
		}
	}
	op.ID = newID()
	if op.State == "" {
		op.State = store.LedgerInProgress
	}
	if len(op.ResultIDs) == 0 {
		op.ResultIDs = []byte(`{}`)
	}
	if len(op.Resource) == 0 {
		op.Resource = []byte(`{}`)
	}
	now := time.Now().UTC()
	if op.CreatedAt.IsZero() {
		op.CreatedAt = now
	}
	if op.UpdatedAt.IsZero() {
		op.UpdatedAt = op.CreatedAt
	}
	t.m.ops[op.ID] = copyOp(op)
	return nil
}

func (t *memTx) Get(_ context.Context, id string) (*store.LedgerOperation, error) {
	r, ok := t.m.ops[id]
	if !ok || !t.visible(r) {
		return nil, store.ErrNotFound
	}
	return copyOp(r), nil
}

func (t *memTx) Transition(_ context.Context, id string, from []string, tr store.LedgerTransition) (bool, error) {
	r, ok := t.m.ops[id]
	if !ok || !t.visible(r) || !slices.Contains(from, r.State) {
		return false, nil
	}
	r.State = tr.State
	r.UpdatedAt = tr.At
	if tr.ResultIDs != nil {
		r.ResultIDs = bytes.Clone(tr.ResultIDs)
	}
	if tr.ErrorCode != nil {
		v := *tr.ErrorCode
		r.ErrorCode = &v
	}
	if tr.ReconcileAttempts != nil {
		r.ReconcileAttempts = *tr.ReconcileAttempts
	}
	if tr.Finished {
		at := tr.At
		r.FinishedAt = &at
	}
	return true, nil
}

func (t *memTx) CreateAttempt(_ context.Context, a *store.LedgerAttempt) error {
	r, ok := t.m.ops[a.OperationID]
	if !ok || !t.visible(r) || r.UserID != a.UserID {
		return fmt.Errorf("store: create ledger attempt: foreign key violation")
	}
	for _, existing := range t.m.attempts[a.OperationID] {
		if existing.Kind == a.Kind && existing.AttemptNo == a.AttemptNo {
			return fmt.Errorf("store: create ledger attempt: duplicate attempt")
		}
	}
	a.ID = newID()
	if a.StartedAt.IsZero() {
		a.StartedAt = time.Now().UTC()
	}
	t.m.attempts[a.OperationID] = append(t.m.attempts[a.OperationID], *a)
	return nil
}

func (t *memTx) List(_ context.Context, f store.LedgerFilter) ([]store.LedgerOperation, error) {
	var out []store.LedgerOperation
	for _, r := range t.m.ops {
		if !t.visible(r) {
			continue
		}
		if f.UserID != "" && r.UserID != f.UserID {
			continue
		}
		if len(f.States) > 0 && !slices.Contains(f.States, r.State) {
			continue
		}
		if !f.CreatedBefore.IsZero() && !r.CreatedAt.Before(f.CreatedBefore) {
			continue
		}
		if !f.UpdatedBefore.IsZero() && !r.UpdatedAt.Before(f.UpdatedBefore) {
			continue
		}
		out = append(out, *copyOp(r))
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID > out[j].ID
	})
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (t *memTx) SweepStale(_ context.Context, before, at time.Time) ([]store.LedgerOperation, error) {
	var out []store.LedgerOperation
	for _, r := range t.m.ops {
		if !t.visible(r) || r.State != store.LedgerInProgress || !r.CreatedAt.Before(before) {
			continue
		}
		r.State = store.LedgerUnknown
		r.UpdatedAt = at
		out = append(out, *copyOp(r))
	}
	return out, nil
}

func (t *memTx) StoreTx() store.Tx { return nil }

func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
