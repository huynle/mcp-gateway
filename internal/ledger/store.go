package ledger

import (
	"context"
	"time"

	"github.com/huynle/mcp-gateway/internal/store"
)

// Store is the persistence the service needs. NewPostgresStore is the
// production implementation (AsUser through store.WithUser, Bypass
// through store.WithJobs); ledgertest.MemStore is the in-memory one.
type Store interface {
	// AsUser runs fn in one transaction scoped to userID: row-level
	// security hides everyone else's operations. Begin, Finish and the
	// portal page use it. The transaction rolls back when fn errs.
	AsUser(ctx context.Context, userID string, fn func(Tx) error) error
	// Bypass runs fn across all users; the reconciler, the stale sweep
	// and the shutdown hook use it.
	Bypass(ctx context.Context, fn func(Tx) error) error
}

// Tx is the set of persistence operations the service performs inside one
// transaction; methods map onto the helpers in store/repo_ledger_ops.go.
// StoreTx exposes the underlying store transaction (nil outside
// PostgreSQL) so the approvals service can consume an approval in the
// same transaction as the in_progress insert (decision dovthftx).
type Tx interface {
	LockKey(ctx context.Context, key string) error
	LatestByKey(ctx context.Context, key string, since time.Time) (*store.LedgerOperation, error)
	Create(ctx context.Context, op *store.LedgerOperation) error
	Get(ctx context.Context, id string) (*store.LedgerOperation, error)
	Transition(ctx context.Context, id string, from []string, t store.LedgerTransition) (bool, error)
	CreateAttempt(ctx context.Context, a *store.LedgerAttempt) error
	List(ctx context.Context, f store.LedgerFilter) ([]store.LedgerOperation, error)
	SweepStale(ctx context.Context, before, at time.Time) ([]store.LedgerOperation, error)
	StoreTx() store.Tx
}

// postgresStore adapts *store.Store to Store.
type postgresStore struct{ st *store.Store }

// NewPostgresStore returns the production Store over the PostgreSQL store.
func NewPostgresStore(st *store.Store) Store { return postgresStore{st: st} }

func (p postgresStore) AsUser(ctx context.Context, userID string, fn func(Tx) error) error {
	return p.st.WithUser(ctx, userID, func(tx store.Tx) error { return fn(pgTx{tx}) })
}

func (p postgresStore) Bypass(ctx context.Context, fn func(Tx) error) error {
	return p.st.WithJobs(ctx, func(tx store.Tx) error { return fn(pgTx{tx}) })
}

// pgTx implements Tx over a store transaction.
type pgTx struct{ tx store.Tx }

func (t pgTx) LockKey(ctx context.Context, key string) error {
	return store.LockLedgerKey(ctx, t.tx, key)
}

func (t pgTx) LatestByKey(ctx context.Context, key string, since time.Time) (*store.LedgerOperation, error) {
	return store.LatestLedgerOperationByKey(ctx, t.tx, key, since)
}

func (t pgTx) Create(ctx context.Context, op *store.LedgerOperation) error {
	return store.CreateLedgerOperation(ctx, t.tx, op)
}

func (t pgTx) Get(ctx context.Context, id string) (*store.LedgerOperation, error) {
	return store.GetLedgerOperation(ctx, t.tx, id)
}

func (t pgTx) Transition(ctx context.Context, id string, from []string, tr store.LedgerTransition) (bool, error) {
	return store.TransitionLedgerOperation(ctx, t.tx, id, from, tr)
}

func (t pgTx) CreateAttempt(ctx context.Context, a *store.LedgerAttempt) error {
	return store.CreateLedgerAttempt(ctx, t.tx, a)
}

func (t pgTx) List(ctx context.Context, f store.LedgerFilter) ([]store.LedgerOperation, error) {
	return store.ListLedgerOperations(ctx, t.tx, f)
}

func (t pgTx) SweepStale(ctx context.Context, before, at time.Time) ([]store.LedgerOperation, error) {
	return store.SweepStaleLedgerOperations(ctx, t.tx, before, at)
}

func (t pgTx) StoreTx() store.Tx { return t.tx }
