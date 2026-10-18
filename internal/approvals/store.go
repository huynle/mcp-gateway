package approvals

import (
	"context"
	"time"

	"github.com/huynle/mcp-gateway/internal/caps"
	"github.com/huynle/mcp-gateway/internal/store"
)

// Store is the persistence the service needs. NewPostgresStore is the
// production implementation (AsUser through store.WithUser, Bypass
// through store.WithJobs); approvalstest.MemStore is the in-memory one.
type Store interface {
	// AsUser runs fn scoped to userID: row-level security hides everyone
	// else's approvals. Every user-facing operation uses it.
	AsUser(ctx context.Context, userID string, fn func(Tx) error) error
	// Bypass runs fn across all users; only the expiry job uses it.
	Bypass(ctx context.Context, fn func(Tx) error) error
}

// Tx is the set of persistence operations the service performs inside one
// transaction; methods map onto the helpers in store/repo_approvals.go.
// Consume takes a Tx so the ledger can run it in the same transaction as
// its in_progress insert (decision dovthftx); FromStoreTx adapts a
// store.Tx for that.
type Tx interface {
	CreateApproval(ctx context.Context, a *store.ApprovalRecord) error
	// ReservePendingApproval is the cap check before CreateApproval: it
	// locks userID's approval budget until the transaction ends and
	// refuses with *caps.ExceededError when the user already has the
	// cap's number of pending, unexpired approvals at at. nil l never
	// refuses.
	ReservePendingApproval(ctx context.Context, l caps.Limiter, userID string, at time.Time) error
	GetApproval(ctx context.Context, id string) (*store.ApprovalRecord, error)
	ListApprovals(ctx context.Context, userID string, pendingOnly bool, limit int) ([]store.ApprovalRecord, error)
	DecideApproval(ctx context.Context, id, userID, status string, at time.Time) (*store.ApprovalRecord, error)
	ConsumeApproval(ctx context.Context, id string, b store.ApprovalBinding, at time.Time) error
	FindApprovedApproval(ctx context.Context, b store.ApprovalBinding, digest []byte, at time.Time) (string, error)
	ExpireApprovals(ctx context.Context, at time.Time) (int64, error)
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

// FromStoreTx adapts a store transaction (one opened by store.WithUser for
// the calling user) to Tx, so another module can consume an approval
// inside its own transaction: svc.Consume(ctx, approvals.FromStoreTx(tx), b).
func FromStoreTx(tx store.Tx) Tx { return pgTx{tx} }

// pgTx implements Tx over a store transaction.
type pgTx struct{ tx store.Tx }

func (t pgTx) ReservePendingApproval(ctx context.Context, l caps.Limiter, userID string, _ time.Time) error {
	return caps.Reserve(ctx, t.tx, l, userID, caps.PendingApprovals)
}

func (t pgTx) CreateApproval(ctx context.Context, a *store.ApprovalRecord) error {
	return store.CreateApproval(ctx, t.tx, a)
}

func (t pgTx) GetApproval(ctx context.Context, id string) (*store.ApprovalRecord, error) {
	return store.GetApproval(ctx, t.tx, id)
}

func (t pgTx) ListApprovals(ctx context.Context, userID string, pendingOnly bool, limit int) ([]store.ApprovalRecord, error) {
	return store.ListApprovals(ctx, t.tx, userID, pendingOnly, limit)
}

func (t pgTx) DecideApproval(ctx context.Context, id, userID, status string, at time.Time) (*store.ApprovalRecord, error) {
	return store.DecideApproval(ctx, t.tx, id, userID, status, at)
}

func (t pgTx) ConsumeApproval(ctx context.Context, id string, b store.ApprovalBinding, at time.Time) error {
	return store.ConsumeApproval(ctx, t.tx, id, b, at)
}

func (t pgTx) FindApprovedApproval(ctx context.Context, b store.ApprovalBinding, digest []byte, at time.Time) (string, error) {
	return store.FindApprovedApproval(ctx, t.tx, b, digest, at)
}

func (t pgTx) ExpireApprovals(ctx context.Context, at time.Time) (int64, error) {
	return store.ExpireApprovals(ctx, t.tx, at)
}
