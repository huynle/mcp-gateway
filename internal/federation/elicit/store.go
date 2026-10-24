package elicit

import (
	"context"
	"time"

	"github.com/huynle/mcp-gateway/internal/store"
)

// Store is the persistence the service needs. NewPostgresStore is the
// production implementation (AsUser through store.WithUser, Bypass through
// store.WithJobs).
type Store interface {
	// AsUser runs fn scoped to userID: row-level security hides everyone
	// else's elicitations. Every user-facing operation uses it.
	AsUser(ctx context.Context, userID string, fn func(Tx) error) error
	// Bypass runs fn across all users: the expiry job.
	Bypass(ctx context.Context, fn func(Tx) error) error
}

// Tx is the set of persistence operations the service performs inside
// one transaction; methods map onto store/repo_elicitations.go.
type Tx interface {
	Lock(ctx context.Context, ownerID string) error
	CountLive(ctx context.Context, ownerID string, at time.Time) (int, error)
	Create(ctx context.Context, e *store.UpstreamElicitation) error
	GetByLink(ctx context.Context, ownerID string, linkHash []byte, at time.Time) (*store.UpstreamElicitation, error)
	MarkOpened(ctx context.Context, ownerID string, linkHash []byte, at time.Time) (*store.UpstreamElicitation, error)
	MarkCancelled(ctx context.Context, ownerID string, linkHash []byte, at time.Time) (*store.UpstreamElicitation, error)
	PurgeExpired(ctx context.Context, before time.Time) (int64, error)
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

func (t pgTx) Lock(ctx context.Context, ownerID string) error {
	return store.LockUpstreamElicitations(ctx, t.tx, ownerID)
}

func (t pgTx) CountLive(ctx context.Context, ownerID string, at time.Time) (int, error) {
	return store.CountLiveUpstreamElicitations(ctx, t.tx, ownerID, at)
}

func (t pgTx) Create(ctx context.Context, e *store.UpstreamElicitation) error {
	return store.CreateUpstreamElicitation(ctx, t.tx, e)
}

func (t pgTx) GetByLink(ctx context.Context, ownerID string, h []byte, at time.Time) (*store.UpstreamElicitation, error) {
	return store.GetUpstreamElicitationByLink(ctx, t.tx, ownerID, h, at)
}

func (t pgTx) MarkOpened(ctx context.Context, ownerID string, h []byte, at time.Time) (*store.UpstreamElicitation, error) {
	return store.MarkUpstreamElicitationOpened(ctx, t.tx, ownerID, h, at)
}

func (t pgTx) MarkCancelled(ctx context.Context, ownerID string, h []byte, at time.Time) (*store.UpstreamElicitation, error) {
	return store.MarkUpstreamElicitationCancelled(ctx, t.tx, ownerID, h, at)
}

func (t pgTx) PurgeExpired(ctx context.Context, before time.Time) (int64, error) {
	return store.PurgeExpiredUpstreamElicitations(ctx, t.tx, before)
}
