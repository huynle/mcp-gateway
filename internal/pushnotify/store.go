package pushnotify

import (
	"context"
	"time"

	"github.com/huynle/mcp-gateway/internal/store"
)

// Store is the persistence the service needs. NewPostgresStore is the
// production implementation (AsUser through store.WithUser, Bypass
// through store.WithJobs).
type Store interface {
	// AsUser runs fn scoped to userID: row-level security hides every
	// other user's subscriptions. Every user-facing operation and the
	// notifier use it.
	AsUser(ctx context.Context, userID string, fn func(Tx) error) error
	// Bypass runs fn across all users: the VAPID key (a system row, read
	// and created like the OAuth signing keys), the endpoint handover and
	// the disable hook on a non-PostgreSQL identity store.
	Bypass(ctx context.Context, fn func(Tx) error) error
}

// Tx is the set of persistence operations the service performs inside one
// transaction; methods map onto the helpers in store/repo_push.go.
type Tx interface {
	GetKey(ctx context.Context) (*store.WebPushKey, error)
	CreateKey(ctx context.Context, k *store.WebPushKey) (bool, error)
	Lock(ctx context.Context, userID string) error
	Count(ctx context.Context, userID string) (int, error)
	GetByHash(ctx context.Context, h []byte) (*store.PushSubscription, error)
	Create(ctx context.Context, s *store.PushSubscription) error
	Update(ctx context.Context, s *store.PushSubscription) error
	List(ctx context.Context, userID string) ([]store.PushSubscription, error)
	Delete(ctx context.Context, id string) (bool, error)
	DeleteByHash(ctx context.Context, h []byte) (bool, error)
	Release(ctx context.Context, h []byte, newOwner string) (int64, error)
	RecordDelivery(ctx context.Context, id string, ok bool, at time.Time) error
	DeleteUser(ctx context.Context, userID string) (int64, error)
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

func (t pgTx) GetKey(ctx context.Context) (*store.WebPushKey, error) {
	return store.GetWebPushKey(ctx, t.tx)
}

func (t pgTx) CreateKey(ctx context.Context, k *store.WebPushKey) (bool, error) {
	return store.CreateWebPushKey(ctx, t.tx, k)
}

func (t pgTx) Lock(ctx context.Context, userID string) error {
	return store.LockPushSubscriptions(ctx, t.tx, userID)
}

func (t pgTx) Count(ctx context.Context, userID string) (int, error) {
	return store.CountPushSubscriptions(ctx, t.tx, userID)
}

func (t pgTx) GetByHash(ctx context.Context, h []byte) (*store.PushSubscription, error) {
	return store.GetPushSubscriptionByHash(ctx, t.tx, h)
}

func (t pgTx) Create(ctx context.Context, s *store.PushSubscription) error {
	return store.CreatePushSubscription(ctx, t.tx, s)
}

func (t pgTx) Update(ctx context.Context, s *store.PushSubscription) error {
	return store.UpdatePushSubscription(ctx, t.tx, s)
}

func (t pgTx) List(ctx context.Context, userID string) ([]store.PushSubscription, error) {
	return store.ListPushSubscriptions(ctx, t.tx, userID)
}

func (t pgTx) Delete(ctx context.Context, id string) (bool, error) {
	return store.DeletePushSubscription(ctx, t.tx, id)
}

func (t pgTx) DeleteByHash(ctx context.Context, h []byte) (bool, error) {
	return store.DeletePushSubscriptionByHash(ctx, t.tx, h)
}

func (t pgTx) Release(ctx context.Context, h []byte, newOwner string) (int64, error) {
	return store.ReleasePushEndpoint(ctx, t.tx, h, newOwner)
}

func (t pgTx) RecordDelivery(ctx context.Context, id string, ok bool, at time.Time) error {
	return store.RecordPushDelivery(ctx, t.tx, id, ok, at)
}

func (t pgTx) DeleteUser(ctx context.Context, userID string) (int64, error) {
	return store.DeleteUserPushSubscriptions(ctx, t.tx, userID)
}
