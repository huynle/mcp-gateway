package secrets

import (
	"context"
	"time"

	"github.com/huynle/mcp-gateway/internal/store"
)

// Store is the persistence the service needs. NewPostgresStore is the
// production implementation (AsUser through store.WithUser, Bypass through
// store.WithJobs); secretstest.MemStore is the in-memory one.
type Store interface {
	// AsUser runs fn scoped to userID: row-level security hides everyone
	// else's secrets. Every user-facing operation uses it.
	AsUser(ctx context.Context, userID string, fn func(Tx) error) error
	// Bypass runs fn across all users: the expiry job and the disable hook
	// on a non-PostgreSQL identity store.
	Bypass(ctx context.Context, fn func(Tx) error) error
}

// Tx is the set of persistence operations the service performs inside one
// transaction; methods map onto the helpers in store/repo_secrets.go.
type Tx interface {
	LockRequests(ctx context.Context, ownerID string) error
	CountRequests(ctx context.Context, ownerID string, since, at time.Time) (pending, recent int, err error)
	CreateSecret(ctx context.Context, s *store.Secret) error
	GetSecret(ctx context.Context, id string) (*store.Secret, error)
	GetSecretByRequestHash(ctx context.Context, h []byte) (*store.Secret, error)
	GetSecretByHandleHash(ctx context.Context, h []byte) (*store.Secret, error)
	ListSecrets(ctx context.Context, ownerID string) ([]store.Secret, error)
	ProvideSecret(ctx context.Context, id string, requestHash []byte, value store.Encrypted, at time.Time) (*store.Secret, error)
	DenySecret(ctx context.Context, requestHash []byte, at time.Time) (*store.Secret, error)
	RevokeSecret(ctx context.Context, id string, at time.Time) (*store.Secret, error)
	ConsumeSecret(ctx context.Context, handleHash []byte, ownerID, harnessID string, b store.SecretBinding, at time.Time) (*store.Secret, error)
	RefundSecret(ctx context.Context, id string, at time.Time) error
	ExpireSecrets(ctx context.Context, at time.Time, retention time.Duration) (store.SecretExpiry, error)
	RevokeUserSecrets(ctx context.Context, ownerID string, at time.Time) (int64, error)
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

// FromStoreTx adapts a store transaction to Tx, so another module can run
// secret operations inside its own transaction.
func FromStoreTx(tx store.Tx) Tx { return pgTx{tx} }

// pgTx implements Tx over a store transaction.
type pgTx struct{ tx store.Tx }

func (t pgTx) LockRequests(ctx context.Context, ownerID string) error {
	return store.LockSecretRequests(ctx, t.tx, ownerID)
}

func (t pgTx) CountRequests(ctx context.Context, ownerID string, since, at time.Time) (int, int, error) {
	return store.CountSecretRequests(ctx, t.tx, ownerID, since, at)
}

func (t pgTx) CreateSecret(ctx context.Context, s *store.Secret) error {
	return store.CreateSecret(ctx, t.tx, s)
}

func (t pgTx) GetSecret(ctx context.Context, id string) (*store.Secret, error) {
	return store.GetSecret(ctx, t.tx, id)
}

func (t pgTx) GetSecretByRequestHash(ctx context.Context, h []byte) (*store.Secret, error) {
	return store.GetSecretByRequestHash(ctx, t.tx, h)
}

func (t pgTx) GetSecretByHandleHash(ctx context.Context, h []byte) (*store.Secret, error) {
	return store.GetSecretByHandleHash(ctx, t.tx, h)
}

func (t pgTx) ListSecrets(ctx context.Context, ownerID string) ([]store.Secret, error) {
	return store.ListSecrets(ctx, t.tx, ownerID)
}

func (t pgTx) ProvideSecret(ctx context.Context, id string, requestHash []byte, value store.Encrypted, at time.Time) (*store.Secret, error) {
	return store.ProvideSecret(ctx, t.tx, id, requestHash, value, at)
}

func (t pgTx) DenySecret(ctx context.Context, requestHash []byte, at time.Time) (*store.Secret, error) {
	return store.DenySecret(ctx, t.tx, requestHash, at)
}

func (t pgTx) RevokeSecret(ctx context.Context, id string, at time.Time) (*store.Secret, error) {
	return store.RevokeSecret(ctx, t.tx, id, at)
}

func (t pgTx) ConsumeSecret(ctx context.Context, handleHash []byte, ownerID, harnessID string, b store.SecretBinding, at time.Time) (*store.Secret, error) {
	return store.ConsumeSecret(ctx, t.tx, handleHash, ownerID, harnessID, b, at)
}

func (t pgTx) RefundSecret(ctx context.Context, id string, at time.Time) error {
	return store.RefundSecret(ctx, t.tx, id, at)
}

func (t pgTx) ExpireSecrets(ctx context.Context, at time.Time, retention time.Duration) (store.SecretExpiry, error) {
	return store.ExpireSecrets(ctx, t.tx, at, retention)
}

func (t pgTx) RevokeUserSecrets(ctx context.Context, ownerID string, at time.Time) (int64, error) {
	return store.RevokeUserSecrets(ctx, t.tx, ownerID, at)
}
