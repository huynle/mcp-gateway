package tokens

import (
	"context"
	"time"

	"github.com/huynle/mcp-gateway/internal/store"
)

// Store is the persistence the token service needs. The production
// implementation (NewPostgresStore) runs Bypass through store.WithJobs and
// AsUser through store.WithUser; unit tests use an in-memory fake.
type Store interface {
	// Bypass runs fn in one transaction that sees every row. Authentication
	// uses it for the one narrow lookup that precedes user resolution
	// (token by public id; decision 9z5sdzsm point 3) and the disable hook
	// for revoking a user's tokens.
	Bypass(ctx context.Context, fn func(Tx) error) error
	// AsUser runs fn scoped to userID: row-level security hides everyone
	// else's tokens. Create, List and Revoke are self-service and use it.
	AsUser(ctx context.Context, userID string, fn func(Tx) error) error
}

// Tx is the set of persistence operations the service performs inside one
// transaction; methods map onto store.TokenRepository and the helpers in
// store/repo_tokens_lookup.go.
type Tx interface {
	CreateToken(ctx context.Context, t *store.Token) error
	FindTokenByPublicID(ctx context.Context, publicID string) (*store.TokenLookup, error)
	TouchToken(ctx context.Context, id string, at time.Time) error
	ListTokensForUser(ctx context.Context, userID string) ([]store.Token, error)
	// RevokeToken returns the token's effective revocation time: at, or
	// the earlier time it was already revoked.
	RevokeToken(ctx context.Context, id string, at time.Time) (time.Time, error)
	RevokeUserTokens(ctx context.Context, userID string, at time.Time) (int64, error)
}

// postgresStore adapts *store.Store to Store.
type postgresStore struct{ st *store.Store }

// NewPostgresStore returns the production Store over the PostgreSQL store.
func NewPostgresStore(st *store.Store) Store { return postgresStore{st: st} }

func (p postgresStore) Bypass(ctx context.Context, fn func(Tx) error) error {
	return p.st.WithJobs(ctx, func(tx store.Tx) error { return fn(pgTx{tx}) })
}

func (p postgresStore) AsUser(ctx context.Context, userID string, fn func(Tx) error) error {
	return p.st.WithUser(ctx, userID, func(tx store.Tx) error { return fn(pgTx{tx}) })
}

// pgTx implements Tx over a store transaction. It is also what the disable
// hook wraps around the identity service's transaction.
type pgTx struct{ tx store.Tx }

func (t pgTx) CreateToken(ctx context.Context, tok *store.Token) error {
	return t.tx.Tokens().Create(ctx, tok)
}

func (t pgTx) FindTokenByPublicID(ctx context.Context, publicID string) (*store.TokenLookup, error) {
	return store.FindTokenByPublicID(ctx, t.tx, publicID)
}

func (t pgTx) TouchToken(ctx context.Context, id string, at time.Time) error {
	return store.TouchToken(ctx, t.tx, id, at)
}

func (t pgTx) ListTokensForUser(ctx context.Context, userID string) ([]store.Token, error) {
	return store.ListTokensForUser(ctx, t.tx, userID)
}

func (t pgTx) RevokeToken(ctx context.Context, id string, at time.Time) (time.Time, error) {
	return store.RevokeToken(ctx, t.tx, id, at)
}

func (t pgTx) RevokeUserTokens(ctx context.Context, userID string, at time.Time) (int64, error) {
	return store.RevokeUserTokens(ctx, t.tx, userID, at)
}
