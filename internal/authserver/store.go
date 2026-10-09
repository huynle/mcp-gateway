package authserver

import (
	"context"
	"time"

	"github.com/huynle/mcp-gateway/internal/store"
)

// Store is the persistence the authorization server needs. The production
// implementation (NewPostgresStore) runs Bypass through store.WithJobs and
// AsUser through store.WithUser; unit tests use authservertest.MemStore.
type Store interface {
	// Bypass runs fn in one transaction that sees every row: client
	// registration and lookup, the token endpoint (no user is known until
	// the code or refresh token is), the JWT authenticator's owner check,
	// signing keys, the disable hook and the pruning job.
	Bypass(ctx context.Context, fn func(Tx) error) error
	// AsUser runs fn scoped to userID: consent (the code is the user's) and
	// the connected-harnesses page, where row-level security hides
	// everyone else's refresh tokens.
	AsUser(ctx context.Context, userID string, fn func(Tx) error) error
}

// Tx is the set of persistence operations the server performs inside one
// transaction; methods map onto the helpers in store/repo_oauth_lookup.go.
type Tx interface {
	CreateClient(ctx context.Context, c *store.OAuthClient) error
	FindClientByClientID(ctx context.Context, clientID string) (*store.OAuthClient, error)
	TouchClient(ctx context.Context, id string, at time.Time) error
	CountUnusedClients(ctx context.Context) (int64, error)
	PruneClients(ctx context.Context, idleBefore time.Time) (int64, error)

	CreateCode(ctx context.Context, c *store.OAuthCode) error
	// ConsumeCode marks the code consumed and returns it with consumed =
	// true; a code that was already consumed comes back with consumed =
	// false (replay); an unknown hash is store.ErrNotFound.
	ConsumeCode(ctx context.Context, codeHash []byte, at time.Time) (code *store.OAuthCode, consumed bool, err error)
	SetCodeFamily(ctx context.Context, id, familyID string) error
	DeleteExpiredCodes(ctx context.Context, before time.Time) (int64, error)

	CreateRefreshToken(ctx context.Context, t *store.OAuthRefreshToken) error
	FindRefreshTokenByHash(ctx context.Context, hash []byte) (*store.RefreshTokenLookup, error)
	// RotateRefreshToken marks the token exchanged for its successor and
	// reports false when it had already been rotated (a concurrent
	// exchange won; the caller treats that as reuse).
	RotateRefreshToken(ctx context.Context, id string, at time.Time) (bool, error)
	TouchRefreshToken(ctx context.Context, id string, at time.Time) error
	RevokeRefreshFamily(ctx context.Context, familyID string, at time.Time) (int64, error)
	RevokeUserRefreshTokens(ctx context.Context, userID string, at time.Time) (int64, error)
	ListHarnesses(ctx context.Context, userID string) ([]store.Harness, error)

	FindUserAuthFacts(ctx context.Context, userID string) (*store.UserAuthFacts, error)

	ListSigningKeys(ctx context.Context) ([]store.SigningKey, error)
	CreateSigningKey(ctx context.Context, k *store.SigningKey) error
	RetireSigningKeys(ctx context.Context, keepKID string, at time.Time) (int64, error)
	DeleteRetiredSigningKeys(ctx context.Context, retiredBefore time.Time) (int64, error)
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

// pgTx implements Tx over a store transaction. The disable hook wraps it
// around the identity service's transaction.
type pgTx struct{ tx store.Tx }

func (t pgTx) CreateClient(ctx context.Context, c *store.OAuthClient) error {
	return t.tx.OAuth().CreateClient(ctx, c)
}

func (t pgTx) FindClientByClientID(ctx context.Context, clientID string) (*store.OAuthClient, error) {
	return store.FindOAuthClientByClientID(ctx, t.tx, clientID)
}

func (t pgTx) TouchClient(ctx context.Context, id string, at time.Time) error {
	return store.TouchOAuthClient(ctx, t.tx, id, at)
}

func (t pgTx) CountUnusedClients(ctx context.Context) (int64, error) {
	return store.CountUnusedOAuthClients(ctx, t.tx)
}

func (t pgTx) PruneClients(ctx context.Context, idleBefore time.Time) (int64, error) {
	return store.PruneOAuthClients(ctx, t.tx, idleBefore)
}

func (t pgTx) CreateCode(ctx context.Context, c *store.OAuthCode) error {
	return store.CreateOAuthCode(ctx, t.tx, c)
}

func (t pgTx) ConsumeCode(ctx context.Context, codeHash []byte, at time.Time) (*store.OAuthCode, bool, error) {
	return store.ConsumeOAuthCode(ctx, t.tx, codeHash, at)
}

func (t pgTx) SetCodeFamily(ctx context.Context, id, familyID string) error {
	return store.SetOAuthCodeFamily(ctx, t.tx, id, familyID)
}

func (t pgTx) DeleteExpiredCodes(ctx context.Context, before time.Time) (int64, error) {
	return store.DeleteExpiredOAuthCodes(ctx, t.tx, before)
}

func (t pgTx) CreateRefreshToken(ctx context.Context, r *store.OAuthRefreshToken) error {
	return store.CreateOAuthRefreshToken(ctx, t.tx, r)
}

func (t pgTx) FindRefreshTokenByHash(ctx context.Context, hash []byte) (*store.RefreshTokenLookup, error) {
	return store.FindOAuthRefreshTokenByHash(ctx, t.tx, hash)
}

func (t pgTx) RotateRefreshToken(ctx context.Context, id string, at time.Time) (bool, error) {
	return store.RotateOAuthRefreshToken(ctx, t.tx, id, at)
}

func (t pgTx) TouchRefreshToken(ctx context.Context, id string, at time.Time) error {
	return store.TouchOAuthRefreshToken(ctx, t.tx, id, at)
}

func (t pgTx) RevokeRefreshFamily(ctx context.Context, familyID string, at time.Time) (int64, error) {
	return store.RevokeOAuthRefreshFamily(ctx, t.tx, familyID, at)
}

func (t pgTx) RevokeUserRefreshTokens(ctx context.Context, userID string, at time.Time) (int64, error) {
	return store.RevokeUserOAuthRefreshTokens(ctx, t.tx, userID, at)
}

func (t pgTx) ListHarnesses(ctx context.Context, userID string) ([]store.Harness, error) {
	return store.ListOAuthHarnesses(ctx, t.tx, userID)
}

func (t pgTx) FindUserAuthFacts(ctx context.Context, userID string) (*store.UserAuthFacts, error) {
	return store.FindUserAuthFacts(ctx, t.tx, userID)
}

func (t pgTx) ListSigningKeys(ctx context.Context) ([]store.SigningKey, error) {
	return store.ListSigningKeys(ctx, t.tx)
}

func (t pgTx) CreateSigningKey(ctx context.Context, k *store.SigningKey) error {
	return t.tx.SigningKeys().Create(ctx, k)
}

func (t pgTx) RetireSigningKeys(ctx context.Context, keepKID string, at time.Time) (int64, error) {
	return store.RetireSigningKeys(ctx, t.tx, keepKID, at)
}

func (t pgTx) DeleteRetiredSigningKeys(ctx context.Context, retiredBefore time.Time) (int64, error) {
	return store.DeleteRetiredSigningKeys(ctx, t.tx, retiredBefore)
}
