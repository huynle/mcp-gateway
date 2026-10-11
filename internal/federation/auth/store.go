package auth

import (
	"context"
	"time"

	"github.com/huynle/mcp-gateway/internal/store"
)

// Store is the persistence the auth service needs. The production
// implementation (NewPostgresStore) runs AsUser through store.WithUser
// (row-level security: the user's own connections, servers they can see,
// owner-only credential rows) and Bypass through store.WithJobs (reading
// and registering a server's OAuth client and shared secret for any user
// of a published server, decision 17iv8p3b).
type Store interface {
	AsUser(ctx context.Context, userID string, fn func(Tx) error) error
	Bypass(ctx context.Context, fn func(Tx) error) error
}

// Tx is one transaction's operations; methods map onto the store's
// repo_mcp_* helpers. A Tx must not be used after its callback returns,
// and callbacks must not open another transaction.
type Tx interface {
	GetServer(ctx context.Context, id string) (*store.MCPServer, error)

	GetOAuthClient(ctx context.Context, serverID string) (*store.MCPOAuthClient, error)
	UpsertOAuthClient(ctx context.Context, c *store.MCPOAuthClient) error

	GetSharedSecret(ctx context.Context, serverID string) (*store.MCPServerSharedSecret, error)
	SetSharedSecret(ctx context.Context, s *store.MCPServerSharedSecret) error

	GetUserConnection(ctx context.Context, serverID, userID string) (*store.MCPUserConnection, error)
	// LockUserConnection reads the connection under a row lock held until
	// the transaction ends (serialised refresh across replicas).
	LockUserConnection(ctx context.Context, serverID, userID string) (*store.MCPUserConnection, error)
	UpsertUserConnection(ctx context.Context, c *store.MCPUserConnection) error
	SetUserConnectionStatus(ctx context.Context, serverID, userID, status string) error
	TouchUserConnectionRefreshed(ctx context.Context, serverID, userID string, at time.Time) error
	DeleteUserConnection(ctx context.Context, serverID, userID string) (int64, error)
}

// NewPostgresStore returns the production Store over the PostgreSQL store.
func NewPostgresStore(st *store.Store) Store { return pgStore{st: st} }

type pgStore struct{ st *store.Store }

func (p pgStore) AsUser(ctx context.Context, userID string, fn func(Tx) error) error {
	return p.st.WithUser(ctx, userID, func(tx store.Tx) error { return fn(pgTx{tx}) })
}

func (p pgStore) Bypass(ctx context.Context, fn func(Tx) error) error {
	return p.st.WithJobs(ctx, func(tx store.Tx) error { return fn(pgTx{tx}) })
}

type pgTx struct{ q store.Querier }

func (t pgTx) GetServer(ctx context.Context, id string) (*store.MCPServer, error) {
	return store.GetMCPServer(ctx, t.q, id)
}

func (t pgTx) GetOAuthClient(ctx context.Context, serverID string) (*store.MCPOAuthClient, error) {
	return store.GetMCPOAuthClient(ctx, t.q, serverID)
}

func (t pgTx) UpsertOAuthClient(ctx context.Context, c *store.MCPOAuthClient) error {
	return store.UpsertMCPOAuthClient(ctx, t.q, c)
}

func (t pgTx) GetSharedSecret(ctx context.Context, serverID string) (*store.MCPServerSharedSecret, error) {
	return store.GetMCPServerSharedSecret(ctx, t.q, serverID)
}

func (t pgTx) SetSharedSecret(ctx context.Context, s *store.MCPServerSharedSecret) error {
	return store.SetMCPServerSharedSecret(ctx, t.q, s)
}

func (t pgTx) GetUserConnection(ctx context.Context, serverID, userID string) (*store.MCPUserConnection, error) {
	return store.GetMCPUserConnection(ctx, t.q, serverID, userID)
}

func (t pgTx) LockUserConnection(ctx context.Context, serverID, userID string) (*store.MCPUserConnection, error) {
	return store.LockMCPUserConnection(ctx, t.q, serverID, userID)
}

func (t pgTx) UpsertUserConnection(ctx context.Context, c *store.MCPUserConnection) error {
	return store.UpsertMCPUserConnection(ctx, t.q, c)
}

func (t pgTx) SetUserConnectionStatus(ctx context.Context, serverID, userID, status string) error {
	return store.SetMCPUserConnectionStatus(ctx, t.q, serverID, userID, status)
}

func (t pgTx) TouchUserConnectionRefreshed(ctx context.Context, serverID, userID string, at time.Time) error {
	return store.TouchMCPUserConnectionRefreshed(ctx, t.q, serverID, userID, at)
}

func (t pgTx) DeleteUserConnection(ctx context.Context, serverID, userID string) (int64, error) {
	return store.DeleteMCPUserConnection(ctx, t.q, serverID, userID)
}
