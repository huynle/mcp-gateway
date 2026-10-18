package connections

import (
	"context"
	"time"

	"github.com/huynle/mcp-gateway/internal/caps"
	"github.com/huynle/mcp-gateway/internal/store"
)

// Store is the persistence the connections service needs. The production
// implementation (NewPostgresStore) runs Bypass through store.WithJobs and
// AsUser through store.WithUser; connectionstest.MemStore is the in-memory
// one for unit tests.
type Store interface {
	// Bypass runs fn in one transaction that sees every row: vendor app
	// administration, the disable hook and the keep-alive job.
	Bypass(ctx context.Context, fn func(Tx) error) error
	// AsUser runs fn scoped to userID: row-level security hides everyone
	// else's connections, secrets and flows. The connect flow, token
	// refresh, disconnect and the account source use it.
	AsUser(ctx context.Context, userID string, fn func(Tx) error) error
}

// Tx is the set of persistence operations the service performs inside one
// transaction; methods map onto the helpers in
// store/repo_connections_lookup.go and the minimal repositories in
// store/tx.go. A Tx must not be used after its callback returns.
type Tx interface {
	ListVendorApps(ctx context.Context) ([]store.VendorApp, error)
	FindVendorApp(ctx context.Context, vendor, name string) (*store.VendorApp, error)
	GetVendorApp(ctx context.Context, id string) (*store.VendorApp, error)
	UpsertVendorApp(ctx context.Context, a *store.VendorApp) error

	ListConnections(ctx context.Context, userID string) ([]store.ConnectionWithApp, error)
	GetConnection(ctx context.Context, id string) (*store.Connection, error)
	FindConnection(ctx context.Context, userID, vendorAppID, externalAccountID string) (*store.Connection, error)
	// LockConnection reads the connection under a row lock held until the
	// transaction ends.
	LockConnection(ctx context.Context, id string) (*store.Connection, error)
	CreateConnection(ctx context.Context, c *store.Connection) error
	// ReserveConnection is the cap check before a new (or revived
	// revoked) connection of userID to vendorAppID: it locks the user's
	// connection budget until the transaction ends and refuses with
	// *caps.ExceededError at the per-app or total cap. A nil l never
	// refuses.
	ReserveConnection(ctx context.Context, l caps.Limiter, userID, vendorAppID string) error
	UpdateConnection(ctx context.Context, c *store.Connection) error
	SetConnectionStatus(ctx context.Context, id, status string) error
	TouchConnectionRefreshed(ctx context.Context, id string, at time.Time) error
	RevokeUserConnections(ctx context.Context, userID string) ([]store.Connection, error)
	ListStaleConnections(ctx context.Context, before time.Time, limit int) ([]store.Connection, error)

	PutSecret(ctx context.Context, s *store.ConnectionSecret) error
	GetSecret(ctx context.Context, connectionID string) (*store.ConnectionSecret, error)
	DeleteSecret(ctx context.Context, connectionID string) (int64, error)

	CreateConnectFlow(ctx context.Context, f *store.ConnectFlow) error
	TakeConnectFlow(ctx context.Context, state string, now time.Time) (*store.ConnectFlow, error)
	PurgeConnectFlows(ctx context.Context, now time.Time) (int64, error)
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

func (t pgTx) ListVendorApps(ctx context.Context) ([]store.VendorApp, error) {
	return store.ListVendorApps(ctx, t.tx)
}

func (t pgTx) FindVendorApp(ctx context.Context, vendor, name string) (*store.VendorApp, error) {
	return store.FindVendorApp(ctx, t.tx, vendor, name)
}

func (t pgTx) GetVendorApp(ctx context.Context, id string) (*store.VendorApp, error) {
	return t.tx.VendorApps().Get(ctx, id)
}

func (t pgTx) UpsertVendorApp(ctx context.Context, a *store.VendorApp) error {
	return store.UpsertVendorApp(ctx, t.tx, a)
}

func (t pgTx) ListConnections(ctx context.Context, userID string) ([]store.ConnectionWithApp, error) {
	return store.ListConnectionsForUser(ctx, t.tx, userID)
}

func (t pgTx) GetConnection(ctx context.Context, id string) (*store.Connection, error) {
	return t.tx.Connections().Get(ctx, id)
}

func (t pgTx) FindConnection(ctx context.Context, userID, vendorAppID, externalAccountID string) (*store.Connection, error) {
	return store.FindConnection(ctx, t.tx, userID, vendorAppID, externalAccountID)
}

func (t pgTx) LockConnection(ctx context.Context, id string) (*store.Connection, error) {
	return store.LockConnection(ctx, t.tx, id)
}

func (t pgTx) ReserveConnection(ctx context.Context, l caps.Limiter, userID, vendorAppID string) error {
	return caps.ReserveConnection(ctx, t.tx, l, userID, vendorAppID)
}

func (t pgTx) CreateConnection(ctx context.Context, c *store.Connection) error {
	return t.tx.Connections().Create(ctx, c)
}

func (t pgTx) UpdateConnection(ctx context.Context, c *store.Connection) error {
	return store.UpdateConnection(ctx, t.tx, c)
}

func (t pgTx) SetConnectionStatus(ctx context.Context, id, status string) error {
	return store.SetConnectionStatus(ctx, t.tx, id, status)
}

func (t pgTx) TouchConnectionRefreshed(ctx context.Context, id string, at time.Time) error {
	return store.TouchConnectionRefreshed(ctx, t.tx, id, at)
}

func (t pgTx) RevokeUserConnections(ctx context.Context, userID string) ([]store.Connection, error) {
	return store.RevokeUserConnections(ctx, t.tx, userID)
}

func (t pgTx) ListStaleConnections(ctx context.Context, before time.Time, limit int) ([]store.Connection, error) {
	return store.ListStaleConnections(ctx, t.tx, before, limit)
}

func (t pgTx) PutSecret(ctx context.Context, s *store.ConnectionSecret) error {
	return t.tx.Connections().PutSecret(ctx, s)
}

func (t pgTx) GetSecret(ctx context.Context, connectionID string) (*store.ConnectionSecret, error) {
	return t.tx.Connections().GetSecret(ctx, connectionID)
}

func (t pgTx) DeleteSecret(ctx context.Context, connectionID string) (int64, error) {
	return store.DeleteConnectionSecret(ctx, t.tx, connectionID)
}

func (t pgTx) CreateConnectFlow(ctx context.Context, f *store.ConnectFlow) error {
	return store.CreateConnectFlow(ctx, t.tx, f)
}

func (t pgTx) TakeConnectFlow(ctx context.Context, state string, now time.Time) (*store.ConnectFlow, error) {
	return store.TakeConnectFlow(ctx, t.tx, state, now)
}

func (t pgTx) PurgeConnectFlows(ctx context.Context, now time.Time) (int64, error) {
	return store.PurgeConnectFlows(ctx, t.tx, now)
}
