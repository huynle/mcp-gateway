package permissions

import (
	"context"

	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/store"
)

// pgStore is the Store over *store.Store. Every call runs as the user it
// is about (WithUser): row-level security shows only their own role
// assignments and user row, and gateway_app may update only the
// gateway_tools_enabled column (schema 16).
type pgStore struct{ st *store.Store }

// NewPostgresStore returns the production Store.
func NewPostgresStore(st *store.Store) Store { return pgStore{st: st} }

// NewPostgres is New over NewPostgresStore(st).
func NewPostgres(st *store.Store, opts Options) *Service { return New(NewPostgresStore(st), opts) }

func (p pgStore) MayAddServers(ctx context.Context, userID string) (bool, error) {
	var ok bool
	err := p.st.WithUser(ctx, userID, func(tx store.Tx) (err error) {
		ok, err = store.UserMayAddServers(ctx, tx, userID, identity.AdminRole)
		return err
	})
	return ok, err
}

func (p pgStore) GatewayToolsEnabled(ctx context.Context, userID string) (bool, error) {
	var on bool
	err := p.st.WithUser(ctx, userID, func(tx store.Tx) (err error) {
		on, err = store.GatewayToolsEnabled(ctx, tx, userID)
		return err
	})
	return on, err
}

func (p pgStore) SetGatewayToolsEnabled(ctx context.Context, userID string, on bool) error {
	return p.st.WithUser(ctx, userID, func(tx store.Tx) error {
		return store.SetGatewayToolsEnabled(ctx, tx, userID, on)
	})
}
