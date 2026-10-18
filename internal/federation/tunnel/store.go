package tunnel

import (
	"context"
	"time"

	"github.com/huynle/mcp-gateway/internal/caps"
	"github.com/huynle/mcp-gateway/internal/store"
)

// pgStore adapts *store.Store to Store. Owner actions run under WithUser
// (row-level security: a user only sees and revokes their own tunnels);
// the token lookup, re-validation and last-seen updates run under
// WithJobs because no user is known when a tunnel client connects
// (decision 17iv8p3b).
type pgStore struct {
	st   *store.Store
	caps caps.Limiter // per-user tunnel cap (nil: unlimited)
}

// NewStore returns the PostgreSQL-backed Store. st must have the jobs pool
// configured (store.WithJobsURL).
func NewStore(st *store.Store) Store { return pgStore{st: st} }

// NewStoreWithCaps is NewStore with the per-user cap on live tunnels
// enforced in CreateTunnel's transaction (*caps.ExceededError).
func NewStoreWithCaps(st *store.Store, l caps.Limiter) Store { return pgStore{st: st, caps: l} }

func (p pgStore) CreateTunnel(ctx context.Context, ownerUserID, name string, tokenHash []byte) (*store.MCPTunnel, error) {
	t := &store.MCPTunnel{OwnerUserID: ownerUserID, Name: name, TokenHash: tokenHash}
	err := p.st.WithUser(ctx, ownerUserID, func(tx store.Tx) error {
		if err := caps.Reserve(ctx, tx, p.caps, ownerUserID, caps.Tunnels); err != nil {
			return err
		}
		return store.CreateMCPTunnel(ctx, tx, t)
	})
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (p pgStore) RevokeTunnel(ctx context.Context, ownerUserID, tunnelID string, at time.Time) error {
	if !uuidRE.MatchString(tunnelID) {
		return store.ErrNotFound
	}
	return p.st.WithUser(ctx, ownerUserID, func(tx store.Tx) error { return store.RevokeMCPTunnel(ctx, tx, tunnelID, at) })
}

func (p pgStore) TunnelByTokenHash(ctx context.Context, hash []byte) (*store.MCPTunnel, error) {
	var t *store.MCPTunnel
	err := p.st.WithJobs(ctx, func(tx store.Tx) error {
		var err error
		t, err = store.GetMCPTunnelByTokenHash(ctx, tx, hash)
		return err
	})
	return t, err
}

func (p pgStore) Tunnel(ctx context.Context, tunnelID string) (*store.MCPTunnel, error) {
	if !uuidRE.MatchString(tunnelID) {
		return nil, store.ErrNotFound
	}
	var t *store.MCPTunnel
	err := p.st.WithJobs(ctx, func(tx store.Tx) error {
		var err error
		t, err = store.GetMCPTunnel(ctx, tx, tunnelID)
		return err
	})
	return t, err
}

func (p pgStore) TouchTunnel(ctx context.Context, tunnelID string, at time.Time) error {
	return p.st.WithJobs(ctx, func(tx store.Tx) error { return store.TouchMCPTunnel(ctx, tx, tunnelID, at) })
}
