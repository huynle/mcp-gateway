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
		taken, err := store.MCPTunnelNameTaken(ctx, tx, ownerUserID, name)
		if err != nil {
			return err
		}
		if taken {
			return ErrNameTaken
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

// NewHolderStore returns the PostgreSQL-backed HolderStore
// (mcp_tunnel_holders, WithJobs). st must have the jobs pool configured.
func NewHolderStore(st *store.Store) HolderStore { return pgStore{st: st} }

func (p pgStore) ClaimHolder(ctx context.Context, tunnelID, holder string, at time.Time) (int64, error) {
	var epoch int64
	err := p.st.WithJobs(ctx, func(tx store.Tx) error {
		var err error
		epoch, err = store.ClaimMCPTunnelHolder(ctx, tx, tunnelID, holder, at)
		return err
	})
	return epoch, err
}

func (p pgStore) ReleaseHolder(ctx context.Context, tunnelID string, epoch int64) error {
	return p.st.WithJobs(ctx, func(tx store.Tx) error {
		_, err := store.ReleaseMCPTunnelHolder(ctx, tx, tunnelID, epoch)
		return err
	})
}

func (p pgStore) Holder(ctx context.Context, tunnelID string) (*store.MCPTunnelHolder, error) {
	if !uuidRE.MatchString(tunnelID) {
		return nil, store.ErrNotFound
	}
	var h *store.MCPTunnelHolder
	err := p.st.WithJobs(ctx, func(tx store.Tx) error {
		var err error
		h, err = store.GetMCPTunnelHolder(ctx, tx, tunnelID)
		return err
	})
	return h, err
}

// NewMachineStore returns the PostgreSQL-backed MachineStore (machines
// and their tunnels, WithJobs). st must have the jobs pool configured.
func NewMachineStore(st *store.Store) MachineStore { return pgStore{st: st} }

func (p pgStore) MachineTunnels(ctx context.Context, machineID string) ([]string, bool, error) {
	if !uuidRE.MatchString(machineID) {
		return nil, false, nil
	}
	var ids []string
	var live bool
	err := p.st.WithJobs(ctx, func(tx store.Tx) error {
		var err error
		ids, live, err = store.MachineTunnelIDs(ctx, tx, machineID)
		return err
	})
	return ids, live, err
}

func (p pgStore) TouchMachine(ctx context.Context, machineID string, at time.Time) error {
	return p.st.WithJobs(ctx, func(tx store.Tx) error { return store.TouchMachine(ctx, tx, machineID, at, "") })
}
