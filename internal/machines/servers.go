package machines

import (
	"context"
	"errors"

	"github.com/huynle/mcp-gateway/internal/federation/connector"
	fedportal "github.com/huynle/mcp-gateway/internal/federation/portal"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/permissions"
	"github.com/huynle/mcp-gateway/internal/store"
)

// ServerManager is the part of *connector.Manager the machine API uses:
// creating a server checks the add-server permission, the name and the
// server cap and reloads the tool registry; updating reloads it too.
type ServerManager interface {
	CreateServer(ctx context.Context, s *store.MCPServer) error
	UpdateServer(ctx context.Context, userID string, s *store.MCPServer) error
}

// SnapshotService is the part of *snapshot.Service the machine API uses.
type SnapshotService interface {
	Refresh(ctx context.Context, a snapshot.Actor, serverID string, sess snapshot.Session) (*snapshot.Record, snapshot.Diff, error)
	Current(ctx context.Context, a snapshot.Actor, serverID string) (*snapshot.Record, error)
	Latest(ctx context.Context, a snapshot.Actor, serverID string) (*snapshot.Record, error)
}

// ServersOptions build the federation-backed Servers.
type ServersOptions struct {
	Store     *store.Store
	Manager   ServerManager
	Snapshots SnapshotService
	// Clients opens upstream sessions as the owner (the factory the
	// servers portal's Refresh uses; tunnel URLs go through the tunnel).
	Clients fedportal.ClientFactory
}

type fedServers struct{ o ServersOptions }

// NewServers adapts the federation to Servers.
func NewServers(o ServersOptions) Servers { return &fedServers{o: o} }

func (f *fedServers) OwnServer(ctx context.Context, ownerID, name string) (*store.MCPServer, error) {
	var out *store.MCPServer
	err := f.o.Store.WithUser(ctx, ownerID, func(tx store.Tx) error {
		s, err := store.GetMCPServerByName(ctx, tx, name)
		if err != nil {
			return err
		}
		if s.OwnerUserID != ownerID {
			return store.ErrNotFound
		}
		out = s
		return nil
	})
	return out, err
}

func (f *fedServers) CreateServer(ctx context.Context, s *store.MCPServer) error {
	err := f.o.Manager.CreateServer(ctx, s)
	switch {
	case errors.Is(err, connector.ErrServerNameTaken) || errors.Is(err, fedportal.ErrNameTaken):
		return ErrServerNameTaken
	case errors.Is(err, permissions.ErrNotPermitted):
		return ErrNotPermitted
	case errors.Is(err, connector.ErrInvalidServerName) || errors.Is(err, connector.ErrReservedServerName):
		return ErrInvalidServerName
	}
	return err
}

func (f *fedServers) SetServerURL(ctx context.Context, ownerID string, s *store.MCPServer) error {
	err := f.o.Manager.UpdateServer(ctx, ownerID, s)
	if errors.Is(err, store.ErrMCPServerLocked) {
		return ErrServerLocked
	}
	return err
}

func (f *fedServers) Refresh(ctx context.Context, ownerID string, s *store.MCPServer) (int, snapshot.Diff, error) {
	sess, err := f.o.Clients.Open(ctx, s, ownerID)
	if err != nil {
		return 0, snapshot.Diff{}, err
	}
	defer func() { _ = sess.Close() }()
	rec, diff, err := f.o.Snapshots.Refresh(ctx, snapshot.Actor{UserID: ownerID}, s.ID, sess)
	if err != nil {
		return 0, snapshot.Diff{}, err
	}
	return rec.Version, diff, nil
}

func (f *fedServers) Review(ctx context.Context, ownerID, serverID string) (int, bool, error) {
	a := snapshot.Actor{UserID: ownerID}
	approved, version := 0, 0
	cur, err := f.o.Snapshots.Current(ctx, a, serverID)
	switch {
	case errors.Is(err, snapshot.ErrNoSnapshot):
	case err != nil:
		return 0, false, err
	default:
		version = cur.Version
		for _, r := range cur.Review {
			if r.Enabled {
				approved++
			}
		}
	}
	latest, err := f.o.Snapshots.Latest(ctx, a, serverID)
	switch {
	case errors.Is(err, snapshot.ErrNoSnapshot):
		return approved, false, nil
	case err != nil:
		return 0, false, err
	}
	return approved, latest.Version > version, nil
}
