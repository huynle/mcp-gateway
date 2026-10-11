package admin

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/huynle/mcp-gateway/internal/store"
)

// PGStore is the Store and Roles over *store.Store. Every call runs through
// WithJobs: publishing, admin review and other users' rows are admin-only
// by grants and row-level security (decision 17iv8p3b), and the pages
// reach it only after the admin check.
type PGStore struct{ st *store.Store }

// NewStore adapts a *store.Store to the admin pages' Store and Roles.
func NewStore(st *store.Store) *PGStore { return &PGStore{st: st} }

var (
	_ Store = (*PGStore)(nil)
	_ Roles = (*PGStore)(nil)
)

func (p *PGStore) jobs(ctx context.Context, fn func(store.Tx) error) error {
	return mapErr(p.st.WithJobs(ctx, fn))
}

// mapErr turns a malformed ID (22P02) into ErrNotFound and a unique
// violation (23505) into ErrDuplicate.
func mapErr(err error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		switch pg.Code {
		case "22P02":
			return store.ErrNotFound
		case "23505":
			return ErrDuplicate
		}
	}
	return err
}

func serverOf(s *store.AdminMCPServer) Server {
	return Server{
		MCPServer: s.MCPServer, OwnerName: s.OwnerDisplayName, HasSharedCredential: s.HasSharedCredential,
		PublishedRoleIDs: s.PublishedRoleIDs, UserConnectionCount: s.UserConnectionCount,
		LatestVersion: s.LatestSnapshotVersion, ApprovedVersion: s.ApprovedSnapshotVersion,
	}
}

func tunnelOf(t *store.AdminMCPTunnel) Tunnel {
	return Tunnel{ID: t.ID, OwnerUserID: t.OwnerUserID, OwnerName: t.OwnerDisplayName, Name: t.Name,
		CreatedAt: t.CreatedAt, LastSeenAt: t.LastSeenAt, RevokedAt: t.RevokedAt}
}

// ListRoles returns every role by name.
func (p *PGStore) ListRoles(ctx context.Context) ([]Role, error) {
	var out []Role
	err := p.jobs(ctx, func(tx store.Tx) error {
		roles, err := store.ListRoles(ctx, tx)
		for _, r := range roles {
			out = append(out, Role{ID: r.ID, Name: r.Name})
		}
		return err
	})
	return out, err
}

// ListServers returns every server by name.
func (p *PGStore) ListServers(ctx context.Context) ([]Server, error) {
	var out []Server
	err := p.jobs(ctx, func(tx store.Tx) error {
		rows, err := store.ListAdminMCPServers(ctx, tx)
		for i := range rows {
			out = append(out, serverOf(&rows[i]))
		}
		return err
	})
	return out, err
}

// GetServer returns one server (store.ErrNotFound).
func (p *PGStore) GetServer(ctx context.Context, id string) (*Server, error) {
	var out *Server
	err := p.jobs(ctx, func(tx store.Tx) error {
		row, err := store.GetAdminMCPServer(ctx, tx, id)
		if err != nil {
			return err
		}
		s := serverOf(row)
		out = &s
		return nil
	})
	return out, err
}

// StaticClientID returns the static OAuth client's ID ("" when the server
// has none, or only an automatic DCR / CIMD client). The secret is never
// read.
func (p *PGStore) StaticClientID(ctx context.Context, serverID string) (string, error) {
	var id string
	err := p.jobs(ctx, func(tx store.Tx) error {
		c, err := store.GetMCPOAuthClient(ctx, tx, serverID)
		switch {
		case errors.Is(err, store.ErrNotFound):
			return nil
		case err != nil:
			return err
		}
		if c.Method == store.MCPOAuthClientStatic {
			id = c.ClientID
		}
		return nil
	})
	return id, err
}

// SetPublishedRoles replaces the server's roles in one transaction: all
// removed (private), then the new set published.
func (p *PGStore) SetPublishedRoles(ctx context.Context, serverID string, roleIDs []string) error {
	return p.jobs(ctx, func(tx store.Tx) error {
		if err := store.UnpublishMCPServer(ctx, tx, serverID, nil); err != nil {
			return err
		}
		if len(roleIDs) == 0 {
			return nil
		}
		return store.PublishMCPServer(ctx, tx, serverID, roleIDs)
	})
}

// SetStatus sets the server's status and clears its last error class.
func (p *PGStore) SetStatus(ctx context.Context, serverID, status string) error {
	return p.jobs(ctx, func(tx store.Tx) error { return store.SetMCPServerStatus(ctx, tx, serverID, status, nil) })
}

// DeleteServer deletes the server with everything that cascades from it.
func (p *PGStore) DeleteServer(ctx context.Context, serverID string) error {
	return p.jobs(ctx, func(tx store.Tx) error { return store.DeleteMCPServer(ctx, tx, serverID) })
}

// ListTunnels returns every user's tunnels.
func (p *PGStore) ListTunnels(ctx context.Context) ([]Tunnel, error) {
	var out []Tunnel
	err := p.jobs(ctx, func(tx store.Tx) error {
		rows, err := store.ListAdminMCPTunnels(ctx, tx)
		for i := range rows {
			out = append(out, tunnelOf(&rows[i]))
		}
		return err
	})
	return out, err
}

// GetTunnel returns one tunnel (store.ErrNotFound).
func (p *PGStore) GetTunnel(ctx context.Context, id string) (*Tunnel, error) {
	var out *Tunnel
	err := p.jobs(ctx, func(tx store.Tx) error {
		row, err := store.GetAdminMCPTunnel(ctx, tx, id)
		if err != nil {
			return err
		}
		t := tunnelOf(row)
		out = &t
		return nil
	})
	return out, err
}

// ListAllowHosts returns the SSRF allow-list by pattern.
func (p *PGStore) ListAllowHosts(ctx context.Context) ([]store.NetguardAllowHost, error) {
	var out []store.NetguardAllowHost
	err := p.jobs(ctx, func(tx store.Tx) error {
		var err error
		out, err = store.ListNetguardAllowHosts(ctx, tx)
		return err
	})
	return out, err
}

// AddAllowHost stores an entry (ErrDuplicate for a known pattern).
func (p *PGStore) AddAllowHost(ctx context.Context, h *store.NetguardAllowHost) error {
	return p.jobs(ctx, func(tx store.Tx) error { return store.CreateNetguardAllowHost(ctx, tx, h) })
}

// DeleteAllowHost removes an entry and returns it (store.ErrNotFound).
func (p *PGStore) DeleteAllowHost(ctx context.Context, id string) (*store.NetguardAllowHost, error) {
	var out *store.NetguardAllowHost
	err := p.jobs(ctx, func(tx store.Tx) error {
		h, err := store.GetNetguardAllowHost(ctx, tx, id)
		if err != nil {
			return err
		}
		out = h
		return store.DeleteNetguardAllowHost(ctx, tx, id)
	})
	return out, err
}
