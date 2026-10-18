package portal

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/huynle/mcp-gateway/internal/caps"
	"github.com/huynle/mcp-gateway/internal/store"
)

// pgStore is the Store over *store.Store: every call runs as the user
// (WithUser), so row-level security decides visibility and ownership
// (decision 17iv8p3b).
type pgStore struct {
	st   *store.Store
	caps caps.Limiter
}

// NewStore adapts a *store.Store to the portal's Store.
func NewStore(st *store.Store) Store { return &pgStore{st: st} }

// NewStoreWithCaps is NewStore with the per-user server cap enforced in
// CreateServer's transaction (*caps.ExceededError at the cap).
func NewStoreWithCaps(st *store.Store, l caps.Limiter) Store { return &pgStore{st: st, caps: l} }

func (p *pgStore) as(ctx context.Context, userID string, fn func(store.Tx) error) error {
	return p.st.WithUser(ctx, userID, fn)
}

// notFound maps a malformed ID (22P02) to ErrNotFound.
func notFound(err error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "22P02" {
		return store.ErrNotFound
	}
	return err
}

func (p *pgStore) ListVisibleServers(ctx context.Context, userID string) ([]store.MCPServer, error) {
	var out []store.MCPServer
	err := p.as(ctx, userID, func(tx store.Tx) error {
		var err error
		out, err = store.ListVisibleMCPServers(ctx, tx, userID)
		return err
	})
	return out, err
}

func (p *pgStore) GetServer(ctx context.Context, userID, serverID string) (*store.MCPServer, error) {
	var out *store.MCPServer
	err := p.as(ctx, userID, func(tx store.Tx) error {
		var err error
		out, err = store.GetMCPServer(ctx, tx, serverID)
		return err
	})
	return out, notFound(err)
}

func (p *pgStore) CreateServer(ctx context.Context, userID string, s *store.MCPServer) error {
	s.OwnerUserID = userID
	err := p.as(ctx, userID, func(tx store.Tx) error {
		if err := caps.Reserve(ctx, tx, p.caps, userID, caps.Servers); err != nil {
			return err
		}
		return store.CreateMCPServer(ctx, tx, s)
	})
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" {
		return ErrNameTaken
	}
	return err
}

// ownerOnly runs fn on a server the user owns (ErrNotFound otherwise): row
// security already limits writes to the owner, the explicit check keeps
// the error the same for servers the user can merely see.
func (p *pgStore) ownerOnly(ctx context.Context, userID, serverID string, fn func(store.Tx) error) error {
	err := p.as(ctx, userID, func(tx store.Tx) error {
		s, err := store.GetMCPServer(ctx, tx, serverID)
		if err != nil {
			return err
		}
		if s.OwnerUserID != userID {
			return store.ErrNotFound
		}
		return fn(tx)
	})
	return notFound(err)
}

func (p *pgStore) UpdateServer(ctx context.Context, userID string, s *store.MCPServer) error {
	return p.ownerOnly(ctx, userID, s.ID, func(tx store.Tx) error { return store.UpdateMCPServer(ctx, tx, s) })
}

func (p *pgStore) DeleteServer(ctx context.Context, userID, serverID string) error {
	return p.ownerOnly(ctx, userID, serverID, func(tx store.Tx) error { return store.DeleteMCPServer(ctx, tx, serverID) })
}

func (p *pgStore) ListConnections(ctx context.Context, userID string) ([]store.MCPUserConnection, error) {
	var out []store.MCPUserConnection
	err := p.as(ctx, userID, func(tx store.Tx) error {
		var err error
		out, err = store.ListMCPUserConnections(ctx, tx, userID)
		return err
	})
	return out, err
}

// CredentialInfo reads the owner-only rows; for anyone else row security
// hides them and the result is zero.
func (p *pgStore) CredentialInfo(ctx context.Context, userID, serverID string) (CredentialInfo, error) {
	var info CredentialInfo
	err := p.as(ctx, userID, func(tx store.Tx) error {
		sec, err := store.GetMCPServerSharedSecret(ctx, tx, serverID)
		switch {
		case err == nil:
			info.SharedSecret, info.SharedKeys = true, sec.SecretKeys
		case !errors.Is(err, store.ErrNotFound):
			return fmt.Errorf("shared secret: %w", err)
		}
		cl, err := store.GetMCPOAuthClient(ctx, tx, serverID)
		switch {
		case err == nil:
			if cl.Method == store.MCPOAuthClientStatic {
				info.StaticClient, info.StaticClientID = true, cl.ClientID
			}
		case !errors.Is(err, store.ErrNotFound):
			return fmt.Errorf("oauth client: %w", err)
		}
		return nil
	})
	return info, notFound(err)
}

func (p *pgStore) ListTunnels(ctx context.Context, userID string) ([]store.MCPTunnel, error) {
	var out []store.MCPTunnel
	err := p.as(ctx, userID, func(tx store.Tx) error {
		var err error
		out, err = store.ListMCPTunnels(ctx, tx, userID)
		return err
	})
	return out, err
}
