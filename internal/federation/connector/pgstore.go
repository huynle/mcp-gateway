package connector

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/huynle/mcp-gateway/internal/caps"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/store"
)

// The anchor vendor app (migration 00015): one disabled vendor_apps row
// that every federated anchor connection belongs to. It has no OAuth
// client; its NOT NULL secret columns hold a sealed placeholder nothing
// reads. The /connections page lists only enabled vendor apps, and the
// connections service's account source never maps an app to this vendor,
// so anchors stay invisible outside the federation.
const (
	AnchorVendor  = "mcp"
	AnchorAppName = "federation"
	// anchorPrefix + server ID is an anchor's external_account_id.
	anchorPrefix = "mcp-server:"
	// GatewayAccountExternalID is the external_account_id of a user's
	// anchor for the gateway.* management tools (Brain task 99b5yzdb):
	// approvals and ledger operations of gateway.delete_server and
	// gateway.add_server reference it.
	GatewayAccountExternalID = "gateway-management"
	// gatewayAccountName is the anchor's display name.
	gatewayAccountName = "gateway"
)

// ErrServerNameTaken: another server already has the name (the unique
// index on mcp_servers.name).
var ErrServerNameTaken = errors.New("federation: server name already taken")

// GatewayAccounts supplies the account the gateway.* management tools run
// under: one anchor connection per user (created on first use, label
// company). NewPostgresStore's Store implements it.
type GatewayAccounts interface {
	GatewayAccount(ctx context.Context, userID string) (string, error)
}

// pgStore implements Store over *store.Store.
type pgStore struct {
	st   *store.Store
	keys crypto.KeyProvider
	caps caps.Limiter // per-user server cap (nil: unlimited)

	mu    sync.Mutex
	appID string // the anchor vendor app, once known
}

// NewPostgresStore returns the production Store. keys seal the anchor
// vendor app's placeholder secret.
func NewPostgresStore(st *store.Store, keys crypto.KeyProvider) Store {
	return &pgStore{st: st, keys: keys}
}

// NewPostgresStoreWithCaps is NewPostgresStore with the per-user server
// cap enforced in CreateServer's transaction.
func NewPostgresStoreWithCaps(st *store.Store, keys crypto.KeyProvider, l caps.Limiter) Store {
	return &pgStore{st: st, keys: keys, caps: l}
}

// AllowHostsLoader reads the admin allow list (netguard_allow_hosts,
// system scope) for netguard.NewCachedAllowList.
func AllowHostsLoader(st *store.Store) func(context.Context) ([]string, error) {
	return func(ctx context.Context) ([]string, error) {
		var out []string
		err := st.WithJobs(ctx, func(tx store.Tx) error {
			hosts, err := store.ListNetguardAllowHosts(ctx, tx)
			for _, h := range hosts {
				out = append(out, h.Pattern)
			}
			return err
		})
		return out, err
	}
}

// ListServers: system scope.
func (p *pgStore) ListServers(ctx context.Context) ([]store.MCPServer, error) {
	var out []store.MCPServer
	err := p.st.WithJobs(ctx, func(tx store.Tx) (err error) {
		out, err = store.ListAllMCPServers(ctx, tx)
		return err
	})
	return out, err
}

// GetServer: system scope.
func (p *pgStore) GetServer(ctx context.Context, id string) (*store.MCPServer, error) {
	var out *store.MCPServer
	err := p.st.WithJobs(ctx, func(tx store.Tx) (err error) {
		out, err = store.GetMCPServer(ctx, tx, id)
		return err
	})
	return out, err
}

// VisibleServerIDs: user scope (row-level security decides).
func (p *pgStore) VisibleServerIDs(ctx context.Context, userID string) ([]string, error) {
	var out []string
	err := p.st.WithUser(ctx, userID, func(tx store.Tx) error {
		servers, err := store.ListVisibleMCPServers(ctx, tx, userID)
		for _, s := range servers {
			out = append(out, s.ID)
		}
		return err
	})
	return out, err
}

// UserConnection: user scope.
func (p *pgStore) UserConnection(ctx context.Context, userID, serverID string) (*store.MCPUserConnection, error) {
	var out *store.MCPUserConnection
	err := p.st.WithUser(ctx, userID, func(tx store.Tx) (err error) {
		out, err = store.GetMCPUserConnection(ctx, tx, serverID, userID)
		return err
	})
	return out, err
}

// CreateServer: user scope, as the owner. A duplicate name is
// ErrServerNameTaken.
func (p *pgStore) CreateServer(ctx context.Context, s *store.MCPServer) error {
	err := p.st.WithUser(ctx, s.OwnerUserID, func(tx store.Tx) error {
		if err := caps.Reserve(ctx, tx, p.caps, s.OwnerUserID, caps.Servers); err != nil {
			return err
		}
		return store.CreateMCPServer(ctx, tx, s)
	})
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" {
		return ErrServerNameTaken
	}
	return err
}

// UpdateServer: user scope (only the owner's rows change).
func (p *pgStore) UpdateServer(ctx context.Context, userID string, s *store.MCPServer) error {
	return p.st.WithUser(ctx, userID, func(tx store.Tx) error {
		return store.UpdateMCPServer(ctx, tx, s)
	})
}

// AnchorAccount returns userID's anchor connection for server, creating
// it under the user's own scope on first use and bringing label, display
// name and status (active) up to date. Concurrent first uses converge on
// one row (the unique (user, app, external id) key; the loser re-reads).
func (p *pgStore) AnchorAccount(ctx context.Context, userID string, server *store.MCPServer, label string) (string, error) {
	return p.anchor(ctx, userID, anchorPrefix+server.ID, server.Name, label)
}

// GatewayAccount returns userID's anchor connection for the gateway.*
// management tools (external id GatewayAccountExternalID, label company),
// created under the user's own scope on first use.
func (p *pgStore) GatewayAccount(ctx context.Context, userID string) (string, error) {
	return p.anchor(ctx, userID, GatewayAccountExternalID, gatewayAccountName, store.AccountCompany)
}

// anchor finds or creates userID's anchor connection with external id ext
// under the anchor vendor app and brings label, display name and status
// (active) up to date.
func (p *pgStore) anchor(ctx context.Context, userID, ext, display, label string) (string, error) {
	appID, err := p.anchorApp(ctx)
	if err != nil {
		return "", err
	}
	var id string
	attempt := func() error {
		return p.st.WithUser(ctx, userID, func(tx store.Tx) error {
			c, err := store.FindConnection(ctx, tx, userID, appID, ext)
			switch {
			case errors.Is(err, store.ErrNotFound):
				c = &store.Connection{UserID: userID, VendorAppID: appID, ExternalAccountID: ext,
					Label: label, DisplayName: display, Status: store.ConnectionActive}
				if err := tx.Connections().Create(ctx, c); err != nil {
					return err
				}
			case err != nil:
				return err
			case c.Label != label || c.DisplayName != display || c.Status != store.ConnectionActive:
				c.Label, c.DisplayName, c.Status = label, display, store.ConnectionActive
				if err := store.UpdateConnection(ctx, tx, c); err != nil {
					return err
				}
			}
			id = c.ID
			return nil
		})
	}
	if err := attempt(); err != nil {
		// A concurrent first use created the row: read it.
		if err2 := attempt(); err2 != nil {
			return "", fmt.Errorf("federation: anchor account: %w", err2)
		}
	}
	return id, nil
}

// anchorApp returns the anchor vendor app's ID, creating the row on first
// use (system scope).
func (p *pgStore) anchorApp(ctx context.Context) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.appID != "" {
		return p.appID, nil
	}
	err := p.st.WithJobs(ctx, func(tx store.Tx) error {
		existing, err := store.FindVendorApp(ctx, tx, AnchorVendor, AnchorAppName)
		switch {
		case err == nil:
			p.appID = existing.ID
			return nil
		case !errors.Is(err, store.ErrNotFound):
			return err
		}
		row := &store.VendorApp{ID: connectors.NewAccountID(), Vendor: AnchorVendor, Name: AnchorAppName,
			ClientID: "mcp-federation", Enabled: false}
		if p.keys == nil {
			return errors.New("no key provider for the anchor vendor app")
		}
		env, err := crypto.Encrypt(ctx, p.keys, crypto.AAD{Kind: "vendor_app", RecordID: row.ID}, []byte(`{"placeholder":true}`))
		if err != nil {
			return err
		}
		row.ClientSecret = store.Encrypted(env)
		if err := store.UpsertVendorApp(ctx, tx, row); err != nil {
			return err
		}
		p.appID = row.ID
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("federation: anchor vendor app: %w", err)
	}
	return p.appID, nil
}
