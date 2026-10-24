package connector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/huynle/mcp-gateway/internal/caps"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/federation/auth"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/federation/tunnel"
	"github.com/huynle/mcp-gateway/internal/netguard"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/permissions"
	"github.com/huynle/mcp-gateway/internal/store"
)

// WireOptions configure Wire. Store, Keys and Registry are required.
type WireOptions struct {
	Store    *store.Store
	Keys     crypto.KeyProvider
	Registry *connectors.Registry
	// BaseURL is GATEWAY_BASE_URL (OAuth redirect URI, client metadata
	// document, connect hints).
	BaseURL string
	// Version is reported upstream as the client version.
	Version string
	// OnChange runs after every Manager.ServerChanged (cmd/gateway:
	// policy.Service.Invalidate, for the owner layer).
	OnChange func()
	// Metrics registers netguard's blocked_dials_total; nil skips it.
	Metrics prometheus.Registerer
	Log     *slog.Logger
	// AllowList overrides the store-backed allow list (tests); nil uses
	// netguard.CachedAllowList over netguard_allow_hosts.
	AllowList netguard.AllowList
	// Timeout bounds each upstream operation (client default when 0).
	Timeout time.Duration
	// ConnectFinish renders the end of the upstream OAuth connect flow
	// (auth.Options.Finish); nil keeps the auth package's default.
	ConnectFinish func(w http.ResponseWriter, r *http.Request, serverID string, err error)
	// Permissions gates Manager.CreateServer; nil uses
	// permissions.NewPostgres over Store.
	Permissions AddServerPermission
	// Caps limits each user's servers and live tunnels, checked inside
	// the creating transaction (nil: unlimited).
	Caps caps.Limiter
	// TunnelRelay enables the cross-replica tunnel relay; nil keeps tunnels
	// local to the replica holding their connection. Holders defaults to
	// tunnel.NewHolderStore(Store) and Metrics to WireOptions.Metrics.
	TunnelRelay *tunnel.RelayOptions
	// CredentialLinks is GATEWAY_CREDENTIAL_LINKS_ENABLED (Options.CredentialLinks):
	// credential problems answer -32042 with a portal link, and the
	// Manager's calls refuse a declared per-user header without a value
	// (auth.ErrUserHeaderMissing). Federation.Auth itself stays lenient,
	// so the servers portal's refresh is unchanged.
	CredentialLinks bool
}

// Federation is every federation piece wired together over one netguard
// Guard: the upstream auth service (OAuth connect flow handlers, client
// metadata document, credentials), the snapshot service, the tunnel
// service (its Handler serves tunnel.ConnectPath) and the Manager.
type Federation struct {
	Manager   *Manager
	Auth      *auth.Service
	Snapshots *snapshot.Service
	Tunnels   *tunnel.Service
	Guard     *netguard.Guard
	// AllowList is the store-backed allow list (nil when overridden);
	// admin pages call Invalidate after editing netguard_allow_hosts.
	AllowList *netguard.CachedAllowList
	// Permissions is the add-server permission check the Manager uses
	// (WireOptions.Permissions or permissions.NewPostgres); the servers
	// portal gates Add server on it too.
	Permissions AddServerPermission
	// Caps is WireOptions.Caps: the servers portal's store enforces the
	// same server cap.
	Caps caps.Limiter
	// GatewayAccounts supplies the anchor account of the gateway.*
	// management tools (internal/federation/gatewaytools).
	GatewayAccounts GatewayAccounts
}

// Wire builds the federation. Nothing is loaded yet: call Start (or
// Manager.Load) once the registry has its built-in connectors.
func Wire(o WireOptions) (*Federation, error) {
	switch {
	case o.Store == nil:
		return nil, errors.New("federation: store is required")
	case o.Keys == nil:
		return nil, errors.New("federation: key provider is required")
	case o.Registry == nil:
		return nil, errors.New("federation: registry is required")
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	f := &Federation{Caps: o.Caps}
	allow := o.AllowList
	if allow == nil {
		f.AllowList = netguard.NewCachedAllowList(AllowHostsLoader(o.Store), netguard.CachedAllowListOptions{Log: o.Log})
		allow = f.AllowList
	}
	gopts := netguard.Options{AllowList: allow, Log: o.Log}
	if o.Metrics != nil {
		pm, err := netguard.NewPrometheusMetrics(o.Metrics)
		if err != nil {
			return nil, fmt.Errorf("federation: netguard metrics: %w", err)
		}
		gopts.Metrics = pm
	}
	f.Guard = netguard.New(gopts)
	var err error
	f.Auth, err = auth.New(auth.Options{
		HTTPClient: f.Guard.Client(), Store: auth.NewPostgresStore(o.Store), Keys: o.Keys, BaseURL: o.BaseURL, Log: o.Log,
		Finish: o.ConnectFinish,
	})
	if err != nil {
		return nil, fmt.Errorf("federation: auth: %w", err)
	}
	f.Snapshots = snapshot.NewService(o.Store)
	topts := tunnel.Options{Store: tunnel.NewStoreWithCaps(o.Store, o.Caps), Machines: tunnel.NewMachineStore(o.Store), Log: o.Log}
	if o.TunnelRelay != nil {
		r := *o.TunnelRelay
		if r.Holders == nil {
			r.Holders = tunnel.NewHolderStore(o.Store)
		}
		if r.Metrics == nil {
			r.Metrics = o.Metrics
		}
		topts.Relay = &r
	}
	f.Tunnels, err = tunnel.NewService(topts)
	if err != nil {
		return nil, fmt.Errorf("federation: tunnel: %w", err)
	}
	perms := o.Permissions
	if perms == nil {
		perms = permissions.NewPostgres(o.Store, permissions.Options{Log: o.Log})
	}
	f.Permissions = perms
	ps := &pgStore{st: o.Store, keys: o.Keys, caps: o.Caps}
	f.GatewayAccounts = ps
	f.Manager, err = New(Options{
		Registry: o.Registry, Store: ps, Snapshots: f.Snapshots,
		Credentials: f.Auth.UserHeadersRequired(o.CredentialLinks), Tunnels: f.Tunnels, Permissions: perms, HTTPClient: f.Guard.Client(),
		BaseURL: o.BaseURL, CredentialLinks: o.CredentialLinks, Version: o.Version, Timeout: o.Timeout, OnChange: o.OnChange, Log: o.Log,
	})
	if err != nil {
		return nil, err
	}
	return f, nil
}

// Start loads the servers (a failure is logged: the gateway still serves
// built-in tools and the periodic reload retries) and reloads every
// DefaultReloadInterval until ctx ends.
func (f *Federation) Start(ctx context.Context) {
	if err := f.Manager.Load(ctx); err != nil {
		f.Manager.log.Error("federated servers not fully loaded at startup", "event", "federation.load_failed",
			"error", observability.RedactError(err))
	}
	go f.Manager.Run(ctx, 0)
}
