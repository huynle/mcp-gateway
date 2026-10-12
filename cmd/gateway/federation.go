package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/crypto"
	fedadmin "github.com/huynle/mcp-gateway/internal/federation/admin"
	"github.com/huynle/mcp-gateway/internal/federation/auth"
	"github.com/huynle/mcp-gateway/internal/federation/connector"
	"github.com/huynle/mcp-gateway/internal/federation/gatewaytools"
	fedportal "github.com/huynle/mcp-gateway/internal/federation/portal"
	"github.com/huynle/mcp-gateway/internal/federation/tunnel"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/store"
)

// newFederation wires user-added MCP servers (Brain plan 0omkv2e1, task
// fybs78bs; docs/federation-connector.md): the netguard Guard over the
// store-backed allow list (netguard_allow_hosts), the upstream auth,
// snapshot and tunnel services, and the connector Manager, whose server
// apps go into registry (after the built-in connectors) and whose changes
// invalidate the compiled policy (the owner layer of private servers).
// It loads the servers and keeps reloading them until ctx ends. Like app
// connections it needs a database and a key provider (credentials are
// sealed); without either it returns nil and nothing is mounted.
func newFederation(ctx context.Context, cfg config.Config, st *store.Store, keys crypto.KeyProvider, registry *connectors.Registry, policySvc *policy.Service, perms connector.AddServerPermission, metrics *observability.Metrics, log *slog.Logger) (*connector.Federation, error) {
	if st == nil || keys == nil {
		log.Warn("no key provider: user-added MCP servers are not mounted")
		return nil, nil
	}
	opts := connector.WireOptions{
		Store: st, Keys: keys, Registry: registry, BaseURL: cfg.BaseURL, Version: version, Log: log,
		ConnectFinish: connectFinish(log), Permissions: perms,
	}
	if policySvc != nil {
		opts.OnChange = policySvc.Invalidate
	}
	if metrics != nil {
		opts.Metrics = metrics.Registry()
	}
	fed, err := connector.Wire(opts)
	if err != nil {
		return nil, fmt.Errorf("federation: %w", err)
	}
	fed.Start(ctx)
	log.Info("user-added MCP servers ready", "server_apps", len(registry.ServerApps()),
		"tunnel_path", tunnel.ConnectPath, "callback_path", auth.CallbackPath)
	return fed, nil
}

// newGatewayTools registers the gateway.* management tools (Brain task
// 99b5yzdb, docs/gateway-management.md) over the federation: visible and
// callable only for users permitted to add MCP servers who switched them
// on in My account. Without a federation (no key provider) there are none
// and the returned nil *Tools leaves every wrapper unchanged.
func newGatewayTools(fed *connector.Federation, st *store.Store, registry *connectors.Registry, activity gatewaytools.Activity, baseURL string, log *slog.Logger) (*gatewaytools.Tools, error) {
	if fed == nil {
		return nil, nil
	}
	gw, err := gatewaytools.Wire(gatewaytools.WireOptions{
		Federation: fed, Store: st, Registry: registry, Activity: activity, BaseURL: baseURL, Log: log,
	})
	if err != nil {
		return nil, fmt.Errorf("gateway tools: %w", err)
	}
	log.Info("gateway management tools registered", "app", gatewaytools.App, "gate_ttl", gatewaytools.DefaultGateTTL)
	return gw, nil
}

// federationAccounts routes server apps to the federation's anchor
// accounts and everything else to base.
func federationAccounts(fed *connector.Federation, base connectors.AccountSource) connectors.AccountSource {
	if fed == nil {
		return base
	}
	return fed.Manager.Accounts(base)
}

// federationDecider adds server visibility (owner of a private server, or
// a role it is published to) to the policy for tools/list, resolve and
// the policy stage.
func federationDecider(fed *connector.Federation, base mcp.Decider) mcp.Decider {
	if fed == nil {
		return base
	}
	return fed.Manager.Decider(base)
}

// withFederationRoutes mounts the public federation routes on the
// top-level mux, outside the portal's session handling: the OAuth client
// metadata document (CIMD) and the tunnel endpoint. The tunnel token is
// the tunnel's credential; its handler must see the raw connection
// (WebSocket upgrade for hours), so it sits outside any buffering or
// whole-request timeout (the outer metrics wrapper unwraps to the
// hijacker; the server sets only ReadHeaderTimeout).
func withFederationRoutes(fed *connector.Federation) muxExtra {
	return func(mux *http.ServeMux) {
		if fed == nil {
			return
		}
		mux.Handle("GET "+auth.ClientMetadataPath, fed.Auth.ClientMetadataDocument())
		mux.Handle(tunnel.ConnectPath, fed.Tunnels.Handler())
	}
}

// withFederationPages mounts the upstream OAuth connect flow behind the
// portal's signed-in check: GET /servers/{id}/connect starts it (302 to
// the server's authorization server), GET /servers/oauth/callback
// finishes it. The servers portal (its own package) links to them.
func withFederationPages(fed *connector.Federation, st *store.Store, baseURL string) portalExtra {
	return func(_ *identity.Service, mountUser func(string, http.Handler), session func(*http.Request) (string, string), log *slog.Logger) {
		if fed == nil {
			return
		}
		user := func(r *http.Request) (string, bool) {
			id, _ := session(r)
			return id, id != ""
		}
		mountUser("GET /servers/{id}/connect", fed.Auth.StartConnect(user))
		mountUser("GET "+auth.CallbackPath, fed.Auth.Callback(user))

		// The servers portal (internal/federation/portal, task 9dp13dgy).
		factory, err := fedportal.NewClientFactory(fedportal.FactoryOptions{
			Credentials: fed.Auth, Tunnels: fed.Tunnels, HTTPClient: fed.Guard.Client(), Log: log,
		})
		if err != nil {
			log.Error("servers portal not mounted", "error", err)
			return
		}
		identityFn := func(r *http.Request) (string, string, bool) {
			id, csrf := session(r)
			return id, csrf, identity.PrincipalFrom(r.Context()).IsAdmin()
		}
		fedportal.NewPortal(fedportal.Deps{
			Store: fedportal.NewStore(st), Snapshots: fed.Snapshots, Auth: fed.Auth, Tunnels: fed.Tunnels,
			ClientFactory: factory, Hook: serverChangedHook{m: fed.Manager, log: log}, Permissions: fed.Permissions,
			Identity: identityFn, Log: log, BaseURL: baseURL,
		}).Mount(mountUser)
	}
}

// withFederationAdmin mounts the admin pages for user-added MCP servers
// (internal/federation/admin, task 1d9i8b07): /admin/servers (publish,
// credentials, status, delete, refresh, review), /admin/tunnels and
// /admin/network/allow-hosts. Their patterns are under /admin, so
// portalMount puts them behind the portal's admin check. Changes call the
// connector Manager's ServerChanged and, for the allow-list, invalidate
// netguard's cached allow list; every change is audited through rec.
func withFederationAdmin(fed *connector.Federation, st *store.Store, rec audit.Recorder) portalExtra {
	return func(_ *identity.Service, mount func(string, http.Handler), session func(*http.Request) (string, string), log *slog.Logger) {
		if fed == nil {
			return
		}
		factory, err := fedportal.NewClientFactory(fedportal.FactoryOptions{
			Credentials: fed.Auth, Tunnels: fed.Tunnels, HTTPClient: fed.Guard.Client(), Log: log,
		})
		if err != nil {
			log.Error("admin servers pages not mounted", "error", err)
			return
		}
		identityFn := func(r *http.Request) (string, string, bool) {
			id, csrf := session(r)
			return id, csrf, identity.PrincipalFrom(r.Context()).IsAdmin()
		}
		deps := fedadmin.Deps{
			Snapshots: fed.Snapshots, Auth: fed.Auth, Tunnels: fed.Tunnels, ClientFactory: factory,
			Hook: fed.Manager, Identity: identityFn, Audit: rec, Log: log,
		}
		if fed.AllowList != nil {
			deps.AllowList = fed.AllowList
		}
		as := fedadmin.NewStore(st)
		deps.Store, deps.Roles = as, as
		fedadmin.NewAdmin(deps).Mount(mount)
	}
}

// serverChangedHook adapts the connector Manager to the portal's
// ToolsChanged hook (no error return): a failed reload is logged and the
// Manager's periodic reload catches up.
type serverChangedHook struct {
	m   *connector.Manager
	log *slog.Logger
}

func (h serverChangedHook) ServerChanged(ctx context.Context, serverID string) {
	if err := h.m.ServerChanged(ctx, serverID); err != nil {
		h.log.Warn("server change not applied yet; periodic reload will retry", "event", "federation.server_changed_failed",
			"server_id", serverID, "error", observability.RedactError(err))
	}
}

// connectFinish ends the upstream OAuth connect flow back on the server's
// portal page.
func connectFinish(log *slog.Logger) func(http.ResponseWriter, *http.Request, string, error) {
	return func(w http.ResponseWriter, r *http.Request, serverID string, err error) {
		target := "/servers"
		if serverID != "" {
			target = "/servers/" + url.PathEscape(serverID)
		}
		if err != nil {
			log.Warn("upstream connect failed", "event", "federation.connect_failed", "server_id", serverID, "error", observability.RedactError(err))
			http.Redirect(w, r, target+"?connect=failed", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, target+"?connect=ok", http.StatusSeeOther)
	}
}
