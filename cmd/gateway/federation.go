package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/federation/auth"
	"github.com/huynle/mcp-gateway/internal/federation/connector"
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
func newFederation(ctx context.Context, cfg config.Config, st *store.Store, keys crypto.KeyProvider, registry *connectors.Registry, policySvc *policy.Service, metrics *observability.Metrics, log *slog.Logger) (*connector.Federation, error) {
	if st == nil || keys == nil {
		log.Warn("no key provider: user-added MCP servers are not mounted")
		return nil, nil
	}
	opts := connector.WireOptions{
		Store: st, Keys: keys, Registry: registry, BaseURL: cfg.BaseURL, Version: version, Log: log,
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
func withFederationPages(fed *connector.Federation) portalExtra {
	return func(_ *identity.Service, mountUser func(string, http.Handler), session func(*http.Request) (string, string), _ *slog.Logger) {
		if fed == nil {
			return
		}
		user := func(r *http.Request) (string, bool) {
			id, _ := session(r)
			return id, id != ""
		}
		mountUser("GET /servers/{id}/connect", fed.Auth.StartConnect(user))
		mountUser("GET "+auth.CallbackPath, fed.Auth.Callback(user))
	}
}
