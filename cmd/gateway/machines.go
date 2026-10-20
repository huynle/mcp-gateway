package main

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/caps"
	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/federation/connector"
	fedportal "github.com/huynle/mcp-gateway/internal/federation/portal"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/machines"
	"github.com/huynle/mcp-gateway/internal/store"
)

// newMachines builds machine enrollment (Brain decision ldjix4y1,
// docs/machines.md) over the federation: machine servers are private MCP
// servers behind tunnels linked to the machine, created through the
// connector Manager (add-server permission, names, server cap) and
// refreshed with the servers portal's client factory; the machine
// connection is the tunnel service's ServeMachine. l enforces the
// machines and tunnels caps. Without a federation (no key provider)
// there are no machines (nil, nil).
func newMachines(cfg config.Config, st *store.Store, fed *connector.Federation, l caps.Limiter, rec audit.Recorder, log *slog.Logger) (*machines.Service, error) {
	if fed == nil {
		return nil, nil
	}
	factory, err := fedportal.NewClientFactory(fedportal.FactoryOptions{
		Credentials: fed.Auth, Tunnels: fed.Tunnels, HTTPClient: fed.Guard.Client(), Log: log,
	})
	if err != nil {
		return nil, fmt.Errorf("machines: %w", err)
	}
	svc, err := machines.New(machines.Options{
		Store:   machines.NewStore(st, l),
		Servers: machines.NewServers(machines.ServersOptions{Store: st, Manager: fed.Manager, Snapshots: fed.Snapshots, Clients: factory}),
		Tunnels: fed.Tunnels, BaseURL: cfg.BaseURL, Audit: rec, Log: log,
	})
	if err != nil {
		return nil, fmt.Errorf("machines: %w", err)
	}
	log.Info("machine enrollment ready", "device_authorization", machines.DeviceAuthorizationPath, "token", machines.TokenPath,
		"activate", machines.ActivatePath)
	return svc, nil
}

// withMachineRoutes mounts the public machine endpoints (device
// authorization, token, enroll, the /machine/v1 API and the machine
// WebSocket) on the top-level mux, outside the portal's sessions: the
// machine token is their credential, and the WebSocket must see the raw
// connection like /tunnel/connect.
func withMachineRoutes(svc *machines.Service) muxExtra {
	return func(mux *http.ServeMux) {
		if svc != nil {
			svc.Mount(mux)
		}
	}
}

// withMachinePages mounts /activate, /machines and /admin/machines behind
// the portal's checks (signed-in active users, CSRF, admin for /admin).
func withMachinePages(svc *machines.Service) portalExtra {
	return func(_ *identity.Service, mount func(string, http.Handler), session func(*http.Request) (string, string), log *slog.Logger) {
		if svc == nil {
			return
		}
		id := func(r *http.Request) (string, string, bool) {
			userID, csrf := session(r)
			return userID, csrf, identity.PrincipalFrom(r.Context()).IsAdmin()
		}
		machines.NewPortal(svc, id, log).Mount(mount)
	}
}
