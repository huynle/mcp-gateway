package main

import (
	"context"
	"log/slog"

	"github.com/huynle/mcp-gateway/internal/account"
	"github.com/huynle/mcp-gateway/internal/federation/connector"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/portal"
	"github.com/huynle/mcp-gateway/internal/store"
)

// accountLifecycle builds the account lifecycle service (data export,
// account deletion) over the portal's identity service, whose OnDisable
// hooks deletion runs.
type accountLifecycle func(idSvc *identity.Service) portal.Account

// newAccountLifecycle wires internal/account over the store. After a
// deletion removed private MCP servers the federation reloads at once so
// their tools leave the registry (other replicas catch up on their
// periodic reload; a deleted tunnel drops at its next heartbeat).
func newAccountLifecycle(st *store.Store, fed *connector.Federation, log *slog.Logger) accountLifecycle {
	return func(idSvc *identity.Service) portal.Account {
		opts := account.Options{Log: log}
		if fed != nil {
			opts.OnDeleted = func(ctx context.Context, _ string, d *store.UserDeletion) {
				if len(d.ServerIDs) > 0 {
					// Errors are logged by ServerChanged; the periodic reload retries.
					_ = fed.Manager.ServerChanged(context.WithoutCancel(ctx), d.ServerIDs[0])
				}
			}
		}
		return account.New(st, idSvc, opts)
	}
}
