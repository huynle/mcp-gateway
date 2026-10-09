package main

import (
	"fmt"
	"log/slog"

	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/microsoft"
)

// registerMicrosoft registers the Microsoft 365 connector (app
// "microsoft") on the registry with the connections service as its
// account source (also handed to the connector so Call can refuse tools
// whose Graph permissions the account has not granted: personal
// accounts never carry the Teams ones) and token source, installs its
// account binder for vendor "microsoft" and maps the app to the vendor.
// Like GitHub it runs whenever connections are mounted, before an admin
// registers the Microsoft vendor app: the tools are listed and answer
// "no connected account" until a user connects an account on
// /connections. Tokens are read per call through connSvc.TokenSource and
// never stored here. Graph's global endpoint is used
// (microsoft.Options.BaseURL stays graph.microsoft.com); the binder
// follows the vendor app's UserInfoURL already.
func registerMicrosoft(_ config.Config, registry *connectors.Registry, connSvc *connections.Service, log *slog.Logger) error {
	c, err := microsoft.New(microsoft.Options{Tokens: connSvc.TokenSource, Accounts: connSvc})
	if err != nil {
		return fmt.Errorf("microsoft: %w", err)
	}
	if err := connectors.RegisterConnector(registry, c, connSvc); err != nil {
		return fmt.Errorf("microsoft: %w", err)
	}
	connSvc.RegisterBinder(connections.VendorMicrosoft, microsoft.Binder{})
	connSvc.MapApp(microsoft.App, connections.VendorMicrosoft)
	log.Info("microsoft connector registered", "app", microsoft.App, "tools", len(c.Tools()))
	return nil
}
