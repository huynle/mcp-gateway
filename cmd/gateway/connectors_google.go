package main

import (
	"fmt"
	"log/slog"

	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

// registerGoogle registers the Google connector's three apps (calendar,
// tasks, gmail) on the registry with the connections service as their
// account source (also consulted for the account's granted scopes: a
// tool whose scope was declined under granular consent answers
// scope_required) and token source, installs the Google account binder
// for vendor "google" (both the internal and the external app) and maps
// each app to the vendor so one Google connection serves all three. It
// runs whenever connections are mounted, whether or not an admin has
// registered a Google vendor app yet: the tools are listed (so roles
// can grant them) and answer "no connected account" until a user
// connects a Google account on /connections. Tokens are read per call
// through connSvc.TokenSource and never stored here.
func registerGoogle(_ config.Config, registry *connectors.Registry, connSvc *connections.Service, log *slog.Logger) error {
	c, err := google.New(google.Options{Tokens: connSvc.TokenSource, Accounts: connSvc})
	if err != nil {
		return fmt.Errorf("google: %w", err)
	}
	tools := 0
	for _, app := range c.Apps() {
		if err := connectors.RegisterConnector(registry, app, connSvc); err != nil {
			return fmt.Errorf("google: %s: %w", app.App(), err)
		}
		connSvc.MapApp(app.App(), connections.VendorGoogle)
		// Google's broader scopes imply narrower ones (google.Grants);
		// the pipeline's scope stage uses the same semantics.
		registry.SetScopeCoverage(app.App(), google.Grants)
		tools += len(app.Tools())
	}
	connSvc.RegisterBinder(connections.VendorGoogle, google.Binder{})
	log.Info("google connector registered", "vendor", connections.VendorGoogle, "apps", google.Apps, "tools", tools)
	return nil
}
