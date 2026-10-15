package main

import (
	"fmt"
	"log/slog"

	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/github"
)

// registerGitHub registers the GitHub connector (app "github") on the
// registry with the connections service as its account source and token
// source, installs its account binder for vendor "github" and maps the
// app to the vendor. It runs whenever connections are mounted, whether or
// not an admin has registered the GitHub vendor app yet: the tools are
// listed (so roles can grant them) and answer "no connected account"
// until a user connects a GitHub account on /connections. Tokens are
// read per call through connSvc.TokenSource and never stored here.
// GHES is not configured yet (github.Options.BaseURL stays api.github.com);
// the binder follows the vendor app's UserInfoURL already.
func registerGitHub(_ config.Config, registry *connectors.Registry, connSvc *connections.Service, log *slog.Logger) error {
	c, err := github.New(github.Options{Tokens: connSvc.TokenSource})
	if err != nil {
		return fmt.Errorf("github: %w", err)
	}
	if err := connectors.RegisterConnector(registry, c, connSvc); err != nil {
		return fmt.Errorf("github: %w", err)
	}
	registry.SetScopeCoverage(github.App, github.ScopeCovered)
	connSvc.RegisterBinder(connections.VendorGitHub, github.Binder{})
	connSvc.MapApp(github.App, connections.VendorGitHub)
	log.Info("github connector registered", "app", github.App, "tools", len(c.Tools()))
	return nil
}
