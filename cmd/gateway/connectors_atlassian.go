package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/atlassian"
)

// registerAtlassian registers the two Atlassian connector apps ("jira"
// and "confluence") on the registry with the connections service as
// their account source, token source and site source, installs the
// account binder for vendor "atlassian" and maps both apps to the
// vendor. Like GitHub it runs whenever connections are mounted, before
// any admin registers the Atlassian vendor app: the tools are listed
// (so roles can grant them) and answer "no connected account" until a
// user connects an Atlassian account on /connections. Tokens are read
// per call through connSvc.TokenSource and never stored here; the cloud
// id of the connection's site comes from the connection's external
// account id ("<account id>@<cloud id>", atlassian.Binder) through
// atlassianSites.
func registerAtlassian(_ config.Config, registry *connectors.Registry, connSvc *connections.Service, log *slog.Logger) error {
	opts := atlassian.Options{Tokens: connSvc.TokenSource, Sites: atlassianSites(connSvc)}
	for _, app := range []string{atlassian.JiraApp, atlassian.ConfluenceApp} {
		c, err := atlassian.New(app, opts)
		if err != nil {
			return fmt.Errorf("%s: %w", app, err)
		}
		if err := connectors.RegisterConnector(registry, c, connSvc); err != nil {
			return fmt.Errorf("%s: %w", app, err)
		}
		connSvc.MapApp(app, connections.VendorAtlassian)
		log.Info("atlassian connector registered", "app", app, "vendor", connections.VendorAtlassian, "tools", len(c.Tools()))
	}
	connSvc.RegisterBinder(connections.VendorAtlassian, atlassian.Binder{})
	return nil
}

// atlassianSites resolves a connection's bound site from the connections
// service: the cloud id is parsed from the external account id the
// binder wrote and the site URL (for links in results) from the display
// name's "<name> @ <url>" suffix, when present. The connection must be
// one of the user's own (row-level security hides the others) and of
// vendor atlassian.
func atlassianSites(connSvc *connections.Service) atlassian.SiteSourceFunc {
	return func(ctx context.Context, userID, connectionID string) (atlassian.Site, error) {
		list, err := connSvc.Connections(ctx, userID)
		if err != nil {
			return atlassian.Site{}, err
		}
		for _, c := range list {
			if c.ID != connectionID || c.Vendor != connections.VendorAtlassian {
				continue
			}
			_, cloudID, ok := atlassian.ParseExternalAccountID(c.ExternalAccountID)
			if !ok {
				return atlassian.Site{}, fmt.Errorf("atlassian: connection %s has no cloud id in its external account id", connectionID)
			}
			return atlassian.Site{CloudID: cloudID, URL: siteURLFromDisplayName(c.DisplayName)}, nil
		}
		return atlassian.Site{}, fmt.Errorf("atlassian: connection %s not found for this user", connectionID)
	}
}

// siteURLFromDisplayName returns the http(s) URL after the last " @ " of
// a display name the binder wrote, "" when there is none.
func siteURLFromDisplayName(name string) string {
	i := strings.LastIndex(name, " @ ")
	if i < 0 {
		return ""
	}
	u := strings.TrimSpace(name[i+3:])
	if !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
		return ""
	}
	return u
}
