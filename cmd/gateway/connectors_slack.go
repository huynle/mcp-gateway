package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/slack"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/store"
)

// registerSlack registers the Slack connector (app "slack") on the
// registry with the connections service as its account source and token
// source, installs its account binder for vendor "slack" and maps the
// app to the vendor. It runs whenever connections are mounted, whether or
// not an admin has registered the Slack vendor app yet: the tools are
// listed (so roles can grant them) and answer "no connected account"
// until a user connects a Slack account on /connections. Tokens are
// read per call through connSvc.TokenSource and never stored here.
//
// Marker reconciliation of post_message and reply_in_thread is opt-in
// through the vendor app's marker_reconcile=true extra, read once here:
// changing it takes effect at the next start.
func registerSlack(_ config.Config, registry *connectors.Registry, connSvc *connections.Service, log *slog.Logger) error {
	marker := slackMarkerReconcile(connSvc, log)
	c, err := slack.New(slack.Options{Tokens: connSvc.TokenSource, Accounts: connSvc, MarkerReconcile: marker})
	if err != nil {
		return fmt.Errorf("slack: %w", err)
	}
	if err := connectors.RegisterConnector(registry, c, connSvc); err != nil {
		return fmt.Errorf("slack: %w", err)
	}
	connSvc.RegisterBinder(connections.VendorSlack, slack.Binder{})
	connSvc.MapApp(slack.App, connections.VendorSlack)
	log.Info("slack connector registered", "app", slack.App, "tools", len(c.Tools()), "marker_reconcile", marker)
	return nil
}

// slackMarkerReconcile reads the Slack vendor app's marker_reconcile
// extra; false when the app is not registered yet or cannot be read
// (logged: the safe default is reconciliation none).
func slackMarkerReconcile(connSvc *connections.Service, log *slog.Logger) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	app, err := connSvc.VendorApp(ctx, connections.VendorSlack, "")
	switch {
	case errors.Is(err, store.ErrNotFound):
		return false
	case err != nil:
		log.Warn("slack vendor app could not be read; marker reconciliation stays off", "error", observability.RedactError(err))
		return false
	}
	return strings.EqualFold(strings.TrimSpace(app.Extra[slack.ExtraMarkerReconcile]), "true")
}
