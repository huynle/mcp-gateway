package main

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/huynle/mcp-gateway/internal/approvals"
	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/slack"
)

// newSlackNotifier builds the Slack DM notifier over the connections
// service (which answers who is connected to the company Slack and holds
// the Slack vendor app's bot token). Without the connections module
// (no key provider) there is nothing to look up and nil is returned;
// approvals stay portal-only. The bot token itself is entered by an
// admin on /admin/vendor-apps/slack; until then every DM attempt for a
// connected user is a logged, non-fatal failure. Call SetArguments with
// the approvals service once it exists so the DM carries the argument
// summary.
func newSlackNotifier(cfg config.Config, connSvc *connections.Service, log *slog.Logger) (*approvals.SlackNotifier, error) {
	if connSvc == nil {
		return nil, nil
	}
	n, err := approvals.NewSlackNotifier(approvals.SlackNotifierOptions{
		Identity: connSvc, Secrets: connSvc, PortalURL: cfg.BaseURL + "/approvals", Log: log,
	})
	if err != nil {
		return nil, fmt.Errorf("slack notifier: %w", err)
	}
	return n, nil
}

// newSlackInteractions builds the handler for POST /slack/interactions
// (Approve / Deny button presses, verified with the Slack vendor app's
// signing secret before anything is parsed). nil when approvals or
// connections are not available.
func newSlackInteractions(approvalSvc *approvals.Service, connSvc *connections.Service, rec audit.Recorder, log *slog.Logger) (http.Handler, error) {
	if approvalSvc == nil || connSvc == nil {
		return nil, nil
	}
	h, err := slack.NewInteractionsHandler(slack.Options{Approvals: approvalSvc, Identity: connSvc, Secrets: connSvc, Audit: rec, Log: log})
	if err != nil {
		return nil, fmt.Errorf("slack interactions: %w", err)
	}
	log.Info("slack interactions endpoint ready", "path", "/slack/interactions")
	return h, nil
}

// notifiers builds the approvals notifier list: the portal always, then
// every non-nil extra (a typed nil *SlackNotifier is skipped).
func notifiers(extra ...approvals.Notifier) approvals.MultiNotifier {
	list := approvals.MultiNotifier{approvals.PortalNotifier{}}
	for _, n := range extra {
		if sn, ok := n.(*approvals.SlackNotifier); ok && sn == nil {
			continue
		}
		if n != nil {
			list = append(list, n)
		}
	}
	return list
}
