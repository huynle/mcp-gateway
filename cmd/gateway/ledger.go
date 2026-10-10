package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/huynle/mcp-gateway/internal/approvals"
	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/jobs"
	"github.com/huynle/mcp-gateway/internal/ledger"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/observability"
)

// newLedger builds the write ledger (decision dovthftx) over st, reading
// GATEWAY_LEDGER_IDEMPOTENCY_WINDOW, GATEWAY_LEDGER_STALE_AFTER,
// GATEWAY_LEDGER_MAX_RECONCILE_ATTEMPTS and GATEWAY_LEDGER_MAX_RECONCILE_AGE
// from getenv. approvalSvc (nil without a key provider) consumes
// approvals inside the ledger's transaction; the registry resolves the
// reconciliation declarations; unresolved operations are reported through
// the log notifier (the Slack notifier joins the MultiNotifier in its own
// task).
func newLedger(cfg config.Config, st ledger.Store, registry *connectors.Registry, approvalSvc *approvals.Service, rec audit.Recorder, metrics *observability.Metrics, getenv func(string) string, log *slog.Logger) (*ledger.Service, error) {
	lcfg, err := ledger.ConfigFromEnv(getenv)
	if err != nil {
		return nil, fmt.Errorf("ledger: %w", err)
	}
	lcfg.BaseURL = cfg.BaseURL
	opts := ledger.Options{
		Registry: registry, Audit: rec, Metrics: metrics, Log: log,
		Notifier: ledger.MultiNotifier{ledger.LogNotifier{Log: log, BaseURL: cfg.BaseURL}},
	}
	if approvalSvc != nil {
		opts.Approvals = approvalSvc.LedgerConsumer()
	}
	svc, err := ledger.New(lcfg, st, opts)
	if err != nil {
		return nil, fmt.Errorf("ledger: %w", err)
	}
	log.Info("ledger ready", "idempotency_window", lcfg.IdempotencyWindow, "stale_after", lcfg.StaleAfter,
		"max_reconcile_attempts", lcfg.MaxReconcileAttempts, "max_reconcile_age", lcfg.MaxReconcileAge, "approvals", approvalSvc != nil)
	return svc, nil
}

// withLedgerStage inserts the ledger stage before ratelimit and, when the
// confirm handler is the approvals one, switches it to deferred
// consumption so the approval is consumed in the ledger's transaction.
func withLedgerStage(svc *ledger.Service) mcpExtra {
	return func(p *mcp.Pipeline, confirm mcp.ConfirmHandler) error {
		if svc == nil {
			return nil
		}
		if err := p.Insert(mcp.Before, mcp.StageRateLimit, mcp.LedgerStage(svc, nil)); err != nil {
			return err
		}
		if h, ok := confirm.(*approvals.ConfirmHandler); ok {
			h.DeferConsumption(true)
		}
		return nil
	}
}

// ledgerJobs are the background jobs the ledger needs: the reconciler
// and the stale in_progress sweep.
func ledgerJobs(svc *ledger.Service) []jobs.Job {
	if svc == nil {
		return nil
	}
	return []jobs.Job{jobs.NewReconcilerJob(svc, 0), jobs.NewStaleSweepJob(svc, 0)}
}

// withOperationsPage mounts GET /operations behind the portal's
// signed-in check.
func withOperationsPage(svc *ledger.Service) portalExtra {
	return func(_ *identity.Service, mountUser func(string, http.Handler), session func(*http.Request) (string, string), log *slog.Logger) {
		if svc == nil {
			return
		}
		ledger.NewPortal(svc, session, log).Mount(mountUser)
	}
}

// shutdownTimeout bounds the ledger's shutdown hook.
const shutdownTimeout = 5 * time.Second

// markInFlightUnknown runs after the server drained (or cut off) its
// requests: every write this replica still has in flight is marked
// unknown so the reconciler finds its outcome instead of the stale sweep
// having to guess two minutes later.
func markInFlightUnknown(svc *ledger.Service, log *slog.Logger) {
	if svc == nil || svc.InFlight() == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	n, err := svc.Shutdown(ctx)
	if err != nil {
		log.Error("ledger shutdown hook failed", "marked", n, "error", err)
	}
}
