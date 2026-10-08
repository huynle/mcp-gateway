package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/huynle/mcp-gateway/internal/approvals"
	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/jobs"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/store"
)

// newApprovals builds the approvals service (decision s0p05diu) over the
// store and the envelope-encryption key provider, reading
// GATEWAY_APPROVAL_TTL and GATEWAY_APPROVAL_WAIT from getenv. Without a
// key provider the stored arguments could not be encrypted, so the
// service is not built (nil, nil): confirmed calls then answer "approval
// required" with no approval flow (mcp.DefaultConfirmHandler) and the
// portal has no approval pages. The Slack notifier joins the
// MultiNotifier in a later task.
func newApprovals(cfg config.Config, st *store.Store, keys crypto.KeyProvider, rec audit.Recorder, metrics *observability.Metrics, getenv func(string) string, log *slog.Logger) (*approvals.Service, error) {
	if keys == nil {
		log.Warn("no key provider: approvals are not available; confirmed tool calls are refused")
		return nil, nil
	}
	acfg, err := approvals.ConfigFromEnv(getenv)
	if err != nil {
		return nil, fmt.Errorf("approvals: %w", err)
	}
	acfg.BaseURL = cfg.BaseURL
	svc, err := approvals.New(acfg, approvals.NewPostgresStore(st), keys, approvals.Options{
		Audit: rec, Metrics: metrics, Notifier: approvals.MultiNotifier{approvals.PortalNotifier{}}, Log: log,
	})
	if err != nil {
		return nil, fmt.Errorf("approvals: %w", err)
	}
	log.Info("approvals ready", "ttl", acfg.TTL, "wait", acfg.Wait, "portal", svc.PortalURL())
	return svc, nil
}

// startJobs registers the background jobs and runs them on one replica
// under job_locks leases until ctx ends. Nothing is started when there is
// no job to run.
func startJobs(ctx context.Context, st *store.Store, log *slog.Logger, list ...jobs.Job) (*jobs.Runner, error) {
	if len(list) == 0 {
		return nil, nil
	}
	runner := jobs.NewRunner(jobs.NewPostgresLocker(st), jobs.Options{Log: log})
	for _, j := range list {
		if err := runner.Register(j); err != nil {
			return nil, fmt.Errorf("jobs: %w", err)
		}
	}
	go func() {
		if err := runner.Run(ctx); err != nil {
			log.Error("jobs runner stopped", "error", err)
		}
	}()
	log.Info("background jobs started", "holder", runner.Holder(), "jobs", runner.Names())
	return runner, nil
}

// getenv is what newApprovals reads settings from in production.
var getenv = os.Getenv
