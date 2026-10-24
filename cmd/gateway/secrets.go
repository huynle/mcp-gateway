package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/federation/connector"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/jobs"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/secrets"
	"github.com/huynle/mcp-gateway/internal/store"
)

// secretsFeature is the wired ephemeral-secrets feature
// (docs/plans/2026-10-23-ephemeral-secrets-design.md): the service, the
// targets secrets bind to (the federation's tools) and what the stage,
// pages and use hook need. nil means the feature is off.
type secretsFeature struct {
	svc     *secrets.Service
	targets secrets.Targets
	st      *store.Store
	rec     audit.Recorder
	baseURL string
	log     *slog.Logger
}

// newSecrets builds the feature when GATEWAY_SECRETS_ENABLED is true and
// registers the secrets app (secrets.request) in registry. visibility
// must be the /mcp pipeline's (so a secret can only be requested for a
// tool the caller sees). It stays off (nil, nil) with a warning when
// there is no key provider (values could not be encrypted) or no
// federation (no tool a secret can bind to), as approvals do without a
// key provider; only an unparsable flag fails startup.
func newSecrets(cfg config.Config, st *store.Store, keys crypto.KeyProvider, fed *connector.Federation, registry *connectors.Registry, visibility mcp.Visibility, rec audit.Recorder, getenv func(string) string, log *slog.Logger) (*secretsFeature, error) {
	scfg, err := secrets.ConfigFromEnv(getenv)
	if err != nil {
		return nil, fmt.Errorf("secrets: %w", err)
	}
	if !scfg.Enabled {
		return nil, nil
	}
	if keys == nil {
		log.Warn(secrets.EnvEnabled + " is set but there is no key provider: ephemeral secrets stay off (values cannot be encrypted)")
		return nil, nil
	}
	if fed == nil {
		log.Warn(secrets.EnvEnabled + " is set but user-added MCP servers are not mounted: ephemeral secrets stay off (nothing to bind them to)")
		return nil, nil
	}
	svc, err := secrets.New(secrets.NewPostgresStore(st), keys, secrets.Options{Log: log})
	if err != nil {
		return nil, fmt.Errorf("secrets: %w", err)
	}
	app, err := secrets.NewConnector(secrets.ConnectorDeps{
		Service: svc, Tools: registry, Visibility: visibility, Targets: fed.Manager, BaseURL: cfg.BaseURL, Log: log,
	})
	if err != nil {
		return nil, fmt.Errorf("secrets: %w", err)
	}
	if err := app.Register(registry); err != nil {
		return nil, fmt.Errorf("secrets: %w", err)
	}
	log.Info("ephemeral secrets ready", "app", secrets.App, "default_ttl", secrets.DefaultTTL, "link_ttl", secrets.LinkTTL)
	return &secretsFeature{svc: svc, targets: fed.Manager, st: st, rec: rec, baseURL: cfg.BaseURL, log: log}, nil
}

// withSecretStage inserts the secret stage immediately before dispatch
// (after policy, ledger and rate limit; design correction 3).
func withSecretStage(f *secretsFeature) mcpExtra {
	return func(p *mcp.Pipeline, _ mcp.ConfirmHandler) error {
		if f == nil {
			return nil
		}
		stage, err := secrets.NewStage(secrets.StageOptions{
			Service: f.svc, Targets: f.targets, BaseURL: f.baseURL, Hook: f, Log: f.log,
		})
		if err != nil {
			return err
		}
		return p.Insert(mcp.Before, mcp.StageDispatch, stage)
	}
}

// withSecretPages mounts /s/{id} and /secrets behind the portal's sign-in
// and CSRF checks, with the portal's own 404 for unknown or foreign links
// and the per-address limit on failed lookups, and registers the disable
// hook that revokes a disabled user's secrets.
func withSecretPages(f *secretsFeature) portalExtra {
	return func(idSvc *identity.Service, mount func(string, http.Handler), session func(*http.Request) (string, string), log *slog.Logger, notFound http.Handler) {
		if f == nil {
			return
		}
		secrets.NewPortal(f.svc, session, secrets.PortalOptions{
			Log:            log,
			Servers:        secrets.ServerNamerFunc(f.serverName),
			Harnesses:      secrets.HarnessNamerFunc(f.harnessName),
			Audit:          f.rec,
			NotFound:       notFound,
			FailureLimiter: secrets.NewAddressLimiter(secrets.EntryFailureBurst, secrets.EntryFailureWindow, nil),
		}).Mount(mount)
		idSvc.OnDisable(f.svc.OnDisableUser)
	}
}

// secretsJobs is the expiry job (wipes ciphertext that ran out).
func secretsJobs(f *secretsFeature) []jobs.Job {
	if f == nil {
		return nil
	}
	return []jobs.Job{f.svc.ExpiryJob(0)}
}

// serverName is the bound server's name as the owner sees it.
func (f *secretsFeature) serverName(ctx context.Context, owner, serverID string) (string, error) {
	var name string
	err := f.st.WithUser(ctx, owner, func(tx store.Tx) error {
		s, err := store.GetMCPServer(ctx, tx, serverID)
		if err != nil {
			return err
		}
		name = s.Name
		return nil
	})
	return name, err
}

// harnessName names the requesting harness: the principal's TokenID is a
// tokens row id for mgw_ tokens and the refresh-token family id for OAuth
// harnesses, so it is the token's name or the OAuth client's name.
func (f *secretsFeature) harnessName(ctx context.Context, owner, harnessID string) (string, error) {
	var name string
	err := f.st.WithUser(ctx, owner, func(tx store.Tx) error {
		tok, err := tx.Tokens().Get(ctx, harnessID)
		switch {
		case err == nil && tok.UserID == owner:
			name = tok.Name
			return nil
		case err != nil && !errors.Is(err, store.ErrNotFound):
			return err
		}
		families, err := store.ListOAuthHarnesses(ctx, tx, owner)
		if err != nil {
			return err
		}
		for _, h := range families {
			if h.FamilyID == harnessID {
				name = h.ClientName
				return nil
			}
		}
		return store.ErrNotFound
	})
	return name, err
}

// SecretUsed implements secrets.UseHook: audit "secret.used" with the
// record id and label only (never the value or the handle).
func (f *secretsFeature) SecretUsed(ctx context.Context, u secrets.Use) {
	if f.rec == nil {
		return
	}
	ev := audit.Event{
		UserID:  u.UserID,
		TokenID: u.HarnessID,
		ResourceIdentity: map[string]string{
			"action": "secret.used", "secret_id": u.SecretID, "label": u.Label, "tool": u.Tool,
		},
		Outcome:   "succeeded",
		RequestID: observability.RequestIDFromContext(ctx),
	}
	if err := f.rec.Record(ctx, ev); err != nil {
		f.log.Error("secret use not audited", "event", "secrets.audit_failed", "action", "secret.used",
			"secret_id", u.SecretID, "error", observability.RedactError(err), observability.RequestIDAttr(ctx))
	}
}
