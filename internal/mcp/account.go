package mcp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/observability"
)

// StageAccount is the account-resolution stage, inserted after strip
// (decision dovthftx). Given the principal's accounts for the tool's app:
//
//   - Call.Account set: it must be one of them, else account_not_found
//     (the same error for another user's account, a nonexistent one and
//     one for another app: the caller learns nothing it does not own);
//   - unset and exactly one account: it is chosen;
//   - unset and several: account_required, listing the caller's own IDs
//     and display names (they are the caller's; list_accounts shows the
//     same);
//   - none at all: no_account, whatever the argument said; a source
//     implementing MissingAccounter may answer instead (same class, e.g.
//     a -32042 with the link where the user connects).
//
// A *ToolError from the source is passed through as it is; any other
// failure is account_lookup_failed (the cause is only logged).
//
// Tools marked NoAccount (list_accounts, secrets.request) skip the stage. The chosen
// account's ID and label go on the CallContext for audit.
const StageAccount = "account"

// MissingAccounter is the optional interface of an AccountSource that can
// explain a missing account (the federation's per-user servers, behind
// GATEWAY_CREDENTIAL_LINKS_ENABLED: a -32042 with the connection link).
// MissingAccount returns a *ToolError to answer instead of no_account, or
// nil to keep no_account. It must not reveal anything the caller may not
// see (a server they cannot use gets nil). Wrapping sources forward it.
type MissingAccounter interface {
	MissingAccount(ctx context.Context, userID, app string) error
}

// AccountStage builds the stage over src. A nil src is a programming
// error: DefaultPipeline only adds the stage when PipelineDeps.Accounts is
// set.
func AccountStage(src connectors.AccountSource, log *slog.Logger) Stage {
	if log == nil {
		log = slog.Default()
	}
	return stage{StageAccount, func(ctx context.Context, cc *CallContext, next Next) (connectors.Result, error) {
		if cc.Tool == nil {
			return connectors.Result{}, ErrToolNotFound(cc.Name)
		}
		if cc.Tool.NoAccount {
			return next(ctx)
		}
		app := cc.Tool.App
		owned, err := src.ListAccounts(ctx, cc.Principal.UserID, app)
		var te *ToolError
		if errors.As(err, &te) {
			return connectors.Result{}, te
		}
		if err != nil {
			log.Error("account lookup failed", "event", "mcp.account_lookup_failed", "app", app,
				"error", observability.RedactError(err), observability.RequestIDAttr(ctx))
			return connectors.Result{}, NewToolError(CodeInternal, "account_lookup_failed", "could not look up connected accounts for "+app)
		}
		var chosen connectors.Account
		switch {
		case len(owned) == 0:
			if te := missingAccount(ctx, src, cc.Principal.UserID, app, log); te != nil {
				return connectors.Result{}, te
			}
			return connectors.Result{}, NewToolError(CodeNoAccount, "no_account", "no connected account for "+app)
		case cc.Call.Account != "":
			found := false
			for _, a := range owned {
				if a.ID == cc.Call.Account {
					chosen, found = a, true
					break
				}
			}
			if !found {
				return connectors.Result{}, NewToolError(CodeInvalidParams, "account_not_found",
					fmt.Sprintf("unknown account %q for %s", cc.Call.Account, app))
			}
		case len(owned) == 1:
			chosen = owned[0]
		default:
			return connectors.Result{}, NewToolError(CodeInvalidParams, "account_required", accountRequiredMessage(app, owned))
		}
		cc.Call.Account = chosen.ID
		cc.AccountID = chosen.ID
		cc.AccountLabel = string(chosen.Label)
		cc.AccountScopes = chosen.Scopes
		return next(ctx)
	}}
}

// missingAccount asks src's MissingAccounter hook, if any, for the answer
// to a call without an account; nil keeps no_account.
func missingAccount(ctx context.Context, src connectors.AccountSource, userID, app string, log *slog.Logger) *ToolError {
	ma, ok := src.(MissingAccounter)
	if !ok {
		return nil
	}
	err := ma.MissingAccount(ctx, userID, app)
	var te *ToolError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &te):
		return te
	}
	log.Warn("missing account hook failed", "event", "mcp.missing_account_failed", "app", app,
		"error", observability.RedactError(err), observability.RequestIDAttr(ctx))
	return nil
}

// accountRequiredMessage lists the caller's own accounts for app, sorted
// by ID, so the model can pick one.
func accountRequiredMessage(app string, owned []connectors.Account) string {
	sorted := append([]connectors.Account(nil), owned...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	parts := make([]string, 0, len(sorted))
	for _, a := range sorted {
		s := a.ID
		if a.DisplayName != "" {
			s += " (" + a.DisplayName
			if a.Label != "" {
				s += ", " + string(a.Label)
			}
			s += ")"
		} else if a.Label != "" {
			s += " (" + string(a.Label) + ")"
		}
		parts = append(parts, s)
	}
	return fmt.Sprintf("account required: you have %d %s accounts; set \"account\" to one of: %s",
		len(sorted), app, strings.Join(parts, ", "))
}
