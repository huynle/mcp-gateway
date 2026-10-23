package mcp

import (
	"context"
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
//   - none at all: no_account, whatever the argument said.
//
// Tools marked NoAccount (list_accounts, secrets.request) skip the stage. The chosen
// account's ID and label go on the CallContext for audit.
const StageAccount = "account"

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
		if err != nil {
			log.Error("account lookup failed", "event", "mcp.account_lookup_failed", "app", app,
				"error", observability.RedactError(err), observability.RequestIDAttr(ctx))
			return connectors.Result{}, NewToolError(CodeInternal, "account_lookup_failed", "could not look up connected accounts for "+app)
		}
		var chosen connectors.Account
		switch {
		case len(owned) == 0:
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
