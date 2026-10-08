package ledger

import (
	"context"
	"errors"
	"log/slog"
	"strings"
)

// Notifier tells the user an operation could not be verified (decision
// dovthftx: "the user is notified: verify in the app"). It is separate
// from approvals.Notifier; the Slack notifier task may implement both.
// Errors are logged by the reconciler and never change the operation.
type Notifier interface {
	NotifyUnresolved(ctx context.Context, op Operation) error
}

// LogNotifier is the default: one warn line per unresolved operation
// (operation id, tool, user, portal URL; never arguments).
type LogNotifier struct {
	Log     *slog.Logger
	BaseURL string
}

// NotifyUnresolved implements Notifier.
func (n LogNotifier) NotifyUnresolved(ctx context.Context, op Operation) error {
	log := n.Log
	if log == nil {
		log = slog.Default()
	}
	log.WarnContext(ctx, "write could not be verified; the user must check the app", "event", "ledger.unresolved",
		"operation_id", op.ID, "tool", op.Tool, "user_id", op.UserID, "account_id", op.AccountID,
		"portal_url", OperationsURL(n.BaseURL))
	return nil
}

// MultiNotifier fans out to every notifier; one failing channel does not
// stop the others and the errors are joined.
type MultiNotifier []Notifier

// NotifyUnresolved implements Notifier.
func (m MultiNotifier) NotifyUnresolved(ctx context.Context, op Operation) error {
	var errs []error
	for _, n := range m {
		if n == nil {
			continue
		}
		if err := n.NotifyUnresolved(ctx, op); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// OperationsURL is where the user sees their operations: BaseURL +
// "/operations".
func OperationsURL(baseURL string) string { return strings.TrimRight(baseURL, "/") + "/operations" }
