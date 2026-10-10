package approvals

import (
	"context"
	"errors"
)

// Notifier tells the user a new approval is waiting (decision s0p05diu).
// The portal implementation is a no-op: the row's existence is the
// notification, the user sees it at /approvals. The Slack DM notifier is
// a later task; a Teams one later still. Notify errors are logged by the
// service and never fail the approval.
type Notifier interface {
	Notify(ctx context.Context, a Approval) error
}

// PortalNotifier is the always-present notifier: nothing to send, the
// approval is already visible in the portal.
type PortalNotifier struct{}

// Notify implements Notifier.
func (PortalNotifier) Notify(context.Context, Approval) error { return nil }

// MultiNotifier fans out to every notifier and joins their errors; one
// failing channel does not stop the others.
type MultiNotifier []Notifier

// Notify implements Notifier.
func (m MultiNotifier) Notify(ctx context.Context, a Approval) error {
	var errs []error
	for _, n := range m {
		if n == nil {
			continue
		}
		if err := n.Notify(ctx, a); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
