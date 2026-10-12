//go:build integration || e2e || security

package security

import (
	"context"
	"sync/atomic"

	"github.com/huynle/mcp-gateway/internal/approvals"
)

// countingNotifier counts approval notifications: every approval the
// gateway creates is announced through the Notifier (the Slack DM in
// production), so a count of zero proves no approval prompt went out.
type countingNotifier struct{ n atomic.Int64 }

func (c *countingNotifier) Notify(context.Context, approvals.Approval) error {
	c.n.Add(1)
	return nil
}

func (c *countingNotifier) count() int64 { return c.n.Load() }
