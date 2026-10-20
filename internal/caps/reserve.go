package caps

import (
	"context"
	"fmt"
	"time"

	"github.com/huynle/mcp-gateway/internal/store"
)

// Reserve is the cap check of one create, run inside the creating
// transaction before the insert: it takes the user's advisory lock for r
// (held until the transaction ends, so parallel creates queue), counts
// what the user already holds and refuses with *ExceededError at the
// limit (telling l). A nil Limiter or a limit of 0 (unlimited) never
// refuses. q must be the transaction (store.WithUser of userID).
func Reserve(ctx context.Context, q store.Querier, l Limiter, userID string, r Resource) error {
	if l == nil {
		return nil
	}
	limit := l.Limit(ctx, userID, r)
	if limit <= 0 {
		return nil
	}
	if err := store.LockUserResourceCap(ctx, q, userID, string(r)); err != nil {
		return err
	}
	var n int
	var err error
	switch r {
	case Servers:
		n, err = store.CountUserMCPServers(ctx, q, userID)
	case Tunnels:
		n, err = store.CountUserLiveMCPTunnels(ctx, q, userID)
	case PendingApprovals:
		n, err = store.CountUserPendingApprovals(ctx, q, userID, time.Now())
	case Machines:
		n, err = store.CountUserLiveMachines(ctx, q, userID)
	default:
		return fmt.Errorf("caps: reserve %q: use ReserveConnection", r)
	}
	if err != nil {
		return err
	}
	return check(ctx, l, userID, r, n, limit)
}

// ReserveConnection is Reserve for a new app connection to vendorAppID:
// both the per-app and the total cap apply (one lock covers both). Call it
// only before inserting a new connection row, never for a reconnect or a
// grant of more access to an existing one.
func ReserveConnection(ctx context.Context, q store.Querier, l Limiter, userID, vendorAppID string) error {
	if l == nil {
		return nil
	}
	perApp, total := l.Limit(ctx, userID, ConnectionsPerApp), l.Limit(ctx, userID, ConnectionsTotal)
	if perApp <= 0 && total <= 0 {
		return nil
	}
	if err := store.LockUserResourceCap(ctx, q, userID, "connections"); err != nil {
		return err
	}
	nApp, nTotal, err := store.CountUserConnections(ctx, q, userID, vendorAppID)
	if err != nil {
		return err
	}
	if perApp > 0 {
		if err := check(ctx, l, userID, ConnectionsPerApp, nApp, perApp); err != nil {
			return err
		}
	}
	if total > 0 {
		return check(ctx, l, userID, ConnectionsTotal, nTotal, total)
	}
	return nil
}

// Check is the cap decision for a store that counts itself (in-memory
// test stores): n is what userID already holds of r.
func Check(ctx context.Context, l Limiter, userID string, r Resource, n int) error {
	if l == nil {
		return nil
	}
	limit := l.Limit(ctx, userID, r)
	if limit <= 0 {
		return nil
	}
	return check(ctx, l, userID, r, n, limit)
}

func check(ctx context.Context, l Limiter, userID string, r Resource, n, limit int) error {
	if n < limit {
		return nil
	}
	l.Refused(ctx, userID, r, limit)
	return &ExceededError{Resource: r, Limit: limit}
}

// Usage counts what userID holds of every resource (ConnectionsPerApp:
// the fullest app). q runs as the user (row-level security).
func Usage(ctx context.Context, q store.Querier, userID string) (Values, error) {
	out := Values{}
	var err error
	if out[Servers], err = store.CountUserMCPServers(ctx, q, userID); err != nil {
		return nil, err
	}
	if out[Tunnels], err = store.CountUserLiveMCPTunnels(ctx, q, userID); err != nil {
		return nil, err
	}
	if out[PendingApprovals], err = store.CountUserPendingApprovals(ctx, q, userID, time.Now()); err != nil {
		return nil, err
	}
	if out[Machines], err = store.CountUserLiveMachines(ctx, q, userID); err != nil {
		return nil, err
	}
	if _, out[ConnectionsTotal], err = store.CountUserConnections(ctx, q, userID, ""); err != nil {
		return nil, err
	}
	if out[ConnectionsPerApp], err = store.MaxUserConnectionsPerApp(ctx, q, userID); err != nil {
		return nil, err
	}
	return out, nil
}
