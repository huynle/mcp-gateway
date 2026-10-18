package store

import (
	"context"
	"fmt"
	"time"
)

// MCP tunnel holders (migration 00026): which replica holds a tunnel's
// live connection, for the cross-replica relay. gateway_jobs only (run
// these through WithJobs): the tunnel endpoint and the relay act before
// any user is known.

// MCPTunnelHolder is a tunnel's current holder joined with the tunnel's
// liveness columns.
type MCPTunnelHolder struct {
	TunnelID  string
	Holder    string // the holder's relay base URL
	Epoch     int64  // distinct for every connection, on any replica
	ClaimedAt time.Time
	// LastSeenAt and Revoked come from mcp_tunnels.
	LastSeenAt *time.Time
	Revoked    bool
}

// ClaimMCPTunnelHolder records holder as the tunnel's holder with a fresh
// epoch (overwriting any previous holder), touches the tunnel's
// last_seen_at and returns the epoch. ErrNotFound when the tunnel does
// not exist.
func ClaimMCPTunnelHolder(ctx context.Context, q Querier, tunnelID, holder string, at time.Time) (int64, error) {
	tag, err := q.Exec(ctx, `UPDATE mcp_tunnels SET last_seen_at = $2 WHERE id = $1`, tunnelID, at)
	if err != nil {
		return 0, fmt.Errorf("store: claim mcp tunnel holder: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return 0, ErrNotFound
	}
	var epoch int64
	err = q.QueryRow(ctx, `
		INSERT INTO mcp_tunnel_holders (tunnel_id, holder, epoch, claimed_at)
		VALUES ($1, $2, nextval('mcp_tunnel_holder_epoch_seq'), $3)
		ON CONFLICT (tunnel_id) DO UPDATE
			SET holder = EXCLUDED.holder, epoch = EXCLUDED.epoch, claimed_at = EXCLUDED.claimed_at
		RETURNING epoch`, tunnelID, holder, at).Scan(&epoch)
	if err != nil {
		return 0, fmt.Errorf("store: claim mcp tunnel holder: %w", err)
	}
	return epoch, nil
}

// ReleaseMCPTunnelHolder deletes the tunnel's holder row if it still
// carries epoch (a newer connection elsewhere keeps its row). It reports
// whether a row was deleted.
func ReleaseMCPTunnelHolder(ctx context.Context, q Querier, tunnelID string, epoch int64) (bool, error) {
	tag, err := q.Exec(ctx, `DELETE FROM mcp_tunnel_holders WHERE tunnel_id = $1 AND epoch = $2`, tunnelID, epoch)
	if err != nil {
		return false, fmt.Errorf("store: release mcp tunnel holder: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// GetMCPTunnelHolder returns the tunnel's holder row with the tunnel's
// last_seen_at and revocation; ErrNotFound when there is none. The caller
// decides staleness.
func GetMCPTunnelHolder(ctx context.Context, q Querier, tunnelID string) (*MCPTunnelHolder, error) {
	var h MCPTunnelHolder
	err := q.QueryRow(ctx, `
		SELECT h.tunnel_id, h.holder, h.epoch, h.claimed_at, t.last_seen_at, t.revoked_at IS NOT NULL
		FROM mcp_tunnel_holders h JOIN mcp_tunnels t ON t.id = h.tunnel_id
		WHERE h.tunnel_id = $1`, tunnelID).
		Scan(&h.TunnelID, &h.Holder, &h.Epoch, &h.ClaimedAt, &h.LastSeenAt, &h.Revoked)
	if err != nil {
		return nil, notFound(err)
	}
	return &h, nil
}
