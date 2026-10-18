package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Per-user resource caps (migration 00028). The settings live in
// gateway_resource_caps (organization, one row) and
// gateway_user_resource_caps (administrator overrides); both are read and
// written through WithJobs. The lock and count helpers run inside the
// creating transaction (WithUser) so a cap cannot be exceeded by
// concurrent creates: LockUserResourceCap serialises one user's creates of
// one resource until the transaction ends, then the count sees every
// committed row.

// ResourceCapColumns are the capped resources' column names.
var ResourceCapColumns = []string{"servers", "tunnels", "connections_per_app", "connections_total", "pending_approvals"}

// ErrUnknownResourceCap is a column outside ResourceCapColumns.
var ErrUnknownResourceCap = errors.New("store: unknown resource cap")

// capLockClass is the first key of the two-key advisory lock (ASCII
// "caps"); the single-bigint key space the migration lock uses is separate.
const capLockClass = 0x63617073

func capSelect() string { return strings.Join(ResourceCapColumns, ", ") }

func scanCaps(row interface{ Scan(dest ...any) error }, extra ...any) (map[string]int, error) {
	vals := make([]*int, len(ResourceCapColumns))
	dest := append([]any{}, extra...)
	for i := range vals {
		dest = append(dest, &vals[i])
	}
	if err := row.Scan(dest...); err != nil {
		return nil, err
	}
	out := map[string]int{}
	for i, v := range vals {
		if v != nil {
			out[ResourceCapColumns[i]] = *v
		}
	}
	return out, nil
}

// GetGatewayResourceCaps returns the organization values (absent = NULL,
// inherit the ENV default) and the settings version.
func GetGatewayResourceCaps(ctx context.Context, q Querier) (map[string]int, int64, error) {
	var version int64
	out, err := scanCaps(q.QueryRow(ctx, `SELECT version, `+capSelect()+` FROM gateway_resource_caps WHERE singleton`), &version)
	if errors.Is(err, pgx.ErrNoRows) {
		// No row (never seeded or truncated): every value inherits.
		return map[string]int{}, 0, nil
	}
	if err != nil {
		return nil, 0, fmt.Errorf("store: get resource caps: %w", err)
	}
	return out, version, nil
}

// ListGatewayUserResourceCaps returns every user's administrator overrides.
func ListGatewayUserResourceCaps(ctx context.Context, q Querier) (map[string]map[string]int, error) {
	rows, err := q.Query(ctx, `SELECT user_id, `+capSelect()+` FROM gateway_user_resource_caps ORDER BY user_id`)
	if err != nil {
		return nil, fmt.Errorf("store: list user resource caps: %w", err)
	}
	defer rows.Close()
	out := map[string]map[string]int{}
	for rows.Next() {
		var user string
		v, err := scanCaps(rows, &user)
		if err != nil {
			return nil, err
		}
		out[user] = v
	}
	return out, rows.Err()
}

// patchSet builds "col = $n" assignments for patch (nil = NULL), starting
// at placeholder first; columns are checked against ResourceCapColumns.
func patchSet(patch map[string]*int, first int) ([]string, []any, error) {
	if len(patch) == 0 {
		return nil, nil, ErrUnknownResourceCap
	}
	var set []string
	var args []any
	for _, col := range ResourceCapColumns {
		v, ok := patch[col]
		if !ok {
			continue
		}
		args = append(args, v)
		set = append(set, fmt.Sprintf("%s = $%d", col, first+len(args)-1))
	}
	for col := range patch {
		if !slices.Contains(ResourceCapColumns, col) {
			return nil, nil, ErrUnknownResourceCap
		}
	}
	return set, args, nil
}

// PatchGatewayResourceCaps changes the given organization values in one
// statement (a nil value clears it); the others are kept.
func PatchGatewayResourceCaps(ctx context.Context, q Querier, patch map[string]*int, actor string) error {
	set, args, err := patchSet(patch, 2)
	if err != nil {
		return err
	}
	if _, err := q.Exec(ctx, `INSERT INTO gateway_resource_caps (singleton) VALUES (true) ON CONFLICT (singleton) DO NOTHING`); err != nil {
		return fmt.Errorf("store: patch resource caps: %w", err)
	}
	_, err = q.Exec(ctx, `UPDATE gateway_resource_caps SET `+strings.Join(set, ", ")+`, version = version + 1, updated_by = $1, updated_at = now() WHERE singleton`,
		append([]any{nullString(actor)}, args...)...)
	if err != nil {
		return fmt.Errorf("store: patch resource caps: %w", err)
	}
	return nil
}

// PatchGatewayUserResourceCaps changes one user's overrides; a row left
// without any override is deleted.
func PatchGatewayUserResourceCaps(ctx context.Context, q Querier, userID string, patch map[string]*int, actor string) error {
	set, args, err := patchSet(patch, 3)
	if err != nil {
		return err
	}
	if _, err := q.Exec(ctx, `INSERT INTO gateway_user_resource_caps (user_id, updated_by) VALUES ($1, $2)
		ON CONFLICT (user_id) DO NOTHING`, userID, nullString(actor)); err != nil {
		return fmt.Errorf("store: patch user resource caps: %w", err)
	}
	if _, err := q.Exec(ctx, `UPDATE gateway_user_resource_caps SET `+strings.Join(set, ", ")+`, updated_by = $2, updated_at = now() WHERE user_id = $1`,
		append([]any{userID, nullString(actor)}, args...)...); err != nil {
		return fmt.Errorf("store: patch user resource caps: %w", err)
	}
	nulls := make([]string, len(ResourceCapColumns))
	for i, c := range ResourceCapColumns {
		nulls[i] = c + " IS NULL"
	}
	if _, err := q.Exec(ctx, `DELETE FROM gateway_user_resource_caps WHERE user_id = $1 AND `+strings.Join(nulls, " AND "), userID); err != nil {
		return fmt.Errorf("store: patch user resource caps: %w", err)
	}
	return nil
}

// LockUserResourceCap takes a transaction-scoped advisory lock on (key,
// user): concurrent creates of the same capped resource by the same user
// wait for each other until the holder's transaction ends.
func LockUserResourceCap(ctx context.Context, q Querier, userID, key string) error {
	if _, err := q.Exec(ctx, `SELECT pg_advisory_xact_lock($1, hashtext($2 || ':' || $3))`, capLockClass, key, userID); err != nil {
		return fmt.Errorf("store: lock resource cap: %w", err)
	}
	return nil
}

// CountUserMCPServers counts the servers userID owns.
func CountUserMCPServers(ctx context.Context, q Querier, userID string) (int, error) {
	return count(ctx, q, "servers", `SELECT count(*) FROM mcp_servers WHERE owner_user_id = $1`, userID)
}

// CountUserLiveMCPTunnels counts userID's tunnels that are not revoked.
func CountUserLiveMCPTunnels(ctx context.Context, q Querier, userID string) (int, error) {
	return count(ctx, q, "tunnels", `SELECT count(*) FROM mcp_tunnels WHERE owner_user_id = $1 AND revoked_at IS NULL`, userID)
}

// CountUserPendingApprovals counts userID's pending approvals that have
// not expired at at.
func CountUserPendingApprovals(ctx context.Context, q Querier, userID string, at time.Time) (int, error) {
	return count(ctx, q, "pending approvals", `SELECT count(*) FROM approvals WHERE user_id = $1 AND status = 'pending' AND expires_at > $2`, userID, at)
}

// AnchorVendor is the vendor of the internal anchor connections of
// user-added servers and the gateway tools (federation/connector); they
// are not the user's app connections and never count.
const AnchorVendor = "mcp"

// CountUserConnections counts userID's connections that are not revoked,
// to vendorAppID and in total, excluding anchor connections.
func CountUserConnections(ctx context.Context, q Querier, userID, vendorAppID string) (perApp, total int, err error) {
	err = q.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE c.vendor_app_id::text = $2), count(*)
		FROM connections c JOIN vendor_apps v ON v.id = c.vendor_app_id
		WHERE c.user_id = $1 AND c.status <> 'revoked' AND v.vendor <> $3`, userID, vendorAppID, AnchorVendor).Scan(&perApp, &total)
	if err != nil {
		return 0, 0, fmt.Errorf("store: count connections: %w", err)
	}
	return perApp, total, nil
}

func count(ctx context.Context, q Querier, what, sql string, args ...any) (int, error) {
	var n int
	if err := q.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count %s: %w", what, err)
	}
	return n, nil
}

// MaxUserConnectionsPerApp is the highest number of userID's live
// (non-revoked, non-anchor) connections to any one vendor app.
func MaxUserConnectionsPerApp(ctx context.Context, q Querier, userID string) (int, error) {
	return count(ctx, q, "connections per app", `
		SELECT coalesce(max(n), 0) FROM (
			SELECT count(*) AS n FROM connections c JOIN vendor_apps v ON v.id = c.vendor_app_id
			WHERE c.user_id = $1 AND c.status <> 'revoked' AND v.vendor <> $2 GROUP BY c.vendor_app_id) per_app`, userID, AnchorVendor)
}
