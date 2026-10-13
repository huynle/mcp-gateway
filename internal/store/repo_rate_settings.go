package store

import (
	"context"
	"fmt"
	"time"
)

type GatewayRateSettings struct {
	UserPerMin, AppPerMin *int
	Version               int64
	UpdatedBy             *string
	UpdatedAt             time.Time
}

type GatewayAppRateLimit struct {
	App       string
	PerMin    int
	UpdatedBy *string
	UpdatedAt time.Time
}

type GatewayUserRateLimit struct {
	UserID                  string
	AdminPerMin, SelfPerMin *int
	UpdatedBy               *string
	UpdatedAt               time.Time
}

func GetGatewayRateSettings(ctx context.Context, q Querier) (*GatewayRateSettings, error) {
	var s GatewayRateSettings
	err := q.QueryRow(ctx, `SELECT user_per_min, app_per_min, version, updated_by, updated_at FROM gateway_rate_settings WHERE singleton`).
		Scan(&s.UserPerMin, &s.AppPerMin, &s.Version, &s.UpdatedBy, &s.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("store: get gateway rate settings: %w", err)
	}
	return &s, nil
}

func SetGatewayRateSettings(ctx context.Context, q Querier, userPerMin, appPerMin *int, actor string) error {
	_, err := q.Exec(ctx, `UPDATE gateway_rate_settings SET user_per_min=$1, app_per_min=$2, version=version+1, updated_by=$3, updated_at=now() WHERE singleton`, userPerMin, appPerMin, nullString(actor))
	if err != nil {
		return fmt.Errorf("store: set gateway rate settings: %w", err)
	}
	return nil
}

func ListGatewayAppRateLimits(ctx context.Context, q Querier) ([]GatewayAppRateLimit, error) {
	rows, err := q.Query(ctx, `SELECT app, per_min, updated_by, updated_at FROM gateway_app_rate_limits ORDER BY app`)
	if err != nil {
		return nil, fmt.Errorf("store: list app rate limits: %w", err)
	}
	defer rows.Close()
	var out []GatewayAppRateLimit
	for rows.Next() {
		var x GatewayAppRateLimit
		if err := rows.Scan(&x.App, &x.PerMin, &x.UpdatedBy, &x.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

func SetGatewayAppRateLimit(ctx context.Context, q Querier, app string, perMin *int, actor string) error {
	if perMin == nil {
		_, err := q.Exec(ctx, `DELETE FROM gateway_app_rate_limits WHERE app=$1`, app)
		return err
	}
	_, err := q.Exec(ctx, `INSERT INTO gateway_app_rate_limits(app,per_min,updated_by) VALUES($1,$2,$3) ON CONFLICT(app) DO UPDATE SET per_min=excluded.per_min,updated_by=excluded.updated_by,updated_at=now()`, app, *perMin, nullString(actor))
	return err
}

func ListGatewayUserRateLimits(ctx context.Context, q Querier) ([]GatewayUserRateLimit, error) {
	rows, err := q.Query(ctx, `SELECT user_id, admin_per_min, self_per_min, updated_by, updated_at FROM gateway_user_rate_limits ORDER BY user_id`)
	if err != nil {
		return nil, fmt.Errorf("store: list user rate limits: %w", err)
	}
	defer rows.Close()
	var out []GatewayUserRateLimit
	for rows.Next() {
		var x GatewayUserRateLimit
		if err := rows.Scan(&x.UserID, &x.AdminPerMin, &x.SelfPerMin, &x.UpdatedBy, &x.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

func GetGatewayUserRateLimit(ctx context.Context, q Querier, userID string) (*GatewayUserRateLimit, error) {
	var x GatewayUserRateLimit
	err := q.QueryRow(ctx, `SELECT user_id,admin_per_min,self_per_min,updated_by,updated_at FROM gateway_user_rate_limits WHERE user_id=$1`, userID).Scan(&x.UserID, &x.AdminPerMin, &x.SelfPerMin, &x.UpdatedBy, &x.UpdatedAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &x, nil
}

func SetGatewayUserRateLimit(ctx context.Context, q Querier, userID string, admin, self *int, actor string) error {
	if admin == nil && self == nil {
		_, err := q.Exec(ctx, `DELETE FROM gateway_user_rate_limits WHERE user_id=$1`, userID)
		return err
	}
	_, err := q.Exec(ctx, `INSERT INTO gateway_user_rate_limits(user_id,admin_per_min,self_per_min,updated_by) VALUES($1,$2,$3,$4) ON CONFLICT(user_id) DO UPDATE SET admin_per_min=excluded.admin_per_min,self_per_min=excluded.self_per_min,updated_by=excluded.updated_by,updated_at=now()`, userID, admin, self, nullString(actor))
	return err
}

// SetGatewayUserSelfRateLimit is the request-path write: its SQL mentions
// only columns gateway_app may change. RLS also confines it to the caller's
// own row. A null value is equivalent to no personal ceiling.
func SetGatewayUserSelfRateLimit(ctx context.Context, q Querier, userID string, self *int) error {
	_, err := q.Exec(ctx, `INSERT INTO gateway_user_rate_limits(user_id,self_per_min,updated_by) VALUES($1,$2,$1) ON CONFLICT(user_id) DO UPDATE SET self_per_min=excluded.self_per_min,updated_by=excluded.updated_by,updated_at=now()`, userID, self)
	return err
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
