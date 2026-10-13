package gatewaytools

import (
	"context"
	"fmt"
	"strings"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/settings"
)

func (c *Connector) rateTools(bounds connectors.Bounds, write connectors.Reconciliation) []connectors.Tool {
	limit := `"per_min":{"type":"integer","minimum":1,"maximum":100000}`
	clear := `"clear":{"type":"boolean","description":"Clear the override and use its parent/default limit."}`
	return []connectors.Tool{
		{App: App, Name: ToolGetRateLimits, Kind: connectors.KindRead, Bounds: bounds, Description: "Show your effective rate limits, organization defaults and optional app override. Administrators also see all overrides.", InputSchema: schema(`"app":{"type":"string","pattern":"^[a-z0-9_-]{1,63}$"}`), ResourceIdentity: func(map[string]any) map[string]string { return map[string]string{"setting": "rate_limits"} }},
		{App: App, Name: ToolSetMyRateLimit, Kind: connectors.KindWrite, Bounds: bounds, Reconcile: write, Description: "Set or clear your own lower calls-per-minute ceiling. It cannot exceed the administrator or organization limit and requires approval.", InputSchema: schema(limit + "," + clear), ResourceIdentity: func(map[string]any) map[string]string { return map[string]string{"setting": "my_rate_limit"} }},
		{App: App, Name: ToolSetOrgRateLimits, Kind: connectors.KindWrite, Bounds: bounds, Reconcile: write, Description: "Administrator only: set the persisted organization defaults. They override ENV defaults immediately and require approval.", InputSchema: schema(`"user_per_min":{"type":"integer","minimum":1,"maximum":100000},"app_per_min":{"type":"integer","minimum":1,"maximum":100000}`, "user_per_min", "app_per_min"), ResourceIdentity: func(map[string]any) map[string]string {
			return map[string]string{"setting": "organization_rate_limits"}
		}},
		{App: App, Name: ToolSetAppRateLimit, Kind: connectors.KindWrite, Bounds: bounds, Reconcile: write, Description: "Administrator only: set or clear one app/server calls-per-minute override; requires approval.", InputSchema: schema(`"app":{"type":"string","pattern":"^[a-z0-9_-]{1,63}$"},`+limit+`,`+clear, "app"), ResourceIdentity: func(a map[string]any) map[string]string {
			return map[string]string{"setting": "app_rate_limit", "app": rawStringArg(a, "app")}
		}},
		{App: App, Name: ToolSetUserRateLimit, Kind: connectors.KindWrite, Bounds: bounds, Reconcile: write, Description: "Administrator only: set or clear one user's base calls-per-minute override; requires approval.", InputSchema: schema(`"user_id":{"type":"string","format":"uuid"},`+limit+`,`+clear, "user_id"), ResourceIdentity: func(map[string]any) map[string]string { return map[string]string{"setting": "user_rate_limit"} }},
	}
}

func (c *Connector) getRateLimits(ctx context.Context, user string, args map[string]any) (connectors.Result, error) {
	app := rawStringArg(args, "app")
	u, a := c.d.Rates.Limits(ctx, user, app)
	s := c.d.Rates.Snapshot(ctx)
	out := map[string]any{"effective_user_per_min": u, "effective_app_per_min": a, "organization_user_per_min": s.UserDefault, "organization_app_per_min": s.AppDefault, "app": app, "admin": c.d.Rates.IsAdmin(ctx, user)}
	if c.d.Rates.IsAdmin(ctx, user) {
		out["app_overrides"] = s.Apps
		out["user_overrides"] = s.Users
	}
	return connectors.Result{Content: out}, nil
}
func limitArg(a map[string]any) (*int, error) {
	clear, _ := a["clear"].(bool)
	n, has := a["per_min"].(float64)
	if clear && has {
		return nil, fmt.Errorf("choose per_min or clear, not both")
	}
	if clear {
		return nil, nil
	}
	if !has {
		return nil, fmt.Errorf("per_min is required unless clear is true")
	}
	x := int(n)
	if x < settings.MinPerMinute || x > settings.MaxPerMinute {
		return nil, settings.ErrInvalidLimit
	}
	return &x, nil
}
func (c *Connector) setMyRateLimit(ctx context.Context, user string, a map[string]any) (connectors.Result, error) {
	n, err := limitArg(a)
	if err == nil {
		err = c.d.Rates.SetSelf(ctx, user, n)
	}
	return settingResult("my_rate_limit", n, err)
}
func (c *Connector) setOrgRateLimits(ctx context.Context, user string, a map[string]any) (connectors.Result, error) {
	if !c.d.Rates.IsAdmin(ctx, user) {
		return connectors.Result{}, mcp.ErrToolNotFound(App + "." + ToolSetOrgRateLimits)
	}
	u, ok1 := a["user_per_min"].(float64)
	p, ok2 := a["app_per_min"].(float64)
	if !ok1 || !ok2 {
		return connectors.Result{}, fmt.Errorf("user_per_min and app_per_min are required")
	}
	err := c.d.Rates.SetOrg(ctx, user, int(u), int(p))
	if err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: map[string]any{"updated": true, "user_per_min": int(u), "app_per_min": int(p)}}, nil
}
func (c *Connector) setAppRateLimit(ctx context.Context, user string, a map[string]any) (connectors.Result, error) {
	if !c.d.Rates.IsAdmin(ctx, user) {
		return connectors.Result{}, mcp.ErrToolNotFound(App + "." + ToolSetAppRateLimit)
	}
	n, err := limitArg(a)
	if err == nil {
		err = c.d.Rates.SetApp(ctx, user, rawStringArg(a, "app"), n)
	}
	return settingResult("app_rate_limit", n, err)
}
func (c *Connector) setUserRateLimit(ctx context.Context, user string, a map[string]any) (connectors.Result, error) {
	if !c.d.Rates.IsAdmin(ctx, user) {
		return connectors.Result{}, mcp.ErrToolNotFound(App + "." + ToolSetUserRateLimit)
	}
	n, err := limitArg(a)
	if err == nil {
		err = c.d.Rates.SetUserAdmin(ctx, user, rawStringArg(a, "user_id"), n)
	}
	return settingResult("user_rate_limit", n, err)
}
func settingResult(kind string, n *int, err error) (connectors.Result, error) {
	if err != nil {
		return connectors.Result{}, err
	}
	var v any = "default"
	if n != nil {
		v = *n
	}
	return connectors.Result{Content: map[string]any{"updated": true, "setting": kind, "per_min": v}}, nil
}
func rawStringArg(a map[string]any, k string) string {
	v, _ := a[k].(string)
	return strings.TrimSpace(v)
}
