package gatewaytools

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/huynle/mcp-gateway/internal/caps"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/mcp"
	isettings "github.com/huynle/mcp-gateway/internal/settings"
)

// Tool names of the per-user resource caps (servers, tunnels, app
// connections, pending approvals; internal/settings CapsService).
const (
	ToolGetLimits     = "get_limits"
	ToolSetOrgLimits  = "set_org_limits"
	ToolSetUserLimits = "set_user_limits"
)

// ResourceCaps is the part of *settings.CapsService the tools use.
type ResourceCaps interface {
	Effective(ctx context.Context, userID string) caps.Values
	Usage(ctx context.Context, userID string) (caps.Values, error)
	Defaults() caps.Values
	CapsSnapshot(ctx context.Context) isettings.CapsSnapshot
	IsAdmin(ctx context.Context, userID string) bool
	SetOrg(ctx context.Context, actor string, p caps.Patch) error
	SetUser(ctx context.Context, actor, userID string, p caps.Patch) error
}

func capProps() string {
	var b strings.Builder
	for _, r := range caps.Resources {
		fmt.Fprintf(&b, `"%s":{"type":"integer","minimum":0,"maximum":%d,"description":"Maximum %s per user; 0 = unlimited."},`, r, caps.Max, r.Noun())
	}
	names := make([]string, len(caps.Resources))
	for i, r := range caps.Resources {
		names[i] = `"` + string(r) + `"`
	}
	b.WriteString(`"clear":{"type":"array","items":{"type":"string","enum":[` + strings.Join(names, ",") + `]},"description":"Resources whose value to remove so the parent value (organization, then ENV default) applies."}`)
	return b.String()
}

func (c *Connector) capsTools(bounds connectors.Bounds, write connectors.Reconciliation) []connectors.Tool {
	userArg := `"user_id":{"type":"string","format":"uuid"}`
	return []connectors.Tool{
		{App: App, Name: ToolGetLimits, Kind: connectors.KindRead, Bounds: bounds,
			Description: "Show your resource limits on this gateway (MCP servers, tunnels, connected accounts per app and in total, pending approvals; 0 = unlimited) and how many you use. Administrators also see the organization values, ENV defaults and per-user overrides, and may pass user_id to see another user's limits.",
			InputSchema: schema(userArg), ResourceIdentity: func(map[string]any) map[string]string { return map[string]string{"setting": "resource_caps"} }},
		{App: App, Name: ToolSetOrgLimits, Kind: connectors.KindWrite, Bounds: bounds, Reconcile: write,
			Description: "Administrator only: set or clear the organization's per-user resource limits (0 = unlimited). They override ENV defaults immediately and always require approval.",
			InputSchema: schema(capProps()), ResourceIdentity: func(map[string]any) map[string]string {
				return map[string]string{"setting": "organization_resource_caps"}
			}},
		{App: App, Name: ToolSetUserLimits, Kind: connectors.KindWrite, Bounds: bounds, Reconcile: write,
			Description: "Administrator only: set or clear one user's resource limit overrides (0 = unlimited); always requires approval.",
			InputSchema: schema(userArg+","+capProps(), "user_id"), ResourceIdentity: func(map[string]any) map[string]string { return map[string]string{"setting": "user_resource_caps"} }},
	}
}

func (c *Connector) getLimits(ctx context.Context, user string, a map[string]any) (connectors.Result, error) {
	admin := c.d.Caps.IsAdmin(ctx, user)
	target := user
	if raw, ok := a["user_id"]; ok {
		s, _ := raw.(string)
		switch {
		case !admin:
			return connectors.Result{}, fail("not_permitted", "only an administrator may read another user's limits")
		case !uuidRE.MatchString(s):
			return connectors.Result{}, fail("args_invalid", "user_id must be a user ID")
		}
		target = s
	}
	out := map[string]any{"user_id": target, "limits": c.d.Caps.Effective(ctx, target), "admin": admin,
		"note": "0 means unlimited. To raise a limit, ask an administrator."}
	if use, err := c.d.Caps.Usage(ctx, target); err == nil {
		out["usage"] = use
	}
	if admin {
		s := c.d.Caps.CapsSnapshot(ctx)
		out["organization"] = s.Org
		out["defaults"] = c.d.Caps.Defaults()
		out["user_overrides"] = s.Users
	}
	return connectors.Result{Content: out}, nil
}

// capPatch reads the resource values and the clear list.
func capPatch(a map[string]any) (caps.Patch, error) {
	p := caps.Patch{}
	for _, r := range caps.Resources {
		raw, ok := a[string(r)]
		if !ok {
			continue
		}
		n, ok := raw.(float64)
		if !ok || n != math.Trunc(n) || n < 0 || n > caps.Max {
			return nil, fail("args_invalid", "%s must be a whole number between 0 (unlimited) and %d", r, caps.Max)
		}
		v := int(n)
		p[r] = &v
	}
	if raw, ok := a["clear"]; ok {
		list, ok := raw.([]any)
		if !ok {
			return nil, fail("args_invalid", "clear must be a list of resource names")
		}
		for _, x := range list {
			s, _ := x.(string)
			r := caps.Resource(s)
			if !slices.Contains(caps.Resources, r) {
				return nil, fail("args_invalid", "clear names an unknown resource")
			}
			if _, set := p[r]; set {
				return nil, fail("args_invalid", "choose a value or clear for %s, not both", r)
			}
			p[r] = nil
		}
	}
	if len(p) == 0 {
		return nil, fail("args_invalid", "give at least one limit or clear")
	}
	return p, nil
}

func capsResult(kind string, p caps.Patch, err error) (connectors.Result, error) {
	switch {
	case errors.Is(err, isettings.ErrInvalidCap):
		return connectors.Result{}, fail("args_invalid", "limits must be known resources between 0 (unlimited) and %d", caps.Max)
	case err != nil:
		return connectors.Result{}, err
	}
	changed := map[string]any{}
	for r, v := range p {
		if v == nil {
			changed[string(r)] = "default"
		} else {
			changed[string(r)] = *v
		}
	}
	return connectors.Result{Content: map[string]any{"updated": true, "setting": kind, "changed": changed}}, nil
}

func (c *Connector) setOrgLimits(ctx context.Context, user string, a map[string]any) (connectors.Result, error) {
	if !c.d.Caps.IsAdmin(ctx, user) {
		return connectors.Result{}, mcp.ErrToolNotFound(App + "." + ToolSetOrgLimits)
	}
	p, err := capPatch(a)
	if err != nil {
		return connectors.Result{}, err
	}
	return capsResult("organization_resource_caps", p, c.d.Caps.SetOrg(ctx, user, p))
}

func (c *Connector) setUserLimits(ctx context.Context, user string, a map[string]any) (connectors.Result, error) {
	if !c.d.Caps.IsAdmin(ctx, user) {
		return connectors.Result{}, mcp.ErrToolNotFound(App + "." + ToolSetUserLimits)
	}
	target := rawStringArg(a, "user_id")
	if !uuidRE.MatchString(target) {
		return connectors.Result{}, fail("args_invalid", "user_id must be a user ID")
	}
	p, err := capPatch(a)
	if err != nil {
		return connectors.Result{}, err
	}
	return capsResult("user_resource_caps", p, c.d.Caps.SetUser(ctx, user, target, p))
}
