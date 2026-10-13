package gatewaytools

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/federation/connector"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/policy"
)

// Activity answers whether the gateway.* tools are on for a user:
// permitted to add MCP servers AND the "Gateway management tools" setting
// switched on (*permissions.Service.GatewayToolsActive). It fails closed.
type Activity interface {
	GatewayToolsActive(ctx context.Context, userID string) bool
}

type AdminChecker interface {
	IsAdmin(ctx context.Context, userID string) bool
}

// Setting is the My account setting the portal switches
// (*permissions.Service; the shape of portal.GatewayTools).
type Setting interface {
	CanAddServers(ctx context.Context, userID string) bool
	GatewayToolsEnabled(ctx context.Context, userID string) (bool, error)
	SetGatewayToolsEnabled(ctx context.Context, userID string, on bool) error
}

// DefaultGateTTL bounds how long one user's answer is cached: a role taken
// away (or the setting switched off on another replica) closes the gate
// within it. Switching the setting through Gate.Setting closes it at once.
const DefaultGateTTL = 2 * time.Second

// GateOptions configure NewGate. TTL defaults to DefaultGateTTL, Now to
// time.Now.
type GateOptions struct {
	TTL   time.Duration
	Now   func() time.Time
	Admin AdminChecker
}

// Gate decides, per request, whether a user's gateway.* tools exist. A
// closed gate makes them hidden: absent from tools/list, and a call is
// answered exactly like an unknown tool. The answer is cached per user for
// a short TTL (tools/list asks once per tool).
type Gate struct {
	act   Activity
	ttl   time.Duration
	now   func() time.Time
	admin AdminChecker

	mu    sync.Mutex
	cache map[string]gateEntry
}

type gateEntry struct {
	active bool
	at     time.Time
}

// NewGate builds the gate over act.
func NewGate(act Activity, o GateOptions) *Gate {
	if o.TTL <= 0 {
		o.TTL = DefaultGateTTL
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Gate{act: act, ttl: o.TTL, now: o.Now, admin: o.Admin, cache: map[string]gateEntry{}}
}

// Active reports whether userID's gateway.* tools are on. No user is a
// "no".
func (g *Gate) Active(ctx context.Context, userID string) bool {
	if userID == "" || g == nil {
		return false
	}
	now := g.now()
	g.mu.Lock()
	e, ok := g.cache[userID]
	g.mu.Unlock()
	if ok && now.Sub(e.at) < g.ttl {
		return e.active
	}
	active := g.act.GatewayToolsActive(ctx, userID)
	g.mu.Lock()
	g.cache[userID] = gateEntry{active: active, at: now}
	g.mu.Unlock()
	return active
}

// Forget drops userID's cached answer (the setting changed).
func (g *Gate) Forget(userID string) {
	g.mu.Lock()
	delete(g.cache, userID)
	g.mu.Unlock()
}

// Setting wraps the My account setting so a change takes effect on this
// replica at once (the cached answer is dropped after every change).
func (g *Gate) Setting(s Setting) Setting { return setting{Setting: s, g: g} }

type setting struct {
	Setting
	g *Gate
}

func (s setting) SetGatewayToolsEnabled(ctx context.Context, userID string, on bool) error {
	err := s.Setting.SetGatewayToolsEnabled(ctx, userID, on)
	s.g.Forget(userID)
	return err
}

// Decider wraps base (the policy, already wrapped by the federation's
// server visibility) so a gateway.* tool of a user whose gate is closed is
// not visible and decides hidden without asking base; with the gate open
// base decides (the policy's gateway layer: reads and add_server allow,
// delete_server confirms; token narrowing and restrictions apply). Other
// apps are base's alone. One wrapper covers tools/list, resolve and the
// policy stage.
func (g *Gate) Decider(base mcp.Decider) mcp.Decider { return decider{g: g, base: base} }

type decider struct {
	g    *Gate
	base mcp.Decider
}

func (d decider) Decide(ctx context.Context, in policy.Input) (policy.Decision, error) {
	if in.Tool.App == App && !d.g.Active(ctx, in.UserID) {
		return policy.Decision{Outcome: policy.OutcomeHidden, Reason: "gateway management tools are off for the user"}, nil
	}
	if in.Tool.App == App && adminRateTool(in.Tool.Name) && (d.g.admin == nil || !d.g.admin.IsAdmin(ctx, in.UserID)) {
		return policy.Decision{Outcome: policy.OutcomeHidden, Reason: "administrator required"}, nil
	}
	return d.base.Decide(ctx, in)
}

func (d decider) Visible(ctx context.Context, in policy.Input) (bool, error) {
	if in.Tool.App == App && !d.g.Active(ctx, in.UserID) {
		return false, nil
	}
	if in.Tool.App == App && adminRateTool(in.Tool.Name) && (d.g.admin == nil || !d.g.admin.IsAdmin(ctx, in.UserID)) {
		return false, nil
	}
	return d.base.Visible(ctx, in)
}

func adminRateTool(name string) bool {
	switch name {
	case ToolSetOrgRateLimits, ToolSetAppRateLimit, ToolSetUserRateLimit:
		return true
	}
	return false
}

// Accounts wraps fallback with the account of the gateway app: a user
// whose gate is open has exactly one, their gateway anchor connection
// (approvals and the ledger reference it; label company); a closed gate
// has none. Every other app goes to fallback.
func (g *Gate) Accounts(fallback connectors.AccountSource, anchors connector.GatewayAccounts) connectors.AccountSource {
	return accounts{g: g, fallback: fallback, anchors: anchors}
}

type accounts struct {
	g        *Gate
	fallback connectors.AccountSource
	anchors  connector.GatewayAccounts
}

func (a accounts) ListAccounts(ctx context.Context, userID, app string) ([]connectors.Account, error) {
	if app != App {
		if a.fallback == nil {
			return nil, nil
		}
		return a.fallback.ListAccounts(ctx, userID, app)
	}
	if !a.g.Active(ctx, userID) {
		return nil, nil
	}
	id, err := a.anchors.GatewayAccount(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("gateway tools: account: %w", err)
	}
	return []connectors.Account{{ID: id, Label: connectors.LabelCompany, DisplayName: "gateway", App: App}}, nil
}
