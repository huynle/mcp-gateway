// Package caps is the vocabulary of per-user resource caps (Brain plan
// r0e6dxnp, feature public-launch): how many MCP servers, tunnels, app
// connections and pending approvals one user may hold on a public
// gateway. internal/settings owns the persisted values (ENV defaults,
// organization values, per-user administrator overrides); this package
// enforces them inside the creating transaction (Reserve).
package caps

import (
	"context"
	"errors"
	"fmt"
	"slices"
)

// Resource names one capped resource. The values are also the column
// names of gateway_resource_caps / gateway_user_resource_caps (00028).
type Resource string

const (
	Servers           Resource = "servers"
	Tunnels           Resource = "tunnels"
	ConnectionsPerApp Resource = "connections_per_app"
	ConnectionsTotal  Resource = "connections_total"
	PendingApprovals  Resource = "pending_approvals"
)

// Resources lists every resource in display order.
var Resources = []Resource{Servers, Tunnels, ConnectionsPerApp, ConnectionsTotal, PendingApprovals}

// Max is the highest storable cap; 0 means unlimited.
const Max = 100000

// Class is the audit / log error class of a refusal.
const Class = "cap_exceeded"

// Values maps resources to caps (0 = unlimited). An absent resource
// inherits from the next level (user → organization → ENV default).
type Values map[Resource]int

// Patch changes stored caps: a value sets it, nil clears it (inherit),
// an absent resource is left alone.
type Patch map[Resource]*int

// Builtin are the defaults when ENV gives none: the gateway never runs
// unlimited unless an administrator says so.
var Builtin = Values{Servers: 10, Tunnels: 5, ConnectionsPerApp: 5, ConnectionsTotal: 20, PendingApprovals: 50}

// Limiter answers a user's effective cap (0 = unlimited) and is told
// about every refusal (it logs it).
type Limiter interface {
	Limit(ctx context.Context, userID string, r Resource) int
	Refused(ctx context.Context, userID string, r Resource, limit int)
}

// ErrExceeded matches every *ExceededError (errors.Is).
var ErrExceeded = errors.New("caps: limit reached")

// Valid reports whether r is a known resource.
func Valid(r Resource) bool {
	return slices.Contains(Resources, r)
}

// Noun is the user-facing plural of r.
func (r Resource) Noun() string {
	switch r {
	case Servers:
		return "MCP servers"
	case Tunnels:
		return "tunnels"
	case ConnectionsPerApp:
		return "connected accounts for this app"
	case ConnectionsTotal:
		return "connected accounts"
	case PendingApprovals:
		return "pending approvals"
	}
	return string(r)
}

// hint is what the user can do besides asking an admin.
func (r Resource) hint() string {
	switch r {
	case Servers:
		return "Delete a server you no longer need"
	case Tunnels:
		return "Revoke a tunnel you no longer need"
	case ConnectionsPerApp, ConnectionsTotal:
		return "Disconnect an account you no longer need"
	case PendingApprovals:
		return "Decide or wait for some pending approvals to expire"
	}
	return "Remove one"
}

// ExceededError is a refusal: the user already holds Limit of Resource.
type ExceededError struct {
	Resource Resource
	Limit    int
}

// Error is the user-facing message: fixed text and the number only.
func (e *ExceededError) Error() string {
	return fmt.Sprintf("You have reached the limit of %d %s. %s, or ask an admin to raise the limit.", e.Limit, e.Resource.Noun(), e.Resource.hint())
}

// ErrorClass is the audit class (mcp.ClassedError).
func (e *ExceededError) ErrorClass() string { return Class }

// Is matches ErrExceeded.
func (e *ExceededError) Is(target error) bool { return target == ErrExceeded }
