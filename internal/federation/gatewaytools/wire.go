package gatewaytools

import (
	"errors"
	"log/slog"
	"time"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/federation/connector"
	fedportal "github.com/huynle/mcp-gateway/internal/federation/portal"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/store"
)

// WireOptions configure Wire. Federation, Store, Registry and Activity
// are required.
type WireOptions struct {
	Federation *connector.Federation
	Store      *store.Store
	Registry   *connectors.Registry
	// Activity is *permissions.Service (GatewayToolsActive).
	Activity     Activity
	RateSettings RateSettings
	// Approvals are the vendor apps' approval modes (*policy.Service);
	// VendorOf names an app's vendor for the admin page link
	// (connections.Service.VendorFor); Audit records server approval-mode
	// changes. All optional.
	Approvals ToolApprovals
	VendorOf  func(app string) string
	Audit     audit.Recorder
	// BaseURL is GATEWAY_BASE_URL (absolute portal links).
	BaseURL string
	// GateTTL: DefaultGateTTL when 0.
	GateTTL time.Duration
	// Timeout bounds each upstream operation of a refresh (client default
	// when 0).
	Timeout time.Duration
	Log     *slog.Logger
}

// Tools is the wired gateway app: its tools are in the registry; the
// wrappers below put the gate in front of the policy and supply the
// account. cmd/gateway (and the end-to-end worlds) apply all three.
type Tools struct {
	Gate      *Gate
	Connector *Connector
	anchors   connector.GatewayAccounts
}

// Wire builds the gateway app over the federation (the same services the
// servers portal uses: its store, snapshots, auth detection, client
// factory and netguard) and registers its tools.
func Wire(o WireOptions) (*Tools, error) {
	f := o.Federation
	switch {
	case f == nil || f.Manager == nil || f.Auth == nil || f.Snapshots == nil || f.Tunnels == nil || f.Guard == nil || f.GatewayAccounts == nil:
		return nil, errors.New("gateway tools: a wired federation is required")
	case o.Store == nil || o.Registry == nil || o.Activity == nil:
		return nil, errors.New("gateway tools: Store, Registry and Activity are required")
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	factory, err := fedportal.NewClientFactory(fedportal.FactoryOptions{
		Credentials: f.Auth, Tunnels: f.Tunnels, HTTPClient: f.Guard.Client(), Timeout: o.Timeout, Log: o.Log,
	})
	if err != nil {
		return nil, err
	}
	gate := NewGate(o.Activity, GateOptions{TTL: o.GateTTL, Admin: o.RateSettings})
	d := Deps{
		Servers: fedportal.NewStore(o.Store), Snapshots: f.Snapshots, Detector: f.Auth, Manager: f.Manager, Clients: factory,
		URLCheck: f.Guard, Gate: gate, BaseURL: o.BaseURL, Log: o.Log, Rates: o.RateSettings,
		Approvals: o.Approvals, VendorOf: o.VendorOf, Audit: o.Audit,
	}
	if o.RateSettings != nil {
		d.Admin = o.RateSettings
	}
	c, err := New(d)
	if err != nil {
		return nil, err
	}
	if err := c.Register(o.Registry); err != nil {
		return nil, err
	}
	return &Tools{Gate: gate, Connector: c, anchors: f.GatewayAccounts}, nil
}

// Decider puts the gate in front of base (nil Tools: base unchanged).
func (t *Tools) Decider(base mcp.Decider) mcp.Decider {
	if t == nil {
		return base
	}
	return t.Gate.Decider(base)
}

// Accounts adds the gateway app's account to base (nil Tools: base
// unchanged).
func (t *Tools) Accounts(base connectors.AccountSource) connectors.AccountSource {
	if t == nil {
		return base
	}
	return t.Gate.Accounts(base, t.anchors)
}

// Setting wraps the My account setting so switching it takes effect at
// once (nil Tools: s unchanged).
func (t *Tools) Setting(s Setting) Setting {
	if t == nil {
		return s
	}
	return t.Gate.Setting(s)
}
