// Package permissions answers "may this user add MCP servers?" and owns
// the per-user "Gateway management tools" setting (Brain task ds5tjou2,
// plan ax0w46sh, decision bnneszc1).
//
// A user may add servers when they hold the admin role or any role an
// admin marked "May add MCP servers" (roles.may_add_servers, schema 16).
// The federation portal (Add server), the connector Manager (CreateServer)
// and the gateway.* MCP tools all ask the same Service, so there is one
// answer everywhere. Every check runs in the user's own database scope and
// fails closed: an error is a "no".
//
// The setting (users.gateway_tools_enabled, default off) is switched in
// My account. Turning it on needs the permission; turning it off never
// does. GatewayToolsActive is what the gateway.* tools gate on: permitted
// AND switched on, so taking the role away switches the tools off without
// rewriting the stored setting.
//
// The package sits below the portal and the federation packages (it
// imports only store, audit, identity and observability), so all of them
// can use it without import cycles.
package permissions

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"time"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/observability"
)

// ErrNotPermitted: the user may not add MCP servers, so they may not turn
// the gateway management tools on either.
var ErrNotPermitted = errors.New("permissions: not permitted to add MCP servers")

// ActionGatewayToolsToggled is the audit action of a changed setting.
const ActionGatewayToolsToggled = "user.gateway_tools_toggled"

// Store is the persistence the Service needs. NewPostgresStore runs every
// call as the user it is about (row-level security).
type Store interface {
	// MayAddServers: the user holds the admin role or a role with
	// may_add_servers.
	MayAddServers(ctx context.Context, userID string) (bool, error)
	// GatewayToolsEnabled returns the stored setting.
	GatewayToolsEnabled(ctx context.Context, userID string) (bool, error)
	// SetGatewayToolsEnabled stores the setting.
	SetGatewayToolsEnabled(ctx context.Context, userID string, on bool) error
}

// Options configure New. Audit defaults to audit.NopRecorder, Log to
// slog.Default() and Now to time.Now.
type Options struct {
	Audit audit.Recorder
	Log   *slog.Logger
	Now   func() time.Time
}

// Service answers permission checks and changes the setting.
type Service struct {
	st    Store
	audit audit.Recorder
	log   *slog.Logger
	now   func() time.Time
}

// New builds the Service over st.
func New(st Store, opts Options) *Service {
	if opts.Audit == nil {
		opts.Audit = audit.NopRecorder{}
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Service{st: st, audit: opts.Audit, log: opts.Log, now: opts.Now}
}

// CanAddServers reports whether userID may add MCP servers: admin, or any
// of the user's roles has "May add MCP servers". No user, or a failed
// lookup, is a "no".
func (s *Service) CanAddServers(ctx context.Context, userID string) bool {
	if userID == "" {
		return false
	}
	ok, err := s.st.MayAddServers(ctx, userID)
	if err != nil {
		s.log.Error("add-server permission lookup failed; refusing", "event", "permissions.lookup_failed",
			"user_id", userID, "error", observability.RedactError(err))
		return false
	}
	return ok
}

// GatewayToolsEnabled returns the user's stored "Gateway management
// tools" setting, whatever their permission. Gate on GatewayToolsActive.
func (s *Service) GatewayToolsEnabled(ctx context.Context, userID string) (bool, error) {
	return s.st.GatewayToolsEnabled(ctx, userID)
}

// GatewayToolsActive reports whether the gateway.* MCP tools are on for
// userID: permitted to add servers AND the setting is on. Errors are a
// "no".
func (s *Service) GatewayToolsActive(ctx context.Context, userID string) bool {
	if !s.CanAddServers(ctx, userID) {
		return false
	}
	on, err := s.st.GatewayToolsEnabled(ctx, userID)
	if err != nil {
		s.log.Error("gateway tools setting lookup failed; treating as off", "event", "permissions.lookup_failed",
			"user_id", userID, "error", observability.RedactError(err))
		return false
	}
	return on
}

// SetGatewayToolsEnabled stores the user's setting and audits it as
// ActionGatewayToolsToggled. Turning it on needs CanAddServers
// (ErrNotPermitted otherwise); turning it off is always allowed.
func (s *Service) SetGatewayToolsEnabled(ctx context.Context, userID string, on bool) error {
	if on && !s.CanAddServers(ctx, userID) {
		return ErrNotPermitted
	}
	if err := s.st.SetGatewayToolsEnabled(ctx, userID, on); err != nil {
		return err
	}
	ev := audit.Event{
		Time:             s.now(),
		UserID:           userID,
		ResourceIdentity: map[string]string{"action": ActionGatewayToolsToggled, "enabled": strconv.FormatBool(on)},
		Decision:         "allow",
		Outcome:          "succeeded",
		RequestID:        observability.RequestIDFromContext(ctx),
	}
	if err := s.audit.Record(ctx, ev); err != nil {
		// The change is committed; a lost audit row is logged, not returned.
		s.log.Error("audit event not recorded", "event", "permissions.audit_failed", "action", ActionGatewayToolsToggled,
			"error", observability.RedactError(err))
	}
	s.log.Info("gateway tools setting changed", "event", ActionGatewayToolsToggled, "user_id", userID, "enabled", on)
	return nil
}
