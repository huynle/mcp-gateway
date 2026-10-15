package policy

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
)

// AppApproval is the org-wide approval-mode layer of one built-in (vendor)
// app such as github, slack or gmail: the admin's per-write-tool Ask /
// Auto choice on Settings → Vendor apps. Ask names the write tools (without
// the app prefix) that need a confirmation for every principal; every
// other tool is Auto, which means "as the roles say" (today's behaviour).
//
// The layer only adds confirmations: a role allow + Ask confirms, a role
// confirm stays confirm (Auto never lifts it), and forbids (role deny,
// user restriction deny, token narrowing) still win. It grants nothing: a
// user without a role grant still cannot call the tool. Read tools are
// never affected. The gateway app and user-added server apps (which keep
// their ServerApproval) are not vendor apps.
type AppApproval struct {
	App string
	Ask []string
}

// Validate checks the layer can be compiled.
func (a AppApproval) Validate() error {
	if !identRE.MatchString(a.App) {
		return fmt.Errorf("%w: app approval app %q must be a lower-case identifier", ErrInvalidRole, a.App)
	}
	if a.App == GatewayApp {
		return fmt.Errorf("%w: the gateway app has fixed approvals", ErrInvalidRole)
	}
	for _, t := range a.Ask {
		if !identRE.MatchString(t) {
			return fmt.Errorf("%w: app approval tool %q of %s must be a lower-case identifier", ErrInvalidRole, t, a.App)
		}
	}
	return nil
}

// normalizeApps validates the layers and returns, per app, the sorted and
// de-duplicated ask tools. Apps without an ask tool and server apps
// (present in servers: they keep their ServerApproval) are left out.
func normalizeApps(apps []AppApproval, servers map[string][]string) (map[string][]string, error) {
	out := map[string][]string{}
	for _, a := range apps {
		a.App = strings.ToLower(strings.TrimSpace(a.App))
		if err := a.Validate(); err != nil {
			return nil, err
		}
		if _, server := servers[a.App]; server || len(a.Ask) == 0 {
			continue
		}
		list := slices.Concat(out[a.App], a.Ask)
		slices.Sort(list)
		out[a.App] = slices.Compact(list)
	}
	return out, nil
}

// appApproval emits the ask-writes policy of one vendor app: a confirm
// permit for exactly the named write tools.
func (w *writer) appApproval(app string, ask []string) {
	resource := fmt.Sprintf(`resource in %s::%s`, EntityApp, strconv.Quote(app))
	names := make([]string, len(ask))
	for i, t := range ask {
		names[i] = strconv.Quote(app + "." + t)
	}
	w.policy("app/"+app+"/ask_writes", "permit", "principal", actions(ActionConfirm), resource,
		[]string{`resource.kind == "write"`, "[" + strings.Join(names, ", ") + "].contains(resource.name)"}, nil)
}

// --- service -------------------------------------------------------------------

// ToolCatalog is the tool registry the approval modes are checked against
// (*connectors.Registry).
type ToolCatalog interface {
	List() []connectors.Tool
	IsServerApp(app string) bool
}

// Errors of the vendor app approval modes.
var (
	// ErrApprovalApp: not a built-in app with write tools (unknown, the
	// gateway app, or a user-added server app).
	ErrApprovalApp = errors.New("policy: not a vendor app with write tools")
	// ErrApprovalTool: not a write tool of the app.
	ErrApprovalTool = errors.New("policy: not a write tool of the app")
	// ErrApprovalMode: a mode other than ask or auto.
	ErrApprovalMode = errors.New("policy: approval mode must be ask or auto")
)

// AppApprovalModesChangedEvent is the audit action of a vendor app
// approval-mode change.
const AppApprovalModesChangedEvent = "vendor_app.approval_modes_changed"

// AppToolMode is one write tool of a vendor app and its approval mode.
type AppToolMode struct {
	App         string
	Tool        string // without the app prefix
	Description string
	Mode        snapshot.Approval
}

// FullName returns "app.tool".
func (m AppToolMode) FullName() string { return m.App + "." + m.Tool }

// AppApprovalChange summarises a change: how many tools changed mode and
// how many writes of the app now ask or run as their roles say.
type AppApprovalChange struct{ Changed, Ask, Auto int }

// writeTools returns app's registered write tools by name, or
// ErrApprovalApp when app is not a vendor app with write tools.
func (s *Service) writeTools(app string) ([]connectors.Tool, error) {
	if s.tools == nil || app == GatewayApp || !identRE.MatchString(app) || s.tools.IsServerApp(app) {
		return nil, ErrApprovalApp
	}
	var out []connectors.Tool
	for _, t := range s.tools.List() {
		if t.App == app && t.Kind == connectors.KindWrite {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return nil, ErrApprovalApp
	}
	slices.SortFunc(out, func(a, b connectors.Tool) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// askSet returns the stored ask tools of app.
func (s *Service) askSet(ctx context.Context, app string) (map[string]bool, error) {
	snap, err := s.store.Load(ctx)
	if err != nil {
		return nil, fmt.Errorf("policy: load: %w", err)
	}
	ask := map[string]bool{}
	for _, a := range snap.Apps {
		if a.App == app {
			for _, t := range a.Ask {
				ask[t] = true
			}
		}
	}
	return ask, nil
}

// AppApprovalModes lists the write tools of a vendor app with their
// approval modes, by name (ErrApprovalApp for anything else).
func (s *Service) AppApprovalModes(ctx context.Context, app string) ([]AppToolMode, error) {
	tools, err := s.writeTools(app)
	if err != nil {
		return nil, err
	}
	ask, err := s.askSet(ctx, app)
	if err != nil {
		return nil, err
	}
	out := make([]AppToolMode, 0, len(tools))
	for _, t := range tools {
		m := AppToolMode{App: app, Tool: t.Name, Description: t.Description, Mode: snapshot.ApprovalAuto}
		if ask[t.Name] {
			m.Mode = snapshot.ApprovalAsk
		}
		out = append(out, m)
	}
	return out, nil
}

// SetAppApprovalModes sets the approval modes of write tools of a vendor
// app (tool name without the prefix → ask | auto; tools not named keep
// theirs), org-wide, on behalf of admin actorID: the caller checks the
// actor is an admin. Every name must be a registered write tool of the
// app (ErrApprovalTool) and every mode ask or auto (ErrApprovalMode);
// nothing is stored otherwise. The policy is recompiled at once (a new
// version under the actor) and the change audited with counts only.
func (s *Service) SetAppApprovalModes(ctx context.Context, actorID, app string, modes map[string]snapshot.Approval) (AppApprovalChange, error) {
	var ch AppApprovalChange
	tools, err := s.writeTools(app)
	if err != nil {
		return ch, err
	}
	for name, mode := range modes {
		if !slices.ContainsFunc(tools, func(t connectors.Tool) bool { return t.Name == name }) {
			return ch, fmt.Errorf("%w: %s", ErrApprovalTool, name)
		}
		if !mode.Valid() {
			return ch, ErrApprovalMode
		}
	}
	ask, err := s.askSet(ctx, app)
	if err != nil {
		return ch, err
	}
	for name, mode := range modes {
		if was := ask[name]; was != (mode == snapshot.ApprovalAsk) {
			ch.Changed++
		}
		if mode == snapshot.ApprovalAsk {
			ask[name] = true
		} else {
			delete(ask, name)
		}
	}
	// Only registered write tools are kept: a name stored for a tool that
	// no longer exists drops out with the next change.
	var list []string
	for _, t := range tools {
		if ask[t.Name] {
			list = append(list, t.Name)
		}
	}
	ch.Ask, ch.Auto = len(list), len(tools)-len(list)
	if err := s.store.SetAppAsk(ctx, actorID, app, list); err != nil {
		return ch, err
	}
	c, err := s.refresh(ctx, actorID)
	if err != nil {
		return ch, err
	}
	s.record(ctx, actorID, c, map[string]string{
		"action": AppApprovalModesChangedEvent, "app": app, "changed": strconv.Itoa(ch.Changed),
		"ask": strconv.Itoa(ch.Ask), "auto": strconv.Itoa(ch.Auto),
	})
	s.log.Info("vendor app approval modes changed", "event", AppApprovalModesChangedEvent, "app", app, "actor_user_id", actorID,
		"changed", ch.Changed, "ask", ch.Ask, "version", c.Version)
	return ch, nil
}
