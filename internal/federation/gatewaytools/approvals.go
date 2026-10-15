package gatewaytools

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/connectors"
	fedportal "github.com/huynle/mcp-gateway/internal/federation/portal"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/store"
)

// Tool names of the approval-mode tools.
const (
	ToolGetToolApprovals = "get_tool_approvals"
	ToolSetToolApproval  = policy.GatewaySetToolApproval
)

// ToolApprovals is the vendor apps' org-wide approval modes
// (*policy.Service).
type ToolApprovals interface {
	AppApprovalModes(ctx context.Context, app string) ([]policy.AppToolMode, error)
	SetAppApprovalModes(ctx context.Context, actorID, app string, modes map[string]snapshot.Approval) (policy.AppApprovalChange, error)
}

const (
	appArg      = `"app":{"type":"string","description":"A built-in app (github, slack, gmail, jira, ...) or the name or ID of an MCP server you can use.","minLength":1,"maxLength":63}`
	approvalArg = `"tools":{"type":"object","description":"Tool name (with or without the app prefix) to ask or auto.","additionalProperties":{"type":"string","enum":["ask","auto"]},"minProperties":1,"maxProperties":500},` +
		`"all":{"type":"string","enum":["ask","auto"],"description":"Set every write tool of the app instead of naming them."}`
	approvalModesNote = " ask: every call needs the user's approval first; auto: the tool runs without one (for a built-in app: as the user's roles say, so a role's confirm or deny still applies). Read tools always run without asking."
)

// toolNameRE bounds a named tool (upstream server tools are not always
// identifiers; anything else is refused before it reaches a message).
var toolNameRE = regexp.MustCompile(`^[A-Za-z0-9_.:/-]{1,128}$`)

func appIdentity(args map[string]any) map[string]string {
	app, _ := args["app"].(string)
	if !serverNameRE.MatchString(app) && !uuidRE.MatchString(app) {
		app = "invalid"
	}
	return map[string]string{"setting": "tool_approvals", "app": app}
}

func appResult(res connectors.Result) map[string]string {
	if m, ok := res.Content.(map[string]any); ok {
		if app, ok := m["app"].(string); ok {
			return map[string]string{"app": app}
		}
	}
	return nil
}

func (c *Connector) approvalTools(bounds connectors.Bounds, write connectors.Reconciliation) []connectors.Tool {
	return []connectors.Tool{
		{
			App: App, Name: ToolGetToolApprovals, Kind: connectors.KindRead, Bounds: bounds,
			Description: "Show the approval mode (ask or auto) of every write tool of a built-in app or of an MCP server you can use, " +
				"whether you may change them, and the browser page where they are managed." + approvalModesNote,
			InputSchema:      schema(appArg, "app"),
			ResourceIdentity: appIdentity,
		},
		{
			App: App, Name: ToolSetToolApproval, Kind: connectors.KindWrite, Bounds: bounds, Reconcile: write, ResultIDs: appResult,
			Description: "Set the approval mode (ask or auto) of write tools of a built-in app (administrators only, for the whole " +
				"organization) or of an MCP server (its owner while private, an administrator once published). Name the tools in " +
				"\"tools\" or set them all with \"all\"." + approvalModesNote + " Every call needs your approval first: the gateway " +
				"answers \"approval required\" with a link; approve in the browser, then retry with approval_id.",
			InputSchema:      schema(appArg+","+approvalArg, "app"),
			ResourceIdentity: appIdentity,
		},
	}
}

// approvalTarget is what the app argument names: a vendor app (modes
// from the policy service) or a user-added server.
type approvalTarget struct {
	app    string
	vendor []policy.AppToolMode
	server *store.MCPServer
}

// resolveApp finds the vendor app or the visible server the app argument
// names; anything else is one "not found" answer.
func (c *Connector) resolveApp(ctx context.Context, user, app string) (approvalTarget, error) {
	if app == App {
		return approvalTarget{}, fail("args_invalid", "the gateway app's approvals are fixed")
	}
	if !serverNameRE.MatchString(app) && !uuidRE.MatchString(app) {
		return approvalTarget{}, errAppNotFound("?")
	}
	if c.d.Approvals != nil && serverNameRE.MatchString(app) {
		modes, err := c.d.Approvals.AppApprovalModes(ctx, app)
		if err == nil {
			return approvalTarget{app: app, vendor: modes}, nil
		}
		if !errors.Is(err, policy.ErrApprovalApp) {
			return approvalTarget{}, fmt.Errorf("gateway tools: approval modes: %w", err)
		}
	}
	s, err := c.lookupServer(ctx, user, app, false)
	if err != nil {
		var te *toolError
		if errors.As(err, &te) && te.class == "server_not_found" {
			return approvalTarget{}, errAppNotFound(app)
		}
		return approvalTarget{}, err
	}
	return approvalTarget{app: s.Name, server: s}, nil
}

// displayTool is a requested tool name as an error message may show it:
// short and nothing the redactor would hide, else "?".
func displayTool(raw string) string {
	if len(raw) > 64 || observability.Redact(raw) != raw {
		return "?"
	}
	return raw
}

func errAppNotFound(app string) error {
	return fail("app_not_found", "no built-in app with write tools or server %q visible to you; gateway.list_servers lists your servers", app)
}

func (c *Connector) isAdmin(ctx context.Context, user string) bool {
	switch {
	case c.d.Admin != nil:
		return c.d.Admin.IsAdmin(ctx, user)
	case c.d.Rates != nil:
		return c.d.Rates.IsAdmin(ctx, user)
	}
	return false
}

func (c *Connector) vendorLink(app string) (string, string) {
	vendor := app
	if c.d.VendorOf != nil {
		vendor = c.d.VendorOf(app)
	}
	return vendor, c.link("/admin/vendor-apps/" + vendor)
}

// toolMode is one write tool in the answers.
type toolMode struct {
	Name string            `json:"name"`
	Kind string            `json:"kind"`
	Mode snapshot.Approval `json:"mode"`
}

type modeCounts struct {
	WriteTools int `json:"write_tools"`
	Ask        int `json:"ask"`
	Auto       int `json:"auto"`
}

func countModes(tools []toolMode) modeCounts {
	n := modeCounts{WriteTools: len(tools)}
	for _, t := range tools {
		if t.Mode == snapshot.ApprovalAsk {
			n.Ask++
		} else {
			n.Auto++
		}
	}
	return n
}

// serverWrites lists the enabled write tools of an approved record by name.
func serverWrites(rec *snapshot.Record) []toolMode {
	out := []toolMode{}
	if rec == nil {
		return out
	}
	for _, name := range slices.Sorted(maps.Keys(rec.Review)) {
		tr := rec.Review[name]
		if tr.Enabled && tr.Kind == snapshot.KindWrite {
			out = append(out, toolMode{Name: snapshot.DisplayName(name), Kind: string(snapshot.KindWrite), Mode: tr.Mode()})
		}
	}
	return out
}

// mayChangeServer: the owner of a private server, or an admin (who sets
// a published server's modes).
func (c *Connector) mayChangeServer(ctx context.Context, user string, s *store.MCPServer) (snapshot.Actor, bool) {
	if c.isAdmin(ctx, user) {
		return snapshot.Actor{UserID: user, Admin: true}, true
	}
	if s.OwnerUserID == user && s.Audience == store.MCPAudiencePrivate {
		return snapshot.Actor{UserID: user}, true
	}
	return snapshot.Actor{}, false
}

func (c *Connector) getToolApprovals(ctx context.Context, user string, args map[string]any) (connectors.Result, error) {
	if err := checkArgs(args, "app"); err != nil {
		return connectors.Result{}, err
	}
	app, err := requiredString(args, "app")
	if err != nil {
		return connectors.Result{}, err
	}
	target, err := c.resolveApp(ctx, user, app)
	if err != nil {
		return connectors.Result{}, err
	}
	const change = "Changing modes (gateway.set_tool_approval) always needs your approval in the browser."
	if target.server == nil {
		tools := make([]toolMode, 0, len(target.vendor))
		for _, m := range target.vendor {
			tools = append(tools, toolMode{Name: m.FullName(), Kind: string(connectors.KindWrite), Mode: m.Mode})
		}
		vendor, link := c.vendorLink(target.app)
		return connectors.Result{Content: map[string]any{
			"app": target.app, "type": "vendor_app", "vendor": vendor, "tools": tools, "counts": countModes(tools),
			"can_change": c.isAdmin(ctx, user), "link": link,
			"note": "Organization-wide modes, set by administrators. auto runs a tool as the user's roles say (a role's confirm or deny still applies); ask always needs an approval. " + change,
		}}, nil
	}
	s := target.server
	cur, err := c.d.Snapshots.Current(ctx, snapshot.Actor{UserID: user}, s.ID)
	if err != nil && !errors.Is(err, snapshot.ErrNoSnapshot) {
		return connectors.Result{}, fmt.Errorf("gateway tools: current snapshot: %w", err)
	}
	tools := serverWrites(cur)
	_, may := c.mayChangeServer(ctx, user, s)
	note := "auto runs a write tool without an approval; ask needs one. Role denies, user restrictions and token limits still apply. " + change
	if cur == nil {
		note = "Nothing is approved yet: approve the server's tools on its review page first. " + change
	}
	return connectors.Result{Content: map[string]any{
		"app": s.Name, "server_id": s.ID, "type": "server", "approved": cur != nil, "tools": tools, "counts": countModes(tools),
		"can_change": may, "link": c.link(fedportal.ServerPath(s.ID)), "note": note,
	}}, nil
}

// requestedModes reads set_tool_approval's tools / all into modes over the
// write tools names (canonical names), mapping each requested name with
// canon (prefix stripped, display name matched); exactly one of the two.
func requestedModes(args map[string]any, writes []string, canon func(string) (string, bool)) (map[string]snapshot.Approval, error) {
	rawTools, hasTools := args["tools"]
	all, err := stringArg(args, "all")
	if err != nil {
		return nil, err
	}
	switch {
	case hasTools && all != "":
		return nil, fail("args_invalid", "give either tools or all, not both")
	case !hasTools && all == "":
		return nil, fail("args_invalid", "give tools (tool name to ask or auto) or all (ask or auto)")
	}
	modes := map[string]snapshot.Approval{}
	if all != "" {
		mode := snapshot.Approval(all)
		if !mode.Valid() {
			return nil, fail("args_invalid", "all must be ask or auto")
		}
		for _, name := range writes {
			modes[name] = mode
		}
		return modes, nil
	}
	m, ok := rawTools.(map[string]any)
	if !ok || len(m) == 0 {
		return nil, fail("args_invalid", "tools must be an object of tool name to ask or auto")
	}
	if len(m) > 500 {
		return nil, fail("args_invalid", "at most 500 tools")
	}
	for _, raw := range slices.Sorted(maps.Keys(m)) {
		if !toolNameRE.MatchString(raw) {
			return nil, fail("args_invalid", "tools: %q is not a tool name", "?")
		}
		v, _ := m[raw].(string)
		mode := snapshot.Approval(v)
		if !mode.Valid() {
			return nil, fail("args_invalid", "tools: the mode of %q must be ask or auto", displayTool(raw))
		}
		name, ok := canon(raw)
		if !ok {
			return nil, fail("args_invalid", "%q is not a write tool of the app (read tools always run without asking); gateway.get_tool_approvals lists them", displayTool(raw))
		}
		modes[name] = mode
	}
	return modes, nil
}

func (c *Connector) setToolApproval(ctx context.Context, user string, args map[string]any) (connectors.Result, error) {
	// The tools object's keys are tool names (some contain words like
	// "token"): they are validated below, not as argument names.
	rest := maps.Clone(args)
	delete(rest, "tools")
	if err := checkArgs(rest, "app", "all", "tools"); err != nil {
		return connectors.Result{}, err
	}
	app, err := requiredString(args, "app")
	if err != nil {
		return connectors.Result{}, err
	}
	target, err := c.resolveApp(ctx, user, app)
	if err != nil {
		return connectors.Result{}, err
	}
	if target.server == nil {
		return c.setVendorApproval(ctx, user, target, args)
	}
	return c.setServerApproval(ctx, user, target.server, args)
}

func (c *Connector) setVendorApproval(ctx context.Context, user string, target approvalTarget, args map[string]any) (connectors.Result, error) {
	writes := make([]string, 0, len(target.vendor))
	for _, m := range target.vendor {
		writes = append(writes, m.Tool)
	}
	canon := func(raw string) (string, bool) {
		name := strings.TrimPrefix(raw, target.app+".")
		return name, slices.Contains(writes, name)
	}
	modes, err := requestedModes(args, writes, canon)
	if err != nil {
		return connectors.Result{}, err
	}
	vendor, link := c.vendorLink(target.app)
	if !c.isAdmin(ctx, user) {
		return connectors.Result{}, fail("not_permitted", "only an administrator changes the approval modes of built-in apps (Settings, Vendor apps, %s)", vendor)
	}
	ch, err := c.d.Approvals.SetAppApprovalModes(ctx, user, target.app, modes)
	switch {
	case errors.Is(err, policy.ErrApprovalTool), errors.Is(err, policy.ErrApprovalMode):
		return connectors.Result{}, fail("args_invalid", "choose ask or auto for write tools of %s", target.app)
	case err != nil:
		return connectors.Result{}, fmt.Errorf("gateway tools: set approval modes: %w", err)
	}
	c.log.Info("vendor app approval modes changed through the gateway tools", "event", "gateway_tools.approval_modes_changed",
		"user_id", user, "app", target.app, "changed", ch.Changed)
	return connectors.Result{Content: map[string]any{
		"app": target.app, "type": "vendor_app", "changed": ch.Changed, "ask": ch.Ask, "auto": ch.Auto, "link": link,
	}}, nil
}

func (c *Connector) setServerApproval(ctx context.Context, user string, s *store.MCPServer, args map[string]any) (connectors.Result, error) {
	cur, err := c.d.Snapshots.Current(ctx, snapshot.Actor{UserID: user}, s.ID)
	if errors.Is(err, snapshot.ErrNoSnapshot) {
		return connectors.Result{}, fail("not_reviewed", "nothing is approved on %s yet; approve its tools in the browser at %s", s.Name, c.link(fedportal.ReviewPath(s.ID)))
	}
	if err != nil {
		return connectors.Result{}, fmt.Errorf("gateway tools: current snapshot: %w", err)
	}
	var writes []string
	display := map[string]string{}
	for _, name := range slices.Sorted(maps.Keys(cur.Review)) {
		if tr := cur.Review[name]; tr.Enabled && tr.Kind == snapshot.KindWrite {
			writes = append(writes, name)
			display[snapshot.DisplayName(name)] = name
		}
	}
	canon := func(raw string) (string, bool) {
		raw = strings.TrimPrefix(raw, s.Name+".")
		if slices.Contains(writes, raw) {
			return raw, true
		}
		name, ok := display[raw]
		return name, ok
	}
	modes, err := requestedModes(args, writes, canon)
	if err != nil {
		return connectors.Result{}, err
	}
	actor, ok := c.mayChangeServer(ctx, user, s)
	if !ok {
		if s.Audience != store.MCPAudiencePrivate {
			return connectors.Result{}, fail("not_permitted", "%s is published: an administrator sets its approval modes", s.Name)
		}
		return connectors.Result{}, fail("not_permitted", "only the owner of %s changes its approval modes", s.Name)
	}
	rec, changed, err := c.d.Snapshots.SetApprovalModes(ctx, actor, s.ID, modes)
	switch {
	case errors.Is(err, snapshot.ErrReviewNotAllowed):
		return connectors.Result{}, fail("not_permitted", "you may not change the approval modes of %s", s.Name)
	case errors.Is(err, snapshot.ErrNoSnapshot):
		return connectors.Result{}, fail("not_reviewed", "the approved tools of %s changed; try again", s.Name)
	case errors.Is(err, snapshot.ErrUnknownTool), errors.Is(err, snapshot.ErrInvalidApproval):
		return connectors.Result{}, fail("args_invalid", "choose ask or auto for enabled write tools of %s", s.Name)
	case err != nil:
		return connectors.Result{}, fmt.Errorf("gateway tools: set approval modes: %w", err)
	}
	c.recordServerApproval(ctx, user, s, rec, changed)
	if err := c.d.Manager.ServerChanged(context.WithoutCancel(ctx), s.ID); err != nil {
		c.log.Warn("server change not applied yet; periodic reload will retry", "event", "gateway_tools.server_changed_failed",
			"server_id", s.ID, "error", err.Error())
	}
	auto := len(rec.Review.AutoRunWrites())
	return connectors.Result{Content: map[string]any{
		"app": s.Name, "server_id": s.ID, "type": "server", "changed": changed, "auto": auto, "ask": len(writes) - auto,
		"link": c.link(fedportal.ServerPath(s.ID)),
	}}, nil
}

// recordServerApproval audits a server mode change exactly like the
// servers portal (mcp_server.approval_modes_changed, counts only).
func (c *Connector) recordServerApproval(ctx context.Context, user string, s *store.MCPServer, rec *snapshot.Record, changed int) {
	c.log.Info("approval modes changed through the gateway tools", "event", fedportal.ApprovalModesChangedEvent, "user_id", user,
		"server_id", s.ID, "changed", changed)
	if c.d.Audit == nil {
		return
	}
	ev := audit.Event{
		Time: time.Now(), UserID: user, ResourceIdentity: fedportal.ApprovalAuditResource(s, rec, changed), Decision: "allow",
		Outcome: "succeeded", RequestID: observability.RequestIDFromContext(ctx),
	}
	if err := c.d.Audit.Record(ctx, ev); err != nil {
		c.log.Error("audit event not recorded", "event", "gateway_tools.audit_failed", "action", fedportal.ApprovalModesChangedEvent,
			"error", observability.RedactError(err))
	}
}
