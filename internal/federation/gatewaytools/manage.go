package gatewaytools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/huynle/mcp-gateway/internal/caps"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/federation/auth"
	"github.com/huynle/mcp-gateway/internal/federation/client"
	"github.com/huynle/mcp-gateway/internal/federation/connector"
	fedportal "github.com/huynle/mcp-gateway/internal/federation/portal"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/federation/tunnel"
	"github.com/huynle/mcp-gateway/internal/permissions"
	"github.com/huynle/mcp-gateway/internal/store"
)

// maxURL bounds a server URL (the portal's limit).
const maxURL = 2048

// blockedMessage is the portal's wording for an address netguard refuses.
var blockedMessage = fedportal.UpstreamMessage(client.ClassBlocked)

// checkHTTPSURL validates a user-supplied https URL before any request:
// shape (the portal's rule), no credential in the query, and netguard's
// literal-host check (private, loopback, link-local and metadata
// addresses are refused unless an admin allow-listed them).
func (c *Connector) checkHTTPSURL(ctx context.Context, raw string) error {
	u, err := url.Parse(raw)
	if err == nil && (u.User != nil || secretQuery(u)) {
		return fail("secret_refused", "%s", secretMessage)
	}
	if err != nil || !fedportal.AbsHTTPSURL(raw) {
		return fail("url_invalid", "the address must be an https URL (no user name or password, no fragment)")
	}
	if err := c.d.URLCheck.CheckURL(ctx, u); err != nil {
		return fail("upstream_blocked", "%s", blockedMessage)
	}
	return nil
}

// detectClass is the audit class of a detection failure.
func detectClass(err error) string {
	var ce *client.Error
	if errors.As(err, &ce) {
		return "upstream_" + strings.TrimSuffix(string(ce.Class), "_error")
	}
	return "detect_failed"
}

func (c *Connector) detectAuth(ctx context.Context, user string, args map[string]any) (connectors.Result, error) {
	if err := checkArgs(args, "url"); err != nil {
		return connectors.Result{}, err
	}
	raw, err := requiredString(args, "url")
	if err != nil {
		return connectors.Result{}, err
	}
	if err := c.checkHTTPSURL(ctx, raw); err != nil {
		return connectors.Result{}, err
	}
	res, err := c.d.Detector.Detect(ctx, raw)
	if err != nil {
		c.log.Info("detect failed", "event", "gateway_tools.detect_failed", "user_id", user, "error", err.Error())
		return connectors.Result{}, fail(detectClass(err), "%s", fedportal.DetectMessage(err))
	}
	out := map[string]any{
		"url":            raw,
		"auth_kinds":     nonNil(res.AuthKinds),
		"oauth":          slices.Contains(res.AuthKinds, store.MCPAuthOAuth),
		"dcr":            res.SupportsDCR,
		"cimd":           res.SupportsCIMD,
		"pkce_s256":      res.SupportsS256,
		"offline_access": res.OfflineAccess,
		"scopes":         displayList(res.Scopes, snapshot.DisplayName),
		"note": "Use the first auth kind with gateway.add_server. Credentials are never passed to the tools: OAuth sign-in and " +
			"API keys, tokens or header values are entered in the browser after adding.",
	}
	if len(res.Blocked) > 0 {
		out["blocked"] = displayList(res.Blocked, snapshot.DisplayTitle)
	}
	return connectors.Result{Content: out}, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func displayList(in []string, display func(string) string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, display(s))
	}
	return out
}

var authKinds = []string{store.MCPAuthOAuth, store.MCPAuthAPIKey, store.MCPAuthBearer, store.MCPAuthHeaders, store.MCPAuthNone}

// addServerArgs are add_server's arguments.
var addServerArgs = []string{"name", "url", "auth_kind", "credential_mode", "api_key_in", "api_key_name", "static_header_names"}

func (c *Connector) addServer(ctx context.Context, user string, args map[string]any) (connectors.Result, error) {
	s, err := c.buildServer(ctx, user, args)
	if err != nil {
		return connectors.Result{}, err
	}
	var ce *caps.ExceededError
	switch err := c.d.Manager.CreateServer(ctx, s); {
	case errors.Is(err, permissions.ErrNotPermitted):
		return connectors.Result{}, fail("not_permitted", "your roles do not allow adding MCP servers; ask an admin for a role that may add MCP servers")
	case errors.Is(err, connector.ErrReservedServerName):
		return connectors.Result{}, fail("name_invalid", "the name %q is reserved for a built-in app; choose another", s.Name)
	case errors.Is(err, connector.ErrInvalidServerName):
		return connectors.Result{}, fail("name_invalid", "use 1-63 lower-case letters, digits, '-' or '_' for the name")
	case errors.As(err, &ce):
		return connectors.Result{}, fail(caps.Class, "%s", ce.Error())
	case errors.Is(err, connector.ErrServerNameTaken):
		return connectors.Result{}, fail("name_taken", "the name %q is already taken; choose another", s.Name)
	case err != nil:
		return connectors.Result{}, fmt.Errorf("gateway tools: create server: %w", err)
	}
	c.log.Info("server added through the gateway tools", "event", "gateway_tools.server_added", "user_id", user, "server_id", s.ID,
		"auth_kind", s.AuthKind, "credential_mode", s.CredentialMode)
	d, err := c.detail(ctx, user, s)
	if err != nil {
		return connectors.Result{}, err
	}
	steps := d.NextSteps
	if s.CredentialMode == store.MCPCredentialShared && fedportal.SecretKind(s.AuthKind) {
		// Make the shared-credential note explicit even if detail already
		// listed it.
		if !slices.ContainsFunc(steps, func(n nextStep) bool { return n.Step == "set_shared_credential" }) {
			steps = append([]nextStep{{Step: "set_shared_credential", Link: c.link(fedportal.EditPath(s.ID)),
				Note: "The shared credential is set in the browser on the server's settings page."}}, steps...)
		}
	}
	return connectors.Result{Content: map[string]any{
		"server_id":   s.ID,
		"server":      d.serverView,
		"next_steps":  steps,
		"review_link": c.link(fedportal.ReviewPath(s.ID)),
		"note": "The server is private and every tool starts disabled. After connecting (if needed), call gateway.refresh_server, " +
			"then approve the tools in the browser at review_link.",
	}}, nil
}

// buildServer validates add_server's arguments into a server row (owner
// user, private, transport auto).
func (c *Connector) buildServer(ctx context.Context, user string, args map[string]any) (*store.MCPServer, error) {
	if err := checkArgs(args, addServerArgs...); err != nil {
		return nil, err
	}
	str := map[string]string{}
	for _, k := range []string{"name", "url", "auth_kind", "credential_mode", "api_key_in", "api_key_name"} {
		v, err := stringArg(args, k)
		if err != nil {
			return nil, err
		}
		str[k] = v
	}
	name, rawURL, kind, mode := str["name"], str["url"], str["auth_kind"], str["credential_mode"]
	for _, k := range []string{"name", "url", "auth_kind", "credential_mode"} {
		if str[k] == "" {
			return nil, fail("args_invalid", "%s is required", k)
		}
	}
	if err := connector.ValidateServerName(name); err != nil {
		if errors.Is(err, connector.ErrReservedServerName) {
			return nil, fail("name_invalid", "the name %q is reserved for a built-in app; choose another", name)
		}
		return nil, fail("name_invalid", "use 1-63 lower-case letters, digits, '-' or '_' for the name")
	}
	u, err := c.serverURL(ctx, user, rawURL)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(authKinds, kind) {
		return nil, fail("args_invalid", "auth_kind must be one of %s", strings.Join(authKinds, ", "))
	}
	if mode != store.MCPCredentialPerUser && mode != store.MCPCredentialShared {
		return nil, fail("args_invalid", "credential_mode must be per_user or shared")
	}
	if kind == store.MCPAuthNone {
		mode = store.MCPCredentialPerUser
	}
	if kind == store.MCPAuthOAuth && mode == store.MCPCredentialShared {
		return nil, fail("args_invalid", "shared OAuth tokens are not supported; use per_user, or a shared api_key, bearer or headers")
	}

	var ac authConfig
	in, keyName := str["api_key_in"], str["api_key_name"]
	if (in != "" || keyName != "") && kind != store.MCPAuthAPIKey {
		return nil, fail("args_invalid", "api_key_in and api_key_name apply to auth_kind api_key only")
	}
	if kind == store.MCPAuthAPIKey && (in != "" || keyName != "") {
		switch in {
		case "header", "":
			if keyName != "" && !fedportal.ValidHeaderName(keyName) {
				return nil, fail("args_invalid", "api_key_name is not a usable header name")
			}
			if keyName != "" {
				ac.APIKey = &apiKeyConfig{Header: http.CanonicalHeaderKey(keyName)}
			}
		case "query":
			if !fedportal.ValidQueryName(keyName) {
				return nil, fail("args_invalid", "api_key_name must be the query parameter name (letters, digits, '-', '_' or '.')")
			}
			ac.APIKey = &apiKeyConfig{Query: keyName}
		default:
			return nil, fail("args_invalid", "api_key_in must be header or query")
		}
	}
	names, err := stringList(args, "static_header_names")
	if err != nil {
		return nil, err
	}
	var hc headerConfig
	for _, n := range names {
		if strings.ContainsAny(n, ":= \t") {
			return nil, fail("secret_refused", "%s", secretMessage)
		}
		if !fedportal.ValidHeaderName(n) {
			return nil, fail("args_invalid", "static_header_names: %q is not a usable header name", displayHeader(n))
		}
		if k := http.CanonicalHeaderKey(n); !slices.Contains(hc.PerUser, k) {
			hc.PerUser = append(hc.PerUser, k)
		}
	}
	if len(hc.PerUser) > 50 {
		return nil, fail("args_invalid", "at most 50 header names")
	}
	acRaw, err := json.Marshal(ac)
	if err != nil {
		return nil, err
	}
	hcRaw, err := json.Marshal(hc)
	if err != nil {
		return nil, err
	}
	return &store.MCPServer{
		Name: name, URL: u, OwnerUserID: user, Transport: store.MCPTransportAuto, CredentialMode: mode, AuthKind: kind,
		AuthConfig: acRaw, HeaderConfig: hcRaw,
	}, nil
}

// displayHeader keeps a header name for an error message only when it is a
// plain token.
func displayHeader(n string) string {
	if len(n) > 64 || !hostRE.MatchString(n) {
		return "?"
	}
	return n
}

// serverURL validates the url argument: an https URL netguard does not
// refuse, or tunnel://<id>/<path> of one of the caller's live tunnels.
func (c *Connector) serverURL(ctx context.Context, user, raw string) (string, error) {
	if len(raw) > maxURL {
		return "", fail("url_invalid", "the address is too long")
	}
	if strings.HasPrefix(strings.ToLower(raw), tunnel.Scheme+"://") {
		id, _, err := tunnel.ParseURL(raw)
		if err != nil {
			return "", fail("url_invalid", "a tunnel address looks like tunnel://<your tunnel id>/<path>")
		}
		tunnels, err := c.d.Servers.ListTunnels(ctx, user)
		if err != nil {
			return "", fmt.Errorf("gateway tools: list tunnels: %w", err)
		}
		if !slices.ContainsFunc(tunnels, func(t store.MCPTunnel) bool { return t.ID == id && t.RevokedAt == nil }) {
			return "", fail("url_invalid", "use one of your own tunnels (tunnels are created in the browser at %s)", c.link("/servers"))
		}
		return raw, nil
	}
	if err := c.checkHTTPSURL(ctx, raw); err != nil {
		return "", err
	}
	return raw, nil
}

// maxDiffNames caps the names listed per change kind.
const maxDiffNames = 20

type changeSummary struct {
	Count     int      `json:"count"`
	Names     []string `json:"names"`
	Truncated bool     `json:"truncated,omitempty"`
}

func summarize(names []string) changeSummary {
	s := changeSummary{Count: len(names), Names: []string{}}
	for i, n := range names {
		if i == maxDiffNames {
			s.Truncated = true
			break
		}
		s.Names = append(s.Names, snapshot.DisplayName(n))
	}
	return s
}

func (c *Connector) refreshServer(ctx context.Context, user string, args map[string]any) (connectors.Result, error) {
	s, err := c.findServer(ctx, user, args, true)
	if err != nil {
		return connectors.Result{}, err
	}
	sess, err := c.d.Clients.Open(ctx, s, user)
	var rec *snapshot.Record
	var diff snapshot.Diff
	if err == nil {
		rec, diff, err = c.d.Snapshots.Refresh(ctx, snapshot.Actor{UserID: user}, s.ID, sess)
		if cerr := sess.Close(); cerr != nil {
			c.log.Debug("close upstream session", "server_id", s.ID, "error", cerr.Error())
		}
	}
	if err != nil {
		c.log.Info("refresh failed", "event", "gateway_tools.refresh_failed", "user_id", user, "server_id", s.ID, "error", err.Error())
		return connectors.Result{}, fail("refresh_failed", "refresh failed: %s See %s", fedportal.SessionMessage(err), c.link(fedportal.ServerPath(s.ID)))
	}
	c.log.Info("server refreshed through the gateway tools", "event", "gateway_tools.server_refreshed", "user_id", user, "server_id", s.ID)
	changed := make([]string, 0, len(diff.Changed))
	for _, ch := range diff.Changed {
		changed = append(changed, ch.Name)
	}
	pending := !diff.Empty()
	// Upstream items discovery left out (NUL or control characters in a
	// key, NUL in a schema key): display-safe names, never stored.
	skipped := rec.Skipped
	if skipped == nil {
		skipped = []snapshot.Skipped{}
	}
	note := "Nothing was approved. New and changed tools stay disabled until you approve them in the browser at review_link."
	if !pending {
		note = "No changes since the approved snapshot. Nothing was approved; manage the tools in the browser at review_link."
	}
	if len(skipped) > 0 {
		note += " Some upstream items were skipped (see skipped): their names or schemas contain characters the gateway cannot store or match, so they are not in the snapshot and cannot be enabled."
	}
	return connectors.Result{Content: map[string]any{
		"server":       s.Name,
		"server_id":    s.ID,
		"from_version": diff.FromVersion,
		"to_version":   rec.Version,
		"added":        summarize(diff.Added),
		"changed":      summarize(changed),
		"removed":      summarize(diff.Removed),
		"resources":    len(diff.Resources.Added) + len(diff.Resources.Removed) + len(diff.Resources.Changed),
		"templates":    len(diff.ResourceTemplates.Added) + len(diff.ResourceTemplates.Removed) + len(diff.ResourceTemplates.Changed),
		"prompts":      len(diff.Prompts.Added) + len(diff.Prompts.Removed) + len(diff.Prompts.Changed),
		"skipped":      skipped,
		"review_link":  c.link(fedportal.ReviewPath(s.ID)),
		"note":         note,
	}}, nil
}

func (c *Connector) deleteServer(ctx context.Context, user string, args map[string]any) (connectors.Result, error) {
	s, err := c.findServer(ctx, user, args, true)
	if err != nil {
		return connectors.Result{}, err
	}
	switch err := c.d.Servers.DeleteServer(ctx, user, s.ID); {
	case errors.Is(err, store.ErrNotFound):
		return connectors.Result{}, errServerNotFound(s.Name, true)
	case err != nil:
		return connectors.Result{}, fmt.Errorf("gateway tools: delete server: %w", err)
	}
	c.log.Info("server deleted through the gateway tools", "event", "gateway_tools.server_deleted", "user_id", user, "server_id", s.ID)
	if err := c.d.Manager.ServerChanged(context.WithoutCancel(ctx), s.ID); err != nil {
		c.log.Warn("server change not applied yet; periodic reload will retry", "event", "gateway_tools.server_changed_failed",
			"server_id", s.ID, "error", err.Error())
	}
	return connectors.Result{Content: map[string]any{"deleted": s.Name, "server_id": s.ID}}, nil
}

// Compile-time checks that the production types fit.
var (
	_ Detector = (*auth.Service)(nil)
	_ Manager  = (*connector.Manager)(nil)
)
