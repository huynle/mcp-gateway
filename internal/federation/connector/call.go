package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/federation/auth"
	"github.com/huynle/mcp-gateway/internal/federation/client"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/federation/tunnel"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/store"
)

// handlerFor binds the registry tools of one server: each call goes
// through Manager.call with the upstream tool name and the kind the tool
// was listed with.
func (m *Manager) handlerFor(serverID string) func(upstream string, kind connectors.Kind) connectors.Handler {
	return func(upstream string, kind connectors.Kind) connectors.Handler {
		return func(ctx context.Context, call connectors.Call) (connectors.Result, error) {
			return m.call(ctx, serverID, upstream, kind, call)
		}
	}
}

// call runs one federated tool call after the pipeline (visibility,
// account, policy, approval, ledger) let it through:
//
//  1. the server must still exist and be active;
//  2. snapshot.Allowed as the caller (RLS visibility again, the tool in
//     the approved snapshot, enabled, arguments valid against the pinned
//     schema); a tool that became a write since it was listed as a read
//     is refused (tool_changed) and the registry reloaded, so a write
//     never skips the confirmation the policy gives writes;
//  3. the caller's credential (auth.ForUser: their own connection, the
//     shared secret or none);
//  4. the endpoint: netguard's client, or for tunnel:// servers the
//     tunnel transport after checking the tunnel belongs to the server's
//     owner; static headers from header_config;
//  5. connect + tools/call under auth.Reauth (one refresh-and-retry on a
//     401), then the upstream result as is (content, structuredContent,
//     isError).
//
// Gateway credentials are never forwarded: the federation client builds
// every upstream request itself from the endpoint and the Authorizer.
// Failures are class-level: refusals are *mcp.ToolError, upstream
// failures a handler error with ErrorClass (and ErrOutcomeUnknown for a
// write whose tools/call may have reached the server).
func (m *Manager) call(ctx context.Context, serverID, upstream string, listed connectors.Kind, call connectors.Call) (connectors.Result, error) {
	user := call.Principal.UserID
	server, tool, kind, err := m.check(ctx, serverID, upstream, listed, call)
	if err != nil {
		return connectors.Result{}, err
	}
	az, err := m.o.Credentials.ForUser(ctx, server, user)
	if err != nil {
		return connectors.Result{}, m.credentialError(call.Tool, user, server, err)
	}
	hc, ep, err := m.endpoint(ctx, server)
	if err != nil {
		return connectors.Result{}, m.credentialLink(user, server, errTunnelURL, err)
	}
	c, err := client.New(client.Options{
		HTTPClient: hc, Authorizer: az, Timeout: m.o.Timeout,
		ClientVersion: m.o.Version, Log: m.log, OnCall: m.o.OnCall,
	})
	if err != nil {
		return connectors.Result{}, mcp.NewToolError(mcp.CodeInternal, "client_unavailable", "the upstream client could not be built")
	}
	var res *sdk.CallToolResult
	err = auth.Reauth(ctx, az, func() error {
		s, err := c.Connect(ctx, ep)
		if err != nil {
			return err
		}
		defer func() { _ = s.Close() }()
		r, err := s.CallToolMeta(ctx, upstream, call.Args, reviewedMeta(tool))
		res = r
		return err
	})
	if err != nil {
		return connectors.Result{}, m.callError(user, server, kind, err)
	}
	if res == nil {
		res = &sdk.CallToolResult{}
	}
	return connectors.Result{Content: res}, nil
}

// check is steps 1 and 2 of call, shared with the pre-policy check
// (precheck.go): the server is still there and active, and the approved
// snapshot allows the tool with these arguments as the caller. It
// returns the server, the approved tool and the reviewed kind, or a
// class-level refusal.
func (m *Manager) check(ctx context.Context, serverID, upstream string, listed connectors.Kind, call connectors.Call) (*store.MCPServer, snapshot.Tool, snapshot.Kind, error) {
	server, err := m.o.Store.GetServer(ctx, serverID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, snapshot.Tool{}, "", mcp.ErrToolNotFound(call.Tool)
	case err != nil:
		m.log.Error("federated server lookup failed", "event", "federation.server_lookup_failed", "server_id", serverID,
			"error", observability.RedactError(err))
		return nil, snapshot.Tool{}, "", mcp.NewToolError(mcp.CodeInternal, "server_unavailable", "the server could not be looked up")
	case server.Status != store.MCPServerActive:
		return nil, snapshot.Tool{}, "", mcp.ErrToolNotFound(call.Tool)
	}
	tool, kind, err := m.o.Snapshots.Allowed(ctx, snapshot.Actor{UserID: call.Principal.UserID}, serverID, upstream, call.Args)
	if err != nil {
		return nil, snapshot.Tool{}, "", m.snapshotError(call.Tool, serverID, err)
	}
	if listed == connectors.KindRead && kind != snapshot.KindRead {
		_ = m.ServerChanged(ctx, serverID)
		return nil, snapshot.Tool{}, "", mcp.NewToolError(mcp.CodeDenied, "tool_changed",
			call.Tool+" was re-reviewed as a write since it was listed; list the tools again and retry")
	}
	return server, tool, kind, nil
}

// endpoint returns the HTTP client and endpoint for server.
func (m *Manager) endpoint(ctx context.Context, server *store.MCPServer) (*http.Client, client.Endpoint, error) {
	ep := client.Endpoint{
		URL: server.URL, Transport: client.Transport(server.Transport),
		Headers: staticHeaders(server.HeaderConfig), Label: server.ID,
	}
	if ep.Transport == "" {
		ep.Transport = client.TransportAuto
	}
	if !tunnel.IsTunnelURL(server.URL) {
		return m.o.HTTPClient, ep, nil
	}
	unavailable := &upstreamError{class: "tunnel_unavailable",
		msg: server.Name + ": the server's tunnel is not available (revoked, or not the server owner's)"}
	if m.o.Tunnels == nil {
		return nil, ep, unavailable
	}
	id, _, err := tunnel.ParseURL(server.URL)
	if err != nil {
		return nil, ep, mcp.NewToolError(mcp.CodeNoAccount, "server_not_configured", server.Name+": the server's tunnel URL is invalid")
	}
	if err := m.o.Tunnels.Authorize(ctx, server.OwnerUserID, id); err != nil {
		if !errors.Is(err, tunnel.ErrForbidden) {
			m.log.Error("tunnel authorization failed", "event", "federation.tunnel_authorize_failed", "server_id", server.ID,
				"error", observability.RedactError(err))
		}
		return nil, ep, unavailable
	}
	u, err := tunnel.ClientURL(server.URL)
	if err != nil {
		return nil, ep, mcp.NewToolError(mcp.CodeNoAccount, "server_not_configured", server.Name+": the server's tunnel URL is invalid")
	}
	ep.URL = u
	return m.o.Tunnels.HTTPClient(m.o.HTTPClient), ep, nil
}

// staticHeaders reads header_config.static (non-secret headers sent to
// the server on every request). Invalid names are refused by the client.
func staticHeaders(raw json.RawMessage) map[string]string {
	var hc struct {
		Static map[string]string `json:"static"`
	}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &hc)
	}
	return hc.Static
}

// portalURL is where a user connects or reconnects their account.
func (m *Manager) portalURL(serverID string) string {
	return strings.TrimRight(m.o.BaseURL, "/") + ServerPath(serverID)
}

// snapshotError maps snapshot.Allowed refusals. Messages never echo
// arguments or upstream text.
func (m *Manager) snapshotError(tool, serverID string, err error) error {
	switch {
	case errors.Is(err, snapshot.ErrArgsInvalid):
		return mcp.NewToolError(mcp.CodeInvalidParams, "args_invalid", "arguments do not match the reviewed input schema of "+tool)
	case errors.Is(err, snapshot.ErrToolDisabled):
		return mcp.NewToolError(mcp.CodeDenied, "tool_disabled", tool+" is disabled in its server's review")
	case errors.Is(err, snapshot.ErrToolNotReviewed):
		return mcp.NewToolError(mcp.CodeDenied, "tool_not_reviewed", tool+" is not in its server's reviewed snapshot; it must be reviewed before it can be used")
	case errors.Is(err, snapshot.ErrNoSnapshot):
		return mcp.ErrToolNotFound(tool)
	}
	m.log.Error("snapshot check failed", "event", "federation.snapshot_failed", "server_id", serverID, "error", observability.RedactError(err))
	return mcp.NewToolError(mcp.CodeInternal, "snapshot_unavailable", "the reviewed snapshot could not be checked")
}

// credentialError maps auth.ForUser failures for user's call (with
// credential links, credentialLink turns them into -32042 answers).
func (m *Manager) credentialError(tool, user string, server *store.MCPServer, err error) error {
	return m.credentialLink(user, server, err, m.credentialAnswer(tool, server, err))
}

// credentialAnswer is credentialError without links.
func (m *Manager) credentialAnswer(tool string, server *store.MCPServer, err error) error {
	switch {
	case errors.Is(err, auth.ErrNotConnected):
		return mcp.NewToolError(mcp.CodeNoAccount, "auth_required",
			fmt.Sprintf("%s needs your %s account: connect it on the portal (%s) and retry", tool, server.Name, m.portalURL(server.ID)))
	case errors.Is(err, auth.ErrNeedsReconnect):
		return m.needsReconnect(server)
	case errors.Is(err, auth.ErrNotConfigured), errors.Is(err, auth.ErrUnsupported):
		return mcp.NewToolError(mcp.CodeNoAccount, "server_not_configured",
			server.Name+": the server's authentication is not set up; ask its owner")
	case errors.Is(err, store.ErrNotFound):
		return mcp.ErrToolNotFound(tool)
	case m.o.CredentialLinks && errors.Is(err, auth.ErrUserHeaderMissing):
		return mcp.NewToolError(mcp.CodeNoAccount, ClassUserHeaderMissing,
			fmt.Sprintf("%s needs your values for the %s server's per-user headers: set them on the portal (%s) and retry", tool, server.Name, m.portalURL(server.ID)))
	}
	m.log.Error("upstream credentials unavailable", "event", "federation.credentials_failed", "server_id", server.ID,
		"error", observability.RedactError(err))
	return mcp.NewToolError(mcp.CodeInternal, "credentials_unavailable", "the credentials for "+server.Name+" could not be loaded")
}

func (m *Manager) needsReconnect(server *store.MCPServer) error {
	return mcp.NewToolError(mcp.CodeNoAccount, "needs_reconnect",
		fmt.Sprintf("your %s connection has expired or was rejected: reconnect it on the portal (%s) and retry", server.Name, m.portalURL(server.ID)))
}

// unknownClasses are the upstream failures after which a write may or may
// not have happened, when they hit tools/call itself.
var unknownClasses = map[client.Class]bool{
	client.ClassTimeout: true, client.ClassUnreachable: true, client.ClassProtocol: true, client.ClassTooLarge: true,
}

// classText is what each class tells the user.
var classText = map[string]string{
	"tunnel_offline":       "the server's tunnel is offline; start `mcp-gateway tunnel` and retry",
	"upstream_unreachable": "the server could not be reached",
	"upstream_blocked":     "the server's address is not allowed (ask an admin to allow-list it)",
	"upstream_forbidden":   "the server refused the request (forbidden)",
	"upstream_protocol":    "the server did not answer like an MCP server",
	"upstream_too_large":   "the server's answer was too large",
	"upstream_timeout":     "the server did not answer in time",
	"upstream_tool_error":  "the server refused the tool call",
	"upstream_error":       "the call to the server failed",
}

// callError maps user's failed connect/tools/call (with credential links,
// credential refusals go through credentialLink).
func (m *Manager) callError(user string, server *store.MCPServer, kind snapshot.Kind, err error) error {
	switch {
	case errors.Is(err, auth.ErrNeedsReconnect):
		return m.credentialLink(user, server, err, m.needsReconnect(server))
	case errors.Is(err, auth.ErrSharedCredentialRejected):
		return m.credentialLink(user, server, err, mcp.NewToolError(mcp.CodeNoAccount, "shared_credential_rejected",
			server.Name+": the server rejected the shared credential; ask the server's owner or an admin to update it"))
	case m.o.CredentialLinks && errors.Is(err, auth.ErrNotConfigured):
		// A no-auth server answering 401 (auth.ErrNowRequiresAuth): the
		// owner's to fix. Without the flag it stays upstream_error.
		return m.credentialLink(user, server, err, m.credentialAnswer("", server, err))
	}
	write := kind != snapshot.KindRead
	var ce *client.Error
	isClient := errors.As(err, &ce)
	inCall := isClient && ce.Op == "tools/call"
	class, unknown := "upstream_error", false
	var te *tunnel.Error
	switch {
	case errors.As(err, &te) && te.Class == tunnel.ClassOffline:
		class, unknown = "tunnel_offline", write && inCall
	case isClient && ce.Class == client.ClassAuthRequired:
		return m.credentialLink(user, server, err, mcp.NewToolError(mcp.CodeNoAccount, "auth_required",
			fmt.Sprintf("%s asked for authentication: connect or reconnect your account on the portal (%s) and retry", server.Name, m.portalURL(server.ID))))
	case isClient:
		class = "upstream_" + strings.TrimSuffix(string(ce.Class), "_error")
		if ce.Class == client.ClassToolError {
			class = "upstream_tool_error"
		}
		unknown = write && inCall && unknownClasses[ce.Class]
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		class, unknown = "upstream_timeout", write
	}
	text, ok := classText[class]
	if !ok {
		class, text = "upstream_error", classText["upstream_error"]
	}
	m.log.Warn("federated call failed", "event", "federation.call_failed", "server", server.Name, "server_id", server.ID,
		"class", class, "outcome_unknown", unknown, "error", observability.RedactError(err))
	msg := server.Name + ": " + text
	if unknown {
		msg += "; the write may or may not have happened, check before retrying"
	}
	return &upstreamError{class: class, msg: msg, unknown: unknown}
}

// upstreamError is a class-level handler error: shown to the model as a
// tool error (IsError), audited and ledgered under its class
// (mcp.ClassedError), and an unknown outcome for the ledger when
// unknown is set.
type upstreamError struct {
	class   string
	msg     string
	unknown bool
}

func (e *upstreamError) Error() string      { return e.msg }
func (e *upstreamError) ErrorClass() string { return e.class }

// Is makes errors.Is(err, connectors.ErrOutcomeUnknown) hold for writes
// whose outcome is unknown.
func (e *upstreamError) Is(target error) bool {
	return e.unknown && target == connectors.ErrOutcomeUnknown
}
