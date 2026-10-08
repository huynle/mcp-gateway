package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

const (
	// DefaultMaxBody bounds a request body (GATEWAY_MCP_MAX_BODY): 1 MiB is
	// far above any tool call and far below what would hurt a replica.
	DefaultMaxBody int64 = 1 << 20
	// ProtectedResourcePath is where the gateway publishes its OAuth
	// Protected Resource Metadata (RFC 9728, decision ysorv868). The
	// document itself ships with the authorization server; the 401
	// challenge already points at it so harnesses discover it.
	ProtectedResourcePath = "/.well-known/oauth-protected-resource"
	// MetaReadKey is the _meta key on a read result carrying the empty,
	// partial and unavailable flags (connectors.Result).
	MetaReadKey = "mcp-gateway/read"
	// ServerName is what the gateway reports in initialize.
	ServerName = "mcp-gateway"
)

// Injected argument descriptions, shown to the model in tools/list.
const (
	accountDescription = "Connected account to run this call against. Optional when you have exactly one account for the app; " +
		"required when you have several (use the app's list_accounts tool to find the ids)."
	approvalDescription = "Approval id from an earlier \"approval required\" response. Set it to retry the call once the " +
		"approval has been granted; the gateway then executes the arguments stored with the approval."
)

// Options configures Handler. Registry, Authenticator and BaseURL are
// required; the rest default as documented on each field.
type Options struct {
	// Registry holds the tools; later modules populate it.
	Registry *connectors.Registry
	// Pipeline runs tools/call. nil builds DefaultPipeline from Visibility,
	// RateLimiter, Audit and Log. Callers that insert stages build the
	// pipeline first and pass it here.
	Pipeline *Pipeline
	// Visibility filters tools/list (and resolve, when Pipeline is nil).
	// Defaults to ScopeVisibility.
	Visibility Visibility
	// Authenticator validates bearer tokens (tokens.Service, later composed
	// with the OAuth access-token authenticator).
	Authenticator tokens.Authenticator
	// Auth tunes the bearer middleware (failure limiter, client IP,
	// metrics). WWWAuthenticateExtra is overwritten with the resource
	// metadata URL derived from BaseURL.
	Auth tokens.MiddlewareOptions
	// BaseURL is GATEWAY_BASE_URL; the 401 challenge advertises BaseURL +
	// ProtectedResourcePath.
	BaseURL string
	// MaxBody bounds request bodies; 0 means DefaultMaxBody.
	MaxBody int64
	// Audit receives one event per tools/call (default pipeline only).
	Audit audit.Recorder
	// RateLimiter is the per-user hook (default pipeline only).
	RateLimiter RateLimiter
	// Log defaults to slog.Default().
	Log *slog.Logger
	// Version is reported in initialize; empty means "dev".
	Version string
}

// Handler returns the /mcp endpoint: tokens.BearerMiddleware around the
// SDK's Streamable HTTP handler in stateless mode (decision ysorv868: no
// session store, no sticky sessions, GET and DELETE answer 405). One SDK
// server serves every request; a receiving middleware owns tools/list
// (registry filtered by Visibility, schemas with the injected account and
// approval_id properties) and tools/call (the Pipeline), so the SDK's own
// tool table stays empty and the registry is the single source of truth.
func Handler(opts Options) (http.Handler, error) {
	switch {
	case opts.Registry == nil:
		return nil, errors.New("mcp: registry is required")
	case opts.Authenticator == nil:
		return nil, errors.New("mcp: authenticator is required")
	case strings.TrimSpace(opts.BaseURL) == "":
		return nil, errors.New("mcp: base URL is required")
	case opts.MaxBody < 0:
		return nil, fmt.Errorf("mcp: max body must not be negative, got %d", opts.MaxBody)
	}
	if opts.MaxBody == 0 {
		opts.MaxBody = DefaultMaxBody
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Visibility == nil {
		opts.Visibility = ScopeVisibility{}
	}
	if opts.Version == "" {
		opts.Version = "dev"
	}
	if opts.Pipeline == nil {
		p, err := DefaultPipeline(PipelineDeps{
			Registry: opts.Registry, Visibility: opts.Visibility, RateLimiter: opts.RateLimiter, Audit: opts.Audit, Log: opts.Log,
		})
		if err != nil {
			return nil, err
		}
		opts.Pipeline = p
	}

	e := &endpoint{opts: opts}
	server := sdk.NewServer(&sdk.Implementation{Name: ServerName, Version: opts.Version}, &sdk.ServerOptions{
		// Tools are served from the registry by the middleware below; the
		// capability must still be advertised. No listChanged: a stateless
		// server cannot push it (ysorv868), harnesses re-list.
		Capabilities: &sdk.ServerCapabilities{Tools: &sdk.ToolCapabilities{ListChanged: false}},
	})
	server.AddReceivingMiddleware(e.middleware)

	streamable := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return server }, &sdk.StreamableHTTPOptions{
		Stateless:           true,
		JSONResponse:        true, // one JSON body per POST: nothing to stream, friendlier to proxies
		MaxRequestBodyBytes: opts.MaxBody,
		// The gateway is a network service behind bearer authentication: a
		// browser-based DNS-rebinding attacker cannot attach the header.
		// The SDK's default would 403 every request a reverse proxy on the
		// same host forwards to 127.0.0.1 with the public Host header.
		DisableLocalhostProtection: true,
		Logger:                     opts.Log,
	})

	auth := opts.Auth
	auth.WWWAuthenticateExtra = `resource_metadata="` + strings.TrimRight(opts.BaseURL, "/") + ProtectedResourcePath + `"`
	if auth.Log == nil {
		auth.Log = opts.Log
	}
	return tokens.BearerMiddleware(opts.Authenticator, auth)(streamable), nil
}

// endpoint is the per-handler state the SDK middleware closes over.
type endpoint struct {
	opts Options
}

// middleware intercepts tools/list and tools/call; everything else
// (initialize, ping, server/discover) goes to the SDK.
func (e *endpoint) middleware(next sdk.MethodHandler) sdk.MethodHandler {
	return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
		switch method {
		case "tools/list":
			return e.listTools(ctx, req)
		case "tools/call":
			r, ok := req.(*sdk.CallToolRequest)
			if !ok {
				return next(ctx, method, req)
			}
			return e.callTool(ctx, r)
		}
		return next(ctx, method, req)
	}
}

// listTools renders the registry entries the caller may see. Cursors are
// accepted and ignored: the whole list fits one page. The list is specific
// to the principal, so the cache hint is "private" and immediately stale.
func (e *endpoint) listTools(ctx context.Context, _ sdk.Request) (sdk.Result, error) {
	principal := tokens.PrincipalFrom(ctx)
	res := &sdk.ListToolsResult{Tools: []*sdk.Tool{}, Cacheable: sdk.Cacheable{CacheScope: "private"}}
	for _, tool := range e.opts.Registry.List() {
		if !e.opts.Visibility.Visible(ctx, principal, tool) {
			continue
		}
		schema, err := injectSchema(tool.InputSchema)
		if err != nil {
			e.opts.Log.Error("tool schema unusable", "event", "mcp.schema_invalid", "tool", tool.FullName(), "error", err.Error())
			continue
		}
		res.Tools = append(res.Tools, &sdk.Tool{
			Name:        tool.FullName(),
			Description: tool.Description,
			InputSchema: schema,
			Annotations: &sdk.ToolAnnotations{ReadOnlyHint: tool.Kind == connectors.KindRead},
		})
	}
	return res, nil
}

// injectSchema adds the optional account and approval_id string properties
// to a tool's input schema without touching anything else. A property the
// connector already declares under one of those names is replaced: the
// gateway owns them.
func injectSchema(raw json.RawMessage) (json.RawMessage, error) {
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		return nil, err
	}
	props, _ := schema["properties"].(map[string]any)
	if props == nil {
		props = map[string]any{}
	}
	props[ArgAccount] = map[string]any{"type": "string", "description": accountDescription}
	props[ArgApprovalID] = map[string]any{"type": "string", "description": approvalDescription}
	schema["properties"] = props
	return json.Marshal(schema)
}

// callTool runs the pipeline and maps its outcome onto the wire: a
// ToolError is a JSON-RPC error (same bytes for the same condition), a
// handler error is a tool result with IsError, a Result is content plus the
// read flags in _meta.
func (e *endpoint) callTool(ctx context.Context, req *sdk.CallToolRequest) (sdk.Result, error) {
	args, err := decodeArgs(req.Params.Arguments)
	if err != nil {
		return nil, &jsonrpc.Error{Code: CodeInvalidParams, Message: "arguments must be a JSON object"}
	}
	cc := &CallContext{
		Principal: tokens.PrincipalFrom(ctx),
		Name:      req.Params.Name,
		RawArgs:   args,
		RequestID: observability.RequestIDFromContext(ctx),
	}
	res, err := e.opts.Pipeline.Run(ctx, cc)
	var te *ToolError
	switch {
	case errors.As(err, &te):
		return nil, &jsonrpc.Error{Code: te.Code, Message: te.Message}
	case err != nil:
		out := &sdk.CallToolResult{}
		out.SetError(errors.New(observability.RedactError(err)))
		return out, nil
	}
	return toCallResult(cc, res)
}

// decodeArgs turns the raw arguments into a map; absent or null means no
// arguments.
func decodeArgs(raw json.RawMessage) (map[string]any, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return map[string]any{}, nil
	}
	var args map[string]any
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, err
	}
	if args == nil {
		args = map[string]any{}
	}
	return args, nil
}

// toCallResult renders a connectors.Result: a string becomes one text
// block, SDK content blocks pass through, anything else is marshalled to
// JSON text and also returned as structuredContent. Reads add the
// empty/partial/unavailable flags under MetaReadKey when any is set.
func toCallResult(cc *CallContext, res connectors.Result) (*sdk.CallToolResult, error) {
	out := &sdk.CallToolResult{}
	switch c := res.Content.(type) {
	case nil:
		out.Content = []sdk.Content{}
	case string:
		out.Content = []sdk.Content{&sdk.TextContent{Text: c}}
	case []sdk.Content:
		out.Content = c
	case sdk.Content:
		out.Content = []sdk.Content{c}
	default:
		b, err := json.Marshal(c)
		if err != nil {
			return nil, &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: "tool result is not serialisable"}
		}
		out.Content = []sdk.Content{&sdk.TextContent{Text: string(b)}}
		out.StructuredContent = json.RawMessage(b)
	}
	if cc.Tool != nil && cc.Tool.Kind == connectors.KindRead && (res.Empty || res.Partial || res.Unavailable) {
		flags := map[string]any{}
		if res.Empty {
			flags["empty"] = true
		}
		if res.Partial {
			flags["partial"] = true
		}
		if res.Unavailable {
			flags["unavailable"] = true
		}
		out.Meta = sdk.Meta{MetaReadKey: flags}
	}
	return out, nil
}
