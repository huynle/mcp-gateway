package client

import (
	"context"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Session is a connected server.
type Session struct {
	c         *Client
	cs        *mcp.ClientSession
	transport Transport
	cancel    context.CancelFunc
	obs       *observer // the session context's observer (legacy SSE stream)
	label     string
	rec       *Recorder // URL-mode elicitations; nil without Options.URLElicitation
}

// MCP operation names used in errors.
const (
	opConnect               = "connect"
	opListTools             = "tools/list"
	opCallTool              = "tools/call"
	opListResources         = "resources/list"
	opListResourceTemplates = "resources/templates/list"
	opReadResource          = "resources/read"
	opListPrompts           = "prompts/list"
	opGetPrompt             = "prompts/get"
)

// Transport is the transport in use.
func (s *Session) Transport() Transport { return s.transport }

func (s *Session) init() *mcp.InitializeResult {
	if r := s.cs.InitializeResult(); r != nil {
		return r
	}
	return &mcp.InitializeResult{}
}

// ServerInfo is the server's implementation info.
func (s *Session) ServerInfo() *mcp.Implementation { return s.init().ServerInfo }

// ProtocolVersion is the negotiated version.
func (s *Session) ProtocolVersion() string { return s.init().ProtocolVersion }

// Instructions are the server's instructions.
func (s *Session) Instructions() string { return s.init().Instructions }

// Capabilities are the server's capabilities.
func (s *Session) Capabilities() *mcp.ServerCapabilities { return s.init().Capabilities }

// do runs f under the client's Timeout with a fresh observer and
// classifies its error.
func do[R any](ctx context.Context, s *Session, op string, f func(context.Context) (R, error)) (R, error) {
	start := time.Now()
	obs := &observer{}
	ctx, cancel := context.WithTimeout(withObserver(withoutSDKValues(ctx), obs), s.c.timeout)
	defer cancel()
	r, err := f(ctx)
	if err != nil {
		var zero R
		ce := classify(ctx, op, err, obs, s.obs)
		s.c.report(s.label, op, s.transport, start, ce)
		return zero, ce
	}
	s.c.report(s.label, op, s.transport, start, nil)
	return r, nil
}

// ListTools lists tools.
func (s *Session) ListTools(ctx context.Context) ([]*mcp.Tool, error) {
	return do(ctx, s, opListTools, func(ctx context.Context) ([]*mcp.Tool, error) {
		return listAll(ctx, s.c.maxList, func(ctx context.Context, cursor string) ([]*mcp.Tool, string, error) {
			r, err := s.cs.ListTools(ctx, &mcp.ListToolsParams{Cursor: cursor})
			if err != nil {
				return nil, "", err
			}
			return r.Tools, r.NextCursor, nil
		})
	})
}

// CallTool calls a tool.
func (s *Session) CallTool(ctx context.Context, name string, args map[string]any) (*mcp.CallToolResult, error) {
	return do(ctx, s, opCallTool, func(ctx context.Context) (*mcp.CallToolResult, error) {
		return s.cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	})
}

// ListResources lists resources.
func (s *Session) ListResources(ctx context.Context) ([]*mcp.Resource, error) {
	return do(ctx, s, opListResources, func(ctx context.Context) ([]*mcp.Resource, error) {
		return listAll(ctx, s.c.maxList, func(ctx context.Context, cursor string) ([]*mcp.Resource, string, error) {
			r, err := s.cs.ListResources(ctx, &mcp.ListResourcesParams{Cursor: cursor})
			if err != nil {
				return nil, "", err
			}
			return r.Resources, r.NextCursor, nil
		})
	})
}

// ListResourceTemplates lists templates.
func (s *Session) ListResourceTemplates(ctx context.Context) ([]*mcp.ResourceTemplate, error) {
	return do(ctx, s, opListResourceTemplates, func(ctx context.Context) ([]*mcp.ResourceTemplate, error) {
		return listAll(ctx, s.c.maxList, func(ctx context.Context, cursor string) ([]*mcp.ResourceTemplate, string, error) {
			r, err := s.cs.ListResourceTemplates(ctx, &mcp.ListResourceTemplatesParams{Cursor: cursor})
			if err != nil {
				return nil, "", err
			}
			return r.ResourceTemplates, r.NextCursor, nil
		})
	})
}

// ReadResource reads a resource.
func (s *Session) ReadResource(ctx context.Context, uri string) (*mcp.ReadResourceResult, error) {
	return do(ctx, s, opReadResource, func(ctx context.Context) (*mcp.ReadResourceResult, error) {
		return s.cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: uri})
	})
}

// ListPrompts lists prompts.
func (s *Session) ListPrompts(ctx context.Context) ([]*mcp.Prompt, error) {
	return do(ctx, s, opListPrompts, func(ctx context.Context) ([]*mcp.Prompt, error) {
		return listAll(ctx, s.c.maxList, func(ctx context.Context, cursor string) ([]*mcp.Prompt, string, error) {
			r, err := s.cs.ListPrompts(ctx, &mcp.ListPromptsParams{Cursor: cursor})
			if err != nil {
				return nil, "", err
			}
			return r.Prompts, r.NextCursor, nil
		})
	})
}

// GetPrompt gets a prompt.
func (s *Session) GetPrompt(ctx context.Context, name string, args map[string]string) (*mcp.GetPromptResult, error) {
	return do(ctx, s, opGetPrompt, func(ctx context.Context) (*mcp.GetPromptResult, error) {
		return s.cs.GetPrompt(ctx, &mcp.GetPromptParams{Name: name, Arguments: args})
	})
}

// Close closes.
func (s *Session) Close() error {
	err := s.cs.Close()
	s.cancel()
	return err
}

// listAll follows cursors until the server reports no next page. It
// fails with ClassTooLarge past max items (or max pages, for servers that
// send empty pages) and with ClassProtocol when a cursor repeats.
func listAll[T any](ctx context.Context, max int, page func(context.Context, string) ([]*T, string, error)) ([]*T, error) {
	var out []*T
	seen := map[string]bool{}
	cursor := ""
	for pages := 1; ; pages++ {
		items, next, err := page(ctx, cursor)
		if err != nil {
			return nil, err
		}
		if len(out)+len(items) > max {
			return nil, &Error{Class: ClassTooLarge, Reason: "list_items"}
		}
		out = append(out, items...)
		if next == "" {
			return out, nil
		}
		if seen[next] {
			return nil, &Error{Class: ClassProtocol, Reason: "cursor_loop"}
		}
		if pages >= max {
			return nil, &Error{Class: ClassTooLarge, Reason: "list_pages"}
		}
		seen[next] = true
		cursor = next
	}
}
