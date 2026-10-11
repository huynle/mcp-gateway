package client

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Session is a connected server.
type Session struct {
	c         *Client
	cs        *mcp.ClientSession
	transport Transport
}

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

func (s *Session) op(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, s.c.timeout)
}

// ListTools lists tools.
func (s *Session) ListTools(ctx context.Context) ([]*mcp.Tool, error) {
	ctx, cancel := s.op(ctx)
	defer cancel()
	return listAll(ctx, func(ctx context.Context, cursor string) ([]*mcp.Tool, string, error) {
		r, err := s.cs.ListTools(ctx, &mcp.ListToolsParams{Cursor: cursor})
		if err != nil {
			return nil, "", err
		}
		return r.Tools, r.NextCursor, nil
	})
}

// CallTool calls a tool.
func (s *Session) CallTool(ctx context.Context, name string, args map[string]any) (*mcp.CallToolResult, error) {
	ctx, cancel := s.op(ctx)
	defer cancel()
	return s.cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
}

// ListResources lists resources.
func (s *Session) ListResources(ctx context.Context) ([]*mcp.Resource, error) {
	ctx, cancel := s.op(ctx)
	defer cancel()
	return listAll(ctx, func(ctx context.Context, cursor string) ([]*mcp.Resource, string, error) {
		r, err := s.cs.ListResources(ctx, &mcp.ListResourcesParams{Cursor: cursor})
		if err != nil {
			return nil, "", err
		}
		return r.Resources, r.NextCursor, nil
	})
}

// ListResourceTemplates lists templates.
func (s *Session) ListResourceTemplates(ctx context.Context) ([]*mcp.ResourceTemplate, error) {
	ctx, cancel := s.op(ctx)
	defer cancel()
	return listAll(ctx, func(ctx context.Context, cursor string) ([]*mcp.ResourceTemplate, string, error) {
		r, err := s.cs.ListResourceTemplates(ctx, &mcp.ListResourceTemplatesParams{Cursor: cursor})
		if err != nil {
			return nil, "", err
		}
		return r.ResourceTemplates, r.NextCursor, nil
	})
}

// ReadResource reads a resource.
func (s *Session) ReadResource(ctx context.Context, uri string) (*mcp.ReadResourceResult, error) {
	ctx, cancel := s.op(ctx)
	defer cancel()
	return s.cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: uri})
}

// ListPrompts lists prompts.
func (s *Session) ListPrompts(ctx context.Context) ([]*mcp.Prompt, error) {
	ctx, cancel := s.op(ctx)
	defer cancel()
	return listAll(ctx, func(ctx context.Context, cursor string) ([]*mcp.Prompt, string, error) {
		r, err := s.cs.ListPrompts(ctx, &mcp.ListPromptsParams{Cursor: cursor})
		if err != nil {
			return nil, "", err
		}
		return r.Prompts, r.NextCursor, nil
	})
}

// GetPrompt gets a prompt.
func (s *Session) GetPrompt(ctx context.Context, name string, args map[string]string) (*mcp.GetPromptResult, error) {
	ctx, cancel := s.op(ctx)
	defer cancel()
	return s.cs.GetPrompt(ctx, &mcp.GetPromptParams{Name: name, Arguments: args})
}

// Close closes.
func (s *Session) Close() error { return s.cs.Close() }

// listAll follows cursors until the server reports no next page.
func listAll[T any](ctx context.Context, page func(context.Context, string) ([]*T, string, error)) ([]*T, error) {
	var out []*T
	cursor := ""
	for {
		items, next, err := page(ctx, cursor)
		if err != nil {
			return nil, err
		}
		out = append(out, items...)
		if next == "" {
			return out, nil
		}
		cursor = next
	}
}
