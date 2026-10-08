package mcp

import (
	"context"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// Visibility decides which registered tools a principal can see in
// tools/list and call. A tool that is not visible does not exist for that
// caller: tools/call answers exactly as for an unknown name.
//
// The policy task replaces ScopeVisibility with the compiled role +
// restrictions + token scope decision (decision 490o45d0: hidden tools are
// absent from the compiled permits and from tools/list).
type Visibility interface {
	Visible(ctx context.Context, principal *tokens.Principal, tool connectors.Tool) bool
}

// ScopeVisibility is the interim Visibility until policy lands: the token's
// allow-list must admit the tool, and a read-only token hides every write
// tool. It knows nothing about roles.
type ScopeVisibility struct{}

// Visible implements Visibility.
func (ScopeVisibility) Visible(_ context.Context, principal *tokens.Principal, tool connectors.Tool) bool {
	if principal == nil {
		return false
	}
	if principal.Scope.ReadOnly && tool.Kind == connectors.KindWrite {
		return false
	}
	return principal.Scope.Allows(tool.FullName())
}
