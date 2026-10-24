package connector

import (
	"context"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/secrets/ref"
)

// Precheck returns the check the /mcp pipeline runs before policy
// (mcp.StagePrecheck, Brain task 8ky7l4e6). For a federated tool it runs
// the review part of the call path (Manager.check): the server is still
// active and the approved snapshot, read as the caller, has the tool,
// enables it and accepts the arguments under the pinned input schema
// (args_invalid, tool_disabled, tool_not_reviewed, tool_changed,
// tool_not_found). So a write that can never run is refused before the
// policy stage asks for an approval: no approval row, no approval
// notification, no ledger operation. Credentials are left to the call
// (its auth_required answer carries the connect link). Built-in tools
// pass through untouched. The call keeps its own check: the review may
// change between an approval and its retry.
//
// Ephemeral secret references ({"$secret": "sec_..."}) are validated as
// their handle string (design correction 2): the precheck sees a copy of
// the arguments with each ref replaced by its handle, so a ref passes
// where the schema expects a string. The secret stage substitutes the
// plaintext right before dispatch, where the call's own check validates
// the real value.
func (m *Manager) Precheck() mcp.Prechecker {
	return mcp.PrecheckerFunc(m.precheck)
}

func (m *Manager) precheck(ctx context.Context, tool connectors.Tool, call connectors.Call) error {
	if !m.o.Registry.IsServerApp(tool.App) {
		return nil
	}
	e, ok := m.entry(tool.App)
	if !ok {
		return mcp.ErrToolNotFound(call.Tool)
	}
	upstream, ok := e.upstream[tool.Name]
	if !ok {
		return mcp.ErrToolNotFound(call.Tool)
	}
	if len(ref.FindWithPaths(call.Args)) > 0 {
		call.Args = ref.ReplaceArgsWithHandle(call.Args)
	}
	_, _, _, err := m.check(ctx, e.server.ID, upstream, tool.Kind, call)
	return err
}

// SecretTarget resolves the registered tool app.tool of a loaded server to
// what an ephemeral secret binds to: the server's id and the tool's
// upstream name (stable across a server rename and the registry's name
// sanitising). Built-in apps and unknown tools have none. It implements
// secrets.Targets.
func (m *Manager) SecretTarget(app, tool string) (serverID, upstream string, ok bool) {
	e, found := m.entry(app)
	if !found {
		return "", "", false
	}
	up, found := e.upstream[tool]
	if !found {
		return "", "", false
	}
	return e.server.ID, up, true
}
