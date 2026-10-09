package slack

import (
	"context"
	"errors"

	goslack "github.com/slack-go/slack"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Write tool names.
const (
	ToolPostMessage   = "post_message"
	ToolReplyInThread = "reply_in_thread"
	ToolAddReaction   = "add_reaction"
)

// Slack user-token scopes the write tools need.
const (
	ScopeChatWrite      = "chat:write"
	ScopeReactionsWrite = "reactions:write"
)

// ErrMissingOperation is returned by every write called without
// Call.OperationID: the ledger stage sets it before dispatch, and the
// marker and stable-id reconciliation derive from it, so a write without
// one could never be verified after an unknown outcome. It means a
// pipeline wiring bug (a write dispatched without the ledger), never a
// harness mistake.
var ErrMissingOperation = errors.New("slack: write called without a ledger operation id")

var errNotImplemented = errors.New("slack: not implemented")

// writeTools declares the three write tools (stub; filled in by the
// write increment).
func (c *Connector) writeTools() []connectors.Tool {
	single := connectors.Bounds{MaxResultBytes: c.bounds.MaxResultBytes}
	return []connectors.Tool{
		{App: App, Name: ToolPostMessage, Kind: connectors.KindWrite, Description: "stub", InputSchema: objectSchema(nil, nil), ResourceIdentity: identity(), Reconcile: connectors.Reconciliation{Kind: connectors.ReconcileNone}, Bounds: single},
		{App: App, Name: ToolReplyInThread, Kind: connectors.KindWrite, Description: "stub", InputSchema: objectSchema(nil, nil), ResourceIdentity: identity(), Reconcile: connectors.Reconciliation{Kind: connectors.ReconcileNone}, Bounds: single},
		{App: App, Name: ToolAddReaction, Kind: connectors.KindWrite, Description: "stub", InputSchema: objectSchema(nil, nil), ResourceIdentity: identity(), Reconcile: connectors.Reconciliation{Kind: connectors.ReconcileNone}, Bounds: single},
	}
}

// writeHandlers maps the write tools' short names to their implementation.
func (c *Connector) writeHandlers() map[string]handler {
	stub := func(context.Context, *goslack.Client, connectors.Call) (connectors.Result, error) {
		return connectors.Result{}, errNotImplemented
	}
	return map[string]handler{ToolPostMessage: stub, ToolReplyInThread: stub, ToolAddReaction: stub}
}
