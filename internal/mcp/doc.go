// Package mcp owns the /mcp Streamable HTTP endpoint (official MCP Go SDK
// in stateless mode: no session store, no sticky sessions, no reliance on
// server-initiated notifications; GET and DELETE answer 405) and the tool
// call pipeline that ties authentication, tool resolution, account
// resolution, policy, approvals, ledger, the app call and audit together.
//
// Handler wraps the SDK's StreamableHTTPHandler in tokens.BearerMiddleware
// (401 challenges carry resource_metadata="<base>/.well-known/oauth-
// protected-resource") and installs one receiving middleware on a single
// SDK server:
//
//   - tools/list renders the connectors.Registry filtered by a Visibility
//     (ScopeVisibility until policy lands) and adds the optional string
//     properties account and approval_id to every schema;
//   - tools/call runs a Pipeline of named Stages. DefaultPipeline is
//     authenticate, audit, resolve, strip, ratelimit, dispatch; audit sits
//     second so it wraps every outcome. Later modules add account-resolve,
//     policy, confirm and ledger with Pipeline.Insert(Before|After, anchor,
//     stage) and never touch the transport.
//
// Hidden and unknown tools produce the same ToolError and therefore the
// same JSON-RPC error bytes. A ToolError is a protocol error; an error from
// a tool's Handler is a tool result with IsError after redaction; read
// results carry empty/partial/unavailable under _meta["mcp-gateway/read"].
//
// Design: Brain plan 36bakiw8 sections 2 and 3; decisions ysorv868, dovthftx,
// s0p05diu (approval_id), 490o45d0 (hidden = absent).
package mcp
